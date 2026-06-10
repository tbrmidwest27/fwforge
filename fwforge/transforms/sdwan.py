"""Move interfaces into SD-WAN members — with all the provisions.

What actually has to happen on a FortiGate when an interface becomes an
SD-WAN member, and what this transform therefore does to the config:

1. members cannot be referenced directly by policies -> rewrite
   srcintf/dstintf to the SD-WAN zone (shared rewrite)
2. members cannot carry their own default routes -> remove per-interface
   default routes, harvest their gateways into the member entries, and
   create a single `set sdwan-zone` static route in their place
3. non-default static routes on members are kept but individually flagged
   (FortiOS may reject them; they usually become SD-WAN rules instead)
4. `config system sdwan` is created (or extended): status enable, zone
   entries, member entries with gateway/cost/weight/priority, and a
   health-check (a ping check is generated unless the plan says
   `health-check = none`)
"""
from __future__ import annotations

from ..parsers.fortios_tree import (
    ConfigNode,
    CTree,
    EditNode,
    SetLine,
    Token,
    find_config_under,
)
from .plan import PlanError, SdwanZoneSpec
from .portmap import tree_interface_names
from .tree_refs import (
    insert_in_scope,
    interface_vdoms,
    resolve_spec_vdom,
    rewrite_policy_refs,
    vdom_scope,
)
from .zones import existing_sdwan_members, existing_zone_members


def validate(tree: CTree, specs: list[SdwanZoneSpec]) -> None:
    interfaces = set(tree_interface_names(tree))
    zoned = existing_zone_members(tree)
    already = existing_sdwan_members(tree)
    claimed: set[str] = set()
    for spec in specs:
        for m in spec.members:
            ifc = m.interface
            if ifc not in interfaces:
                raise PlanError(
                    f"[sdwan {spec.name}]: '{ifc}' is not an interface in "
                    "this config (after portmap)")
            if ifc in zoned:
                raise PlanError(
                    f"[sdwan {spec.name}]: '{ifc}' is in zone "
                    f"'{zoned[ifc]}' — remove it from the zone before "
                    "making it an SD-WAN member")
            if ifc in already:
                raise PlanError(
                    f"[sdwan {spec.name}]: '{ifc}' is already an SD-WAN "
                    "member in the source config")
            if ifc in claimed:
                raise PlanError(
                    f"'{ifc}' is listed in more than one [sdwan] section")
            claimed.add(ifc)


def _ensure_sdwan_node(scope) -> ConfigNode:
    node = find_config_under(scope, "system", "sdwan")
    if node is None:
        node = ConfigNode(["system", "sdwan"])
        insert_in_scope(scope, node)
    has_status = any(
        isinstance(c, SetLine) and c.attr == "status" for c in node.children)
    if not has_status:
        node.children.insert(0, SetLine("status", [Token("enable", False)]))
    return node


def _ensure_subsection(sdwan: ConfigNode, name: str) -> ConfigNode:
    for child in sdwan.children:
        if isinstance(child, ConfigNode) and child.path == [name]:
            return child
    # canonical FortiOS order: status, zone, members, health-check, service
    order = {"zone": 1, "members": 2, "health-check": 3, "service": 4}
    rank = order.get(name, 9)
    idx = len(sdwan.children)
    for i, child in enumerate(sdwan.children):
        if isinstance(child, ConfigNode) \
                and order.get(child.path[0], 9) > rank:
            idx = i
            break
    node = ConfigNode([name])
    sdwan.children.insert(idx, node)
    return node


def _next_edit_id(node: ConfigNode) -> int:
    ids = [int(c.name.value) for c in node.children
           if isinstance(c, EditNode) and c.name.value.isdigit()]
    return max(ids, default=0) + 1


def _route_attrs(edit: EditNode) -> dict[str, list[Token]]:
    return {c.attr: c.values for c in edit.children if isinstance(c, SetLine)}


def _is_default_route(attrs: dict) -> bool:
    dst = attrs.get("dst")
    if dst is None:
        return True  # FortiOS omits dst at its default 0.0.0.0/0
    return [t.value for t in dst] == ["0.0.0.0", "0.0.0.0"]


def convert_member_routes(scope, member_ifcs: set[str],
                          zone_of: dict[str, str], report) -> dict:
    """Within one VDOM's scope: remove member default routes (returning
    their gateways) and create the replacement sdwan-zone route."""
    gateways: dict[str, str] = {}
    distances: set[str] = set()
    priorities: set[str] = set()
    zones_hit: list[str] = []
    converted = 0

    node = find_config_under(scope, "router", "static")
    if node is not None:
        keep = []
        for child in node.children:
            if not isinstance(child, EditNode):
                keep.append(child)
                continue
            attrs = _route_attrs(child)
            device = attrs.get("device")
            dev = device[0].value if device else ""
            if dev not in member_ifcs:
                keep.append(child)
                continue
            if _is_default_route(attrs):
                gw = attrs.get("gateway")
                if gw:
                    gateways.setdefault(dev, gw[0].value)
                if "distance" in attrs:
                    distances.add(attrs["distance"][0].value)
                if "priority" in attrs:
                    priorities.add(attrs["priority"][0].value)
                zone = zone_of[dev]
                if zone not in zones_hit:
                    zones_hit.append(zone)
                converted += 1
                report.add(
                    "info", "sdwan",
                    f"default route {child.name.value} via '{dev}' removed; "
                    f"its gateway moves onto SD-WAN member '{dev}'")
                continue  # drop the edit
            keep.append(child)
            dst = " ".join(t.value for t in attrs.get("dst", []))
            report.add(
                "warn", "sdwan",
                f"static route {child.name.value} ({dst} via '{dev}') kept, "
                "but FortiOS may reject routes on SD-WAN member interfaces "
                "— consider an SD-WAN rule or move the route to the zone",
            )
        node.children = keep

        if converted and zones_hit:
            new_id = _next_edit_id(node)
            route = EditNode(Token(str(new_id), False))
            route.children.append(
                SetLine("sdwan-zone", [Token(z, True) for z in zones_hit]))
            if len(distances) == 1:
                route.children.append(
                    SetLine("distance", [Token(distances.pop(), False)]))
            elif len(distances) > 1:
                report.add(
                    "warn", "sdwan",
                    "replaced default routes had different distances "
                    f"({', '.join(sorted(distances))}) — the sdwan-zone "
                    "route uses the default; set it manually if needed")
            if len(priorities) == 1:
                route.children.append(
                    SetLine("priority", [Token(priorities.pop(), False)]))
            node.children.append(route)
            report.add(
                "info", "sdwan",
                f"created static route {new_id}: set sdwan-zone "
                f"{' '.join(zones_hit)} (replaces {converted} member "
                "default route(s))")

    if not converted:
        report.add(
            "info", "sdwan",
            "no default routes were found on the new members — no "
            "sdwan-zone route created; add one if these links should "
            "carry the default route")
    return {"gateways": gateways, "converted": converted}


def apply_sdwan(tree: CTree, specs: list[SdwanZoneSpec], report) -> dict:
    validate(tree, specs)
    ifc_vdoms = interface_vdoms(tree)

    by_vdom: dict[str, list[SdwanZoneSpec]] = {}
    for spec in specs:
        vd = resolve_spec_vdom([m.interface for m in spec.members],
                               ifc_vdoms, spec.vdom, f"sdwan {spec.name}")
        spec.vdom = vd
        by_vdom.setdefault(vd, []).append(spec)

    mapping: dict[str, str] = {}
    members_added = 0
    routes_converted = 0

    for vd, vdom_specs in by_vdom.items():
        scope = vdom_scope(tree, vd)
        member_ifcs = {m.interface for s in vdom_specs for m in s.members}
        zone_of = {m.interface: s.name
                   for s in vdom_specs for m in s.members}

        route_info = convert_member_routes(scope, member_ifcs, zone_of,
                                           report)
        routes_converted += route_info["converted"]

        sdwan = _ensure_sdwan_node(scope)
        zone_node = _ensure_subsection(sdwan, "zone")
        members_node = _ensure_subsection(sdwan, "members")

        existing_zones = {c.name.value for c in zone_node.children
                          if isinstance(c, EditNode)}
        health_specs: list[tuple[str, str, str, list[int]]] = []

        for spec in vdom_specs:
            if spec.name not in existing_zones:
                zone_node.children.append(EditNode(Token(spec.name, True)))
                existing_zones.add(spec.name)
            new_ids: list[int] = []
            for m in spec.members:
                mid = _next_edit_id(members_node)
                new_ids.append(mid)
                edit = EditNode(Token(str(mid), False))
                edit.children.append(
                    SetLine("interface", [Token(m.interface, True)]))
                edit.children.append(
                    SetLine("zone", [Token(spec.name, True)]))
                gw = m.gateway or route_info["gateways"].get(m.interface, "")
                if (m.gateway and m.interface in route_info["gateways"]
                        and m.gateway != route_info["gateways"][m.interface]):
                    report.add(
                        "warn", "sdwan",
                        f"member '{m.interface}': plan gateway {m.gateway} "
                        "differs from the removed default route's gateway "
                        f"{route_info['gateways'][m.interface]} — using the "
                        "plan's value")
                if gw:
                    edit.children.append(
                        SetLine("gateway", [Token(gw, False)]))
                for attr in ("cost", "weight", "priority"):
                    val = getattr(m, attr)
                    if val:
                        edit.children.append(
                            SetLine(attr, [Token(val, False)]))
                members_node.children.append(edit)
                members_added += 1
                mapping[m.interface] = spec.name
                if not gw:
                    report.add(
                        "info", "sdwan",
                        f"member '{m.interface}' has no gateway (none in "
                        "plan, no default route found) — fine for "
                        "DHCP/PPPoE links, otherwise set one")

            hc = spec.health_check
            if hc is None:
                health_specs.append(
                    (f"fwforge_{spec.name}", "ping", "8.8.8.8", new_ids))
                report.add(
                    "info", "sdwan",
                    f"no health-check specified for [{spec.name}] — "
                    "generated a ping check to 8.8.8.8 (edit the plan to "
                    "change or use 'health-check = none')")
            elif hc[0] != "none":
                health_specs.append(
                    (f"fwforge_{spec.name}", hc[0], hc[1], new_ids))

        if health_specs:
            hc_node = _ensure_subsection(sdwan, "health-check")
            existing_hc = {c.name.value for c in hc_node.children
                           if isinstance(c, EditNode)}
            for name, protocol, server, ids in health_specs:
                if name in existing_hc:
                    continue
                edit = EditNode(Token(name, True))
                edit.children.append(
                    SetLine("server", [Token(server, True)]))
                if protocol != "ping":
                    edit.children.append(
                        SetLine("protocol", [Token(protocol, False)]))
                edit.children.append(
                    SetLine("members",
                            [Token(str(i), False) for i in ids]))
                hc_node.children.append(edit)

    touched = rewrite_policy_refs(tree, mapping, report, "sdwan")
    vdom_note = f" across VDOM(s) {', '.join(sorted(by_vdom))}" \
        if len(by_vdom) > 1 or list(by_vdom) != ["root"] else ""
    report.add(
        "info", "sdwan",
        f"SD-WAN: {members_added} member(s) added across "
        f"{len(specs)} zone(s){vdom_note}; {touched} policy entries now "
        "reference the SD-WAN zone")
    return {
        "members_added": members_added,
        "routes_converted": routes_converted,
        "policies_rewritten": touched,
        "mapping": mapping,
    }
