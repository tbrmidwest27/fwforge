"""Interface mapping: source interface/zone names -> target FortiGate ports.

Two modes:

- IR mode (cross-vendor): set Interface.target_name and rewrite every IR
  reference (policies, routes, VIPs, NAT intents).

- Tree mode (FortiOS -> FortiOS migration): rewrite interface references
  across the whole config tree, reference-aware. `set member` is only
  rewritten in sections where members are interfaces (an address group
  member that happens to be named "port1" is left alone).

Map file format — one mapping per line, '#' comments:

    # asa-nameif-or-old-port = target-port
    outside = wan1
    inside  = port1
"""
from __future__ import annotations

from ..model import FirewallConfig
from ..parsers.fortios_tree import (
    ConfigNode,
    CTree,
    EditNode,
    SetLine,
    Token,
    iter_config_nodes,
    path_endswith,
)

# `set <attr> ...` whose values are interface names anywhere in the config
GLOBAL_INTF_ATTRS = {
    "interface", "srcintf", "dstintf", "extintf", "device",
    "input-device", "output-device", "associated-interface", "hbdev",
    "monitor", "session-sync-dev", "srcintf-filter", "mirror-intf",
    "split-interface", "aggregate", "fortilink", "source-interface",
    "intf",  # firewall local-in-policy
}

# namespaces whose port-like names belong to OTHER devices (FortiSwitch
# ports, FortiExtender ports) — never rename, never flag
_FOREIGN_NAME_PATHS = (("switch-controller",),)

# attrs that hold interface names only under specific config paths.
# `set member` under system interface = switch/aggregate/redundant member
# ports (always interface names); under virtual-wire-pair = the pair's two
# interfaces. Matched by suffix so it also fires inside config global on
# multi-VDOM configs.
PATH_SCOPED_ATTRS: dict[tuple, set[str]] = {
    ("system", "virtual-wire-pair"): {"member"},
    ("system", "interface"): {"member"},
    ("system", "switch-interface"): {"member"},  # software-switch bridges
}

# config paths whose `edit <name>` entries ARE interface names
EDIT_RENAME_PATHS = {
    ("system", "interface"),
    ("system", "dns-server"),               # edit <interface>
    ("system", "virtual-switch"),           # edit <hard-switch name>
    ("system", "virtual-switch", "port"),   # nested member ports
}


def load_map(path: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    # utf-8-sig: tolerate the BOM that Windows editors/PowerShell prepend
    with open(path, encoding="utf-8-sig") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if "=" in line:
                src, dst = line.split("=", 1)
            else:
                parts = line.split()
                if len(parts) != 2:
                    continue
                src, dst = parts
            mapping[src.strip()] = dst.strip()
    return mapping


def sample_map(names: list[str]) -> str:
    width = max((len(n) for n in names), default=8)
    lines = [
        "# fwforge interface map: source name = target FortiGate port",
        "# fill in the right-hand side, then re-run with --map this-file",
    ]
    for n in names:
        lines.append(f"{n.ljust(width)} = CHANGE_ME")
    return "\n".join(lines) + "\n"


# -- IR mode ----------------------------------------------------------------

def apply_ir(cfg: FirewallConfig, mapping: dict[str, str], report) -> list[str]:
    """Apply mapping to the IR. Returns source names left unmapped."""
    unmapped: set[str] = set()
    # zone-based vendors (PAN-OS): policies reference zones, not
    # interfaces — only the zones' member interfaces need mapping.
    # VPN tunnel names are interfaces fwforge itself creates on the
    # target; they are never source ports to map.
    skip_names = {z.name for z in cfg.zones} \
        | {p.name for p in cfg.phase1s}
    # interfaces fwforge *creates* on the target (VLAN subinterfaces,
    # aggregates, loopbacks) are not source ports the user maps — they ride
    # their mapped parent and the name sanitizer finalizes the name. An
    # explicit map entry still rewrites them; they're just never flagged as
    # an unmapped port needing a target.
    created = {i.name for i in cfg.interfaces
               if i.kind in ("vlan", "aggregate", "loopback", "tunnel")}

    def mapped(name: str) -> str:
        if name in ("any", "all", "") or name in skip_names:
            return name
        if name in mapping:
            return mapping[name]
        if name not in created:
            unmapped.add(name)
        return name

    for itf in cfg.interfaces:
        if itf.name in mapping:
            itf.target_name = mapping[itf.name]
    for zone in cfg.zones:
        zone.members = [mapped(m) for m in zone.members]
    for p1 in cfg.phase1s:
        p1.interface = mapped(p1.interface)
    for pol in cfg.policies:
        pol.src_zones = [mapped(z) for z in pol.src_zones]
        pol.dst_zones = [mapped(z) for z in pol.dst_zones]
    for rt in cfg.routes:
        rt.interface = mapped(rt.interface)
    for vip in cfg.vips:
        vip.ext_intf = mapped(vip.ext_intf)
    for nat in cfg.nats:
        nat.real_ifc = mapped(nat.real_ifc)
        nat.mapped_ifc = mapped(nat.mapped_ifc)

    for name in sorted(unmapped):
        report.add(
            "warn", "interfaces",
            f"no target port mapped for source interface '{name}' — output "
            "keeps the source name; add it to the map file",
        )
    return sorted(unmapped)


def apply_authoring(cfg, authoring: dict | None, report) -> None:
    """GUI 'aggregate authoring' overlay, applied after apply_ir: create or
    update target LAGs (name + member target-ports + LACP) and re-nest
    VLANs onto a chosen parent. Specs are already in TARGET terms — the
    emitter passes a name through unchanged when no source interface owns
    it, so target port / LAG names resolve correctly."""
    if not authoring:
        return
    from ..model import Interface
    aggregates = authoring.get("aggregates") or []
    vlan_parents = authoring.get("vlan_parents") or {}

    # target port -> the source interface already mapped onto it, to warn
    # when a LAG claims a port that is also a standalone interface's target
    claimed: dict[str, str] = {}
    for i in cfg.interfaces:
        if i.kind in ("physical", "vlan", "loopback") and i.target_name:
            claimed.setdefault(i.target_name, i.name)

    built = 0
    promoted = 0
    for spec in aggregates:
        name = (spec.get("name") or "").strip()
        if not name:
            continue
        members = [m.strip() for m in (spec.get("members") or []) if m.strip()]
        lacp = (spec.get("lacp") or "active").strip().lower()
        if lacp not in ("active", "passive", "static"):
            lacp = "active"
        agg = next((i for i in cfg.interfaces
                    if i.kind == "aggregate" and i.mapped == name), None)
        promoted_here = False
        if agg is None:
            # the GUI flipped a source PHYSICAL interface to an aggregate in
            # place (its IP / description / VLAN children ride the LAG):
            # same interface, kind becomes aggregate, chosen target ports
            # become members. Identified by the physical whose mapped target
            # IS this LAG name (the GUI sets a promoted row's map_dst to the
            # LAG name). A separately-named new LAG that merely bonds a port
            # has name != that port's mapped target, so it is NOT promotion.
            agg = next((i for i in cfg.interfaces
                        if i.kind == "physical" and i.mapped == name), None)
            promoted_here = agg is not None
        if agg is None:                       # a LAG the source didn't have
            agg = Interface(name=name, kind="aggregate", target_name=name)
            cfg.interfaces.append(agg)
        agg.kind = "aggregate"
        agg.target_name = name
        agg.members = members
        agg.lacp_mode = lacp
        built += 1
        if promoted_here:
            promoted += 1
            report.add(
                "info", "interfaces",
                f"interface '{agg.name}' promoted from physical to an "
                f"802.3ad aggregate (LACP {lacp}) with member port(s) "
                f"{', '.join(members) if members else '(none chosen yet)'}; "
                "its VLAN subinterfaces ride the LAG")
        src_members = [i.name for i in cfg.interfaces
                       if i.kind == "aggregate-member" and i.parent == agg.name]
        if src_members:
            report.add(
                "info", "interfaces",
                f"LAG '{name}' absorbs source member port(s) "
                f"{', '.join(src_members)} as "
                f"{', '.join(members) if members else '(no ports chosen yet)'}")
        for m in members:
            owner = claimed.get(m)
            if owner and owner != name:
                report.add(
                    "warn", "interfaces",
                    f"LAG '{name}' member '{m}' is also the target port of "
                    f"interface '{owner}' — a port can be a LAG member or a "
                    "standalone interface, not both")

    # repoint zone / route / VIP / NAT references from a bonded member port
    # to its LAG, so nothing dangles when a referenced port is absorbed
    member_to_lag: dict[str, str] = {}
    for spec in aggregates:
        nm = (spec.get("name") or "").strip()
        for m in (spec.get("members") or []):
            m = m.strip()
            if m and m != nm:
                member_to_lag[m] = nm
    repointed = 0
    if member_to_lag:
        for zone in cfg.zones:
            new = [member_to_lag.get(m, m) for m in zone.members]
            repointed += sum(1 for a, b in zip(zone.members, new) if a != b)
            zone.members = new
        for rt in cfg.routes:
            if rt.interface in member_to_lag:
                rt.interface = member_to_lag[rt.interface]
                repointed += 1
        for vip in cfg.vips:
            if vip.ext_intf in member_to_lag:
                vip.ext_intf = member_to_lag[vip.ext_intf]
                repointed += 1
        for nat in cfg.nats:
            if nat.real_ifc in member_to_lag:
                nat.real_ifc = member_to_lag[nat.real_ifc]
                repointed += 1
            if nat.mapped_ifc in member_to_lag:
                nat.mapped_ifc = member_to_lag[nat.mapped_ifc]
                repointed += 1
        if repointed:
            report.add(
                "info", "interfaces",
                f"repointed {repointed} reference(s) from a bonded port to "
                "its LAG")

    by_name = {i.name: i for i in cfg.interfaces}
    nested = 0
    for vlan_src, parent in vlan_parents.items():
        parent = (parent or "").strip()
        itf = by_name.get(vlan_src)
        if itf is not None and itf.kind == "vlan" and parent:
            itf.parent = parent
            nested += 1

    if built or nested:
        report.add(
            "info", "interfaces",
            f"GUI interface authoring: {built} aggregate(s) set"
            + (f" ({promoted} promoted from a physical interface)"
               if promoted else "")
            + f", {nested} VLAN(s) re-nested onto a chosen parent")


# -- tree mode (FortiOS -> FortiOS) -----------------------------------------

def apply_tree(tree: CTree, mapping: dict[str, str]) -> dict:
    """Rename interface references across a FortiOS config tree.
    Returns stats: {'edits': int, 'values': int, 'by_attr': {attr: count}}.
    """
    stats = {"edits": 0, "values": 0, "by_attr": {}}

    def bump(attr: str):
        stats["values"] += 1
        stats["by_attr"][attr] = stats["by_attr"].get(attr, 0) + 1

    def rewrite_set(node: SetLine, extra_attrs: set[str]):
        if node.attr not in GLOBAL_INTF_ATTRS and node.attr not in extra_attrs:
            return
        new_values = []
        for tok in node.values:
            target = mapping.get(tok.value)
            if target is not None and target != tok.value:
                new_values.append(Token(target, tok.quoted))
                bump(node.attr)
            else:
                new_values.append(tok)
        node.values = new_values

    def walk(children, path: tuple):
        extra: set[str] = set()
        for scoped_path, attrs in PATH_SCOPED_ATTRS.items():
            if path_endswith(path, scoped_path):
                extra |= attrs
        for child in children:
            if isinstance(child, SetLine):
                rewrite_set(child, extra)
            elif isinstance(child, EditNode):
                if any(path_endswith(path, p) for p in EDIT_RENAME_PATHS) \
                        and mapping.get(child.name.value,
                                        child.name.value) != child.name.value:
                    child.name = Token(mapping[child.name.value],
                                       child.name.quoted)
                    stats["edits"] += 1
                walk(child.children, path)
            elif isinstance(child, ConfigNode):
                walk(child.children, path + tuple(child.path))

    walk(tree.children, ())
    return stats


def leftover_scan(tree: CTree, mapping: dict[str, str], report) -> int:
    """After a rename, find remaining tokens that still equal a *renamed*
    source name. These live in attrs we deliberately don't rewrite — some
    are other devices' ports (FortiSwitch: skipped), the rest get an info
    finding so a human decides."""
    from ..parsers.fortios_tree import (iter_config_nodes, iter_set_lines,
                                        path_endswith)

    renamed = {src for src, dst in mapping.items() if src != dst}
    if not renamed:
        return 0
    flagged = 0
    for path, line in iter_set_lines(tree):
        if any(path[:len(p)] == p for p in _FOREIGN_NAME_PATHS):
            continue
        if path_endswith(path, ("system", "interface")):
            continue
        hits = [t.value for t in line.values if t.value in renamed]
        if hits:
            flagged += 1
            report.add(
                "info", "portmap",
                f"'{', '.join(hits)}' left untouched at config "
                f"{' '.join(path)} (set {line.attr}) — likely another "
                "device's port name (extender/switch); verify",
            )
    # edit names that still equal a renamed source (outside the explicit
    # EDIT_RENAME_PATHS) may be interface-keyed tables we don't know about
    for path, node in iter_config_nodes(tree):
        if any(path[:len(p)] == p for p in _FOREIGN_NAME_PATHS):
            continue
        if any(path_endswith(path, p) for p in EDIT_RENAME_PATHS):
            continue
        for edit in node.children:
            if isinstance(edit, EditNode) and edit.name.value in renamed:
                flagged += 1
                report.add(
                    "info", "portmap",
                    f"entry '{edit.name.value}' under config "
                    f"{' '.join(path)} matches a renamed source port but "
                    "was not renamed — verify whether this table is keyed "
                    "by interface name",
                )
    return flagged


def tree_interface_names(tree: CTree) -> list[str]:
    """All interface names defined in `config system interface`."""
    names: list[str] = []
    for path, node in iter_config_nodes(tree):
        if path_endswith(path, ("system", "interface")):
            for child in node.children:
                if isinstance(child, EditNode):
                    names.append(child.name.value)
    return names


def _mask_bits(mask: str) -> str:
    try:
        return str(sum(bin(int(o)).count("1") for o in mask.split(".")))
    except ValueError:
        return mask


def tree_interface_details(tree: CTree) -> list[dict]:
    """Per-interface facts from `config system interface`, for informed
    member selection (zone/SD-WAN builders, mapping grids)."""
    out: list[dict] = []
    for path, node in iter_config_nodes(tree):
        if not path_endswith(path, ("system", "interface")):
            continue
        for edit in node.children:
            if not isinstance(edit, EditNode):
                continue
            d = {"name": edit.name.value, "ip": "", "alias": "",
                 "descr": "", "type": "", "vlanid": "", "parent": "",
                 "role": "", "status": "", "vdom": "", "kind": "",
                 "members": []}
            mode = ""
            for line in edit.children:
                if not isinstance(line, SetLine) or not line.values:
                    continue
                v = line.values[0].value
                if line.attr == "ip":
                    if "/" in v:
                        d["ip"] = v
                    elif len(line.values) >= 2 and v != "0.0.0.0":
                        d["ip"] = f"{v}/{_mask_bits(line.values[1].value)}"
                elif line.attr == "mode":
                    mode = v
                elif line.attr == "alias":
                    d["alias"] = " ".join(t.value for t in line.values)
                elif line.attr == "description":
                    d["descr"] = " ".join(t.value for t in line.values)
                elif line.attr in ("type", "vlanid", "role", "status",
                                   "vdom"):
                    d[line.attr] = v
                elif line.attr == "interface":
                    d["parent"] = v
                elif line.attr == "member":
                    d["members"] = [t.value for t in line.values]
            if not d["ip"] and mode in ("dhcp", "pppoe"):
                d["ip"] = mode
            if not d["type"]:
                d["type"] = "vlan" if d["vlanid"] else "physical"
            out.append(d)
    # second pass: aggregate / redundant bundles and their member ports,
    # so the mapping grid shows the LAG, badges its members, and keeps
    # VLANs nested on the bundle — same awareness as the cross-vendor path
    agg_of: dict[str, str] = {}
    for d in out:
        if d["type"] in ("aggregate", "redundant"):
            for m in d["members"]:
                agg_of[m] = d["name"]
    for d in out:
        if d["type"] in ("aggregate", "redundant"):
            d["kind"] = "aggregate"
        elif d["name"] in agg_of:
            d["kind"] = "aggregate-member"
            d["parent"] = agg_of[d["name"]]
            d["type"] = "physical"   # maps to a target physical port
        elif d["type"] == "vlan" or d["vlanid"]:
            d["kind"] = "vlan"
        elif d["type"] in ("loopback", "tunnel"):
            d["kind"] = d["type"]
        else:
            d["kind"] = "physical"
    return out
