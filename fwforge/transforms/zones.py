"""Fold interfaces into zones — with all the ramifications.

FortiOS refuses to add an interface to a zone while any firewall policy
references it directly, so a converted config must arrive with the zone
defined AND every policy reference rewritten. This transform:

1. validates members (exist, not already in a zone, not SD-WAN members)
2. creates the zone (or extends an existing zone of the same name),
   defaulting to `intrazone deny` so policy enforcement between members
   is preserved
3. rewrites srcintf/dstintf in every zone-capable section, collapsing
   duplicate tokens
4. flags policies that became same-zone (member-to-member traffic now
   crosses the zone boundary's intrazone setting)

Duplicate-policy merging and the leftover-reference audit run from the
caller, shared with the SD-WAN transform.
"""
from __future__ import annotations

from ..parsers.fortios_tree import (
    ConfigNode,
    CTree,
    EditNode,
    SetLine,
    Token,
    find_config_under,
    iter_config_nodes,
    path_endswith,
)
from .plan import PlanError, ZoneSpec
from .portmap import tree_interface_names
from .tree_refs import (
    insert_in_scope,
    interface_vdoms,
    resolve_spec_vdom,
    rewrite_policy_refs,
    vdom_scope,
)


def existing_zone_members(tree: CTree) -> dict[str, str]:
    """interface -> zone name, from `config system zone`."""
    members: dict[str, str] = {}
    for path, node in iter_config_nodes(tree):
        if not path_endswith(path, ("system", "zone")):
            continue
        for edit in node.children:
            if not isinstance(edit, EditNode):
                continue
            for line in edit.children:
                if isinstance(line, SetLine) and line.attr == "interface":
                    for tok in line.values:
                        members[tok.value] = edit.name.value
    return members


def existing_sdwan_members(tree: CTree) -> set[str]:
    found: set[str] = set()
    for path, node in iter_config_nodes(tree):
        if not path_endswith(path, ("system", "sdwan", "members")):
            continue
        for edit in node.children:
            if not isinstance(edit, EditNode):
                continue
            for line in edit.children:
                if isinstance(line, SetLine) and line.attr == "interface":
                    found.update(t.value for t in line.values)
    return found


def validate(tree: CTree, specs: list[ZoneSpec]) -> None:
    interfaces = set(tree_interface_names(tree))
    zoned = existing_zone_members(tree)
    sdwan = existing_sdwan_members(tree)
    claimed: dict[str, str] = {}
    for spec in specs:
        if spec.name in interfaces:
            raise PlanError(
                f"[zone {spec.name}]: an interface with that name exists — "
                "FortiOS zones and interfaces share one reference "
                "namespace; pick another zone name")
        for m in spec.members:
            if m not in interfaces:
                raise PlanError(
                    f"[zone {spec.name}]: '{m}' is not an interface in this "
                    "config (after portmap)")
            if m in zoned and zoned[m] != spec.name:
                raise PlanError(
                    f"[zone {spec.name}]: '{m}' is already in zone "
                    f"'{zoned[m]}' — an interface can be in only one zone")
            if m in sdwan:
                raise PlanError(
                    f"[zone {spec.name}]: '{m}' is an SD-WAN member — it "
                    "cannot also join a regular zone")
            if m in claimed and claimed[m] != spec.name:
                raise PlanError(
                    f"'{m}' is listed in both [zone {claimed[m]}] and "
                    f"[zone {spec.name}]")
            claimed[m] = spec.name


def _ensure_zone_section(scope) -> ConfigNode:
    node = find_config_under(scope, "system", "zone")
    if node is None:
        node = ConfigNode(["system", "zone"])
        insert_in_scope(scope, node)
    return node


def _upsert_zone(section: ConfigNode, spec: ZoneSpec, report) -> None:
    for edit in section.children:
        if isinstance(edit, EditNode) and edit.name.value == spec.name:
            # extend the existing zone's member list
            for line in edit.children:
                if isinstance(line, SetLine) and line.attr == "interface":
                    have = {t.value for t in line.values}
                    line.values += [Token(m, True) for m in spec.members
                                    if m not in have]
                    report.add("info", "zones",
                               f"extended existing zone '{spec.name}' with "
                               f"{', '.join(spec.members)}")
                    return
            edit.children.append(
                SetLine("interface", [Token(m, True) for m in spec.members]))
            report.add("info", "zones",
                       f"extended existing zone '{spec.name}' with "
                       f"{', '.join(spec.members)}")
            return
    edit = EditNode(Token(spec.name, True))
    edit.children.append(SetLine("intrazone", [Token(spec.intrazone, False)]))
    edit.children.append(
        SetLine("interface", [Token(m, True) for m in spec.members]))
    section.children.append(edit)
    where = f" in VDOM '{spec.vdom}'" if spec.vdom else ""
    report.add("info", "zones",
               f"created zone '{spec.name}' (intrazone {spec.intrazone})"
               f"{where} with members: {', '.join(spec.members)}")


# sections whose entries can carry `set associated-interface`
_ADDR_PATHS: tuple[tuple, ...] = (
    ("firewall", "address"),
    ("firewall", "addrgrp"),
    ("firewall", "address6"),
    ("firewall", "addrgrp6"),
)


def _rebind_associated_addresses(scope, mapping: dict[str, str],
                                 report) -> int:
    """FortiOS restricts an associated-interface-bound address to
    policies on that exact interface — a zone containing the member does
    not satisfy the check, so a policy rewritten to the zone would
    reject the address at load. The field's datasource is
    system.interface.name + system.zone.name (verified read-only against
    a live FortiOS 8.0 box), so a zone is a valid value — rebind member
    -> zone along with the policies. (Contrast the interface-subnet
    `interface` field, datasource system.interface.name ONLY, which is
    why ZONE_EXTRA_ALLOWED keeps it on the member.)"""
    rebound = 0
    for path, node in iter_config_nodes(scope):
        if not any(path_endswith(path, p) for p in _ADDR_PATHS):
            continue
        for edit in node.children:
            if not isinstance(edit, EditNode):
                continue
            for line in edit.children:
                if not isinstance(line, SetLine) or not line.values:
                    continue
                if line.attr != "associated-interface":
                    continue
                target = mapping.get(line.values[0].value)
                if target is None:
                    continue
                old = line.values[0].value
                line.values = [Token(target, True)]
                rebound += 1
                report.add(
                    "info", "zones",
                    f"address '{edit.name.value}': associated-interface "
                    f"rebound '{old}' -> zone '{target}' (member-bound "
                    "addresses cannot be used by policies that now "
                    "reference the zone)")
    return rebound


def _flag_same_zone_policies(scope, zone_names: set[str],
                             report) -> None:
    for path, node in iter_config_nodes(scope):
        if not (path_endswith(path, ("firewall", "policy"))
                or path_endswith(path, ("firewall", "security-policy"))):
            continue
        for edit in node.children:
            if not isinstance(edit, EditNode):
                continue
            src = dst = None
            for line in edit.children:
                if isinstance(line, SetLine) and line.attr == "srcintf":
                    src = {t.value for t in line.values}
                if isinstance(line, SetLine) and line.attr == "dstintf":
                    dst = {t.value for t in line.values}
            if src and dst and src == dst and src <= zone_names:
                report.add(
                    "info", "zones",
                    f"policy {edit.name.value} is now same-zone "
                    f"({'/'.join(src)} -> itself) — kept; it still applies "
                    "because the zone is 'intrazone deny'",
                )


def apply_zones(tree: CTree, specs: list[ZoneSpec], report) -> dict:
    """Returns stats: zones created, policies rewritten."""
    validate(tree, specs)
    ifc_vdoms = interface_vdoms(tree)
    mapping: dict[str, str] = {}             # combined, returned for callers
    by_vdom: dict[str, dict[str, str]] = {}  # per-VDOM member -> zone
    for spec in specs:
        vd = resolve_spec_vdom(spec.members, ifc_vdoms, spec.vdom,
                               f"zone {spec.name}")
        scope = vdom_scope(tree, vd)
        section = _ensure_zone_section(scope)
        spec.vdom = vd
        _upsert_zone(section, spec, report)
        for m in spec.members:
            mapping[m] = spec.name
            by_vdom.setdefault(vd, {})[m] = spec.name
        if spec.intrazone == "allow":
            report.add(
                "warn", "zones",
                f"zone '{spec.name}' is 'intrazone allow': traffic between "
                f"{', '.join(spec.members)} will flow without policies, "
                "logging, or inspection — confirm this is intended",
            )
    # Rewrite references within EACH VDOM's own scope, using only that VDOM's
    # member->zone map — a same-named interface (vlan30, agg1, ...) in another
    # VDOM must not be rewritten to a zone that exists only here. For a
    # single-VDOM config vdom_scope() returns the whole tree, so behavior is
    # unchanged there.
    zone_names = {s.name for s in specs}
    touched = 0
    rebound = 0
    for vd, vd_mapping in by_vdom.items():
        scope = vdom_scope(tree, vd)
        touched += rewrite_policy_refs(scope, vd_mapping, report, "zones")
        rebound += _rebind_associated_addresses(scope, vd_mapping, report)
        _flag_same_zone_policies(scope, zone_names, report)
    return {"zones": len(specs), "policies_rewritten": touched,
            "addresses_rebound": rebound, "mapping": mapping}
