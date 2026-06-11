"""Shared machinery for interface-membership refactors (zones, SD-WAN).

Three jobs, used by both refactors:

- rewrite_policy_refs: replace member-interface tokens with the zone name
  in the config sections where FortiOS accepts zones, deduplicating the
  token list (srcintf "port2" "vlan30" -> srcintf "lan", once).

- dedup_policies: policies that differed only by interface collapse into
  exact duplicates after a rewrite; FortiOS would keep both and the second
  would never match. Merge them, loudly.

- audit_leftovers: after a refactor, sweep the whole tree for remaining
  references to the moved interfaces. References that are legitimate stay
  silent (DHCP servers, IPsec phase1 bindings, the interface's own edit);
  everything else gets a warning with its config path. This is the "all
  the ramifications" safety net — FortiOS rejects configs we miss, so we
  surface them instead.
"""
from __future__ import annotations

from ..parsers.fortios_tree import (
    ConfigNode,
    CTree,
    EditNode,
    SetLine,
    Token,
    iter_config_nodes,
    iter_set_lines,
    path_endswith,
    vdom_scopes,
)
from .plan import PlanError

# config sections whose srcintf/dstintf accept zone names
ZONE_CAPABLE_PATHS: tuple[tuple, ...] = (
    ("firewall", "policy"),
    ("firewall", "security-policy"),
    ("firewall", "shaping-policy"),
    ("firewall", "central-snat-map"),
)

# (config-path suffix, attr) pairs where a moved interface may legitimately
# still be referenced after a zone refactor. "*" matches any attr.
BASE_ALLOWED: frozenset = frozenset({
    (("system", "interface"), "*"),        # the interface's own definition
    (("system", "zone"), "interface"),     # the zone we just created
    (("system", "sdwan", "members"), "interface"),
    (("system", "sdwan", "health-check"), "*"),
    (("system", "dhcp", "server"), "interface"),
    (("vpn", "ipsec", "phase1-interface"), "interface"),
    (("system", "ha"), "*"),               # hbdev / monitor
    (("system", "link-monitor"), "srcintf"),
})

ZONE_EXTRA_ALLOWED: frozenset = frozenset({
    # static routes stay on member interfaces in a zone refactor,
    # and a VIP's extintf may legally remain a zoned interface
    (("router", "static"), "device"),
    (("firewall", "vip"), "extintf"),
})

SDWAN_EXTRA_ALLOWED: frozenset = frozenset({
    # member static routes are handled (and individually warned) by the
    # sdwan transform itself — don't double-report
    (("router", "static"), "device"),
})

# attrs that carry interface names (reused from the portmap engine)
from .portmap import GLOBAL_INTF_ATTRS  # noqa: E402


def rewrite_policy_refs(tree: CTree, mapping: dict[str, str], report,
                        area: str) -> int:
    """Replace member tokens with zone tokens in zone-capable sections.
    Returns the number of policy entries touched."""
    touched = 0
    for path, node in iter_config_nodes(tree):
        if not any(path_endswith(path, p) for p in ZONE_CAPABLE_PATHS):
            continue
        for edit in node.children:
            if not isinstance(edit, EditNode):
                continue
            changed = False
            for line in edit.children:
                if not isinstance(line, SetLine):
                    continue
                if line.attr not in ("srcintf", "dstintf"):
                    continue
                new_vals: list[Token] = []
                seen: set[str] = set()
                for tok in line.values:
                    target = mapping.get(tok.value)
                    if target is None:
                        val_tok = tok
                    else:
                        val_tok = Token(target, True)
                        changed = True
                    if val_tok.value in seen:
                        changed = True  # collapsed a duplicate
                        continue
                    seen.add(val_tok.value)
                    new_vals.append(val_tok)
                line.values = new_vals
            if changed:
                touched += 1
    return touched


def _policy_fingerprint(edit: EditNode) -> tuple:
    """Match-relevant identity of a policy (name/uuid/comments ignored)."""
    lines = []
    for line in edit.children:
        if isinstance(line, SetLine) and line.attr not in (
                "name", "uuid", "comments"):
            lines.append((line.attr, tuple(t.value for t in line.values)))
    return tuple(sorted(lines))


def _edit_label(edit: EditNode) -> str:
    name = ""
    for line in edit.children:
        if isinstance(line, SetLine) and line.attr == "name" and line.values:
            name = line.values[0].value
    return f"{edit.name.value}" + (f" ('{name}')" if name else "")


def dedup_policies(tree: CTree, report) -> int:
    """Remove policies that became exact duplicates after a rewrite."""
    merged = 0
    for path, node in iter_config_nodes(tree):
        if not path_endswith(path, ("firewall", "policy")):
            continue
        seen: dict[tuple, EditNode] = {}
        keep = []
        for child in node.children:
            if not isinstance(child, EditNode):
                keep.append(child)
                continue
            fp = _policy_fingerprint(child)
            if fp in seen:
                merged += 1
                report.add(
                    "warn", "policies",
                    f"policy {_edit_label(child)} became identical to policy "
                    f"{_edit_label(seen[fp])} after the refactor — merged "
                    "(removed the duplicate; it could never match)",
                )
            else:
                seen[fp] = child
                keep.append(child)
        node.children = keep
    return merged


_MATCH_ATTRS = ("srcintf", "dstintf", "srcaddr", "dstaddr", "service",
                "schedule", "action")


def flag_conflicting_policies(tree: CTree, report) -> int:
    """After a zone/SD-WAN rewrite, policies that now match IDENTICAL
    traffic but differ in other settings (NAT, profiles, logging) are not
    exact duplicates — FortiOS keeps both and only the first ever matches.
    Flag them; a human has to reconcile the differing settings."""
    flagged = 0
    for path, node in iter_config_nodes(tree):
        if not path_endswith(path, ("firewall", "policy")):
            continue
        groups: dict[tuple, list[EditNode]] = {}
        for child in node.children:
            if not isinstance(child, EditNode):
                continue
            match = tuple(
                (line.attr, tuple(t.value for t in line.values))
                for line in child.children
                if isinstance(line, SetLine) and line.attr in _MATCH_ATTRS)
            groups.setdefault(tuple(sorted(match)), []).append(child)
        for edits in groups.values():
            if len(edits) < 2:
                continue
            flagged += 1
            labels = ", ".join(_edit_label(e) for e in edits)
            report.add(
                "warn", "policies",
                f"policies {labels} now match identical traffic (same "
                "interfaces/addresses/service) but differ in other "
                "settings (NAT/profiles/logging) — only the first ever "
                "matches; reconcile them into one policy",
            )
    return flagged


def audit_leftovers(tree: CTree, moved: set[str], allowed: frozenset,
                    report, area: str) -> int:
    """Warn about every remaining reference to a moved interface that is
    not on the allowed list."""
    warned = 0
    for path, line in iter_set_lines(tree):
        if line.attr not in GLOBAL_INTF_ATTRS and line.attr != "member":
            continue
        hits = [t.value for t in line.values if t.value in moved]
        if not hits:
            continue
        ok = any(
            path_endswith(path, suffix) and attr in ("*", line.attr)
            for suffix, attr in allowed
        )
        if ok:
            continue
        warned += 1
        report.add(
            "warn", area,
            f"'{', '.join(hits)}' still referenced at "
            f"config {' '.join(path)} (set {line.attr}) — review whether "
            "this should point at the new zone or be removed",
        )
    return warned


def is_multi_vdom(tree: CTree) -> bool:
    for child in tree.children:
        if isinstance(child, ConfigNode) and child.path in (
                ["vdom"], ["global"]):
            return True
    return False


def interface_vdoms(tree: CTree) -> dict[str, str]:
    """interface name -> owning VDOM, read from `set vdom` in
    `config system interface` ('root' when unset)."""
    out: dict[str, str] = {}
    for path, node in iter_config_nodes(tree):
        if not path_endswith(path, ("system", "interface")):
            continue
        for edit in node.children:
            if not isinstance(edit, EditNode):
                continue
            vd = "root"
            for line in edit.children:
                if isinstance(line, SetLine) and line.attr == "vdom" \
                        and line.values:
                    vd = line.values[0].value
            out[edit.name.value] = vd
    return out


def resolve_spec_vdom(members: list[str], ifc_vdoms: dict[str, str],
                      declared: str | None, label: str) -> str:
    """Which VDOM a zone/sdwan spec belongs to — derived from its members,
    cross-checked against an explicit `vdom =` in the plan."""
    vds = {ifc_vdoms.get(m, "root") for m in members}
    if len(vds) > 1:
        raise PlanError(
            f"[{label}]: members span VDOMs {', '.join(sorted(vds))} — "
            "zones and SD-WAN members must stay within one VDOM")
    derived = vds.pop()
    if declared and declared != derived:
        raise PlanError(
            f"[{label}]: plan says vdom={declared} but the members belong "
            f"to VDOM '{derived}'")
    return derived


def vdom_scope(tree: CTree, vdom: str):
    """The container whose children hold a VDOM's config sections."""
    scopes = vdom_scopes(tree)
    if len(scopes) == 1 and scopes[0][0] is None:
        return tree  # single-VDOM: everything is top-level
    for name, container in scopes:
        if name == vdom:
            return container
    raise PlanError(
        f"VDOM '{vdom}' has no configuration section in this config "
        f"(found: {', '.join(n for n, _ in scopes)})")


def insert_in_scope(scope, node: ConfigNode) -> None:
    """Insert a new config section in load-order-safe position: before the
    first firewall/router/vpn section of the scope (i.e. after the system
    sections that define the names it references)."""
    children = scope.children
    idx = len(children)
    for i, child in enumerate(children):
        if isinstance(child, ConfigNode) and child.path \
                and child.path[0] in ("firewall", "router", "vpn"):
            idx = i
            break
    children.insert(idx, node)
