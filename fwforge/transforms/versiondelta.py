"""FortiOS version-upgrade artifact scanner.

When a FortiGate-to-FortiGate conversion also jumps FortiOS versions
(e.g. a 7.4 config landing on an 8.0 box), three classes of artifacts
remain in the config:

- **removed** sections/attributes: the target FortiOS silently drops them
  on load (they only show up in `diag debug config-error-log read`)
- **renamed** commands: safe ones are auto-fixed here and reported
- **default flips**: the nastiest kind — the config line was never written
  because it relied on the old default, and the new firmware quietly uses
  a different one (8.0 changed IPsec DH groups, hairpin redirect, inline
  IPS). No diff will ever show these; only a rule base can.

The rule table is curated from Fortinet release notes ("Changes in CLI" /
"Changes in default behavior"). It is deliberately conservative and
partial — extend RULES as new versions land.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..parsers.fortios_tree import (
    ConfigNode,
    CTree,
    CommentLine,
    EditNode,
    SetLine,
    iter_config_nodes,
    path_endswith,
)


@dataclass
class DeltaRule:
    since: tuple[int, int]  # FortiOS version where the change lands
    kind: str  # removed-section | removed-attr | renamed-attr |
    #            renamed-section | flip-if-absent | note-if-attr |
    #            note-if-section
    path: tuple[str, ...] = ()  # config-path suffix; () = anywhere
    attr: str = ""
    new: str = ""  # rename target
    level: str = "warn"
    message: str = ""


RULES: list[DeltaRule] = [
    # ----- FortiOS 7.6 -------------------------------------------------
    DeltaRule(
        (7, 6), "removed-section", ("vpn", "ssl", "settings"), level="error",
        message="SSL-VPN tunnel mode was removed in FortiOS 7.6 — this "
                "config still carries 'vpn ssl settings'; migrate remote "
                "access to IKEv2/IPsec dial-up before the cutover"),
    DeltaRule(
        (7, 6), "removed-section", ("vpn", "ssl", "web", "portal"),
        level="warn",
        message="SSL-VPN portals present — removed in FortiOS 7.6; these "
                "entries are dropped on load"),
    # ----- FortiOS 8.0 -------------------------------------------------
    DeltaRule(
        (8, 0), "flip-if-absent", ("vpn", "ipsec", "phase1-interface"),
        attr="dhgrp", level="warn",
        message="phase1 has no explicit 'set dhgrp': the default changed "
                "14 -> 20 in FortiOS 8.0, so tunnels to peers pinned at "
                "DH14 stop negotiating — set dhgrp explicitly"),
    DeltaRule(
        (8, 0), "flip-if-absent", ("vpn", "ipsec", "phase2-interface"),
        attr="dhgrp", level="warn",
        message="phase2 has no explicit 'set dhgrp': the default changed "
                "5 -> 21 in FortiOS 8.0 — set dhgrp explicitly to match "
                "the peer"),
    DeltaRule(
        (8, 0), "flip-if-absent", ("system", "settings"),
        attr="allow-traffic-redirect", level="warn",
        message="'allow-traffic-redirect' is unset and its default flipped "
                "enable -> disable in 8.0: hairpinned traffic (src and dst "
                "on the same interface) will start dropping — set it "
                "explicitly if you rely on it"),
    DeltaRule(
        (8, 0), "removed-section", ("system", "admin", "gui-dashboard"),
        level="warn",
        message="'config gui-dashboard' under system admin was removed in "
                "8.0 (replaced by system gui-dashboard-collection) — these "
                "entries are dropped on load"),
    DeltaRule(
        (8, 0), "removed-attr", (), attr="intra-vap-privacy", level="warn",
        message="'intra-vap-privacy' was removed in 8.0 — the line is "
                "dropped on load"),
    DeltaRule(
        (8, 0), "renamed-attr", ("firewall", "address"), attr="hw-model",
        new="hw-version", level="info",
        message="firewall address 'hw-model' renamed to 'hw-version' in "
                "8.0 — auto-renamed"),
    DeltaRule(
        (8, 0), "note-if-attr", ("firewall", "policy"), attr="ips-sensor",
        level="warn",
        message="IPS inline enforcement defaults to DISABLED in 8.0 — "
                "policies with IPS sensors run detection-only until inline "
                "mode is re-enabled; verify after the move"),
    DeltaRule(
        (8, 0), "note-if-section", ("system", "npu"), level="info",
        message="NP7 defaults changed in 8.0 (VLAN lookup cache off, "
                "dedicated message queue) — review 'config system npu' "
                "tuning on the new box"),
    # ----- legacy helper (very old sources) -----------------------------
    DeltaRule(
        (6, 4), "renamed-section", ("system", "virtual-wan-link"),
        new="sdwan", level="info",
        message="'config system virtual-wan-link' became 'config system "
                "sdwan' in 6.4 — auto-renamed; review member/zone syntax"),
]


def parse_version(text: str) -> tuple[int, int] | None:
    m = re.match(r"^\s*v?(\d+)\.(\d+)", str(text))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def source_version_from_header(tree: CTree) -> tuple[int, int] | None:
    """Read the source FortiOS version from #config-version=PLAT-X.Y.Z-…"""
    for child in tree.children:
        if isinstance(child, CommentLine) \
                and child.text.startswith("#config-version="):
            m = re.search(r"-(\d+)\.(\d+)\.\d+-", child.text)
            if m:
                return int(m.group(1)), int(m.group(2))
    return None


def _edit_label(edit: EditNode) -> str:
    return edit.name.value


def _section_entry_count(node: ConfigNode) -> tuple[int, list[str]]:
    edits = [c for c in node.children if isinstance(c, EditNode)]
    if edits:
        return len(edits), [_edit_label(e) for e in edits[:3]]
    sets = sum(1 for c in node.children if isinstance(c, SetLine))
    return (sets, []) if sets else (0, [])


def scan(tree: CTree, source: tuple[int, int], target: tuple[int, int],
         report) -> dict:
    """Apply every rule whose change version lies in (source, target].
    Auto-fixes renames in place. Returns counters."""
    stats = {"artifacts": 0, "auto_fixed": 0, "rules_hit": 0}
    if target <= source:
        return stats
    active = [r for r in RULES if source < r.since <= target]

    for rule in active:
        hits = 0
        examples: list[str] = []

        if rule.kind in ("removed-section", "note-if-section"):
            for path, node in iter_config_nodes(tree):
                if not path_endswith(path, rule.path):
                    continue
                count, names = _section_entry_count(node)
                if count:
                    hits += count
                    examples += names
        elif rule.kind == "renamed-section":
            for path, node in iter_config_nodes(tree):
                if path_endswith(path, rule.path):
                    node.path[-1] = rule.new
                    hits += 1
                    stats["auto_fixed"] += 1
        elif rule.kind in ("removed-attr", "renamed-attr", "note-if-attr"):
            for path, node in iter_config_nodes(tree):
                if rule.path and not path_endswith(path, rule.path):
                    continue
                for child in node.children:
                    targets = [child]
                    if isinstance(child, EditNode):
                        targets = child.children
                    for line in targets:
                        if isinstance(line, SetLine) \
                                and line.attr == rule.attr:
                            hits += 1
                            if isinstance(child, EditNode) \
                                    and len(examples) < 3:
                                examples.append(_edit_label(child))
                            if rule.kind == "renamed-attr":
                                line.attr = rule.new
                                stats["auto_fixed"] += 1
        elif rule.kind == "flip-if-absent":
            for path, node in iter_config_nodes(tree):
                if not path_endswith(path, rule.path):
                    continue
                edits = [c for c in node.children if isinstance(c, EditNode)]
                if edits:
                    for e in edits:
                        if not any(isinstance(l, SetLine)
                                   and l.attr == rule.attr
                                   for l in e.children):
                            hits += 1
                            if len(examples) < 3:
                                examples.append(_edit_label(e))
                else:
                    if not any(isinstance(c, SetLine)
                               and c.attr == rule.attr
                               for c in node.children):
                        hits += 1

        if hits:
            stats["rules_hit"] += 1
            stats["artifacts"] += hits
            if examples:
                more = " ..." if hits > len(examples) else ""
                where = f" (x{hits}: {', '.join(examples)}{more})"
            else:
                where = f" (x{hits})"
            report.add(
                rule.level, "upgrade",
                f"[{rule.since[0]}.{rule.since[1]}] {rule.message}{where}")
    return stats
