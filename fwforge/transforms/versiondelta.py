"""FortiOS version-change artifact scanner (both directions).

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

Downgrades (target older than source) run the same rule table backwards:
renames are reverted (hw-version -> hw-model), default flips warn with
the reverse wording (the default goes BACK on the older build), and
sections/attributes *introduced* after the target are flagged as
dropped-on-load. A standing note reminds that the scan is rule-based —
anything the older firmware doesn't know is silently skipped on load.

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
    #            note-if-section | introduced-section | introduced-attr
    path: tuple[str, ...] = ()  # config-path suffix; () = anywhere
    attr: str = ""
    new: str = ""  # rename target
    level: str = "warn"
    message: str = ""
    # flip-if-absent only: the path is an edit-keyed table, so an EMPTY
    # section means "no entries", not "entry relying on the default"
    edit_table: bool = False
    # wording for the DOWNGRADE direction (flip-if-absent /
    # introduced-*); empty = a generic message is synthesized
    down_message: str = ""


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
        attr="dhgrp", level="warn", edit_table=True,
        message="phase1 has no explicit 'set dhgrp': the default changed "
                "14 -> 20 in FortiOS 8.0, so tunnels to peers pinned at "
                "DH14 stop negotiating — set dhgrp explicitly",
        down_message="phase1 has no explicit 'set dhgrp': the default "
                     "goes back 20 -> 14 below FortiOS 8.0 — peers "
                     "negotiated at DH20 stop matching; set dhgrp "
                     "explicitly"),
    DeltaRule(
        (8, 0), "flip-if-absent", ("vpn", "ipsec", "phase2-interface"),
        attr="dhgrp", level="warn", edit_table=True,
        message="phase2 has no explicit 'set dhgrp': the default changed "
                "5 -> 21 in FortiOS 8.0 — set dhgrp explicitly to match "
                "the peer",
        down_message="phase2 has no explicit 'set dhgrp': the default "
                     "goes back 21 -> 5 below FortiOS 8.0 — set dhgrp "
                     "explicitly to match the peer"),
    DeltaRule(
        (8, 0), "flip-if-absent", ("system", "settings"),
        attr="allow-traffic-redirect", level="warn",
        message="'allow-traffic-redirect' is unset and its default flipped "
                "enable -> disable in 8.0: hairpinned traffic (src and dst "
                "on the same interface) will start dropping — set it "
                "explicitly if you rely on it",
        down_message="'allow-traffic-redirect' is unset: below 8.0 the "
                     "default is enable again, so hairpinned traffic "
                     "(src and dst on the same interface) starts FLOWING "
                     "on the older build — set it explicitly if you "
                     "depend on it being blocked"),
    DeltaRule(
        (8, 0), "introduced-section",
        ("system", "gui-dashboard-collection"), level="warn",
        down_message="'config system gui-dashboard-collection' does not "
                     "exist before FortiOS 8.0 — these entries are "
                     "dropped on load (rebuild admin dashboards under "
                     "'config gui-dashboard' per admin)"),
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


def parse_version(text: str) -> tuple | None:
    """'7.6' -> (7, 6); '7.6.3' / 'v7.6.3' -> (7, 6, 3). A missing patch
    component means 'the train, patch unspecified' — scan() treats that
    as equal to any patch of the same train."""
    m = re.match(r"^\s*v?(\d+)\.(\d+)(?:\.(\d+))?", str(text))
    if not m:
        return None
    if m.group(3) is None:
        return int(m.group(1)), int(m.group(2))
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def source_version_from_header(tree: CTree) -> tuple | None:
    """Read the source FortiOS version from #config-version=PLAT-X.Y.Z-…
    Backup headers always carry the patch, so this returns a 3-tuple."""
    for child in tree.children:
        if isinstance(child, CommentLine) \
                and child.text.startswith("#config-version="):
            m = re.search(r"-(\d+)\.(\d+)\.(\d+)-", child.text)
            if m:
                return (int(m.group(1)), int(m.group(2)),
                        int(m.group(3)))
    return None


def vlabel(v: tuple) -> str:
    return ".".join(str(x) for x in v)


def _pad(v: tuple) -> tuple[int, int, int]:
    return (v[0], v[1], v[2] if len(v) > 2 else 0)


def _edit_label(edit: EditNode) -> str:
    return edit.name.value


def _section_entry_count(node: ConfigNode) -> tuple[int, list[str]]:
    edits = [c for c in node.children if isinstance(c, EditNode)]
    if edits:
        return len(edits), [_edit_label(e) for e in edits[:3]]
    sets = sum(1 for c in node.children if isinstance(c, SetLine))
    if sets:
        return sets, []
    # a section whose body is ONLY nested config (e.g. `config system
    # npu` holding sub-tables) is still PRESENT — removed/note/introduced
    # rules describe the section's existence, so count it as one
    return (1, []) if node.children else (0, [])


def scan(tree: CTree, source: tuple, target: tuple, report) -> dict:
    """Apply every rule whose change version lies between source and
    target — in either direction, at patch granularity when both sides
    carry one. Auto-fixes renames in place (forward or reverted).
    Returns counters; stats['direction'] is 'up' / 'down' / 'none'.

    A patch-less version means 'this train, patch unspecified': within
    the same train it compares equal (picking target '7.6' for a 7.6.6
    source is not a downgrade), across trains it counts as .0 — so
    patch-scoped rules only fire when the crossing is provable."""
    stats = {"artifacts": 0, "auto_fixed": 0, "rules_hit": 0,
             "direction": "none"}
    if source[:2] == target[:2] and (len(source) < 3 or len(target) < 3):
        return stats
    s, t = _pad(source), _pad(target)
    if s == t:
        return stats
    labels = (vlabel(source), vlabel(target))
    if t < s:
        stats["direction"] = "down"
        return _scan_down(tree, s, t, report, stats, labels)
    stats["direction"] = "up"
    return _scan_up(tree, s, t, report, stats)


def _scan_up(tree: CTree, source: tuple, target: tuple, report,
             stats: dict) -> dict:
    active = [r for r in RULES if source < _pad(r.since) <= target]

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
                elif rule.edit_table:
                    # empty edit-keyed table = no entries; nothing relies
                    # on the flipped default
                    continue
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
                f"[{vlabel(rule.since)}] {rule.message}{where}")
    return stats


def _scan_down(tree: CTree, source: tuple, target: tuple, report,
               stats: dict, labels: tuple[str, str]) -> dict:
    """Reverse direction: the config was written for `source` and lands
    on the OLDER `target`. Renames revert, default flips warn with the
    reverse wording, introduced features are flagged as dropped."""
    active = [r for r in RULES if target < _pad(r.since) <= source]
    src_label, tgt_label = labels

    for rule in active:
        hits = 0
        examples: list[str] = []
        message = ""

        if rule.kind == "renamed-attr":
            # the config carries the NEW name; the older build only
            # knows the old one — rename back
            for path, node in iter_config_nodes(tree):
                if rule.path and not path_endswith(path, rule.path):
                    continue
                for child in node.children:
                    targets = [child]
                    if isinstance(child, EditNode):
                        targets = child.children
                    for line in targets:
                        if isinstance(line, SetLine) \
                                and line.attr == rule.new:
                            line.attr = rule.attr
                            hits += 1
                            stats["auto_fixed"] += 1
                            if isinstance(child, EditNode) \
                                    and len(examples) < 3:
                                examples.append(_edit_label(child))
            message = (f"'{rule.new}' does not exist before "
                       f"{vlabel(rule.since)} — auto-renamed "
                       f"back to '{rule.attr}'")
        elif rule.kind == "renamed-section":
            want = rule.path[:-1] + (rule.new,)
            for path, node in iter_config_nodes(tree):
                if path_endswith(path, want):
                    node.path[-1] = rule.path[-1]
                    hits += 1
                    stats["auto_fixed"] += 1
            message = (f"'config {' '.join(want)}' does not exist before "
                       f"{vlabel(rule.since)} — auto-renamed "
                       f"back to 'config {' '.join(rule.path)}'")
        elif rule.kind == "flip-if-absent":
            for path, node in iter_config_nodes(tree):
                if not path_endswith(path, rule.path):
                    continue
                edits = [c for c in node.children
                         if isinstance(c, EditNode)]
                if edits:
                    for e in edits:
                        if not any(isinstance(l, SetLine)
                                   and l.attr == rule.attr
                                   for l in e.children):
                            hits += 1
                            if len(examples) < 3:
                                examples.append(_edit_label(e))
                elif rule.edit_table:
                    continue
                else:
                    if not any(isinstance(c, SetLine)
                               and c.attr == rule.attr
                               for c in node.children):
                        hits += 1
            message = rule.down_message or (
                f"the default for '{rule.attr}' differs on either side "
                f"of {vlabel(rule.since)} — set it explicitly "
                "so behavior survives the downgrade")
        elif rule.kind == "introduced-section":
            for path, node in iter_config_nodes(tree):
                if not path_endswith(path, rule.path):
                    continue
                count, names = _section_entry_count(node)
                if count:
                    hits += count
                    examples += names
            message = rule.down_message or (
                f"'config {' '.join(rule.path)}' does not exist on "
                f"FortiOS {tgt_label} — these entries are dropped on "
                "load")
        elif rule.kind == "introduced-attr":
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
            message = rule.down_message or (
                f"'{rule.attr}' does not exist on FortiOS {tgt_label} — "
                "the line is dropped on load")
        # removed-* and note-if-* rules are upgrade-direction only: the
        # feature they describe cannot appear in a newer-version source

        if hits:
            stats["rules_hit"] += 1
            stats["artifacts"] += hits
            if examples:
                more = " ..." if hits > len(examples) else ""
                where = f" (x{hits}: {', '.join(examples)}{more})"
            else:
                where = f" (x{hits})"
            report.add(
                rule.level, "downgrade",
                f"[{vlabel(rule.since)}] {message}{where}")

    report.add(
        "info", "downgrade",
        f"downgrade scan ({src_label} -> {tgt_label}) is "
        "rule-based and partial: any syntax this older FortiOS does not "
        "know is silently skipped on load — after restoring, run "
        "'diag debug config-error-log read' to see what the box "
        "rejected")
    return stats
