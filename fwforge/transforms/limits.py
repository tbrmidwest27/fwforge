"""FortiOS object-name limits AND table count limits — single source of truth,
plus convert-time backstops for both.

**Name limits** are clamped at the source (parsers, transforms/names.py, the
emitter). `validate_name_limits` is the safety net: it re-reads the emitted
config and warns on any name that still exceeds its FortiOS limit.

**Table count limits** cannot be clamped — if a source config has 150 zones
and FortiOS only allows 100, some will be silently rejected on load.
`validate_table_counts` catches this at convert time so the operator knows
before deploying.

All values schema-verified against a live FortiGate-601F on FortiOS 8.0.0
build0167 (2026-06-17) via read-only GET /api/v2/cmdb/<path>?action=schema.
The `mkey.size` field gives name lengths; `max_table_size_vdom` (or _global
when vdom=0) gives the per-VDOM object cap.  Error codes for violations:
  -1 / -61    name too long
  -162        name collides with a predefined/reserved name
  -651        list entry rejected (missing object, or table full)
  count cap   higher-numbered `edit` blocks silently accepted then rejected
              on commit when the table is already full — always check counts.
"""
from __future__ import annotations

from ..parsers import fortios_tree as ft

# ---------------------------------------------------------------------------
# Name length limits (max chars for the `edit <name>` key)
# ---------------------------------------------------------------------------
# Schema-verified 8.0.0 build0167. UTM/IPS profiles are 47 on 8.0 but capped
# at 35 here so output loads on 7.x targets too (a real 7.x box rejected a
# 36-char IPS sensor name). Raise to 47 when --fortios targets 8.0+.
NAME_LIMITS = {
    ("system", "interface"): 15,          # creates a real interface
    ("system", "switch-interface"): 15,   # software switch — is an interface
    ("system", "virtual-switch"): 15,     # hardware switch group — is an interface
    ("system", "zone"): 35,
    ("firewall", "address"): 79,
    ("firewall", "address6"): 79,
    ("firewall", "addrgrp"): 79,
    ("firewall", "addrgrp6"): 79,
    ("firewall", "vip"): 79,
    ("firewall", "vipgrp"): 79,
    ("firewall", "service", "custom"): 79,
    ("firewall", "service", "group"): 79,
    ("firewall", "schedule", "recurring"): 31,
    ("firewall", "schedule", "onetime"): 31,
    # UTM/IPS profiles: 8.0 schema = 47, kept at the stricter 35 for 7.x
    ("ips", "sensor"): 35,
    ("application", "list"): 35,
    ("webfilter", "profile"): 35,
    ("antivirus", "profile"): 35,
    ("file-filter", "profile"): 35,
    ("dlp", "profile"): 35,
    ("vpn", "ipsec", "phase1-interface"): 15,   # the edit name IS a tunnel iface
    ("vpn", "ipsec", "phase2-interface"): 35,
}
VDOM_NAME_MAX = 11
POLICY_NAME_MAX = 35  # firewall policy `set name` (the edit id is numeric)

# ---------------------------------------------------------------------------
# Table count limits (max `edit` entries per VDOM)
# ---------------------------------------------------------------------------
# Schema field: max_table_size_vdom (or max_table_size_global when vdom cap
# is 0/absent).  0 in the schema means "no limit reported" — omitted here.
# The zone limit (100) is the most dangerous: large PAN configs routinely
# exceed it.  srcintf/dstintf per-policy has no reported limit on 601F 8.0;
# -651 on those lines means a referenced zone/interface does not exist, not
# a count overflow.
TABLE_LIMITS = {
    ("system", "zone"):                 100,    # vdom cap; most likely to hit
    ("firewall", "service", "custom"):  4096,   # vdom cap
    ("firewall", "addrgrp"):            4000,   # global+vdom cap
    ("firewall", "addrgrp6"):           8192,   # global cap
    ("firewall", "address"):            40000,  # global+vdom cap
    ("firewall", "address6"):           40000,  # global+vdom cap
    ("firewall", "vip"):                16384,  # global+vdom cap
    ("firewall", "vipgrp"):             500,    # vdom cap
    ("firewall", "policy"):             30000,  # global+vdom cap
    ("router", "static"):               10000,  # vdom cap
    ("system", "interface"):            8192,   # global cap
}


def _key(path: tuple) -> tuple:
    return tuple(t for t in path if t not in ("global", "vdom"))


def validate_name_limits(out_text: str, report) -> int:
    """Re-parse the emitted config and warn on any object name over its
    FortiOS limit (it would be rejected on load). Returns the hit count;
    a non-zero count is a converter gap, not a source-config problem."""
    tree = ft.parse_config(out_text, "emit")
    hits = 0
    for path, node in ft.iter_config_nodes(tree):
        key = _key(path)
        limit = NAME_LIMITS.get(key)
        if limit is not None:
            for e in node.children:
                if isinstance(e, ft.EditNode) and len(e.name.value) > limit:
                    hits += 1
                    report.add(
                        "warn", "limits",
                        f"emitted {' '.join(key)} name '{e.name.value}' is "
                        f"{len(e.name.value)} chars > FortiOS max {limit} — "
                        "it would be rejected on load (converter gap).")
        elif key == ("firewall", "policy"):
            for e in node.children:
                if not isinstance(e, ft.EditNode):
                    continue
                nm = next((ln for ln in e.children
                           if isinstance(ln, ft.SetLine) and ln.attr == "name"),
                          None)
                if nm and nm.values and len(nm.values[0].value) > POLICY_NAME_MAX:
                    hits += 1
                    report.add(
                        "warn", "limits",
                        f"emitted firewall policy name '{nm.values[0].value}' "
                        f"is {len(nm.values[0].value)} chars > FortiOS max "
                        f"{POLICY_NAME_MAX} (converter gap).")
    return hits


def validate_table_counts(out_text: str, report) -> int:
    """Re-parse the emitted config and warn on any table whose entry count
    exceeds FortiOS's per-VDOM cap.  Returns the hit count."""
    tree = ft.parse_config(out_text, "emit")
    hits = 0
    for path, node in ft.iter_config_nodes(tree):
        key = _key(path)
        limit = TABLE_LIMITS.get(key)
        if limit is None:
            continue
        count = sum(1 for e in node.children if isinstance(e, ft.EditNode))
        if count > limit:
            hits += 1
            report.add(
                "warn", "limits",
                f"emitted {' '.join(key)} has {count} entries > FortiOS "
                f"per-VDOM max {limit} — entries beyond the cap will be "
                "rejected on load. Split across VDOMs or reduce the count.")
    return hits
