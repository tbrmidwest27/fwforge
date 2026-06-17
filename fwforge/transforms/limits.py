"""FortiOS object-name limits — the single source of truth, plus a
convert-time backstop.

Names are clamped at the source (the parsers, transforms/names.py, the
emitter). `validate_name_limits` is the safety net: it re-reads the emitted
config and warns on any name that still exceeds its FortiOS limit, so a
future emit path that forgets to clamp surfaces as a convert-time warning
instead of a silent `-1` / `-162` when the config is loaded on the box.

Schema-verified against a live FortiGate-601F on FortiOS 8.0.0 build0167
(2026-06-17, per-table `?action=schema` -> mkey `size`). Every value below is
exact on 8.0 EXCEPT the UTM / IPS profiles: 8.0 allows 47, but they are kept
at the stricter 35 (older-FortiOS limit) so output loads on 7.x and 8.x alike
— a real 7.x target rejected a 36-char IPS sensor name. If fwforge ever keys
limits off the `--fortios` target, the UTM cap can rise to 47 for 8.0+.
"""
from __future__ import annotations

from ..parsers import fortios_tree as ft

# max name length (chars) keyed by config-section path (the `config global` /
# `config vdom` wrappers are stripped before lookup)
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
