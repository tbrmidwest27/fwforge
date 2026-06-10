"""Hardware-switch -> software-switch conversion.

Desktop/mid FortiGates bundle physical ports into a line-rate hardware
switch: an interface with `set type hard-switch` and `set member ...`,
backed by `config system virtual-switch` (port membership on the switch
chip) and `config system physical-switch` (the chip itself). A target
model without that same switch fabric can't load those, so the bridge is
re-expressed as a CPU-based software switch (`set type switch`), keeping
the same name, IP, allowaccess and member ports — so every policy/route/
VLAN that referenced the bundle keeps working untouched.

Only the interface `type` changes (and the now-dead hardware-switch
infrastructure sections are dropped). Member port renames, if any, are
handled by the interface-mapping pass, not here.

hard-switch-vlan interfaces are flagged for manual review rather than
guessed at (they carry VLAN semantics a plain software switch loses); when
any remain, the virtual/physical-switch sections are kept.
"""
from __future__ import annotations

from ..parsers.fortios_tree import (
    ConfigNode,
    CTree,
    EditNode,
    SetLine,
    Token,
    iter_config_nodes,
    path_endswith,
)


def _iface_type(edit: EditNode) -> SetLine | None:
    for c in edit.children:
        if isinstance(c, SetLine) and c.attr == "type":
            return c
    return None


def _global_container(tree: CTree) -> ConfigNode | None:
    for c in tree.children:
        if isinstance(c, ConfigNode) and c.path == ["global"]:
            return c
    return None


def _drop_sections(tree: CTree, paths: set[tuple], report) -> int:
    """Remove top-level (flat) or config-global (multi-VDOM) sections."""
    dropped = 0
    containers = [tree]
    g = _global_container(tree)
    if g is not None:
        containers.append(g)
    for cont in containers:
        keep = []
        for c in cont.children:
            if isinstance(c, ConfigNode) and tuple(c.path) in paths:
                dropped += 1
                report.add("info", "hw-switch",
                           f"dropped 'config {' '.join(c.path)}' — "
                           "hardware-switch infrastructure has no meaning on "
                           "a software-switch target")
            else:
                keep.append(c)
        cont.children = keep
    return dropped


def convert(tree: CTree, report) -> dict:
    converted: list[str] = []
    remaining = 0

    for path, node in iter_config_nodes(tree):
        if not path_endswith(path, ("system", "interface")):
            continue
        for edit in node.children:
            if not isinstance(edit, EditNode):
                continue
            tline = _iface_type(edit)
            if tline is None or not tline.values:
                continue
            kind = tline.values[0].value
            if kind == "hard-switch":
                tline.values = [Token("switch", False)]
                converted.append(edit.name.value)
            elif kind == "hard-switch-vlan":
                remaining += 1
                report.add(
                    "warn", "hw-switch",
                    f"interface '{edit.name.value}' is hard-switch-vlan — "
                    "left as-is; rebuild it as a software switch plus a "
                    "VLAN sub-interface manually (it carries a VLAN the "
                    "plain software switch can't express)")

    if not converted and not remaining:
        report.add("info", "hw-switch",
                   "no hardware-switch interfaces found — nothing to convert")
        return {"converted": 0, "dropped": 0}

    if converted:
        report.add(
            "warn", "hw-switch",
            f"converted {len(converted)} hardware-switch interface(s) to "
            f"software switches: {', '.join(converted)}. A software switch "
            "bridges in the CPU (no NP offload) — fine for management/low-"
            "throughput segments; for line-rate use native ports or "
            "FortiSwitch.")

    dropped = 0
    if not remaining:
        dropped = _drop_sections(
            tree, {("system", "virtual-switch"),
                   ("system", "physical-switch")}, report)
    else:
        report.add("info", "hw-switch",
                   "kept system virtual-switch / physical-switch — still "
                   "referenced by hard-switch-vlan interface(s)")
    return {"converted": len(converted), "dropped": dropped}
