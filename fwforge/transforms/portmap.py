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
}

# config paths whose `edit <name>` entries ARE interface names
EDIT_RENAME_PATHS = {("system", "interface")}


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

    def mapped(name: str) -> str:
        if name in ("any", "all", "") or name in skip_names:
            return name
        if name in mapping:
            return mapping[name]
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
    from ..parsers.fortios_tree import iter_set_lines, path_endswith

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
                 "role": "", "status": "", "vdom": ""}
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
            if not d["ip"] and mode in ("dhcp", "pppoe"):
                d["ip"] = mode
            if not d["type"]:
                d["type"] = "vlan" if d["vlanid"] else "physical"
            out.append(d)
    return out
