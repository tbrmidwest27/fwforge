"""non-VDOM <-> VDOM mode conversion for FortiOS configs.

FortiConverter can change a config's VDOM mode (and, when loading into an
existing VDOM-enabled box, ignore global-scope config to avoid clobbering
the target's system settings). This module does the same on the tree.

The crux is FortiOS's scope split. When multi-VDOM is enabled:

  config global            <- system-wide objects
      config system global / interface / admin / ha / npu / dns / ntp ...
  config vdom
      edit <vdom>
          config system settings / zone / sdwan / dhcp ...   (per-VDOM)
          config firewall ... / router ... / vpn ... / user ...

So `system.*` is GLOBAL **except** a known per-VDOM subset (settings, zone,
sdwan, dhcp, the tunnel types, ...). Everything outside `system.*`
(firewall, router, vpn, user, the UTM profiles, ...) is per-VDOM.

The split is curated from FortiOS docs and is high-confidence for the
common sections; genuinely ambiguous roots (log, certificates) default to
global and are flagged for review. The full partition is reported so a
human can eyeball it.

wrap   (to_multi_vdom): flat config -> config global + config vdom/edit X
unwrap (to_single_vdom): single-VDOM config -> flat (errors on 2+ VDOMs)
`scope_only` drops global-scope sections on wrap, for loading a config
into an already-configured multi-VDOM box without overwriting its globals.
"""
from __future__ import annotations

import re

from ..parsers.fortios_tree import (
    CommentLine,
    ConfigNode,
    CTree,
    EditNode,
    RawLine,
    SetLine,
    Token,
    iter_config_nodes,
    iter_set_lines,
    path_endswith,
    vdom_scopes,
)

# `config system <sub>` blocks that live INSIDE a VDOM, not in config global
VDOM_SYSTEM = {
    "settings", "zone", "sdwan", "dhcp", "session-ttl", "gre-tunnel",
    "ipip-tunnel", "vxlan", "geneve", "virtual-wire-pair",
    "replacemsg-group", "proxy-arp", "dns-database", "dns-server",
    "sit-tunnel", "mobile-tunnel", "pppoe-interface", "sflow", "nat64",
    "ike", "ipv6-tunnel",
}
# top-level roots (outside system.*) that are global despite not being system
GLOBAL_ROOTS = {"log"}
# roots we flag as scope-ambiguous when present
AMBIGUOUS = {("log",), ("vpn", "certificate")}


def classify(path: tuple) -> str:
    """'global' or 'vdom' for a top-level config section path."""
    if not path:
        return "vdom"
    root = path[0]
    if root == "system":
        sub = path[1] if len(path) > 1 else ""
        return "vdom" if sub in VDOM_SYSTEM else "global"
    if root in GLOBAL_ROOTS:
        return "global"
    return "vdom"


def _rewrite_header(tree: CTree, vdom_flag: int) -> None:
    for child in tree.children:
        if isinstance(child, CommentLine) \
                and child.text.startswith("#config-version="):
            child.text = re.sub(r":vdom=\d+:", f":vdom={vdom_flag}:",
                                child.text)
            return


def _find_section(nodes, *path) -> ConfigNode | None:
    target = list(path)
    for n in nodes:
        if isinstance(n, ConfigNode) and n.path == target:
            return n
    return None


def _set_interface_vdom(iface_node: ConfigNode, vdom: str, add: bool) -> int:
    """Add or strip `set vdom` on every interface edit. Returns count."""
    changed = 0
    for edit in iface_node.children:
        if not isinstance(edit, EditNode):
            continue
        existing = [c for c in edit.children
                    if isinstance(c, SetLine) and c.attr == "vdom"]
        if add:
            if existing:
                existing[0].values = [Token(vdom, True)]
            else:
                edit.children.insert(0, SetLine("vdom", [Token(vdom, True)]))
            changed += 1
        else:
            if existing:
                for e in existing:
                    edit.children.remove(e)
                changed += 1
    return changed


def _set_vdom_mode(global_sections, enable: bool, report) -> None:
    sysglobal = _find_section(global_sections, "system", "global")
    if sysglobal is None:
        return
    line = next((c for c in sysglobal.children
                 if isinstance(c, SetLine) and c.attr == "vdom-mode"), None)
    if enable:
        if line:
            line.values = [Token("multi-vdom", False)]
        else:
            sysglobal.children.insert(0, SetLine(
                "vdom-mode", [Token("multi-vdom", False)]))
    elif line:
        sysglobal.children.remove(line)


def is_multi_vdom(tree: CTree) -> bool:
    return any(isinstance(c, ConfigNode) and c.path in (["global"], ["vdom"])
              for c in tree.children)


def to_multi_vdom(tree: CTree, report, vdom_name: str = "root",
                  scope_only: bool = False) -> dict:
    if is_multi_vdom(tree):
        report.add("info", "vdom-mode",
                   "config is already multi-VDOM — mode conversion skipped")
        return {"converted": False}

    header = [c for c in tree.children
              if isinstance(c, (CommentLine, RawLine))]
    sections = [c for c in tree.children if isinstance(c, ConfigNode)]
    global_sections = [n for n in sections
                       if classify(tuple(n.path)) == "global"]
    vdom_sections = [n for n in sections
                     if classify(tuple(n.path)) == "vdom"]

    iface = _find_section(global_sections, "system", "interface")
    if iface is not None:
        n = _set_interface_vdom(iface, vdom_name, add=True)
        report.add("info", "vdom-mode",
                   f"assigned {n} interface(s) to VDOM '{vdom_name}'")
    _set_vdom_mode(global_sections, True, report)

    for amb in AMBIGUOUS:
        if any(tuple(n.path[:len(amb)]) == amb for n in global_sections):
            report.add("warn", "vdom-mode",
                       f"section '{' '.join(amb)}' placed in global scope — "
                       "verify; it may belong per-VDOM in your deployment")

    _rewrite_header(tree, 1)
    new_children: list = list(header)
    decl = ConfigNode(["vdom"])
    decl.children = [EditNode(Token(vdom_name, True))]
    new_children.append(decl)

    if scope_only:
        report.add("warn", "vdom-mode",
                   f"scope-only: dropped {len(global_sections)} global-scope "
                   "section(s) ("
                   + ", ".join(" ".join(n.path) for n in global_sections[:8])
                   + (" …" if len(global_sections) > 8 else "")
                   + ") so this loads into an existing VDOM without "
                   "overwriting the box's global config")
    else:
        gnode = ConfigNode(["global"])
        gnode.children = global_sections
        new_children.append(gnode)

    vnode = ConfigNode(["vdom"])
    vedit = EditNode(Token(vdom_name, True))
    vedit.children = vdom_sections
    vnode.children = [vedit]
    new_children.append(vnode)
    tree.children = new_children

    report.add("info", "vdom-mode",
               f"wrapped flat config into multi-VDOM form: "
               f"{0 if scope_only else len(global_sections)} global + "
               f"{len(vdom_sections)} per-VDOM section(s) under '{vdom_name}'")
    return {"converted": True, "global": len(global_sections),
            "vdom": len(vdom_sections), "vdom_name": vdom_name}


def to_single_vdom(tree: CTree, report) -> dict:
    scopes = vdom_scopes(tree)
    if len(scopes) == 1 and scopes[0][0] is None:
        report.add("info", "vdom-mode",
                   "config is already single/flat — nothing to unwrap")
        return {"converted": False}
    real = [(n, c) for n, c in scopes if n not in (None, "global")]
    if len(real) != 1:
        names = ", ".join(n for n, _ in real)
        report.add("error", "vdom-mode",
                   f"cannot flatten a config with {len(real)} VDOMs "
                   f"({names}) — flat configs hold one VDOM. Extract a "
                   "single VDOM first.")
        return {"converted": False, "vdoms": len(real)}

    vdom_name, vedit = real[0]
    global_node = _find_section(tree.children, "global")
    header = [c for c in tree.children
              if isinstance(c, (CommentLine, RawLine))]

    global_children = list(global_node.children) if global_node else []
    iface = _find_section(global_children, "system", "interface")
    if iface is not None:
        _set_interface_vdom(iface, vdom_name, add=False)
    _set_vdom_mode(global_children, False, report)

    _rewrite_header(tree, 0)
    tree.children = header + global_children + list(vedit.children)
    report.add("info", "vdom-mode",
               f"flattened VDOM '{vdom_name}' into a non-VDOM config "
               f"({len(global_children)} global + {len(vedit.children)} "
               "per-VDOM section(s) merged)")
    return {"converted": True, "vdom_name": vdom_name}


VDOM_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,11}$")


def rename_vdoms(tree: CTree, mapping: dict[str, str], report) -> dict:
    """Rename VDOMs across a multi-VDOM tree (FortiConverter's "VDOM
    Mapping"): `config vdom` edit names, every interface's `set vdom`,
    `management-vdom`, and `system vdom-property` entries.

    Raises PlanError on invalid mappings (FortiOS VDOM names are max 11
    chars of letters/digits/_-)."""
    from .plan import PlanError

    mapping = {s: d for s, d in mapping.items() if s and d and s != d}
    if not mapping:
        return {"edits": 0, "refs": 0}
    if not is_multi_vdom(tree):
        raise PlanError("[vdommap]: VDOM mapping needs a multi-VDOM source "
                        "config")
    existing = [n for n, _ in vdom_scopes(tree) if n not in (None, "global")]
    for s, d in mapping.items():
        if s not in existing:
            raise PlanError(
                f"[vdommap]: source VDOM '{s}' is not in this config "
                f"(found: {', '.join(existing)})")
        if not VDOM_NAME_RE.match(d):
            raise PlanError(
                f"[vdommap]: target VDOM name '{d}' invalid — max 11 "
                "characters, letters/digits/_/- only")
        if d in existing and d not in mapping:
            raise PlanError(
                f"[vdommap]: target VDOM name '{d}' already exists in the "
                "config")
    targets = list(mapping.values())
    if len(set(targets)) != len(targets):
        raise PlanError("[vdommap]: two VDOMs are mapped to the same "
                        "target name")

    edits = 0
    refs = 0
    for child in tree.children:
        if isinstance(child, ConfigNode) and child.path == ["vdom"]:
            for e in child.children:
                if isinstance(e, EditNode) and e.name.value in mapping:
                    e.name = Token(mapping[e.name.value], e.name.quoted)
                    edits += 1
    for path, node in iter_config_nodes(tree):
        if path_endswith(path, ("system", "vdom-property")):
            for e in node.children:
                if isinstance(e, EditNode) and e.name.value in mapping:
                    e.name = Token(mapping[e.name.value], True)
                    edits += 1
    for path, line in iter_set_lines(tree):
        if line.attr in ("vdom", "management-vdom"):
            new_vals = []
            for t in line.values:
                if t.value in mapping:
                    new_vals.append(Token(mapping[t.value], t.quoted))
                    refs += 1
                else:
                    new_vals.append(t)
            line.values = new_vals

    report.add("info", "vdom",
               "renamed VDOM(s): "
               + ", ".join(f"{s} -> {d}" for s, d in mapping.items())
               + f" ({edits} edit(s), {refs} reference(s) updated)")
    return {"edits": edits, "refs": refs}


def apply(tree: CTree, mode: str, report, vdom_name: str = "root",
          scope_only: bool = False) -> dict:
    if mode == "multi":
        return to_multi_vdom(tree, report, vdom_name, scope_only)
    if mode == "single":
        return to_single_vdom(tree, report)
    return {"converted": False}
