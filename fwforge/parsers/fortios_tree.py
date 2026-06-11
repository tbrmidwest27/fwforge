"""Structural parser for FortiOS CLI configs.

Parses `config / edit / set / unset / next / end` text into a tree and
serializes it back. This powers FortiOS -> FortiOS model migration, where
the goal is the opposite of cross-vendor conversion: keep *everything*,
including sections this tool knows nothing about, and apply only deliberate
transforms (interface renames). Unknown config survives verbatim.

Handles the two traps in real-world configs:
- quoted values that span physical lines (certificates, scripts)
- backslash escapes inside double quotes
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, NamedTuple


class Token(NamedTuple):
    value: str
    quoted: bool


class UnbalancedQuote(Exception):
    """A quoted value continues past end-of-line (multi-line value)."""


_BARE_SAFE = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:/-+@"
)


def split_line(line: str) -> list[Token]:
    """Tokenize one logical config line. Raises UnbalancedQuote if a
    double-quoted value is still open at end of line."""
    tokens: list[Token] = []
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if ch in " \t":
            i += 1
            continue
        if ch == '"':
            i += 1
            buf = []
            closed = False
            while i < n:
                c = line[i]
                if c == "\\" and i + 1 < n:
                    buf.append(line[i + 1])
                    i += 2
                    continue
                if c == '"':
                    closed = True
                    i += 1
                    break
                buf.append(c)
                i += 1
            if not closed:
                raise UnbalancedQuote("".join(buf))
            tokens.append(Token("".join(buf), True))
        else:
            j = i
            while j < n and line[j] not in " \t":
                j += 1
            tokens.append(Token(line[i:j], False))
            i = j
    return tokens


def format_token(tok: Token) -> str:
    v = tok.value
    needs_quote = tok.quoted or v == "" or any(c not in _BARE_SAFE for c in v)
    if not needs_quote:
        return v
    escaped = v.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


@dataclass
class SetLine:
    attr: str
    values: list[Token]
    line: int = 0


@dataclass
class UnsetLine:
    attr: str
    line: int = 0


@dataclass
class CommentLine:
    text: str  # verbatim, including leading '#'
    line: int = 0


@dataclass
class RawLine:
    text: str  # anything we don't recognize — preserved verbatim
    line: int = 0


@dataclass
class EditNode:
    name: Token
    children: list = field(default_factory=list)
    line: int = 0


@dataclass
class ConfigNode:
    path: list[str]  # e.g. ["firewall", "policy"]
    children: list = field(default_factory=list)
    line: int = 0


@dataclass
class CTree:
    children: list = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    filename: str = ""


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Join physical lines while a double-quoted value is open, preserving
    the newline inside the value."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start = i
        buf = lines[i]
        if buf.lstrip().startswith("#"):
            # comments never open quoted values; joining here would swallow
            # real config lines after a stray quote in an annotation
            yield start + 1, buf
            i += 1
            continue
        while True:
            try:
                split_line(buf)
                break
            except UnbalancedQuote:
                i += 1
                if i >= len(lines):
                    break  # unterminated at EOF; emit as-is
                buf += "\n" + lines[i]
        yield start + 1, buf
        i += 1


def parse_config(text: str, filename: str = "") -> CTree:
    tree = CTree(filename=filename)
    stack: list = [tree]

    for lineno, line in _logical_lines(text):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            stack[-1].children.append(CommentLine(line.rstrip(), lineno))
            continue
        try:
            tokens = split_line(stripped)
        except UnbalancedQuote:
            stack[-1].children.append(RawLine(line.rstrip(), lineno))
            tree.warnings.append(f"line {lineno}: unterminated quote")
            continue
        if not tokens:
            continue
        head = tokens[0].value

        if head == "config" and len(tokens) > 1:
            node = ConfigNode([t.value for t in tokens[1:]], line=lineno)
            stack[-1].children.append(node)
            stack.append(node)
        elif head == "edit" and isinstance(stack[-1], ConfigNode):
            name = tokens[1] if len(tokens) > 1 else Token("", True)
            node = EditNode(name, line=lineno)
            stack[-1].children.append(node)
            stack.append(node)
        elif head == "next":
            if isinstance(stack[-1], EditNode):
                stack.pop()
            else:
                tree.warnings.append(f"line {lineno}: stray 'next'")
        elif head == "end":
            # pop the innermost ConfigNode (closing an unclosed edit first
            # mirrors FortiOS CLI tolerance)
            while len(stack) > 1 and isinstance(stack[-1], EditNode):
                stack.pop()
            if isinstance(stack[-1], ConfigNode):
                stack.pop()
            else:
                tree.warnings.append(f"line {lineno}: stray 'end'")
        elif head == "set" and len(tokens) >= 2:
            stack[-1].children.append(
                SetLine(tokens[1].value, list(tokens[2:]), lineno)
            )
        elif head == "unset" and len(tokens) >= 2:
            stack[-1].children.append(UnsetLine(tokens[1].value, lineno))
        else:
            stack[-1].children.append(RawLine(line.rstrip(), lineno))

    while len(stack) > 1:
        node = stack.pop()
        kind = "config" if isinstance(node, ConfigNode) else "edit"
        tree.warnings.append(f"line {node.line}: unclosed '{kind}' at EOF")
    return tree


def _fmt_edit_name(tok: Token) -> str:
    if not tok.quoted and tok.value.isdigit():
        return tok.value
    return format_token(Token(tok.value, True))


def _serialize_children(children: list, depth: int, out: list[str]) -> None:
    pad = "    " * depth
    for child in children:
        if isinstance(child, CommentLine):
            out.append(child.text if depth == 0 else pad + child.text.strip())
        elif isinstance(child, RawLine):
            out.append(pad + child.text.strip())
        elif isinstance(child, SetLine):
            vals = " ".join(format_token(t) for t in child.values)
            out.append(f"{pad}set {child.attr} {vals}".rstrip())
        elif isinstance(child, UnsetLine):
            out.append(f"{pad}unset {child.attr}")
        elif isinstance(child, EditNode):
            out.append(f"{pad}edit {_fmt_edit_name(child.name)}")
            _serialize_children(child.children, depth + 1, out)
            out.append(f"{pad}next")
        elif isinstance(child, ConfigNode):
            out.append(f"{pad}config {' '.join(child.path)}")
            _serialize_children(child.children, depth + 1, out)
            out.append(f"{pad}end")
    return None


def serialize(tree: CTree) -> str:
    out: list[str] = []
    _serialize_children(tree.children, 0, out)
    return "\n".join(out) + "\n"


def iter_config_nodes(
    node, path: tuple = ()
) -> Iterator[tuple[tuple, "ConfigNode"]]:
    """Yield (accumulated_path, ConfigNode) for every config block, where
    accumulated_path concatenates nested config tokens, e.g.
    ('system', 'dhcp', 'server', 'ip-range')."""
    children = getattr(node, "children", [])
    for child in children:
        if isinstance(child, ConfigNode):
            child_path = path + tuple(child.path)
            yield child_path, child
            yield from iter_config_nodes(child, child_path)
        elif isinstance(child, EditNode):
            yield from iter_config_nodes(child, path)


def iter_set_lines(node, path: tuple = ()) -> Iterator[tuple[tuple, "SetLine"]]:
    """Yield (accumulated_config_path, SetLine) for every set line in the
    tree, descending through edits and nested config blocks."""
    for child in getattr(node, "children", []):
        if isinstance(child, SetLine):
            yield path, child
        elif isinstance(child, EditNode):
            yield from iter_set_lines(child, path)
        elif isinstance(child, ConfigNode):
            yield from iter_set_lines(child, path + tuple(child.path))


def path_endswith(path: tuple, suffix: tuple) -> bool:
    return len(path) >= len(suffix) and tuple(path[-len(suffix):]) == tuple(suffix)


def find_config(tree: CTree, *path: str) -> ConfigNode | None:
    target = tuple(path)
    for p, node in iter_config_nodes(tree):
        if p == target:
            return node
    return None


def find_config_under(scope, *path: str) -> ConfigNode | None:
    """Like find_config, but relative to any container (a CTree, a VDOM's
    EditNode, ...) — paths accumulate from the scope, not the file root."""
    target = tuple(path)
    for p, node in iter_config_nodes(scope):
        if p == target:
            return node
    return None


def vdom_scopes(tree: CTree) -> list[tuple[str | None, object]]:
    """The editable scopes of a config.

    Single-VDOM: [(None, tree)] — everything lives at the top level.
    Multi-VDOM: [("global", <config global>), ("<vdom>", <edit node>), ...]
    — one entry per VDOM body. Declaration-only `edit X` entries (the
    initial empty `config vdom` block) are skipped.
    """
    scopes: list[tuple[str | None, object]] = []
    multi = False
    for child in tree.children:
        if isinstance(child, ConfigNode) and child.path == ["global"]:
            multi = True
            scopes.append(("global", child))
        elif isinstance(child, ConfigNode) and child.path == ["vdom"]:
            multi = True
            for e in child.children:
                if isinstance(e, EditNode) and e.children:
                    scopes.append((e.name.value, e))
    return scopes if multi else [(None, tree)]


def section_inventory(tree: CTree) -> dict[str, int]:
    """Top-level section -> number of edit entries (for reporting)."""
    inv: dict[str, int] = {}
    for child in tree.children:
        if isinstance(child, ConfigNode):
            key = " ".join(child.path)
            edits = sum(1 for c in child.children if isinstance(c, EditNode))
            inv[key] = inv.get(key, 0) + max(edits, 1)
    return inv
