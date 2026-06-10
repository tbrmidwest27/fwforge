from pathlib import Path

from fwforge.parsers import fortios_tree as ft

FIX = Path(__file__).parent / "fixtures"


def load():
    return (FIX / "fortios_sample.conf").read_text(encoding="utf-8")


def normalize(node):
    """Structural fingerprint, independent of formatting."""
    kids = []
    for c in getattr(node, "children", []):
        if isinstance(c, ft.SetLine):
            kids.append(("set", c.attr, tuple(t.value for t in c.values)))
        elif isinstance(c, ft.UnsetLine):
            kids.append(("unset", c.attr))
        elif isinstance(c, ft.CommentLine):
            kids.append(("comment", c.text.strip()))
        elif isinstance(c, ft.RawLine):
            kids.append(("raw", c.text.strip()))
        elif isinstance(c, ft.EditNode):
            kids.append(("edit", c.name.value, normalize(c)))
        elif isinstance(c, ft.ConfigNode):
            kids.append(("config", tuple(c.path), normalize(c)))
    return tuple(kids)


def test_roundtrip_is_lossless():
    tree1 = ft.parse_config(load(), "fixture")
    assert not tree1.warnings
    text2 = ft.serialize(tree1)
    tree2 = ft.parse_config(text2, "roundtrip")
    assert normalize(tree1) == normalize(tree2)


def test_multiline_quoted_value_preserved():
    tree = ft.parse_config(load())
    node = ft.find_config(tree, "vpn", "certificate", "local")
    assert node is not None
    cert_value = None
    for edit in node.children:
        if isinstance(edit, ft.EditNode) and edit.name.value == "lab-cert":
            for line in edit.children:
                if isinstance(line, ft.SetLine) and line.attr == "certificate":
                    cert_value = line.values[0].value
    assert cert_value is not None
    assert "\n" in cert_value
    assert cert_value.startswith("-----BEGIN CERTIFICATE-----")
    # survives serialization
    out = ft.serialize(tree)
    assert "-----BEGIN CERTIFICATE-----\nMIIB" in out


def test_unknown_sections_survive():
    tree = ft.parse_config(load())
    out = ft.serialize(tree)
    assert "config system ntp" in out
    assert "set ntpsync enable" in out
    assert "set start-ip 10.1.0.100" in out  # nested config block


def test_section_inventory():
    tree = ft.parse_config(load())
    inv = ft.section_inventory(tree)
    assert inv["system interface"] == 3
    assert inv["firewall policy"] == 1
    assert "system ntp" in inv
