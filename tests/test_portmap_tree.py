from pathlib import Path

from fwforge.parsers import fortios_tree as ft
from fwforge.transforms import portmap

FIX = Path(__file__).parent / "fixtures"

MAPPING = {"port1": "wan1", "port2": "internal1"}


def converted():
    tree = ft.parse_config(
        (FIX / "fortios_sample.conf").read_text(encoding="utf-8")
    )
    stats = portmap.apply_tree(tree, MAPPING)
    return ft.serialize(tree), stats


def test_interface_edits_renamed():
    out, stats = converted()
    assert stats["edits"] == 2
    assert '    edit "wan1"' in out
    assert '    edit "internal1"' in out


def test_references_rewritten_everywhere():
    out, _ = converted()
    assert 'set srcintf "internal1"' in out
    assert 'set dstintf "wan1"' in out
    assert 'set device "wan1"' in out  # router static
    assert 'set interface "wan1"' in out  # zone member list
    assert 'set interface "internal1"' in out  # dhcp + vlan parent


def test_lookalike_names_not_touched():
    out, _ = converted()
    # the firewall *address* literally named port1 must keep its name...
    assert 'set comment "address that shares a port name on purpose"' in out
    assert '    edit "port1"' in out  # the address object, not an interface
    # ...and the address-group member referring to it must not be rewritten
    assert 'set member "lan-net" "port1"' in out


def test_rename_stats_by_attr():
    _, stats = converted()
    # vlan parent + dhcp = 'interface' x2, plus zone 'interface' = 3
    assert stats["by_attr"]["interface"] == 3
    assert stats["by_attr"]["srcintf"] == 1
    assert stats["by_attr"]["dstintf"] == 1
    assert stats["by_attr"]["device"] == 1
    assert stats["values"] == 6
