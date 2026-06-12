import pytest

from fwforge import platforms
from fwforge.transforms.plan import PlanError


def test_known_code_passthrough():
    code, note = platforms.resolve("FG9H1G")
    assert code == "FG9H1G"
    assert "confirm" in note  # derived entry carries a verify reminder


def test_verified_entry_has_no_note():
    assert platforms.resolve("FGT60F") == ("FGT60F", "")
    assert platforms.resolve("601F") == ("FG6H1F", "")
    # verified 2026-06-12 against a native 701G backup
    assert platforms.resolve("701G") == ("FG7H1G", "")


def test_bare_model_number_lowercase():
    # the real-world regression: '701g' typed into the platform field
    code, note = platforms.resolve("701g")
    assert code == "FG7H1G"


def test_product_name_and_sku():
    assert platforms.resolve("FortiGate 701G")[0] == "FG7H1G"
    assert platforms.resolve("FG-701G")[0] == "FG7H1G"
    assert platforms.resolve("fg-601f")[0] == "FG6H1F"


def test_bare_model_prefers_fortigate_over_fortiwifi():
    assert platforms.resolve("60F")[0] == "FGT60F"
    assert platforms.resolve("FortiWiFi 60F")[0] == "FWF60F"


def test_unknown_but_plausible_code_accepted():
    code, note = platforms.resolve("fg1k8f")
    assert code == "FG1K8F"
    assert "not in the known-model table" in note


def test_garbage_rejected():
    with pytest.raises(PlanError):
        platforms.resolve("purple")
    with pytest.raises(PlanError):
        platforms.resolve("  ")


def test_close_match_hint():
    with pytest.raises(PlanError) as e:
        platforms.resolve("601")
    assert "FG6H1F" in str(e.value)


def test_groups_cover_all_platforms():
    grouped = [p for _, items in platforms.GROUPS for p in items]
    assert sorted(grouped) == sorted(platforms.PLATFORMS)
    assert all(items for _, items in platforms.GROUPS)


def test_port_inventory():
    p701g = platforms.ports_for("FG7H1G")
    assert "wan1" in p701g and "lan22" in p701g and "x8" in p701g
    assert "mgmt" in p701g and "ha" in p701g
    assert "port1" not in p701g  # 700G series has no portN names
    p601f = platforms.ports_for("fg6h1f")  # case-insensitive
    assert "port24" in p601f and "x8" in p601f
    assert "lan1" not in p601f
    assert platforms.ports_for("FGT60F") == platforms.ports_for("FGT61F")
    assert platforms.ports_for("FG100F") == ()  # unconfirmed model


TARGET_CONF = """#config-version=FG7H1G-8.0.0-FW-build0167-260420:opmode=0:vdom=0:user=admin
config system interface
    edit "mgmt"
        set vdom "root"
        set type physical
    next
    edit "wan1"
        set vdom "root"
        set type physical
    next
    edit "lan1"
        set vdom "root"
        set type physical
    next
    edit "x1"
        set vdom "root"
        set type physical
    next
    edit "modem"
        set vdom "root"
    next
    edit "vlan10"
        set vdom "root"
        set interface "lan1"
        set vlanid 10
    next
    edit "ssl.root"
        set vdom "root"
        set type tunnel
    next
end
"""


def test_inventory_from_config():
    code, ver, ports = platforms.inventory_from_config(TARGET_CONF)
    assert code == "FG7H1G"
    assert ver == "8.0.0"
    # physical only: no modem, no vlan, no tunnel
    assert set(ports) == {"mgmt", "wan1", "lan1", "x1"}


def test_inventory_requires_header_and_interfaces():
    with pytest.raises(PlanError):
        platforms.inventory_from_config("config system interface\nend\n")
    with pytest.raises(PlanError):
        platforms.inventory_from_config(
            "#config-version=FG7H1G-8.0.0-FW-build0167-1:x\nconfig x\nend\n")
