import json
from pathlib import Path

from fwforge import cli
from fwforge.parsers import fortios_tree as ft
from fwforge.report import Report
from fwforge.transforms import hwswitch, portmap

FIX = Path(__file__).parent / "fixtures"


def hw_tree():
    return ft.parse_config(
        (FIX / "fortios_hwswitch.conf").read_text(encoding="utf-8"))


def _iface(tree, name):
    node = ft.find_config(tree, "system", "interface")
    return next(e for e in node.children
               if isinstance(e, ft.EditNode) and e.name.value == name)


def _attr(edit, attr):
    line = next((c for c in edit.children
                 if isinstance(c, ft.SetLine) and c.attr == attr), None)
    return [t.value for t in line.values] if line else None


def test_convert_hard_switch_to_software():
    tree = hw_tree()
    report = Report()
    stats = hwswitch.convert(tree, report)
    assert stats["converted"] == 1

    internal = _iface(tree, "internal")
    assert _attr(internal, "type") == ["switch"]          # was hard-switch
    assert _attr(internal, "member") == ["port1", "port2", "port3"]  # kept
    assert _attr(internal, "ip") == ["10.0.0.1", "255.255.255.0"]    # kept
    assert _attr(internal, "allowaccess") == ["ping", "https", "ssh"]

    # the hardware-switch infrastructure is gone
    out = ft.serialize(tree)
    assert "config system virtual-switch" not in out
    assert "config system physical-switch" not in out
    assert stats["dropped"] == 2
    # a VLAN riding on the bundle still references it (works on a soft switch)
    assert _attr(_iface(tree, "vlan10"), "interface") == ["internal"]
    # the no-NP-offload caveat is surfaced
    assert any("NP offload" in f.message for f in report.findings)


def test_hard_switch_vlan_flagged_and_infra_kept():
    text = (
        "#config-version=FGT80F-7.4.4-FW-build2662-240514:vdom=0\n"
        "config system physical-switch\n    edit \"sw0\"\n    next\nend\n"
        "config system virtual-switch\n    edit \"lan\"\n"
        "        set physical-switch \"sw0\"\n    next\nend\n"
        "config system interface\n"
        "    edit \"lan\"\n        set type hard-switch\n"
        "        set member \"port1\" \"port2\"\n    next\n"
        "    edit \"guest\"\n        set type hard-switch-vlan\n"
        "        set vlanid 50\n    next\nend\n"
    )
    tree = ft.parse_config(text)
    report = Report()
    stats = hwswitch.convert(tree, report)
    assert stats["converted"] == 1                # lan converted
    assert stats["dropped"] == 0                  # infra kept (vlan remains)
    out = ft.serialize(tree)
    assert "config system virtual-switch" in out  # not dropped
    assert any("hard-switch-vlan" in f.message and f.level == "warn"
               for f in report.findings)


def test_no_hardware_switch_is_noop():
    tree = ft.parse_config(
        (FIX / "fortios_sample.conf").read_text(encoding="utf-8"))
    report = Report()
    stats = hwswitch.convert(tree, report)
    assert stats == {"converted": 0, "dropped": 0}


def test_portmap_renames_switch_members():
    """The latent gap this feature fixed: port renames must flow into a
    switch's member list."""
    tree = hw_tree()
    hwswitch.convert(tree, Report())
    portmap.apply_tree(tree, {"port1": "lan1", "port2": "lan2",
                              "port3": "lan3"})
    internal = _iface(tree, "internal")
    assert _attr(internal, "member") == ["lan1", "lan2", "lan3"]


def test_e2e_hw_switch_with_portmap(tmp_path):
    planfile = tmp_path / "m.plan"
    planfile.write_text(
        "[portmap]\nport1 = lan1\nport2 = lan2\nport3 = lan3\n",
        encoding="utf-8")
    rc = cli.main([
        "convert", str(FIX / "fortios_hwswitch.conf"), "-o", str(tmp_path),
        "--plan", str(planfile), "--hw-switch", "convert",
    ])
    assert rc == 0
    conf = (tmp_path / "fortios_hwswitch.conf").read_text(
        encoding="utf-8")
    report = json.loads(
        (tmp_path / "fortios_hwswitch.report.json").read_text(
            encoding="utf-8"))
    assert "set type switch" in conf
    assert "set type hard-switch" not in conf
    assert 'set member "lan1" "lan2" "lan3"' in conf  # renamed members
    assert "config system virtual-switch" not in conf
    assert report["meta"]["hw_switch_converted"] == 1


def test_e2e_hw_switch_keep_is_default(tmp_path):
    rc = cli.main([
        "convert", str(FIX / "fortios_hwswitch.conf"), "-o", str(tmp_path),
    ])
    assert rc == 0
    conf = (tmp_path / "fortios_hwswitch.conf").read_text(
        encoding="utf-8")
    assert "set type hard-switch" in conf              # untouched by default
    assert "config system virtual-switch" in conf
