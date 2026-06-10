import json
from pathlib import Path

from fwforge import cli
from fwforge.parsers import fortios_tree as ft
from fwforge.report import Report
from fwforge.transforms import tree_refs, vdommode

FIX = Path(__file__).parent / "fixtures"


def flat_tree():
    return ft.parse_config(
        (FIX / "fortios_sample.conf").read_text(encoding="utf-8"))


def mv_tree():
    return ft.parse_config(
        (FIX / "fortios_multivdom.conf").read_text(encoding="utf-8"))


def test_classify():
    assert vdommode.classify(("system", "global")) == "global"
    assert vdommode.classify(("system", "interface")) == "global"
    assert vdommode.classify(("system", "ha")) == "global"
    assert vdommode.classify(("system", "ntp")) == "global"
    assert vdommode.classify(("system", "settings")) == "vdom"
    assert vdommode.classify(("system", "zone")) == "vdom"
    assert vdommode.classify(("system", "sdwan")) == "vdom"
    assert vdommode.classify(("system", "dhcp", "server")) == "vdom"
    assert vdommode.classify(("firewall", "policy")) == "vdom"
    assert vdommode.classify(("router", "static")) == "vdom"
    assert vdommode.classify(("vpn", "ipsec", "phase1-interface")) == "vdom"


def test_wrap_flat_to_multi():
    tree = flat_tree()
    report = Report()
    stats = vdommode.to_multi_vdom(tree, report)
    assert stats["converted"]
    assert tree_refs.is_multi_vdom(tree)

    scopes = dict((n, c) for n, c in ft.vdom_scopes(tree))
    assert "global" in scopes and "root" in scopes
    gtext = ft.serialize(scopes["global"])
    vtext = ft.serialize(scopes["root"])
    # global scope
    assert "config system global" in gtext
    assert "config system interface" in gtext
    assert "config system ntp" in gtext
    # per-VDOM scope
    assert "config firewall policy" in vtext
    assert "config firewall address" in vtext
    assert "config router static" in vtext
    assert "config system zone" in vtext        # per-VDOM system
    assert "config system dhcp server" in vtext
    # interfaces got assigned to the VDOM
    assert 'set vdom "root"' in gtext
    # vdom-mode flag + header
    assert "set vdom-mode multi-vdom" in gtext
    out = ft.serialize(tree)
    assert "vdom=1" in out


def test_roundtrip_wrap_then_unwrap():
    tree = flat_tree()
    before = ft.section_inventory(tree)
    vdommode.to_multi_vdom(tree, Report())
    vdommode.to_single_vdom(tree, Report())
    assert not tree_refs.is_multi_vdom(tree)
    after = ft.section_inventory(tree)
    # same sections present after a wrap/unwrap round-trip
    assert before == after
    out = ft.serialize(tree)
    assert "vdom=0" in out
    assert "set vdom-mode" not in out
    assert 'set vdom "root"' not in out  # stripped from interfaces


def test_scope_only_drops_globals():
    tree = flat_tree()
    report = Report()
    vdommode.to_multi_vdom(tree, report, scope_only=True)
    out = ft.serialize(tree)
    # global sections dropped; only the VDOM body remains
    assert "config system global" not in out
    assert "config system interface" not in out
    assert "config firewall policy" in out
    assert any(f.level == "warn" and "scope-only" in f.message
               for f in report.findings)


def test_unwrap_multi_vdom_errors():
    tree = mv_tree()  # has root + FGSP
    report = Report()
    stats = vdommode.to_single_vdom(tree, report)
    assert not stats["converted"]
    assert any(f.level == "error" and "2 VDOMs" in f.message
               for f in report.findings)


def test_wrap_into_named_vdom():
    tree = flat_tree()
    vdommode.to_multi_vdom(tree, Report(), vdom_name="CUSTOMER-A")
    names = [n for n, _ in ft.vdom_scopes(tree)]
    assert "CUSTOMER-A" in names


def test_cli_wrap_with_portmap(tmp_path):
    planfile = tmp_path / "m.plan"
    planfile.write_text("[portmap]\nport1 = wan1\n", encoding="utf-8")
    rc = cli.main([
        "convert", str(FIX / "fortios_sample.conf"), "-o", str(tmp_path),
        "--plan", str(planfile), "--vdom-mode", "multi",
        "--vdom-name", "root",
    ])
    assert rc == 0
    conf = (tmp_path / "fortios_sample.conf").read_text(encoding="utf-8")
    report = json.loads(
        (tmp_path / "fortios_sample.report.json").read_text(encoding="utf-8"))
    assert "config global" in conf
    assert "config vdom" in conf
    # portmap still applied across the now-wrapped structure
    assert 'edit "wan1"' in conf
    assert "vdom_mode" in report["meta"]
