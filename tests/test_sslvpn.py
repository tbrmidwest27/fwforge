import json
from pathlib import Path

from fwforge import cli
from fwforge.parsers import fortios_tree as ft
from fwforge.report import Report
from fwforge.transforms import sslvpn

FIX = Path(__file__).parent / "fixtures"


def sslvpn_tree():
    return ft.parse_config(
        (FIX / "fortios_sslvpn.conf").read_text(encoding="utf-8"))


def _edit(tree, *path_and_name):
    *path, name = path_and_name
    node = ft.find_config(tree, *path)
    return next(e for e in node.children
               if isinstance(e, ft.EditNode) and e.name.value == name)


def _attr(edit, attr):
    line = next((c for c in edit.children
                 if isinstance(c, ft.SetLine) and c.attr == attr), None)
    return [t.value for t in line.values] if line else None


def test_phase1_scaffold_from_sslvpn():
    tree = sslvpn_tree()
    report = Report()
    stats = sslvpn.convert(tree, report, psk="s3cret-psk")
    assert stats["tunnels"] == 1

    p1 = _edit(tree, "vpn", "ipsec", "phase1-interface", "dialup-ipsec")
    assert _attr(p1, "type") == ["dynamic"]
    assert _attr(p1, "interface") == ["wan1"]        # = source-interface
    assert _attr(p1, "ike-version") == ["2"]
    assert _attr(p1, "mode-cfg") == ["enable"]
    assert _attr(p1, "authusrgrp") == ["sslvpn-users"]   # from auth-rule
    assert _attr(p1, "ipv4-start-ip") == ["10.212.134.200"]  # from pool obj
    assert _attr(p1, "ipv4-end-ip") == ["10.212.134.250"]
    assert _attr(p1, "ipv4-split-include") == ["internal-subnets"]
    assert _attr(p1, "eap") == ["enable"]
    assert _attr(p1, "psksecret") == ["s3cret-psk"]

    p2 = _edit(tree, "vpn", "ipsec", "phase2-interface", "dialup-ipsec-p2")
    assert _attr(p2, "phase1name") == ["dialup-ipsec"]


def test_policy_rewired_and_sslvpn_removed():
    tree = sslvpn_tree()
    sslvpn.convert(tree, Report())
    out = ft.serialize(tree)
    # SSL-VPN policy now arrives on the IPsec tunnel, groups preserved
    pol = _edit(tree, "firewall", "policy", "1")
    assert _attr(pol, "srcintf") == ["dialup-ipsec"]
    assert _attr(pol, "groups") == ["sslvpn-users"]
    # the other policy is untouched
    assert _attr(_edit(tree, "firewall", "policy", "2"), "srcintf") \
        == ["internal"]
    # SSL-VPN sections are gone (they fail to load on 7.6+/8.0)
    assert "config vpn ssl settings" not in out
    assert "config vpn ssl web portal" not in out


def test_action_required_findings():
    tree = sslvpn_tree()
    report = Report()
    sslvpn.convert(tree, report)
    msgs = [f.message for f in report.findings]
    assert any("ACTION REQUIRED" in m and "real PSK" in m for m in msgs)
    assert any("FortiClient" in m for m in msgs)
    assert any("mode-cfg pool 10.212.134.200" in m for m in msgs)


def test_web_mode_only_left_untouched():
    text = (
        "#config-version=FGT60F-7.4.4-FW-build1-240514:vdom=0\n"
        "config vpn ssl settings\n    set status enable\n"
        "    set source-interface \"wan1\"\nend\n"
        "config vpn ssl web portal\n    edit \"web-only\"\n"
        "        set tunnel-mode disable\n        set web-mode enable\n"
        "    next\nend\n"
    )
    tree = ft.parse_config(text)
    report = Report()
    stats = sslvpn.convert(tree, report)
    assert stats["tunnels"] == 0
    assert "config vpn ssl settings" in ft.serialize(tree)  # untouched
    assert any("web-mode only" in f.message for f in report.findings)


def test_e2e_cli(tmp_path):
    rc = cli.main([
        "convert", str(FIX / "fortios_sslvpn.conf"), "-o", str(tmp_path),
        "--sslvpn-to-ipsec", "--sslvpn-psk", "MyTunnelKey1",
        "--fortios", "8.0",
    ])
    assert rc == 0
    conf = (tmp_path / "fortios_sslvpn.fos.conf").read_text(encoding="utf-8")
    report = json.loads(
        (tmp_path / "fortios_sslvpn.report.json").read_text(encoding="utf-8"))
    assert "config vpn ipsec phase1-interface" in conf
    assert 'set psksecret "MyTunnelKey1"' in conf
    assert "config vpn ssl settings" not in conf
    assert report["meta"]["sslvpn_tunnels"] == 1
    # converted -> no longer flagged as a removed-in-7.6 artifact
    assert not any("SSL-VPN tunnel mode was removed" in f["message"]
                   for f in report["findings"])


def test_not_converted_without_flag(tmp_path):
    rc = cli.main([
        "convert", str(FIX / "fortios_sslvpn.conf"), "-o", str(tmp_path),
        "--fortios", "8.0",
    ])
    # without the flag, SSL-VPN stays and the 7.6 removal is flagged
    assert rc == 1
    report = json.loads(
        (tmp_path / "fortios_sslvpn.report.json").read_text(encoding="utf-8"))
    assert any("SSL-VPN tunnel mode was removed" in f["message"]
               for f in report["findings"])
    conf = (tmp_path / "fortios_sslvpn.fos.conf").read_text(encoding="utf-8")
    assert "config vpn ssl settings" in conf
