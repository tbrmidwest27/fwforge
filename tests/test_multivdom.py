import json
from pathlib import Path

import pytest

from fwforge import cli
from fwforge.parsers import fortios_tree as ft
from fwforge.report import Report
from fwforge.transforms import portmap, sdwan, tree_refs, zones
from fwforge.transforms.plan import (
    PlanError,
    SdwanMember,
    SdwanZoneSpec,
    ZoneSpec,
)

FIX = Path(__file__).parent / "fixtures"


def load_tree():
    return ft.parse_config(
        (FIX / "fortios_multivdom.conf").read_text(encoding="utf-8"))


def vdom_text(tree, vdom):
    """Serialized text of one VDOM's body only."""
    scope = tree_refs.vdom_scope(tree, vdom)
    out = []
    from fwforge.parsers.fortios_tree import _serialize_children
    _serialize_children(scope.children, 0, out)
    return "\n".join(out)


def test_scopes_and_interface_vdoms():
    tree = load_tree()
    names = [n for n, _ in ft.vdom_scopes(tree)]
    assert names == ["global", "root", "FGSP"]  # declaration edits skipped
    vd = tree_refs.interface_vdoms(tree)
    assert vd["port1"] == "root"
    assert vd["vlan30"] == "root"
    assert vd["port3"] == "FGSP"


def test_portmap_on_multivdom():
    tree = load_tree()
    stats = portmap.apply_tree(tree, {"port1": "wan1"})
    out = ft.serialize(tree)
    assert stats["edits"] == 1  # edit under config global > system interface
    assert '        edit "wan1"' in out
    assert 'set dstintf "wan1"' in out  # policy inside the root VDOM body
    assert 'set device "wan1"' in out  # root VDOM static route


def test_zone_lands_in_owning_vdom():
    tree = load_tree()
    report = Report()
    zones.apply_zones(
        tree, [ZoneSpec(name="lan", members=["port2", "vlan30"])], report)
    merged = tree_refs.dedup_policies(tree, report)

    root_text = vdom_text(tree, "root")
    fgsp_text = vdom_text(tree, "FGSP")
    assert "config system zone" in root_text
    assert 'edit "lan"' in root_text
    assert "config system zone" not in fgsp_text
    assert 'set srcintf "lan"' in root_text
    # policies 1 and 2 differed only by srcintf -> identical after the fold
    assert merged == 1
    # zone section must precede the firewall section for load order
    assert root_text.index("config system zone") \
        < root_text.index("config firewall policy")
    assert any("VDOM 'root'" in f.message for f in report.findings)


def test_zone_members_must_share_vdom():
    tree = load_tree()
    with pytest.raises(PlanError, match="span VDOMs"):
        zones.apply_zones(
            tree, [ZoneSpec(name="bad", members=["port2", "port3"])],
            Report())


def test_declared_vdom_mismatch_rejected():
    tree = load_tree()
    with pytest.raises(PlanError, match="vdom=FGSP"):
        zones.apply_zones(
            tree,
            [ZoneSpec(name="lan", members=["port2"], vdom="FGSP")],
            Report())


def test_sdwan_lands_in_owning_vdom():
    tree = load_tree()
    report = Report()
    spec = SdwanZoneSpec(
        name="vwl", members=[SdwanMember(interface="port4")],
        health_check=("none", ""),
    )
    stats = sdwan.apply_sdwan(tree, [spec], report)

    root_text = vdom_text(tree, "root")
    fgsp_text = vdom_text(tree, "FGSP")
    assert stats["members_added"] == 1
    assert stats["routes_converted"] == 1
    assert "config system sdwan" in fgsp_text
    assert "config system sdwan" not in root_text
    # FGSP default route became the sdwan-zone route, gateway harvested
    assert 'set sdwan-zone "vwl"' in fgsp_text
    assert "set gateway 203.0.113.9" in fgsp_text  # now on the member
    assert 'set device "port4"' not in fgsp_text
    # root VDOM's own default route is untouched
    assert "set gateway 198.18.0.1" in root_text
    assert 'set device "port1"' in root_text
    # policy rewrite confined to references of the member
    assert 'set dstintf "vwl"' in fgsp_text
    assert 'set dstintf "port1"' in root_text


def test_full_multivdom_plan_cli(tmp_path):
    planfile = tmp_path / "m.plan"
    planfile.write_text(
        "[portmap]\nport1 = wan1\n\n"
        "[zone lan]\nmember = port2, vlan30\n\n"
        "[sdwan vwl]\nvdom = FGSP\nmember = port4\n"
        "health-check = ping 8.8.8.8\n",
        encoding="utf-8",
    )
    rc = cli.main([
        "convert", str(FIX / "fortios_multivdom.conf"),
        "-o", str(tmp_path), "--plan", str(planfile),
    ])
    assert rc == 0
    conf = (tmp_path / "fortios_multivdom.conf").read_text(
        encoding="utf-8")
    report = json.loads(
        (tmp_path / "fortios_multivdom.report.json").read_text(
            encoding="utf-8"))
    assert report["meta"]["vdoms"] == "root, FGSP"
    assert report["meta"]["zones_created"] == 1
    assert report["meta"]["sdwan_members_added"] == 1
    assert report["meta"]["policies_merged"] == 1
    assert 'edit "wan1"' in conf
    assert 'set dstintf "wan1"' in conf
    assert 'edit "fwforge_vwl"' in conf  # health check created in FGSP
