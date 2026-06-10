import json
from pathlib import Path

import pytest

from fwforge import cli
from fwforge.parsers import fortios_tree as ft
from fwforge.report import Report
from fwforge.transforms import sdwan, zones
from fwforge.transforms.plan import (
    PlanError,
    SdwanMember,
    SdwanZoneSpec,
    ZoneSpec,
    load_plan,
)

FIX = Path(__file__).parent / "fixtures"

PLAN = """\
[zone lan]
intrazone = deny
member = port2, vlan30

[sdwan virtual-wan-link]
member = port3, port4 weight=10
health-check = ping 8.8.8.8
"""


def load_tree():
    return ft.parse_config(
        (FIX / "fortios_refactor.conf").read_text(encoding="utf-8"))


# -- plan file parsing -------------------------------------------------------

def test_plan_parsing(tmp_path):
    f = tmp_path / "m.plan"
    f.write_text(
        "[portmap]\nold2 = port2\n\n"
        "[zone lan]\nmember = old2, vlan30\n\n"
        "[sdwan wan]\nmember = port3 gateway=1.2.3.4, port4 weight=5\n"
        "health-check = dns 9.9.9.9\n",
        encoding="utf-8",
    )
    plan = load_plan(str(f))
    assert plan.portmap == {"old2": "port2"}
    # zone members listed by *source* name are translated via the portmap
    assert plan.zones[0].members == ["port2", "vlan30"]
    s = plan.sdwan[0]
    assert s.members[0].gateway == "1.2.3.4"
    assert s.members[1].weight == "5"
    assert s.health_check == ("dns", "9.9.9.9")


@pytest.mark.parametrize("bad", [
    "[zone lan]\nmember = p1\nintrazone = maybe\n",
    "[zone lan]\nmember = p1\nbogus = x\n",
    "[sdwan w]\nmember = p1 mtu=9000\n",
    "[teleport x]\nmember = p1\n",
    "[zone lan]\nintrazone = deny\n",  # no members
])
def test_plan_rejects_garbage(tmp_path, bad):
    f = tmp_path / "bad.plan"
    f.write_text(bad, encoding="utf-8")
    with pytest.raises(PlanError):
        load_plan(str(f))


# -- zone refactor -----------------------------------------------------------

def test_zone_refactor():
    tree = load_tree()
    report = Report()
    stats = zones.apply_zones(
        tree, [ZoneSpec(name="lan", members=["port2", "vlan30"])], report)
    out = ft.serialize(tree)

    assert stats["zones"] == 1
    # zone created next to the existing one
    assert 'edit "lan"' in out
    assert 'set interface "port2" "vlan30"' in out
    assert "set intrazone deny" in out
    assert 'edit "legacy-zone"' in out  # existing zone untouched
    # policy references rewritten and token lists deduped
    assert 'set srcintf "lan"' in out
    assert 'set srcintf "port2"' not in out
    # same-zone policy flagged but kept
    assert any("same-zone" in f.message for f in report.findings)
    # dstintf vlan30 -> lan on policy 3
    assert 'set dstintf "lan"' in out


def test_zone_conflicts_rejected():
    tree = load_tree()
    with pytest.raises(PlanError, match="legacy-zone"):
        zones.apply_zones(
            tree, [ZoneSpec(name="wan2", members=["port1"])], Report())
    tree = load_tree()
    with pytest.raises(PlanError, match="not an interface"):
        zones.apply_zones(
            tree, [ZoneSpec(name="z", members=["port9"])], Report())


def test_sdwan_member_in_zone_rejected():
    tree = load_tree()
    spec = SdwanZoneSpec(name="vwl", members=[SdwanMember(interface="port1")])
    with pytest.raises(PlanError, match="zone 'legacy-zone'"):
        sdwan.apply_sdwan(tree, [spec], Report())


# -- sdwan refactor ----------------------------------------------------------

def test_sdwan_refactor():
    tree = load_tree()
    report = Report()
    spec = SdwanZoneSpec(
        name="virtual-wan-link",
        members=[SdwanMember(interface="port3"),
                 SdwanMember(interface="port4", weight="10")],
        health_check=("ping", "8.8.8.8"),
    )
    stats = sdwan.apply_sdwan(tree, [spec], report)
    out = ft.serialize(tree)

    assert stats["members_added"] == 2
    assert stats["routes_converted"] == 2
    assert "config system sdwan" in out
    assert "set status enable" in out
    assert 'edit "virtual-wan-link"' in out
    # gateways harvested from the removed default routes
    assert 'set interface "port3"' in out
    assert "set gateway 203.0.113.1" in out
    assert "set gateway 198.51.100.1" in out
    assert "set weight 10" in out
    # one sdwan-zone route replaces the two member default routes
    assert 'set sdwan-zone "virtual-wan-link"' in out
    # the specific route on port3 is kept (and warned about)
    assert "set dst 10.50.0.0 255.255.0.0" in out
    assert any("may reject routes" in f.message for f in report.findings)
    # health check with both member ids
    assert 'edit "fwforge_virtual-wan-link"' in out
    assert 'set server "8.8.8.8"' in out
    assert "set members 1 2" in out
    # policies now point at the sdwan zone
    assert 'set dstintf "virtual-wan-link"' in out
    assert 'set dstintf "port3"' not in out


# -- the full plan through the CLI -------------------------------------------

def test_full_plan_cli(tmp_path):
    planfile = tmp_path / "m.plan"
    planfile.write_text(PLAN, encoding="utf-8")
    rc = cli.main([
        "convert", str(FIX / "fortios_refactor.conf"),
        "-o", str(tmp_path), "--plan", str(planfile),
    ])
    assert rc == 0
    conf = (tmp_path / "fortios_refactor.conf").read_text(encoding="utf-8")
    report = json.loads(
        (tmp_path / "fortios_refactor.report.json").read_text(encoding="utf-8"))

    # policies 1 and 2 differed only by egress interface; after zone+sdwan
    # they are identical -> merged
    assert 'set name "lan-out-3"' in conf
    assert 'set name "lan-out-4"' not in conf
    assert report["meta"]["policies_merged"] == 1
    assert report["meta"]["zones_created"] == 1
    assert report["meta"]["sdwan_members_added"] == 2
    assert report["meta"]["default_routes_converted"] == 2

    # leftover-reference audit catches what we must fix by hand
    messages = [f["message"] for f in report["findings"]]
    assert any("router policy" in m and "output-device" in m
               for m in messages)  # PBR still points at port3
    assert any("router policy" in m and "input-device" in m
               for m in messages)  # PBR still points at port2
    assert any("firewall vip" in m and "extintf" in m
               for m in messages)  # VIP pinned to an sdwan member

    # legitimate references stay silent: DHCP on port2 is fine in a zone
    assert not any("dhcp" in m for m in messages)


def test_plan_scaffold_command(tmp_path):
    out = tmp_path / "x.plan"
    rc = cli.main([
        "plan", str(FIX / "fortios_refactor.conf"), "-o", str(out)])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "[portmap]" in text
    assert "port1" in text and "vlan30" in text
    assert "[sdwan virtual-wan-link]" in text.replace("# ", "")
