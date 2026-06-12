import json
from pathlib import Path

import pytest

from fwforge import cli
from fwforge.parsers import fortios_tree as ft
from fwforge.report import Report
from fwforge.transforms import sdwan, tree_refs, zones
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
    assert stats["routes_converted"] == 3  # 2 defaults + 1 pinned specific
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
    # health check with both member ids + a generated SLA target
    assert 'edit "fwforge_virtual-wan-link"' in out
    assert 'set server "8.8.8.8"' in out
    assert "set members 1 2" in out
    assert "set latency-threshold 250" in out
    # generated steering: SLA rule over both members
    assert "config service" in out
    assert 'set name "virtual-wan-link-steer"' in out
    assert "set mode sla" in out
    assert "set priority-members 1 2" in out
    # policies now point at the sdwan zone
    assert 'set dstintf "virtual-wan-link"' in out
    assert 'set dstintf "port3"' not in out


def test_member_specific_route_pinned():
    """The 10.50/16-via-port3 route becomes: address object + manual
    steering rule pinned to that member + an sdwan-zone route — not an
    (invalid) static route on the member."""
    tree = load_tree()
    report = Report()
    spec = SdwanZoneSpec(
        name="virtual-wan-link",
        members=[SdwanMember(interface="port3"),
                 SdwanMember(interface="port4")],
        health_check=("ping", "8.8.8.8"),
    )
    sdwan.apply_sdwan(tree, [spec], report)
    out = ft.serialize(tree)

    assert 'set device "port3"' not in out          # old member route gone
    assert 'edit "sdwan-10.50.0.0-16"' in out       # generated address obj
    assert "set subnet 10.50.0.0 255.255.0.0" in out
    assert 'set name "pin-10.50.0.0-16"' in out     # pinned steering rule
    assert "set mode manual" in out
    assert "set priority-members 1" in out          # port3 = member 1
    assert 'set dst "sdwan-10.50.0.0-16"' in out
    assert "set dst 10.50.0.0 255.255.0.0" in out   # zone route for prefix
    # the pin rule must come BEFORE the catch-all steer rule
    assert out.index("pin-10.50.0.0-16") < out.index("virtual-wan-link-steer")
    assert any("pinned steering rule" in f.message for f in report.findings)


def test_rule_modes():
    # priority: preferred member first, FortiOS mode 'manual'
    tree = load_tree()
    spec = SdwanZoneSpec(
        name="vwl", members=[SdwanMember(interface="port3"),
                             SdwanMember(interface="port4")],
        health_check=("none", ""), rule_mode="priority", rule_member="port4")
    sdwan.apply_sdwan(tree, [spec], Report())
    out = ft.serialize(tree)
    steer = out[out.index('set name "vwl-steer"'):]
    assert "set mode manual" in steer.split("next")[0]
    assert "set priority-members 2 1" in steer  # port4 (id 2) preferred

    # none: no steer rule (pins still allowed)
    tree2 = load_tree()
    spec2 = SdwanZoneSpec(
        name="vwl", members=[SdwanMember(interface="port4")],
        health_check=("none", ""), rule_mode="none")
    sdwan.apply_sdwan(tree2, [spec2], Report())
    assert '"vwl-steer"' not in ft.serialize(tree2)

    # auto with no health-check -> load-balance
    tree3 = load_tree()
    spec3 = SdwanZoneSpec(
        name="vwl", members=[SdwanMember(interface="port4")],
        health_check=("none", ""))
    sdwan.apply_sdwan(tree3, [spec3], Report())
    out3 = ft.serialize(tree3)
    assert 'set name "vwl-steer"' in out3
    assert "set mode load-balance" in out3


def test_rule_validation():
    tree = load_tree()
    with pytest.raises(PlanError, match="not one of this zone's members"):
        sdwan.apply_sdwan(tree, [SdwanZoneSpec(
            name="vwl", members=[SdwanMember(interface="port4")],
            rule_mode="priority", rule_member="port9")], Report())
    tree2 = load_tree()
    with pytest.raises(PlanError, match="needs a health-check"):
        sdwan.apply_sdwan(tree2, [SdwanZoneSpec(
            name="vwl", members=[SdwanMember(interface="port4")],
            health_check=("none", ""), rule_mode="sla")], Report())


def test_conflicting_policies_flagged():
    text = (
        "config system interface\n"
        "    edit \"port1\"\n        set vdom \"root\"\n    next\nend\n"
        "config firewall policy\n"
        "    edit 1\n        set name \"a\"\n"
        "        set srcintf \"lan\"\n        set dstintf \"wan\"\n"
        "        set srcaddr \"all\"\n        set dstaddr \"all\"\n"
        "        set action accept\n        set schedule \"always\"\n"
        "        set service \"ALL\"\n        set nat enable\n    next\n"
        "    edit 2\n        set name \"b\"\n"
        "        set srcintf \"lan\"\n        set dstintf \"wan\"\n"
        "        set srcaddr \"all\"\n        set dstaddr \"all\"\n"
        "        set action accept\n        set schedule \"always\"\n"
        "        set service \"ALL\"\n    next\nend\n"
    )
    tree = ft.parse_config(text)
    report = Report()
    n = tree_refs.flag_conflicting_policies(tree, report)
    assert n == 1
    assert any("only the first ever matches" in f.message
               for f in report.findings)


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
    assert report["meta"]["default_routes_converted"] == 3

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


DSTADDR_CFG = """#config-version=FGT601F-7.6.6-FW-build3510-250101:opmode=0:vdom=0:user=admin
config system interface
    edit "wan1"
        set vdom "root"
        set ip 198.18.0.2 255.255.255.248
    next
    edit "wan2"
        set vdom "root"
        set ip 198.51.100.2 255.255.255.248
    next
end
config firewall address
    edit "branch-nets"
        set subnet 10.50.0.0 255.255.0.0
    next
end
config router static
    edit 1
        set gateway 198.18.0.1
        set device "wan1"
    next
    edit 2
        set dstaddr "branch-nets"
        set gateway 198.51.100.1
        set device "wan2"
    next
end
"""


def test_sdwan_dstaddr_route_pinned_not_deleted():
    # a `set dstaddr` route has no `set dst` either — it must not be
    # mistaken for a default route and silently removed
    tree = ft.parse_config(DSTADDR_CFG)
    report = Report()
    spec = SdwanZoneSpec(name="vwl", members=[
        SdwanMember(interface="wan1"), SdwanMember(interface="wan2")])
    sdwan.apply_sdwan(tree, [spec], report)
    out = ft.serialize(tree)
    assert 'set dstaddr "branch-nets"' in out      # replacement route
    assert 'set name "pin-branch-nets"' in out     # pinned steering rule
    assert "set gateway 198.18.0.1" in out         # wan1 member gateway


def test_sdwan_status_disable_flipped_to_enable():
    text = DSTADDR_CFG + """config system sdwan
    set status disable
end
"""
    tree = ft.parse_config(text)
    report = Report()
    spec = SdwanZoneSpec(name="vwl",
                         members=[SdwanMember(interface="wan1")])
    sdwan.apply_sdwan(tree, [spec], report)
    out = ft.serialize(tree)
    assert "set status enable" in out
    assert "set status disable" not in out


def test_zone_name_colliding_with_interface_rejected():
    tree = ft.parse_config(DSTADDR_CFG)
    with pytest.raises(PlanError, match="namespace"):
        zones.validate(tree, [ZoneSpec(name="wan1", members=["wan2"])])


# -- associated-interface rebind + leftover-noise triage ---------------------

ASSOC_SRC = """\
config system interface
    edit "port2"
        set vdom "root"
    next
    edit "port9"
        set vdom "root"
    next
end
config firewall address
    edit "lan-host"
        set subnet 10.0.0.5 255.255.255.255
        set associated-interface "port2"
    next
    edit "lan-net"
        set type interface-subnet
        set subnet 10.0.0.0 255.255.255.0
        set interface "port2"
    next
    edit "other"
        set subnet 10.9.9.9 255.255.255.255
        set associated-interface "port9"
    next
end
config system ntp
    set server-mode enable
    set interface "port2" "port9"
end
config firewall policy
    edit 1
        set srcintf "port2"
        set dstintf "port9"
        set srcaddr "lan-host"
        set dstaddr "other"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""


def test_zone_rebinds_associated_interface():
    from fwforge.transforms.plan import ZoneSpec
    tree = ft.parse_config(ASSOC_SRC)
    report = Report()
    stats = zones.apply_zones(
        tree, [ZoneSpec(name="lan", members=["port2"])], report)
    out = ft.serialize(tree)

    # the bound address followed its member into the zone...
    assert stats["addresses_rebound"] == 1
    assert 'set associated-interface "lan"' in out
    # ...an address bound to an unmoved interface is untouched...
    assert 'set associated-interface "port9"' in out
    # ...and the interface-subnet address keeps its real interface
    assert 'set interface "port2"' in out
    assert 'set srcintf "lan"' in out


def test_zone_leftover_audit_silences_legitimate_refs():
    from fwforge.transforms.plan import ZoneSpec
    tree = ft.parse_config(ASSOC_SRC)
    report = Report()
    stats = zones.apply_zones(
        tree, [ZoneSpec(name="lan", members=["port2"])], report)
    warned = tree_refs.audit_leftovers(
        tree, set(stats["mapping"]),
        tree_refs.BASE_ALLOWED | tree_refs.ZONE_EXTRA_ALLOWED,
        report, "zones")
    # interface-subnet address + ntp listen list are legitimate stays,
    # the associated-interface ref was rewritten: zero noise left
    assert warned == 0
