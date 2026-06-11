from pathlib import Path

from fwforge import cli
from fwforge.parsers import cisco_asa, paloalto, pfsense

FIX = Path(__file__).parent / "fixtures"

PA_V6 = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip>
      <entry name="203.0.113.2/29"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1">
    <zone>
      <entry name="untrust"><network><layer3>
        <member>ethernet1/1</member></layer3></network></entry>
      <entry name="trust"><network><layer3>
        <member>ethernet1/1</member></layer3></network></entry>
    </zone>
    <address>
      <entry name="V6WEB"><ip-netmask>2001:db8:1::10/128</ip-netmask></entry>
      <entry name="V6NET"><ip-netmask>2001:db8:2::/48</ip-netmask></entry>
      <entry name="V4WEB"><ip-netmask>10.0.0.10/32</ip-netmask></entry>
    </address>
    <rulebase><security><rules>
      <entry name="v6 in">
        <from><member>untrust</member></from>
        <to><member>trust</member></to>
        <source><member>any</member></source>
        <destination><member>V6WEB</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>allow</action>
      </entry>
      <entry name="v4 in">
        <from><member>untrust</member></from>
        <to><member>trust</member></to>
        <source><member>any</member></source>
        <destination><member>V4WEB</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>allow</action>
      </entry>
    </rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""

PF_V6 = """<?xml version="1.0"?>
<pfsense>
  <version>23.3</version>
  <system><hostname>v6-pf</hostname>
    <defaultgw4>WAN4</defaultgw4><defaultgw6>WAN6</defaultgw6></system>
  <interfaces>
    <wan><enable></enable><if>em0</if><ipaddr>203.0.113.2</ipaddr>
      <subnet>29</subnet><gateway>WAN4</gateway></wan>
    <lan><enable></enable><if>em1</if><ipaddr>10.0.0.1</ipaddr>
      <subnet>16</subnet></lan>
  </interfaces>
  <gateways>
    <gateway_item><interface>wan</interface><gateway>203.0.113.1</gateway>
      <name>WAN4</name><ipprotocol>inet</ipprotocol></gateway_item>
    <gateway_item><interface>wan</interface>
      <gateway>2001:db8:ff::1</gateway>
      <name>WAN6</name><ipprotocol>inet6</ipprotocol></gateway_item>
  </gateways>
  <staticroutes>
    <route><network>2001:db8:50::/48</network><gateway>WAN6</gateway>
      <descr></descr></route>
  </staticroutes>
  <aliases>
    <alias><name>V6Servers</name><type>host</type>
      <address>2001:db8::10 2001:db8::11</address><descr></descr></alias>
  </aliases>
  <filter>
    <rule>
      <type>pass</type><interface>wan</interface>
      <ipprotocol>inet6</ipprotocol><protocol>tcp</protocol>
      <source><any></any></source>
      <destination><address>V6Servers</address><port>443</port></destination>
      <descr><![CDATA[v6 web]]></descr>
    </rule>
  </filter>
</pfsense>"""


# -- Palo Alto IPv6 ---------------------------------------------------------

def test_pan_v6_addresses():
    cfg = paloalto.parse(PA_V6, "x")
    web = cfg.address_by_name("V6WEB")
    assert (web.type, web.value) == ("host", "2001:db8:1::10")
    net = cfg.address_by_name("V6NET")
    assert (net.type, net.value) == ("subnet", "2001:db8:2::/48")
    assert cfg.address_by_name("V4WEB").value == "10.0.0.10"


def test_pan_v6_e2e(tmp_path):
    (tmp_path / "v6.xml").write_text(PA_V6, encoding="utf-8")
    mapf = tmp_path / "m.map"
    mapf.write_text("ethernet1/1 = wan1\n", encoding="utf-8")
    rc = cli.main(["convert", str(tmp_path / "v6.xml"), "-o", str(tmp_path),
                   "--map", str(mapf)])
    assert rc == 0
    conf = (tmp_path / "v6.config-all.txt").read_text(encoding="utf-8")
    # v6 objects land in address6, v4 in address
    assert "config firewall address6" in conf
    a6 = conf[conf.index("config firewall address6"):]
    assert "set ip6 2001:db8:1::10/128" in a6
    assert "set ip6 2001:db8:2::/48" in a6
    assert "config firewall address\n" in conf  # v4 section too
    # the v6 policy uses dstaddr6, the v4 policy uses dstaddr
    blocks = conf.split("    edit ")
    v6pol = next(b for b in blocks if 'set name "v6_in"' in b)
    assert 'set dstaddr6 "V6WEB"' in v6pol
    assert "set dstaddr " not in v6pol
    v4pol = next(b for b in blocks if 'set name "v4_in"' in b)
    assert 'set dstaddr "V4WEB"' in v4pol


# -- Cisco ASA IPv6 (modern unified ACL) ------------------------------------

ASA_V6 = """ASA Version 9.12(4)
hostname asa6
interface GigabitEthernet0/0
 nameif outside
 ip address 203.0.113.2 255.255.255.248
interface GigabitEthernet0/1
 nameif inside
 ip address 10.0.0.1 255.255.0.0
object network V6-WEB
 host 2001:db8::10
object network V6-LAN
 subnet 2001:db8:abcd::/48
access-list OUT extended permit tcp any6 object V6-WEB eq 443
access-group OUT in interface outside
ipv6 route outside ::/0 2001:db8:ff::1
"""


def test_asa_v6():
    cfg = cisco_asa.parse(ASA_V6, "asa6")
    web = cfg.address_by_name("V6-WEB")
    assert (web.type, web.value) == ("host", "2001:db8::10")
    lan = cfg.address_by_name("V6-LAN")
    assert (lan.type, lan.value) == ("subnet", "2001:db8:abcd::/48")
    # any6 -> all; the ACE converts
    pol = next(p for p in cfg.policies if p.name == "OUT-1")
    assert pol.src_addrs == ["all"]
    assert pol.dst_addrs == ["V6-WEB"]
    # ipv6 route captured
    assert any(r.dest == "::/0" and r.gateway == "2001:db8:ff::1"
               for r in cfg.routes)


def test_asa_v6_e2e(tmp_path):
    (tmp_path / "asa6.cfg").write_text(ASA_V6, encoding="utf-8")
    mapf = tmp_path / "m.map"
    mapf.write_text("outside = wan1\ninside = internal1\n", encoding="utf-8")
    rc = cli.main(["convert", str(tmp_path / "asa6.cfg"), "-o", str(tmp_path),
                   "--map", str(mapf)])
    assert rc in (0, 1)
    conf = (tmp_path / "asa6.config-all.txt").read_text(encoding="utf-8")
    assert "set ip6 2001:db8::10/128" in conf
    assert "set ip6 2001:db8:abcd::/48" in conf
    assert "config router static6" in conf
    blocks = conf.split("    edit ")
    pol = next(b for b in blocks if 'set name "OUT-1"' in b)
    assert 'set dstaddr6 "V6-WEB"' in pol


# -- pfSense IPv6 -----------------------------------------------------------

def test_pfsense_v6():
    cfg = pfsense.parse(PF_V6, "x")
    grp = next(g for g in cfg.addr_groups if g.name == "V6Servers")
    assert grp.members == ["h6-2001:db8::10", "h6-2001:db8::11"]
    # both default routes + the v6 static route
    assert any(r.dest == "::/0" and r.gateway == "2001:db8:ff::1"
               for r in cfg.routes)
    assert any(r.dest == "0.0.0.0/0" for r in cfg.routes)
    v6route = next(r for r in cfg.routes if r.dest == "2001:db8:50::/48")
    assert v6route.gateway == "2001:db8:ff::1"
    pol = cfg.policies[0]
    assert pol.family == 6
    assert pol.dst_addrs == ["V6Servers"]


def test_pfsense_v6_e2e(tmp_path):
    (tmp_path / "v6.xml").write_text(PF_V6, encoding="utf-8")
    mapf = tmp_path / "m.map"
    mapf.write_text("wan = wan1\nlan = internal1\n", encoding="utf-8")
    rc = cli.main(["convert", str(tmp_path / "v6.xml"), "-o", str(tmp_path),
                   "--map", str(mapf)])
    assert rc == 0
    conf = (tmp_path / "v6.config-all.txt").read_text(encoding="utf-8")
    assert "config firewall address6" in conf
    assert "config firewall addrgrp6" in conf
    assert "config router static6" in conf
    s6 = conf[conf.index("config router static6"):]
    assert "set dst 2001:db8:50::/48" in s6
    assert "set gateway 2001:db8:ff::1" in s6
    # v4 default route still in router static
    assert "config router static\n" in conf
    blocks = conf.split("    edit ")
    v6pol = next(b for b in blocks if "pf-1" in b and "set name" in b)
    assert 'set srcaddr6 "all"' in v6pol
    assert 'set dstaddr6 "V6Servers"' in v6pol


def test_mixed_family_policy_emits_complete_pairs():
    # v4 source + v6 destination: each family leg needs a complete
    # srcaddr/dstaddr pair or FortiOS rejects the policy on load
    from fwforge.emit import fortios as emit_fortios
    from fwforge.model import Address, FirewallConfig, Policy
    from fwforge.report import Report

    cfg = FirewallConfig(vendor="test")
    cfg.addresses.append(Address(name="V4SRC", type="host",
                                 value="10.0.0.1"))
    cfg.addresses.append(Address(name="V6DST", type="host",
                                 value="2001:db8::10"))
    cfg.policies.append(Policy(src_addrs=["V4SRC"], dst_addrs=["V6DST"],
                               services=["ALL"], action="accept"))
    out = emit_fortios.emit(cfg, Report())
    assert 'set srcaddr "V4SRC"' in out
    assert 'set dstaddr "none"' in out
    assert 'set srcaddr6 "none"' in out
    assert 'set dstaddr6 "V6DST"' in out
