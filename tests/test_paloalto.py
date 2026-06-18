import json
from pathlib import Path

from fwforge import cli
from fwforge.parsers import detect_vendor, paloalto

FIX = Path(__file__).parent / "fixtures"


def parse_xml():
    return paloalto.parse(
        (FIX / "pa_sample.xml").read_text(encoding="utf-8"), "pa_sample.xml")


def parse_set():
    return paloalto.parse(
        (FIX / "pa_sample.set").read_text(encoding="utf-8"), "pa_sample.set")


def findings(cfg):
    return cfg.meta["findings"]


def _policy(cfg, name):
    return next(p for p in cfg.policies if p.name == name)


def test_detection_both_formats():
    for fname in ("pa_sample.xml", "pa_sample.set"):
        vendor, conf = detect_vendor(
            (FIX / fname).read_text(encoding="utf-8"))
        assert vendor == "paloalto", fname
        assert conf >= 0.7
    # existing detections unaffected
    assert detect_vendor(
        (FIX / "asa_sample.cfg").read_text(encoding="utf-8"))[0] == "cisco-asa"
    assert detect_vendor(
        (FIX / "fortios_sample.conf").read_text(encoding="utf-8"))[0] == "fortios"


def test_detection_panorama_template_merged():
    # a Panorama template-merged running-config has a ptpl="..." attribute
    # on EVERY tag, so <devices> / <entry name="..."> never appear bare.
    # (real-world: Jabil TIS PAN-OS 11.1 merged-running-config.xml)
    merged = (
        '<?xml version="1.0"?>\n'
        '<config ptpl="T1" version="11.1.0" urldb="paloaltonetworks">\n'
        '  <devices ptpl="T1">\n'
        '    <entry name="localhost.localdomain" ptpl="T1">\n'
        '      <vsys ptpl="T1"><entry name="vsys1" ptpl="T1"/></vsys>\n'
        '    </entry>\n'
        '  </devices>\n'
        '</config>\n')
    vendor, conf = detect_vendor(merged)
    assert vendor == "paloalto"
    assert conf >= 0.9


def test_detection_panorama_set_format():
    # a Panorama 'set' / display-set export leads with device-group / template /
    # template-stack lines; detection must recognize those, not only the
    # firewall-local tokens (deviceconfig/network/rulebase/...)
    cfg = "\n".join([
        'set device-group "DG1" rulebase security rules "r1" action allow',
        'set device-group "DG1" address "a1" ip-netmask 10.0.0.0/24',
        'set template "T1" config devices localhost.localdomain network '
        'interface ethernet ethernet1/1 layer3',
        'set template-stack "TS1" templates "T1"',
        'set shared address "s1" ip-netmask 172.16.0.0/16',
    ])
    vendor, conf = detect_vendor(cfg)
    assert vendor == "paloalto"
    assert conf >= 0.7


def test_xml_basics():
    cfg = parse_xml()
    assert cfg.hostname == "pa-lab"
    eth1 = cfg.interface_by_name("ethernet1/1")
    assert eth1.ip == "203.0.113.2/29"
    assert eth1.description == "wan uplink"
    sub = cfg.interface_by_name("ethernet1/2.30")
    assert (sub.parent, sub.vlan_id, sub.ip) == (
        "ethernet1/2", 30, "192.168.30.1/24")
    # layer2 interface flagged, not converted
    assert cfg.interface_by_name("ethernet1/3") is None
    assert any("layer2" in m for _, _, m, _ in findings(cfg))


def test_xml_zones_and_objects():
    cfg = parse_xml()
    zones = {z.name: z.members for z in cfg.zones}
    assert zones["untrust"] == ["ethernet1/1"]
    assert zones["trust"] == ["ethernet1/2", "ethernet1/2.30"]
    web = cfg.address_by_name("WEBSRV")
    assert (web.type, web.value, web.comment) == (
        "host", "10.1.1.10", "web box")
    assert cfg.address_by_name("POOL").type == "range"
    assert cfg.address_by_name("UPDATES").type == "fqdn"
    grp = next(g for g in cfg.addr_groups if g.name == "SERVERS")
    assert grp.members == ["WEBSRV", "POOL"]
    ports = next(s for s in cfg.services if s.name == "web-ports")
    assert ports.dst_ports == "80 8000-8080"  # comma list converted
    hi = next(s for s in cfg.services if s.name == "syslog-hiport")
    assert (hi.protocol, hi.dst_ports, hi.src_ports) == (
        "udp", "514", "1024-65535")
    # predefined service referenced by a rule is synthesized
    https = next(s for s in cfg.services if s.name == "service-https")
    assert (https.protocol, https.dst_ports) == ("tcp", "443")


def test_snmp_app_default_not_broadened():
    # snmp/snmp-trap must NOT map to the FortiOS built-in SNMP (tcp+udp
    # 161-162) -- that is wider than PAN snmp (udp/161) / snmp-trap (udp/162),
    # a silent rule-broadening. They fall through to an exact synthesized
    # service from DEFAULT_PORTS. Built-ins that are equal-or-narrower stay.
    from fwforge.parsers import pan_appid
    assert pan_appid.builtin_services("snmp") is None
    assert pan_appid.builtin_services("snmp-trap") is None
    assert pan_appid.default_ports("snmp") == [("udp", "161")]
    assert pan_appid.default_ports("snmp-trap") == [("udp", "162")]
    assert pan_appid.builtin_services("dns") == ["DNS"]  # canonical kept


def test_xml_rules():
    cfg = parse_xml()
    assert len(cfg.policies) == 4

    allow = _policy(cfg, "Allow Web")
    assert allow.src_zones == ["untrust"]
    assert allow.dst_zones == ["trust"]
    assert allow.dst_addrs == ["WEBSRV"]
    assert allow.services == ["WEB-ALL"]

    out = _policy(cfg, "Out Web")
    # application-default -> the apps' FortiOS built-in services
    # (web-browsing=HTTP, ssl=HTTPS), as a port group, not ALL
    assert len(out.services) == 1 and out.services[0].startswith("appsvc-grp-")
    grp = next(g for g in cfg.svc_groups if g.name == out.services[0])
    assert set(grp.members) == {"HTTP", "HTTPS"}
    assert "PAN apps: web-browsing, ssl" in out.comment
    assert any("App-ID" in m for _, _, m, _ in findings(cfg))
    assert any("App-IDs -> port-based service" in m
               and "application-default" in m
               for _, _, m, _ in findings(cfg))

    neg = _policy(cfg, "Not Updates")
    assert neg.dst_negate is True
    assert neg.services == ["service-https"]

    block = _policy(cfg, "Block Rest")
    assert (block.action, block.disabled, block.comment) == (
        "deny", True, "catch all")


def test_xml_nat_and_routes():
    cfg = parse_xml()
    nat = cfg.nats[0]
    assert (nat.kind, nat.real_ifc, nat.mapped_ifc) == (
        "dynamic-interface", "trust", "untrust")
    vip = cfg.vips[0]
    assert (vip.ext_ip, vip.mapped_ip) == ("203.0.113.10", "10.1.1.10")
    assert vip.ext_intf == "ethernet1/1"  # zone untrust -> single member
    assert (vip.protocol, vip.ext_port, vip.mapped_port) == (
        "tcp", "443", "8443")

    assert len(cfg.routes) == 2
    default = next(r for r in cfg.routes if r.dest == "0.0.0.0/0")
    assert default.interface == "ethernet1/1"
    lab = next(r for r in cfg.routes if r.dest == "10.9.0.0/16")
    assert lab.interface == "ethernet1/2"  # inferred from connected net
    assert any("inferred" in m for _, _, m, _ in findings(cfg))


def test_unconverted_sections_reported():
    cfg = parse_xml()
    assert any(area == "coverage" and "'tag'" in m
               for _, area, m, _ in findings(cfg))


def test_set_format_parity():
    x, s = parse_xml(), parse_set()
    assert s.hostname == x.hostname
    assert {z.name: z.members for z in s.zones} == {
        "untrust": ["ethernet1/1"],
        "trust": ["ethernet1/2", "ethernet1/2.30"]}
    ax, as_ = _policy(x, "Allow Web"), _policy(s, "Allow Web")
    assert (ax.src_zones, ax.dst_zones, ax.dst_addrs) == (
        as_.src_zones, as_.dst_zones, as_.dst_addrs)
    assert s.nats[0].kind == "dynamic-interface"
    sub = s.interface_by_name("ethernet1/2.30")
    assert (sub.vlan_id, sub.ip) == (30, "192.168.30.1/24")
    lab = next(r for r in s.routes if r.dest == "10.9.0.0/16")
    assert lab.interface == "ethernet1/2"


def test_e2e_cli_paloalto(tmp_path):
    mapfile = tmp_path / "ports.map"
    mapfile.write_text(
        "ethernet1/1 = wan1\nethernet1/2 = internal1\n"
        "ethernet1/2.30 = vlan30\n", encoding="utf-8")
    rc = cli.main([
        "convert", str(FIX / "pa_sample.xml"),
        "-o", str(tmp_path), "--map", str(mapfile),
    ])
    assert rc == 0
    conf = (tmp_path / "pa_sample.config-all.txt").read_text(encoding="utf-8")
    report = json.loads(
        (tmp_path / "pa_sample.report.json").read_text(encoding="utf-8"))

    # zones become real FortiOS zones with mapped members
    assert "config system zone" in conf
    assert 'set interface "internal1" "vlan30"' in conf
    assert "set intrazone allow" in conf
    # policies reference zones; zone names must NOT be flagged as unmapped
    assert 'set srcintf "untrust"' in conf
    assert not any("untrust" in f["message"] and "no target port" in f["message"]
                   for f in report["findings"])
    # negate carried through
    blocks = conf.split("    edit ")
    neg = next(b for b in blocks if 'set name "Not_Updates"' in b)
    assert "set dstaddr-negate enable" in neg
    assert 'set service "HTTPS"' in neg  # predefined -> built-in
    # interface PAT pair (trust -> untrust) gets nat enable
    out = next(b for b in blocks if 'set name "Out_Web"' in b)
    assert "set nat enable" in out
    # app-default -> built-in services HTTP/HTTPS as a port group
    assert 'set service "appsvc-grp-' in out
    assert 'set member "HTTP" "HTTPS"' in conf
    # multi-range + source-port emission
    assert "set tcp-portrange 80 8000-8080" in conf
    assert "set udp-portrange 514:1024-65535" in conf
    # VIP with port-forward, extintf mapped through the zone member
    assert 'set extintf "wan1"' in conf
    assert "set extport 443" in conf
    assert "set mappedport 8443" in conf
    # routes mapped + inferred
    assert 'set device "wan1"' in conf
    assert 'set device "internal1"' in conf


def test_xml_coverage_map():
    text = (FIX / "pa_sample.xml").read_text(encoding="utf-8")
    cfg = paloalto.parse(text, "pa_sample.xml")
    cov = cfg.meta.get("xml_coverage", "")
    assert "% of" in cov and "read by the converter" in cov
    msgs = [m for _, _, m, _ in findings(cfg)]
    assert any("XML coverage:" in m for m in msgs)
    # an unhandled subtree is named with its size
    text2 = text.replace(
        "<vsys>",
        "<botnet><configuration><http><enabled>yes</enabled></http>"
        "</configuration></botnet><vsys>", 1)
    cfg2 = paloalto.parse(text2, "pa2.xml")
    msgs2 = [m for _, _, m, _ in findings(cfg2)]
    assert any("unread subtree:" in m and "botnet" in m for m in msgs2)


PA_NONL3_ZONES = """<config version="11.1.0"><devices>
<entry name="localhost.localdomain">
  <vsys><entry name="vsys1">
    <zone>
      <entry name="trust"><network><layer3>
        <member>ethernet1/1</member></layer3></network></entry>
      <entry name="genpop_untrust_TAP"><network><tap>
        <member>ethernet1/12</member>
        <member>ethernet1/17</member></tap></network></entry>
      <entry name="untrust"><network><virtual-wire/></network></entry>
    </zone>
  </entry></vsys>
</entry></devices></config>"""


def test_non_layer3_zones_classified_not_double_flagged():
    # FortiOS zones are layer-3 only. A tap/virtual-wire/layer2 PAN zone has no
    # zone-level equivalent, so it is kept OUT of cfg.zones -- which also stops
    # the emitter re-flagging it as 'no layer-3 members' -- and reported once:
    # a loud warn if it binds interfaces, a quiet info if it is empty.
    cfg = paloalto.parse(PA_NONL3_ZONES, ".merged-running-config.xml")
    # the real layer-3 zone survives; the tap/vwire zones never reach the IR
    assert {z.name for z in cfg.zones} == {"trust"}
    msgs = [(lvl, m) for lvl, area, m, _ in findings(cfg) if area == "zones"]
    # tap zone with members -> one warn naming the members + the FortiOS target
    tap = [m for lvl, m in msgs if lvl == "warn" and "genpop_untrust_TAP" in m]
    assert len(tap) == 1
    assert "ethernet1/12" in tap[0] and "ethernet1/17" in tap[0]
    assert "tap zone" in tap[0] and "not converted" in tap[0]
    assert "sniffer" in tap[0]  # actionable hint, not just a dead end
    # empty virtual-wire zone -> one quiet info, never a warn
    vw = [(lvl, m) for lvl, m in msgs if "virtual-wire" in m]
    assert len(vw) == 1 and vw[0][0] == "info"
    assert "untrust" in vw[0][1]
    assert "empty" in vw[0][1] and "skipped" in vw[0][1]


PA_ROUTING = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network>
    <interface><ethernet>
      <entry name="ethernet1/1"><layer3><ip>
        <entry name="203.0.113.2/29"/></ip></layer3></entry>
      <entry name="ethernet1/2"><layer3><ip>
        <entry name="10.1.0.1/24"/></ip></layer3></entry>
    </ethernet></interface>
    <virtual-router><entry name="default">
      <protocol>
        <bgp>
          <enable>yes</enable>
          <router-id>203.0.113.2</router-id>
          <local-as>65010</local-as>
          <peer-group><entry name="upstream">
            <peer><entry name="isp1">
              <peer-as>65000</peer-as>
              <peer-address><ip>203.0.113.1</ip></peer-address>
            </entry></peer>
          </entry></peer-group>
        </bgp>
        <ospf>
          <enable>yes</enable>
          <router-id>203.0.113.2</router-id>
          <area><entry name="0.0.0.0">
            <interface><entry name="ethernet1/2">
              <passive>yes</passive></entry></interface>
          </entry></area>
        </ospf>
      </protocol>
    </entry></virtual-router>
  </network>
  <vsys><entry name="vsys1">
    <zone><entry name="trust"><network><layer3>
      <member>ethernet1/2</member></layer3></network></entry></zone>
  </entry></vsys>
</entry></devices></config>"""


def test_pan_bgp_ospf_converted():
    cfg = paloalto.parse(PA_ROUTING, "rt.xml")
    assert cfg.bgp.asn == "65010"
    assert cfg.bgp.router_id == "203.0.113.2"
    assert [(n.ip, n.remote_as) for n in cfg.bgp.neighbors] == [
        ("203.0.113.1", "65000")]
    area = cfg.ospf.areas[0]
    assert area.id == "0.0.0.0"
    assert area.networks == ["10.1.0.0/24"]
    assert area.passive == ["ethernet1/2"]


NETMAP = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip>
      <entry name="10.0.0.1/24"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1">
    <zone><entry name="untrust"><network><layer3>
      <member>ethernet1/1</member></layer3></network></entry></zone>
    <address>
      <entry name="ext-net"><ip-netmask>10.65.226.0/24</ip-netmask></entry>
      <entry name="int-net"><ip-netmask>172.19.139.0/24</ip-netmask></entry>
      <entry name="mismatch"><ip-netmask>10.1.1.0/30</ip-netmask></entry>
    </address>
    <rulebase><nat><rules>
      <entry name="SubnetDNAT">
        <to><member>untrust</member></to>
        <from><member>untrust</member></from>
        <source><member>any</member></source>
        <destination><member>ext-net</member></destination>
        <service>any</service>
        <destination-translation>
          <translated-address>int-net</translated-address>
        </destination-translation>
      </entry>
      <entry name="BadSize">
        <to><member>untrust</member></to>
        <from><member>untrust</member></from>
        <source><member>any</member></source>
        <destination><member>ext-net</member></destination>
        <service>any</service>
        <destination-translation>
          <translated-address>mismatch</translated-address>
        </destination-translation>
      </entry>
    </rules></nat></rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_subnet_destination_nat_netmap():
    cfg = paloalto.parse(NETMAP, "netmap.xml")
    # /24 -> /24 destination NAT becomes a 1:1 range VIP
    vip = next(v for v in cfg.vips if "SubnetDNAT" in v.name)
    assert vip.ext_ip == "10.65.226.0-10.65.226.255"
    assert vip.mapped_ip == "172.19.139.0-172.19.139.255"
    msgs = [(l, m) for l, _, m, _ in cfg.meta["findings"]]
    assert any("1:1 subnet destination NAT" in m for _, m in msgs)
    # mismatched sizes (/24 -> /30) is a clear error, not a silent guess
    assert any(l == "error" and "sizes" in m and "BadSize" in m
               for l, m in msgs)


AGGCFG = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface>
    <aggregate-ethernet>
      <entry name="ae1">
        <lacp><enable>yes</enable><mode>active</mode></lacp>
        <layer3><units>
        <entry name="ae1.1"><tag>11</tag>
          <ip><entry name="10.65.4.7/25"/></ip></entry>
      </units></layer3></entry>
    </aggregate-ethernet>
    <ethernet>
      <entry name="ethernet1/1"><aggregate-group>ae1</aggregate-group></entry>
      <entry name="ethernet1/2"><aggregate-group>ae1</aggregate-group></entry>
    </ethernet>
  </interface></network>
  <vsys><entry name="vsys1">
    <zone><entry name="z"><network><layer3>
      <member>ae1.1</member></layer3></network></entry></zone>
  </entry></vsys>
</entry></devices></config>"""


# a physical port carrying a nested VLAN subinterface (the ethernet1/6 case)
PHYSCFG = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface>
    <ethernet>
      <entry name="ethernet1/6"><layer3><units>
        <entry name="ethernet1/6.100"><tag>100</tag>
          <ip><entry name="10.20.0.1/24"/></ip></entry>
      </units></layer3></entry>
      <entry name="ethernet1/7"><layer3/></entry>
      <entry name="ethernet1/8"><layer3/></entry>
    </ethernet>
  </interface></network>
  <vsys><entry name="vsys1">
    <zone><entry name="z"><network><layer3>
      <member>ethernet1/6.100</member></layer3></network></entry></zone>
  </entry></vsys>
</entry></devices></config>"""


def test_aggregate_captured_in_model():
    cfg = paloalto.parse(AGGCFG, "agg.xml")
    ae1 = next(i for i in cfg.interfaces if i.name == "ae1")
    assert ae1.kind == "aggregate"
    assert ae1.members == ["ethernet1/1", "ethernet1/2"]
    assert ae1.lacp_mode == "active"   # read from the source <lacp>
    members = [i for i in cfg.interfaces if i.kind == "aggregate-member"]
    assert {m.name for m in members} == {"ethernet1/1", "ethernet1/2"}
    assert all(m.parent == "ae1" for m in members)
    sub = next(i for i in cfg.interfaces if i.name == "ae1.1")
    assert sub.kind == "vlan" and sub.parent == "ae1" and sub.vlan_id == 11


def test_aggregate_rebuilt_as_lag(tmp_path):
    (tmp_path / "agg.xml").write_text(AGGCFG, encoding="utf-8")
    mapfile = tmp_path / "m.map"
    mapfile.write_text("ethernet1/1 = lan1\nethernet1/2 = lan2\n",
                       encoding="utf-8")
    rc = cli.main(["convert", str(tmp_path / "agg.xml"), "-o",
                   str(tmp_path), "--map", str(mapfile)])
    conf = (tmp_path / "agg.config-all.txt").read_text(encoding="utf-8")
    assert "config system interface" in conf
    assert "set type aggregate" in conf
    assert 'set member "lan1" "lan2"' in conf      # members mapped to ports
    assert "set lacp-mode active" in conf
    # the VLAN subinterface rides the aggregate and carries the L3
    assert 'set interface "ae1"' in conf
    assert "set vlanid 11" in conf
    assert "set ip 10.65.4.7 255.255.255.128" in conf
    # the aggregate MUST be defined before the VLAN that nests on it, or
    # FortiOS rejects 'set interface "ae1"' on load
    assert conf.index('edit "ae1"\n') < conf.index('edit "ae1.1"')


def test_authoring_pipeline_emit():
    # GUI authoring: rename the LAG, override LACP, set target members, and
    # re-nest the VLAN — all flow through run_cross into the emitted config
    from fwforge import pipeline
    res = pipeline.run_cross(
        AGGCFG, "paloalto", "agg.xml",
        {"ethernet1/1": "x5", "ethernet1/2": "x6", "ae1": "bond0"},
        target="7.4",
        authoring={
            "aggregates": [{"name": "bond0", "lacp": "passive",
                            "members": ["x5", "x6"]}],
            "vlan_parents": {"ae1.1": "bond0"}})
    conf = res.out_text
    assert 'edit "bond0"' in conf and "set type aggregate" in conf
    assert 'set member "x5" "x6"' in conf
    assert "set lacp-mode passive" in conf       # GUI override beats source
    assert 'set interface "bond0"' in conf        # VLAN re-nested onto the LAG
    # aggregate still emitted before the VLAN that rides it
    assert conf.index('edit "bond0"\n') < conf.index('edit "ae1.1"')
    # the absorbed PAN member ports are recorded for traceability
    assert any("absorbs source member" in f.message for f in res.report.findings)


def test_authoring_repoints_bonded_port():
    # creating a LAG that bonds a port a zone referenced repoints the zone
    # to the LAG, so nothing dangles
    from fwforge.model import FirewallConfig, Interface, Zone
    from fwforge.report import Report
    from fwforge.transforms import portmap
    cfg = FirewallConfig(vendor="paloalto")
    cfg.interfaces.append(Interface(name="eth5", kind="physical",
                                    target_name="x9"))
    cfg.zones.append(Zone(name="trust", members=["x9"]))
    portmap.apply_authoring(cfg, {
        "aggregates": [{"name": "bond0", "lacp": "active",
                        "members": ["x9"]}],
        "vlan_parents": {}}, Report())
    agg = next(i for i in cfg.interfaces if i.kind == "aggregate")
    assert agg.mapped == "bond0" and agg.members == ["x9"]
    assert cfg.zones[0].members == ["bond0"]   # zone follows the bonded port


def test_authoring_promotes_physical_in_place():
    # the GUI "physical -> 802.3ad aggregate" toggle: the SAME interface
    # becomes the LAG (kind flips, chosen target ports attach as members,
    # its L3 / VLAN children ride it) — no separate, duplicate aggregate.
    # The promoted row's map_dst already carries the LAG name, so the
    # physical's mapped target == the LAG spec name (the promotion signal).
    from fwforge.model import FirewallConfig, Interface
    from fwforge.report import Report
    from fwforge.transforms import portmap
    cfg = FirewallConfig(vendor="paloalto")
    cfg.interfaces.append(Interface(name="ethernet1/6", kind="physical",
                                    target_name="lag6", ip="10.0.0.1/24"))
    cfg.interfaces.append(Interface(name="ethernet1/6.100", kind="vlan",
                                    vlan_id=100, parent="ethernet1/6",
                                    target_name="ethernet1/6.100"))
    rep = Report()
    portmap.apply_authoring(cfg, {
        "aggregates": [{"name": "lag6", "lacp": "passive",
                        "members": ["port5", "port6"]}],
        "vlan_parents": {"ethernet1/6.100": "lag6"}}, rep)
    aggs = [i for i in cfg.interfaces if i.kind == "aggregate"]
    assert len(aggs) == 1                       # promoted in place, no dup
    agg = aggs[0]
    assert agg.name == "ethernet1/6"            # identity kept
    assert agg.mapped == "lag6"                 # emitted under the LAG name
    assert agg.members == ["port5", "port6"]
    assert agg.lacp_mode == "passive"
    assert agg.ip == "10.0.0.1/24"              # the parent's L3 rides the LAG
    vlan = next(i for i in cfg.interfaces if i.kind == "vlan")
    assert vlan.parent == "lag6"               # VLAN re-nested onto the LAG
    assert any("promoted from physical" in f.message for f in rep.findings)


def test_authoring_promote_pipeline_emit():
    # end-to-end: a physical port with a nested VLAN, flipped to an
    # aggregate, emits 'set type aggregate' + members and its VLAN rides the
    # LAG — emitted in dependency order (LAG before the VLAN that needs it).
    from fwforge import pipeline
    res = pipeline.run_cross(
        PHYSCFG, "paloalto", "phys.xml",
        {"ethernet1/6": "lag6", "ethernet1/6.100": "ethernet1/6.100",
         "ethernet1/7": "x7", "ethernet1/8": "x8"},
        target="7.4",
        authoring={"aggregates": [{"name": "lag6", "lacp": "active",
                                   "members": ["x7", "x8"]}],
                   "vlan_parents": {"ethernet1/6.100": "lag6"}})
    conf = res.out_text
    assert 'edit "lag6"' in conf and "set type aggregate" in conf
    assert 'set member "x7" "x8"' in conf
    assert 'set interface "lag6"' in conf       # VLAN rides the promoted LAG
    assert "set vlanid 100" in conf
    assert conf.index('edit "lag6"\n') < conf.index('edit "ethernet1/6.100"')
    assert any("promoted from physical" in f.message for f in res.report.findings)


# a PAN config with url-filtering + file-blocking profiles, a profile-group,
# and rules referencing them directly and via the group
PROFCFG = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip><entry name="10.0.0.1/24"/></ip></layer3></entry>
    <entry name="ethernet1/2"><layer3><ip><entry name="10.0.1.1/24"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1">
    <zone>
      <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
      <entry name="untrust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
    </zone>
    <profiles>
      <custom-url-category><entry name="corp-block">
        <type>URL List</type>
        <list><member>*.badsite.com</member><member>malware.example.com</member></list>
      </entry></custom-url-category>
      <url-filtering>
        <entry name="url-strict">
          <block><member>malware</member><member>phishing</member><member>command-and-control</member><member>corp-block</member></block>
          <alert><member>social-networking</member><member>high-risk</member><member>copyright-infringement</member></alert>
          <continue><member>streaming-media</member></continue>
          <override><member>gambling</member></override>
        </entry>
      </url-filtering>
      <file-blocking>
        <entry name="block-exe">
          <rules><entry name="r1">
            <action>block</action>
            <file-type><member>exe</member><member>msoffice</member></file-type>
            <direction>both</direction>
          </entry></rules>
        </entry>
      </file-blocking>
    </profiles>
    <profile-group><entry name="pg1">
      <url-filtering><member>url-strict</member></url-filtering>
      <file-blocking><member>block-exe</member></file-blocking>
      <virus><member>av-default</member></virus>
    </entry></profile-group>
    <rulebase><security><rules>
      <entry name="r-direct">
        <from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <service><member>any</member></service><application><member>any</member></application>
        <action>allow</action>
        <profile-setting><profiles>
          <url-filtering><member>url-strict</member></url-filtering>
          <file-blocking><member>block-exe</member></file-blocking>
          <virus><member>av-default</member></virus>
          <spyware><member>strict</member></spyware>
          <data-filtering><member>default</member></data-filtering>
        </profiles></profile-setting>
      </entry>
      <entry name="r-group">
        <from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <service><member>any</member></service><application><member>any</member></application>
        <action>allow</action>
        <profile-setting><group><member>pg1</member></group></profile-setting>
      </entry>
    </rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_url_filtering_to_webfilter():
    cfg = paloalto.parse(PROFCFG, "prof.xml")
    wfs = cfg.webfilters
    assert len(wfs) == 1                       # deduped across both rules
    wf = wfs[0]
    assert wf.name == "wf-url-strict"
    f = dict(wf.filters)                        # ftgd id -> action
    assert f[26] == "block"                    # malware / command-and-control
    assert f[61] == "block"                    # phishing
    assert f[37] == "monitor"                  # social-networking (alert)
    assert f[25] == "warning"                  # streaming-media (continue)
    assert f[11] == "authenticate"             # gambling (override)
    # both policies reference the one profile
    assert all(p.webfilter == "wf-url-strict" for p in cfg.policies)


def test_custom_url_category_to_urlfilter():
    cfg = paloalto.parse(PROFCFG, "prof.xml")
    wf = cfg.webfilters[0]
    # PAN custom-url-category "URL List" -> per-URL urlfilter entries
    urls = {u: (t, a) for u, t, a in wf.urls}
    assert urls["*.badsite.com"] == ("wildcard", "block")   # wildcard detected
    assert urls["malware.example.com"] == ("simple", "block")


def test_custom_url_pipeline_emit():
    from fwforge import pipeline
    res = pipeline.run_cross(
        PROFCFG, "paloalto", "prof.xml",
        {"ethernet1/1": "port1", "ethernet1/2": "port2"}, target="8.0")
    conf = res.out_text
    assert "config webfilter urlfilter" in conf
    assert 'set url "*.badsite.com"' in conf and "set type wildcard" in conf
    assert "set action block" in conf
    # the profile references the urlfilter table
    assert "set urlfilter-table 1" in conf


def test_url_filtering_flags_risk_and_unmapped():
    cfg = paloalto.parse(PROFCFG, "prof.xml")
    msgs = " ".join(m for _, _, m, _ in findings(cfg))
    assert "high-risk" in msgs                 # PAN risk bucket flagged
    assert "copyright-infringement" in msgs    # unmapped category flagged


def test_file_blocking_to_file_filter():
    cfg = paloalto.parse(PROFCFG, "prof.xml")
    ffs = cfg.file_filters
    assert len(ffs) == 1                        # deduped
    ff = ffs[0]
    assert ff.name == "ff-block-exe"
    assert ff.rules[0]["action"] == "block"
    # PAN "msoffice" covers legacy + OOXML -> both FortiOS types
    assert ff.rules[0]["file_types"] == ["exe", "msoffice", "msofficex"]
    assert all(p.file_filter == "ff-block-exe" for p in cfg.policies)


def test_unconverted_profiles_still_flagged():
    cfg = paloalto.parse(PROFCFG, "prof.xml")
    msgs = " ".join(m for _, _, m, _ in findings(cfg))
    # only Data Filtering remains unconverted now (AV + IPS + WildFire convert);
    # it's flagged, never dropped silently
    assert "not converted" in msgs and "data" in msgs.lower()
    # the PAN built-in 'strict' anti-spyware maps to a FortiGuard stock sensor
    assert any(p.ips_sensor == "high_security" for p in cfg.policies)


def test_antivirus_to_av_profile():
    cfg = paloalto.parse(PROFCFG, "prof.xml")
    avs = cfg.av_profiles
    assert len(avs) == 1                         # deduped across both rules
    av = avs[0]
    assert av.name == "av-av-default"
    # built-in/undefined PAN AV profile -> block on the common protocols
    assert av.protocols.get("http") == "block"
    assert av.protocols.get("smtp") == "block"
    assert all(p.antivirus == "av-av-default" for p in cfg.policies)


def test_antivirus_pipeline_emit():
    from fwforge import pipeline
    res = pipeline.run_cross(
        PROFCFG, "paloalto", "prof.xml",
        {"ethernet1/1": "port1", "ethernet1/2": "port2"}, target="7.4")
    conf = res.out_text
    assert "config antivirus profile" in conf and 'edit "av-av-default"' in conf
    assert "config http" in conf and "set av-scan block" in conf
    assert 'set av-profile "av-av-default"' in conf
    assert 'set ssl-ssh-profile "certificate-inspection"' in conf


AVCFG = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip><entry name="10.0.0.1/24"/></ip></layer3></entry>
    <entry name="ethernet1/2"><layer3><ip><entry name="10.0.1.1/24"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1">
    <zone>
      <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
      <entry name="untrust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
    </zone>
    <profiles><virus><entry name="av-custom"><decoder>
      <entry name="http"><action>reset-both</action></entry>
      <entry name="smtp"><action>alert</action></entry>
      <entry name="ftp"><action>allow</action></entry>
      <entry name="smb"><action>default</action></entry>
    </decoder></entry></virus></profiles>
    <rulebase><security><rules><entry name="av-rule">
      <from><member>trust</member></from><to><member>untrust</member></to>
      <source><member>any</member></source><destination><member>any</member></destination>
      <service><member>any</member></service><application><member>any</member></application>
      <action>allow</action>
      <profile-setting><profiles><virus><member>av-custom</member></virus></profiles></profile-setting>
    </entry></rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_antivirus_decoder_action_mapping():
    cfg = paloalto.parse(AVCFG, "av.xml")
    av = next(a for a in cfg.av_profiles if a.name == "av-av-custom")
    assert av.protocols["http"] == "block"      # reset-both -> block
    assert av.protocols["smtp"] == "monitor"    # alert -> monitor
    assert av.protocols["ftp"] == "disable"     # allow -> disable
    assert av.protocols["cifs"] == "block"      # smb -> cifs; default -> block


# antivirus + WildFire on one rule, and a WildFire-only rule
WFCFG = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip><entry name="10.0.0.1/24"/></ip></layer3></entry>
    <entry name="ethernet1/2"><layer3><ip><entry name="10.0.1.1/24"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1">
    <zone>
      <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
      <entry name="untrust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
    </zone>
    <profiles>
      <virus><entry name="av1"><decoder>
        <entry name="http"><action>reset-both</action></entry>
      </decoder></entry></virus>
    </profiles>
    <rulebase><security><rules>
      <entry name="av-and-wf">
        <from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <service><member>any</member></service><application><member>any</member></application>
        <action>allow</action>
        <profile-setting><profiles>
          <virus><member>av1</member></virus>
          <wildfire-analysis><member>default</member></wildfire-analysis>
        </profiles></profile-setting>
      </entry>
      <entry name="wf-only">
        <from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <service><member>any</member></service><application><member>any</member></application>
        <action>allow</action>
        <profile-setting><profiles>
          <wildfire-analysis><member>default</member></wildfire-analysis>
        </profiles></profile-setting>
      </entry>
    </rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_wildfire_to_fortisandbox():
    cfg = paloalto.parse(WFCFG, "wf.xml")
    # av1 + WildFire -> av-av1-wf with sandbox; WildFire-only -> av-wildfire-wf
    byname = {a.name: a for a in cfg.av_profiles}
    assert "av-av1-wf" in byname and byname["av-av1-wf"].sandbox is True
    assert byname["av-av1-wf"].protocols["http"] == "block"
    wfonly = byname.get("av-wildfire-wf")
    assert wfonly is not None and wfonly.sandbox is True
    pols = {p.name: p for p in cfg.policies}
    assert pols["av-and-wf"].antivirus == "av-av1-wf"
    assert pols["wf-only"].antivirus == "av-wildfire-wf"


def test_wildfire_pipeline_emit():
    from fwforge import pipeline
    res = pipeline.run_cross(
        WFCFG, "paloalto", "wf.xml",
        {"ethernet1/1": "port1", "ethernet1/2": "port2"}, target="8.0")
    conf = res.out_text
    assert "set analytics-db enable" in conf
    assert "set fortisandbox block" in conf
    assert 'set av-profile "av-av1-wf"' in conf
    # WildFire dependency surfaced in the report
    assert any("fortisandbox" in f.message.lower()
               for f in res.report.findings)


IPSCFG = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip><entry name="10.0.0.1/24"/></ip></layer3></entry>
    <entry name="ethernet1/2"><layer3><ip><entry name="10.0.1.1/24"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1">
    <zone>
      <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
      <entry name="untrust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
    </zone>
    <profiles>
      <vulnerability><entry name="vuln-strict">
        <rules>
          <entry name="block-hi"><action><reset-both/></action>
            <severity><member>critical</member><member>high</member></severity>
            <cve><member>any</member></cve><host>any</host></entry>
          <entry name="alert-med"><action><alert/></action>
            <severity><member>medium</member></severity></entry>
          <entry name="log4shell"><action><reset-both/></action>
            <cve><member>CVE-2021-44228</member></cve></entry>
        </rules>
        <threat-exception><entry name="91284"><action><allow/></action></entry></threat-exception>
      </entry></vulnerability>
      <spyware><entry name="spy-strict">
        <rules><entry name="block-cc"><action><reset-both/></action>
          <severity><member>critical</member><member>high</member></severity>
          <category>command-and-control</category></entry></rules>
        <botnet-domains><lists/></botnet-domains>
      </entry></spyware>
    </profiles>
    <rulebase><security><rules><entry name="ips-rule">
      <from><member>trust</member></from><to><member>untrust</member></to>
      <source><member>any</member></source><destination><member>any</member></destination>
      <service><member>any</member></service><application><member>any</member></application>
      <action>allow</action>
      <profile-setting><profiles>
        <vulnerability><member>vuln-strict</member></vulnerability>
        <spyware><member>spy-strict</member></spyware>
      </profiles></profile-setting>
    </entry></rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_ips_sensor_construction():
    cfg = paloalto.parse(IPSCFG, "ips.xml")
    assert len(cfg.ips_sensors) == 1
    s = cfg.ips_sensors[0]
    assert s.name == "ips-vuln-strict-spy-strict"
    # severity grouping, first-match: critical/high -> reset, medium -> monitor
    crit = next(e for e in s.entries if "critical" in e.get("severity", []))
    assert crit["action"] == "reset" and "high" in crit["severity"]
    med = next(e for e in s.entries if e.get("severity") == ["medium"])
    assert med["action"] == "pass" and med.get("log") == "enable"
    # the CVE cross-vendor key: a CVE-pinned PAN rule -> exact FortiOS cve entry
    cve_e = next(e for e in s.entries if e.get("cve"))
    assert cve_e["cve"] == ["CVE-2021-44228"] and cve_e["action"] == "reset"
    assert cfg.policies[0].ips_sensor == "ips-vuln-strict-spy-strict"
    msgs = " ".join(m for _, _, m, _ in findings(cfg))
    assert "91284" in msgs                       # per-threat exception flagged
    assert "sinkhole" in msgs.lower()            # DNS sinkhole flagged


def test_ips_pipeline_emit():
    from fwforge import pipeline
    res = pipeline.run_cross(
        IPSCFG, "paloalto", "ips.xml",
        {"ethernet1/1": "port1", "ethernet1/2": "port2"}, target="8.0")
    conf = res.out_text
    assert "config ips sensor" in conf
    assert 'edit "ips-vuln-strict-spy-strict"' in conf
    assert "set severity critical high" in conf
    assert "set cve CVE-2021-44228" in conf
    assert 'set ips-sensor "ips-vuln-strict-spy-strict"' in conf


def test_profiles_pipeline_emit():
    from fwforge import pipeline
    res = pipeline.run_cross(
        PROFCFG, "paloalto", "prof.xml",
        {"ethernet1/1": "port1", "ethernet1/2": "port2"}, target="7.4")
    conf = res.out_text
    assert "config webfilter profile" in conf and 'edit "wf-url-strict"' in conf
    assert "config ftgd-wf" in conf and "set category 26" in conf
    assert "set action authenticate" in conf       # override -> authenticate
    assert "config file-filter profile" in conf
    assert 'set file-type "exe" "msoffice"' in conf
    # policies attach the profiles + an SSL-inspection profile
    assert 'set webfilter-profile "wf-url-strict"' in conf
    assert 'set file-filter-profile "ff-block-exe"' in conf
    assert 'set ssl-ssh-profile "certificate-inspection"' in conf
    # one profile def, referenced by both policies
    assert conf.count('edit "wf-url-strict"') == 1
    assert conf.count('set webfilter-profile "wf-url-strict"') == 2


def test_pan_urlcat_mapping():
    from fwforge.parsers import pan_urlcat
    assert pan_urlcat.to_ftgd("malware") == [26]
    assert pan_urlcat.to_ftgd("alcohol-and-tobacco") == [64, 65]  # expands
    assert pan_urlcat.to_ftgd("no-such-category") == []
    assert "high-risk" in pan_urlcat.RISK_BUCKETS


# a tiny stand-in FortiGuard app DB so signature tests don't depend on a
# cache being present on the machine
FAKE_APPDB = {
    "version": "8.0.0", "build": 167, "host": "test", "count": 5,
    "apps": [
        {"name": "Facebook", "id": 15832, "category": 23, "popularity": 5},
        {"name": "Gmail", "id": 15817, "category": 21, "popularity": 5},
        {"name": "HTTP.BROWSER", "id": 40568, "category": 25, "popularity": 5},
        {"name": "Microsoft.Teams", "id": 45001, "category": 28, "popularity": 5},
        {"name": "YouTube", "id": 31077, "category": 5, "popularity": 5},
    ],
}

APPIDCFG = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip><entry name="10.0.0.1/24"/></ip></layer3></entry>
    <entry name="ethernet1/2"><layer3><ip><entry name="10.0.1.1/24"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1">
    <zone>
      <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
      <entry name="untrust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
    </zone>
    <rulebase><security><rules><entry name="app-rule">
      <from><member>trust</member></from><to><member>untrust</member></to>
      <source><member>any</member></source><destination><member>any</member></destination>
      <service><member>application-default</member></service>
      <application><member>facebook</member><member>web-browsing</member><member>salesforce</member></application>
      <action>allow</action>
    </entry></rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_appdb_build_index():
    from fwforge import appdb
    idx = appdb.build_index(FAKE_APPDB)
    assert idx[appdb._canon("Microsoft.Teams")]["id"] == 45001
    assert idx[appdb._canon("Facebook")]["id"] == 15832
    assert appdb.build_index(None) == {}     # no DB -> empty index


def test_appid_signature_mapping():
    from fwforge import appdb
    from fwforge.parsers import pan_appid
    idx = appdb.build_index(FAKE_APPDB)
    ids, names, matched, unmatched, transport = pan_appid.map_to_sigs(
        ["facebook", "gmail", "web-browsing", "ms-teams",
         "salesforce", "ssl"], idx)
    assert 15832 in ids and 15817 in ids        # facebook, gmail (exact)
    assert 40568 in ids                          # web-browsing -> HTTP.BROWSER (alias)
    assert 45001 in ids                          # ms-teams -> Microsoft.Teams (alias)
    assert "salesforce" in unmatched             # not in this DB -> category fallback
    assert "ssl" in transport                    # transport, not an app signature


def test_appid_sig_pipeline_emit():
    from fwforge import pipeline
    res = pipeline.run_cross(
        APPIDCFG, "paloalto", "app.xml",
        {"ethernet1/1": "port1", "ethernet1/2": "port2"},
        target="7.4", app_db=FAKE_APPDB)
    conf = res.out_text
    assert "config application list" in conf
    # per-application signatures emitted (facebook + HTTP.BROWSER)
    assert "set application 15832 40568" in conf
    # salesforce has no signature in this DB -> FortiGuard category fallback
    assert "set category 29" in conf             # Business
    al = res.cfg.app_lists[0]
    assert 15832 in al.applications and 40568 in al.applications
    assert 29 in al.categories


def test_appid_category_when_no_appdb():
    # without an app DB it stays category-level (deterministic regardless of
    # any cache on the machine) — no 'set application' lines
    from fwforge import pipeline
    res = pipeline.run_cross(
        APPIDCFG, "paloalto", "app.xml",
        {"ethernet1/1": "port1", "ethernet1/2": "port2"}, target="7.4")
    conf = res.out_text
    assert "set category" in conf and "set application " not in conf


WILDCARD_CFG = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <vsys><entry name="vsys1">
    <address>
      <entry name="vpn-subnets">
        <ip-wildcard>10.0.0.0/255.0.255.0</ip-wildcard>
        <description>VPN summary wildcard</description>
      </entry>
    </address>
    <address-group>
      <entry name="remote-nets">
        <static><member>vpn-subnets</member></static>
      </entry>
    </address-group>
    <rulebase><security><rules/></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_ip_wildcard_address_parsed():
    """PAN ip-wildcard addresses convert to FortiOS 'type wildcard'."""
    from fwforge import pipeline
    from fwforge.emit import fortios as emit_fo
    from fwforge.report import Report

    cfg = paloalto.parse(WILDCARD_CFG, "wc.xml")
    addr = next((a for a in cfg.addresses if a.name == "vpn-subnets"), None)
    assert addr is not None, "wildcard address not parsed"
    assert addr.type == "wildcard"
    assert addr.value == "10.0.0.0/255.0.255.0"

    out = emit_fo.emit(cfg, Report())
    assert "set type wildcard" in out
    assert "set wildcard 10.0.0.0 255.0.255.0" in out


def test_aggregate_lacp_mode_parsed():
    import re
    passive = AGGCFG.replace("<mode>active</mode>", "<mode>passive</mode>")
    ae1 = next(i for i in paloalto.parse(passive, "agg.xml").interfaces
               if i.name == "ae1")
    assert ae1.lacp_mode == "passive"
    # an LACP block present but disabled -> static bond
    disabled = AGGCFG.replace("<enable>yes</enable>", "<enable>no</enable>")
    ae1 = next(i for i in paloalto.parse(disabled, "agg.xml").interfaces
               if i.name == "ae1")
    assert ae1.lacp_mode == "static"
    # no LACP config at all -> None (emitter defaults to active + flags)
    nolacp = re.sub(r"<lacp>.*?</lacp>", "", AGGCFG)
    ae1 = next(i for i in paloalto.parse(nolacp, "agg.xml").interfaces
               if i.name == "ae1")
    assert ae1.lacp_mode is None


# --- Schedule conversion tests -----------------------------------------------

SCHED_WEEKLY_CFG = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <vsys><entry name="vsys1">
    <schedule>
      <entry name="business-hours">
        <schedule-type>
          <recurring>
            <weekly>
              <monday><member>08:00-17:00</member></monday>
              <tuesday><member>08:00-17:00</member></tuesday>
              <wednesday><member>08:00-17:00</member></wednesday>
              <thursday><member>08:00-17:00</member></thursday>
              <friday><member>08:00-17:00</member></friday>
            </weekly>
          </recurring>
        </schedule-type>
      </entry>
    </schedule>
    <rulebase><security><rules>
      <entry name="office-web">
        <from><member>trust</member></from>
        <to><member>untrust</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <service><member>application-default</member></service>
        <application><member>web-browsing</member></application>
        <schedule>business-hours</schedule>
        <action>allow</action>
      </entry>
    </rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""

SCHED_ONETIME_CFG = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <vsys><entry name="vsys1">
    <schedule>
      <entry name="maintenance-2024">
        <schedule-type>
          <non-recurring>
            <member>2024/01/15@02:00-2024/01/15@04:00</member>
          </non-recurring>
        </schedule-type>
      </entry>
    </schedule>
    <rulebase><security><rules>
      <entry name="maint-allow">
        <from><member>mgmt</member></from>
        <to><member>any</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <service><member>any</member></service>
        <application><member>any</member></application>
        <schedule>maintenance-2024</schedule>
        <action>allow</action>
      </entry>
    </rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""

SCHED_DAILY_CFG = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <vsys><entry name="vsys1">
    <schedule>
      <entry name="backup-window">
        <schedule-type>
          <recurring>
            <daily>
              <member>02:00-04:00</member>
            </daily>
          </recurring>
        </schedule-type>
      </entry>
    </schedule>
    <rulebase><security><rules/></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_schedule_weekly_parsed():
    """Weekly recurring schedule round-trips: IR populated + FortiOS emitted."""
    from fwforge.emit import fortios as emit_fo
    from fwforge.report import Report

    cfg = paloalto.parse(SCHED_WEEKLY_CFG, "sched.xml")
    assert len(cfg.schedules) == 1, "expected exactly one schedule"
    s = cfg.schedules[0]
    assert s.name == "business-hours"
    assert s.type == "recurring"
    assert set(s.days) == {"monday", "tuesday", "wednesday", "thursday", "friday"}
    assert s.start == "08:00"
    assert s.end == "17:00"

    # policy references the schedule
    pol = cfg.policies[0]
    assert pol.schedule == "business-hours"

    # emitter produces the schedule block
    out = emit_fo.emit(cfg, Report())
    assert "config firewall schedule recurring" in out
    assert '"business-hours"' in out
    assert "set day monday tuesday wednesday thursday friday" in out
    assert "set start 08:00" in out
    assert "set end 17:00" in out
    # policy set schedule line uses name, not "always"
    assert 'set schedule "business-hours"' in out
    assert 'set schedule "always"' not in out

    # vsys section "schedule" no longer appears in coverage notes
    lvls = [f[0] for f in cfg.meta["findings"]
            if "vsys section 'schedule'" in f[2]]
    assert lvls == [], "schedule section should be consumed, not flagged"


def test_schedule_onetime_parsed():
    """Non-recurring (onetime) schedule converts to FortiOS schedule onetime."""
    from fwforge.emit import fortios as emit_fo
    from fwforge.report import Report

    cfg = paloalto.parse(SCHED_ONETIME_CFG, "sched2.xml")
    assert len(cfg.schedules) == 1
    s = cfg.schedules[0]
    assert s.name == "maintenance-2024"
    assert s.type == "onetime"
    assert s.start == "2024/01/15 02:00:00"
    assert s.end == "2024/01/15 04:00:00"

    out = emit_fo.emit(cfg, Report())
    assert "config firewall schedule onetime" in out
    assert '"maintenance-2024"' in out
    assert "set start 2024/01/15 02:00:00" in out
    assert "set end 2024/01/15 04:00:00" in out
    assert 'set schedule "maintenance-2024"' in out


def test_schedule_daily_parsed():
    """Daily recurring schedule maps to FortiOS 'set day everyday'."""
    from fwforge.emit import fortios as emit_fo
    from fwforge.report import Report

    cfg = paloalto.parse(SCHED_DAILY_CFG, "sched3.xml")
    assert len(cfg.schedules) == 1
    s = cfg.schedules[0]
    assert s.name == "backup-window"
    assert s.type == "recurring"
    assert s.days == ["everyday"]
    assert s.start == "02:00"
    assert s.end == "04:00"

    out = emit_fo.emit(cfg, Report())
    assert "set day everyday" in out
    assert "set start 02:00" in out
    assert "set end 04:00" in out


def test_schedule_missing_falls_back_to_always():
    """A policy referencing an unknown schedule name falls back to 'always' with a warning."""
    from fwforge.emit import fortios as emit_fo
    from fwforge.report import Report
    from fwforge.model import Policy, FirewallConfig

    cfg = FirewallConfig(vendor="paloalto")
    cfg.policies.append(Policy(name="test", schedule="nonexistent-sched"))
    report = Report()
    out = emit_fo.emit(cfg, report)
    assert 'set schedule "always"' in out
    warns = [f for f in report.findings
             if f.area == "schedule" and "nonexistent-sched" in f.message]
    assert warns, "expected a warning for unresolved schedule reference"


# --- Geography / region address tests ----------------------------------------

GEO_ADDR_CFG = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <vsys><entry name="vsys1">
    <address>
      <entry name="block-russia">
        <region>RU</region>
        <description>Block Russia</description>
      </entry>
      <entry name="block-china">
        <region>CN</region>
      </entry>
    </address>
    <address-group>
      <entry name="blocked-countries">
        <static>
          <member>block-russia</member>
          <member>block-china</member>
        </static>
      </entry>
    </address-group>
    <rulebase><security><rules/></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""

REGION_VSYS_CFG = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <vsys><entry name="vsys1">
    <region>
      <entry name="US-DataCenters">
        <address>
          <member>10.1.0.0/16</member>
          <member>10.2.0.0/16</member>
        </address>
      </entry>
    </region>
    <rulebase><security><rules/></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_geography_address_parsed():
    """PAN region-type address (country geo) converts to FortiOS type geography."""
    from fwforge.emit import fortios as emit_fo
    from fwforge.report import Report

    cfg = paloalto.parse(GEO_ADDR_CFG, "geo.xml")
    ru = next((a for a in cfg.addresses if a.name == "block-russia"), None)
    cn = next((a for a in cfg.addresses if a.name == "block-china"), None)
    assert ru is not None and ru.type == "geography" and ru.value == "RU"
    assert cn is not None and cn.type == "geography" and cn.value == "CN"

    out = emit_fo.emit(cfg, Report())
    assert "set type geography" in out
    assert "set country RU" in out
    assert "set country CN" in out

    # no "unsupported type" warning for region addresses
    warns = [f for f in cfg.meta["findings"]
             if f[0] == "warn" and "unsupported type" in f[2]]
    assert warns == [], f"unexpected unsupported-type warnings: {warns}"


def test_vsys_region_to_addr_group():
    """vsys <region> user-defined regions convert to address groups."""
    from fwforge.emit import fortios as emit_fo
    from fwforge.report import Report

    cfg = paloalto.parse(REGION_VSYS_CFG, "region.xml")
    grp = next((g for g in cfg.addr_groups if g.name == "US-DataCenters"), None)
    assert grp is not None, "region entry should become an address group"
    assert len(grp.members) == 2

    out = emit_fo.emit(cfg, Report())
    # address group for the region is emitted
    assert '"US-DataCenters"' in out

    # vsys section 'region' should be consumed (no coverage note)
    region_notes = [f for f in cfg.meta["findings"]
                    if "vsys section 'region'" in f[2]]
    assert region_notes == [], "region section should be consumed, not flagged"


# --- Subnet-based static NAT range VIP tests ---------------------------------

_NAT_BASE = """\
<config version="11.0.0"><devices><entry name="localhost.localdomain">
<vsys><entry name="vsys1">
<address>
  <entry name="src-net"><ip-netmask>172.19.139.0/24</ip-netmask></entry>
  <entry name="nat-net"><ip-netmask>10.65.226.0/24</ip-netmask></entry>
</address>
<rulebase><security><rules/></security></rulebase>
<rulebase><nat><rules>
  {nat_rule}
</rules></nat></rulebase>
</entry></vsys>
</entry></devices></config>"""

_BIDIR_RULE = """\
<entry name="bidir-subnet-nat">
  <from><member>untrust</member></from>
  <to><member>trust</member></to>
  <source><member>src-net</member></source>
  <destination><member>any</member></destination>
  <service>any</service>
  <source-translation>
    <static-ip>
      <bi-directional>yes</bi-directional>
      <translated-address>nat-net</translated-address>
    </static-ip>
  </source-translation>
</entry>"""


def test_bidir_static_nat_subnet_converts_to_range_vip():
    """Bi-directional static NAT with subnet addresses → range VIP (not warning)."""
    cfg = paloalto.parse(_NAT_BASE.format(nat_rule=_BIDIR_RULE), "nat.xml")
    findings = cfg.meta["findings"]

    # no "NAT references non-host" warnings
    nonhost = [f for f in findings
               if f[0] == "warn" and "non-host address" in f[2]]
    assert nonhost == [], f"unexpected non-host warnings: {nonhost}"

    # exactly one VIP created
    assert len(cfg.vips) == 1
    v = cfg.vips[0]
    # translated-address is ext_ip; original source is mapped_ip (VIP convention)
    assert v.ext_ip == "10.65.226.0-10.65.226.255"
    assert v.mapped_ip == "172.19.139.0-172.19.139.255"

    # an info finding mentioning the range conversion
    infos = [f for f in findings
             if f[0] == "info" and "range VIP" in f[2]]
    assert infos, "expected an info note about 1:1 subnet NAT range VIP"


# --- DIPP-pool and one-way static SNAT → FortiOS ippool tests ----------------

_NAT_BASE_HOST = """\
<config version="11.0.0"><devices><entry name="localhost.localdomain">
<vsys><entry name="vsys1">
<address>
  <entry name="pool-addr"><ip-netmask>203.0.113.10/32</ip-netmask></entry>
  <entry name="snat-addr"><ip-netmask>198.51.100.5/32</ip-netmask></entry>
</address>
<rulebase><security><rules/></security></rulebase>
<rulebase><nat><rules>
  {nat_rule}
</rules></nat></rulebase>
</entry></vsys>
</entry></devices></config>"""

_DIPP_POOL_RULE = """\
<entry name="dipp-pool-rule">
  <from><member>trust</member></from>
  <to><member>untrust</member></to>
  <source><member>any</member></source>
  <destination><member>any</member></destination>
  <service>any</service>
  <source-translation>
    <dynamic-ip-and-port>
      <translated-address><member>pool-addr</member></translated-address>
    </dynamic-ip-and-port>
  </source-translation>
</entry>"""

_STATIC_ONE_WAY_RULE = """\
<entry name="oneway-snat-rule">
  <from><member>trust</member></from>
  <to><member>untrust</member></to>
  <source><member>any</member></source>
  <destination><member>any</member></destination>
  <service>any</service>
  <source-translation>
    <static-ip>
      <translated-address>snat-addr</translated-address>
    </static-ip>
  </source-translation>
</entry>"""


def test_dipp_pool_converts_to_ippool_overload():
    """DIPP with explicit address pool → FortiOS ippool type overload."""
    cfg = paloalto.parse(
        _NAT_BASE_HOST.format(nat_rule=_DIPP_POOL_RULE), "nat.xml")
    findings = cfg.meta["findings"]

    # no warnings about "address pool" falling through
    warns = [f for f in findings
             if f[0] == "warn" and "address pool" in f[2].lower()]
    assert warns == [], f"unexpected pool fallback warning: {warns}"

    # one ippool created, overload type
    assert len(cfg.ippools) == 1
    pool = cfg.ippools[0]
    assert pool.start == "203.0.113.10"
    assert pool.end == "203.0.113.10"
    assert pool.pool_type == "overload"
    assert "dipp-pool-rule" in pool.name

    # one ip-pool NatRule created
    nat_rules = [n for n in cfg.nats if n.kind == "ip-pool"]
    assert len(nat_rules) == 1
    assert nat_rules[0].pool_name == pool.name

    # info finding about conversion
    infos = [f for f in findings
             if f[0] == "info" and "ippool overload" in f[2].lower()]
    assert infos, "expected info note about DIPP pool → ippool overload"


def test_static_one_way_snat_converts_to_ippool():
    """One-way static SNAT → FortiOS ippool type one-to-one."""
    cfg = paloalto.parse(
        _NAT_BASE_HOST.format(nat_rule=_STATIC_ONE_WAY_RULE), "nat.xml")
    findings = cfg.meta["findings"]

    # no warnings about one-way static
    warns = [f for f in findings
             if f[0] == "warn" and "one-way static" in f[2].lower()]
    assert warns == [], f"unexpected one-way static warning: {warns}"

    # one ippool created, one-to-one type
    assert len(cfg.ippools) == 1
    pool = cfg.ippools[0]
    assert pool.start == "198.51.100.5"
    assert pool.end == "198.51.100.5"
    assert pool.pool_type == "one-to-one"
    assert "oneway-snat-rule" in pool.name

    # info finding about conversion
    infos = [f for f in findings
             if f[0] == "info" and "one-to-one" in f[2].lower()]
    assert infos, "expected info note about one-way SNAT → ippool one-to-one"


def test_ippool_emitted_in_output():
    """ippool objects appear in the FortiOS CLI output."""
    from fwforge import pipeline
    cfg_xml = _NAT_BASE_HOST.format(nat_rule=_DIPP_POOL_RULE)
    result = pipeline.run_cross(cfg_xml, "paloalto", "nat.xml", {})
    out = result.out_text
    assert "config firewall ippool" in out
    assert "set startip 203.0.113.10" in out
    assert "set endip 203.0.113.10" in out


# --- Application-filter category resolution ----------------------------------

_APP_FILTER_CFG = """\
<config version="11.0.0"><devices><entry name="localhost.localdomain">
<vsys><entry name="vsys1">
<application-filter>
  <entry name="block-social">
    <category><member>general-internet</member></category>
    <subcategory><member>social-networking</member></subcategory>
  </entry>
  <entry name="block-video">
    <category><member>media</member></category>
    <subcategory><member>video-streaming</member></subcategory>
  </entry>
  <entry name="any-networking">
    <category><member>networking</member></category>
  </entry>
</application-filter>
<rulebase><security><rules>
  <entry name="deny-social">
    <from><member>trust</member></from>
    <to><member>untrust</member></to>
    <source><member>any</member></source>
    <destination><member>any</member></destination>
    <application><member>block-social</member></application>
    <service><member>application-default</member></service>
    <action>deny</action>
  </entry>
  <entry name="deny-video">
    <from><member>trust</member></from>
    <to><member>untrust</member></to>
    <source><member>any</member></source>
    <destination><member>any</member></destination>
    <application>
      <member>block-video</member>
      <member>block-social</member>
    </application>
    <service><member>application-default</member></service>
    <action>deny</action>
  </entry>
</rules></security></rulebase>
</entry></vsys>
</entry></devices></config>"""


def test_app_filter_resolved_to_fortiguard_category():
    """Application-filter names are resolved via crosswalk, not left unmapped."""
    cfg = paloalto.parse(_APP_FILTER_CFG, "appfilter.xml")
    findings = cfg.meta["findings"]

    # No "no FortiOS app-control category mapping" warnings for filter names
    unmapped_warns = [f for f in findings
                      if f[0] == "warn" and "category mapping" in f[2]
                      and ("block-social" in f[2] or "block-video" in f[2])]
    assert unmapped_warns == [], (
        f"filter names should be resolved, not unmapped: {unmapped_warns}")

    # At least one app-list was created (the deny-social policy gets one)
    assert len(cfg.app_lists) >= 1

    # The app-list for block-social should include Social.Media category
    social_list = next(
        (a for a in cfg.app_lists if "Social.Media" in a.cat_names), None)
    assert social_list is not None, (
        "expected an app-list with Social.Media for block-social filter")


# --- source-user / HIP profile / tag handling --------------------------------

_SOURCE_USER_CFG = """\
<config version="11.0.0"><devices><entry name="localhost.localdomain">
<vsys><entry name="vsys1">
<rulebase><security><rules>
  <entry name="user-restricted">
    <from><member>trust</member></from>
    <to><member>untrust</member></to>
    <source><member>any</member></source>
    <destination><member>any</member></destination>
    <source-user>
      <member>corp\\domain-admins</member>
      <member>corp\\it-staff</member>
    </source-user>
    <service><member>application-default</member></service>
    <application><member>any</member></application>
    <action>allow</action>
  </entry>
  <entry name="second-user-rule">
    <from><member>trust</member></from>
    <to><member>untrust</member></to>
    <source><member>any</member></source>
    <destination><member>any</member></destination>
    <source-user>
      <member>corp\\devs</member>
    </source-user>
    <service><member>any</member></service>
    <application><member>any</member></application>
    <action>allow</action>
  </entry>
</rules></security></rulebase>
</entry></vsys>
</entry></devices></config>"""

_HIP_CFG = """\
<config version="11.0.0"><devices><entry name="localhost.localdomain">
<vsys><entry name="vsys1">
<rulebase><security><rules>
  <entry name="hip-rule">
    <from><member>vpn</member></from>
    <to><member>trust</member></to>
    <source><member>any</member></source>
    <destination><member>any</member></destination>
    <hip-profiles>
      <member>compliant-windows</member>
      <member>patched-endpoint</member>
    </hip-profiles>
    <service><member>any</member></service>
    <application><member>any</member></application>
    <action>allow</action>
  </entry>
</rules></security></rulebase>
</entry></vsys>
</entry></devices></config>"""

_TAG_CFG = """\
<config version="11.0.0"><devices><entry name="localhost.localdomain">
<vsys><entry name="vsys1">
<rulebase><security><rules>
  <entry name="tagged-rule">
    <from><member>trust</member></from>
    <to><member>untrust</member></to>
    <source><member>any</member></source>
    <destination><member>any</member></destination>
    <tag>
      <member>change-123</member>
      <member>team-security</member>
    </tag>
    <service><member>any</member></service>
    <application><member>any</member></application>
    <action>deny</action>
  </entry>
</rules></security></rulebase>
</entry></vsys>
</entry></devices></config>"""


def test_source_user_preserved_in_comment():
    """source-user entries appear in policy comment and FSSO warning is emitted."""
    cfg = paloalto.parse(_SOURCE_USER_CFG, "su.xml")
    findings = cfg.meta["findings"]

    # users preserved in comments
    pol = next(p for p in cfg.policies if p.name == "user-restricted")
    assert pol.comment and "source-user" in pol.comment.lower()
    assert "domain-admins" in pol.comment

    # src_users populated
    assert "corp\\domain-admins" in pol.src_users
    assert "corp\\it-staff" in pol.src_users

    # FSSO warning emitted exactly once (two rules, one warning)
    fsso_warns = [f for f in findings
                  if f[0] == "warn" and "fsso" in f[2].lower()]
    assert len(fsso_warns) == 1, (
        f"expected exactly one FSSO warning, got {len(fsso_warns)}")


def test_source_user_any_ignored():
    """source-user=any produces no FSSO warning and empty src_users."""
    xml = """\
<config version="11.0.0"><devices><entry name="localhost.localdomain">
<vsys><entry name="vsys1">
<rulebase><security><rules>
  <entry name="open-rule">
    <from><member>trust</member></from>
    <to><member>untrust</member></to>
    <source><member>any</member></source>
    <destination><member>any</member></destination>
    <source-user><member>any</member></source-user>
    <service><member>any</member></service>
    <application><member>any</member></application>
    <action>allow</action>
  </entry>
</rules></security></rulebase>
</entry></vsys></entry></devices></config>"""
    cfg = paloalto.parse(xml, "su_any.xml")
    pol = cfg.policies[0]
    assert pol.src_users == []
    fsso_warns = [f for f in cfg.meta["findings"]
                  if "fsso" in f[2].lower()]
    assert fsso_warns == []


def test_hip_profiles_preserved_in_comment():
    """hip-profiles appear in policy comment and EMS warning is emitted."""
    cfg = paloalto.parse(_HIP_CFG, "hip.xml")
    findings = cfg.meta["findings"]

    pol = cfg.policies[0]
    assert pol.comment and "hip-profiles" in pol.comment.lower()
    assert "compliant-windows" in pol.comment

    # EMS/HIP warning emitted
    hip_warns = [f for f in findings
                 if f[0] == "warn" and "hip" in f[2].lower()
                 and "ems" in f[2].lower()]
    assert hip_warns, "expected HIP → EMS warning"
    # only once
    assert len(hip_warns) == 1


def test_tags_preserved_in_comment():
    """PAN rule tags appear in the policy comment."""
    cfg = paloalto.parse(_TAG_CFG, "tag.xml")
    pol = cfg.policies[0]
    assert pol.comment and "change-123" in pol.comment
    assert "team-security" in pol.comment


_URLFILTER_BLOCKLIST_CFG = """\
<config version="11.0.0"><devices><entry name="localhost.localdomain">
<vsys><entry name="vsys1">
  <profiles>
    <url-filtering>
      <entry name="strict-with-lists">
        <block><member>malware</member></block>
        <block-list>
          <member>*.evil-domain.com</member>
          <member>badhost.example.org</member>
        </block-list>
        <allow-list>
          <member>safe.partner.com</member>
          <member>*.trusted.internal</member>
        </allow-list>
      </entry>
    </url-filtering>
  </profiles>
  <rulebase><security><rules>
    <entry name="web-out">
      <from><member>trust</member></from>
      <to><member>untrust</member></to>
      <source><member>any</member></source>
      <destination><member>any</member></destination>
      <service><member>any</member></service>
      <application><member>web-browsing</member></application>
      <action>allow</action>
      <profile-setting><profiles>
        <url-filtering><member>strict-with-lists</member></url-filtering>
      </profiles></profile-setting>
    </entry>
  </rules></security></rulebase>
</entry></vsys>
</entry></devices></config>"""


def test_url_filtering_blocklist_allowlist():
    """block-list and allow-list explicit URL entries in a url-filtering profile
    are carried through to the webfilter's url table, not silently dropped."""
    cfg = paloalto.parse(_URLFILTER_BLOCKLIST_CFG, "bl.xml")
    assert cfg.webfilters, "webfilter profile must be produced"
    wf = cfg.webfilters[0]
    urls = {u: (t, a) for u, t, a in wf.urls}

    # block-list entries present with correct type and action
    assert "*.evil-domain.com" in urls
    assert urls["*.evil-domain.com"] == ("wildcard", "block")
    assert "badhost.example.org" in urls
    assert urls["badhost.example.org"] == ("simple", "block")

    # allow-list entries present with correct type and action
    assert "safe.partner.com" in urls
    assert urls["safe.partner.com"] == ("simple", "allow")
    assert "*.trusted.internal" in urls
    assert urls["*.trusted.internal"] == ("wildcard", "allow")
