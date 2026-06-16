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
      <url-filtering>
        <entry name="url-strict">
          <block><member>malware</member><member>phishing</member><member>command-and-control</member></block>
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
    # AV / signature-level profiles are NOT converted, but ARE flagged
    assert "not converted" in msgs and "virus" in msgs


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
