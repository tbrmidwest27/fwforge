import json
from pathlib import Path

from fwforge import cli, pipeline
from fwforge.parsers import detect_vendor, pfsense

FIX = Path(__file__).parent / "fixtures"


def parse():
    return pfsense.parse(
        (FIX / "pfsense_sample.xml").read_text(encoding="utf-8"),
        "pfsense_sample.xml")


def msgs(cfg):
    return [m for _, _, m, _ in cfg.meta["findings"]]


def _pol(cfg, prefix):
    return next(p for p in cfg.policies if p.name.startswith(prefix))


def test_detection():
    vendor, conf = detect_vendor(
        (FIX / "pfsense_sample.xml").read_text(encoding="utf-8"))
    assert vendor == "pfsense"
    assert conf >= 0.9
    # other vendors unaffected
    assert detect_vendor(
        (FIX / "pa_sample.xml").read_text(encoding="utf-8"))[0] == "paloalto"


def test_interfaces_and_vlans():
    cfg = parse()
    assert cfg.hostname == "edge-pf"
    wan = cfg.interface_by_name("wan")
    assert wan.ip == "203.0.113.2/29"
    assert wan.description == "Internet"
    opt1 = cfg.interface_by_name("opt1")
    assert (opt1.vlan_id, opt1.parent) == (30, "lan")  # em1.30 -> lan
    assert opt1.ip == "192.168.30.1/24"


def test_aliases():
    cfg = parse()
    grp = next(g for g in cfg.addr_groups if g.name == "WebServers")
    assert grp.members == ["h-10.0.1.10", "h-10.0.1.11"]
    admin = cfg.address_by_name("AdminNets")
    assert (admin.type, admin.value) == ("subnet", "10.0.2.0/24")
    # urltable alias flagged, not silently dropped
    assert any("BadList" in m and "not convertible" in m for m in msgs(cfg))


def test_routes():
    cfg = parse()
    default = next(r for r in cfg.routes if r.dest == "0.0.0.0/0")
    assert (default.gateway, default.interface) == ("203.0.113.1", "wan")
    lab = next(r for r in cfg.routes if r.dest == "10.9.0.0/16")
    assert (lab.gateway, lab.interface) == ("10.0.0.254", "lan")


def test_rules():
    cfg = parse()
    assert len(cfg.policies) == 8  # incl. the inet6 rule (now converted)

    web = _pol(cfg, "pf-1")
    assert web.src_zones == ["wan"]
    assert web.dst_addrs == ["WebServers"]
    assert web.log is True
    svc = next(s for s in cfg.services if s.name in web.services)
    assert svc.dst_ports == "80 443 8000-8080"  # port alias, colon fixed

    ping = _pol(cfg, "pf-2")
    assert ping.dst_addrs == ["h-203.0.113.2"]  # 'wanip' macro
    psvc = next(s for s in cfg.services if s.name in ping.services)
    assert (psvc.protocol, psvc.icmp_type) == ("icmp", 8)

    lanout = _pol(cfg, "pf-3")
    assert lanout.src_addrs == ["lan-net"]  # 'lan net' macro
    assert cfg.address_by_name("lan-net").value == "10.0.0.0/16"

    nodns = _pol(cfg, "pf-4")
    assert nodns.action == "deny"
    assert nodns.dst_negate is True  # <not/>
    dsvc = next(s for s in cfg.services if s.name in nodns.services)
    assert (dsvc.protocol, dsvc.dst_ports) == ("tcp/udp", "53")

    pbr = _pol(cfg, "pf-6")
    assert pbr.disabled is True
    assert "policy-routing gateway WAN_GW" in pbr.comment
    assert any("policy routing" in m for m in msgs(cfg))

    floating = _pol(cfg, "pf-7")
    assert floating.src_zones == ["wan", "lan"]
    assert any("floating" in m for m in msgs(cfg))
    # the inet6 rule is now converted as an IPv6 policy
    v6rule = _pol(cfg, "pf-8")
    assert v6rule.family == 6


def test_nat():
    cfg = parse()
    # outbound automatic -> wildcard interface-PAT toward wan
    assert any(n.real_ifc == "*" and n.mapped_ifc == "wan"
               for n in cfg.nats)
    pf = next(v for v in cfg.vips if v.name == "vip-pf-1")
    assert (pf.ext_ip, pf.mapped_ip) == ("203.0.113.2", "10.0.1.10")
    assert (pf.ext_port, pf.mapped_port) == ("443", "8443")
    oto = next(v for v in cfg.vips if v.name == "vip-1to1-1")
    assert (oto.ext_ip, oto.mapped_ip) == ("203.0.113.4", "10.0.1.11")
    # VPN flagged honestly
    assert any("OpenVPN" in m for m in msgs(cfg))
    assert any("IPsec phase1" in m for m in msgs(cfg))
    assert any("'widgets' not converted" in m for m in msgs(cfg))


def test_e2e_policy_nat(tmp_path):
    mapfile = tmp_path / "ports.map"
    mapfile.write_text("wan = wan1\nlan = internal1\nopt1 = dmz\n",
                       encoding="utf-8")
    rc = cli.main([
        "convert", str(FIX / "pfsense_sample.xml"),
        "-o", str(tmp_path), "--map", str(mapfile),
    ])
    assert rc == 0
    conf = (tmp_path / "pfsense_sample.config-all.txt").read_text(
        encoding="utf-8")
    blocks = conf.split("    edit ")
    # ssh-out rule: dstintf inferred to wan via default route, and the
    # automatic-outbound wildcard NAT pair lights it up
    ssh = next(b for b in blocks if 'set name "pf-5-ssh_out"' in b)
    assert 'set srcintf "internal1"' in ssh
    assert 'set dstintf "wan1"' in ssh
    assert "set nat enable" in ssh
    # negate carried through
    nodns = next(b for b in blocks if "pf-4" in b and "set name" in b)
    assert "set dstaddr-negate enable" in nodns
    # port-alias service with multiple ranges
    assert "set tcp-portrange 80 443 8000-8080" in conf
    assert 'set extip "203.0.113.2"' in conf  # wanip resolved


def test_e2e_central_nat(tmp_path):
    rc = cli.main([
        "convert", str(FIX / "pfsense_sample.xml"), "-o", str(tmp_path),
        "--nat-mode", "central",
    ])
    assert rc == 0
    conf = (tmp_path / "pfsense_sample.config-all.txt").read_text(
        encoding="utf-8")
    assert "set central-nat enable" in conf
    assert "config firewall central-snat-map" in conf
    assert 'set srcintf "any"' in conf  # wildcard outbound rule
    assert 'set dstintf "wan"' in conf
    assert "set nat enable" in conf  # inside the central-snat-map entry
    # policies carry no per-policy NAT in central mode
    pol_section = conf[conf.index("config firewall policy"):]
    assert "set nat enable" not in pol_section
    report = json.loads(
        (tmp_path / "pfsense_sample.report.json").read_text(
            encoding="utf-8"))
    assert report["meta"]["nat_mode"] == "central NAT"


def test_central_nat_on_asa(tmp_path):
    rc = cli.main([
        "convert", str(FIX / "asa_sample.cfg"), "-o", str(tmp_path),
        "--nat-mode", "central",
    ])
    assert rc in (0, 1)
    conf = (tmp_path / "asa_sample.config-all.txt").read_text(
        encoding="utf-8")
    snat = conf[conf.index("config firewall central-snat-map"):]
    snat = snat[:snat.index("end")]
    assert 'set srcintf "inside"' in snat
    assert 'set dstintf "outside"' in snat
    assert 'set orig-addr "LAN"' in snat  # ASA object NAT carried over
    pol_section = conf[conf.index("config firewall policy"):]
    assert "set nat enable" not in pol_section


def test_alias_bare_hostname_member_is_fqdn_not_phantom():
    # a bare single-label hostname in a MULTI-entry host alias must become a
    # real FQDN object, not a dangling group member (old code keyed
    # reference-vs-literal off '.'/':' and dropped 'intranet' into the group).
    xml = ('<?xml version="1.0"?><pfsense><version>23.3</version>'
           '<aliases><alias><name>Hosts</name><type>host</type>'
           '<address>10.0.0.5 intranet</address></alias></aliases></pfsense>')
    cfg = pfsense.parse(xml, "t.xml")
    grp = next(g for g in cfg.addr_groups if g.name == "Hosts")
    assert "fq-intranet" in grp.members          # materialized to an FQDN obj
    assert "intranet" not in grp.members         # not a bare phantom member
    obj = cfg.address_by_name("fq-intranet")
    assert obj is not None and (obj.type, obj.value) == ("fqdn", "intranet")
    names = {a.name for a in cfg.addresses} | {g.name for g in cfg.addr_groups}
    assert all(m in names for m in grp.members)  # nothing dangling


def test_alias_nested_reference_still_classified_as_member():
    xml = ('<?xml version="1.0"?><pfsense><version>23.3</version><aliases>'
           '<alias><name>Inner</name><type>host</type>'
           '<address>10.0.0.9</address></alias>'
           '<alias><name>Outer</name><type>host</type>'
           '<address>10.0.0.10 Inner</address></alias></aliases></pfsense>')
    cfg = pfsense.parse(xml, "t.xml")
    outer = next(g for g in cfg.addr_groups if g.name == "Outer")
    assert "Inner" in outer.members              # nested-alias reference kept


def test_pf_selector_dotted_quad_netmask():
    # a dotted-quad netmask must normalize to a CIDR, not 10.0.0.0/255.255...
    p = pfsense.PfSenseParser("<pfsense></pfsense>", "t.xml")
    assert p._pf_selector(
        {"address": "10.0.0.0", "netmask": "255.255.255.0"}, None) \
        == "10.0.0.0/24"
    assert p._pf_selector({"address": "10.0.0.0", "netmask": "24"}, None) \
        == "10.0.0.0/24"
    assert p._pf_selector({"address": "10.0.0.0"}, None) == "10.0.0.0/32"


def test_outbound_nat_no_wan_warns_no_snat():
    # automatic outbound NAT with no gateway'd interface must WARN that no
    # SNAT was generated, not silently report success behind 'or WAN'.
    xml = ('<?xml version="1.0"?><pfsense><version>23.3</version>'
           '<interfaces><lan><enable></enable><if>em1</if>'
           '<ipaddr>10.0.0.1</ipaddr><subnet>16</subnet></lan></interfaces>'
           '<nat><outbound><mode>automatic</mode></outbound></nat></pfsense>')
    cfg = pfsense.parse(xml, "t.xml")
    assert not cfg.nats
    assert any("NO source-NAT" in m for m in msgs(cfg))


def test_report_unconverted_list_and_string_sections():
    # repeated (list) and string-valued top-level sections must still appear
    # in the coverage report (old guard dropped non-dicts).
    xml = ('<?xml version="1.0"?><pfsense><version>23.3</version>'
           '<cert>AAAA</cert><cert>BBBB</cert>'
           '<revision>note</revision></pfsense>')
    cfg = pfsense.parse(xml, "t.xml")
    ms = msgs(cfg)
    assert any("'cert'" in m and "(x2)" in m for m in ms)  # list, count noted
    assert any("'revision'" in m for m in ms)              # string section


def test_one_to_one_nat_destination_restriction_flagged():
    # a <destination> restriction on a 1:1 mapping must be flagged (old code
    # silently emitted an unconditional, broader VIP).
    xml = ('<?xml version="1.0"?><pfsense><version>23.3</version><nat>'
           '<onetoone><external>203.0.113.4</external>'
           '<interface>wan</interface>'
           '<source><address>10.0.1.11</address></source>'
           '<destination><address>198.51.100.50</address></destination>'
           '</onetoone></nat></pfsense>')
    cfg = pfsense.parse(xml, "t.xml")
    vip = next(v for v in cfg.vips if v.name == "vip-1to1-1")
    assert (vip.ext_ip, vip.mapped_ip) == ("203.0.113.4", "10.0.1.11")
    assert any("1:1 NAT 1" in m and "broader" in m for m in msgs(cfg))
