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
