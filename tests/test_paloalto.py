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
    assert out.services == ["ALL"]  # application-default
    assert "PAN apps: web-browsing, ssl" in out.comment
    assert any("App-ID" in m for _, _, m, _ in findings(cfg))
    assert any("application-default" in m for _, _, m, _ in findings(cfg))

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
    conf = (tmp_path / "pa_sample.fos.conf").read_text(encoding="utf-8")
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
    assert 'set service "ALL"' in out
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
