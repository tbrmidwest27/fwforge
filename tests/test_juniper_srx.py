import json
from pathlib import Path

from fwforge import cli
from fwforge.parsers import detect_vendor, juniper_srx
from fwforge.parsers import junos_apps

FIX = Path(__file__).parent / "fixtures"


def parse_curly():
    return juniper_srx.parse(
        (FIX / "srx_sample.conf").read_text(encoding="utf-8"),
        "srx_sample.conf")


def _to_set(node, prefix):
    lines = []
    for toks in node.leaves:
        lines.append(" ".join(["set"] + prefix + list(toks)))
    for key, child in node.containers:
        lines += _to_set(child, prefix + list(key))
    return lines


def set_text():
    root = juniper_srx._tree_from_curly(
        (FIX / "srx_sample.conf").read_text(encoding="utf-8"))
    return "\n".join(_to_set(root, [])) + "\n"


def findings(cfg):
    return cfg.meta["findings"]


def _pol(cfg, name):
    return next(p for p in cfg.policies if p.name == name)


def test_detection():
    text = (FIX / "srx_sample.conf").read_text(encoding="utf-8")
    assert detect_vendor(text) == ("juniper-srx", 0.9)
    assert detect_vendor(set_text())[0] == "juniper-srx"
    # other vendors unaffected
    assert detect_vendor(
        (FIX / "asa_sample.cfg").read_text(encoding="utf-8"))[0] \
        == "cisco-asa"


def test_interfaces():
    cfg = parse_curly()
    byname = {i.name: i for i in cfg.interfaces}
    assert byname["ge-0/0/0.0"].ip == "203.0.113.2/29"
    # bare unit 0 is a plain L3 interface, never vlanid 0
    assert byname["ge-0/0/1.0"].vlan_id is None
    assert byname["ge-0/0/1.0"].parent is None
    # explicit vlan-id -> subinterface
    assert byname["ge-0/0/1.30"].vlan_id == 30
    assert byname["ge-0/0/1.30"].parent == "ge-0/0/1"
    assert byname["st0.0"].ip is None  # tunnel interface


def test_apply_groups_expanded():
    cfg = parse_curly()
    assert any("apply-groups expanded" in m
               for _, _, m, _ in findings(cfg))


def test_zones_and_scoped_books():
    cfg = parse_curly()
    zones = {z.name: z.members for z in cfg.zones}
    assert zones["trust"] == ["ge-0/0/1.0", "ge-0/0/1.30"]
    assert zones["untrust"] == ["ge-0/0/0.0"]
    # global + zone address books flattened
    assert cfg.address_by_name("corp-net").value == "10.0.0.0/8"
    assert cfg.address_by_name("lan-net").value == "10.1.0.0/24"
    assert cfg.address_by_name("web-srv").type == "host"
    grp = next(g for g in cfg.addr_groups if g.name == "servers")
    assert grp.members == ["web-srv"]


def test_zone_pair_and_global_policies():
    cfg = parse_curly()
    allow = _pol(cfg, "allow-web")
    assert allow.src_zones == ["trust"] and allow.dst_zones == ["untrust"]
    assert allow.src_addrs == ["lan-net"] and allow.dst_addrs == ["all"]
    assert allow.action == "accept" and allow.log is True
    block = _pol(cfg, "block-rest")
    assert block.action == "deny"
    glob = _pol(cfg, "global-deny")
    assert glob.src_zones == ["any"] and glob.dst_zones == ["any"]
    assert "global policy" in (glob.comment or "")


def test_application_resolution():
    cfg = parse_curly()
    # application-set with custom + predefined apps -> service group
    grp = next(g for g in cfg.svc_groups if g.name == "web-apps")
    members = {s.name: s for s in cfg.services
               if s.name in grp.members}
    ports = sorted(s.dst_ports for s in members.values())
    assert ports == ["443", "80", "8443"]
    # predefined junos-ssh resolves to tcp/22
    ssh = next(s for s in cfg.services if s.dst_ports == "22")
    assert ssh.protocol == "tcp"


def test_junos_apps_table():
    assert junos_apps.junos_app("junos-https") == [("tcp", "443")]
    assert junos_apps.junos_app("junos-dns-udp") == [("udp", "53")]
    assert junos_apps.junos_app("junos-ping") == [("icmp", "")]
    assert junos_apps.junos_app("junos-nonexistent") is None


def test_nat():
    cfg = parse_curly()
    # source-nat interface -> dynamic-interface keyed by zones
    snat = cfg.nats[0]
    assert (snat.kind, snat.real_ifc, snat.mapped_ifc) == (
        "dynamic-interface", "trust", "untrust")
    # destination-nat -> VIP with port forward
    dnat = next(v for v in cfg.vips if v.name == "vip-dnat-web")
    assert (dnat.ext_ip, dnat.mapped_ip) == ("203.0.113.5", "10.1.0.10")
    assert (dnat.ext_port, dnat.mapped_port) == ("443", "8443")
    # static-nat -> 1:1 VIP
    stat = next(v for v in cfg.vips if v.name == "vip-static-mail")
    assert (stat.ext_ip, stat.mapped_ip) == ("203.0.113.6", "10.1.0.20")


def test_routes():
    cfg = parse_curly()
    dests = {r.dest: r.gateway for r in cfg.routes}
    assert dests["0.0.0.0/0"] == "203.0.113.1"
    assert dests["10.9.0.0/16"] == "10.1.0.254"


def test_route_based_vpn():
    cfg = parse_curly()
    p1 = cfg.phase1s[0]
    assert p1.name == "vpn-branch-vpn"
    assert p1.remote_gw == "198.51.100.9"
    assert p1.ike_version == 2
    assert "aes256-sha256" in p1.proposals
    assert p1.dhgrp == ["14"]
    assert p1.psk == "mysecretkey"
    p2 = cfg.phase2s[0]
    assert (p2.src, p2.dst) == ("10.1.0.0/24", "10.2.0.0/24")
    assert p2.pfs_group == "14"
    # tunnel route + bidirectional policies generated
    assert any(r.dest == "10.2.0.0/24" and r.interface == "vpn-branch-vpn"
               for r in cfg.routes)
    assert any(p.dst_zones == ["vpn-branch-vpn"] for p in cfg.policies)


def test_encrypted_psk_flagged():
    text = (FIX / "srx_sample.conf").read_text(encoding="utf-8").replace(
        "pre-shared-key ascii-text mysecretkey",
        "pre-shared-key ascii-text \"$9$abc123DEF\"")
    cfg = juniper_srx.parse(text, "x.conf")
    assert cfg.phase1s[0].psk == "CHANGEME-PSK"
    assert any("Junos-encrypted" in m and lvl == "error"
               for lvl, _, m, _ in findings(cfg))


def test_both_formats_parity():
    curly = parse_curly()
    setc = juniper_srx.parse(set_text(), "srx_sample.set")

    def summ(c):
        return {
            "if": sorted((i.name, i.ip, i.vlan_id) for i in c.interfaces),
            "zones": sorted((z.name, tuple(z.members)) for z in c.zones),
            "addr": sorted((a.name, a.value) for a in c.addresses),
            "pol": sorted(
                (p.name, tuple(p.src_zones), tuple(p.dst_zones),
                 tuple(p.src_addrs), tuple(p.services), p.action)
                for p in c.policies),
            "nat": sorted((n.real_ifc, n.mapped_ifc) for n in c.nats),
            "vip": sorted((v.name, v.ext_ip, v.mapped_ip) for v in c.vips),
            "rt": sorted((r.dest, r.gateway) for r in c.routes),
            "p1": sorted((p.name, p.remote_gw) for p in c.phase1s),
            "bgp": (c.bgp.asn, c.bgp.router_id,
                    sorted((n.ip, n.remote_as) for n in c.bgp.neighbors))
            if c.bgp else None,
            "ospf": (c.ospf.router_id,
                     sorted((a.id, tuple(sorted(a.networks)),
                             tuple(sorted(a.passive)))
                            for a in c.ospf.areas)) if c.ospf else None,
        }

    assert summ(curly) == summ(setc)


def test_e2e_cli(tmp_path):
    mapfile = tmp_path / "ports.map"
    mapfile.write_text(
        "ge-0/0/0.0 = wan1\nge-0/0/1.0 = internal1\n"
        "ge-0/0/1.30 = vlan30\nst0.0 = st0.0\n", encoding="utf-8")
    rc = cli.main(["convert", str(FIX / "srx_sample.conf"),
                   "-o", str(tmp_path), "--map", str(mapfile)])
    assert rc == 0
    conf = (tmp_path / "srx_sample.config-all.txt").read_text(
        encoding="utf-8")
    report = json.loads(
        (tmp_path / "srx_sample.report.json").read_text(encoding="utf-8"))

    # zone-based policies
    assert "config system zone" in conf
    assert 'set interface "internal1" "vlan30"' in conf
    assert 'set srcintf "trust"' in conf
    assert 'set dstintf "untrust"' in conf
    # NAT enable applied to the trust->untrust pair
    assert "set nat enable" in conf
    # VIPs
    assert 'edit "vip-dnat-web"' in conf
    assert "set extport 443" in conf and "set mappedport 8443" in conf
    # VPN
    assert "config vpn ipsec phase1-interface" in conf
    assert "set remote-gw 198.51.100.9" in conf
    # predefined junos-ssh -> built-in SSH service
    assert 'set service "SSH"' in conf
    # zone names must not be flagged as unmapped interfaces
    assert not any("trust" in f["message"] and "no target port"
                   in f["message"] for f in report["findings"])


def test_routing_instances_flagged():
    text = (FIX / "srx_sample.conf").read_text(encoding="utf-8") + """
routing-instances {
    CUSTOMER-A {
        instance-type virtual-router;
        interface ge-0/0/3.0;
    }
}
"""
    cfg = juniper_srx.parse(text, "ri.conf")
    assert any("routing-instance" in m and "VDOM" in m
               for _, _, m, _ in findings(cfg))


def test_coverage_map():
    text = (FIX / "srx_sample.conf").read_text(encoding="utf-8") + """
security {
    idp {
        idp-policy recommended;
    }
}
"""
    cfg = juniper_srx.parse(text, "cov.conf")
    msgs = [m for _, _, m, _ in findings(cfg)]
    assert any("unread stanza" in m and "idp" in m for m in msgs)


def test_bgp_parsed():
    cfg = parse_curly()
    b = cfg.bgp
    assert b.asn == "65001" and b.router_id == "10.1.0.1"
    nb = {n.ip: n for n in b.neighbors}
    assert nb["203.0.113.1"].remote_as == "65000"      # eBGP group peer-as
    assert nb["10.1.0.7"].remote_as == "65001"         # iBGP -> local AS
    assert nb["10.1.0.7"].description == "dc core"
    msgs = [m for _, _, m, _ in findings(cfg)]
    assert any("export policies" in m and "send-statics" in m
               for m in msgs)


def test_ospf_parsed():
    cfg = parse_curly()
    o = cfg.ospf
    assert o.router_id == "10.1.0.1"
    area = o.areas[0]
    assert area.id == "0.0.0.0"
    # networks derived from the area interfaces' connected subnets
    assert sorted(area.networks) == ["10.1.0.0/24", "192.168.30.0/24"]
    assert area.passive == ["ge-0/0/1.30"]


def test_bgp_ospf_emitted(tmp_path):
    mapfile = tmp_path / "ports.map"
    mapfile.write_text(
        "ge-0/0/0.0 = wan1\nge-0/0/1.0 = internal1\n"
        "ge-0/0/1.30 = vlan30\nst0.0 = st0.0\n", encoding="utf-8")
    rc = cli.main(["convert", str(FIX / "srx_sample.conf"),
                   "-o", str(tmp_path), "--map", str(mapfile)])
    assert rc == 0
    conf = (tmp_path / "srx_sample.config-all.txt").read_text(
        encoding="utf-8")
    assert "config router bgp" in conf
    assert "set as 65001" in conf
    assert "set router-id 10.1.0.1" in conf
    assert 'edit "203.0.113.1"' in conf
    assert "set remote-as 65000" in conf
    assert "config router ospf" in conf
    assert "set prefix 10.1.0.0 255.255.255.0" in conf
    assert "set area 0.0.0.0" in conf
    assert 'set passive-interface "vlan30"' in conf  # mapped name
