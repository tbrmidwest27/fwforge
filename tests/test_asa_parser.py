from pathlib import Path

from fwforge.parsers import cisco_asa, detect_vendor
from fwforge.report import Report
from fwforge.transforms import routes as routes_tf

FIX = Path(__file__).parent / "fixtures"


def parse():
    text = (FIX / "asa_sample.cfg").read_text(encoding="utf-8")
    return cisco_asa.parse(text, "asa_sample.cfg"), text


def find_policy(cfg, name):
    return next(p for p in cfg.policies if p.name == name)


def test_detection():
    _, text = parse()
    vendor, conf = detect_vendor(text)
    assert vendor == "cisco-asa"
    assert conf >= 0.7


def test_basics():
    cfg, _ = parse()
    assert cfg.hostname == "lab-asa"
    assert cfg.version.startswith("9.8")
    assert [i.name for i in cfg.interfaces] == ["outside", "inside", "dmz"]
    dmz = cfg.interface_by_name("dmz")
    assert dmz.vlan_id == 30
    assert dmz.parent == "GigabitEthernet0/1"
    assert dmz.ip == "192.168.30.1/24"


def test_objects():
    cfg, _ = parse()
    lan = cfg.address_by_name("LAN")
    assert (lan.type, lan.value) == ("subnet", "10.1.0.0/16")
    rng = cfg.address_by_name("DMZ-POOL")
    assert (rng.type, rng.value) == ("range", "192.168.30.100-192.168.30.150")
    fqdn = cfg.address_by_name("UPDATES-FQDN")
    assert (fqdn.type, fqdn.value) == ("fqdn", "updates.example.com")
    grp = next(g for g in cfg.addr_groups if g.name == "ADMIN-HOSTS")
    assert grp.members == ["h-10.1.1.50", "n-10.1.2.0_24", "WEBSRV-INT"]


def test_service_groups():
    cfg, _ = parse()
    web = next(g for g in cfg.svc_groups if g.name == "WEB-PORTS")
    assert web.members == ["tcp_80", "tcp_443", "tcp_8000-8080"]
    mgmt = next(g for g in cfg.svc_groups if g.name == "MGMT-SVCS")
    assert mgmt.members == ["tcp_22", "udp_161", "icmp_echo", "TCP-8443"]
    t8443 = next(s for s in cfg.services if s.name == "TCP-8443")
    assert (t8443.protocol, t8443.dst_ports) == ("tcp", "8443")


def test_acl_to_policies():
    cfg, _ = parse()
    assert len(cfg.policies) == 9  # UNUSED-ACL is unbound -> not converted

    p1 = find_policy(cfg, "OUTSIDE-IN-1")
    assert p1.src_zones == ["outside"]
    assert p1.src_addrs == ["all"]
    assert p1.dst_addrs == ["WEBSRV-INT"]
    assert p1.services == ["WEB-PORTS"]  # service group in port position
    assert "Public web server access" in p1.comment  # remark carried over

    deny = find_policy(cfg, "OUTSIDE-IN-3")
    assert deny.action == "deny"
    assert deny.log is True

    dns = find_policy(cfg, "INSIDE-OUT-1")
    assert dns.services == ["tcpudp_53"]  # protocol group tcp+udp merged

    high = find_policy(cfg, "INSIDE-OUT-3")
    assert high.services == ["udp_33434-65535"]  # gt 33433

    mgmt = find_policy(cfg, "INSIDE-OUT-4")
    assert mgmt.disabled is True  # 'inactive'
    assert mgmt.services == ["MGMT-SVCS"]
    assert mgmt.src_addrs == ["ADMIN-HOSTS"]

    tr = find_policy(cfg, "DMZ-IN-1")
    assert "time-range BUSINESS" in tr.comment

    icmp = find_policy(cfg, "OUTSIDE-IN-2")
    svc = next(s for s in cfg.services if s.name in icmp.services)
    assert svc.protocol == "icmp" and svc.icmp_type == 0  # echo-reply


def test_port_operator_unbounded_fails_closed():
    # 'gt 65535' / 'lt 1' / 'lt 0' match no ports and FortiOS cannot express
    # them. They must fail closed (ok=False -> policy emitted disabled for
    # review), never an inverted range like '65536-65535' / '1-0' left enabled
    # (which would also break the service table on load). Regression for the
    # silent rule-broadening invariant.
    p = cisco_asa.AsaParser("")
    # normal operators still produce valid ranges
    assert p.parse_port_spec(["gt", "33433"], None) == ("33434-65535", True)
    assert p.parse_port_spec(["lt", "1024"], None) == ("1-1023", True)
    # boundaries that match nothing -> fail closed
    assert p.parse_port_spec(["gt", "65535"], None) == ("", False)
    assert p.parse_port_spec(["lt", "1"], None) == ("", False)
    assert p.parse_port_spec(["lt", "0"], None) == ("", False)


def test_nat():
    cfg, _ = parse()
    assert len(cfg.nats) == 1
    nat = cfg.nats[0]
    assert (nat.kind, nat.real_ifc, nat.mapped_ifc) == (
        "dynamic-interface", "inside", "outside")
    assert len(cfg.vips) == 1
    vip = cfg.vips[0]
    assert vip.ext_ip == "203.0.113.10"
    assert vip.mapped_ip == "10.1.1.10"
    assert vip.ext_intf == "outside"
    assert (vip.protocol, vip.ext_port, vip.mapped_port) == ("tcp", "443", "443")
    # twice-NAT must be flagged as an error, not dropped silently
    findings = cfg.meta["findings"]
    assert any(lvl == "error" and area == "nat" and "twice-NAT" in msg
               for lvl, area, msg, _ in findings)


def test_routes_parsed():
    cfg, _ = parse()
    assert len(cfg.routes) == 2
    assert cfg.routes[0].dest == "0.0.0.0/0"
    assert cfg.routes[0].interface == "outside"
    assert cfg.routes[1].dest == "10.9.0.0/16"


def test_nothing_dropped_silently():
    cfg, _ = parse()
    unparsed_text = " ".join(r.raw for r in cfg.unparsed)
    assert "snmp-server" in unparsed_text
    findings = cfg.meta["findings"]
    assert any("UNUSED-ACL" in msg for _, _, msg, _ in findings)
    assert any(area == "vpn" for _, area, _, _ in findings)  # crypto flagged


def test_route_based_dstintf_inference():
    cfg, _ = parse()
    report = Report()
    routes_tf.infer_dst_zones(cfg, report)
    # dst host 10.1.1.10 is inside the connected 10.1.0.0/16 -> inside
    assert find_policy(cfg, "OUTSIDE-IN-1").dst_zones == ["inside"]
    assert find_policy(cfg, "OUTSIDE-IN-1").dst_inferred is True
    # dst 203.0.113.10 is on the outside connected net -> outside
    assert find_policy(cfg, "INSIDE-OUT-4").dst_zones == ["outside"]
    # FQDN destination cannot be routed -> any, with a warning
    assert find_policy(cfg, "INSIDE-OUT-5").dst_zones == ["any"]
    assert any(f.level == "warn" and "INSIDE-OUT-5" in f.message
               for f in report.findings)


def test_object_nat_static_interface_is_flagged():
    text = """object network WEB
 host 10.1.1.10
 nat (inside,outside) static interface service tcp 3389 3389
"""
    cfg = cisco_asa.parse(text, "t.cfg")
    vip = cfg.vips[0]
    assert vip.ext_ip.startswith("<")          # placeholder, not 'interface'
    assert vip.mapped_ip == "10.1.1.10"
    msgs = [m for lvl, _, m, _ in cfg.meta["findings"] if lvl == "error"]
    assert any("interface address" in m for m in msgs)


def test_truncated_ace_does_not_crash():
    text = "access-list X extended permit ip host\n"
    cfg = cisco_asa.parse(text, "t.cfg")   # must not raise
    assert not cfg.policies
    msgs = [m for lvl, _, m, _ in cfg.meta["findings"] if lvl == "error"]
    assert any("unsupported address token" in m for m in msgs)


def test_numeric_icmp_type_in_ace():
    text = """access-list T extended permit icmp any any 8
access-group T in interface outside
"""
    cfg = cisco_asa.parse(text, "t.cfg")
    svc = cfg.policies[0].services
    assert svc != ["ALL_ICMP"]             # echo-only, not all ICMP
    assert any("icmp_8" in s for s in svc)
