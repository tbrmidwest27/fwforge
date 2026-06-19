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


def test_wildcard_apply_groups_merge():
    text = """groups {
    wan-defaults {
        interfaces {
            <ge-0/0/0> {
                unit <*> {
                    description "from-group";
                }
            }
        }
    }
}
apply-groups wan-defaults;
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 198.18.0.2/29;
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            description "local wins";
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone z1 {
            interfaces {
                ge-0/0/0.0;
            }
        }
    }
}
"""
    cfg = juniper_srx.parse(text, "wc.conf")
    byname = {i.name: i for i in cfg.interfaces}
    # wildcard group description lands on the matching interface...
    assert byname["ge-0/0/0.0"].description == "from-group"
    # ...but never overrides explicit config, and never creates stanzas
    assert byname["ge-0/0/1.0"].description == "local wins"


def test_host_inbound_traffic_allowaccess():
    text = """interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 203.0.113.2/29;
            }
        }
    }
}
security {
    zones {
        security-zone untrust {
            interfaces {
                ge-0/0/0.0 {
                    host-inbound-traffic {
                        system-services {
                            ssh;
                            ping;
                            ike;
                        }
                    }
                }
            }
        }
    }
}
"""
    cfg = juniper_srx.parse(text, "hit.conf")
    msgs = [m for _, _, m, _ in findings(cfg)]
    # ssh/ping -> allowaccess; ike has no equivalent and is dropped quietly
    assert any("set allowaccess ping ssh" in m and "ge-0/0/0.0" in m
               for m in msgs)


def test_logical_systems_flagged():
    text = (FIX / "srx_sample.conf").read_text(encoding="utf-8") + """
logical-systems {
    TENANT-A {
        interfaces {
            ge-0/0/5 {
                unit 0;
            }
        }
    }
}
"""
    cfg = juniper_srx.parse(text, "ls.conf")
    assert any(lvl == "error" and "TENANT-A" in m
               for lvl, _, m, _ in findings(cfg))


PB_VPN = """interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 203.0.113.2/29;
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.1.0.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone untrust {
            interfaces {
                ge-0/0/0.0;
            }
        }
        security-zone trust {
            interfaces {
                ge-0/0/1.0;
            }
            address-book {
                address lan 10.1.0.0/24;
                address remote 10.7.0.0/24;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy to-branch {
                match {
                    source-address lan;
                    destination-address remote;
                    application any;
                }
                then {
                    permit {
                        tunnel {
                            ipsec-vpn pb-vpn;
                        }
                    }
                }
            }
        }
    }
    ike {
        proposal p1 {
            dh-group group14;
            authentication-algorithm sha-256;
            encryption-algorithm aes-256-cbc;
        }
        policy ikepol {
            proposals p1;
            pre-shared-key ascii-text secret123;
        }
        gateway gw1 {
            ike-policy ikepol;
            address 198.51.100.77;
            external-interface ge-0/0/0.0;
        }
    }
    ipsec {
        proposal p2 {
            authentication-algorithm hmac-sha-256-128;
            encryption-algorithm aes-256-cbc;
        }
        policy ipsecpol {
            proposals p2;
        }
        vpn pb-vpn {
            ike {
                gateway gw1;
                ipsec-policy ipsecpol;
            }
        }
    }
}
"""


def test_policy_based_vpn_converted():
    cfg = juniper_srx.parse(PB_VPN, "pb.conf")
    p1 = cfg.phase1s[0]
    assert p1.name == "vpn-pb-vpn"
    assert p1.remote_gw == "198.51.100.77"
    # selectors derived from the permit-tunnel policy's addresses
    p2 = cfg.phase2s[0]
    assert (p2.src, p2.dst) == ("10.1.0.0/24", "10.7.0.0/24")
    # the original policy-based rule is kept, disabled, and annotated
    orig = next(p for p in cfg.policies if p.name == "to-branch")
    assert orig.disabled is True
    assert "replaced by route-based tunnel" in orig.comment
    msgs = [m for _, _, m, _ in findings(cfg)]
    assert any("POLICY-BASED" in m and "pb-vpn" in m for m in msgs)


RI_CONF = """interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 203.0.113.2/29;
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.1.0.1/24;
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 10.50.0.1/24;
            }
        }
    }
}
routing-options {
    static {
        route 0.0.0.0/0 next-hop 203.0.113.1;
    }
}
routing-instances {
    CUSTOMER-A-LONGNAME {
        instance-type virtual-router;
        interface ge-0/0/2.0;
        routing-options {
            static {
                route 0.0.0.0/0 next-hop 10.50.0.254;
            }
        }
    }
}
security {
    zones {
        security-zone untrust {
            interfaces {
                ge-0/0/0.0;
            }
        }
        security-zone trust {
            interfaces {
                ge-0/0/1.0;
            }
        }
        security-zone cust-a {
            interfaces {
                ge-0/0/2.0;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy out {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
        from-zone cust-a to-zone cust-a {
            policy intra {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
        global {
            policy g-deny {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                }
            }
        }
    }
}
"""


def test_routing_instances_become_vdoms():
    cfg = juniper_srx.parse(RI_CONF, "ri.conf")
    scopes = dict(cfg.meta["vsys_cfgs"])
    assert set(scopes) == {"root", "CUSTOMER-A-LONGNAME"}
    root, cust = scopes["root"], scopes["CUSTOMER-A-LONGNAME"]
    # interfaces and zones split by instance membership
    assert {i.name for i in root.interfaces} == {"ge-0/0/0.0",
                                                 "ge-0/0/1.0"}
    assert {i.name for i in cust.interfaces} == {"ge-0/0/2.0"}
    assert {z.name for z in root.zones} == {"untrust", "trust"}
    assert {z.name for z in cust.zones} == {"cust-a"}
    # policies follow their zones; global policy replicated
    assert {p.name for p in root.policies} == {"out", "g-deny"}
    assert {p.name for p in cust.policies} == {"intra", "g-deny"}
    # routes: default-instance vs instance routing-options
    assert [r.gateway for r in root.routes] == ["203.0.113.1"]
    assert [r.gateway for r in cust.routes] == ["10.50.0.254"]


def test_ri_vdom_blocks_emitted(tmp_path):
    from fwforge import pipeline
    result = pipeline.run_cross(RI_CONF, "juniper-srx", "ri.conf", {})
    out = result.out_text
    assert "config vdom" in out
    assert "edit root" in out
    # long instance name clamped to a valid VDOM name with a warning
    assert "edit CUSTOMER-A-" not in out or len(
        [l for l in out.splitlines() if l.startswith("edit ")][1]) <= 16
    assert any("VDOM" in f.message and "11 chars" in f.message
               for f in result.report.findings)


def test_bracketed_value_lists():
    # `[ a b c ]` lists must flatten to members, not keep literal brackets
    text = """security {
    zones { security-zone trust { address-book {
        address h1 10.0.0.1/32;
        address h2 10.0.0.2/32; } } }
    policies { from-zone trust to-zone trust {
        policy p { match {
            source-address [ h1 h2 ];
            destination-address any;
            application [ junos-http junos-https ];
        } then { permit; } } } }
}"""
    cfg = juniper_srx.parse(text, "br.conf")
    p = cfg.policies[0]
    assert p.src_addrs == ["h1", "h2"]
    assert "[" not in p.src_addrs and "]" not in p.src_addrs
    assert "ALL" not in p.services  # both apps resolved, no bracket noise
    assert len(p.services) == 2


def test_inactive_marker_curly():
    text = """security {
    zones { security-zone z { } }
    policies { from-zone z to-zone z {
        inactive: policy dead { match { source-address any;
            destination-address any; application any; } then { permit; } }
        policy live { match { source-address any;
            destination-address any; application any; } then { permit; } }
    } }
}"""
    cfg = juniper_srx.parse(text, "ia.conf")
    by = {p.name: p for p in cfg.policies}
    assert by["dead"].disabled is True     # inactive: marker honored
    assert by["live"].disabled is False
    assert "inactive:" not in by["dead"].src_addrs  # marker stripped clean


def test_inactive_leaf_curly():
    # an `inactive:` marker on a *leaf* (here a zone interface) must disable
    # that statement, not merely strip the prefix. Regression: the curly leaf
    # branch computed the inactive flag and threw it away, so a deactivated
    # interface was added as a live zone member (and a deactivated address /
    # route / match-line silently became active).
    text = """security {
    zones { security-zone trust { interfaces {
        ge-0/0/0.0;
        inactive: ge-0/0/1.0;
    } } }
}"""
    cfg = juniper_srx.parse(text, "ial.conf")
    zones = {z.name: z.members for z in cfg.zones}
    assert zones["trust"] == ["ge-0/0/0.0"]  # inactive member excluded


_NESTED_SETS = """security {
    policies { from-zone trust to-zone untrust {
        policy p { match { source-address any; destination-address any;
            application outer; } then { permit; } }
    } }
    zones { security-zone trust { } security-zone untrust { } }
}
applications {
    application app-a { protocol tcp; destination-port 1111; }
    application app-b { protocol tcp; destination-port 2222; }
    application-set inner { application app-b; }
    application-set outer { application app-a; application-set inner; }
}"""


def _policy_ports(cfg, polname):
    pol = _pol(cfg, polname)
    names = set(pol.services)
    for g in cfg.svc_groups:
        if g.name in names:
            names |= set(g.members)
    return " ".join(s.dst_ports for s in cfg.services if s.name in names)


def test_nested_application_set_resolves_in_both_formats():
    # a nested application-set must resolve in BOTH curly and set format.
    # Regression: set format stores the nested set as a container, so
    # leaf_all('application-set') missed it and the inner set's members were
    # silently lost -- narrowing the policy's service.
    curly = juniper_srx.parse(_NESTED_SETS, "nested.conf")
    setc = juniper_srx.parse(
        "\n".join(_to_set(juniper_srx._tree_from_curly(_NESTED_SETS), []))
        + "\n", "nested.set")
    for cfg in (curly, setc):
        ports = _policy_ports(cfg, "p")
        assert "1111" in ports      # outer's direct application
        assert "2222" in ports      # inner (nested) set's application


def test_setformat_vpn_crypto_and_selectors():
    # set-format `proposals` (leaf) and `proxy-identity` (container) must
    # parse the same as curly — regression for two set-only crypto bugs
    text = set_text()  # generated from srx_sample.conf
    setc = juniper_srx.parse(text, "x.set")
    curly = parse_curly()
    sp1 = curly.phase1s[0]
    tp1 = setc.phase1s[0]
    # real proposals (not the aes256-sha256 default) survive in set format
    assert tp1.proposals == sp1.proposals
    assert tp1.dhgrp == sp1.dhgrp
    assert "aes256-sha256" not in tp1.proposals or sp1.proposals == tp1.proposals
    # selectors match (traffic-selector form here; proxy-identity tested below)
    assert [(p.src, p.dst) for p in setc.phase2s] == \
           [(p.src, p.dst) for p in curly.phase2s]


def test_setformat_proxy_identity_selectors():
    text = """security {
    zones { security-zone untrust { interfaces { ge-0/0/0.0; } } }
    ike { proposal pr { dh-group group14;
            authentication-algorithm sha-256;
            encryption-algorithm aes-256-cbc; }
        policy po { proposals pr; pre-shared-key ascii-text sec; }
        gateway gw { ike-policy po; address 198.51.100.1;
            external-interface ge-0/0/0.0; } }
    ipsec { proposal ip { authentication-algorithm hmac-sha-256-128;
            encryption-algorithm aes-256-cbc; }
        policy ipo { proposals ip; }
        vpn v { bind-interface st0.0; ike { gateway gw; ipsec-policy ipo;
            proxy-identity { local 10.1.0.0/24; remote 10.2.0.0/24; } } } }
}"""
    curly = juniper_srx.parse(text, "pi.conf")
    # build set form and reparse
    root = juniper_srx._tree_from_curly(text)
    setlines = _to_set(root, [])
    setc = juniper_srx.parse("\n".join(setlines) + "\n", "pi.set")
    assert (curly.phase2s[0].src, curly.phase2s[0].dst) == \
           ("10.1.0.0/24", "10.2.0.0/24")
    assert (setc.phase2s[0].src, setc.phase2s[0].dst) == \
           (curly.phase2s[0].src, curly.phase2s[0].dst)
    # not the 0.0.0.0/0 fallback
    assert setc.phase2s[0].src != "0.0.0.0/0"


def test_nested_application_set():
    text = """applications {
    application-set inner { application junos-https; }
    application-set outer { application-set inner; application junos-ssh; }
}
security {
    zones { security-zone z { } }
    policies { from-zone z to-zone z {
        policy p { match { source-address any; destination-address any;
            application outer; } then { permit; } } } }
}"""
    cfg = juniper_srx.parse(text, "nas.conf")
    p = cfg.policies[0]
    assert "ALL" not in p.services  # nested set resolved, not widened
    # multi-proto set -> one service group; check its member ports
    grp = next(g for g in cfg.svc_groups if g.name in p.services)
    ports = sorted(s.dst_ports for s in cfg.services
                   if s.name in grp.members)
    assert "443" in ports and "22" in ports


def test_deactivated_zone_pair_disables_policies():
    # a deactivated zone-pair must disable EVERY policy inside it. Regression:
    # disabled was read only from the policy node, so policies under a
    # deactivated `from-zone A to-zone B` stayed ENABLED (silently re-enabling
    # deactivated config).
    text = """security {
    zones { security-zone trust { } security-zone untrust { } }
    policies {
        inactive: from-zone trust to-zone untrust {
            policy p1 { match { source-address any; destination-address any;
                application any; } then { permit; } }
            policy p2 { match { source-address any; destination-address any;
                application any; } then { permit; } }
        }
        from-zone untrust to-zone trust {
            policy live { match { source-address any;
                destination-address any; application any; } then { deny; } }
        }
    }
}"""
    cfg = juniper_srx.parse(text, "dzp.conf")
    by = {p.name: p for p in cfg.policies}
    assert by["p1"].disabled is True and by["p2"].disabled is True
    assert by["live"].disabled is False
    # set-format parity (exercises the set reader's container inactive marker)
    setc = juniper_srx.parse(
        "\n".join(_to_set(juniper_srx._tree_from_curly(text), [])) + "\n",
        "dzp.set")
    sby = {p.name: p for p in setc.policies}
    assert sby["p1"].disabled is True and sby["p2"].disabled is True
    assert sby["live"].disabled is False


def test_ipv6_only_subinterface_flagged():
    # an inet6-only unit has no IPv4 address; the v6 address can't ride in the
    # single-string IR ip, but dropping it MUST be flagged, not silent.
    text = """interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet6 { address 2001:db8::1/64; }
        }
    }
}"""
    cfg = juniper_srx.parse(text, "v6.conf")
    msgs = [m for _, _, m, _ in findings(cfg)]
    assert any("IPv6 interface address 2001:db8::1/64 not converted" in m
               and "ge-0/0/0.0" in m for m in msgs)


def test_dnat_named_match_address_resolved():
    # destination-nat whose match destination-address is a NAMED address-book
    # object must resolve to the object's IP, never ship the name as ext_ip.
    text = """security {
    zones { security-zone untrust { interfaces { ge-0/0/0.0; }
        address-book { address pub-vip 203.0.113.50/32; } } }
    nat { destination {
        pool dnp { address 10.1.0.10/32; }
        rule-set rs { from zone untrust;
            rule r { match { destination-address pub-vip; }
                then { destination-nat { pool dnp; } } } } } }
}"""
    cfg = juniper_srx.parse(text, "dnatname.conf")
    vip = next(v for v in cfg.vips if v.name == "vip-r")
    assert vip.ext_ip == "203.0.113.50"   # resolved, not the literal "pub-vip"
    assert vip.mapped_ip == "10.1.0.10"


def test_dnat_unresolvable_match_address_skipped():
    # neither a CIDR nor a resolvable host object -> warn and SKIP, never a VIP
    # with a bogus ext_ip.
    text = """security {
    zones { security-zone untrust { interfaces { ge-0/0/0.0; } } }
    nat { destination {
        pool dnp { address 10.1.0.10/32; }
        rule-set rs { from zone untrust;
            rule r { match { destination-address no-such-object; }
                then { destination-nat { pool dnp; } } } } } }
}"""
    cfg = juniper_srx.parse(text, "dnatbad.conf")
    assert not any(v.name == "vip-r" for v in cfg.vips)
    msgs = [m for _, _, m, _ in findings(cfg)]
    assert any("skipped" in m and "no-such-object" in m for m in msgs)


def test_setformat_term_app_resolves_not_broadened():
    # C1a regression: a set-format multi-`term` custom application must parse
    # each term's protocol/destination-port. Previously `term` was not a
    # name-consuming container, so the term leaves were lost, `_app_to_specs`
    # found no protocol, returned None, and the policy's service was silently
    # broadened to ALL (the no-silent-broadening bug class).
    # real `display set` output puts each leaf on its own line
    text = (
        "set applications application multiterm term t1 protocol tcp\n"
        "set applications application multiterm term t1 destination-port 8080\n"
        "set applications application multiterm term t2 protocol udp\n"
        "set applications application multiterm term t2 destination-port 9090\n"
        "set security policies from-zone trust to-zone untrust policy p "
        "match source-address any\n"
        "set security policies from-zone trust to-zone untrust policy p "
        "match destination-address any\n"
        "set security policies from-zone trust to-zone untrust policy p "
        "match application multiterm\n"
        "set security policies from-zone trust to-zone untrust policy p "
        "then permit\n")
    cfg = juniper_srx.parse(text, "term.set")
    pol = _pol(cfg, "p")
    assert "ALL" not in pol.services            # not broadened
    ports = _policy_ports(cfg, "p")
    assert "8080" in ports and "9090" in ports  # both terms resolved
    assert not any("multiterm" in m and "no port" in m
                   for _, _, m, _ in findings(cfg))


def test_setformat_unknown_toplevel_stanza_flagged():
    # C2 regression: a top-level set-format keyword the parser doesn't model
    # (firewall/lo0 control-plane filter, policy-options, ...) becomes a leaf
    # on the ROOT node. report_coverage only walked containers, so it was
    # dropped with NO finding. It must now be counted + flagged, upholding the
    # no-silent-loss promise.
    text = (
        "set firewall family inet filter FF-LO0 term t1 from protocol udp\n"
        "set firewall family inet filter FF-LO0 term t1 then accept\n"
        "set interfaces lo0 unit 0 family inet filter input FF-LO0\n"
        "set policy-options prefix-list PL-LOCAL 10.0.0.0/8\n"
        "set security policies from-zone trust to-zone untrust policy p "
        "match source-address any\n"
        "set security policies from-zone trust to-zone untrust policy p "
        "match destination-address any\n"
        "set security policies from-zone trust to-zone untrust policy p "
        "match application any\n"
        "set security policies from-zone trust to-zone untrust policy p "
        "then permit\n")
    cfg = juniper_srx.parse(text, "fw.set")
    msgs = [m for _, _, m, _ in findings(cfg)]
    assert any("firewall" in m and "unread stanza" in m for m in msgs)
    assert any("policy-options" in m and "unread stanza" in m for m in msgs)
    assert cfg.meta.get("stanzas_unread", 0) >= 2
