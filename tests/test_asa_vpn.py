from pathlib import Path

from fwforge import cli
from fwforge.parsers import cisco_asa

FIX = Path(__file__).parent / "fixtures"


def parse():
    return cisco_asa.parse(
        (FIX / "asa_vpn.cfg").read_text(encoding="utf-8"), "asa_vpn.cfg")


def msgs(cfg):
    return [m for _, _, m, _ in cfg.meta["findings"]]


def p1(cfg, name):
    return next(p for p in cfg.phase1s if p.name == name)


def test_phase1_ikev1():
    cfg = parse()
    assert len(cfg.phase1s) == 2
    t = p1(cfg, "s2s-113-99")
    assert t.ike_version == 1
    assert t.interface == "outside"
    assert t.remote_gw == "203.0.113.99"
    assert t.proposals == ["aes256-sha1"]  # from ikev1 policy 10
    assert t.dhgrp == ["2"]
    assert t.keylife == 86400
    assert t.psk == "branchsecret"


def test_phase1_ikev2_with_masked_psk():
    cfg = parse()
    t = p1(cfg, "s2s-113-77")
    assert t.ike_version == 2
    assert t.proposals == ["aes256-sha256"]  # from ikev2 policy 10
    assert t.dhgrp == ["14", "5"]
    # masked '*****' keys in the export -> placeholder + error finding
    assert t.psk == "CHANGEME-PSK"
    assert any(lvl == "error" and "masked" in m
               for lvl, _, m, _ in cfg.meta["findings"])


def test_phase2_selectors_and_pfs():
    cfg = parse()
    assert len(cfg.phase2s) == 3
    b1 = next(p for p in cfg.phase2s if p.name == "s2s-113-99-p2-1")
    assert (b1.src, b1.dst) == ("10.20.0.0/16", "192.168.50.0/24")
    assert b1.pfs_group == "14"  # set pfs group14
    assert b1.keylife == 3600  # SA lifetime carried to keylifeseconds
    assert b1.proposals == ["aes256-sha1"]
    b2 = next(p for p in cfg.phase2s if p.name == "s2s-113-99-p2-2")
    assert b2.src == "10.20.99.0/24"  # second ACE -> second selector
    dc = next(p for p in cfg.phase2s if p.phase1 == "s2s-113-77")
    assert dc.pfs_group == ""  # no 'set pfs' on the ASA = PFS off
    assert dc.proposals == ["aes256-sha256"]


def test_vpn_ramifications():
    cfg = parse()
    # routes: default + one per unique remote subnet per tunnel
    vpn_routes = [r for r in cfg.routes if not r.gateway]
    assert {(r.dest, r.interface) for r in vpn_routes} == {
        ("192.168.50.0/24", "s2s-113-99"),
        ("172.16.0.0/16", "s2s-113-77"),
    }
    # policies: 1 ACL policy + out/in pair per selector (3 selectors)
    assert len(cfg.policies) == 1 + 6
    out = next(p for p in cfg.policies if p.name == "s2s-113-99-out-1")
    assert out.src_zones == ["inside"]  # inferred from connected net
    assert out.dst_zones == ["s2s-113-99"]
    assert out.src_addrs == ["LAN"] and out.dst_addrs == ["BRANCH-NET"]
    inn = next(p for p in cfg.policies if p.name == "s2s-113-99-in-1")
    assert inn.src_zones == ["s2s-113-99"]
    assert inn.dst_zones == ["inside"]
    # crypto ACLs consumed, not reported as dangling
    assert any("consumed as VPN" in m for m in msgs(cfg))
    assert not any("VPN-BRANCH" in m and "not bound" in m for m in msgs(cfg))
    # dial-up flagged, never silent
    assert any("dial-up" in m for m in msgs(cfg))


def test_e2e_vpn_emission(tmp_path):
    mapfile = tmp_path / "ports.map"
    mapfile.write_text("outside = wan1\ninside = internal1\n",
                       encoding="utf-8")
    rc = cli.main([
        "convert", str(FIX / "asa_vpn.cfg"),
        "-o", str(tmp_path), "--map", str(mapfile),
    ])
    assert rc == 1  # masked PSK is an error-level finding
    conf = (tmp_path / "asa_vpn.config-all.txt").read_text(encoding="utf-8")

    assert "config vpn ipsec phase1-interface" in conf
    blocks = conf.split("    edit ")
    branch = next(b for b in blocks if b.startswith('"s2s-113-99"'))
    assert 'set interface "wan1"' in branch  # portmap applied
    assert "set proposal aes256-sha1" in branch
    assert 'set psksecret "branchsecret"' in branch
    assert "set keylife 86400" in branch
    dc = next(b for b in blocks if b.startswith('"s2s-113-77"'))
    assert "set ike-version 2" in dc
    assert "set dhgrp 14 5" in dc
    assert "CHANGEME-PSK" in dc

    p2_branch = next(b for b in blocks
                     if b.startswith('"s2s-113-99-p2-1"'))
    assert "set dhgrp 14" in p2_branch  # PFS group14
    assert "set keylifeseconds 3600" in p2_branch
    assert "set src-subnet 10.20.0.0 255.255.0.0" in p2_branch
    assert "set dst-subnet 192.168.50.0 255.255.255.0" in p2_branch
    p2_dc = next(b for b in blocks if b.startswith('"s2s-113-77-p2-1"'))
    assert "set pfs disable" in p2_dc  # ASA default preserved

    # tunnel route: device only, no gateway
    route_block = next(b for b in blocks
                       if 'set device "s2s-113-99"' in b)
    assert "set gateway" not in route_block
    # VPN policy pair with inferred LAN interface
    pol = next(b for b in blocks if 'set name "s2s-113-99-out-1"' in b)
    assert 'set srcintf "internal1"' in pol
    assert 'set dstintf "s2s-113-99"' in pol
