from pathlib import Path

from fwforge import cli, pipeline
from fwforge.parsers import paloalto, pfsense

FIX = Path(__file__).parent / "fixtures"


def _p1(cfg, name):
    return next(p for p in cfg.phase1s if p.name == name)


# -- Palo Alto IPsec --------------------------------------------------------

def test_pan_ipsec():
    cfg = paloalto.parse((FIX / "pa_vpn.xml").read_text(encoding="utf-8"),
                         "pa_vpn.xml")
    assert len(cfg.phase1s) == 1
    t = _p1(cfg, "vpn-branch-vpn")
    assert t.interface == "ethernet1/1"        # gateway local-address
    assert t.remote_gw == "198.51.100.9"
    assert t.ike_version == 2
    assert t.proposals == ["aes256-sha256"]    # from ike-crypto-profile
    assert t.dhgrp == ["14"]
    assert t.psk == "plainsecret"
    assert t.keylife == 28800

    p2 = next(p for p in cfg.phase2s if p.phase1 == "vpn-branch-vpn")
    assert (p2.src, p2.dst) == ("10.20.0.0/16", "192.168.50.0/24")
    assert p2.pfs_group == "14"
    assert p2.proposals == ["aes256-sha256"]

    # tunnel route + bidirectional policies with inferred LAN interface
    assert any(r.dest == "192.168.50.0/24" and r.interface == "vpn-branch-vpn"
               for r in cfg.routes)
    out = next(p for p in cfg.policies if p.name == "vpn-branch-vpn-out-1")
    assert out.src_zones == ["ethernet1/2"]    # inferred from 10.20.0.0/16
    assert out.dst_zones == ["vpn-branch-vpn"]


def test_pan_encrypted_psk_flagged():
    xml = (FIX / "pa_vpn.xml").read_text(encoding="utf-8").replace(
        "<key>plainsecret</key>",
        "<key>-AQ==abcdefghijklmnopqrstuvwxyz0123456789ABCD=</key>")
    cfg = paloalto.parse(xml, "x")
    t = _p1(cfg, "vpn-branch-vpn")
    assert t.psk == "CHANGEME-PSK"
    assert any(lvl == "error" and "encrypted" in m
               for lvl, _, m, _ in cfg.meta["findings"])


def test_pan_no_vpn_still_works():
    # the original PA sample has no IPsec -> no phase1s, no crash
    cfg = paloalto.parse((FIX / "pa_sample.xml").read_text(encoding="utf-8"),
                         "pa_sample.xml")
    assert cfg.phase1s == []
    assert len(cfg.policies) == 4   # unchanged from before


def test_pan_zone_with_tunnel_iface_resolves_to_phase1():
    # a zone that includes the PAN tunnel-interface (tunnel.1) must emit the
    # FortiOS phase1-interface name (the real tunnel interface), not the raw
    # tunnel.1 — which never exists, so 'set interface "tunnel.1"' fails to
    # load (-3). The VPN section must also precede the zone that references it.
    xml = (FIX / "pa_vpn.xml").read_text(encoding="utf-8").replace(
        '<vsys><entry name="vsys1"><zone/></entry></vsys>',
        '<vsys><entry name="vsys1"><zone>'
        '<entry name="IPSEC_VPN"><network><layer3>'
        '<member>tunnel.1</member></layer3></network></entry></zone>'
        '</entry></vsys>')
    result = pipeline.run_cross(xml, "paloalto", "pav.xml", {})
    out = result.out_text
    # zone points at the realized tunnel interface; nothing dangles on tunnel.1
    assert 'set interface "vpn-branch-vpn"' in out
    assert '"tunnel.1"' not in out
    # phase1-interface (which creates that tunnel iface) precedes the zone
    assert out.index("config vpn ipsec phase1-interface") < \
        out.index("config system zone")
    # the tunnel iface isn't mis-flagged as an unmapped physical port
    assert not any("tunnel.1" in f.message and "no target port" in f.message
                   for f in result.report.findings)


# -- pfSense IPsec ----------------------------------------------------------

def test_pfsense_ipsec():
    cfg = pfsense.parse((FIX / "pfsense_vpn.xml").read_text(encoding="utf-8"),
                        "pfsense_vpn.xml")
    assert len(cfg.phase1s) == 1
    t = _p1(cfg, "vpn-ike1")
    assert t.interface == "wan"
    assert t.remote_gw == "198.51.100.9"
    assert t.ike_version == 2
    assert t.proposals == ["aes256-sha256"]
    assert t.dhgrp == ["14"]
    assert t.psk == "branchpsk"

    p2 = next(p for p in cfg.phase2s if p.phase1 == "vpn-ike1")
    assert (p2.src, p2.dst) == ("10.30.0.0/16", "192.168.60.0/24")
    assert p2.pfs_group == "14"
    assert p2.proposals == ["aes256-sha256"]

    out = next(p for p in cfg.policies if p.name == "vpn-ike1-out-1")
    assert out.src_zones == ["lan"]            # inferred from 10.30.0.0/16
    assert out.dst_zones == ["vpn-ike1"]
    assert any(r.dest == "192.168.60.0/24" and r.interface == "vpn-ike1"
               for r in cfg.routes)


def test_pfsense_ipsec_stub_phase1_skipped():
    # the original pfSense sample has a phase1 with no phase2 -> skipped,
    # not silently converted
    cfg = pfsense.parse(
        (FIX / "pfsense_sample.xml").read_text(encoding="utf-8"), "x")
    assert cfg.phase1s == []
    assert any("no phase2" in m for _, _, m, _ in cfg.meta["findings"])


# -- end to end -------------------------------------------------------------

def test_pan_vpn_e2e_emits_fortios(tmp_path):
    mapfile = tmp_path / "ports.map"
    mapfile.write_text("ethernet1/1 = wan1\nethernet1/2 = internal1\n",
                       encoding="utf-8")
    rc = cli.main(["convert", str(FIX / "pa_vpn.xml"), "-o", str(tmp_path),
                   "--map", str(mapfile)])
    assert rc == 0
    conf = (tmp_path / "pa_vpn.config-all.txt").read_text(encoding="utf-8")
    assert "config vpn ipsec phase1-interface" in conf
    blocks = conf.split("    edit ")
    p1 = next(b for b in blocks if b.startswith('"vpn-branch-vpn"'))
    assert 'set interface "wan1"' in p1          # mapped egress
    assert "set ike-version 2" in p1
    assert "set proposal aes256-sha256" in p1
    assert 'set psksecret "plainsecret"' in p1
    p2 = next(b for b in blocks if b.startswith('"vpn-branch-vpn-p2-1"'))
    assert "set src-subnet 10.20.0.0 255.255.0.0" in p2
    assert "set dst-subnet 192.168.50.0 255.255.255.0" in p2
    assert "set dhgrp 14" in p2                   # PFS


def test_pfsense_vpn_e2e(tmp_path):
    rc = cli.main(["convert", str(FIX / "pfsense_vpn.xml"),
                   "-o", str(tmp_path)])
    assert rc == 0
    conf = (tmp_path / "pfsense_vpn.config-all.txt").read_text(
        encoding="utf-8")
    assert 'edit "vpn-ike1"' in conf
    assert "set src-subnet 10.30.0.0 255.255.0.0" in conf
    assert 'set device "vpn-ike1"' in conf       # tunnel route
