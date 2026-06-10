import json
from pathlib import Path

from fwforge import cli

FIX = Path(__file__).parent / "fixtures"


def _policy_block(text: str, name: str) -> str:
    blocks = text.split("    edit ")
    return next(b for b in blocks if f'set name "{name}"' in b)


def test_convert_asa_end_to_end(tmp_path):
    mapfile = tmp_path / "ports.map"
    mapfile.write_text(
        "outside = wan1\ninside = internal1\ndmz = dmz\n", encoding="utf-8"
    )
    rc = cli.main([
        "convert", str(FIX / "asa_sample.cfg"),
        "-o", str(tmp_path), "--map", str(mapfile),
    ])
    # twice-NAT in the fixture is reported as an error -> exit code 1
    assert rc == 1

    conf = (tmp_path / "asa_sample.config-all.txt").read_text(encoding="utf-8")
    report_md = (tmp_path / "asa_sample.report.md").read_text(encoding="utf-8")
    report = json.loads(
        (tmp_path / "asa_sample.report.json").read_text(encoding="utf-8")
    )

    # interface mapping applied
    assert 'set srcintf "wan1"' in conf
    assert 'set srcintf "internal1"' in conf
    # built-in reuse: tcp/443 -> HTTPS; tcp+udp/53 -> DNS; udp/53 alone never
    assert 'set service "DNS"' in conf
    assert '"HTTPS"' in conf
    # but non-exact matches stay custom
    assert 'edit "udp_33434-65535"' in conf
    # VIP from static object NAT
    assert 'edit "vip-WEBSRV-INT"' in conf
    assert "set extip 203.0.113.10" in conf
    assert "set portforward enable" in conf
    # interface PAT applied to the matching policy
    nat_pol = _policy_block(conf, "INSIDE-OUT-4")
    assert "set nat enable" in nat_pol
    assert "set status disable" in nat_pol  # was 'inactive' on the ASA
    # provenance-rich report
    assert report["summary"]["policies"] == 9
    assert report["summary"]["errors"] >= 1
    assert any("twice-NAT" in f["message"] for f in report["findings"])
    assert "Unconverted source lines" in report_md
    # everything mapped -> no sample portmap emitted
    assert not (tmp_path / "asa_sample.portmap").exists()


def test_convert_asa_without_map_writes_sample(tmp_path):
    rc = cli.main([
        "convert", str(FIX / "asa_sample.cfg"), "-o", str(tmp_path),
    ])
    assert rc == 1
    sample = (tmp_path / "asa_sample.portmap").read_text(encoding="utf-8")
    assert "outside" in sample and "CHANGE_ME" in sample


def test_migrate_fortios_end_to_end(tmp_path):
    mapfile = tmp_path / "ports.map"
    mapfile.write_text("port1 = wan1\nport2 = internal1\n", encoding="utf-8")
    rc = cli.main([
        "convert", str(FIX / "fortios_sample.conf"),
        "-o", str(tmp_path), "--map", str(mapfile),
    ])
    assert rc == 0
    # FortiGate->FortiGate = one full restorable .conf, not split files
    conf = (tmp_path / "fortios_sample.conf").read_text(encoding="utf-8")
    assert not (tmp_path / "fortios_sample.branches").exists()
    assert conf.splitlines()[0].startswith("#config-version=")  # restorable
    assert 'edit "wan1"' in conf
    assert 'set dstintf "wan1"' in conf
    # unknown-to-the-tool sections survive a migration untouched
    assert "config system ntp" in conf
    assert "-----BEGIN CERTIFICATE-----" in conf


def test_detect_command(capsys):
    rc = cli.main(["detect", str(FIX / "asa_sample.cfg")])
    assert rc == 0
    assert "cisco-asa" in capsys.readouterr().out
