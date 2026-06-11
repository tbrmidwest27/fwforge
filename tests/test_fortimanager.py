import json
from pathlib import Path

from fwforge import cli, pipeline
from fwforge.emit import fortimanager
from fwforge.report import Report

FIX = Path(__file__).parent / "fixtures"


def _bundle(fixture="asa_sample.cfg", mapping=None, **kw):
    text = (FIX / fixture).read_text(encoding="utf-8")
    result = pipeline.run_cross(text, "cisco-asa", fixture, mapping or {})
    report = result.report
    return fortimanager.build_bundle(result.cfg, report, **kw), report


def _req_for(bundle, fragment):
    return next(r for r in bundle["requests"]
                if fragment in r["params"][0]["url"])


def test_bundle_structure():
    bundle, report = _bundle(adom="lab", package="migr8")
    assert bundle["fortimanager"]["adom"] == "lab"
    assert bundle["fortimanager"]["package"] == "migr8"

    addr = _req_for(bundle, "/pm/config/adom/lab/obj/firewall/address")
    lan = next(d for d in addr["params"][0]["data"] if d["name"] == "LAN")
    assert lan["subnet"] == ["10.1.0.0", "255.255.0.0"]
    rng = next(d for d in addr["params"][0]["data"]
               if d["name"] == "DMZ-POOL")
    assert rng["type"] == "iprange"
    assert rng["start-ip"] == "192.168.30.100"

    vip = _req_for(bundle, "/obj/firewall/vip")
    v = vip["params"][0]["data"][0]
    assert v["mappedip"] == [{"range": "10.1.1.10"}]
    assert v["portforward"] == "enable"

    pkg = _req_for(bundle, "/pm/pkg/adom/lab")
    assert pkg["params"][0]["data"][0] == {"name": "migr8", "type": "pkg"}

    pol = _req_for(bundle, "/pkg/migr8/firewall/policy")
    p1 = next(d for d in pol["params"][0]["data"]
              if d["name"] == "OUTSIDE-IN-1")
    assert p1["srcintf"] == ["outside"]
    assert p1["srcaddr"] == ["all"]
    assert p1["service"] == ["WEB-PORTS"]
    assert p1["action"] == "accept"
    disabled = next(d for d in pol["params"][0]["data"]
                    if d["name"] == "INSIDE-OUT-4")
    assert disabled["status"] == "disable"

    msgs = [f.message for f in report.findings]
    assert any("FortiManager bundle" in m for m in msgs)
    assert any("per-device mappings or zones" in m for m in msgs)
    assert any("device-level" in m for m in msgs)  # routes present


def test_bundle_uses_mapped_interfaces():
    bundle, _ = _bundle(mapping={"outside": "wan1", "inside": "internal1",
                                 "dmz": "dmz"})
    pol = _req_for(bundle, "/firewall/policy")
    p1 = pol["params"][0]["data"][0]
    assert p1["srcintf"] == ["wan1"]


def test_cli_fmg_flag(tmp_path):
    rc = cli.main([
        "convert", str(FIX / "asa_sample.cfg"), "-o", str(tmp_path),
        "--fmg", "root/migr8",
    ])
    assert rc in (0, 1)
    bundle = json.loads(
        (tmp_path / "asa_sample.fmg.json").read_text(encoding="utf-8"))
    assert bundle["fortimanager"]["package"] == "migr8"
    assert len(bundle["requests"]) >= 5
    report = (tmp_path / "asa_sample.report.md").read_text(encoding="utf-8")
    assert "FortiManager bundle" in report
