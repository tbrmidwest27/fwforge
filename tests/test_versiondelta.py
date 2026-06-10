import json
from pathlib import Path

from fwforge import cli
from fwforge.parsers import fortios_tree as ft
from fwforge.report import Report
from fwforge.transforms import versiondelta as vd

FIX = Path(__file__).parent / "fixtures"


def load_tree():
    return ft.parse_config(
        (FIX / "fortios_74_legacy.conf").read_text(encoding="utf-8"))


def test_version_parsing():
    assert vd.parse_version("7.4") == (7, 4)
    assert vd.parse_version("v8.0.1") == (8, 0)
    assert vd.parse_version("garbage") is None
    assert vd.source_version_from_header(load_tree()) == (7, 4)


def test_scan_74_to_80_finds_all_artifact_classes():
    tree = load_tree()
    report = Report()
    stats = vd.scan(tree, (7, 4), (8, 0), report)
    msgs = [f.message for f in report.findings]

    # removed feature (7.6): SSL-VPN
    assert any("SSL-VPN tunnel mode was removed" in m for m in msgs)
    assert any(f.level == "error" for f in report.findings
               if "SSL-VPN tunnel mode" in f.message)
    assert any("portals present" in m for m in msgs)
    # default flips (8.0): only the phase1 WITHOUT dhgrp is flagged
    p1 = next(m for m in msgs if "phase1 has no explicit" in m)
    assert "to-branch" in p1 and "to-dc" not in p1
    assert any("phase2 has no explicit" in m for m in msgs)
    assert any("allow-traffic-redirect" in m for m in msgs)
    # removed section/attr (8.0)
    assert any("gui-dashboard" in m for m in msgs)
    assert any("intra-vap-privacy" in m for m in msgs)
    # behavior note for IPS inline
    assert any("detection-only" in m for m in msgs)
    # NP7 note
    assert any("NP7 defaults changed" in m for m in msgs)
    # auto-fix applied in the tree
    assert stats["auto_fixed"] == 1
    out = ft.serialize(tree)
    assert 'set hw-version "HP"' in out
    assert "hw-model" not in out
    assert any("auto-renamed" in m for m in msgs)


def test_same_version_scan_is_silent():
    tree = load_tree()
    report = Report()
    stats = vd.scan(tree, (7, 4), (7, 4), report)
    assert stats["artifacts"] == 0
    assert not report.findings


def test_intermediate_target_only_applies_crossed_versions():
    tree = load_tree()
    report = Report()
    vd.scan(tree, (7, 4), (7, 6), report)
    msgs = [f.message for f in report.findings]
    assert any("SSL-VPN" in m for m in msgs)  # 7.6 rule crossed
    assert not any("dhgrp" in m for m in msgs)  # 8.0 rules not crossed


def test_renamed_section_autofix():
    text = (
        "#config-version=FGT60E-6.2.3-FW-build1066-191219:opmode=0\n"
        "config system virtual-wan-link\n"
        "    set status enable\n"
        "end\n"
    )
    tree = ft.parse_config(text)
    report = Report()
    vd.scan(tree, (6, 2), (7, 4), report)
    out = ft.serialize(tree)
    assert "config system sdwan" in out
    assert "virtual-wan-link" not in out


def test_e2e_upgrade_scan_cli(tmp_path):
    rc = cli.main([
        "convert", str(FIX / "fortios_74_legacy.conf"),
        "-o", str(tmp_path), "--fortios", "8.0",
    ])
    # SSL-VPN artifact is error-level -> exit 1 (finished, with errors)
    assert rc == 1
    report = json.loads(
        (tmp_path / "fortios_74_legacy.report.json").read_text(
            encoding="utf-8"))
    assert report["meta"]["fortios_versions"] == "7.4 -> 8.0"
    assert report["meta"]["upgrade_artifacts"] >= 7
    assert report["meta"]["upgrade_auto_fixed"] == 1
    md = (tmp_path / "fortios_74_legacy.report.md").read_text(
        encoding="utf-8")
    assert "Errors" in md and "SSL-VPN" in md


def test_e2e_same_version_no_upgrade_findings(tmp_path):
    rc = cli.main([
        "convert", str(FIX / "fortios_74_legacy.conf"),
        "-o", str(tmp_path), "--fortios", "7.4",
    ])
    assert rc == 0
    report = json.loads(
        (tmp_path / "fortios_74_legacy.report.json").read_text(
            encoding="utf-8"))
    assert "upgrade_artifacts" not in report["meta"]
    assert not any(f["area"] == "upgrade" and "removed" in f["message"]
                   for f in report["findings"])
