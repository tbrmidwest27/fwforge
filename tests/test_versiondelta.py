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
    assert vd.parse_version("7.4") == (7, 4)          # train only
    assert vd.parse_version("v8.0.1") == (8, 0, 1)    # full patch
    assert vd.parse_version("7.6.3") == (7, 6, 3)
    assert vd.parse_version("garbage") is None
    # backup headers always carry the patch
    assert vd.source_version_from_header(load_tree()) == (7, 4, 4)


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


DOWNGRADE_SRC = """#config-version=FGT601F-8.0.1-FW-build4100-260301:opmode=0:vdom=0:user=admin
config system gui-dashboard-collection
    edit "default"
        set layout 2
    next
end
config firewall address
    edit "printer"
        set hw-version "HP"
    next
end
config vpn ipsec phase1-interface
    edit "to-branch"
        set interface "wan1"
        set remote-gw 203.0.113.9
        set psksecret ENC abc
    next
    edit "to-dc"
        set interface "wan1"
        set dhgrp 20
        set remote-gw 203.0.113.10
        set psksecret ENC def
    next
end
"""


def test_downgrade_scan_80_to_74():
    tree = ft.parse_config(DOWNGRADE_SRC)
    report = Report()
    stats = vd.scan(tree, (8, 0), (7, 4), report)
    msgs = [f.message for f in report.findings]

    # introduced section flagged as dropped on the older build
    assert any("gui-dashboard-collection" in m and "dropped" in m
               for m in msgs)
    # rename reverted: hw-version -> hw-model
    out = ft.serialize(tree)
    assert 'set hw-model "HP"' in out
    assert "hw-version" not in out
    assert stats["auto_fixed"] == 1
    # default flip warned with the reverse wording, only for the entry
    # relying on the default
    p1 = next(m for m in msgs if "goes back 20 -> 14" in m)
    assert "to-branch" in p1 and "to-dc" not in p1
    # the standing rule-based caveat is present
    assert any("config-error-log" in m for m in msgs)
    assert all(f.area == "downgrade" for f in report.findings)


def test_downgrade_empty_phase_tables_silent():
    text = ("#config-version=FGT601F-8.0.1-FW-build4100-260301:opmode=0\n"
            "config vpn ipsec phase1-interface\n"
            "end\n")
    tree = ft.parse_config(text)
    report = Report()
    stats = vd.scan(tree, (8, 0), (7, 4), report)
    assert stats["artifacts"] == 0
    assert not any("dhgrp" in f.message for f in report.findings)


def test_e2e_downgrade_scan_cli(tmp_path):
    srcdir = tmp_path / "in"
    srcdir.mkdir()
    src = srcdir / "newbox.conf"
    src.write_text(DOWNGRADE_SRC, encoding="utf-8")
    rc = cli.main(["convert", str(src), "-o", str(tmp_path),
                   "--fortios", "7.4"])
    assert rc == 0  # warnings only
    report = json.loads(
        (tmp_path / "newbox.report.json").read_text(encoding="utf-8"))
    assert report["meta"]["fortios_versions"] == "8.0 -> 7.4"
    assert report["meta"]["downgrade_artifacts"] >= 2
    assert report["meta"]["downgrade_auto_fixed"] == 1
    conf = (tmp_path / "newbox.conf").read_text(encoding="utf-8")
    assert "set hw-model" in conf
    assert src.read_text(encoding="utf-8") == DOWNGRADE_SRC  # untouched


def test_cli_refuses_to_overwrite_its_input(tmp_path):
    src = tmp_path / "samebox.conf"
    src.write_text(DOWNGRADE_SRC, encoding="utf-8")
    rc = cli.main(["convert", str(src), "-o", str(tmp_path),
                   "--fortios", "7.4"])
    assert rc == 0
    # input intact; output written under a shifted stem
    assert src.read_text(encoding="utf-8") == DOWNGRADE_SRC
    out = (tmp_path / "samebox-converted.conf").read_text(encoding="utf-8")
    assert "set hw-model" in out


def test_same_train_patchless_target_is_silent():
    # picking target "7.6" for a 7.6.6 source is not a downgrade
    tree = ft.parse_config(DOWNGRADE_SRC)
    report = Report()
    stats = vd.scan(tree, (8, 0, 1), (8, 0), report)
    assert stats["direction"] == "none"
    assert not report.findings


def test_within_train_downgrade_gets_caveat():
    tree = ft.parse_config(DOWNGRADE_SRC)
    report = Report()
    stats = vd.scan(tree, (8, 0, 1), (8, 0, 0), report)
    assert stats["direction"] == "down"
    msgs = [f.message for f in report.findings]
    assert any("8.0.1 -> 8.0.0" in m and "config-error-log" in m
               for m in msgs)
    # no train-boundary rules fire inside the train
    assert not any("gui-dashboard-collection" in m for m in msgs)


def test_patch_scoped_rule_fires_within_train():
    rule = vd.DeltaRule(
        (7, 6, 3), "introduced-attr", ("system", "global"),
        attr="fake-new-knob", level="warn")
    vd.RULES.append(rule)
    try:
        text = ("#config-version=FGT601F-7.6.6-FW-build3510-250101:"
                "opmode=0:vdom=0\n"
                "config system global\n"
                "    set fake-new-knob enable\n"
                "end\n")
        tree = ft.parse_config(text)
        report = Report()
        stats = vd.scan(tree, (7, 6, 6), (7, 6, 1), report)
        msgs = [f.message for f in report.findings]
        assert any("[7.6.3]" in m and "fake-new-knob" in m for m in msgs)
        assert stats["artifacts"] >= 1
        # and it does NOT fire when the move stays above it
        report2 = Report()
        vd.scan(ft.parse_config(text), (7, 6, 6), (7, 6, 4), report2)
        assert not any("fake-new-knob" in f.message
                       for f in report2.findings)
    finally:
        vd.RULES.remove(rule)


def test_e2e_within_train_downgrade_uses_header_patch(tmp_path):
    # the GUI pre-fills source-os with the train; the header's patch
    # must still drive within-train comparisons
    srcdir = tmp_path / "in"
    srcdir.mkdir()
    src = srcdir / "train.conf"
    src.write_text(DOWNGRADE_SRC, encoding="utf-8")
    rc = cli.main(["convert", str(src), "-o", str(tmp_path),
                   "--source-os", "8.0", "--fortios", "8.0.0"])
    assert rc == 0
    report = json.loads(
        (tmp_path / "train.report.json").read_text(encoding="utf-8"))
    assert report["meta"]["fortios_versions"] == "8.0.1 -> 8.0.0"
    assert "downgrade_artifacts" in report["meta"]
