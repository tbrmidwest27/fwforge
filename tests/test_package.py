from pathlib import Path

from fwforge.emit import package
from fwforge.report import Report

FIX = Path(__file__).parent / "fixtures"

SAMPLE = """\
#config-version=FGT121G-8.0.0-FW-build0167-260420:vdom=0
#buildno=0167
config system global
    set hostname "x"
end
config firewall address
    edit "a1"
        set subnet 10.0.0.0 255.0.0.0
    next
end
config firewall policy
    edit 1
        config something-nested
            edit 1
            next
        end
    next
end
"""


def test_split_branches():
    branches = package.split_branches(SAMPLE)
    names = [n for n, _ in branches]
    assert names == ["system global", "firewall address", "firewall policy"]
    # nested config doesn't create a top-level branch
    policy_block = dict(branches)["firewall policy"]
    assert "config something-nested" in policy_block
    assert policy_block.strip().endswith("end")


def test_write_full_single_file(tmp_path):
    """FortiGate->FortiGate: one restorable .conf, no branch split."""
    report = Report()
    report.add("warn", "vpn", "set a real PSK")
    pkg = package.write_full(tmp_path, "demo", SAMPLE, report)
    assert pkg["split"] is False
    assert pkg["main_name"] == "demo.conf"
    assert not (tmp_path / "demo.branches").exists()
    text = (tmp_path / "demo.conf").read_text(encoding="utf-8")
    assert text.splitlines()[0].startswith("#config-version=")  # restorable
    assert "# [WARN] vpn: set a real PSK" in text
    assert "config firewall policy" in text


def test_write_split_layout(tmp_path):
    report = Report()
    report.add("error", "nat", "twice-NAT not converted")
    report.add("warn", "vpn", "set a real PSK")
    report.add("info", "names", "renamed X")  # info is NOT embedded

    pkg = package.write_split(tmp_path, "demo", SAMPLE, report)
    config_all = (tmp_path / "demo.config-all.txt").read_text(
        encoding="utf-8")

    # findings embedded as comments, after the #config-version header
    assert config_all.splitlines()[0].startswith("#config-version=")
    assert "# [ERROR] nat: twice-NAT not converted" in config_all
    assert "# [WARN] vpn: set a real PSK" in config_all
    assert "renamed X" not in config_all          # info level excluded
    # the actual config survives intact below the comments
    assert "config firewall address" in config_all

    # per-branch files
    assert pkg["branch_count"] == 3
    files = sorted(p.name for p in pkg["branch_dir"].glob("*.txt"))
    assert files == ["01-system-global.txt", "02-firewall-address.txt",
                     "03-firewall-policy.txt"]
    pol = (pkg["branch_dir"] / "03-firewall-policy.txt").read_text(
        encoding="utf-8")
    assert pol.startswith("config firewall policy")
    assert "# [ERROR]" not in pol                 # branch files are pure


def test_rerun_clears_stale_branches(tmp_path):
    package.write_split(tmp_path, "demo", SAMPLE, Report())
    smaller = "config firewall address\n    edit \"a\"\n    next\nend\n"
    pkg = package.write_split(tmp_path, "demo", smaller, Report())
    assert pkg["branch_count"] == 1
    assert sorted(p.name for p in pkg["branch_dir"].glob("*.txt")) == \
        ["01-firewall-address.txt"]


def test_html_report(tmp_path):
    from fwforge import cli
    report = Report()
    report.add("error", "nat", "x <b>not</b> converted")
    html = report.to_html()
    assert "fwforge conversion report" in html
    assert "&lt;b&gt;not&lt;/b&gt;" in html  # escaped, not injected
    # CLI writes it alongside the other reports
    rc = cli.main(["convert", str(FIX / "fortios_sample.conf"),
                   "-o", str(tmp_path)])
    assert rc in (0, 1)
    out = (tmp_path / "fortios_sample.report.html").read_text(
        encoding="utf-8")
    assert "Summary" in out and "print this page to PDF" in out


def test_restorable_header_stays_first_line(tmp_path):
    """A migrate backup must keep #config-version on line 1 so restore
    accepts it — comments go after the header block, not before."""
    report = Report()
    report.add("warn", "x", "y")
    package.write_split(tmp_path, "demo", SAMPLE, report)
    text = (tmp_path / "demo.config-all.txt").read_text(encoding="utf-8")
    lines = text.splitlines()
    assert lines[0].startswith("#config-version=")
    assert lines[1].startswith("#buildno=")
    # the comment block begins only after the contiguous header
    assert any(l.startswith("# [WARN]") for l in lines)
