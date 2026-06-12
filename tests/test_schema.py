import json
from pathlib import Path

import pytest

from fwforge import cli
from fwforge import schema as sc
from fwforge.report import Report

FIX = Path(__file__).parent / "fixtures"

# structure-only mini schema, shaped like a stripped live fetch
MINI = {
    "version": "8.0.0", "build": 167, "host": "lab", "fetched": "now",
    "tables": {
        "system/global": {"hostname": {}},
        "system/interface": {"vdom": {}, "ip": {}, "role": {},
                             "interface": {}, "vlanid": {}, "type": {},
                             "member": {}},
        "system/sdwan": {"status": {},
                         "members": {"interface": {}, "gateway": {},
                                     "zone": {}, "weight": {}},
                         "zone": {"name": {}}},
        "firewall/address": {"subnet": {}, "comment": {}},
        "firewall/policy": {"name": {}, "srcintf": {}, "dstintf": {},
                            "srcaddr": {}, "dstaddr": {}, "action": {},
                            "schedule": {}, "service": {}, "nat": {},
                            "logtraffic": {}},
        "vpn.ipsec/phase1-interface": {"interface": {}, "remote-gw": {},
                                       "psksecret": {}},
        "router/static": {"dst": {}, "gateway": {}, "device": {}},
    },
}

GOOD = """config system global
    set hostname "box"
end
config system interface
    edit "port1"
        set vdom "root"
        set ip 10.0.0.1 255.255.255.0
    next
end
config vpn ipsec phase1-interface
    edit "t1"
        set interface "port1"
        set remote-gw 203.0.113.9
        set psksecret ENC x
    next
end
config system sdwan
    set status enable
    config members
        edit 1
            set interface "port1"
            set gateway 10.0.0.254
        next
    end
end
"""


def test_table_key_mapping():
    assert sc._table_key(["system", "interface"]) == "system/interface"
    assert sc._table_key(["vpn", "ipsec", "phase1-interface"]) \
        == "vpn.ipsec/phase1-interface"
    assert sc._table_key(["router", "static"]) == "router/static"


def test_clean_config_passes():
    report = Report()
    stats = sc.check(GOOD, MINI, report)
    assert stats["unknown_tables"] == 0
    assert stats["unknown_attrs"] == 0
    assert any("CLEAN" in f.message for f in report.findings)
    assert "CLEAN" in report.meta["schema_check"]


def test_unknown_attr_and_section_flagged():
    # NB: the unknown section must be genuinely fictional — sections a
    # real backup carries that the REST schema hides (replacemsg,
    # gui-dashboard-collection, rule *) are exempted, not flagged
    bad = GOOD + """config firewall super-shield
    edit "d"
        set layout 2
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set fancy-new-knob enable
    next
end
"""
    report = Report()
    stats = sc.check(bad, MINI, report)
    msgs = [f.message for f in report.findings]
    assert stats["unknown_tables"] == 1
    assert stats["unknown_attrs"] == 1
    assert any("super-shield" in m and "dropped" in m for m in msgs)
    assert any("fancy-new-knob" in m for m in msgs)
    # severity split: whole sections = error, single attrs = warn
    assert any(f.level == "error" for f in report.findings
               if "super-shield" in f.message)
    assert any(f.level == "warn" for f in report.findings
               if "fancy-new-knob" in f.message)


def test_nested_table_attrs_checked():
    bad = GOOD.replace("set gateway 10.0.0.254",
                       "set gateway 10.0.0.254\n            "
                       "set warp-speed enable")
    report = Report()
    stats = sc.check(bad, MINI, report)
    assert stats["unknown_attrs"] == 1
    assert any("warp-speed" in f.message
               and "system sdwan > members" in f.message
               for f in report.findings)


def test_multi_vdom_unwrapped():
    text = """config global
config system global
    set hostname "mv"
end
end
config vdom
edit root
config firewall address
    edit "a"
        set subnet 10.0.0.0 255.0.0.0
    next
end
next
end
"""
    report = Report()
    stats = sc.check(text, MINI, report)
    assert stats["unknown_tables"] == 0
    assert stats["unknown_attrs"] == 0


def test_target_train_mismatch_warns():
    report = Report()
    sc.check(GOOD, MINI, report, target="7.4")
    assert any("targets 7.4" in f.message for f in report.findings)


def test_cache_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(sc, "SCHEMA_DIR", tmp_path / "schemas")
    p = sc.save(MINI)
    assert p.name == "fortios-8.0.0-b167.json"
    loaded = sc.load(p)
    assert loaded["tables"].keys() == MINI["tables"].keys()
    cached = sc.list_cached()
    assert len(cached) == 1
    assert cached[0]["version"] == "8.0.0"
    # resolve() takes the file path directly
    schema, fetched = sc.resolve(str(p))
    assert not fetched and schema["build"] == 167


def test_resolve_host_without_token_errors():
    with pytest.raises(ValueError, match="token"):
        sc.resolve("10.0.0.1")


def test_e2e_cli_schema_check(tmp_path):
    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps(MINI), encoding="utf-8")
    src = tmp_path / "box.conf"
    src.write_text(
        "#config-version=FGT601F-8.0.0-FW-build167-260301:opmode=0:"
        "vdom=0:user=admin\n" + GOOD, encoding="utf-8")
    out = tmp_path / "out"
    rc = cli.main(["convert", str(src), "-o", str(out),
                   "--fortios", "8.0",
                   "--schema-check", str(schema_file)])
    assert rc == 0
    report = json.loads(
        (out / "box.report.json").read_text(encoding="utf-8"))
    assert "CLEAN" in report["meta"]["schema_check"]

    # an unknown section turns the run into exit 1 with an error finding
    src2 = tmp_path / "box2.conf"
    src2.write_text(
        src.read_text(encoding="utf-8")
        + "config system quantum-tunnel\n    set spin up\nend\n",
        encoding="utf-8")
    rc2 = cli.main(["convert", str(src2), "-o", str(out),
                    "--fortios", "8.0",
                    "--schema-check", str(schema_file)])
    assert rc2 == 1
    conf = (out / "box2.conf").read_text(encoding="utf-8")
    assert "quantum-tunnel" in conf  # output still written
    assert any("does not exist on FortiOS" in line
               for line in conf.splitlines() if line.startswith("#"))


def test_scalar_attr_not_accepted_as_nested_table():
    # a `config <scalar-attr>` block must NOT be masked by the
    # first-token nested-table fallback (router-id is a leaf, not a table)
    sch = {"version": "8.0.0", "build": 1, "tables": {
        "router/bgp": {"as": {}, "router-id": {},
                       "redistribute": {"status": {}}}}}
    good = ('config router bgp\n    set as 65001\n'
            '    config redistribute "connected"\n'
            '        set status enable\n    end\nend\n')
    r = Report()
    assert sc.check(good, sch, r)["unknown_tables"] == 0  # real nested table
    bad = ('config router bgp\n    set as 65001\n'
           '    config router-id "x"\n        set foo bar\n    end\nend\n')
    r2 = Report()
    assert sc.check(bad, sch, r2)["unknown_tables"] == 1  # scalar, not table


def test_check_without_tables_raises():
    import pytest
    with pytest.raises(ValueError, match="tables"):
        sc.check("config system global\nend\n", {"version": "8.0"},
                 Report())


def test_schema_check_skips_fortiguard_and_internal_attrs():
    out = """config rule iotd "Vendor.Device"
    set behavior x
end
config rule otdt "Other.Sig"
    set category y
end
config firewall address
    edit "a"
        set subnet 10.0.0.1 255.255.255.255
        set dirty clean
        set definitely-not-real 1
    next
end
"""
    report = Report()
    stats = sc.check(out, MINI, report)
    # the two FortiGuard signature blocks are not unknown-section errors
    assert stats["unknown_tables"] == 0
    assert report.count("error") == 0
    # 'set dirty' (internal) is skipped; the truly unknown attr remains
    assert stats["unknown_attrs"] == 1
    msgs = " | ".join(f.message for f in report.findings)
    assert "definitely-not-real" in msgs
    assert "dirty" not in msgs.replace("FortiGuard", "")
    assert "skipped" in msgs and "FortiGuard" in msgs


def test_schema_check_skips_replacemsg_and_dashboards():
    out = """config system replacemsg admin "post_admin-disclaimer-text"
    set buffer "x"
end
config system gui-dashboard-collection
    edit 1
        set name "d"
    next
end
"""
    report = Report()
    stats = sc.check(out, MINI, report)
    assert stats["unknown_tables"] == 0
    assert report.count("error") == 0
