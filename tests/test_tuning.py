from pathlib import Path

from fwforge import cli, pipeline
from fwforge.model import (Address, AddressGroup, FirewallConfig, Policy,
                          Service)
from fwforge.report import Report
from fwforge.transforms import tuning
from fwforge.transforms.tuning import TuningOptions

FIX = Path(__file__).parent / "fixtures"


def _cfg():
    cfg = FirewallConfig(vendor="test")
    cfg.addresses = [
        Address(name="a1", type="host", value="10.0.0.1"),
        Address(name="a2", type="host", value="10.0.0.1"),   # dup of a1
        Address(name="used", type="subnet", value="10.1.0.0/16"),
        Address(name="orphan", type="host", value="10.9.9.9"),
    ]
    cfg.services = [
        Service(name="s1", protocol="tcp", dst_ports="80"),
        Service(name="s2", protocol="tcp", dst_ports="80"),   # dup of s1
        Service(name="unused", protocol="udp", dst_ports="9999"),
    ]
    cfg.policies = [
        Policy(name="p1", src_zones=["lan"], dst_zones=["wan"],
               src_addrs=["a1", "a2"], dst_addrs=["used"], services=["s1"]),
    ]
    return cfg


def test_merge_duplicates():
    cfg = _cfg()
    n = tuning.merge_duplicates(cfg, Report())
    assert n == 2  # a2->a1, s2->s1
    assert [a.name for a in cfg.addresses] == ["a1", "used", "orphan"]
    assert [s.name for s in cfg.services] == ["s1", "unused"]
    # references collapsed and de-duplicated
    assert cfg.policies[0].src_addrs == ["a1"]
    assert cfg.policies[0].services == ["s1"]


def test_prune_unreferenced():
    cfg = _cfg()
    n = tuning._prune(cfg, Report())
    names = {a.name for a in cfg.addresses} | {s.name for s in cfg.services}
    assert "orphan" not in names
    assert "unused" not in names
    assert "a1" in names and "used" in names
    # orphan addr + duplicate-but-unmerged s2 + unused svc = 3 removed
    assert n == 3


def test_prune_keeps_group_chain():
    cfg = FirewallConfig()
    cfg.addresses = [
        Address(name="m1", type="host", value="10.0.0.1"),
        Address(name="loose", type="host", value="10.0.0.2"),
    ]
    cfg.addr_groups = [AddressGroup(name="grp", members=["m1"])]
    cfg.policies = [Policy(name="p", src_addrs=["grp"], dst_addrs=["all"])]
    tuning._prune(cfg, Report())
    # m1 stays (referenced via grp), loose is dropped
    assert {a.name for a in cfg.addresses} == {"m1"}
    assert [g.name for g in cfg.addr_groups] == ["grp"]


def test_filter_exclude_and_only():
    cfg = FirewallConfig()
    cfg.policies = [Policy(name=f"r{i}") for i in range(4)]
    tuning.filter_policies(cfg, exclude=["r1", "r3"], only=[], report=Report())
    assert [p.name for p in cfg.policies] == ["r0", "r2"]

    cfg2 = FirewallConfig()
    cfg2.policies = [Policy(name=f"r{i}") for i in range(4)]
    rep = Report()
    tuning.filter_policies(cfg2, exclude=[], only=["r2", "nope"], report=rep)
    assert [p.name for p in cfg2.policies] == ["r2"]
    assert any("does not exist" in f.message for f in rep.findings)


def test_split_interface_pairs():
    cfg = FirewallConfig()
    cfg.policies = [
        Policy(name="multi", src_zones=["z1", "z2"], dst_zones=["w1", "w2"],
               src_addrs=["all"], dst_addrs=["all"], services=["ALL"]),
        Policy(name="single", src_zones=["a"], dst_zones=["b"]),
    ]
    n = tuning.split_interface_pairs(cfg, Report())
    assert n == 1
    names = [p.name for p in cfg.policies]
    assert names == ["multi-1", "multi-2", "multi-3", "multi-4", "single"]
    pairs = {(p.src_zones[0], p.dst_zones[0]) for p in cfg.policies
             if p.name.startswith("multi")}
    assert pairs == {("z1", "w1"), ("z1", "w2"), ("z2", "w1"), ("z2", "w2")}


def test_pipeline_prune_on_asa():
    text = (FIX / "asa_sample.cfg").read_text(encoding="utf-8")
    base = pipeline.run_cross(text, "cisco-asa", "asa", {})
    # every object in asa_sample is referenced -> prune alone is a no-op
    noop = pipeline.run_cross(text, "cisco-asa", "asa", {},
                              tuning=TuningOptions(prune=True))
    assert len(noop.cfg.addresses) == len(base.cfg.addresses)
    # dropping DMZ-IN-1 orphans DMZ-POOL, which prune then removes
    tuned = pipeline.run_cross(
        text, "cisco-asa", "asa", {},
        tuning=TuningOptions(prune=True, exclude=["DMZ-IN-1"]))
    assert len(tuned.cfg.addresses) < len(base.cfg.addresses)
    assert "tuning" in tuned.report.meta
    assert any(f.area == "tuning" and "pruned" in f.message
               for f in tuned.report.findings)


def test_palo_split_pairs_e2e(tmp_path):
    # PAN rules can carry multiple from/to zones -> split produces pairs
    rc = cli.main([
        "convert", str(FIX / "pa_sample.xml"), "-o", str(tmp_path),
        "--split-interface-pairs", "--prune", "--merge-dupes",
    ])
    assert rc == 0
    report = (tmp_path / "pa_sample.report.md").read_text(encoding="utf-8")
    assert "tuning" in report.lower()


def test_exclude_via_cli(tmp_path):
    rc = cli.main([
        "convert", str(FIX / "asa_sample.cfg"), "-o", str(tmp_path),
        "--exclude", "OUTSIDE-IN-3",
    ])
    assert rc in (0, 1)
    conf = (tmp_path / "asa_sample.fos.conf").read_text(encoding="utf-8")
    assert 'set name "OUTSIDE-IN-3"' not in conf
    assert 'set name "OUTSIDE-IN-1"' in conf
