from fwforge.model import Address, AddressGroup, FirewallConfig, Policy, Service
from fwforge.report import Report
from fwforge.transforms import names, optimize


def test_sanitize_renames_and_remaps_references():
    cfg = FirewallConfig()
    cfg.addresses = [
        Address(name="bad name!", type="host", value="10.0.0.1"),
        Address(name="x" * 90, type="host", value="10.0.0.2"),
        Address(name="all", type="host", value="10.0.0.3"),  # reserved
    ]
    cfg.addr_groups = [AddressGroup(name="grp", members=["bad name!", "all"])]
    cfg.policies = [
        Policy(name="p" * 50, src_addrs=["x" * 90], dst_addrs=["all"]),
    ]
    report = Report()
    renames = names.apply(cfg, report)

    assert cfg.addresses[0].name == "bad_name"
    assert len(cfg.addresses[1].name) <= 79
    assert cfg.addresses[2].name == "all_o"
    assert cfg.addr_groups[0].members == ["bad_name", "all_o"]
    assert len(cfg.policies[0].name) <= 35
    assert cfg.policies[0].src_addrs == [renames["x" * 90]]
    # plain 'all' in a policy refers to the FortiOS built-in any-address —
    # the rename map must have applied to the renamed *object* reference
    assert cfg.policies[0].dst_addrs == ["all_o"]


def test_hygiene_findings():
    cfg = FirewallConfig()
    cfg.addresses = [
        Address(name="a1", type="host", value="10.0.0.1"),
        Address(name="a2", type="host", value="10.0.0.1"),  # duplicate value
        Address(name="orphan", type="host", value="10.9.9.9"),
    ]
    cfg.services = [Service(name="s1", protocol="tcp", dst_ports="81")]
    cfg.policies = [
        Policy(name="p1", src_zones=["a"], dst_zones=["b"],
               src_addrs=["a1"], dst_addrs=["a2"], services=["s1"]),
        Policy(name="p2", src_zones=["a"], dst_zones=["b"],
               src_addrs=["a1"], dst_addrs=["a2"], services=["s1"]),  # dup
        Policy(name="wide", src_zones=["a"], dst_zones=["b"],
               src_addrs=["all"], dst_addrs=["all"], services=["ALL"]),
    ]
    report = Report()
    optimize.analyze(cfg, report)
    msgs = [f.message for f in report.findings]
    assert any("duplicate address definitions" in m for m in msgs)
    assert any("orphan" in m for m in msgs)
    assert any("duplicates 'p1'" in m for m in msgs)
    assert any("any/any/ALL" in m for m in msgs)
