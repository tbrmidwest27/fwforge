from fwforge.model import (
    Address, AddressGroup, FirewallConfig, Policy, Service, ServiceGroup,
)
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


def test_sanitize_separates_object_namespaces():
    # FortiOS object namespaces are independent: an address and a service may
    # both be named 'web'. Sanitization must NOT rename one because the other
    # already took the name, and must NOT cross-wire references. Regression: a
    # single shared rename map renamed the service to 'web~2' and then rewrote
    # the policy's *address* reference 'web' onto the renamed service.
    cfg = FirewallConfig()
    cfg.addresses = [Address(name="web", type="host", value="10.0.0.1")]
    cfg.services = [Service(name="web", protocol="tcp", dst_ports="80")]
    cfg.addr_groups = [AddressGroup(name="ag", members=["web"])]  # the address
    cfg.svc_groups = [ServiceGroup(name="sg", members=["web"])]   # the service
    cfg.policies = [
        Policy(name="p1", src_addrs=["web"], dst_addrs=["web"], services=["web"]),
    ]
    report = Report()
    names.apply(cfg, report)

    # neither object is renamed — they live in different namespaces
    assert cfg.addresses[0].name == "web"
    assert cfg.services[0].name == "web"
    # references stay pointed at the right namespace, never cross-wired
    assert cfg.addr_groups[0].members == ["web"]   # -> the address
    assert cfg.svc_groups[0].members == ["web"]    # -> the service
    assert cfg.policies[0].src_addrs == ["web"]
    assert cfg.policies[0].dst_addrs == ["web"]
    assert cfg.policies[0].services == ["web"]


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
