from fwforge.emit import fortios as emit_fortios
from fwforge.model import (
    Address, AddressGroup, FirewallConfig, Service, ServiceGroup,
    VpnPhase1, VpnPhase2,
)
from fwforge.report import Report


def test_nested_groups_emitted_in_dependency_order():
    # A group that references another group as a member must be emitted AFTER
    # that member group, even when it appears first in the list -- otherwise
    # FortiOS sees 'set member <child>' before <child> exists and drops the
    # member on restore (silent member loss).
    cfg = FirewallConfig(vendor="test")
    cfg.addresses.append(Address(name="h1", type="host", value="10.0.0.1"))
    cfg.addr_groups.append(AddressGroup(name="parent", members=["child"]))
    cfg.addr_groups.append(AddressGroup(name="child", members=["h1"]))
    cfg.services.append(Service(name="s1", protocol="tcp", dst_ports="80"))
    cfg.svc_groups.append(
        ServiceGroup(name="sg-parent", members=["sg-child"]))
    cfg.svc_groups.append(ServiceGroup(name="sg-child", members=["s1"]))
    out = emit_fortios.emit(cfg, Report())
    assert out.index('edit "child"') < out.index('edit "parent"')
    assert out.index('edit "sg-child"') < out.index('edit "sg-parent"')


def test_group_membership_cycle_is_safe():
    # A membership cycle must not recurse forever; every group is still emitted
    # exactly once and an error is reported.
    cfg = FirewallConfig(vendor="test")
    cfg.addr_groups.append(AddressGroup(name="a", members=["b"]))
    cfg.addr_groups.append(AddressGroup(name="b", members=["a"]))
    report = Report()
    out = emit_fortios.emit(cfg, report)
    assert out.count('edit "a"') == 1
    assert out.count('edit "b"') == 1
    assert any(f.level == "error" and "cycle" in f.message
               for f in report.findings)


def test_empty_proposal_substitutes_default():
    # An empty IKE/IPsec proposal list must never emit a bare 'set proposal'
    # line (FortiOS rejects it and can abort the rest of the edit block) --
    # substitute a safe default and flag it.
    cfg = FirewallConfig(vendor="test")
    cfg.phase1s.append(VpnPhase1(name="t1", interface="wan1",
                                 remote_gw="203.0.113.1", psk="x"))
    cfg.phase2s.append(VpnPhase2(name="t1-p2", phase1="t1",
                                 src="10.0.0.0/24", dst="10.1.0.0/24"))
    report = Report()
    out = emit_fortios.emit(cfg, report)
    assert all(line.strip() != "set proposal" for line in out.splitlines())
    assert "set proposal aes256-sha256 aes128-sha256" in out
    assert any(f.level == "warn" and "no IKE proposal" in f.message
               for f in report.findings)
