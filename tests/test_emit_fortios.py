from fwforge.emit import fortios as emit_fortios
from fwforge.model import (
    Address, AddressGroup, BgpConfig, FirewallConfig, Interface, IpPool,
    IpsSensor, NatRule, OspfArea, OspfConfig, Policy, Service, ServiceGroup,
    Vip, VpnPhase1, VpnPhase2,
)
from fwforge.report import Report
from fwforge.transforms import names as names_tf


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


def test_service_group_drops_undefined_member():
    # A group member that is neither a defined custom service nor a real FortiOS
    # built-in (e.g. a bogus "IPMI" an App-ID mapping invented) would make the
    # whole `set member` line fail to load (-3). It must be dropped + flagged,
    # the real members kept.
    cfg = FirewallConfig(vendor="test")
    cfg.services.append(Service(name="appdef-tcp-623", protocol="tcp",
                                dst_ports="623"))
    cfg.svc_groups.append(ServiceGroup(
        name="appsvc-grp-1",
        members=["HTTPS", "IPMI", "appdef-tcp-623", "SMB"]))
    report = Report()
    out = emit_fortios.emit(cfg, report)
    member_line = next(l for l in out.splitlines()
                       if l.strip().startswith("set member"))
    assert '"IPMI"' not in member_line                 # bogus name dropped
    assert '"HTTPS"' in member_line and '"SMB"' in member_line   # built-ins kept
    assert '"appdef-tcp-623"' in member_line                     # custom kept
    assert any("IPMI" in f.message and "dropped member" in f.message
               for f in report.findings)


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


def test_redistribute_value_is_quoted_via_q():
    # the redistribute value must go through _q() (BGP and OSPF), not be
    # hand-interpolated into quotes -- a value with a quote/backslash would
    # otherwise corrupt the CLI line and break branch splitting.
    cfg = FirewallConfig(vendor="test")
    cfg.bgp = BgpConfig(asn="65001", router_id="1.1.1.1",
                        redistribute=['connected"x'])
    cfg.ospf = OspfConfig(router_id="2.2.2.2",
                          areas=[OspfArea(id="0.0.0.0")],
                          redistribute=["static"])
    out = emit_fortios.emit(cfg, Report())
    assert r'config redistribute "connected\"x"' in out
    assert 'config redistribute "static"' in out


def test_interface_invalid_prefix_reports_error_not_silent():
    # a non-integer prefix must not be silently dropped: emit no 'set ip'
    # line AND add an error finding (parity with addresses()/routes()).
    cfg = FirewallConfig(vendor="test")
    cfg.interfaces.append(Interface(name="lo0", kind="loopback",
                                    ip="10.0.0.1/xx"))
    report = Report()
    out = emit_fortios.emit(cfg, report)
    assert "set ip 10.0.0.1" not in out
    assert any(f.level == "error" and f.area == "interfaces"
               and "invalid ip" in f.message for f in report.findings)


def test_vip_extip_is_quoted():
    # extip must be quoted like mappedip -- close the inconsistent-quoting gap.
    cfg = FirewallConfig(vendor="test")
    cfg.vips.append(Vip(name="web", ext_ip="203.0.113.10",
                        mapped_ip="10.0.0.10", ext_intf="wan1"))
    out = emit_fortios.emit(cfg, Report())
    assert 'set extip "203.0.113.10"' in out
    assert 'set mappedip "10.0.0.10"' in out


def test_predefined_service_name_collisions_renamed():
    # services, groups, and FortiOS predefined services share one namespace,
    # so a converted service/group named like a predefined (e.g. a group
    # "VNC") fails to load with -162. They must be renamed + references remapped.
    cfg = FirewallConfig(vendor="test")
    cfg.services.append(Service(name="VNC", protocol="tcp", dst_ports="5900"))
    cfg.svc_groups.append(ServiceGroup(name="SMB", members=["VNC"]))   # collides
    cfg.svc_groups.append(ServiceGroup(name="MyGroup", members=["VNC"]))  # ok
    cfg.policies.append(Policy(name="p", services=["VNC", "SMB"]))
    emit_fortios.avoid_predefined_service_collisions(cfg, Report())

    assert {s.name for s in cfg.services} == {"VNC_svc"}        # service renamed
    grps = {g.name for g in cfg.svc_groups}
    assert "SMB" not in grps and "SMB_grp" in grps              # group renamed
    assert "MyGroup" in grps                                    # non-colliding kept
    # references follow the renames
    assert cfg.policies[0].services == ["VNC_svc", "SMB_grp"]
    mg = next(g for g in cfg.svc_groups if g.name == "MyGroup")
    assert mg.members == ["VNC_svc"]


def test_deny_policy_no_utm_output():
    """Deny-action policies must NOT emit utm-status or any UTM profile lines.
    FortiOS accepts the CLI but drops traffic before inspection — the UTM
    attributes are misleading dead config."""
    cfg = FirewallConfig(vendor="paloalto")
    cfg.ips_sensors.append(IpsSensor(name="strict-ips"))
    p = Policy(name="deny-block", action="deny",
               src_zones=["trust"], dst_zones=["untrust"],
               src_addrs=["any"], dst_addrs=["any"], services=["ALL"])
    p.ips_sensor = "strict-ips"
    p.app_list = "block-apps"
    cfg.policies.append(p)
    out = emit_fortios.emit(cfg, Report())
    assert "utm-status" not in out
    assert "ips-sensor" not in out
    assert "application-list" not in out


def test_accept_policy_emits_utm():
    """Accept-action policies with UTM profiles must emit utm-status."""
    cfg = FirewallConfig(vendor="paloalto")
    cfg.ips_sensors.append(IpsSensor(name="strict-ips"))
    p = Policy(name="allow-web", action="accept",
               src_zones=["trust"], dst_zones=["untrust"],
               src_addrs=["any"], dst_addrs=["any"], services=["ALL"])
    p.ips_sensor = "strict-ips"
    cfg.policies.append(p)
    out = emit_fortios.emit(cfg, Report())
    assert "set utm-status enable" in out
    assert "set ips-sensor" in out


def test_utm_profile_names_clamped_to_35():
    # FortiOS IPS-sensor / UTM profile names cap at 35 chars (< 8.0);
    # a longer `edit` is rejected (-1). Clamp + remap the policy reference.
    cfg = FirewallConfig(vendor="paloalto")
    long_name = "ips-Jabil-VP-Global-Jabil-Spy-Global"   # 36 chars
    assert len(long_name) == 36
    cfg.ips_sensors.append(IpsSensor(name=long_name))
    cfg.policies.append(Policy(name="p", ips_sensor=long_name))
    names_tf.sanitize_profiles(cfg, Report())   # default max_len=35
    nm = cfg.ips_sensors[0].name
    assert len(nm) <= 35 and nm != long_name
    assert cfg.policies[0].ips_sensor == nm        # reference remapped


def test_utm_profile_names_47_on_forti8():
    # FortiOS 8.0+ allows 47-char profile names; a 40-char name must survive.
    cfg = FirewallConfig(vendor="paloalto")
    name_40 = "ips-Jabil-VP-Global-Jabil-Spy-Global-All"   # 40 chars
    assert len(name_40) == 40
    cfg.ips_sensors.append(IpsSensor(name=name_40))
    cfg.policies.append(Policy(name="p", ips_sensor=name_40))
    names_tf.sanitize_profiles(cfg, Report(),
                               max_len=names_tf.profile_name_max("8.0"))
    assert cfg.ips_sensors[0].name == name_40   # unchanged — fits in 47
    assert cfg.policies[0].ips_sensor == name_40


def test_utm_profile_name_max():
    assert names_tf.profile_name_max("7.4") == 35
    assert names_tf.profile_name_max("7.99") == 35
    assert names_tf.profile_name_max("8.0") == 47
    assert names_tf.profile_name_max("8.2") == 47
    assert names_tf.profile_name_max("bad") == 35  # fallback


def test_central_nat_ippool_in_snat_map_not_policy():
    """In central NAT mode, ip-pool SNAT goes to central-snat-map, not policy."""
    cfg = FirewallConfig(vendor="paloalto")
    cfg.interfaces.append(Interface(name="wan1", ip="203.0.113.2/29"))
    cfg.interfaces.append(Interface(name="lan1", ip="10.0.0.1/24"))
    cfg.ippools.append(IpPool(name="pub-pool", start="203.0.113.10",
                              end="203.0.113.20"))
    cfg.nats.append(NatRule(kind="ip-pool", pool_name="pub-pool",
                            real_ifc="trust", mapped_ifc="untrust"))
    cfg.policies.append(Policy(name="allow-out",
                                src_zones=["trust"], dst_zones=["untrust"],
                                src_addrs=["all"], dst_addrs=["all"],
                                services=["ALL"], action="accept"))
    report = Report()
    out = emit_fortios.emit(cfg, report, nat_mode="central")

    # ip-pool rule must appear in central-snat-map
    assert "config firewall central-snat-map" in out
    assert "set nat-ippool" in out
    assert '"pub-pool"' in out

    # policy must NOT have set ippool enable
    pol_block = out[out.index("config firewall policy"):]
    assert "set ippool enable" not in pol_block
    assert "set poolname" not in pol_block


def test_policy_nat_mode_ippool_in_policy():
    """In policy NAT mode, ip-pool SNAT is wired into matching policies."""
    cfg = FirewallConfig(vendor="paloalto")
    cfg.interfaces.append(Interface(name="wan1", ip="203.0.113.2/29"))
    cfg.interfaces.append(Interface(name="lan1", ip="10.0.0.1/24"))
    cfg.ippools.append(IpPool(name="pub-pool", start="203.0.113.10",
                              end="203.0.113.20"))
    cfg.nats.append(NatRule(kind="ip-pool", pool_name="pub-pool",
                            real_ifc="trust", mapped_ifc="untrust"))
    cfg.policies.append(Policy(name="allow-out",
                                src_zones=["trust"], dst_zones=["untrust"],
                                src_addrs=["all"], dst_addrs=["all"],
                                services=["ALL"], action="accept"))
    report = Report()
    out = emit_fortios.emit(cfg, report, nat_mode="policy")

    # policy block should have set ippool enable + set poolname
    pol_block = out[out.index("config firewall policy"):]
    assert "set ippool enable" in pol_block
    assert '"pub-pool"' in pol_block

    # no central-snat-map (only for dynamic-interface nats in policy mode)
    assert "config firewall central-snat-map" not in out
