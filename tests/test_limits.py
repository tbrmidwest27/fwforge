"""FortiOS name-length limits: the convert-time guardrail + the zone clamp."""
from fwforge.model import FirewallConfig, Policy, Zone
from fwforge.report import Report
from fwforge.transforms import names as names_tf
from fwforge.transforms.limits import validate_name_limits


def test_guardrail_flags_overlong_interface():
    out = ('config system interface\n'
           '    edit "this-interface-name-is-too-long"\n'   # 32 > 15
           '        set vdom "root"\n    next\nend\n')
    rep = Report()
    assert validate_name_limits(out, rep) == 1
    assert any(f.area == "limits" and "interface" in f.message
               for f in rep.findings)


def test_guardrail_flags_overlong_policy_name():
    out = ('config firewall policy\n    edit 1\n'
           '        set name "this-policy-name-is-definitely-over-the-35"\n'
           '    next\nend\n')
    assert validate_name_limits(out, Report()) == 1


def test_guardrail_clean_config_no_hits():
    out = ('config system interface\n    edit "port1"\n    next\nend\n'
           'config system zone\n    edit "trust"\n    next\nend\n')
    assert validate_name_limits(out, Report()) == 0


def test_zone_name_clamped_to_35():
    # FortiOS zone names cap at 35; names.apply must clamp + remap policy refs
    cfg = FirewallConfig(vendor="paloalto")
    long_zone = "zone-" + "x" * 40            # 45 chars
    cfg.zones.append(Zone(name=long_zone, members=["port1"]))
    cfg.policies.append(Policy(name="p", src_zones=[long_zone]))
    names_tf.apply(cfg, Report())
    assert len(cfg.zones[0].name) <= 35
    assert cfg.policies[0].src_zones == [cfg.zones[0].name]   # reference remapped
