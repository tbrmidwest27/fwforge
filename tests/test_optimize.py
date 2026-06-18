"""Tests for transforms/optimize.py — policy shadow detection, collapse
candidates, and existing hygiene checks."""
from __future__ import annotations

import pytest

from fwforge.model import (
    Address, AddressGroup, FirewallConfig, Policy, Service, ServiceGroup,
)
from fwforge.report import Report
from fwforge.transforms.optimize import (
    _AddrResolver, _AddrSet, _SvcResolver, _SvcSet, _PRange,
    _zones_cover, _shadow_check, _collapse_check, analyze,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _cfg(*policies, addresses=(), addr_groups=(),
         services=(), svc_groups=()) -> FirewallConfig:
    cfg = FirewallConfig()
    cfg.policies = list(policies)
    cfg.addresses = list(addresses)
    cfg.addr_groups = list(addr_groups)
    cfg.services = list(services)
    cfg.svc_groups = list(svc_groups)
    return cfg


def _pol(name="p", src_zones=("trust",), dst_zones=("untrust",),
         src_addrs=("all",), dst_addrs=("all",),
         services=("ALL",), action="accept", disabled=False,
         src_negate=False, dst_negate=False) -> Policy:
    return Policy(
        name=name,
        src_zones=list(src_zones),
        dst_zones=list(dst_zones),
        src_addrs=list(src_addrs),
        dst_addrs=list(dst_addrs),
        services=list(services),
        action=action,
        disabled=disabled,
        src_negate=src_negate,
        dst_negate=dst_negate,
    )


def _findings(cfg, level=None):
    r = Report()
    analyze(cfg, r)
    return [f for f in r.findings if (level is None or f.level == level)]


def _msgs(cfg, level=None):
    return [f.message for f in _findings(cfg, level)]


# ── CIDR / _AddrSet tests ─────────────────────────────────────────────────────

class TestAddrSet:
    def test_any_contains_everything(self):
        any_ = _AddrSet(is_any=True)
        host = _AddrSet(nets=(None,))  # arbitrary non-empty
        specific = _AddrSet(nets=())
        assert any_.contains(_AddrSet(is_any=True))
        assert any_.contains(specific)

    def test_supernet_contains_subnet(self):
        import ipaddress
        net10 = (ipaddress.ip_network("10.0.0.0/8"),)
        net10_1 = (ipaddress.ip_network("10.1.0.0/16"),)
        assert _AddrSet(nets=net10).contains(_AddrSet(nets=net10_1))
        assert not _AddrSet(nets=net10_1).contains(_AddrSet(nets=net10))

    def test_fqdn_blocks_comparison(self):
        fqdn = _AddrSet(has_fqdn=True)
        any_ = _AddrSet(is_any=True)
        import ipaddress
        specific = _AddrSet(nets=(ipaddress.ip_network("10.0.0.1"),))
        # fqdn as self: never claims to contain anything
        assert not fqdn.contains(specific)
        # any contains fqdn? no — other.is_any=False but other.has_fqdn=True
        assert not specific.contains(fqdn)
        assert any_.contains(fqdn)  # any_ always contains

    def test_host_contained_by_supernet(self):
        import ipaddress
        supernet = (ipaddress.ip_network("192.168.0.0/24"),)
        host = (ipaddress.ip_network("192.168.0.5"),)
        assert _AddrSet(nets=supernet).contains(_AddrSet(nets=host))
        assert not _AddrSet(nets=host).contains(_AddrSet(nets=supernet))

    def test_different_family_not_contained(self):
        import ipaddress
        v4 = (ipaddress.ip_network("10.0.0.0/8"),)
        v6 = (ipaddress.ip_network("::1"),)
        assert not _AddrSet(nets=v4).contains(_AddrSet(nets=v6))


class TestAddrResolver:
    def _r(self, addrs=(), groups=()):
        cfg = FirewallConfig()
        cfg.addresses = list(addrs)
        cfg.addr_groups = list(groups)
        return _AddrResolver(cfg)

    def test_resolves_all(self):
        r = self._r()
        s = r.resolve_list(["all"])
        assert s.is_any

    def test_resolves_host(self):
        r = self._r(addrs=[Address(name="h", type="host", value="10.0.0.1")])
        s = r.resolve_list(["h"])
        assert not s.is_any and not s.has_fqdn
        assert len(s.nets) == 1

    def test_resolves_fqdn(self):
        r = self._r(addrs=[Address(name="f", type="fqdn", value="example.com")])
        s = r.resolve_list(["f"])
        assert s.has_fqdn

    def test_group_expands_recursively(self):
        import ipaddress
        r = self._r(
            addrs=[
                Address(name="h1", type="host", value="10.0.0.1"),
                Address(name="h2", type="host", value="10.0.0.2"),
            ],
            groups=[
                AddressGroup(name="g", members=["h1", "h2"]),
            ],
        )
        s = r.resolve_list(["g"])
        assert len(s.nets) == 2

    def test_group_with_all_member_propagates_any(self):
        r = self._r(
            addrs=[Address(name="any_addr", type="host", value="0.0.0.0/0")],
            groups=[
                AddressGroup(name="g", members=["any_addr"]),
            ],
        )
        # 0.0.0.0/0 is a subnet, not "all" — should resolve to a single network
        s = r.resolve_list(["g"])
        assert not s.is_any  # subnet, not the "all" sentinel

    def test_negate_returns_opaque(self):
        r = self._r(addrs=[Address(name="h", type="host", value="10.0.0.1")])
        s = r.resolve_list(["h"], negate=True)
        assert s.has_fqdn  # can't compare negated sets

    def test_cycle_guard(self):
        cfg = FirewallConfig()
        cfg.addresses = []
        cfg.addr_groups = [
            AddressGroup(name="g1", members=["g2"]),
            AddressGroup(name="g2", members=["g1"]),
        ]
        r = _AddrResolver(cfg)
        s = r.resolve_list(["g1"])  # must not infinite-loop
        assert not s.is_any


# ── Port-range tests ───────────────────────────────────────────────────────────

class TestPRange:
    def test_exact_match(self):
        assert _PRange("tcp", 80, 80).contains(_PRange("tcp", 80, 80))

    def test_wide_contains_narrow(self):
        assert _PRange("tcp", 0, 65535).contains(_PRange("tcp", 443, 443))
        assert not _PRange("tcp", 443, 443).contains(_PRange("tcp", 0, 65535))

    def test_proto_mismatch(self):
        assert not _PRange("tcp", 80, 80).contains(_PRange("udp", 80, 80))

    def test_ip_contains_any_proto(self):
        assert _PRange("ip", 0, 0).contains(_PRange("tcp", 443, 443))
        assert _PRange("ip", 0, 0).contains(_PRange("udp", 53, 53))

    def test_range_superset(self):
        assert _PRange("tcp", 1000, 2000).contains(_PRange("tcp", 1100, 1900))
        assert not _PRange("tcp", 1100, 1900).contains(_PRange("tcp", 1000, 2000))


class TestSvcSet:
    def test_all_contains_specific(self):
        all_ = _SvcSet(is_all=True)
        tcp80 = _SvcSet(ranges=(_PRange("tcp", 80, 80),))
        assert all_.contains(tcp80)
        assert not tcp80.contains(all_)

    def test_specific_contains_narrower(self):
        wide = _SvcSet(ranges=(_PRange("tcp", 0, 65535),))
        narrow = _SvcSet(ranges=(_PRange("tcp", 443, 443),))
        assert wide.contains(narrow)
        assert not narrow.contains(wide)


class TestSvcResolver:
    def _r(self, services=(), groups=()):
        cfg = FirewallConfig()
        cfg.services = list(services)
        cfg.svc_groups = list(groups)
        return _SvcResolver(cfg)

    def test_ALL_resolves_to_all(self):
        r = self._r()
        assert r.resolve_list(["ALL"]).is_all

    def test_builtin_http(self):
        r = self._r()
        s = r.resolve_list(["HTTP"])
        assert not s.is_all
        assert any(pr.proto == "tcp" and pr.lo == 80 for pr in s.ranges)

    def test_custom_service_tcp(self):
        r = self._r(services=[Service(name="web", protocol="tcp", dst_ports="80 8080")])
        s = r.resolve_list(["web"])
        assert not s.is_all
        ports = {pr.lo for pr in s.ranges}
        assert {80, 8080} <= ports

    def test_tcp_udp_expands(self):
        r = self._r(services=[Service(name="dns", protocol="tcp/udp", dst_ports="53")])
        s = r.resolve_list(["dns"])
        protos = {pr.proto for pr in s.ranges}
        assert "tcp" in protos and "udp" in protos

    def test_service_group(self):
        r = self._r(
            services=[
                Service(name="HTTP", protocol="tcp", dst_ports="80"),
                Service(name="HTTPS", protocol="tcp", dst_ports="443"),
            ],
            groups=[ServiceGroup(name="web", members=["HTTP", "HTTPS"])],
        )
        s = r.resolve_list(["web"])
        ports = {pr.lo for pr in s.ranges}
        assert {80, 443} <= ports


# ── Zone coverage helper ───────────────────────────────────────────────────────

class TestZonesCover:
    def test_any_covers_all(self):
        assert _zones_cover([], ["trust"])
        assert _zones_cover([], [])
        assert _zones_cover([], ["a", "b", "c"])

    def test_superset_covers_subset(self):
        assert _zones_cover(["trust", "dmz"], ["trust"])
        assert _zones_cover(["trust", "dmz"], ["dmz"])
        assert _zones_cover(["trust", "dmz"], ["trust", "dmz"])

    def test_subset_does_not_cover_superset(self):
        assert not _zones_cover(["trust"], ["trust", "dmz"])

    def test_specific_does_not_cover_any(self):
        assert not _zones_cover(["trust"], [])

    def test_disjoint_zones_not_covered(self):
        assert not _zones_cover(["trust"], ["untrust"])


# ── Shadow detection integration tests ────────────────────────────────────────

class TestShadowDetection:
    def _shadow_msgs(self, cfg):
        r = Report()
        addr_r = _AddrResolver(cfg)
        svc_r = _SvcResolver(cfg)
        _shadow_check(cfg.policies, addr_r, svc_r, r)
        return [f.message for f in r.findings]

    def test_any_any_ALL_shadows_specific(self):
        """A permit-all rule before a specific rule shadows the specific."""
        cfg = _cfg(
            _pol("allow-all", src_addrs=["all"], dst_addrs=["all"], services=["ALL"]),
            _pol("specific", src_addrs=["all"], dst_addrs=["all"], services=["HTTP"]),
            services=[Service(name="HTTP", protocol="tcp", dst_ports="80")],
        )
        msgs = self._shadow_msgs(cfg)
        assert any("'specific'" in m and "shadowed" in m for m in msgs)

    def test_supernet_shadows_host(self):
        """A broader subnet rule before a host rule shadows the host."""
        cfg = _cfg(
            _pol("broad", src_addrs=["net10"], dst_addrs=["all"], services=["ALL"]),
            _pol("host", src_addrs=["h10"], dst_addrs=["all"], services=["ALL"]),
            addresses=[
                Address(name="net10", type="subnet", value="10.0.0.0/8"),
                Address(name="h10", type="host", value="10.1.2.3"),
            ],
        )
        msgs = self._shadow_msgs(cfg)
        assert any("'host'" in m and "shadowed" in m for m in msgs)

    def test_host_does_not_shadow_net(self):
        """A more-specific rule before a broader rule is NOT a shadow."""
        cfg = _cfg(
            _pol("host", src_addrs=["h10"], dst_addrs=["all"], services=["ALL"]),
            _pol("broad", src_addrs=["net10"], dst_addrs=["all"], services=["ALL"]),
            addresses=[
                Address(name="net10", type="subnet", value="10.0.0.0/8"),
                Address(name="h10", type="host", value="10.1.2.3"),
            ],
        )
        msgs = self._shadow_msgs(cfg)
        assert not any("shadowed" in m for m in msgs)

    def test_accept_shadows_deny(self):
        """Accept-all before a deny rule: deny is bypassed — security concern."""
        cfg = _cfg(
            _pol("allow-all", action="accept",
                 src_addrs=["all"], dst_addrs=["all"], services=["ALL"]),
            _pol("deny-specific", action="deny",
                 src_addrs=["all"], dst_addrs=["all"], services=["HTTP"]),
            services=[Service(name="HTTP", protocol="tcp", dst_ports="80")],
        )
        msgs = self._shadow_msgs(cfg)
        assert any("DENY is bypassed" in m for m in msgs)

    def test_deny_shadows_accept(self):
        """Deny before accept in same scope → accept is unreachable."""
        cfg = _cfg(
            _pol("deny-all", action="deny",
                 src_addrs=["all"], dst_addrs=["all"], services=["ALL"]),
            _pol("allow", action="accept",
                 src_addrs=["all"], dst_addrs=["all"], services=["HTTP"]),
            services=[Service(name="HTTP", protocol="tcp", dst_ports="80")],
        )
        msgs = self._shadow_msgs(cfg)
        assert any("ACCEPT is unreachable" in m for m in msgs)

    def test_disabled_rule_not_shadowed(self):
        """Disabled rules don't participate in shadow analysis (they never fire)."""
        cfg = _cfg(
            _pol("allow-all", src_addrs=["all"], dst_addrs=["all"], services=["ALL"]),
            _pol("disabled", src_addrs=["all"], dst_addrs=["all"],
                 services=["HTTP"], disabled=True),
            services=[Service(name="HTTP", protocol="tcp", dst_ports="80")],
        )
        msgs = self._shadow_msgs(cfg)
        assert not any("shadowed" in m for m in msgs)

    def test_different_zones_not_shadow(self):
        """Rules in different zone pairs never shadow each other."""
        cfg = _cfg(
            _pol("trust-untrust", src_zones=["trust"], dst_zones=["untrust"],
                 src_addrs=["all"], dst_addrs=["all"], services=["ALL"]),
            _pol("dmz-untrust", src_zones=["dmz"], dst_zones=["untrust"],
                 src_addrs=["all"], dst_addrs=["all"], services=["ALL"]),
        )
        msgs = self._shadow_msgs(cfg)
        assert not any("shadowed" in m for m in msgs)

    def test_any_zone_shadows_specific_zone(self):
        """A rule with empty (any) src zone shadows a rule with a specific zone."""
        cfg = _cfg(
            _pol("allow-any-zone", src_zones=[], dst_zones=[],
                 src_addrs=["all"], dst_addrs=["all"], services=["ALL"]),
            _pol("specific-zone", src_zones=["trust"], dst_zones=["untrust"],
                 src_addrs=["all"], dst_addrs=["all"], services=["ALL"]),
        )
        msgs = self._shadow_msgs(cfg)
        assert any("'specific-zone'" in m and "shadowed" in m for m in msgs)

    def test_service_scope_prevents_shadow(self):
        """Broad address + narrow service does NOT shadow narrow address + broad service."""
        cfg = _cfg(
            _pol("p1", src_addrs=["all"], dst_addrs=["all"], services=["HTTP"]),
            _pol("p2", src_addrs=["h1"], dst_addrs=["all"], services=["ALL"]),
            addresses=[Address(name="h1", type="host", value="10.0.0.1")],
            services=[Service(name="HTTP", protocol="tcp", dst_ports="80")],
        )
        msgs = self._shadow_msgs(cfg)
        assert not any("'p2'" in m and "shadowed" in m for m in msgs)

    def test_supernet_with_specific_service_shadows(self):
        """Supernet + wider service both satisfied → shadow."""
        cfg = _cfg(
            _pol("broad", src_addrs=["net10"], dst_addrs=["all"], services=["ALL"]),
            _pol("narrow", src_addrs=["h10"], dst_addrs=["all"], services=["HTTPS"]),
            addresses=[
                Address(name="net10", type="subnet", value="10.0.0.0/8"),
                Address(name="h10", type="host", value="10.5.5.5"),
            ],
        )
        msgs = self._shadow_msgs(cfg)
        assert any("'narrow'" in m and "shadowed" in m for m in msgs)

    def test_fqdn_skipped(self):
        """FQDN addresses block shadow comparison (can't do IP math)."""
        cfg = _cfg(
            _pol("p1", src_addrs=["all"], dst_addrs=["domain1"], services=["ALL"]),
            _pol("p2", src_addrs=["all"], dst_addrs=["domain2"], services=["HTTPS"]),
            addresses=[
                Address(name="domain1", type="fqdn", value="example.com"),
                Address(name="domain2", type="fqdn", value="example.com"),
            ],
        )
        msgs = self._shadow_msgs(cfg)
        assert not any("shadowed" in m for m in msgs)

    def test_negated_src_skipped(self):
        """Negated src address skips shadow check (inversion breaks containment)."""
        cfg = _cfg(
            _pol("p1", src_addrs=["all"], dst_addrs=["all"], services=["ALL"]),
            _pol("p2", src_addrs=["h1"], dst_addrs=["all"],
                 services=["ALL"], src_negate=True),
            addresses=[Address(name="h1", type="host", value="10.0.0.1")],
        )
        msgs = self._shadow_msgs(cfg)
        # p2 has negated src — should be skipped, not reported as shadowed
        assert not any("'p2'" in m and "shadowed" in m for m in msgs)

    def test_single_rule_no_shadow(self):
        cfg = _cfg(_pol("only", src_addrs=["all"], dst_addrs=["all"], services=["ALL"]))
        assert self._shadow_msgs(cfg) == []

    def test_empty_policies_no_crash(self):
        cfg = _cfg()
        assert self._shadow_msgs(cfg) == []

    def test_reports_first_shadower_only(self):
        """If p1 and p2 both shadow p3, only the first (p1) is reported."""
        cfg = _cfg(
            _pol("p1", src_addrs=["all"], dst_addrs=["all"], services=["ALL"]),
            _pol("p2", src_addrs=["all"], dst_addrs=["all"], services=["ALL"],
                 action="deny"),
            _pol("p3", src_addrs=["all"], dst_addrs=["all"], services=["HTTP"]),
            services=[Service(name="HTTP", protocol="tcp", dst_ports="80")],
        )
        msgs = self._shadow_msgs(cfg)
        p3_reports = [m for m in msgs if "'p3'" in m]
        assert len(p3_reports) == 1


# ── Collapse candidate tests ───────────────────────────────────────────────────

class TestCollapseCheck:
    def _collapse_msgs(self, cfg):
        r = Report()
        _collapse_check(cfg.policies, r)
        return [f.message for f in r.findings]

    def test_same_zones_addrs_different_services(self):
        cfg = _cfg(
            _pol("p1", services=["HTTP"]),
            _pol("p2", services=["HTTPS"]),
        )
        msgs = self._collapse_msgs(cfg)
        assert any("collapse" in m.lower() for m in msgs)
        assert any("p1" in m and "p2" in m for m in msgs)

    def test_different_actions_not_collapsed(self):
        cfg = _cfg(
            _pol("p1", services=["HTTP"], action="accept"),
            _pol("p2", services=["HTTPS"], action="deny"),
        )
        msgs = self._collapse_msgs(cfg)
        assert not msgs

    def test_different_src_addrs_not_collapsed(self):
        cfg = _cfg(
            _pol("p1", src_addrs=["h1"], services=["HTTP"]),
            _pol("p2", src_addrs=["h2"], services=["HTTPS"]),
            addresses=[
                Address(name="h1", type="host", value="10.0.0.1"),
                Address(name="h2", type="host", value="10.0.0.2"),
            ],
        )
        msgs = self._collapse_msgs(cfg)
        assert not msgs

    def test_identical_services_is_duplicate_not_collapse(self):
        """Exact same services → already caught by dup-check, not collapse."""
        cfg = _cfg(
            _pol("p1", services=["HTTP"]),
            _pol("p2", services=["HTTP"]),
        )
        msgs = self._collapse_msgs(cfg)
        assert not msgs  # same svc key → excluded from collapse candidates

    def test_three_collapsible(self):
        cfg = _cfg(
            _pol("p1", services=["HTTP"]),
            _pol("p2", services=["HTTPS"]),
            _pol("p3", services=["DNS"]),
        )
        msgs = self._collapse_msgs(cfg)
        assert any("3 policies" in m for m in msgs)

    def test_disabled_excluded(self):
        cfg = _cfg(
            _pol("p1", services=["HTTP"]),
            _pol("p2", services=["HTTPS"]),
            _pol("p3", services=["DNS"], disabled=True),
        )
        msgs = self._collapse_msgs(cfg)
        assert any("2 policies" in m for m in msgs)
        assert not any("p3" in m for m in msgs)

    def test_different_utm_profiles_not_collapsed(self):
        """Rules with different UTM profiles must not be collapsed."""
        p1 = _pol("p1", services=["HTTP"])
        p1.webfilter = "profile-A"
        p2 = _pol("p2", services=["HTTPS"])
        p2.webfilter = "profile-B"
        cfg = _cfg(p1, p2)
        msgs = self._collapse_msgs(cfg)
        assert not msgs


# ── Full analyze() integration ─────────────────────────────────────────────────

class TestAnalyze:
    def test_existing_hygiene_still_works(self):
        """Existing duplicate-object, orphan, and any/any/ALL checks survive."""
        cfg = _cfg(
            _pol("p1", src_addrs=["a1"], dst_addrs=["a2"], services=["s1"]),
            _pol("p2", src_addrs=["a1"], dst_addrs=["a2"], services=["s1"]),  # dup
            _pol("wide", src_addrs=["all"], dst_addrs=["all"], services=["ALL"]),
            addresses=[
                Address(name="a1", type="host", value="10.0.0.1"),
                Address(name="a2", type="host", value="10.0.0.1"),  # dup value
                Address(name="orphan", type="host", value="10.9.9.9"),
            ],
            services=[Service(name="s1", protocol="tcp", dst_ports="81")],
        )
        msgs = _msgs(cfg)
        assert any("duplicate address" in m for m in msgs)
        assert any("orphan" in m for m in msgs)
        assert any("duplicates 'p1'" in m for m in msgs)
        assert any("any/any/ALL" in m for m in msgs)

    def test_shadow_findings_appear_in_full_analyze(self):
        cfg = _cfg(
            _pol("allow-all", src_addrs=["all"], dst_addrs=["all"],
                 services=["ALL"]),
            _pol("specific", src_addrs=["all"], dst_addrs=["all"],
                 services=["HTTP"]),
            services=[Service(name="HTTP", protocol="tcp", dst_ports="80")],
        )
        msgs = _msgs(cfg, level="warn")
        assert any("policy-opt" in f.area and "shadowed" in f.message
                   for f in _findings(cfg, "warn"))

    def test_collapse_findings_appear_in_full_analyze(self):
        cfg = _cfg(
            _pol("p1", services=["HTTP"]),
            _pol("p2", services=["HTTPS"]),
        )
        info = _findings(cfg, "info")
        assert any("collapse" in f.message.lower() and "policy-opt" in f.area
                   for f in info)

    def test_no_false_positives_on_clean_config(self):
        """A tight, well-ordered config should produce no policy-opt warnings."""
        cfg = _cfg(
            _pol("deny-bad", src_addrs=["bad"], dst_addrs=["all"],
                 services=["ALL"], action="deny"),
            _pol("allow-web", src_addrs=["trusted"], dst_addrs=["servers"],
                 services=["HTTP"]),
            _pol("allow-ssh", src_addrs=["admin"], dst_addrs=["servers"],
                 services=["SSH"]),
            addresses=[
                Address(name="bad", type="subnet", value="172.16.0.0/12"),
                Address(name="trusted", type="subnet", value="10.0.0.0/24"),
                Address(name="servers", type="subnet", value="10.0.1.0/24"),
                Address(name="admin", type="host", value="10.0.0.5"),
            ],
        )
        # No policy-opt warnings expected for this well-ordered config
        warn_opt = [f for f in _findings(cfg, "warn")
                    if f.area == "policy-opt"]
        assert not warn_opt
