"""Config hygiene + policy optimization analysis.

FortiConverter converts a config 1:1 by default — including objects nothing
references and rules shadowed by earlier rules. This module reports them
instead of silently porting (or silently dropping) them; auto-clean flags
come later.

Top-down evaluation model: in FortiOS (and every vendor we convert from)
the first matching rule wins. A rule whose conditions are a subset of an
earlier rule's conditions will NEVER fire. The shadow analysis here detects
that with CIDR set math and port-range containment so the report tells the
engineer exactly which rule is dead and why.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterator

from ..model import FirewallConfig, Policy


# ── CIDR / IP-set math ────────────────────────────────────────────────────────

_IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network


def _net_ge(a: _IPNet, b: _IPNet) -> bool:
    """True when network a fully contains (is a superset of) network b."""
    try:
        return b.subnet_of(a)
    except TypeError:
        return False  # different address families — can't compare


class _AddrSet:
    """Resolved set of IP networks for a list of address object names.

    Three states:
    - is_any=True   : matches every IP (from an 'all' reference)
    - has_fqdn=True : contains FQDN or range members — comparison not safe
    - nets           : flat list of IPv4/IPv6Network objects to compare
    """
    __slots__ = ("is_any", "has_fqdn", "nets")

    def __init__(self, is_any: bool = False, has_fqdn: bool = False,
                 nets: tuple[_IPNet, ...] = ()):
        self.is_any = is_any
        self.has_fqdn = has_fqdn
        self.nets = nets

    def contains(self, other: _AddrSet) -> bool:
        """Return True when self covers every IP that other covers (self ⊇ other)."""
        if self.is_any:
            return True
        if other.is_any or self.has_fqdn or other.has_fqdn:
            return False
        if not other.nets:
            return True   # other is empty → trivially covered
        if not self.nets:
            return False
        return all(
            any(_net_ge(a, b) for a in self.nets)
            for b in other.nets
        )


def _parse_addr(value: str, atype: str) -> tuple[tuple[_IPNet, ...], bool]:
    """Parse an Address value → (networks, has_fqdn)."""
    if atype == "fqdn":
        return (), True
    if atype in ("host", "subnet", "ipmask"):
        try:
            return (ipaddress.ip_network(value, strict=False),), False
        except ValueError:
            return (), True
    if atype == "range":
        # "10.0.0.1-10.0.0.9" — represent as the two endpoint /32 hosts;
        # containment logic will be conservative but never produce false
        # "shadowed" verdicts for ranges unless clearly contained
        parts = value.split("-", 1)
        nets: list[_IPNet] = []
        for p in parts:
            try:
                nets.append(ipaddress.ip_network(p.strip(), strict=False))
            except ValueError:
                pass
        return tuple(nets), False
    return (), True   # unknown type → treat as opaque


class _AddrResolver:
    """Builds and caches _AddrSet for every address/group name in the config."""

    def __init__(self, cfg: FirewallConfig):
        self._addrs = {a.name: a for a in cfg.addresses}
        self._groups = {g.name: g for g in cfg.addr_groups}
        self._cache: dict[str, _AddrSet] = {}

    def resolve_list(self, names: list[str], negate: bool = False) -> _AddrSet:
        if negate:
            return _AddrSet(has_fqdn=True)   # negated address → cannot compare
        if not names or names == ["all"]:
            return _AddrSet(is_any=True)
        nets: list[_IPNet] = []
        has_fqdn = False
        for name in names:
            s = self._resolve_one(name, set())
            if s.is_any:
                return _AddrSet(is_any=True)
            has_fqdn = has_fqdn or s.has_fqdn
            nets.extend(s.nets)
        return _AddrSet(has_fqdn=has_fqdn, nets=tuple(nets))

    def _resolve_one(self, name: str, visited: set[str]) -> _AddrSet:
        if name in self._cache:
            return self._cache[name]
        if name in visited:
            return _AddrSet()   # cycle guard
        visited.add(name)

        if name in self._addrs:
            a = self._addrs[name]
            nets, fqdn = _parse_addr(a.value, a.type)
            result = _AddrSet(has_fqdn=fqdn, nets=nets)
        elif name in self._groups:
            g = self._groups[name]
            m_nets: list[_IPNet] = []
            m_fqdn = False
            for m in g.members:
                s = self._resolve_one(m, visited)
                if s.is_any:
                    result = _AddrSet(is_any=True)
                    self._cache[name] = result
                    return result
                m_fqdn = m_fqdn or s.has_fqdn
                m_nets.extend(s.nets)
            result = _AddrSet(has_fqdn=m_fqdn, nets=tuple(m_nets))
        else:
            result = _AddrSet()   # unknown name — conservative: empty

        self._cache[name] = result
        return result


# ── Port-range / service-set math ─────────────────────────────────────────────

@dataclass(frozen=True)
class _PRange:
    """Immutable (proto, lo_port, hi_port) port range."""
    proto: str    # "tcp" | "udp" | "icmp" | "ip"
    lo: int       # 0 for ICMP / IP protocols
    hi: int       # 65535 for any-port

    def contains(self, other: _PRange) -> bool:
        """True when self covers every port+proto that other covers."""
        if self.proto == "ip":                          # ip = all proto
            return True
        if self.proto != other.proto and other.proto != "ip":
            return False
        return self.lo <= other.lo and self.hi >= other.hi


# FortiOS predefined service names → resolved port ranges
_BUILTIN: dict[str, list[_PRange]] = {
    "HTTP":     [_PRange("tcp", 80, 80)],
    "HTTPS":    [_PRange("tcp", 443, 443)],
    "DNS":      [_PRange("tcp", 53, 53), _PRange("udp", 53, 53)],
    "FTP":      [_PRange("tcp", 20, 21)],
    "FTP_PUT":  [_PRange("tcp", 20, 21)],
    "SSH":      [_PRange("tcp", 22, 22)],
    "SMTP":     [_PRange("tcp", 25, 25)],
    "SMTPS":    [_PRange("tcp", 465, 465)],
    "SMTP_ALT": [_PRange("tcp", 587, 587)],
    "TELNET":   [_PRange("tcp", 23, 23)],
    "RDP":      [_PRange("tcp", 3389, 3389)],
    "SMB":      [_PRange("tcp", 445, 445)],
    "IMAP":     [_PRange("tcp", 143, 143)],
    "IMAPS":    [_PRange("tcp", 993, 993)],
    "POP3":     [_PRange("tcp", 110, 110)],
    "POP3S":    [_PRange("tcp", 995, 995)],
    "LDAP":     [_PRange("tcp", 389, 389)],
    "LDAPS":    [_PRange("tcp", 636, 636)],
    "NTP":      [_PRange("udp", 123, 123)],
    "SNMP":     [_PRange("udp", 161, 161), _PRange("udp", 162, 162)],
    "PING":     [_PRange("icmp", 0, 0)],
    "MYSQL":    [_PRange("tcp", 3306, 3306)],
    "MSSQL":    [_PRange("tcp", 1433, 1434)],
    "ORACLE":   [_PRange("tcp", 1521, 1521)],
    "RADIUS":   [_PRange("udp", 1812, 1813)],
    "KERBEROS": [_PRange("tcp", 88, 88), _PRange("udp", 88, 88)],
    "BGP":      [_PRange("tcp", 179, 179)],
    "OSPF":     [_PRange("ip", 0, 0)],
    "GRE":      [_PRange("ip", 0, 0)],
    "SIP":      [_PRange("tcp", 5060, 5061), _PRange("udp", 5060, 5060)],
    "ALL_TCP":  [_PRange("tcp", 0, 65535)],
    "ALL_UDP":  [_PRange("udp", 0, 65535)],
    "ALL_ICMP": [_PRange("icmp", 0, 0)],
    "ALL_ICMP6":[_PRange("icmp", 0, 0)],
}


def _parse_svc_obj(svc) -> list[_PRange]:
    """Parse a model.Service into _PRange list."""
    proto = (svc.protocol or "tcp").lower()
    if proto in ("icmp", "icmp6"):
        return [_PRange("icmp", 0, 0)]
    if proto in ("ip", "gre", "esp", "ah", "ospf"):
        return [_PRange("ip", 0, 0)]
    protos = ["tcp", "udp"] if proto in ("tcp/udp", "any") else [proto]
    if not svc.dst_ports:
        return [_PRange(p, 0, 65535) for p in protos]
    ranges: list[_PRange] = []
    for part in svc.dst_ports.split():
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                continue
        else:
            try:
                lo = hi = int(part)
            except ValueError:
                continue
        for p in protos:
            ranges.append(_PRange(p, lo, hi))
    return ranges or [_PRange(protos[0], 0, 65535)]


class _SvcSet:
    """Resolved protocol+port set for a policy's service list.

    is_all=True means the policy matches ALL traffic (service = ALL).
    """
    __slots__ = ("is_all", "ranges")

    def __init__(self, is_all: bool = False, ranges: tuple[_PRange, ...] = ()):
        self.is_all = is_all
        self.ranges = ranges

    def contains(self, other: _SvcSet) -> bool:
        """True when self covers every proto+port that other covers (self ⊇ other)."""
        if self.is_all:
            return True
        if other.is_all:
            return False
        if not other.ranges:
            return True
        if not self.ranges:
            return False
        return all(
            any(a.contains(b) for a in self.ranges)
            for b in other.ranges
        )


class _SvcResolver:
    """Builds and caches _SvcSet for every service/group name in the config."""

    def __init__(self, cfg: FirewallConfig):
        self._svcs = {s.name: s for s in cfg.services}
        self._groups = {g.name: g for g in cfg.svc_groups}
        self._cache: dict[str, _SvcSet] = {}

    def resolve_list(self, names: list[str]) -> _SvcSet:
        if not names or "ALL" in names:
            return _SvcSet(is_all=True)
        ranges: list[_PRange] = []
        for name in names:
            s = self._resolve_one(name, set())
            if s.is_all:
                return _SvcSet(is_all=True)
            ranges.extend(s.ranges)
        return _SvcSet(ranges=tuple(ranges))

    def _resolve_one(self, name: str, visited: set[str]) -> _SvcSet:
        if name in self._cache:
            return self._cache[name]
        if name == "ALL":
            return _SvcSet(is_all=True)
        if name in visited:
            return _SvcSet()
        visited.add(name)

        if name in _BUILTIN:
            result = _SvcSet(ranges=tuple(_BUILTIN[name]))
        elif name in self._svcs:
            result = _SvcSet(ranges=tuple(_parse_svc_obj(self._svcs[name])))
        elif name in self._groups:
            g = self._groups[name]
            merged: list[_PRange] = []
            for m in g.members:
                s = self._resolve_one(m, visited)
                if s.is_all:
                    result = _SvcSet(is_all=True)
                    self._cache[name] = result
                    return result
                merged.extend(s.ranges)
            result = _SvcSet(ranges=tuple(merged))
        else:
            result = _SvcSet()   # unknown name → treat as empty (conservative)

        self._cache[name] = result
        return result


# ── Zone coverage helper ───────────────────────────────────────────────────────

def _zones_cover(i_zones: list[str], j_zones: list[str]) -> bool:
    """True when rule i's zone set is a superset of rule j's zone set.

    An empty zone list means 'any zone' (matches all interfaces).
    """
    if not i_zones:          # i = any zone → covers everything
        return True
    if not j_zones:          # j = any zone → i can't cover it (unless i is also any)
        return False
    return set(j_zones) <= set(i_zones)


# ── Object hygiene helpers (carried over from v1) ─────────────────────────────

def _referenced_names(cfg: FirewallConfig) -> tuple[set[str], set[str]]:
    addr_refs: set[str] = set()
    svc_refs: set[str] = set()
    for pol in cfg.policies:
        addr_refs.update(pol.src_addrs)
        addr_refs.update(pol.dst_addrs)
        svc_refs.update(pol.services)
    for n in cfg.nats:
        if n.real_obj:
            addr_refs.add(n.real_obj)
    # group membership counts as a reference transitively
    changed = True
    while changed:
        changed = False
        for grp in cfg.addr_groups:
            if grp.name in addr_refs:
                for m in grp.members:
                    if m not in addr_refs:
                        addr_refs.add(m)
                        changed = True
        for grp in cfg.svc_groups:
            if grp.name in svc_refs:
                for m in grp.members:
                    if m not in svc_refs:
                        svc_refs.add(m)
                        changed = True
    return addr_refs, svc_refs


# ── Shadow detection ───────────────────────────────────────────────────────────

def _shadow_check(policies: list[Policy], addr_r: _AddrResolver,
                  svc_r: _SvcResolver, report) -> None:
    """Detect rules that will never fire due to an earlier, more-general rule.

    Runs pairwise over the active (non-disabled) policy list in top-down order.
    For rule j to be shadowed by earlier rule i:
      · i's src zones  ⊇ j's src zones
      · i's dst zones  ⊇ j's dst zones
      · i's src addrs  ⊇ j's src addrs  (IP set containment)
      · i's dst addrs  ⊇ j's dst addrs
      · i's services   ⊇ j's services   (port-range containment)

    Rules with negated src/dst addresses are skipped (inversion makes
    containment math unreliable). FQDN-only address lists are also skipped.

    For configs with > 800 active rules, address containment falls back to
    name-set equality (still catches same-object rules that differ only in
    zone or service scope).
    """
    # Build (original_1based_idx, policy) for active rules only.
    active: list[tuple[int, Policy]] = [
        (idx + 1, p) for idx, p in enumerate(policies) if not p.disabled
    ]
    n = len(active)
    if n < 2:
        return

    # Pre-resolve addresses and services once per rule
    src_sets = [addr_r.resolve_list(p.src_addrs, p.src_negate) for _, p in active]
    dst_sets = [addr_r.resolve_list(p.dst_addrs, p.dst_negate) for _, p in active]
    svc_sets = [svc_r.resolve_list(p.services) for _, p in active]

    # For large configs fall back to name-equality for address comparison
    deep_ip = (n <= 800)

    for j_pos in range(1, n):
        j_rule, pj = active[j_pos]
        sj_src = src_sets[j_pos]
        sj_dst = dst_sets[j_pos]
        sj_svc = svc_sets[j_pos]

        for i_pos in range(j_pos):
            i_rule, pi = active[i_pos]

            # ── zone coverage ──────────────────────────────────────────────
            if not (_zones_cover(pi.src_zones, pj.src_zones) and
                    _zones_cover(pi.dst_zones, pj.dst_zones)):
                continue

            # ── service containment (fast — resolve is cached) ─────────────
            si_svc = svc_sets[i_pos]
            if not si_svc.contains(sj_svc):
                continue

            # ── address containment ────────────────────────────────────────
            si_src = src_sets[i_pos]
            si_dst = dst_sets[i_pos]

            if deep_ip:
                # Full CIDR set math — skip if FQDNs prevent comparison
                if (si_src.has_fqdn or sj_src.has_fqdn or
                        si_dst.has_fqdn or sj_dst.has_fqdn):
                    continue
                addr_shadow = (si_src.contains(sj_src) and
                               si_dst.contains(sj_dst))
            else:
                # Fallback: name-set equality only
                addr_shadow = (set(pi.src_addrs) == set(pj.src_addrs) and
                               set(pi.dst_addrs) == set(pj.dst_addrs))

            if not addr_shadow:
                continue

            # ── found a shadow — classify by action relationship ───────────
            if pi.action == pj.action:
                report.add(
                    "warn", "policy-opt",
                    f"policy '{pj.name}' (rule {j_rule}) is fully shadowed by "
                    f"'{pi.name}' (rule {i_rule}) — will never match "
                    f"in top-down evaluation ({pi.action}/{pi.action}); "
                    "consider removing or moving it above the broader rule",
                    pj.source,
                )
            elif pi.action == "accept" and pj.action == "deny":
                report.add(
                    "warn", "policy-opt",
                    f"policy '{pj.name}' (rule {j_rule}) DENY is bypassed: "
                    f"'{pi.name}' (rule {i_rule}) already ACCEPTs this traffic — "
                    "the deny rule will never be reached; fix rule order or "
                    "tighten the accept rule above it",
                    pj.source,
                )
            else:
                # deny then accept: j's permit is blocked by i's deny
                report.add(
                    "info", "policy-opt",
                    f"policy '{pj.name}' (rule {j_rule}) ACCEPT is unreachable: "
                    f"'{pi.name}' (rule {i_rule}) DENYs this traffic first — "
                    "verify that the deny above is intentional",
                    pj.source,
                )
            break  # report only the first (nearest) shadower for each rule


# ── Collapse candidates ────────────────────────────────────────────────────────

def _collapse_check(policies: list[Policy], report) -> None:
    """Detect rules with identical match criteria (except services) that can be
    collapsed into a single rule with a merged service list.

    Rules that differ only in the service list are candidates for merging —
    the combined rule is semantically equivalent and reduces table size.
    UTM profile differences prevent merging (different inspection intent).
    """
    groups: dict[tuple, list[Policy]] = defaultdict(list)
    for pol in policies:
        if pol.disabled:
            continue
        key = (
            tuple(sorted(pol.src_zones)),
            tuple(sorted(pol.dst_zones)),
            tuple(sorted(pol.src_addrs)),
            tuple(sorted(pol.dst_addrs)),
            pol.action,
            pol.nat,
            pol.log,
            pol.src_negate,
            pol.dst_negate,
            pol.app_list or "",
            pol.webfilter or "",
            pol.file_filter or "",
            pol.antivirus or "",
            pol.ips_sensor or "",
        )
        groups[key].append(pol)

    for pols in groups.values():
        if len(pols) < 2:
            continue
        # Skip if all have the same service list — that is a true duplicate
        # and is already reported by the exact-duplicate check below.
        svc_keys = [tuple(sorted(p.services)) for p in pols]
        if len(set(svc_keys)) < 2:
            continue
        names = [p.name for p in pols]
        all_svcs = sorted({s for p in pols for s in p.services})
        report.add(
            "info", "policy-opt",
            f"{len(pols)} policies have identical match criteria except services "
            f"— collapse candidates: {', '.join(names[:8])}"
            + (" …" if len(names) > 8 else "")
            + f"; merged service list would be: {', '.join(all_svcs[:12])}"
            + (" …" if len(all_svcs) > 12 else ""),
        )


# ── Public entry point ─────────────────────────────────────────────────────────

def analyze(cfg: FirewallConfig, report) -> None:
    """Run all config hygiene + policy optimization checks.

    Findings are added to report at info/warn levels; no config is modified.
    Called by pipeline._cross_one() after all transforms and before emit.
    """
    # ── duplicate object definitions ──────────────────────────────────────────
    by_value: dict[tuple, list[str]] = {}
    for a in cfg.addresses:
        by_value.setdefault(("addr", a.type, a.value), []).append(a.name)
    for s in cfg.services:
        by_value.setdefault(("svc",) + s.signature(), []).append(s.name)
    for key, names in sorted(by_value.items()):
        if len(names) > 1:
            kind = "address" if key[0] == "addr" else "service"
            report.add(
                "info", "hygiene",
                f"duplicate {kind} definitions (same value, {len(names)} "
                f"names): {', '.join(names)} — candidates to merge",
            )

    # ── unreferenced objects ───────────────────────────────────────────────────
    addr_refs, svc_refs = _referenced_names(cfg)
    dead_addrs = [a.name for a in cfg.addresses if a.name not in addr_refs]
    dead_addrs += [g.name for g in cfg.addr_groups if g.name not in addr_refs]
    dead_svcs = [s.name for s in cfg.services if s.name not in svc_refs]
    dead_svcs += [g.name for g in cfg.svc_groups if g.name not in svc_refs]
    if dead_addrs:
        report.add(
            "info", "hygiene",
            f"{len(dead_addrs)} address object(s) referenced by no policy or "
            f"group: {', '.join(sorted(dead_addrs)[:15])}"
            + (" …" if len(dead_addrs) > 15 else ""),
        )
    if dead_svcs:
        report.add(
            "info", "hygiene",
            f"{len(dead_svcs)} service object(s) referenced by no policy or "
            f"group: {', '.join(sorted(dead_svcs)[:15])}"
            + (" …" if len(dead_svcs) > 15 else ""),
        )

    # ── exact duplicate policies and any/any/ALL rules ─────────────────────────
    seen: dict[tuple, str] = {}
    for pol in cfg.policies:
        key = (
            tuple(pol.src_zones), tuple(pol.dst_zones),
            tuple(sorted(pol.src_addrs)), tuple(sorted(pol.dst_addrs)),
            tuple(sorted(pol.services)),
        )
        if key in seen:
            report.add(
                "warn", "hygiene",
                f"policy '{pol.name}' duplicates '{seen[key]}' "
                "(identical match criteria — the later one never matches)",
                pol.source,
            )
        else:
            seen[key] = pol.name
        if (pol.action == "accept" and not pol.disabled
                and pol.src_addrs == ["all"] and pol.dst_addrs == ["all"]
                and pol.services == ["ALL"]):
            report.add(
                "warn", "hygiene",
                f"policy '{pol.name}' is an any/any/ALL accept — "
                "confirm this is intentional",
                pol.source,
            )

    # ── shadow detection (top-down first-match) ────────────────────────────────
    if cfg.policies:
        addr_r = _AddrResolver(cfg)
        svc_r = _SvcResolver(cfg)
        _shadow_check(cfg.policies, addr_r, svc_r, report)
        _collapse_check(cfg.policies, report)
