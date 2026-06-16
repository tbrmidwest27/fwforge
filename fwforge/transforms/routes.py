"""Route-based egress inference.

FortiConverter's own docs admit: when routing info is missing it sets the
policy interface to 'any'. We do better — build a routing table from the
source config (static routes + connected interface networks) and resolve
each policy's destination addresses to an egress interface via
longest-prefix match. Only when destinations genuinely diverge (or are
'all') do we fall back to 'any', and we say so in the report.
"""
from __future__ import annotations

import ipaddress

from ..model import FirewallConfig


class RouteTable:
    def __init__(self, cfg: FirewallConfig):
        self.entries: list[tuple[ipaddress.IPv4Network, str]] = []
        for itf in cfg.interfaces:
            if itf.ip:
                try:
                    net = ipaddress.IPv4Interface(itf.ip).network
                    self.entries.append((net, itf.name))
                except ValueError:
                    pass
        for rt in cfg.routes:
            try:
                self.entries.append((ipaddress.IPv4Network(rt.dest), rt.interface))
            except ValueError:
                pass
        # longest prefix first
        self.entries.sort(key=lambda e: e[0].prefixlen, reverse=True)

    def lookup_net(self, net: ipaddress.IPv4Network) -> str | None:
        for entry_net, ifc in self.entries:
            if (net.network_address in entry_net
                    and net.broadcast_address in entry_net):
                return ifc
        return None


def _addr_networks(cfg: FirewallConfig, name: str,
                   seen: set[str]) -> list[ipaddress.IPv4Network] | None:
    """Resolve an address/group name to networks; None = unresolvable."""
    if name in seen:
        return []
    seen.add(name)
    addr = cfg.address_by_name(name)
    if addr:
        try:
            if addr.type == "host":
                return [ipaddress.IPv4Network(f"{addr.value}/32")]
            if addr.type == "subnet":
                return [ipaddress.IPv4Network(addr.value, strict=False)]
            if addr.type == "range":
                lo, hi = addr.value.split("-", 1)
                # summarize the WHOLE range, not just its endpoints: the
                # interior may be unrouted (or routed elsewhere) even when both
                # endpoints resolve to one interface. Covering every block lets
                # lookup_net surface that gap and fall back to 'any' instead of
                # mis-inferring a single dstintf from the endpoints alone.
                return list(ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(lo.strip()),
                    ipaddress.IPv4Address(hi.strip())))
        except ValueError:
            return None
        return None  # fqdn etc.
    for grp in cfg.addr_groups:
        if grp.name == name:
            nets: list[ipaddress.IPv4Network] = []
            for member in grp.members:
                sub = _addr_networks(cfg, member, seen)
                if sub is None:
                    return None
                nets.extend(sub)
            return nets
    return None


def infer_dst_zones(cfg: FirewallConfig, report) -> None:
    table = RouteTable(cfg)
    inferred = 0
    fell_back = 0
    for pol in cfg.policies:
        if pol.dst_zones:
            continue
        if pol.dst_addrs == ["all"]:
            pol.dst_zones = ["any"]
            continue
        egress: set[str] = set()
        resolvable = True
        for name in pol.dst_addrs:
            nets = _addr_networks(cfg, name, set())
            if nets is None or not nets:
                resolvable = False
                break
            for net in nets:
                ifc = table.lookup_net(net)
                if ifc is None:
                    resolvable = False
                    break
                egress.add(ifc)
            if not resolvable:
                break
        if resolvable and len(egress) == 1:
            pol.dst_zones = [egress.pop()]
            pol.dst_inferred = True
            inferred += 1
        else:
            pol.dst_zones = ["any"]
            fell_back += 1
            report.add(
                "warn", "policies",
                f"policy '{pol.name}': could not infer a single egress "
                "interface for destinations "
                f"{pol.dst_addrs} — using 'any' (review)",
                pol.source,
            )
    if inferred:
        report.add(
            "info", "policies",
            f"inferred dstintf from routing for {inferred} "
            f"{'policy' if inferred == 1 else 'policies'} "
            f"({fell_back} fell back to 'any')",
        )
