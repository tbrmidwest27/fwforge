"""Shared route-based IPsec tunnel assembly for the cross-vendor parsers.

Given a resolved phase1 spec and a list of selector pairs, this appends the
FortiOS route-based pieces every VPN conversion needs:

  - one VpnPhase1 (the IKE gateway)
  - one VpnPhase2 per selector (the proxy-id / interesting-traffic pair)
  - a tunnel route to each remote subnet via the tunnel interface
  - a bidirectional firewall policy pair, LAN-side interface inferred from
    the source routing table (so the tunnel actually passes traffic)

Address objects for the policies are synthesized and de-duplicated here.
The Cisco ASA parser has its own parallel inline implementation that
predates this helper; PAN-OS and pfSense use this shared path.
"""
from __future__ import annotations

import ipaddress

from ..model import (
    Address,
    Policy,
    Route,
    VpnPhase1,
    VpnPhase2,
)

# common algorithm normalization, vendor token -> FortiOS token
ENC = {
    "des": "des", "3des": "3des",
    "aes": "aes128", "aes128": "aes128", "aes-128": "aes128",
    "aes192": "aes192", "aes-192": "aes192",
    "aes256": "aes256", "aes-256": "aes256",
    "aes-128-cbc": "aes128", "aes-192-cbc": "aes192", "aes-256-cbc": "aes256",
    "aes128gcm": "aes128gcm", "aes256gcm": "aes256gcm",
    "aes-128-gcm": "aes128gcm", "aes-256-gcm": "aes256gcm",
    "aes128gcm16": "aes128gcm", "aes256gcm16": "aes256gcm",
}
HASH = {
    "md5": "md5", "sha1": "sha1", "sha": "sha1", "sha-1": "sha1",
    "sha256": "sha256", "sha-256": "sha256", "sha384": "sha384",
    "sha-384": "sha384", "sha512": "sha512", "sha-512": "sha512",
    "hmac_md5": "md5", "hmac_sha1": "sha1", "hmac_sha256": "sha256",
    "hmac_sha384": "sha384", "hmac_sha512": "sha512",
}


def esp_combos(encs: list[str], hashes: list[str]) -> list[str]:
    """FortiOS proposal tokens: enc-hash, except GCM (AEAD, no auth)."""
    out: list[str] = []
    for e in encs:
        if e.endswith("gcm"):
            out.append(e)
        else:
            for h in (hashes or ["sha256"]):
                out.append(f"{e}-{h}")
    seen: set[str] = set()
    return [p for p in out if not (p in seen or seen.add(p))]


def _addr_name(cfg, cidr: str) -> str | None:
    """Synthesize (and cache) an address object for a selector CIDR."""
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return None
    if net.prefixlen == 32:
        name, kind, value = (f"vpn-h-{net.network_address}", "host",
                             str(net.network_address))
    else:
        name, kind, value = (f"vpn-{net.network_address}-{net.prefixlen}",
                             "subnet", str(net))
    if not any(a.name == name for a in cfg.addresses):
        cfg.addresses.append(Address(name=name, type=kind, value=value,
                                     comment="VPN selector"))
    return name


def add_route_based_tunnel(cfg, report, route_table, *, name: str,
                           interface: str, remote_gw: str,
                           ike_version: int, p1_proposals: list[str],
                           p1_dhgrp: list[str], psk: str,
                           psk_remote: str = "", p1_keylife: int = 0,
                           selectors: list[tuple[str, str]],
                           p2_proposals: list[str], pfs_group: str = "",
                           p2_keylife: int = 0, comment: str | None = None,
                           source=None) -> int:
    """selectors: list of (src_cidr, dst_cidr). Returns phase2 count
    (0 = nothing emitted)."""
    usable = [(s, d) for s, d in selectors if s and d]
    if not usable:
        report.add("warn", "vpn",
                   f"tunnel '{name}' (peer {remote_gw}) has no convertible "
                   "selectors — skipped", source)
        return 0

    cfg.phase1s.append(VpnPhase1(
        name=name, interface=interface, remote_gw=remote_gw,
        ike_version=ike_version, proposals=p1_proposals, dhgrp=p1_dhgrp,
        psk=psk, psk_remote=psk_remote, keylife=p1_keylife,
        comment=comment, source=source))

    route_seen: set[str] = set()
    for i, (src_cidr, dst_cidr) in enumerate(usable, start=1):
        cfg.phase2s.append(VpnPhase2(
            name=f"{name}-p2-{i}", phase1=name, proposals=p2_proposals,
            pfs_group=pfs_group, src=src_cidr, dst=dst_cidr,
            keylife=p2_keylife, source=source))

        src_name = _addr_name(cfg, src_cidr) or "all"
        dst_name = _addr_name(cfg, dst_cidr) or "all"

        if dst_cidr != "0.0.0.0/0" and dst_cidr not in route_seen:
            route_seen.add(dst_cidr)
            cfg.routes.append(Route(
                dest=dst_cidr, gateway="", interface=name,
                comment=f"VPN route for tunnel {name}", source=source))

        lan_ifc = "any"
        if src_cidr != "0.0.0.0/0":
            try:
                lan_ifc = route_table.lookup_net(
                    ipaddress.IPv4Network(src_cidr, strict=False)) or "any"
            except ValueError:
                lan_ifc = "any"
        if lan_ifc == "any":
            report.add("warn", "vpn",
                       f"{name}: could not infer the LAN-side interface for "
                       f"{src_cidr} — VPN policies use 'any'; review",
                       source)
        cfg.policies.append(Policy(
            name=f"{name}-out-{i}", src_zones=[lan_ifc], dst_zones=[name],
            src_addrs=[src_name], dst_addrs=[dst_name], services=["ALL"],
            comment="auto-generated VPN policy", source=source))
        cfg.policies.append(Policy(
            name=f"{name}-in-{i}", src_zones=[name], dst_zones=[lan_ifc],
            src_addrs=[dst_name], dst_addrs=[src_name], services=["ALL"],
            comment="auto-generated VPN policy", source=source))
    return len(usable)
