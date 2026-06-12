"""FortiManager output target: a JSON-RPC import bundle.

FortiConverter can emit "FortiManager config"; fwforge's version is
automation-grade — a JSON document of ready-to-send FortiManager JSON-RPC
requests that:

  1. create the converted address/group/service/VIP objects in an ADOM
     (`/pm/config/adom/<adom>/obj/firewall/...`)
  2. create a policy package and fill it with the converted policies
     (`/pm/config/adom/<adom>/pkg/<pkg>/firewall/policy`)

Each entry in `requests` is a complete JSON-RPC envelope minus the session
key — POST them in order to https://<fmg>/jsonrpc after login (or add a
Bearer token on FMG 7.2.2+). Apply with a normal FortiManager install to
the target device afterwards.

Scope (deliberate): objects + policies — the things FortiManager manages
centrally. Device-level config (routes, VPN phase1/2, interfaces) stays in
the CLI script and is flagged; interface/zone names used by policies must
exist in the ADOM as per-device mappings or zones.
"""
from __future__ import annotations

import ipaddress
import json

from ..model import FirewallConfig


def _is_v6(value: str) -> bool:
    return ":" in value


def _addr_entry(a) -> dict:
    if a.type == "host":
        return {"name": a.name, "type": "ipmask",
                "subnet": [a.value, "255.255.255.255"],
                **({"comment": a.comment} if a.comment else {})}
    if a.type == "subnet":
        net = ipaddress.IPv4Network(a.value, strict=False)
        return {"name": a.name, "type": "ipmask",
                "subnet": [str(net.network_address), str(net.netmask)],
                **({"comment": a.comment} if a.comment else {})}
    if a.type == "range":
        lo, hi = a.value.split("-", 1)
        return {"name": a.name, "type": "iprange",
                "start-ip": lo, "end-ip": hi,
                **({"comment": a.comment} if a.comment else {})}
    # fqdn
    return {"name": a.name, "type": "fqdn", "fqdn": a.value,
            **({"comment": a.comment} if a.comment else {})}


def _addr6_entry(a) -> dict:
    if a.type == "host":
        return {"name": a.name, "type": "ipprefix", "ip6": f"{a.value}/128",
                **({"comment": a.comment} if a.comment else {})}
    if a.type == "subnet":
        return {"name": a.name, "type": "ipprefix", "ip6": a.value,
                **({"comment": a.comment} if a.comment else {})}
    if a.type == "range":
        lo, hi = a.value.split("-", 1)
        return {"name": a.name, "type": "iprange",
                "start-ip": lo, "end-ip": hi,
                **({"comment": a.comment} if a.comment else {})}
    return {"name": a.name, "type": "fqdn", "fqdn": a.value,
            **({"comment": a.comment} if a.comment else {})}


def _svc_entry(s) -> dict:
    out: dict = {"name": s.name}
    if s.protocol in ("tcp", "udp", "tcp/udp"):
        ranges = (s.dst_ports or "1-65535").split()
        if s.src_ports:
            ranges = [f"{r}:{s.src_ports}" for r in ranges]
        out["protocol"] = "TCP/UDP/SCTP"
        if s.protocol in ("tcp", "tcp/udp"):
            out["tcp-portrange"] = ranges
        if s.protocol in ("udp", "tcp/udp"):
            out["udp-portrange"] = ranges
    elif s.protocol == "icmp":
        out["protocol"] = "ICMP"
        if s.icmp_type is not None:
            out["icmptype"] = s.icmp_type
    else:  # ip
        out["protocol"] = "IP"
        if s.proto_number is not None:
            out["protocol-number"] = s.proto_number
    if s.comment:
        out["comment"] = s.comment
    return out


def _vip_entry(v, intf_of) -> dict:
    out = {"name": v.name, "extip": v.ext_ip,
           "mappedip": [{"range": v.mapped_ip}],
           "extintf": intf_of(v.ext_intf)}
    if v.protocol and v.ext_port:
        out["portforward"] = "enable"
        out["protocol"] = v.protocol
        out["extport"] = v.ext_port
        out["mappedport"] = v.mapped_port or v.ext_port
    if v.comment:
        out["comment"] = v.comment
    return out


def _policy_family(p, fam: dict[str, int]) -> int:
    """Same classification as the CLI emitter: 4, 6, or 0 (mixed)."""
    if p.family in (4, 6):
        return p.family
    names = [n for n in (p.src_addrs + p.dst_addrs) if n != "all"]
    has6 = any(fam.get(n) == 6 for n in names)
    has4 = any(fam.get(n, 4) == 4 for n in names)
    if has6 and not has4:
        return 6
    if has6 and has4:
        return 0
    return 4


def _policy_entry(p, intf_of, fam: dict[str, int], nat_on: bool) -> dict:
    out = {
        "name": p.name or "",
        "srcintf": [intf_of(z) for z in (p.src_zones or ["any"])],
        "dstintf": [intf_of(z) for z in (p.dst_zones or ["any"])],
        "service": p.services or ["ALL"],
        "action": p.action,
        "schedule": ["always"],
        "logtraffic": "all" if p.log else "disable",
        "status": "disable" if p.disabled else "enable",
        "nat": "enable" if (p.nat or nat_on) else "disable",
    }
    pfam = _policy_family(p, fam)
    src = p.src_addrs or ["all"]
    dst = p.dst_addrs or ["all"]
    if pfam in (4, 0):
        out["srcaddr"] = [a for a in src if fam.get(a, 4) != 6] or ["none"]
        out["dstaddr"] = [a for a in dst if fam.get(a, 4) != 6] or ["none"]
        if p.src_negate:
            out["srcaddr-negate"] = "enable"
        if p.dst_negate:
            out["dstaddr-negate"] = "enable"
    if pfam in (6, 0):
        v6 = lambda names: [a for a in names
                            if fam.get(a) == 6 or a == "all"] or ["none"]
        out["srcaddr6"] = v6(src)
        out["dstaddr6"] = v6(dst)
        if p.src_negate:
            out["srcaddr6-negate"] = "enable"
        if p.dst_negate:
            out["dstaddr6-negate"] = "enable"
    if p.comment:
        out["comments"] = p.comment[:1023]
    return out


def build_bundle(cfg: FirewallConfig, report, adom: str = "root",
                 package: str = "fwforge-converted",
                 nat_mode: str = "policy") -> dict:
    """Build the JSON-RPC request bundle from a post-transform IR."""
    def intf_of(zone: str) -> str:
        if zone in ("any", "all", ""):
            return "any"
        itf = cfg.interface_by_name(zone)
        return itf.mapped if itf else zone

    obj = f"/pm/config/adom/{adom}/obj"
    requests: list[dict] = []

    def add(url: str, data: list) -> None:
        if data:
            requests.append({"method": "add",
                             "params": [{"url": url, "data": data}]})

    # name -> family, mirroring the CLI emitter
    fam: dict[str, int] = {}
    for a in cfg.addresses:
        fam[a.name] = 6 if _is_v6(a.value) else 4
    for v in cfg.vips:
        fam[v.name] = 4
    for g in cfg.addr_groups:
        for m in g.members:
            if m in fam:
                fam[g.name] = fam[m]
                break

    addr4 = [a for a in cfg.addresses if not _is_v6(a.value)]
    addr6 = [a for a in cfg.addresses if _is_v6(a.value)]
    grp4 = [g for g in cfg.addr_groups if fam.get(g.name, 4) != 6]
    grp6 = [g for g in cfg.addr_groups if fam.get(g.name) == 6]
    add(f"{obj}/firewall/address", [_addr_entry(a) for a in addr4])
    add(f"{obj}/firewall/address6", [_addr6_entry(a) for a in addr6])
    add(f"{obj}/firewall/addrgrp",
        [{"name": g.name, "member": g.members,
          **({"comment": g.comment} if g.comment else {})}
         for g in grp4])
    add(f"{obj}/firewall/addrgrp6",
        [{"name": g.name, "member": g.members,
          **({"comment": g.comment} if g.comment else {})}
         for g in grp6])
    add(f"{obj}/firewall/service/custom",
        [_svc_entry(s) for s in cfg.services])
    add(f"{obj}/firewall/service/group",
        [{"name": g.name, "member": g.members,
          **({"comment": g.comment} if g.comment else {})}
         for g in cfg.svc_groups])
    add(f"{obj}/firewall/vip",
        [_vip_entry(v, intf_of) for v in cfg.vips
         if v.ext_ip and not v.ext_ip.startswith("<")
         and v.mapped_ip and not v.mapped_ip.startswith("<")])

    # same interface-PAT intent as the CLI emitter's 'set nat enable'
    nat_pairs = set() if nat_mode == "central" else {
        (n.real_ifc, n.mapped_ifc) for n in cfg.nats
        if n.kind == "dynamic-interface"}

    def nat_on(p) -> bool:
        return p.action == "accept" and any(
            (sz, dz) in nat_pairs or ("*", dz) in nat_pairs
            for sz in (p.src_zones or [])
            for dz in (p.dst_zones or []))

    requests.append({"method": "add", "params": [{
        "url": f"/pm/pkg/adom/{adom}",
        "data": [{"name": package, "type": "pkg"}]}]})
    add(f"/pm/config/adom/{adom}/pkg/{package}/firewall/policy",
        [_policy_entry(p, intf_of, fam, nat_on(p)) for p in cfg.policies])

    if nat_mode == "central":
        report.add(
            "warn", "fortimanager",
            "central NAT mode: the central-snat-map rules are NOT in the "
            "FortiManager bundle — apply them from the CLI script")
    if any(p.app_list for p in cfg.policies):
        report.add(
            "warn", "fortimanager",
            "App-ID application-list profiles are NOT in the FortiManager "
            "bundle — create them from the CLI script's 'config "
            "application list' and attach to the policies in the package")

    n_obj = (len(cfg.addresses) + len(cfg.addr_groups) + len(cfg.services)
             + len(cfg.svc_groups) + len(cfg.vips))
    report.add(
        "info", "fortimanager",
        f"FortiManager bundle: {n_obj} object(s) and {len(cfg.policies)} "
        f"policy(ies) for ADOM '{adom}', package '{package}'. POST each "
        "request to https://<fmg>/jsonrpc after login; then install the "
        "package to the target device.")
    intf_names = sorted({intf_of(z) for p in cfg.policies
                         for z in (p.src_zones + p.dst_zones)} - {"any"})
    if intf_names:
        report.add(
            "warn", "fortimanager",
            "policies reference interface/zone names "
            f"({', '.join(intf_names[:8])}"
            + (" …" if len(intf_names) > 8 else "")
            + ") — create matching per-device mappings or zones in the "
            "ADOM before installing the package")
    if cfg.phase1s or cfg.routes or cfg.bgp or cfg.ospf:
        report.add(
            "info", "fortimanager",
            "routes, dynamic routing, and VPN tunnels are device-level — "
            "they are NOT in the FortiManager bundle; apply them from the "
            "CLI script (or via FortiManager's device database / VPN "
            "Manager)")

    return {
        "fortimanager": {
            "generated-by": "fwforge",
            "adom": adom,
            "package": package,
            "source-vendor": cfg.vendor,
            "source-hostname": cfg.hostname,
            "how-to": ("POST each entry in 'requests' (in order) to "
                       "https://<fortimanager>/jsonrpc with your session "
                       "key added to the envelope"),
        },
        "requests": requests,
    }


def render(bundle: dict) -> str:
    return json.dumps(bundle, indent=2) + "\n"
