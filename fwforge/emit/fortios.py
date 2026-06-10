"""FortiOS CLI emitter: IR -> paste-able config script.

Output is deterministic (no timestamps) so converted configs diff cleanly
across runs. Built-in FortiOS services are reused only on exact semantic
match — `udp/53` is NOT mapped to built-in DNS (which is tcp+udp/53);
silent broadening is precisely the class of bug this tool exists to avoid.
"""
from __future__ import annotations

import ipaddress

from ..model import FirewallConfig, Service

# (protocol, dst_ports, src_ports, icmp_type, proto_number) -> built-in name
BUILTIN_SERVICES = {
    ("tcp", "80", "", None, None): "HTTP",
    ("tcp", "443", "", None, None): "HTTPS",
    ("tcp", "22", "", None, None): "SSH",
    ("tcp", "23", "", None, None): "TELNET",
    ("tcp", "21", "", None, None): "FTP",
    ("tcp", "25", "", None, None): "SMTP",
    ("tcp", "110", "", None, None): "POP3",
    ("tcp", "143", "", None, None): "IMAP",
    ("tcp", "3389", "", None, None): "RDP",
    ("tcp", "445", "", None, None): "SMB",
    ("tcp/udp", "53", "", None, None): "DNS",
    ("tcp/udp", "88", "", None, None): "KERBEROS",
    ("udp", "123", "", None, None): "NTP",
    ("udp", "514", "", None, None): "SYSLOG",
    ("udp", "161", "", None, None): "SNMP",
    ("icmp", "", "", 8, None): "PING",
    ("icmp", "", "", None, None): "ALL_ICMP",
    ("ip", "", "", None, 47): "GRE",
    ("ip", "", "", None, 50): "ESP",
    ("ip", "", "", None, 51): "AH",
}


def _q(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _mask(prefix: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def map_builtin_services(cfg: FirewallConfig, report) -> None:
    """Replace custom services that exactly match a FortiOS built-in."""
    renames: dict[str, str] = {}
    kept: list[Service] = []
    for svc in cfg.services:
        builtin = BUILTIN_SERVICES.get(svc.signature())
        if builtin:
            renames[svc.name] = builtin
        else:
            kept.append(svc)
    if not renames:
        return
    cfg.services[:] = kept
    for pol in cfg.policies:
        pol.services = [renames.get(s, s) for s in pol.services]
    for grp in cfg.svc_groups:
        grp.members = [renames.get(m, m) for m in grp.members]
    report.add(
        "info", "services",
        f"mapped {len(renames)} service(s) to exact FortiOS built-ins: "
        + ", ".join(f"{k}->{v}" for k, v in sorted(renames.items())[:10])
        + (" …" if len(renames) > 10 else ""),
    )


def _intf(cfg: FirewallConfig, zone: str) -> str:
    if zone in ("any", "all", ""):
        return "any"
    itf = cfg.interface_by_name(zone)
    return itf.mapped if itf else zone


class Emitter:
    def __init__(self, cfg: FirewallConfig, report, target: str = "7.4"):
        self.cfg = cfg
        self.report = report
        self.target = target
        self.out: list[str] = []

    def line(self, s: str = ""):
        self.out.append(s)

    def emit(self) -> str:
        cfg = self.cfg
        # header stays pure ASCII so the script pastes safely into any CLI
        self.line(f"# fwforge converted config - source vendor: {cfg.vendor}"
                  + (f" {cfg.version}" if cfg.version else ""))
        self.line(f"# source hostname: {cfg.hostname or '(unknown)'}"
                  f" | target: FortiOS {self.target}")
        self.line("# review the companion report before applying")
        self.zones()
        self.addresses()
        self.addr_groups()
        self.services()
        self.svc_groups()
        self.vips()
        self.routes()
        self.policies()
        return "\n".join(self.out) + "\n"

    def zones(self):
        emittable = [z for z in self.cfg.zones if z.members]
        for z in self.cfg.zones:
            if not z.members:
                self.report.add("warn", "zones",
                                f"zone '{z.name}' has no layer-3 members — "
                                "not emitted", z.source)
        if not emittable:
            return
        self.line()
        self.line("config system zone")
        for z in emittable:
            members = [_intf(self.cfg, m) for m in z.members]
            self.line(f"    edit {_q(z.name)}")
            # PAN-OS allows intrazone traffic by default; mirror that so
            # the migration doesn't break same-zone flows (flagged below)
            self.line("        set intrazone allow")
            self.line("        set interface "
                      + " ".join(_q(m) for m in members))
            self.line("    next")
        self.line("end")
        self.report.add(
            "warn", "zones",
            f"{len(emittable)} zone(s) emitted with 'intrazone allow' to "
            "preserve PAN-OS's default same-zone behavior. That traffic "
            "bypasses policies/logging — switch to 'intrazone deny' and add "
            "explicit policies when you want enforcement.")

    def addresses(self):
        if not self.cfg.addresses:
            return
        self.line()
        self.line("config firewall address")
        for a in self.cfg.addresses:
            self.line(f"    edit {_q(a.name)}")
            try:
                if a.type == "host":
                    self.line(f"        set subnet {a.value} 255.255.255.255")
                elif a.type == "subnet":
                    net = ipaddress.IPv4Network(a.value, strict=False)
                    self.line(f"        set subnet {net.network_address} "
                              f"{net.netmask}")
                elif a.type == "range":
                    lo, hi = a.value.split("-", 1)
                    self.line("        set type iprange")
                    self.line(f"        set start-ip {lo}")
                    self.line(f"        set end-ip {hi}")
                elif a.type == "fqdn":
                    self.line("        set type fqdn")
                    self.line(f"        set fqdn {_q(a.value)}")
            except ValueError:
                self.report.add("error", "addresses",
                                f"address '{a.name}': invalid value "
                                f"'{a.value}' — emitted as 0.0.0.0/32",
                                a.source)
                self.line("        set subnet 0.0.0.0 255.255.255.255")
            if a.comment:
                self.line(f"        set comment {_q(a.comment[:255])}")
            self.line("    next")
        self.line("end")

    def addr_groups(self):
        if not self.cfg.addr_groups:
            return
        self.line()
        self.line("config firewall addrgrp")
        for g in self.cfg.addr_groups:
            self.line(f"    edit {_q(g.name)}")
            if g.members:
                members = " ".join(_q(m) for m in g.members)
                self.line(f"        set member {members}")
            else:
                self.report.add("warn", "addresses",
                                f"address group '{g.name}' has no members — "
                                "FortiOS rejects empty groups; emitted with "
                                "placeholder 'all'", g.source)
                self.line('        set member "all"')
            if g.comment:
                self.line(f"        set comment {_q(g.comment[:255])}")
            self.line("    next")
        self.line("end")

    def services(self):
        if not self.cfg.services:
            return
        self.line()
        self.line("config firewall service custom")
        for s in self.cfg.services:
            self.line(f"    edit {_q(s.name)}")
            if s.protocol in ("tcp", "udp", "tcp/udp"):
                ranges = (s.dst_ports or "1-65535").split()
                if s.src_ports:
                    ranges = [f"{r}:{s.src_ports}" for r in ranges]
                spec = " ".join(ranges)
                if s.protocol in ("tcp", "tcp/udp"):
                    self.line(f"        set tcp-portrange {spec}")
                if s.protocol in ("udp", "tcp/udp"):
                    self.line(f"        set udp-portrange {spec}")
            elif s.protocol == "icmp":
                self.line("        set protocol ICMP")
                if s.icmp_type is not None:
                    self.line(f"        set icmptype {s.icmp_type}")
            elif s.protocol == "ip":
                self.line("        set protocol IP")
                if s.proto_number is not None:
                    self.line(f"        set protocol-number {s.proto_number}")
            if s.comment:
                self.line(f"        set comment {_q(s.comment[:255])}")
            self.line("    next")
        self.line("end")

    def svc_groups(self):
        if not self.cfg.svc_groups:
            return
        self.line()
        self.line("config firewall service group")
        for g in self.cfg.svc_groups:
            self.line(f"    edit {_q(g.name)}")
            if g.members:
                self.line("        set member "
                          + " ".join(_q(m) for m in g.members))
            if g.comment:
                self.line(f"        set comment {_q(g.comment[:255])}")
            self.line("    next")
        self.line("end")

    def vips(self):
        emittable = [v for v in self.cfg.vips
                     if v.ext_ip and not v.mapped_ip.startswith("<")]
        for v in self.cfg.vips:
            if v not in emittable:
                self.report.add(
                    "error", "nat",
                    f"VIP '{v.name}' incomplete (mapped ip unresolved) — "
                    "not emitted, convert manually", v.source)
        if not emittable:
            return
        self.report.add(
            "info", "nat",
            f"{len(emittable)} VIP(s) created from static NAT. FortiOS "
            "matches inbound DNAT traffic on the VIP object — review "
            "policies whose dstaddr is the VIP's internal host and decide "
            "whether they should reference the VIP instead.",
        )
        self.line()
        self.line("config firewall vip")
        for v in emittable:
            self.line(f"    edit {_q(v.name)}")
            self.line(f"        set extip {v.ext_ip}")
            self.line(f"        set mappedip {_q(v.mapped_ip)}")
            ext = _intf(self.cfg, v.ext_intf)
            self.line(f"        set extintf {_q(ext)}")
            if v.protocol and v.ext_port:
                self.line("        set portforward enable")
                self.line(f"        set protocol {v.protocol}")
                self.line(f"        set extport {v.ext_port}")
                self.line(f"        set mappedport "
                          f"{v.mapped_port or v.ext_port}")
            if v.comment:
                self.line(f"        set comment {_q(v.comment[:255])}")
            self.line("    next")
        self.line("end")

    def routes(self):
        if not self.cfg.routes:
            return
        self.line()
        self.line("config router static")
        for i, rt in enumerate(self.cfg.routes, start=1):
            try:
                net = ipaddress.IPv4Network(rt.dest, strict=False)
            except ValueError:
                self.report.add("error", "routes",
                                f"route to '{rt.dest}' invalid — skipped",
                                rt.source)
                continue
            self.line(f"    edit {i}")
            if net.prefixlen or net.network_address != ipaddress.IPv4Address("0.0.0.0"):
                self.line(f"        set dst {net.network_address} {net.netmask}")
            self.line(f"        set gateway {rt.gateway}")
            self.line(f"        set device {_q(_intf(self.cfg, rt.interface))}")
            if rt.distance != 10:
                self.line(f"        set distance {rt.distance}")
            self.line("    next")
        self.line("end")

    def policies(self):
        if not self.cfg.policies:
            return
        # apply interface-PAT NAT intents
        nat_pairs = {(n.real_ifc, n.mapped_ifc) for n in self.cfg.nats
                     if n.kind == "dynamic-interface"}
        applied_nat = 0
        self.line()
        self.line("config firewall policy")
        for i, p in enumerate(self.cfg.policies, start=1):
            src_i = [_intf(self.cfg, z) for z in (p.src_zones or ["any"])]
            dst_i = [_intf(self.cfg, z) for z in (p.dst_zones or ["any"])]
            self.line(f"    edit {i}")
            if p.name:
                self.line(f"        set name {_q(p.name)}")
            self.line("        set srcintf "
                      + " ".join(_q(z) for z in src_i))
            self.line("        set dstintf "
                      + " ".join(_q(z) for z in dst_i))
            self.line("        set srcaddr "
                      + " ".join(_q(a) for a in (p.src_addrs or ["all"])))
            if p.src_negate:
                self.line("        set srcaddr-negate enable")
            self.line("        set dstaddr "
                      + " ".join(_q(a) for a in (p.dst_addrs or ["all"])))
            if p.dst_negate:
                self.line("        set dstaddr-negate enable")
            if p.action == "accept":
                self.line("        set action accept")
            self.line('        set schedule "always"')
            self.line("        set service "
                      + " ".join(_q(s) for s in (p.services or ["ALL"])))
            self.line("        set logtraffic "
                      + ("all" if p.log else "disable"))
            nat_hit = any(
                (sz, dz) in nat_pairs
                for sz in (p.src_zones or [])
                for dz in (p.dst_zones or [])
            )
            if p.nat or (nat_hit and p.action == "accept"):
                self.line("        set nat enable")
                applied_nat += 1
            if p.disabled:
                self.line("        set status disable")
            comment = p.comment or ""
            if p.dst_inferred:
                comment = (comment + "; " if comment else "") \
                    + "dstintf inferred from source routing"
            if comment:
                self.line(f"        set comments {_q(comment[:1023])}")
            self.line("    next")
        self.line("end")
        if nat_pairs:
            self.report.add(
                "info", "nat",
                f"interface-PAT applied: 'set nat enable' on {applied_nat} "
                f"policies matching source NAT pairs "
                f"{sorted(nat_pairs)}",
            )


def emit(cfg: FirewallConfig, report, target: str = "7.4") -> str:
    map_builtin_services(cfg, report)
    return Emitter(cfg, report, target).emit()
