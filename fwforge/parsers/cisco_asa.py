"""Cisco ASA configuration parser -> fwforge IR.

v1 scope (the constructs that carry the security policy):
  interfaces (incl. VLAN subinterfaces), name aliases, network/service
  objects, object-groups (network / service / protocol / nested),
  extended ACLs, access-group bindings, static routes, object NAT
  (static -> VIP intent, dynamic interface -> PAT intent).

Anything else is recorded in FirewallConfig.unparsed with line numbers —
nothing is dropped silently. Twice-NAT and crypto/VPN are explicitly
flagged as not-yet-converted.
"""
from __future__ import annotations

import ipaddress
import re

from ..model import (
    Address,
    AddressGroup,
    FirewallConfig,
    Interface,
    NatRule,
    Policy,
    Route,
    Service,
    ServiceGroup,
    SourceRef,
    Vip,
)

# --- Cisco literal tables (well-known names the ASA CLI accepts) -----------

PORT_NAMES = {
    "echo": 7, "discard": 9, "daytime": 13, "chargen": 19, "ftp-data": 20,
    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "time": 37,
    "nameserver": 42, "whois": 43, "tacacs": 49, "domain": 53, "bootps": 67,
    "bootpc": 68, "tftp": 69, "gopher": 70, "finger": 79, "www": 80,
    "http": 80, "hostname": 101, "pop2": 109, "pop3": 110, "sunrpc": 111,
    "ident": 113, "nntp": 119, "ntp": 123, "netbios-ns": 137,
    "netbios-dgm": 138, "netbios-ssn": 139, "imap4": 143, "snmp": 161,
    "snmptrap": 162, "xdmcp": 177, "irc": 194, "ldap": 389, "https": 443,
    "ike": 500, "isakmp": 500, "exec": 512, "biff": 512, "login": 513,
    "who": 513, "rsh": 514, "syslog": 514, "lpd": 515, "talk": 517,
    "rip": 520, "uucp": 540, "klogin": 543, "kshell": 544, "ldaps": 636,
    "kerberos": 750, "lotusnotes": 1352, "citrix-ica": 1494, "sqlnet": 1521,
    "radius": 1645, "radius-acct": 1646, "h323": 1720, "pptp": 1723,
    "mgcp": 2427, "ctiqbe": 2748, "sip": 5060, "aol": 5190,
    "pcanywhere-data": 5631, "pcanywhere-status": 5632, "vxlan": 4789,
}

ICMP_TYPE_NAMES = {
    "echo-reply": 0, "unreachable": 3, "source-quench": 4, "redirect": 5,
    "alternate-address": 6, "echo": 8, "router-advertisement": 9,
    "router-solicitation": 10, "time-exceeded": 11, "parameter-problem": 12,
    "timestamp-request": 13, "timestamp-reply": 14, "information-request": 15,
    "information-reply": 16, "mask-request": 17, "mask-reply": 18,
    "traceroute": 30,
}

PROTO_NUMBERS = {
    "icmp": 1, "igmp": 2, "ipinip": 4, "tcp": 6, "udp": 17, "gre": 47,
    "esp": 50, "ah": 51, "icmp6": 58, "eigrp": 88, "ospf": 89, "nos": 94,
    "pim": 103, "pcp": 108, "snp": 109, "sctp": 132,
}

# Lines that are pure cosmetics — the only things skipped without a report.
_COSMETIC = re.compile(r"^(!|:\s|:$|ASA Version|Cryptochecksum)")


def detect(text: str) -> float:
    score = 0.0
    if re.search(r"^ASA Version", text, re.M):
        score += 0.7
    if re.search(r"^\s*nameif\s", text, re.M):
        score += 0.2
    if re.search(r"^access-list .+ extended ", text, re.M):
        score += 0.2
    if re.search(r"^object network ", text, re.M):
        score += 0.1
    return min(score, 1.0)


class _Lines:
    """Cursor over config lines with 1-based numbering."""

    def __init__(self, text: str, filename: str):
        self.lines = text.splitlines()
        self.i = 0
        self.filename = filename

    def eof(self) -> bool:
        return self.i >= len(self.lines)

    def peek(self) -> str:
        return self.lines[self.i]

    def take(self) -> tuple[int, str]:
        line = self.lines[self.i]
        self.i += 1
        return self.i, line  # 1-based number of the taken line

    def ref(self, lineno: int, raw: str) -> SourceRef:
        return SourceRef(self.filename, lineno, raw.strip())


def _is_indented(line: str) -> bool:
    return line[:1] in (" ", "\t") and line.strip() != ""


def _mask_to_prefix(mask: str) -> int:
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


class AsaParser:
    def __init__(self, text: str, filename: str = ""):
        self.src = _Lines(text, filename)
        self.cfg = FirewallConfig(vendor="cisco-asa")
        self.name_map: dict[str, str] = {}  # `name <ip> <alias>` table
        self._addr_cache: dict[str, str] = {}  # value-key -> object name
        self._svc_cache: dict[tuple, str] = {}  # signature -> name
        self._acl_remarks: dict[str, list[str]] = {}
        self._acl_policies: dict[str, list[Policy]] = {}
        self._access_groups: list[tuple[str, str, SourceRef]] = []
        self._findings: list[tuple[str, str, str, SourceRef | None]] = []

    # -- findings -----------------------------------------------------------

    def note(self, level: str, area: str, msg: str, ref: SourceRef | None = None):
        self._findings.append((level, area, msg, ref))

    # -- shared object synthesis --------------------------------------------

    def addr_for_host(self, ip: str, ref: SourceRef) -> str:
        key = f"h:{ip}"
        if key not in self._addr_cache:
            name = f"h-{ip}"
            self.cfg.addresses.append(
                Address(name=name, type="host", value=ip, source=ref)
            )
            self._addr_cache[key] = name
        return self._addr_cache[key]

    def addr_for_subnet(self, net: str, prefix: int, ref: SourceRef) -> str:
        key = f"n:{net}/{prefix}"
        if key not in self._addr_cache:
            name = f"n-{net}_{prefix}"
            self.cfg.addresses.append(
                Address(name=name, type="subnet", value=f"{net}/{prefix}", source=ref)
            )
            self._addr_cache[key] = name
        return self._addr_cache[key]

    def svc_for(self, svc: Service) -> str:
        sig = svc.signature()
        if sig in self._svc_cache:
            return self._svc_cache[sig]
        self.cfg.services.append(svc)
        self._svc_cache[sig] = svc.name
        return svc.name

    # -- token helpers ------------------------------------------------------

    def _is_service_name(self, name: str) -> bool:
        if any(s.name == name for s in self.cfg.services):
            return True
        return any(g.name == name for g in self.cfg.svc_groups)

    def _take_svc_group(self, t: list[str]) -> str | None:
        """Consume `object[-group] <name>` if <name> is a known service
        object/group (ASA puts these in port position)."""
        if (len(t) >= 2 and t[0] in ("object", "object-group")
                and self._is_service_name(t[1])):
            t.pop(0)
            return t.pop(0)
        return None

    def _resolve_port(self, tok: str, ref: SourceRef) -> str | None:
        if tok.isdigit():
            return tok
        if tok in PORT_NAMES:
            return str(PORT_NAMES[tok])
        self.note("warn", "services", f"unknown port name '{tok}'", ref)
        return None

    def parse_port_spec(self, toks: list[str], ref: SourceRef) -> tuple[str, bool]:
        """Consume a port spec from toks. Returns (portrange, ok).
        Empty string means 'no port constraint'."""
        if not toks:
            return "", True
        op = toks[0]
        if op == "eq" and len(toks) >= 2:
            toks.pop(0)
            p = self._resolve_port(toks.pop(0), ref)
            return (p or "", p is not None)
        if op == "range" and len(toks) >= 3:
            toks.pop(0)
            a = self._resolve_port(toks.pop(0), ref)
            b = self._resolve_port(toks.pop(0), ref)
            ok = a is not None and b is not None
            return (f"{a}-{b}" if ok else "", ok)
        if op == "gt" and len(toks) >= 2:
            toks.pop(0)
            p = self._resolve_port(toks.pop(0), ref)
            if p is None:
                return "", False
            return f"{int(p) + 1}-65535", True
        if op == "lt" and len(toks) >= 2:
            toks.pop(0)
            p = self._resolve_port(toks.pop(0), ref)
            if p is None:
                return "", False
            return f"1-{int(p) - 1}", True
        if op == "neq":
            # converting 'not-equal' would silently broaden the rule
            return "", False
        return "", True  # not a port spec; leave toks untouched

    def parse_addr_spec(self, toks: list[str], ref: SourceRef) -> str | None:
        """Consume an address spec from toks; return IR object/group name,
        'all', or None when unsupported."""
        if not toks:
            return None
        tok = toks.pop(0)
        if tok in ("any", "any4"):
            return "all"
        if tok == "any6":
            self.note("warn", "policies", "IPv6 'any6' not converted", ref)
            return None
        if tok == "host":
            ip = toks.pop(0)
            ip = self.name_map.get(ip, ip)
            return self.addr_for_host(ip, ref)
        if tok in ("object", "object-group"):
            return toks.pop(0)
        if tok == "interface":
            ifc = toks.pop(0)
            self.note(
                "warn", "policies",
                f"'interface {ifc}' address token approximated as 'all'", ref,
            )
            return "all"
        # bare `<net> <mask>` or a `name` alias or bare host IP
        cand = self.name_map.get(tok, tok)
        try:
            ipaddress.IPv4Address(cand)
        except ValueError:
            self.note("warn", "policies", f"unrecognized address token '{tok}'", ref)
            return None
        if toks:
            try:
                prefix = _mask_to_prefix(toks[0])
            except ValueError:
                prefix = None
            if prefix is not None:
                toks.pop(0)
                if prefix == 32:
                    return self.addr_for_host(cand, ref)
                net = ipaddress.IPv4Network(f"{cand}/{prefix}", strict=False)
                return self.addr_for_subnet(str(net.network_address), prefix, ref)
        return self.addr_for_host(cand, ref)

    # -- section parsers ----------------------------------------------------

    def parse(self) -> FirewallConfig:
        while not self.src.eof():
            lineno, line = self.src.take()
            stripped = line.strip()
            if not stripped or _COSMETIC.match(stripped):
                if stripped.startswith("ASA Version"):
                    self.cfg.version = stripped.replace("ASA Version", "").strip()
                continue
            if _is_indented(line):
                # an orphaned sub-line (parent unhandled) — record it
                self.cfg.unparsed.append(self.src.ref(lineno, line))
                continue

            toks = stripped.split()
            head = toks[0]
            ref = self.src.ref(lineno, stripped)

            if head == "hostname" and len(toks) > 1:
                self.cfg.hostname = toks[1]
            elif head == "name" and len(toks) >= 3:
                self.name_map[toks[2]] = toks[1]
            elif head == "interface":
                self.parse_interface(stripped, lineno)
            elif stripped.startswith("object network "):
                self.parse_object_network(toks[2], lineno)
            elif stripped.startswith("object service "):
                self.parse_object_service(toks[2], lineno)
            elif stripped.startswith("object-group "):
                self.parse_object_group(toks, lineno, stripped)
            elif head == "access-list":
                self.parse_access_list(toks, ref)
            elif head == "access-group":
                self.parse_access_group(toks, ref)
            elif head == "route" and len(toks) >= 5:
                self.parse_route(toks, ref)
            elif stripped.startswith("nat ("):
                self.note(
                    "error", "nat",
                    "twice-NAT (section 1/3) rule not converted — manual review",
                    ref,
                )
                self.cfg.unparsed.append(ref)
            elif head in ("crypto", "tunnel-group", "group-policy"):
                self._swallow_block(lineno, line)
                self.note(
                    "warn", "vpn",
                    f"VPN-related '{stripped[:40]}…' not converted in v1", ref,
                )
            else:
                self.cfg.unparsed.append(ref)
                self._swallow_block(lineno, line, record=True)

        self.finish_acls()
        self.cfg.meta["findings"] = self._findings
        return self.cfg

    def _swallow_block(self, lineno: int, first: str, record: bool = False):
        """Consume indented continuation lines of an unhandled block."""
        while not self.src.eof() and _is_indented(self.src.peek()):
            ln, raw = self.src.take()
            if record:
                self.cfg.unparsed.append(self.src.ref(ln, raw))

    def parse_interface(self, header: str, lineno: int):
        name = header.split(None, 1)[1]
        itf = Interface(name=name, source=self.src.ref(lineno, header))
        nameif = None
        m = re.match(r"^(.*)\.(\d+)$", name)
        if m:
            itf.parent, itf.vlan_id = m.group(1), int(m.group(2))
        while not self.src.eof() and _is_indented(self.src.peek()):
            ln, raw = self.src.take()
            t = raw.strip().split()
            if not t:
                continue
            if t[0] == "nameif" and len(t) > 1:
                nameif = t[1]
            elif t[0] == "shutdown":
                itf.enabled = False
            elif t[0] == "description":
                itf.description = raw.strip().split(None, 1)[1]
            elif t[0] == "vlan" and len(t) > 1 and t[1].isdigit():
                itf.vlan_id = int(t[1])
            elif t[:2] == ["ip", "address"] and len(t) >= 4:
                try:
                    prefix = _mask_to_prefix(t[3])
                    itf.ip = f"{t[2]}/{prefix}"
                except ValueError:
                    self.note("warn", "interfaces",
                              f"bad ip address line: {raw.strip()}",
                              self.src.ref(ln, raw))
            elif t[0] in ("security-level", "management-only", "no", "speed",
                          "duplex"):
                pass  # no FortiOS equivalent needed / cosmetic
            else:
                self.cfg.unparsed.append(self.src.ref(ln, raw))
        if nameif:
            itf.name = nameif
            itf.source.raw += f" (nameif {nameif})"
            self.cfg.interfaces.append(itf)
        else:
            self.note("info", "interfaces",
                      f"interface {name} has no nameif — skipped",
                      itf.source)

    def parse_object_network(self, name: str, lineno: int):
        ref = self.src.ref(lineno, f"object network {name}")
        addr = Address(name=name, source=ref)
        created = False
        nat_lines: list[tuple[str, SourceRef]] = []
        while not self.src.eof() and _is_indented(self.src.peek()):
            ln, raw = self.src.take()
            t = raw.strip().split()
            sref = self.src.ref(ln, raw)
            if not t:
                continue
            if t[0] == "host" and len(t) > 1:
                addr.type, addr.value, created = "host", self.name_map.get(t[1], t[1]), True
            elif t[0] == "subnet" and len(t) > 2:
                try:
                    prefix = _mask_to_prefix(t[2])
                    addr.type, addr.value = "subnet", f"{t[1]}/{prefix}"
                    created = True
                except ValueError:
                    self.note("warn", "addresses", f"bad subnet: {raw.strip()}", sref)
            elif t[0] == "range" and len(t) > 2:
                addr.type, addr.value, created = "range", f"{t[1]}-{t[2]}", True
            elif t[0] == "fqdn":
                addr.type, addr.value, created = "fqdn", t[-1], True
            elif t[0] == "description":
                addr.comment = raw.strip().split(None, 1)[1]
            elif t[0] == "nat":
                nat_lines.append((raw.strip(), sref))
            else:
                self.cfg.unparsed.append(sref)
        if created:
            # same object may be re-opened later (e.g. to attach NAT) —
            # replace any earlier definition instead of duplicating
            existing = self.cfg.address_by_name(name)
            if existing:
                self.cfg.addresses.remove(existing)
            self.cfg.addresses.append(addr)
        # NAT lines reference the object's own address — resolve them only
        # after the object is registered
        for nat_raw, nat_ref in nat_lines:
            self.parse_object_nat(name, nat_raw, nat_ref)

    def parse_object_nat(self, obj_name: str, line: str, ref: SourceRef):
        m = re.match(r"nat \(([^,]+),([^)]+)\)\s+(static|dynamic)\s+(.*)", line)
        if not m:
            self.note("error", "nat", f"unparsed object NAT: {line}", ref)
            return
        real_ifc, mapped_ifc, kind, rest = (
            m.group(1).strip(), m.group(2).strip(), m.group(3), m.group(4).strip(),
        )
        rest_toks = rest.split()
        if kind == "dynamic":
            if rest_toks and rest_toks[0] == "interface":
                self.cfg.nats.append(NatRule(
                    kind="dynamic-interface", real_obj=obj_name,
                    real_ifc=real_ifc, mapped_ifc=mapped_ifc, source=ref,
                ))
            else:
                self.note("warn", "nat",
                          f"dynamic NAT to pool '{rest}' not converted (v1 "
                          "handles interface PAT only)", ref)
        else:  # static
            mapped = rest_toks[0] if rest_toks else ""
            vip = Vip(
                name=f"vip-{obj_name}", ext_ip=self.name_map.get(mapped, mapped),
                ext_intf=mapped_ifc, comment=f"from object NAT on {obj_name}",
                source=ref,
            )
            obj = self.cfg.address_by_name(obj_name)
            if obj and obj.type == "host":
                vip.mapped_ip = obj.value
            else:
                vip.mapped_ip = f"<{obj_name}>"
                self.note("warn", "nat",
                          f"static NAT for non-host object '{obj_name}' — "
                          "set mappedip manually", ref)
            if "service" in rest_toks:
                i = rest_toks.index("service")
                try:
                    vip.protocol, vip.mapped_port, vip.ext_port = (
                        rest_toks[i + 1],
                        str(PORT_NAMES.get(rest_toks[i + 2], rest_toks[i + 2])),
                        str(PORT_NAMES.get(rest_toks[i + 3], rest_toks[i + 3])),
                    )
                except IndexError:
                    self.note("warn", "nat", f"bad static NAT service spec: {line}", ref)
            self.cfg.vips.append(vip)

    def parse_object_service(self, name: str, lineno: int):
        ref = self.src.ref(lineno, f"object service {name}")
        svc = Service(name=name, source=ref)
        seen = False
        while not self.src.eof() and _is_indented(self.src.peek()):
            ln, raw = self.src.take()
            t = raw.strip().split()
            sref = self.src.ref(ln, raw)
            if not t:
                continue
            if t[0] == "service":
                t = t[1:]
                proto = t.pop(0) if t else ""
                if proto not in ("tcp", "udp", "icmp"):
                    if proto in PROTO_NUMBERS:
                        svc.protocol, svc.proto_number = "ip", PROTO_NUMBERS[proto]
                        seen = True
                        continue
                    self.note("warn", "services",
                              f"object service {name}: protocol '{proto}' skipped", sref)
                    continue
                svc.protocol = proto
                seen = True
                while t:
                    if t[0] == "source":
                        t.pop(0)
                        ports, ok = self.parse_port_spec(t, sref)
                        if ok:
                            svc.src_ports = ports
                    elif t[0] == "destination":
                        t.pop(0)
                        ports, ok = self.parse_port_spec(t, sref)
                        if ok:
                            svc.dst_ports = ports
                    elif proto == "icmp" and t[0] in ICMP_TYPE_NAMES:
                        svc.icmp_type = ICMP_TYPE_NAMES[t.pop(0)]
                    else:
                        t.pop(0)
            elif t[0] == "description":
                svc.comment = raw.strip().split(None, 1)[1]
            else:
                self.cfg.unparsed.append(sref)
        if seen:
            self.cfg.services.append(svc)
            self._svc_cache[svc.signature()] = svc.name

    def parse_object_group(self, toks: list[str], lineno: int, header: str):
        ref = self.src.ref(lineno, header)
        gtype = toks[1]
        name = toks[2] if len(toks) > 2 else ""
        if gtype == "network":
            grp = AddressGroup(name=name, source=ref)
            while not self.src.eof() and _is_indented(self.src.peek()):
                ln, raw = self.src.take()
                t = raw.strip().split()
                sref = self.src.ref(ln, raw)
                if not t:
                    continue
                if t[0] == "network-object":
                    member = self.parse_addr_spec(t[1:], sref)
                    if member and member != "all":
                        grp.members.append(member)
                    elif member == "all":
                        self.note("warn", "addresses",
                                  f"group {name}: 'any' member dropped", sref)
                elif t[0] == "group-object" and len(t) > 1:
                    grp.members.append(t[1])
                elif t[0] == "description":
                    grp.comment = raw.strip().split(None, 1)[1]
                else:
                    self.cfg.unparsed.append(sref)
            self.cfg.addr_groups.append(grp)
        elif gtype == "service":
            self.parse_service_group(name, toks, ref)
        elif gtype == "protocol":
            protos: list[str] = []
            while not self.src.eof() and _is_indented(self.src.peek()):
                ln, raw = self.src.take()
                t = raw.strip().split()
                if t and t[0] == "protocol-object" and len(t) > 1:
                    protos.append(t[1])
            self.cfg.meta.setdefault("protocol_groups", {})[name] = protos
        elif gtype == "icmp-type":
            grp = ServiceGroup(name=name, source=ref)
            while not self.src.eof() and _is_indented(self.src.peek()):
                ln, raw = self.src.take()
                t = raw.strip().split()
                sref = self.src.ref(ln, raw)
                if t and t[0] == "icmp-object" and len(t) > 1:
                    itype = ICMP_TYPE_NAMES.get(t[1])
                    if itype is None and t[1].isdigit():
                        itype = int(t[1])
                    svc = Service(name=f"icmp_{t[1]}", protocol="icmp",
                                  icmp_type=itype, source=sref)
                    grp.members.append(self.svc_for(svc))
            self.cfg.svc_groups.append(grp)
        else:
            self.cfg.unparsed.append(ref)
            self._swallow_block(lineno, header, record=True)

    def parse_service_group(self, name: str, toks: list[str], ref: SourceRef):
        grp = ServiceGroup(name=name, source=ref)
        # legacy form: `object-group service NAME tcp|udp|tcp-udp`
        legacy_proto = toks[3] if len(toks) > 3 else None
        while not self.src.eof() and _is_indented(self.src.peek()):
            ln, raw = self.src.take()
            t = raw.strip().split()
            sref = self.src.ref(ln, raw)
            if not t:
                continue
            if t[0] == "port-object" and legacy_proto:
                proto = "tcp/udp" if legacy_proto == "tcp-udp" else legacy_proto
                ports, ok = self.parse_port_spec(t[1:], sref)
                if ok and ports:
                    svc = Service(name=f"{proto.replace('/', '')}_{ports}",
                                  protocol=proto, dst_ports=ports, source=sref)
                    grp.members.append(self.svc_for(svc))
                else:
                    self.note("warn", "services",
                              f"group {name}: port-object skipped: {raw.strip()}", sref)
            elif t[0] == "service-object":
                t = t[1:]
                if not t:
                    continue
                if t[0] == "object" and len(t) > 1:
                    grp.members.append(t[1])
                    continue
                proto = t.pop(0)
                if proto in ("tcp", "udp", "tcp-udp"):
                    proto_ir = "tcp/udp" if proto == "tcp-udp" else proto
                    dst = src = ""
                    while t:
                        if t[0] == "destination":
                            t.pop(0)
                            dst, _ = self.parse_port_spec(t, sref)
                        elif t[0] == "source":
                            t.pop(0)
                            src, _ = self.parse_port_spec(t, sref)
                        else:
                            # bare `eq 80` shorthand = destination
                            d, ok = self.parse_port_spec(t, sref)
                            if ok and d:
                                dst = d
                            else:
                                t.pop(0) if t else None
                    svc = Service(
                        name=f"{proto_ir.replace('/', '')}_{dst or 'any'}",
                        protocol=proto_ir, dst_ports=dst, src_ports=src, source=sref,
                    )
                    grp.members.append(self.svc_for(svc))
                elif proto == "icmp":
                    itype = None
                    if t and (t[0] in ICMP_TYPE_NAMES or t[0].isdigit()):
                        itype = ICMP_TYPE_NAMES.get(t[0], None)
                        if itype is None:
                            itype = int(t[0])
                    svc = Service(name=f"icmp_{t[0] if t else 'any'}",
                                  protocol="icmp", icmp_type=itype, source=sref)
                    grp.members.append(self.svc_for(svc))
                elif proto in PROTO_NUMBERS or proto == "ip":
                    num = None if proto == "ip" else PROTO_NUMBERS[proto]
                    svc = Service(name=f"proto_{proto}", protocol="ip",
                                  proto_number=num, source=sref)
                    grp.members.append(self.svc_for(svc))
                else:
                    self.note("warn", "services",
                              f"group {name}: protocol '{proto}' skipped", sref)
            elif t[0] == "group-object" and len(t) > 1:
                grp.members.append(t[1])
            elif t[0] == "description":
                grp.comment = raw.strip().split(None, 1)[1]
            else:
                self.cfg.unparsed.append(sref)
        self.cfg.svc_groups.append(grp)

    # -- ACLs ----------------------------------------------------------------

    def parse_access_list(self, toks: list[str], ref: SourceRef):
        acl = toks[1]
        if len(toks) >= 3 and toks[2] == "remark":
            self._acl_remarks.setdefault(acl, []).append(" ".join(toks[3:]))
            return
        if len(toks) < 4 or toks[2] != "extended":
            self.note("info", "policies",
                      f"non-extended ACL line skipped: {ref.raw[:60]}", ref)
            self.cfg.unparsed.append(ref)
            return

        t = toks[3:]
        action = t.pop(0)
        if action not in ("permit", "deny"):
            self.cfg.unparsed.append(ref)
            return

        # protocol position: literal | object | object-group
        protos: list[tuple[str, int | None]] = []
        svc_ref: str | None = None
        ptok = t.pop(0)
        if ptok == "object" or ptok == "object-group":
            target = t.pop(0)
            pg = self.cfg.meta.get("protocol_groups", {})
            if ptok == "object-group" and target in pg:
                for p in pg[target]:
                    protos.append((p, PROTO_NUMBERS.get(p)))
            else:
                svc_ref = target  # service object/group carries proto+ports
                protos.append(("ip", None))
        else:
            protos.append((ptok, PROTO_NUMBERS.get(ptok)))

        src = self.parse_addr_spec(t, ref)
        src_ports, sp_ok = ("", True)
        # ASA allows a *service* object-group in port position; the only way
        # to distinguish it from a destination network group is the registry
        svc_grp_ref = self._take_svc_group(t)
        if not svc_grp_ref and t and t[0] in ("eq", "range", "gt", "lt", "neq"):
            src_ports, sp_ok = self.parse_port_spec(t, ref)
        dst = self.parse_addr_spec(t, ref)
        dst_ports, dp_ok = ("", True)
        icmp_type: int | None = None
        if not svc_grp_ref:
            svc_grp_ref = self._take_svc_group(t)
        if t and t[0] in ("eq", "range", "gt", "lt", "neq"):
            dst_ports, dp_ok = self.parse_port_spec(t, ref)
        elif t and protos[0][0] == "icmp" and t[0] in ICMP_TYPE_NAMES:
            icmp_type = ICMP_TYPE_NAMES[t.pop(0)]
        if svc_grp_ref:
            svc_ref = svc_ref or svc_grp_ref

        disabled = False
        log = False
        comment_bits: list[str] = []
        while t:
            tok = t.pop(0)
            if tok == "log":
                log = True
                while t and (t[0].isdigit() or t[0] in ("interval", "disable",
                                                        "default")):
                    t.pop(0)
            elif tok == "inactive":
                disabled = True
            elif tok == "time-range" and t:
                tr = t.pop(0)
                self.note("warn", "policies",
                          f"time-range '{tr}' not converted — policy emitted "
                          "without schedule restriction", ref)
                comment_bits.append(f"time-range {tr}")
            else:
                comment_bits.append(tok)

        if src is None or dst is None:
            self.note("error", "policies",
                      f"ACE skipped (unsupported address token): {ref.raw[:80]}", ref)
            self.cfg.unparsed.append(ref)
            return

        review = not (sp_ok and dp_ok)
        services = self._services_for_ace(
            protos, svc_ref, src_ports, dst_ports, icmp_type, ref
        )

        pol = Policy(
            src_addrs=[src], dst_addrs=[dst], services=services,
            action="accept" if action == "permit" else "deny",
            log=log or action == "deny", disabled=disabled or review,
            source=ref,
        )
        remarks = self._acl_remarks.pop(acl, [])
        bits = remarks + comment_bits
        if review:
            bits.append("REVIEW: port operator (neq/named) not convertible — "
                        "policy disabled")
            self.note("error", "policies",
                      f"ACE has non-convertible port spec; emitted disabled: "
                      f"{ref.raw[:80]}", ref)
        if bits:
            pol.comment = "; ".join(bits)[:1023]
        self._acl_policies.setdefault(acl, []).append(pol)

    def _services_for_ace(self, protos, svc_ref, src_ports, dst_ports,
                          icmp_type, ref) -> list[str]:
        if svc_ref:
            return [svc_ref]
        # merge tcp+udp same ports into one service
        names = {p for p, _ in protos}
        if names == {"ip"} and not dst_ports and not src_ports:
            return ["ALL"]
        if {"tcp", "udp"} <= names and dst_ports:
            svc = Service(name=f"tcpudp_{dst_ports}", protocol="tcp/udp",
                          dst_ports=dst_ports, src_ports=src_ports, source=ref)
            out = [self.svc_for(svc)]
            rest = [(p, n) for p, n in protos if p not in ("tcp", "udp")]
            if rest:
                out += self._services_for_ace(rest, None, src_ports, "",
                                              None, ref)
            return out
        out: list[str] = []
        for proto, num in protos:
            if proto in ("tcp", "udp"):
                base = f"{proto}_{dst_ports or 'any'}"
                if src_ports:
                    base += f"_s{src_ports}"
                svc = Service(name=base, protocol=proto, dst_ports=dst_ports,
                              src_ports=src_ports, source=ref)
                out.append(self.svc_for(svc))
            elif proto == "icmp":
                nm = f"icmp_{icmp_type}" if icmp_type is not None else "ALL_ICMP"
                if nm == "ALL_ICMP":
                    out.append("ALL_ICMP")
                else:
                    svc = Service(name=nm, protocol="icmp",
                                  icmp_type=icmp_type, source=ref)
                    out.append(self.svc_for(svc))
            elif proto == "ip":
                out.append("ALL")
            else:
                num = num if num is not None else PROTO_NUMBERS.get(proto)
                if num is None:
                    self.note("warn", "services",
                              f"unknown protocol '{proto}' — using ALL", ref)
                    out.append("ALL")
                else:
                    svc = Service(name=f"proto_{proto}", protocol="ip",
                                  proto_number=num, source=ref)
                    out.append(self.svc_for(svc))
        return out

    def parse_access_group(self, toks: list[str], ref: SourceRef):
        # access-group NAME in interface IFC
        if len(toks) >= 5 and toks[2] == "in" and toks[3] == "interface":
            self._access_groups.append((toks[1], toks[4], ref))
        elif len(toks) >= 3 and toks[2] == "global":
            self._access_groups.append((toks[1], "any", ref))
            self.note("info", "policies",
                      f"global access-group '{toks[1]}' mapped with srcintf any", ref)
        else:
            self.cfg.unparsed.append(ref)

    def finish_acls(self):
        bound: set[str] = set()
        for acl, ifc, _ref in self._access_groups:
            bound.add(acl)
            for n, pol in enumerate(self._acl_policies.get(acl, []), start=1):
                pol.name = f"{acl}-{n}"
                pol.src_zones = [ifc]
                self.cfg.policies.append(pol)
        for acl, pols in self._acl_policies.items():
            if acl not in bound:
                self.note("info", "policies",
                          f"ACL '{acl}' ({len(pols)} ACEs) is not bound to any "
                          "interface via access-group — not converted "
                          "(may be VPN interesting-traffic or unused)", None)

    def parse_route(self, toks: list[str], ref: SourceRef):
        try:
            ifc, dest_ip, mask, gw = toks[1], toks[2], toks[3], toks[4]
            prefix = _mask_to_prefix(mask)
            dist = int(toks[5]) if len(toks) > 5 and toks[5].isdigit() else 10
            net = ipaddress.IPv4Network(f"{dest_ip}/{prefix}", strict=False)
            self.cfg.routes.append(Route(
                dest=str(net), gateway=gw, interface=ifc, distance=dist,
                source=ref,
            ))
        except (ValueError, IndexError):
            self.note("warn", "routes", f"unparsed route: {ref.raw}", ref)
            self.cfg.unparsed.append(ref)


def parse(text: str, filename: str = "") -> FirewallConfig:
    return AsaParser(text, filename).parse()
