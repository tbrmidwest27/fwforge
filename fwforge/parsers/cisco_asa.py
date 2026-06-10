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
    VpnPhase1,
    VpnPhase2,
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

# ASA crypto algorithm tokens -> FortiOS names
VPN_ENC = {
    "des": "des", "3des": "3des", "aes": "aes128", "aes-128": "aes128",
    "aes-192": "aes192", "aes-256": "aes256", "aes-gcm": "aes128gcm",
    "aes-gcm-128": "aes128gcm", "aes-gcm-192": "aes192gcm",
    "aes-gcm-256": "aes256gcm", "null": "null",
}
VPN_HASH = {
    "md5": "md5", "sha": "sha1", "sha-1": "sha1", "sha1": "sha1",
    "sha-256": "sha256", "sha256": "sha256", "sha-384": "sha384",
    "sha384": "sha384", "sha-512": "sha512", "sha512": "sha512",
}
# esp- transform tokens (ikev1 transform-sets)
ESP_ENC = {f"esp-{k}": v for k, v in VPN_ENC.items()}
ESP_HASH = {
    "esp-md5-hmac": "md5", "esp-sha-hmac": "sha1",
    "esp-sha-1-hmac": "sha1", "esp-sha-256-hmac": "sha256",
    "esp-sha-384-hmac": "sha384", "esp-sha-512-hmac": "sha512",
    "esp-none": "null",
}


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
        # --- VPN collection (assembled in finish_vpn) ---
        self._ike_policies: dict[int, list[dict]] = {1: [], 2: []}
        self._transform_sets: dict[str, list[str]] = {}  # ikev1
        self._ipsec_proposals: dict[str, list[str]] = {}  # ikev2
        self._crypto_maps: dict[tuple[str, int], dict] = {}
        self._map_bindings: list[tuple[str, str, SourceRef]] = []
        self._tunnel_groups: dict[str, dict] = {}
        self._vpn_consumed_acls: set[str] = set()

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
                    "twice-NAT (section 1/3) rule not converted — manual "
                    "review. If this is a VPN NAT-exemption (identity) "
                    "rule, it is unnecessary on FortiOS route-based VPNs",
                    ref,
                )
                self.cfg.unparsed.append(ref)
            elif head == "crypto":
                self.parse_crypto(toks, lineno, stripped, ref)
            elif head == "tunnel-group":
                self.parse_tunnel_group(toks, lineno, stripped, ref)
            elif head == "group-policy":
                self._swallow_block(lineno, line)
                self.note("info", "vpn",
                          f"group-policy '{toks[1] if len(toks) > 1 else ''}'"
                          " skipped (remote-access attribute container)", ref)
            else:
                self.cfg.unparsed.append(ref)
                self._swallow_block(lineno, line, record=True)

        self.finish_vpn()
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

    # -- VPN -----------------------------------------------------------------

    def parse_crypto(self, toks: list[str], lineno: int, stripped: str,
                     ref: SourceRef):
        t = toks[1:]
        if not t:
            return
        kind = t[0]

        if kind in ("ikev1", "ikev2") and len(t) >= 2:
            ver = 1 if kind == "ikev1" else 2
            if t[1] == "enable" and len(t) >= 3:
                self.cfg.meta.setdefault("ike_enabled", []).append(
                    (ver, t[2]))
                return
            if t[1] == "policy" and len(t) >= 3:
                self._parse_ike_policy(ver, t[2], lineno)
                return
            self.cfg.unparsed.append(ref)
            return

        if kind == "ipsec" and len(t) >= 2:
            if t[1] == "ikev1" and len(t) >= 4 and t[2] == "transform-set":
                self._parse_transform_set(t[3], t[4:], ref)
                return
            if t[1] == "ikev2" and len(t) >= 4 and t[2] == "ipsec-proposal":
                self._parse_ipsec_proposal(t[3], lineno)
                return
            self.cfg.unparsed.append(ref)
            return

        if kind == "map" and len(t) >= 3:
            name = t[1]
            if t[2] == "interface" and len(t) >= 4:
                self._map_bindings.append((name, t[3], ref))
                return
            if t[2].isdigit():
                seq = int(t[2])
                entry = self._crypto_maps.setdefault(
                    (name, seq),
                    {"acl": "", "peers": [], "ts": [], "props": [],
                     "pfs": "", "salife": 0, "ref": ref})
                rest = t[3:]
                if rest[:2] == ["match", "address"] and len(rest) >= 3:
                    entry["acl"] = rest[2]
                elif rest[:1] == ["ipsec-isakmp"] and "dynamic" in rest:
                    self.note("warn", "vpn",
                              f"crypto map {name} {seq} references a "
                              "dynamic map (dial-up) — convert to a "
                              "FortiOS dial-up phase1 manually", ref)
                elif rest[:1] == ["set"] and len(rest) >= 2:
                    sub = rest[1]
                    if sub == "peer":
                        entry["peers"] += rest[2:]
                    elif sub == "ikev1" and len(rest) >= 4 \
                            and rest[2] == "transform-set":
                        entry["ts"] += rest[3:]
                    elif sub == "ikev2" and len(rest) >= 4 \
                            and rest[2] == "ipsec-proposal":
                        entry["props"] += rest[3:]
                    elif sub == "pfs":
                        grp = rest[2] if len(rest) >= 3 else "group2"
                        entry["pfs"] = grp.replace("group", "")
                    elif sub == "security-association" and len(rest) >= 5 \
                            and rest[2] == "lifetime" \
                            and rest[3] == "seconds":
                        entry["salife"] = int(rest[4])
                    elif sub == "trustpoint":
                        self.note("warn", "vpn",
                                  f"crypto map {name} {seq} uses "
                                  "certificate auth (trustpoint) — import "
                                  "certs and set authmethod signature "
                                  "manually", ref)
                    elif sub == "phase1-mode" and "aggressive" in rest:
                        self.note("warn", "vpn",
                                  f"crypto map {name} {seq} uses aggressive "
                                  "mode — set 'set mode aggressive' on the "
                                  "phase1 if the peer requires it", ref)
                    # nat-t / reverse-route / connection-type: defaults fine
                return
            self.cfg.unparsed.append(ref)
            return

        if kind == "dynamic-map":
            self.note("warn", "vpn",
                      "crypto dynamic-map present — dial-up/remote-access "
                      "IPsec is not auto-converted", ref)
            self._swallow_block(lineno, stripped)
            return
        if kind == "ca":
            self.note("warn", "vpn",
                      "certificate (crypto ca) configuration is not "
                      "converted — re-import certificates on the FortiGate",
                      ref)
            self._swallow_block(lineno, stripped)
            return
        self.cfg.unparsed.append(ref)

    def _parse_ike_policy(self, ver: int, seq: str, lineno: int):
        pol = {"seq": int(seq) if seq.isdigit() else 999,
               "enc": [], "hash": [], "dh": [], "prf": [], "life": 0}
        while not self.src.eof() and _is_indented(self.src.peek()):
            ln, raw = self.src.take()
            t = raw.strip().split()
            if not t:
                continue
            if t[0] == "encryption":
                pol["enc"] += [VPN_ENC[x] for x in t[1:] if x in VPN_ENC]
            elif t[0] in ("hash", "integrity"):
                pol["hash"] += [VPN_HASH[x] for x in t[1:] if x in VPN_HASH]
            elif t[0] == "group":
                pol["dh"] += [x for x in t[1:] if x.isdigit()]
            elif t[0] == "prf":
                pol["prf"] += [VPN_HASH[x] for x in t[1:] if x in VPN_HASH]
            elif t[0] == "lifetime":
                nums = [x for x in t[1:] if x.isdigit()]
                if nums:
                    pol["life"] = int(nums[0])
            elif t[0] == "authentication" and "pre-share" not in t:
                self.note("warn", "vpn",
                          f"ikev{ver} policy {seq}: non-PSK authentication "
                          f"({' '.join(t[1:])}) — certificates must be "
                          "handled manually", self.src.ref(ln, raw))
        self._ike_policies[ver].append(pol)

    @staticmethod
    def _esp_combos(encs: list[str], hashes: list[str]) -> list[str]:
        out: list[str] = []
        for e in encs:
            if e.endswith("gcm"):
                out.append(e)  # GCM is AEAD: no auth suffix in FortiOS
            else:
                for h in (hashes or ["sha1"]):
                    out.append(f"{e}-{h}")
        seen: set[str] = set()
        return [p for p in out if not (p in seen or seen.add(p))]

    def _parse_transform_set(self, name: str, toks: list[str],
                             ref: SourceRef):
        encs = [ESP_ENC[t] for t in toks if t in ESP_ENC]
        hashes = [ESP_HASH[t] for t in toks if t in ESP_HASH]
        if "mode" in toks and "transport" in toks:
            self.note("warn", "vpn",
                      f"transform-set {name} uses transport mode — FortiOS "
                      "phase2 here is tunnel mode; review (GRE-over-IPsec?)",
                      ref)
        if not encs:
            self.note("warn", "vpn",
                      f"transform-set {name}: no recognizable ESP "
                      "encryption — skipped", ref)
            return
        self._transform_sets[name] = self._esp_combos(encs, hashes)

    def _parse_ipsec_proposal(self, name: str, lineno: int):
        encs: list[str] = []
        hashes: list[str] = []
        while not self.src.eof() and _is_indented(self.src.peek()):
            ln, raw = self.src.take()
            t = raw.strip().split()
            if t[:3] == ["protocol", "esp", "encryption"]:
                encs += [VPN_ENC[x] for x in t[3:] if x in VPN_ENC]
            elif t[:3] == ["protocol", "esp", "integrity"]:
                hashes += [VPN_HASH[x] for x in t[3:] if x in VPN_HASH]
        if encs:
            self._ipsec_proposals[name] = self._esp_combos(encs, hashes)

    def parse_tunnel_group(self, toks: list[str], lineno: int,
                           stripped: str, ref: SourceRef):
        if len(toks) < 3:
            self.cfg.unparsed.append(ref)
            return
        peer = toks[1]
        if toks[2] == "type":
            ttype = toks[3] if len(toks) > 3 else ""
            if ttype == "ipsec-l2l":
                self._tunnel_groups.setdefault(peer, {})
            else:
                self.note("info", "vpn",
                          f"tunnel-group '{peer}' type {ttype} skipped "
                          "(remote-access — not auto-converted)", ref)
                self._tunnel_groups.setdefault(peer, {})["skip"] = True
            return
        if toks[2] == "ipsec-attributes":
            tg = self._tunnel_groups.setdefault(peer, {})
            while not self.src.eof() and _is_indented(self.src.peek()):
                ln, raw = self.src.take()
                t = raw.strip().split()
                if t[:2] == ["ikev1", "pre-shared-key"] and len(t) >= 3:
                    tg["psk1"] = t[2]
                elif t[:3] == ["ikev2", "local-authentication",
                               "pre-shared-key"] and len(t) >= 4:
                    tg["psk2_local"] = t[3]
                elif t[:3] == ["ikev2", "remote-authentication",
                               "pre-shared-key"] and len(t) >= 4:
                    tg["psk2_remote"] = t[3]
            return
        # general-attributes / webvpn-attributes etc: irrelevant for L2L
        self._swallow_block(lineno, stripped)

    def _psk(self, value: str | None, peer: str, what: str,
             ref: SourceRef) -> str:
        if not value:
            self.note("error", "vpn",
                      f"peer {peer}: no {what} pre-shared key found in any "
                      "tunnel-group — placeholder emitted, set the real key",
                      ref)
            return "CHANGEME-PSK"
        if set(value) == {"*"}:
            self.note("error", "vpn",
                      f"peer {peer}: {what} pre-shared key is masked "
                      "('*****') in this export — re-export with "
                      "'more system:running-config' or re-enter the key",
                      ref)
            return "CHANGEME-PSK"
        return value

    def _ike_proposals(self, ver: int) -> tuple[list[str], list[str], int]:
        props: list[str] = []
        dh: list[str] = []
        life = 0
        for pol in sorted(self._ike_policies[ver], key=lambda d: d["seq"]):
            for e in pol["enc"]:
                if e.endswith("gcm"):
                    prf = (pol["prf"] or ["sha1"])[0]
                    props.append(f"{e}-prf{prf}")
                else:
                    for h in (pol["hash"] or ["sha1"]):
                        props.append(f"{e}-{h}")
            dh += pol["dh"]
            if not life and pol["life"]:
                life = pol["life"]
        seen: set[str] = set()
        props = [p for p in props if not (p in seen or seen.add(p))]
        seen = set()
        dh = [d for d in dh if not (d in seen or seen.add(d))]
        return props[:8], dh, life

    def _cidr_for(self, name: str, ref: SourceRef) -> str | None:
        if name == "all":
            return "0.0.0.0/0"
        addr = self.cfg.address_by_name(name)
        if addr is None:
            self.note("warn", "vpn",
                      f"VPN selector references group/unknown object "
                      f"'{name}' — expand to host/subnet objects manually",
                      ref)
            return None
        if addr.type == "host":
            return f"{addr.value}/32"
        if addr.type == "subnet":
            return addr.value
        self.note("warn", "vpn",
                  f"VPN selector object '{name}' is {addr.type} — only "
                  "host/subnet selectors convert", ref)
        return None

    def finish_vpn(self):
        have_material = (self._crypto_maps or self._transform_sets
                         or self._ipsec_proposals
                         or self._ike_policies[1] or self._ike_policies[2])
        if not self._map_bindings:
            if have_material:
                self.note("info", "vpn",
                          "IKE/IPsec material present but no crypto map is "
                          "bound to an interface — no tunnels converted")
            return

        from ..transforms.routes import RouteTable
        table = RouteTable(self.cfg)  # before VPN routes are added
        taken: set[str] = set()
        route_seen: set[tuple[str, str]] = set()

        for map_name, bind_ifc, bref in self._map_bindings:
            entries = sorted(
                (k[1], v) for k, v in self._crypto_maps.items()
                if k[0] == map_name)
            for seq, e in entries:
                ref = e["ref"]
                if not e["peers"] or not e["acl"]:
                    self.note("warn", "vpn",
                              f"crypto map {map_name} {seq} incomplete "
                              "(missing peer or match address) — skipped",
                              ref)
                    continue
                peer = e["peers"][0]
                if len(e["peers"]) > 1:
                    self.note("warn", "vpn",
                              f"crypto map {map_name} {seq}: backup peers "
                              f"{', '.join(e['peers'][1:])} not converted — "
                              "consider a second phase1 or SD-WAN overlay",
                              ref)
                ver = 2 if e["props"] else 1
                if e["props"] and e["ts"]:
                    self.note("info", "vpn",
                              f"crypto map {map_name} {seq} allows IKEv1 "
                              "and IKEv2 — converted as IKEv2", ref)

                # phase2 proposals from the named sets
                p2_props: list[str] = []
                names = e["props"] if ver == 2 else e["ts"]
                table_src = self._ipsec_proposals if ver == 2 \
                    else self._transform_sets
                for n in names:
                    p2_props += table_src.get(n, [])
                if not p2_props:
                    self.note("warn", "vpn",
                              f"crypto map {map_name} {seq}: transform-set/"
                              "proposal not found — defaulting to "
                              "aes256-sha1", ref)
                    p2_props = ["aes256-sha1"]
                seen: set[str] = set()
                p2_props = [p for p in p2_props
                            if not (p in seen or seen.add(p))]

                # phase1
                tg = self._tunnel_groups.get(peer, {})
                octets = peer.split(".")
                base = (f"s2s-{octets[2]}-{octets[3]}"
                        if len(octets) == 4 else f"s2s-{map_name}-{seq}")
                name = base[:15]
                n = 2
                while name in taken:
                    name = f"{base[:13]}~{n}"
                    n += 1
                taken.add(name)

                p1 = VpnPhase1(
                    name=name, interface=bind_ifc, remote_gw=peer,
                    ike_version=ver,
                    comment=f"peer {peer} (crypto map {map_name} {seq})",
                    source=ref)
                p1.proposals, p1.dhgrp, p1.keylife = self._ike_proposals(ver)
                if not p1.proposals:
                    self.note("warn", "vpn",
                              f"no ikev{ver} policies found — phase1 "
                              f"'{name}' defaults to aes256-sha256/aes256-"
                              "sha1, dhgrp 14; match the peer manually",
                              ref)
                    p1.proposals = ["aes256-sha256", "aes256-sha1"]
                    p1.dhgrp = ["14"]
                if ver == 1:
                    p1.psk = self._psk(tg.get("psk1"), peer, "IKEv1", ref)
                else:
                    local = tg.get("psk2_local") or tg.get("psk2_remote")
                    remote = tg.get("psk2_remote")
                    p1.psk = self._psk(local, peer, "IKEv2", ref)
                    if remote and tg.get("psk2_local") \
                            and remote != tg.get("psk2_local"):
                        p1.psk_remote = remote
                        self.note("info", "vpn",
                                  f"peer {peer}: asymmetric IKEv2 PSKs — "
                                  "emitted as psksecret/psksecret-remote",
                                  ref)

                # phase2 selectors from the crypto ACL
                acl = e["acl"]
                self._vpn_consumed_acls.add(acl)
                aces = self._acl_policies.get(acl, [])
                made = 0
                for ace in aces:
                    if ace.action != "accept":
                        self.note("info", "vpn",
                                  f"crypto ACL {acl}: deny ACE ignored "
                                  "(FortiOS selectors are permit-only)",
                                  ace.source)
                        continue
                    src_name = (ace.src_addrs or ["all"])[0]
                    dst_name = (ace.dst_addrs or ["all"])[0]
                    src_cidr = self._cidr_for(src_name, ace.source or ref)
                    dst_cidr = self._cidr_for(dst_name, ace.source or ref)
                    if src_cidr is None or dst_cidr is None:
                        continue
                    made += 1
                    self.cfg.phase2s.append(VpnPhase2(
                        name=f"{name}-p2-{made}", phase1=name,
                        proposals=p2_props, pfs_group=e["pfs"],
                        src=src_cidr, dst=dst_cidr, keylife=e["salife"],
                        source=ace.source or ref))

                    # ramifications: route + the two policies
                    if dst_cidr != "0.0.0.0/0" \
                            and (name, dst_cidr) not in route_seen:
                        route_seen.add((name, dst_cidr))
                        self.cfg.routes.append(Route(
                            dest=dst_cidr, gateway="", interface=name,
                            comment=f"VPN route (crypto map {map_name} "
                                    f"{seq})", source=ref))
                    lan_ifc = "any"
                    if src_cidr != "0.0.0.0/0":
                        net = ipaddress.IPv4Network(src_cidr, strict=False)
                        lan_ifc = table.lookup_net(net) or "any"
                    if lan_ifc == "any":
                        self.note("warn", "vpn",
                                  f"{name}: could not infer the LAN-side "
                                  f"interface for {src_cidr} — VPN policies "
                                  "use 'any'; review", ref)
                    self.cfg.policies.append(Policy(
                        name=f"{name}-out-{made}", src_zones=[lan_ifc],
                        dst_zones=[name], src_addrs=[src_name],
                        dst_addrs=[dst_name], services=["ALL"],
                        comment="auto-generated VPN policy", source=ref))
                    self.cfg.policies.append(Policy(
                        name=f"{name}-in-{made}", src_zones=[name],
                        dst_zones=[lan_ifc], src_addrs=[dst_name],
                        dst_addrs=[src_name], services=["ALL"],
                        comment="auto-generated VPN policy", source=ref))

                if made:
                    self.cfg.phase1s.append(p1)
                else:
                    taken.discard(name)
                    self.note("warn", "vpn",
                              f"crypto map {map_name} {seq} (peer {peer}): "
                              "no convertible selectors — tunnel skipped",
                              ref)

    def finish_acls(self):
        bound: set[str] = set()
        for acl, ifc, _ref in self._access_groups:
            bound.add(acl)
            for n, pol in enumerate(self._acl_policies.get(acl, []), start=1):
                pol.name = f"{acl}-{n}"
                pol.src_zones = [ifc]
                self.cfg.policies.append(pol)
        for acl, pols in self._acl_policies.items():
            if acl in bound:
                continue
            if acl in self._vpn_consumed_acls:
                self.note("info", "vpn",
                          f"ACL '{acl}' consumed as VPN interesting-traffic "
                          "selector", None)
                continue
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
