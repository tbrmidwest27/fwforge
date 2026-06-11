"""pfSense configuration parser (config.xml) -> fwforge IR.

pfSense stores everything in one XML document. The semantics that matter:

- interfaces have logical names (wan/lan/opt1...) that RULES reference;
  the physical NIC lives in <if> and VLANs are separate <vlans> entries
- aliases are typed: host/network -> addresses (multi-entry -> group),
  port -> services (protocol-agnostic, so they materialize per-protocol
  at rule-conversion time)
- filter rules are per-interface INBOUND (like ASA): srcintf = the rule's
  interface, dstintf is left for fwforge's route-based inference
- pfSense macros: <network>lan</network> = that interface's subnet,
  "lanip"/"wanip" = the interface address; <not/> = negation (FortiOS
  srcaddr/dstaddr-negate)
- NAT: port forwards and 1:1 -> VIPs; outbound automatic/hybrid -> NAT
  enabled on egress-to-WAN policies

Flagged, never silent: floating rules, policy-routing gateways on rules,
manual outbound NAT, IPv6 rules, OpenVPN (no FortiOS equivalent — and
SSL-VPN is gone in 7.6+), IPsec tunnels (convert manually for now),
url/urltable aliases.
"""
from __future__ import annotations

import ipaddress
import re
import xml.parsers.expat

from ..model import (
    Address,
    AddressGroup,
    FirewallConfig,
    Interface,
    NatRule,
    Policy,
    Route,
    Service,
    SourceRef,
    Vip,
)
from . import _vpn_common as vpn


class _Reporter:
    """Adapter so _vpn_common can append findings via the parser's note()."""

    def __init__(self, parser):
        self._p = parser

    def add(self, level, area, msg, ref=None):
        self._p.note(level, area, msg, ref)

LINE = "__line__"

ICMP_PF = {
    "echoreq": 8, "echorep": 0, "unreach": 3, "squench": 4, "redir": 5,
    "routeradv": 9, "routersol": 10, "timex": 11, "paramprob": 12,
    "timereq": 13, "timerep": 14, "inforeq": 15, "inforep": 16,
    "maskreq": 17, "maskrep": 18, "trace": 30,
}

CONSUMED = {"version", "system", "interfaces", "vlans", "gateways",
            "staticroutes", "aliases", "filter", "nat", "dhcpd",
            "openvpn", "ipsec", LINE}


def detect(text: str) -> float:
    head = text[:2000]
    if "<pfsense>" in head or "<pfsense " in head:
        return 0.95
    return 0.0


def _tree_from_xml(text: str) -> dict:
    parser = xml.parsers.expat.ParserCreate()
    root: dict = {}
    stack: list = [("", root, [])]

    def reject_entities(*_a):
        raise ValueError("XML entity declarations are not allowed in "
                         "firewall configs")

    parser.EntityDeclHandler = reject_entities

    def start(tag, attrs):
        stack.append((tag, {LINE: parser.CurrentLineNumber}, []))

    def chars(data):
        stack[-1][2].append(data)

    def end(tag):
        tag, node, parts = stack.pop()
        parent = stack[-1][1]
        kids = [k for k in node if k != LINE]
        value = node if kids else "".join(parts).strip()
        if tag in parent:
            if not isinstance(parent[tag], list):
                parent[tag] = [parent[tag]]
            parent[tag].append(value)
        else:
            parent[tag] = value

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    parser.Parse(text, True)
    return root.get("pfsense", root)


def _items(parent, key) -> list[dict]:
    v = parent.get(key)
    if v is None:
        return []
    if isinstance(v, list):
        return [x for x in v if isinstance(x, dict)]
    return [v] if isinstance(v, dict) else []


def _s(node, key, default: str = "") -> str:
    v = node.get(key, default) if isinstance(node, dict) else default
    return v if isinstance(v, str) else default


class PfSenseParser:
    def __init__(self, text: str, filename: str = ""):
        self.filename = filename
        self.cfg = FirewallConfig(vendor="pfsense")
        self.tree = _tree_from_xml(text)
        self._findings: list[tuple[str, str, str, SourceRef | None]] = []
        self._port_aliases: dict[str, str] = {}  # name -> "80 443 8000-8080"
        self._addr_names: set[str] = set()
        self._addr_cache: dict[str, str] = {}
        self._svc_cache: dict[tuple, str] = {}
        self._wan_ifcs: list[str] = []

    def note(self, level, area, msg, ref=None):
        self._findings.append((level, area, msg, ref))

    def ref(self, node, label: str) -> SourceRef:
        line = node.get(LINE, 0) if isinstance(node, dict) else 0
        return SourceRef(self.filename, line, label)

    # -- shared synthesis -------------------------------------------------

    def addr_for(self, value: str, ref: SourceRef) -> str | None:
        """Literal IP / CIDR -> shared address object name."""
        try:
            if "/" in value:
                net = ipaddress.IPv4Network(value, strict=False)
                if net.prefixlen == 32:
                    value = str(net.network_address)
                else:
                    key = f"n-{net.network_address}_{net.prefixlen}"
                    if key not in self._addr_cache:
                        self.cfg.addresses.append(Address(
                            name=key, type="subnet", value=str(net),
                            source=ref))
                        self._addr_cache[key] = key
                        self._addr_names.add(key)
                    return key
            ipaddress.IPv4Address(value)
        except ValueError:
            return None
        key = f"h-{value}"
        if key not in self._addr_cache:
            self.cfg.addresses.append(Address(
                name=key, type="host", value=value, source=ref))
            self._addr_cache[key] = key
            self._addr_names.add(key)
        return key

    def svc_for(self, svc: Service) -> str:
        sig = svc.signature()
        if sig in self._svc_cache:
            return self._svc_cache[sig]
        self.cfg.services.append(svc)
        self._svc_cache[sig] = svc.name
        return svc.name

    # -- sections ----------------------------------------------------------

    def parse(self) -> FirewallConfig:
        system = self.tree.get("system", {})
        self.cfg.hostname = _s(system, "hostname")
        self.cfg.version = _s(self.tree, "version")

        self.parse_interfaces()
        self.parse_aliases()
        self.parse_gateways_and_routes(system)
        self.parse_rules()
        self.parse_nat()
        self.parse_ipsec()
        self.flag_vpn_and_misc()
        self.report_unconverted()
        self.cfg.meta["findings"] = self._findings
        return self.cfg

    def parse_interfaces(self):
        ifs = self.tree.get("interfaces", {})
        if not isinstance(ifs, dict):
            return
        # vlanif (em1.30) -> (parent physical, tag)
        vlan_of: dict[str, tuple[str, int]] = {}
        for v in _items(self.tree.get("vlans", {}), "vlan"):
            tag = _s(v, "tag")
            if tag.isdigit():
                vlan_of[_s(v, "vlanif")] = (_s(v, "if"), int(tag))
        phys_to_logical: dict[str, str] = {}
        entries = [(k, v) for k, v in ifs.items()
                   if isinstance(v, dict) and k != LINE]
        for name, node in entries:
            phys_to_logical[_s(node, "if")] = name

        for name, node in entries:
            ref = self.ref(node, f"interface {name}")
            itf = Interface(name=name, source=ref,
                            description=_s(node, "descr") or None,
                            enabled="enable" in node)
            ipaddr = _s(node, "ipaddr")
            prefix = _s(node, "subnet")
            if ipaddr and ipaddr not in ("dhcp", "pppoe", "pptp", "l2tp"):
                if prefix.isdigit():
                    itf.ip = f"{ipaddr}/{prefix}"
                else:
                    itf.ip = f"{ipaddr}/32"
            elif ipaddr:
                self.note("info", "interfaces",
                          f"interface {name} is {ipaddr} — set the matching "
                          "addressing mode on the target interface", ref)
            phys = _s(node, "if")
            if phys in vlan_of:
                parent_phys, tag = vlan_of[phys]
                itf.vlan_id = tag
                itf.parent = phys_to_logical.get(parent_phys, parent_phys)
            if _s(node, "gateway"):
                self._wan_ifcs.append(name)
            self.cfg.interfaces.append(itf)

    def parse_aliases(self):
        for a in _items(self.tree.get("aliases", {}), "alias"):
            name = _s(a, "name")
            atype = _s(a, "type")
            entries = _s(a, "address").split()
            descr = _s(a, "descr") or None
            ref = self.ref(a, f"alias {name}")
            if atype == "port":
                ranges = " ".join(e.replace(":", "-") for e in entries)
                self._port_aliases[name] = ranges
                continue
            if atype not in ("host", "network"):
                self.note("warn", "addresses",
                          f"alias '{name}' type '{atype}' (url/urltable/…) "
                          "not convertible — recreate as a FortiOS external "
                          "resource or FQDN objects", ref)
                continue
            members: list[str] = []
            literals: list[str] = []
            for entry in entries:
                if re.match(r"^\d", entry):
                    literals.append(entry)
                else:
                    members.append(entry)  # nested alias reference
            if len(entries) == 1 and literals and not members:
                value = literals[0]
                if "/" in value and not value.endswith("/32"):
                    self.cfg.addresses.append(Address(
                        name=name, type="subnet", value=value,
                        comment=descr, source=ref))
                else:
                    self.cfg.addresses.append(Address(
                        name=name, type="host",
                        value=value.split("/")[0], comment=descr,
                        source=ref))
                self._addr_names.add(name)
                continue
            for lit in literals:
                m = self.addr_for(lit, ref)
                if m:
                    members.append(m)
                else:
                    # hostnames are allowed in pfSense host aliases
                    fq = f"fq-{lit}"[:79]
                    if fq not in self._addr_cache:
                        self.cfg.addresses.append(Address(
                            name=fq, type="fqdn", value=lit, source=ref))
                        self._addr_cache[fq] = fq
                        self._addr_names.add(fq)
                    members.append(fq)
            self.cfg.addr_groups.append(AddressGroup(
                name=name, members=members, comment=descr, source=ref))
            self._addr_names.add(name)

    def parse_gateways_and_routes(self, system):
        gw_ip: dict[str, str] = {}
        gw_if: dict[str, str] = {}
        for g in _items(self.tree.get("gateways", {}), "gateway_item"):
            name = _s(g, "name")
            gw_ip[name] = _s(g, "gateway")
            gw_if[name] = _s(g, "interface")
            if _s(g, "ipprotocol") == "inet6":
                self.note("info", "routes",
                          f"IPv6 gateway '{name}' skipped", self.ref(g, name))
        default = _s(system, "defaultgw4")
        if default and default in gw_ip:
            self.cfg.routes.append(Route(
                dest="0.0.0.0/0", gateway=gw_ip[default],
                interface=gw_if.get(default, ""),
                comment=f"default via gateway '{default}'",
                source=self.ref(system, "defaultgw4")))
        elif gw_ip:
            self.note("warn", "routes",
                      "no defaultgw4 set — default route not emitted; add "
                      "one on the FortiGate "
                      f"(gateways found: {', '.join(gw_ip)})")
        for r in _items(self.tree.get("staticroutes", {}), "route"):
            ref = self.ref(r, f"route {_s(r, 'network')}")
            gw = _s(r, "gateway")
            if gw not in gw_ip:
                self.note("warn", "routes",
                          f"route {_s(r, 'network')}: gateway '{gw}' not "
                          "found in gateways — skipped", ref)
                continue
            try:
                net = ipaddress.IPv4Network(_s(r, "network"), strict=False)
            except ValueError:
                self.note("warn", "routes",
                          f"route network '{_s(r, 'network')}' not IPv4 — "
                          "skipped", ref)
                continue
            self.cfg.routes.append(Route(
                dest=str(net), gateway=gw_ip[gw],
                interface=gw_if.get(gw, ""),
                comment=_s(r, "descr") or None, source=ref))

    # -- rules --------------------------------------------------------------

    def _endpoint(self, node, ref, what: str) -> tuple[str | None, bool, str]:
        """(address-name|'all'|None, negated, port-spec)"""
        if not isinstance(node, dict):
            return "all", False, ""
        negated = "not" in node
        port = _s(node, "port").replace(":", "-")
        if "any" in node:
            return "all", negated, port
        net = _s(node, "network")
        if net:
            if net.endswith("ip"):
                base = net[:-2]
                itf = self.cfg.interface_by_name(base)
                if itf and itf.ip:
                    return self.addr_for(itf.ip.split("/")[0],
                                         ref), negated, port
                self.note("warn", "policies",
                          f"{what} '{net}': interface address unknown "
                          "(dynamic?) — using 'all'", ref)
                return "all", negated, port
            itf = self.cfg.interface_by_name(net)
            if itf and itf.ip:
                name = f"{net}-net"
                if name not in self._addr_cache:
                    sub = str(ipaddress.IPv4Interface(itf.ip).network)
                    self.cfg.addresses.append(Address(
                        name=name, type="subnet", value=sub,
                        comment=f"pfSense '{net} net'", source=ref))
                    self._addr_cache[name] = name
                    self._addr_names.add(name)
                return name, negated, port
            self.note("warn", "policies",
                      f"{what} network '{net}' unresolved — using 'all'",
                      ref)
            return "all", negated, port
        addr = _s(node, "address")
        if not addr:
            return "all", negated, port
        if addr in self._addr_names:
            return addr, negated, port
        made = self.addr_for(addr, ref)
        if made:
            return made, negated, port
        self.note("warn", "policies",
                  f"{what} '{addr}' is not an alias or IPv4 literal — rule "
                  "skipped", ref)
        return None, negated, port

    def _services(self, proto: str, port: str, icmptype: str,
                  ref) -> list[str]:
        if not proto:
            return ["ALL"]
        if proto == "icmp":
            if icmptype and icmptype in ICMP_PF:
                t = ICMP_PF[icmptype]
                return [self.svc_for(Service(
                    name=f"icmp_{t}", protocol="icmp", icmp_type=t,
                    source=ref))]
            if icmptype:
                self.note("info", "services",
                          f"icmp type '{icmptype}' unmapped — using "
                          "ALL_ICMP", ref)
            return ["ALL_ICMP"]
        if proto in ("tcp", "udp", "tcp/udp"):
            ranges = port
            if port in self._port_aliases:
                ranges = self._port_aliases[port]
            if not ranges:
                base = f"{proto.replace('/', '')}_any"
                return [self.svc_for(Service(
                    name=base, protocol=proto, dst_ports="", source=ref))]
            label = port if port in self._port_aliases \
                else ranges.replace(" ", "_")
            return [self.svc_for(Service(
                name=f"{label}_{proto.replace('/', '')}"[:79],
                protocol=proto, dst_ports=ranges, source=ref))]
        # other IP protocols
        num = {"esp": 50, "ah": 51, "gre": 47, "igmp": 2, "ospf": 89,
               "pim": 103, "sctp": 132}.get(proto)
        if num is None:
            self.note("warn", "services",
                      f"protocol '{proto}' unmapped — using ALL", ref)
            return ["ALL"]
        return [self.svc_for(Service(
            name=f"proto_{proto}", protocol="ip", proto_number=num,
            source=ref))]

    def parse_rules(self):
        n = 0
        for r in _items(self.tree.get("filter", {}), "rule"):
            n += 1
            ref = self.ref(r, f"filter rule {n}")
            if _s(r, "ipprotocol") == "inet6":
                self.note("info", "policies",
                          f"rule {n}: IPv6-only — skipped (IPv6 in v2)", ref)
                continue
            floating = _s(r, "floating") == "yes"
            ifaces = [i for i in _s(r, "interface").split(",") if i]
            src_zones = ifaces or ["any"]
            if floating:
                self.note("warn", "policies",
                          f"rule {n}: floating rule — converted with "
                          f"srcintf {','.join(src_zones)}; floating "
                          "match-order semantics differ, review placement",
                          ref)
            src, sneg, sport = self._endpoint(r.get("source"), ref, "source")
            dst, dneg, dport = self._endpoint(r.get("destination"), ref,
                                              "destination")
            if src is None or dst is None:
                continue
            proto = _s(r, "protocol")
            services = self._services(proto, dport, _s(r, "icmptype"), ref)
            if sport:
                self.note("info", "policies",
                          f"rule {n}: source-port restriction '{sport}' not "
                          "carried into the service object — add manually "
                          "if required", ref)
            action = _s(r, "type", "pass")
            comment_bits = []
            descr = _s(r, "descr")
            if descr:
                comment_bits.append(descr)
            if action == "reject":
                comment_bits.append("pfSense 'reject' (FortiOS deny drops "
                                    "silently)")
            gw = _s(r, "gateway")
            if gw:
                comment_bits.append(f"policy-routing gateway {gw}")
                self.note("warn", "policies",
                          f"rule {n}: policy routing to gateway '{gw}' not "
                          "converted — recreate as an SD-WAN rule or "
                          "policy route", ref)
            self.cfg.policies.append(Policy(
                name=f"pf-{n}" + (f"-{descr[:24]}" if descr else ""),
                src_zones=src_zones,
                src_addrs=[src], dst_addrs=[dst], services=services,
                action="accept" if action == "pass" else "deny",
                log="log" in r, disabled="disabled" in r,
                src_negate=sneg, dst_negate=dneg,
                comment="; ".join(comment_bits)[:1023] or None,
                source=ref))

    # -- NAT ------------------------------------------------------------

    def parse_nat(self):
        nat = self.tree.get("nat", {})
        if not isinstance(nat, dict):
            return
        outbound = nat.get("outbound", {})
        mode = _s(outbound, "mode", "automatic")
        if mode in ("automatic", "hybrid"):
            for wan in self._wan_ifcs:
                self.cfg.nats.append(NatRule(
                    kind="dynamic-interface", real_ifc="*",
                    mapped_ifc=wan,
                    source=self.ref(outbound, "outbound nat")))
            self.note("info", "nat",
                      f"outbound NAT mode '{mode}': NAT enabled on "
                      "policies egressing "
                      f"{', '.join(self._wan_ifcs) or 'WAN'} "
                      "(matching pfSense's automatic source NAT)")
        manual_rules = _items(outbound, "rule")
        if mode in ("hybrid", "manual") and manual_rules:
            self.note("warn", "nat",
                      f"{len(manual_rules)} manual outbound NAT rule(s) "
                      "not converted — recreate as FortiOS IP pools / "
                      "central SNAT", self.ref(outbound, "outbound nat"))

        for i, r in enumerate(_items(nat, "rule"), start=1):
            ref = self.ref(r, f"port forward {i}")
            target = _s(r, "target")
            proto = _s(r, "protocol", "tcp")
            dest = r.get("destination", {})
            extport = _s(dest, "port").replace(":", "-")
            ext_ip = ""
            dnet = _s(dest, "network")
            if dnet.endswith("ip"):
                itf = self.cfg.interface_by_name(dnet[:-2])
                if itf and itf.ip:
                    ext_ip = itf.ip.split("/")[0]
            elif _s(dest, "address"):
                ext_ip = _s(dest, "address")
            if not ext_ip or not target:
                self.note("warn", "nat",
                          f"port forward {i}: external IP or target "
                          "unresolved (dynamic WAN?) — convert manually",
                          ref)
                continue
            protos = ["tcp", "udp"] if proto == "tcp/udp" else [proto]
            for p in protos:
                suffix = f"-{p}" if len(protos) > 1 else ""
                self.cfg.vips.append(Vip(
                    name=f"vip-pf-{i}{suffix}", ext_ip=ext_ip,
                    mapped_ip=target,
                    ext_intf=_s(r, "interface") or "wan",
                    protocol=p if extport else None,
                    ext_port=extport.split(" ")[0] if extport else None,
                    mapped_port=_s(r, "local-port") or None,
                    comment=_s(r, "descr") or None, source=ref))

        for i, r in enumerate(_items(nat, "onetoone"), start=1):
            ref = self.ref(r, f"1:1 NAT {i}")
            ext = _s(r, "external")
            internal = _s(r, "source", "")
            if isinstance(r.get("source"), dict):
                internal = _s(r["source"], "address")
            if ext and internal and "/" not in internal:
                self.cfg.vips.append(Vip(
                    name=f"vip-1to1-{i}", ext_ip=ext, mapped_ip=internal,
                    ext_intf=_s(r, "interface") or "wan",
                    comment=_s(r, "descr") or "pfSense 1:1 NAT",
                    source=ref))
            else:
                self.note("warn", "nat",
                          f"1:1 NAT {i}: subnet-style or unresolved "
                          "mapping — convert to a VIP range manually", ref)

    # -- IPsec ----------------------------------------------------------

    def _pf_enc(self, name: str, keylen: str) -> str | None:
        if not name:
            return None
        if name == "aes" and keylen:
            return vpn.ENC.get(f"aes{keylen}")
        return vpn.ENC.get(name)

    def _pf_selector(self, node, ref) -> str | None:
        if not isinstance(node, dict):
            return None
        t = _s(node, "type")
        addr = _s(node, "address")
        if addr:
            nm = _s(node, "netmask")
            return f"{addr}/{nm}" if nm else f"{addr}/32"
        itf = self.cfg.interface_by_name(t)
        if itf and itf.ip:
            return str(ipaddress.IPv4Interface(itf.ip).network)
        if t in ("lan", "wan") or t.startswith("opt"):
            self.note("warn", "vpn",
                      f"phase2 selector '{t}': interface subnet unknown — "
                      "set the selector manually", ref)
            return None
        self.note("warn", "vpn",
                  f"phase2 selector type '{t}' not convertible", ref)
        return None

    def parse_ipsec(self):
        ipsec = self.tree.get("ipsec", {})
        if not isinstance(ipsec, dict):
            return
        phase1s = _items(ipsec, "phase1")
        if not phase1s:
            return
        p2_by_ike: dict[str, list] = {}
        for p2 in _items(ipsec, "phase2"):
            p2_by_ike.setdefault(_s(p2, "ikeid"), []).append(p2)

        from ..transforms.routes import RouteTable
        table = RouteTable(self.cfg)

        for p1 in phase1s:
            ikeid = _s(p1, "ikeid")
            ref = self.ref(p1, f"ipsec phase1 ikeid {ikeid}")
            peer = _s(p1, "remote-gateway")
            iface = _s(p1, "interface") or "wan"
            ike_version = 2 if "ikev2" in _s(p1, "iketype") else 1

            # a phase1 with no phase2 carries no interesting traffic — skip
            # it cleanly before flagging anything about its credentials
            my_p2 = p2_by_ike.get(ikeid, [])
            if not my_p2:
                self.note("warn", "vpn",
                          f"IPsec phase1 ikeid {ikeid}: no phase2 — skipped",
                          ref)
                continue

            authm = _s(p1, "authentication_method", "pre_shared_key")
            psk = _s(p1, "pre-shared-key")
            if authm not in ("pre_shared_key", "mutual_psk", ""):
                self.note("error", "vpn",
                          f"IPsec phase1 ikeid {ikeid}: auth method "
                          f"'{authm}' (certificate?) — placeholder PSK "
                          "emitted, set authentication manually", ref)
                psk = "CHANGEME-PSK"
            elif not psk:
                self.note("error", "vpn",
                          f"IPsec phase1 ikeid {ikeid}: no pre-shared key — "
                          "placeholder emitted", ref)
                psk = "CHANGEME-PSK"

            encs: list[str] = []
            hashes: list[str] = []
            dh: list[str] = []
            items = _items(p1.get("encryption", {}), "item") \
                if isinstance(p1.get("encryption"), dict) else []
            if items:
                for it in items:
                    ea = it.get("encryption-algorithm", {})
                    e = self._pf_enc(_s(ea, "name"), _s(ea, "keylen"))
                    if e:
                        encs.append(e)
                    h = vpn.HASH.get(_s(it, "hash-algorithm"))
                    if h:
                        hashes.append(h)
                    if _s(it, "dhgroup"):
                        dh.append(_s(it, "dhgroup"))
            else:
                ea = p1.get("encryption-algorithm", {})
                e = self._pf_enc(_s(ea, "name"), _s(ea, "keylen"))
                if e:
                    encs.append(e)
                h = vpn.HASH.get(_s(p1, "hash-algorithm"))
                if h:
                    hashes.append(h)
                if _s(p1, "dhgroup"):
                    dh.append(_s(p1, "dhgroup"))

            selectors = []
            p2_encs: list[str] = []
            p2_hashes: list[str] = []
            pfs = ""
            for p2 in my_p2:
                lc = self._pf_selector(p2.get("localid"), ref)
                rc = self._pf_selector(p2.get("remoteid"), ref)
                if lc and rc:
                    selectors.append((lc, rc))
                for ea in _items(p2, "encryption-algorithm-option"):
                    e = self._pf_enc(_s(ea, "name"), _s(ea, "keylen"))
                    if e:
                        p2_encs.append(e)
                ha = p2.get("hash-algorithm-option")
                for h in ([ha] if isinstance(ha, str) else ha or []):
                    if vpn.HASH.get(h):
                        p2_hashes.append(vpn.HASH[h])
                if _s(p2, "pfsgroup") and not pfs:
                    pfs = _s(p2, "pfsgroup")

            p1_props = vpn.esp_combos(encs, hashes) or ["aes256-sha256"]
            p2_props = vpn.esp_combos(
                list(dict.fromkeys(p2_encs)),
                list(dict.fromkeys(p2_hashes))) or ["aes256-sha256"]
            if not encs or not p2_encs:
                self.note("warn", "vpn",
                          f"IPsec ikeid {ikeid}: proposal incomplete — "
                          "defaulted to aes256-sha256; match the peer", ref)
            name = f"vpn-ike{ikeid}"[:15]
            vpn.add_route_based_tunnel(
                self.cfg, _Reporter(self), table, name=name,
                interface=iface, remote_gw=peer, ike_version=ike_version,
                p1_proposals=p1_props, p1_dhgrp=dh or ["14"], psk=psk,
                selectors=selectors, p2_proposals=p2_props, pfs_group=pfs,
                comment=f"pfSense IPsec ikeid {ikeid} (peer {peer})",
                source=ref)

    def flag_vpn_and_misc(self):
        ovpn = self.tree.get("openvpn", {})
        servers = _items(ovpn, "openvpn-server") if isinstance(ovpn, dict) \
            else []
        clients = _items(ovpn, "openvpn-client") if isinstance(ovpn, dict) \
            else []
        if servers or clients:
            self.note("warn", "vpn",
                      f"OpenVPN config present ({len(servers)} server(s), "
                      f"{len(clients)} client(s)) — FortiOS has no OpenVPN; "
                      "migrate remote access to IKEv2 dial-up IPsec "
                      "(FortiClient)", self.ref(ovpn, "openvpn"))
        if "dhcpd" in self.tree:
            self.note("info", "coverage",
                      "DHCP server config present — recreate per-interface "
                      "DHCP on the FortiGate")

    def report_unconverted(self):
        for key, node in self.tree.items():
            if key in CONSUMED or not isinstance(node, dict):
                continue
            self.note("info", "coverage",
                      f"pfSense section '{key}' not converted",
                      self.ref(node, key))


def parse(text: str, filename: str = "") -> FirewallConfig:
    return PfSenseParser(text, filename).parse()
