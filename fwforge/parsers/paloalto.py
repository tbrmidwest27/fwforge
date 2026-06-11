"""Palo Alto PAN-OS configuration parser -> fwforge IR.

Accepts both PAN-OS formats:
- XML (`export configuration` / running-config.xml)
- set format (`show config running | display set`, one attribute per line)

Both are normalized into the same nested-dict tree, so one extractor covers
both. PAN-OS is zone-based like FortiOS, so zones convert 1:1; the honest
gap is App-ID — FortiOS policies match services, not applications, so any
rule using applications is converted on its service match and loudly
flagged for review. Nothing is dropped silently: unconverted sections and
constructs land in the report.

v1 scope: interfaces (ethernet/aggregate + L3 subinterfaces), zones,
addresses/groups, services/groups (incl. predefined service-http/https),
security rules (negate flags supported), NAT (interface PAT + static
bi-directional + destination translation -> VIP), static routes (egress
inferred when omitted). Multi-vsys: first vsys converted, rest flagged.
"""
from __future__ import annotations

import ipaddress
import re
import xml.parsers.expat

from ..model import (
    Address,
    AddressGroup,
    AppList,
    FirewallConfig,
    Interface,
    NatRule,
    Policy,
    Service,
    ServiceGroup,
    SourceRef,
    Vip,
    Zone,
)
from . import _vpn_common as vpn
from . import pan_appid

LINE = "__line__"

# PAN-OS predefined services that rules may reference without defining
PREDEFINED_SERVICES = {
    "service-http": ("tcp", "80 8080"),
    "service-https": ("tcp", "443"),
}


def detect(text: str) -> float:
    head = text[:4000]
    if "<config" in head and "<devices>" in text:
        if '<entry name="localhost.localdomain">' in text:
            return 0.95
        return 0.7
    set_lines = 0
    total = 0
    for line in text.splitlines()[:300]:
        line = line.strip()
        if not line:
            continue
        total += 1
        toks = line.split(None, 2)
        if len(toks) >= 2 and toks[0] == "set" and toks[1] in (
                "deviceconfig", "network", "zone", "rulebase", "address",
                "service", "vsys", "address-group", "service-group",
                "mgt-config", "shared", "tag", "application-group"):
            set_lines += 1
    if total and set_lines / total > 0.6:
        return 0.9
    return 0.0


# --- format readers: both produce the same nested-dict tree ----------------

def _tree_from_xml(text: str) -> dict:
    parser = xml.parsers.expat.ParserCreate()
    root: dict = {}
    # (tag, attrs, node, textparts)
    stack: list = [("", {}, root, [])]

    def reject_entities(*_args):
        raise ValueError("XML entity declarations are not allowed in "
                         "firewall configs")

    parser.EntityDeclHandler = reject_entities

    def start(tag, attrs):
        stack.append((tag, attrs, {LINE: parser.CurrentLineNumber}, []))

    def chars(data):
        stack[-1][3].append(data)

    def end(tag):
        tag, attrs, node, textparts = stack.pop()
        parent = stack[-1][2]
        text_value = "".join(textparts).strip()
        if tag == "member":
            parent.setdefault("member", []).append(text_value)
            return
        key = attrs.get("name", tag) if tag == "entry" else tag
        children = [k for k in node if k != LINE]
        if children:
            parent[key] = node
        elif text_value:
            parent[key] = text_value
        else:
            parent[key] = node  # empty entry, e.g. <entry name="1.2.3.4/29"/>

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    parser.Parse(text, True)
    return root.get("config", root)


def _set_tokens(line: str) -> list[str]:
    toks: list[str] = []
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if ch.isspace():
            i += 1
            continue
        if ch == '"':
            j = line.find('"', i + 1)
            if j < 0:
                j = n
            toks.append(line[i + 1:j])
            i = j + 1
        else:
            j = i
            while j < n and not line[j].isspace():
                j += 1
            toks.append(line[i:j])
            i = j
    return toks


def _tree_from_set_lines(text: str, unparsed: list[SourceRef],
                         filename: str) -> dict:
    """set-format reader: each line is a path; last token (or bracketed
    list) is the value."""
    root: dict = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        toks = _set_tokens(line)
        if not toks or toks[0] != "set" or len(toks) < 3:
            unparsed.append(SourceRef(filename, lineno, line[:120]))
            continue
        toks = toks[1:]
        if "[" in toks:
            li = toks.index("[")
            path = toks[:li]
            value: object = [t for t in toks[li + 1:] if t != "]"]
        else:
            path, value = toks[:-1], toks[-1]
        if not path:
            unparsed.append(SourceRef(filename, lineno, line[:120]))
            continue

        node = root
        for tok in path[:-1]:
            child = node.get(tok)
            if not isinstance(child, dict):
                child = {LINE: lineno}
                node[tok] = child
            node = child
        attr = path[-1]
        existing = node.get(attr)
        if isinstance(existing, dict):
            # value-less container also used as leaf — store under itself
            existing.setdefault(value if isinstance(value, str) else "",
                                {LINE: lineno})
        elif existing is None:
            node[attr] = value
        else:
            merged = existing if isinstance(existing, list) else [existing]
            merged += value if isinstance(value, list) else [value]
            node[attr] = merged
    return root


# --- tree helpers -----------------------------------------------------------

def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [x for x in v if isinstance(x, str)]
    if isinstance(v, dict):
        if "member" in v:
            return _as_list(v["member"])
        return [k for k in v if k != LINE]
    return []


def _entries(v) -> list[tuple[str, dict]]:
    if not isinstance(v, dict):
        return []
    out = []
    for k, child in v.items():
        if k == LINE:
            continue
        out.append((k, child if isinstance(child, dict) else {"__value__": child}))
    return out


def _line(node: dict) -> int:
    return node.get(LINE, 0) if isinstance(node, dict) else 0


class _Reporter:
    """Adapter so _vpn_common can append findings via a parser's note()."""

    def __init__(self, parser):
        self._p = parser

    def add(self, level, area, msg, ref=None):
        self._p.note(level, area, msg, ref)


class PaloParser:
    def __init__(self, text: str, filename: str = ""):
        self.filename = filename
        self.cfg = FirewallConfig(vendor="paloalto")
        self._findings: list[tuple[str, str, str, SourceRef | None]] = []
        if text.lstrip().startswith("<"):
            tree = _tree_from_xml(text)
        else:
            tree = _tree_from_set_lines(text, self.cfg.unparsed, filename)
        self.tree = tree

    def note(self, level: str, area: str, msg: str,
             ref: SourceRef | None = None):
        self._findings.append((level, area, msg, ref))

    def ref(self, node, label: str) -> SourceRef:
        return SourceRef(self.filename, _line(node), label)

    # -- scope resolution -----------------------------------------------

    def scopes(self) -> tuple[dict, dict]:
        """(device_scope, vsys_scope) for both formats."""
        cfg = self.tree
        device = cfg
        devices = cfg.get("devices")
        if isinstance(devices, dict):
            for name, node in _entries(devices):
                device = node
                break
        vsys_scope = device
        vsys = device.get("vsys")
        if isinstance(vsys, dict):
            entries = _entries(vsys)
            if entries:
                vsys_scope = entries[0][1]
                if len(entries) > 1:
                    self.note(
                        "error", "vsys",
                        f"multi-vsys config ({len(entries)} vsys): only "
                        f"'{entries[0][0]}' converted — re-run per vsys or "
                        "wait for VDOM-mapped conversion")
        # shared objects (Panorama / shared scope) merge in at lower priority
        shared = cfg.get("shared")
        if isinstance(shared, dict):
            merged = dict(shared)
            merged.update({k: v for k, v in vsys_scope.items() if k != LINE})
            vsys_scope = merged
        return device, vsys_scope

    # -- sections ---------------------------------------------------------

    def parse(self) -> FirewallConfig:
        device, vsys = self.scopes()
        hostname = device.get("deviceconfig", {})
        if isinstance(hostname, dict):
            self.cfg.hostname = str(
                hostname.get("system", {}).get("hostname", "")
                if isinstance(hostname.get("system"), dict) else "")

        self.parse_interfaces(device.get("network", {}))
        self.parse_zones(vsys.get("zone"))
        self.parse_addresses(vsys.get("address"))
        self.parse_addr_groups(vsys.get("address-group"))
        self.parse_services(vsys.get("service"))
        self.parse_svc_groups(vsys.get("service-group"))
        rulebase = vsys.get("rulebase", {})
        if isinstance(rulebase, dict):
            sec = rulebase.get("security", {})
            self.parse_rules(sec.get("rules") if isinstance(sec, dict) else None)
            nat = rulebase.get("nat", {})
            self.parse_nat(nat.get("rules") if isinstance(nat, dict) else None)
        self.parse_routes(device.get("network", {}))
        self.parse_vpn(device.get("network", {}))
        self.report_unconverted_sections(device, vsys, rulebase)
        self.cfg.meta["findings"] = self._findings
        return self.cfg

    @staticmethod
    def _lifetime(node) -> int:
        if not isinstance(node, dict):
            return 0
        if node.get("seconds", "").isdigit():
            return int(node["seconds"])
        if node.get("hours", "").isdigit():
            return int(node["hours"]) * 3600
        if node.get("days", "").isdigit():
            return int(node["days"]) * 86400
        return 0

    def _psk(self, key: str, peer: str, ref: SourceRef) -> str:
        if not key:
            self.note("error", "vpn",
                      f"tunnel to {peer}: no pre-shared key (cert auth?) — "
                      "placeholder emitted, set authentication manually", ref)
            return "CHANGEME-PSK"
        # PAN exports PSKs encrypted (base64 with '=' padding, often a
        # leading '-'); a plaintext secret has neither
        if "=" in key or key.startswith("-"):
            self.note("error", "vpn",
                      f"tunnel to {peer}: PAN exports the pre-shared key "
                      "encrypted — placeholder emitted, set the real key",
                      ref)
            return "CHANGEME-PSK"
        return key

    def parse_vpn(self, network):
        if not isinstance(network, dict):
            return
        ike = network.get("ike", {})
        cps = ike.get("crypto-profiles", {}) if isinstance(ike, dict) else {}

        ike_prof: dict[str, dict] = {}
        for nm, e in _entries(cps.get("ike-crypto-profiles", {})):
            encs = [vpn.ENC[x] for x in _as_list(e.get("encryption"))
                    if x in vpn.ENC]
            hashes = [vpn.HASH[x] for x in _as_list(e.get("hash"))
                      if x in vpn.HASH]
            dh = [x.replace("group", "") for x in _as_list(e.get("dh-group"))]
            ike_prof[nm] = {"props": vpn.esp_combos(encs, hashes),
                            "dh": dh, "life": self._lifetime(e.get("lifetime"))}
        ipsec_prof: dict[str, dict] = {}
        for nm, e in _entries(cps.get("ipsec-crypto-profiles", {})):
            esp = e.get("esp", {})
            encs = [vpn.ENC[x] for x in _as_list(esp.get("encryption"))
                    if x in vpn.ENC]
            auths = [vpn.HASH[x] for x in _as_list(esp.get("authentication"))
                     if x in vpn.HASH]
            dh = [x.replace("group", "") for x in _as_list(e.get("dh-group"))]
            ipsec_prof[nm] = {"props": vpn.esp_combos(encs, auths),
                              "pfs": dh[0] if dh else "",
                              "life": self._lifetime(e.get("lifetime"))}
        gateways = {nm: e for nm, e in _entries(ike.get("gateway", {}))}

        tunnels = network.get("tunnel", {})
        ipsec_tuns = tunnels.get("ipsec", {}) if isinstance(tunnels, dict) \
            else {}
        tun_entries = _entries(ipsec_tuns)
        if not tun_entries:
            return
        from ..transforms.routes import RouteTable
        table = RouteTable(self.cfg)

        for tname, t in tun_entries:
            ref = self.ref(t, f"ipsec tunnel {tname}")
            auto = t.get("auto-key", {})
            if not isinstance(auto, dict):
                self.note("warn", "vpn",
                          f"tunnel {tname}: not an auto-key IPsec tunnel — "
                          "convert manually", ref)
                continue
            gw_names = [n for n, _ in _entries(auto.get("ike-gateway", {}))]
            gw = gateways.get(gw_names[0]) if gw_names else None
            if gw is None:
                self.note("warn", "vpn",
                          f"tunnel {tname}: IKE gateway not found — skipped",
                          ref)
                continue
            peer = ""
            pa = gw.get("peer-address", {})
            if isinstance(pa, dict):
                peer = pa.get("ip", "") if isinstance(pa.get("ip"), str) \
                    else ""
            la = gw.get("local-address", {})
            local_if = la.get("interface", "") if isinstance(la, dict) else ""
            proto = gw.get("protocol", {}) if isinstance(
                gw.get("protocol"), dict) else {}
            ver = proto.get("version", "ikev1")
            ike_version = 2 if "ikev2" in str(ver) else 1
            ikecp = ""
            for v in ("ikev2", "ikev1"):
                sub = proto.get(v, {})
                if isinstance(sub, dict) and sub.get("ike-crypto-profile"):
                    ikecp = sub["ike-crypto-profile"]
                    break
            p1 = ike_prof.get(ikecp, {"props": [], "dh": [], "life": 0})
            ipcp = auto.get("ipsec-crypto-profile", "")
            p2 = ipsec_prof.get(ipcp, {"props": [], "pfs": "", "life": 0})

            auth = gw.get("authentication", {})
            psk_node = auth.get("pre-shared-key", {}) if isinstance(
                auth, dict) else {}
            key = psk_node.get("key", "") if isinstance(psk_node, dict) else ""

            selectors = []
            for pname, pid in _entries(t.get("proxy-id", {})):
                local = pid.get("local", "") if isinstance(
                    pid.get("local"), str) else ""
                remote = pid.get("remote", "") if isinstance(
                    pid.get("remote"), str) else ""
                if local and remote:
                    selectors.append((local, remote))
            if not selectors:
                selectors = [("0.0.0.0/0", "0.0.0.0/0")]
                self.note("info", "vpn",
                          f"tunnel {tname}: no proxy-id — using a "
                          "0.0.0.0/0 <-> 0.0.0.0/0 selector (route-based)",
                          ref)

            p1_props = p1["props"] or ["aes256-sha256"]
            p2_props = p2["props"] or ["aes256-sha256"]
            if not p1["props"] or not p2["props"]:
                self.note("warn", "vpn",
                          f"tunnel {tname}: crypto profile incomplete — "
                          "defaulted proposals to aes256-sha256; match the "
                          "peer manually", ref)
            tun_name = f"vpn-{tname}"[:15]
            vpn.add_route_based_tunnel(
                self.cfg, _Reporter(self), table, name=tun_name,
                interface=local_if or "wan1", remote_gw=peer,
                ike_version=ike_version, p1_proposals=p1_props,
                p1_dhgrp=p1["dh"] or ["14"],
                psk=self._psk(key, peer or tname, ref),
                p1_keylife=p1["life"], selectors=selectors,
                p2_proposals=p2_props, pfs_group=p2["pfs"],
                p2_keylife=p2["life"],
                comment=f"PAN tunnel {tname} (peer {peer})", source=ref)

    def parse_interfaces(self, network):
        if not isinstance(network, dict):
            return
        iface = network.get("interface", {})
        if not isinstance(iface, dict):
            return
        for family in ("ethernet", "aggregate-ethernet", "vlan", "loopback",
                       "tunnel"):
            fam = iface.get(family)
            for name, node in _entries(fam):
                self._one_interface(name, node)

    def _one_interface(self, name: str, node: dict):
        ref = self.ref(node, f"interface {name}")
        layer3 = node.get("layer3") if isinstance(node, dict) else None
        if isinstance(node, dict) and (
                "layer2" in node or "virtual-wire" in node or "tap" in node):
            mode = [m for m in ("layer2", "virtual-wire", "tap") if m in node]
            self.note("warn", "interfaces",
                      f"interface {name} is {mode[0]} mode — no layer-3 "
                      "conversion; map manually", ref)
            return
        if isinstance(node, dict) and "aggregate-group" in node:
            self.note("info", "interfaces",
                      f"interface {name} is a member of aggregate "
                      f"'{node['aggregate-group']}' — recreate the LACP "
                      "bundle on the FortiGate", ref)
            return
        itf = Interface(name=name, source=ref)
        if isinstance(node, dict):
            comment = node.get("comment")
            if isinstance(comment, str):
                itf.description = comment
        if isinstance(layer3, dict):
            ips = _as_list(layer3.get("ip"))
            if ips:
                itf.ip = ips[0]
                if len(ips) > 1:
                    self.note("warn", "interfaces",
                              f"{name}: {len(ips) - 1} secondary IP(s) not "
                              "converted (FortiOS secondary-IP) — add "
                              "manually", ref)
            elif "dhcp-client" in layer3:
                self.note("info", "interfaces",
                          f"{name}: DHCP client — set mode dhcp on the "
                          "target interface", ref)
            units = layer3.get("units")
            for uname, unode in _entries(units):
                sub = Interface(name=uname, parent=name,
                                source=self.ref(unode, f"interface {uname}"))
                tag = unode.get("tag")
                if isinstance(tag, str) and tag.isdigit():
                    sub.vlan_id = int(tag)
                else:
                    m = re.match(r".*\.(\d+)$", uname)
                    if m:
                        sub.vlan_id = int(m.group(1))
                uips = _as_list(unode.get("ip"))
                if uips:
                    sub.ip = uips[0]
                ucomment = unode.get("comment")
                if isinstance(ucomment, str):
                    sub.description = ucomment
                self.cfg.interfaces.append(sub)
        self.cfg.interfaces.append(itf)

    def parse_zones(self, zones):
        for name, node in _entries(zones):
            ref = self.ref(node, f"zone {name}")
            net = node.get("network", {}) if isinstance(node, dict) else {}
            members = _as_list(net.get("layer3")) if isinstance(net, dict) \
                else []
            if isinstance(net, dict) and not members:
                for mode in ("layer2", "virtual-wire", "tap"):
                    if mode in net:
                        self.note("warn", "zones",
                                  f"zone {name} is {mode} — not converted",
                                  ref)
            self.cfg.zones.append(Zone(name=name, members=members,
                                       source=ref))

    def parse_addresses(self, addresses):
        for name, node in _entries(addresses):
            ref = self.ref(node, f"address {name}")
            desc = node.get("description")
            comment = desc if isinstance(desc, str) else None
            if "ip-netmask" in node:
                value = str(node["ip-netmask"])
                try:
                    net = ipaddress.IPv4Network(value if "/" in value
                                                else value + "/32",
                                                strict=False)
                except ValueError:
                    self.note("warn", "addresses",
                              f"address {name}: '{value}' not IPv4 — "
                              "skipped (IPv6 in v2)", ref)
                    continue
                if net.prefixlen == 32:
                    self.cfg.addresses.append(Address(
                        name=name, type="host",
                        value=str(net.network_address),
                        comment=comment, source=ref))
                else:
                    self.cfg.addresses.append(Address(
                        name=name, type="subnet", value=str(net),
                        comment=comment, source=ref))
            elif "ip-range" in node:
                self.cfg.addresses.append(Address(
                    name=name, type="range", value=str(node["ip-range"]),
                    comment=comment, source=ref))
            elif "fqdn" in node:
                self.cfg.addresses.append(Address(
                    name=name, type="fqdn", value=str(node["fqdn"]),
                    comment=comment, source=ref))
            else:
                self.note("warn", "addresses",
                          f"address {name}: unsupported type "
                          f"({', '.join(k for k in node if k != LINE)})",
                          ref)

    def parse_addr_groups(self, groups):
        for name, node in _entries(groups):
            ref = self.ref(node, f"address-group {name}")
            if "dynamic" in node:
                self.note("warn", "addresses",
                          f"address-group {name} is dynamic (tag-based) — "
                          "not convertible; recreate with FortiOS dynamic "
                          "address objects", ref)
                continue
            members = _as_list(node.get("static"))
            self.cfg.addr_groups.append(AddressGroup(
                name=name, members=members, source=ref))

    @staticmethod
    def _ports(value: str) -> str:
        # PAN uses comma-separated port lists; FortiOS uses spaces
        return " ".join(p.strip() for p in str(value).split(",") if p.strip())

    def parse_services(self, services):
        for name, node in _entries(services):
            ref = self.ref(node, f"service {name}")
            proto_node = node.get("protocol", {})
            if not isinstance(proto_node, dict):
                continue
            made = False
            for proto in ("tcp", "udp"):
                p = proto_node.get(proto)
                if not isinstance(p, dict):
                    continue
                svc = Service(
                    name=name, protocol=proto,
                    dst_ports=self._ports(p.get("port", "")),
                    src_ports=self._ports(p.get("source-port", "")),
                    source=ref)
                desc = node.get("description")
                if isinstance(desc, str):
                    svc.comment = desc
                self.cfg.services.append(svc)
                made = True
            if not made:
                self.note("warn", "services",
                          f"service {name}: no tcp/udp definition — skipped",
                          ref)

    def parse_svc_groups(self, groups):
        for name, node in _entries(groups):
            ref = self.ref(node, f"service-group {name}")
            members = _as_list(node.get("members"))
            for m in members:
                self._ensure_service(m, ref)
            self.cfg.svc_groups.append(ServiceGroup(
                name=name, members=members, source=ref))

    def _ensure_service(self, name: str, ref: SourceRef) -> None:
        if name in ("any", "application-default"):
            return
        if any(s.name == name for s in self.cfg.services):
            return
        if any(g.name == name for g in self.cfg.svc_groups):
            return
        if name in PREDEFINED_SERVICES:
            proto, ports = PREDEFINED_SERVICES[name]
            self.cfg.services.append(Service(
                name=name, protocol=proto, dst_ports=ports,
                comment="PAN-OS predefined service", source=ref))
        else:
            self.note("warn", "services",
                      f"service '{name}' referenced but not defined — "
                      "define it on the FortiGate or fix the reference",
                      ref)

    def parse_rules(self, rules):
        for name, r in _entries(rules):
            ref = self.ref(r, f"security rule '{name}'")
            action = str(r.get("action", "allow"))
            services: list[str] = []
            app_default = False
            for svc in _as_list(r.get("service")) or ["any"]:
                if svc == "any":
                    services.append("ALL")
                elif svc == "application-default":
                    app_default = True
                    services.append("ALL")
                else:
                    self._ensure_service(svc, ref)
                    services.append(svc)
            apps = _as_list(r.get("application")) or ["any"]
            comment_bits: list[str] = []
            desc = r.get("description")
            if isinstance(desc, str):
                comment_bits.append(desc)
            app_list = self._app_list_for(apps, name, ref)
            if apps != ["any"]:
                shown = ", ".join(apps[:6]) + (" …" if len(apps) > 6 else "")
                comment_bits.append(f"PAN apps: {shown}")
            if app_default:
                self.note(
                    "warn", "policies",
                    f"rule '{name}' uses service=application-default — "
                    "ports depend on the App-ID database; converted as ALL, "
                    "tighten manually", ref)
            if "profile-setting" in r:
                self.note("info", "policies",
                          f"rule '{name}': security profiles not converted "
                          "— attach FortiOS UTM profiles manually", ref)

            pol = Policy(
                name=name,
                src_zones=_as_list(r.get("from")) or ["any"],
                dst_zones=_as_list(r.get("to")) or ["any"],
                src_addrs=[a if a != "any" else "all"
                           for a in (_as_list(r.get("source")) or ["any"])],
                dst_addrs=[a if a != "any" else "all"
                           for a in (_as_list(r.get("destination"))
                                     or ["any"])],
                services=services,
                action="accept" if action == "allow" else "deny",
                log=str(r.get("log-end", "yes")) != "no",
                disabled=str(r.get("disabled", "no")) == "yes",
                src_negate=str(r.get("negate-source", "no")) == "yes",
                dst_negate=str(r.get("negate-destination", "no")) == "yes",
                app_list=app_list,
                source=ref,
            )
            if action not in ("allow", "deny", "drop"):
                self.note("info", "policies",
                          f"rule '{name}': action '{action}' mapped to deny",
                          ref)
            if comment_bits:
                pol.comment = "; ".join(comment_bits)[:1023]
            self.cfg.policies.append(pol)

    def _app_list_for(self, apps: list[str], rule: str,
                      ref: SourceRef) -> str:
        """Map a rule's PAN App-IDs to a FortiOS application-list profile
        (deduped across rules). Returns the profile name, or ''."""
        if apps == ["any"] or not apps:
            return ""
        cats, ids, transport, unmapped = pan_appid.map_apps(apps)
        if not cats:
            if unmapped:
                self.note("warn", "policies",
                          f"rule '{rule}': App-ID(s) {', '.join(unmapped)} "
                          "have no FortiOS app-control category mapping — "
                          "add application control manually", ref)
            return ""
        key = tuple(sorted(ids))
        cache = self.cfg.meta.setdefault("_applist_cache", {})
        if key not in cache:
            name = f"pan-appctrl-{len(self.cfg.app_lists) + 1}"
            self.cfg.app_lists.append(AppList(
                name=name, categories=ids, cat_names=cats,
                apps=[a for a in apps if a not in ("any",
                                                   "application-default")],
                source=ref))
            cache[key] = name
        name = cache[key]
        msg = (f"rule '{rule}': App-ID -> application-list '{name}' "
               f"(categories: {', '.join(cats)})")
        if transport:
            msg += f"; transport app(s) ignored: {', '.join(transport)}"
        if unmapped:
            msg += (f"; UNMAPPED (add manually): {', '.join(unmapped)}")
        self.note("warn", "policies", msg
                  + ". Category-level control approximates PAN's per-app "
                  "match; verify and tighten.", ref)
        return name

    def _zone_single_member(self, zone_name: str) -> str:
        for z in self.cfg.zones:
            if z.name == zone_name and len(z.members) == 1:
                return z.members[0]
        return "any"

    def _resolve_ip(self, token: str, ref: SourceRef) -> str | None:
        addr = self.cfg.address_by_name(token)
        if addr:
            if addr.type == "host":
                return addr.value
            self.note("warn", "nat",
                      f"NAT references non-host address '{token}' "
                      f"({addr.type}) — set the IP manually", ref)
            return None
        try:
            ipaddress.IPv4Address(token)
            return token
        except ValueError:
            return None

    def parse_nat(self, rules):
        for name, r in _entries(rules):
            ref = self.ref(r, f"nat rule '{name}'")
            if str(r.get("disabled", "no")) == "yes":
                self.note("info", "nat", f"nat rule '{name}' is disabled — "
                                         "skipped", ref)
                continue
            st = r.get("source-translation")
            dt = r.get("destination-translation")
            frm = _as_list(r.get("from")) or ["any"]
            to = _as_list(r.get("to")) or ["any"]
            handled = False

            if isinstance(st, dict):
                dipp = st.get("dynamic-ip-and-port")
                static = st.get("static-ip")
                if isinstance(dipp, dict) and "interface-address" in dipp:
                    self.cfg.nats.append(NatRule(
                        kind="dynamic-interface",
                        real_obj=",".join(_as_list(r.get("source"))),
                        real_ifc=frm[0], mapped_ifc=to[0], source=ref))
                    handled = True
                elif isinstance(dipp, dict):
                    self.note("warn", "nat",
                              f"nat rule '{name}': SNAT to address pool — "
                              "create a FortiOS ippool + policy manually",
                              ref)
                elif isinstance(static, dict):
                    trans = str(static.get("translated-address", ""))
                    ext = self._resolve_ip(trans, ref)
                    srcs = _as_list(r.get("source"))
                    mapped = self._resolve_ip(srcs[0], ref) if srcs else None
                    if str(static.get("bi-directional", "no")) == "yes" \
                            and ext and mapped:
                        self.cfg.vips.append(Vip(
                            name=f"vip-{name}", ext_ip=ext, mapped_ip=mapped,
                            ext_intf=self._zone_single_member(to[0]),
                            comment=f"from PAN bi-directional static NAT "
                                    f"'{name}'", source=ref))
                        handled = True
                    else:
                        self.note("warn", "nat",
                                  f"nat rule '{name}': one-way static "
                                  "source NAT — use a FortiOS ippool "
                                  "(type one-to-one) + policy", ref)
                else:
                    self.note("warn", "nat",
                              f"nat rule '{name}': unsupported "
                              "source-translation variant", ref)

            if isinstance(dt, dict):
                dsts = _as_list(r.get("destination"))
                ext = self._resolve_ip(dsts[0], ref) if dsts else None
                mapped = self._resolve_ip(
                    str(dt.get("translated-address", "")), ref)
                if ext and mapped:
                    vip = Vip(
                        name=f"vip-{name}", ext_ip=ext, mapped_ip=mapped,
                        ext_intf=self._zone_single_member(frm[0]),
                        comment=f"from PAN destination NAT '{name}'",
                        source=ref)
                    tport = dt.get("translated-port")
                    svc = str(r.get("service", "any"))
                    if tport is not None:
                        proto, extport = "tcp", None
                        match = next((s for s in self.cfg.services
                                      if s.name == svc), None)
                        if svc in PREDEFINED_SERVICES:
                            proto, extport = (
                                PREDEFINED_SERVICES[svc][0],
                                PREDEFINED_SERVICES[svc][1].split()[0])
                        elif match:
                            proto = "tcp" if "tcp" in match.protocol \
                                else "udp"
                            extport = (match.dst_ports or "").split()[0] \
                                if match.dst_ports else None
                        if extport:
                            vip.protocol = proto
                            vip.ext_port = extport
                            vip.mapped_port = str(tport)
                        else:
                            self.note("warn", "nat",
                                      f"nat rule '{name}': translated-port "
                                      f"{tport} but external port unclear "
                                      f"(service '{svc}') — set "
                                      "extport/mappedport manually", ref)
                    self.cfg.vips.append(vip)
                    handled = True
                else:
                    self.note("error", "nat",
                              f"nat rule '{name}': destination NAT could "
                              "not be resolved to host IPs — convert "
                              "manually", ref)

            if not handled and not st and not dt:
                self.note("info", "nat",
                          f"nat rule '{name}' has no translation "
                          "(no-NAT rule) — FortiOS default is no NAT "
                          "unless enabled per policy; nothing emitted", ref)

    def parse_routes(self, network):
        if not isinstance(network, dict):
            return
        vrs = network.get("virtual-router")
        vr_entries = _entries(vrs)
        if len(vr_entries) > 1:
            self.note("warn", "routes",
                      f"{len(vr_entries)} virtual routers — all static "
                      "routes merged into one table (FortiOS VRFs in v2)")
        from ..model import Route
        for vrname, vr in vr_entries:
            rt = vr.get("routing-table", {})
            ip = rt.get("ip", {}) if isinstance(rt, dict) else {}
            static = ip.get("static-route") if isinstance(ip, dict) else None
            for rname, rnode in _entries(static):
                ref = self.ref(rnode, f"static-route {rname} (vr {vrname})")
                dest = str(rnode.get("destination", ""))
                nexthop = rnode.get("nexthop", {})
                gw = ""
                if isinstance(nexthop, dict):
                    gw = str(nexthop.get("ip-address", ""))
                    if not gw:
                        kinds = [k for k in nexthop if k != LINE]
                        self.note("warn", "routes",
                                  f"route {rname}: nexthop {kinds} not "
                                  "convertible — review", ref)
                        continue
                ifc = str(rnode.get("interface", ""))
                if not ifc and gw:
                    ifc = self._egress_for(gw)
                    if ifc:
                        self.note("info", "routes",
                                  f"route {rname}: egress interface "
                                  f"'{ifc}' inferred from connected "
                                  "networks", ref)
                try:
                    net = ipaddress.IPv4Network(dest, strict=False)
                except ValueError:
                    self.note("warn", "routes",
                              f"route {rname}: bad destination '{dest}'",
                              ref)
                    continue
                metric = rnode.get("metric")
                dist = 10
                if isinstance(metric, str) and metric.isdigit():
                    dist = min(int(metric), 255)
                self.cfg.routes.append(Route(
                    dest=str(net), gateway=gw, interface=ifc or "any",
                    distance=dist, source=ref))

    def _egress_for(self, gw: str) -> str:
        try:
            addr = ipaddress.IPv4Address(gw)
        except ValueError:
            return ""
        for itf in self.cfg.interfaces:
            if itf.ip:
                try:
                    if addr in ipaddress.IPv4Interface(itf.ip).network:
                        return itf.name
                except ValueError:
                    continue
        return ""

    def report_unconverted_sections(self, device, vsys, rulebase):
        consumed_vsys = {"zone", "address", "address-group", "service",
                         "service-group", "rulebase", "import", LINE}
        for key, node in list(vsys.items()):
            if key in consumed_vsys or not isinstance(node, dict):
                continue
            n = len(_entries(node)) or 1
            self.note("info", "coverage",
                      f"vsys section '{key}' ({n} entries) not converted",
                      self.ref(node, key))
        if isinstance(rulebase, dict):
            for key, node in rulebase.items():
                if key in ("security", "nat", LINE):
                    continue
                self.note("info", "coverage",
                          f"rulebase '{key}' not converted",
                          self.ref(node if isinstance(node, dict) else {},
                                   key))


def parse(text: str, filename: str = "") -> FirewallConfig:
    return PaloParser(text, filename).parse()
