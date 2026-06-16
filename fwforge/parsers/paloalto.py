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
    # Panorama template-merged running-configs carry a `ptpl="..."`
    # attribute on every tag (<devices ptpl=...>, <entry name="..." ptpl=
    # ...>), so match tag prefixes, not the bare `<devices>` / closing
    # `>`. `urldb="paloaltonetworks"` is an unmistakable PAN-OS signal.
    if "<config" in head and ("<devices" in text
                              or 'urldb="paloaltonetworks"' in head):
        if '<entry name="localhost.localdomain"' in text:
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


class PanoramaChoiceNeeded(ValueError):
    """A Panorama export has several device-groups — the caller must
    pick one (and optionally a template for network config)."""

    def __init__(self, device_groups: list[str], templates: list[str]):
        self.device_groups = device_groups
        self.templates = templates
        super().__init__(
            "Panorama export: pick a device-group "
            f"(available: {', '.join(device_groups)}; "
            f"templates: {', '.join(templates) or 'none'})")


class _Reporter:
    """Adapter so _vpn_common can append findings via a parser's note()."""

    def __init__(self, parser):
        self._p = parser

    def add(self, level, area, msg, ref=None):
        self._p.note(level, area, msg, ref)


class PaloParser:
    def __init__(self, text: str, filename: str = "",
                 vsys: str | None = None,
                 device_group: str | None = None,
                 template: str | None = None):
        self.filename = filename
        self.cfg = FirewallConfig(vendor="paloalto")
        self._findings: list[tuple[str, str, str, SourceRef | None]] = []
        self._want_vsys = vsys
        self._dg = device_group
        self._tmpl = template
        self._sibling_names: list[str] = []
        self._import_ifcs: set[str] | None = None
        self._import_vrs: set[str] | None = None
        self._pre_rules: list = []
        self._post_rules: list = []
        if text.lstrip().startswith("<"):
            tree = _tree_from_xml(text)
        else:
            tree = _tree_from_set_lines(text, self.cfg.unparsed, filename)
        self.tree = tree

    def note(self, level: str, area: str, msg: str,
             ref: SourceRef | None = None):
        if self._want_vsys:
            msg = f"[vsys {self._want_vsys}] {msg}"
        self._findings.append((level, area, msg, ref))

    def ref(self, node, label: str) -> SourceRef:
        return SourceRef(self.filename, _line(node), label)

    # -- scope resolution -----------------------------------------------

    def device_groups(self) -> list[str]:
        """Device-group names when this is a Panorama export."""
        device = self._device_node()
        return [n for n, _ in _entries(device.get("device-group"))]

    def templates(self) -> list[str]:
        device = self._device_node()
        return [n for n, _ in _entries(device.get("template"))]

    def _device_node(self) -> dict:
        devices = self.tree.get("devices")
        if isinstance(devices, dict):
            for _name, node in _entries(devices):
                return node
        return self.tree

    def _merge_scope(self, base: dict, over: dict) -> dict:
        """Section-aware merge: entries of both sides survive within an
        object section (over wins on a same-name entry); a plain
        top-level update would drop e.g. every shared address the
        moment the vsys/device-group defines one of its own."""
        merged = {k: v for k, v in base.items() if k != LINE}
        for k, v in over.items():
            if k == LINE:
                continue
            if k in merged and isinstance(merged[k], dict) \
                    and isinstance(v, dict):
                inner = {kk: vv for kk, vv in merged[k].items()
                         if kk != LINE}
                inner.update({kk: vv for kk, vv in v.items()
                              if kk != LINE})
                merged[k] = inner
            else:
                merged[k] = v
        return merged

    def _rules_of(self, scope, *path) -> list:
        node = scope
        for part in path:
            node = node.get(part) if isinstance(node, dict) else None
            if node is None:
                return []
        return _entries(node)

    def scopes(self) -> tuple[dict, dict]:
        """(device_scope, vsys_scope) for both formats. Also resolves
        Panorama device-group exports and pushed pre/post rulebases."""
        cfg = self.tree
        device = self._device_node()
        self._dev_key = ""
        devices = cfg.get("devices")
        if isinstance(devices, dict):
            for name, _node in _entries(devices):
                self._dev_key = name
                break
        self._vsys_key = ""
        shared = cfg.get("shared")
        shared = shared if isinstance(shared, dict) else {}

        # ---- Panorama export: a device-group plays the vsys role ----
        dgs = device.get("device-group")
        if isinstance(dgs, dict) and _entries(dgs):
            return self._panorama_scopes(device, dgs, shared)

        vsys_scope = device
        vsys = device.get("vsys")
        if isinstance(vsys, dict):
            entries = _entries(vsys)
            if self._want_vsys is not None:
                pick = next((e for e in entries
                             if e[0] == self._want_vsys), None)
                if pick is None:
                    self.note("error", "vsys",
                              f"vsys '{self._want_vsys}' not found")
                    entries = []
                else:
                    vsys_scope = pick[1]
                    self._vsys_key = pick[0]
            elif entries:
                vsys_scope = entries[0][1]
                self._vsys_key = entries[0][0]
                self._sibling_names = [n for n, _ in entries[1:]]
                if self._sibling_names:
                    self.note(
                        "info", "vsys",
                        f"multi-vsys config ({len(entries)} vsys): each "
                        "vsys converts into its own VDOM "
                        f"({', '.join(n for n, _ in entries)})")
        # interface / virtual-router imports scope device-level network
        # to this vsys (only enforced when there are multiple vsys)
        if self._vsys_key and (self._sibling_names or self._want_vsys):
            imp = vsys_scope.get("import", {})
            net = imp.get("network", {}) if isinstance(imp, dict) else {}
            if isinstance(net, dict):
                self._import_ifcs = set(_as_list(net.get("interface")))
                self._import_vrs = set(_as_list(net.get("virtual-router")))

        # Panorama-pushed config on a managed firewall: pre/post
        # rulebases + pushed objects live under /config/panorama
        pano = cfg.get("panorama")
        if isinstance(pano, dict):
            pscopes = [pano]
            pvsys = pano.get("vsys")
            if isinstance(pvsys, dict) and self._vsys_key:
                node = pvsys.get(self._vsys_key)
                if isinstance(node, dict):
                    pscopes.append(node)
            for ps in pscopes:
                self._pre_rules += self._rules_of(
                    ps, "pre-rulebase", "security", "rules")
            # PAN post order: device-group/vsys post BEFORE shared post,
            # so accumulate the pushed scopes in reverse
            for ps in reversed(pscopes):
                self._post_rules += self._rules_of(
                    ps, "post-rulebase", "security", "rules")
            for ps in pscopes:
                # pushed objects merge below local ones
                shared = self._merge_scope(shared, {
                    k: v for k, v in ps.items()
                    if k in ("address", "address-group", "service",
                             "service-group", "application",
                             "application-group", "application-filter")})
            if self._pre_rules or self._post_rules:
                self.note(
                    "info", "panorama",
                    f"Panorama-pushed rulebases merged: "
                    f"{len(self._pre_rules)} pre + local + "
                    f"{len(self._post_rules)} post (PAN evaluation order)")

        # shared objects (Panorama / shared scope) merge in at lower
        # priority
        if shared:
            vsys_scope = self._merge_scope(shared, vsys_scope)
        return device, vsys_scope

    def _panorama_scopes(self, device: dict, dgs: dict,
                         shared: dict) -> tuple[dict, dict]:
        """Panorama export: shared + one device-group form the object/
        rule scope; an optional template supplies network config."""
        names = [n for n, _ in _entries(dgs)]
        if self._dg is None and len(names) == 1:
            self._dg = names[0]
        if self._dg is None or self._dg not in names:
            raise PanoramaChoiceNeeded(names, self.templates())
        dg = dgs[self._dg]
        self._vsys_key = self._dg
        self.cfg.meta["panorama"] = {
            "device_group": self._dg, "device_groups": names,
            "template": self._tmpl or "", "templates": self.templates()}
        self.note("info", "panorama",
                  f"Panorama export: converting device-group "
                  f"'{self._dg}'" + (f" with template '{self._tmpl}'"
                                     if self._tmpl else " (no template — "
                                     "interfaces/zones come from "
                                     "templates; pick one for network "
                                     "config)"))
        self._pre_rules = self._rules_of(
            shared, "pre-rulebase", "security", "rules") + self._rules_of(
            dg, "pre-rulebase", "security", "rules")
        self._post_rules = self._rules_of(
            dg, "post-rulebase", "security", "rules") + self._rules_of(
            shared, "post-rulebase", "security", "rules")
        parent = dg.get("parent-dg")
        if isinstance(parent, str) and parent:
            self.note("warn", "panorama",
                      f"device-group '{self._dg}' inherits from "
                      f"'{parent}' — parent device-group rules/objects "
                      "are NOT merged yet; convert the parent separately")

        scope = self._merge_scope(shared, dg)
        net_device: dict = {}
        if self._tmpl:
            tmpl = device.get("template", {})
            tnode = tmpl.get(self._tmpl) if isinstance(tmpl, dict) else None
            if not isinstance(tnode, dict):
                stacks = self.templates()
                self.note("error", "panorama",
                          f"template '{self._tmpl}' not found "
                          f"(available: {', '.join(stacks) or 'none'})")
            else:
                tcfg = tnode.get("config", {})
                tdevs = tcfg.get("devices", {}) if isinstance(tcfg, dict) \
                    else {}
                for _n, tdev in _entries(tdevs):
                    net_device = tdev
                    break
                # template vsys carries zones (and vsys-ish settings)
                tvsys = net_device.get("vsys")
                if isinstance(tvsys, dict):
                    for _n, tv in _entries(tvsys):
                        if isinstance(tv, dict) and "zone" in tv \
                                and "zone" not in scope:
                            scope = self._merge_scope(
                                {"zone": tv["zone"]}, scope)
                        break
        return net_device, scope

    # -- sections ---------------------------------------------------------

    def parse(self) -> FirewallConfig:
        device, vsys = self.scopes()
        hostname = device.get("deviceconfig", {})
        if isinstance(hostname, dict):
            self.cfg.hostname = str(
                hostname.get("system", {}).get("hostname", "")
                if isinstance(hostname.get("system"), dict) else "")
        if not self.cfg.hostname and self._dg:
            self.cfg.hostname = self._dg

        self.parse_interfaces(device.get("network", {}))
        self.parse_zones(vsys.get("zone"))
        self.parse_addresses(vsys.get("address"))
        self.parse_addr_groups(vsys.get("address-group"))
        self.parse_services(vsys.get("service"))
        self.parse_svc_groups(vsys.get("service-group"))
        self.parse_applications(vsys)
        rulebase = vsys.get("rulebase", {})
        local_rules: list = []
        nat_rules = None
        if isinstance(rulebase, dict):
            sec = rulebase.get("security", {})
            if isinstance(sec, dict):
                local_rules = _entries(sec.get("rules"))
            nat = rulebase.get("nat", {})
            nat_rules = nat.get("rules") if isinstance(nat, dict) else None
        # PAN evaluation order: Panorama pre -> local -> Panorama post
        self.parse_rules_entries(
            self._pre_rules + local_rules + self._post_rules)
        self.parse_nat(nat_rules)
        self.parse_routes(device.get("network", {}))
        self.parse_vpn(device.get("network", {}))
        self.report_unconverted_sections(device, vsys, rulebase)
        if not self._want_vsys:
            self.report_xml_coverage()
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
            # 'no-pfs' is PAN's explicit PFS-off token, not a DH group
            dh = [x.replace("group", "")
                  for x in _as_list(e.get("dh-group")) if x != "no-pfs"]
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
        used_names: set[str] = set()

        for tname, t in tun_entries:
            ref = self.ref(t, f"ipsec tunnel {tname}")
            tif = t.get("tunnel-interface", "")
            if isinstance(tif, str) and tif and not self._imported(tif):
                continue  # tunnel interface belongs to another vsys
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
            if tun_name in used_names:
                # 15-char truncation collided with an earlier tunnel —
                # FortiOS would silently merge the two phase1s
                base = tun_name
                n = 2
                while tun_name in used_names:
                    suffix = f"~{n}"
                    tun_name = base[:15 - len(suffix)] + suffix
                    n += 1
                self.note("warn", "vpn",
                          f"tunnel {tname}: truncated name collided; "
                          f"renamed to {tun_name}", ref)
            used_names.add(tun_name)
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

    def _imported(self, name: str) -> bool:
        """Should the parser ENTER this device-level interface for the
        current vsys — i.e. is the interface itself or any of its
        subinterfaces imported? (Always true when not multi-vsys.)"""
        if self._import_ifcs is None:
            return True
        imps = self._import_ifcs
        return (name in imps
                or any(i.startswith(name + ".") for i in imps))

    def _owns(self, name: str) -> bool:
        """Is THIS exact logical interface's own config owned by the
        current vsys? PAN imports each logical interface (base and each
        subinterface) individually, so ownership is an exact match — a
        base interface is NOT owned just because one of its subinterfaces
        is imported (that would duplicate the base IP into two VDOMs)."""
        return self._import_ifcs is None or name in self._import_ifcs

    def parse_interfaces(self, network):
        if not isinstance(network, dict):
            return
        iface = network.get("interface", {})
        if not isinstance(iface, dict):
            return
        self._agg_members: dict[str, list[str]] = getattr(
            self, "_agg_members", {})
        for family in ("ethernet", "aggregate-ethernet"):
            fam = iface.get(family)
            for name, node in _entries(fam):
                if not self._imported(name):
                    continue
                self._one_interface(name, node,
                                    is_agg=family == "aggregate-ethernet")
        # link aggregate members captured above onto their bundle
        for itf in self.cfg.interfaces:
            if itf.kind == "aggregate" and itf.name in self._agg_members:
                itf.members = self._agg_members[itf.name]
        # vlan/loopback/tunnel interfaces live in a <units> container
        # directly under the family node, and their entries carry <ip>
        # without a <layer3> wrapper
        for family in ("vlan", "loopback", "tunnel"):
            fam = iface.get(family)
            if not isinstance(fam, dict):
                continue
            for uname, unode in _entries(fam.get("units")):
                if not self._owns(uname):
                    continue
                sub = Interface(
                    name=uname,
                    kind="vlan" if family == "vlan" else family,
                    source=self.ref(unode, f"interface {uname}"))
                if isinstance(unode, dict):
                    ips = _as_list(unode.get("ip"))
                    if ips:
                        sub.ip = ips[0]
                    tag = unode.get("tag")
                    if isinstance(tag, str) and tag.isdigit():
                        sub.vlan_id = int(tag)
                    ucomment = unode.get("comment")
                    if isinstance(ucomment, str):
                        sub.description = ucomment
                self.cfg.interfaces.append(sub)

    @staticmethod
    def _lacp_mode(node) -> str | None:
        """FortiOS lacp-mode for a PAN aggregate-ethernet entry: the
        configured mode when LACP is enabled, 'static' when an LACP block
        is present but disabled, or None when there is no LACP config at
        all (the emitter then defaults to active and flags it)."""
        if not isinstance(node, dict):
            return None
        lacp = node.get("lacp")
        if not isinstance(lacp, dict):   # some templates nest it under L2/L3
            for wrap in ("layer3", "layer2"):
                w = node.get(wrap)
                if isinstance(w, dict) and isinstance(w.get("lacp"), dict):
                    lacp = w["lacp"]
                    break
        if not isinstance(lacp, dict):
            return None
        enabled = str(lacp.get("enable", "")).strip().lower() \
            in ("yes", "true", "1")
        if not enabled:
            return "static"
        mode = str(lacp.get("mode", "")).strip().lower()
        return mode if mode in ("active", "passive") else "active"

    def _one_interface(self, name: str, node: dict, is_agg: bool = False):
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
            # a physical port bundled into an aggregate: keep it as a
            # mappable member (it becomes the FortiOS LAG's member port)
            grp = str(node["aggregate-group"])
            self._agg_members.setdefault(grp, [])
            if name not in self._agg_members[grp]:
                self._agg_members[grp].append(name)
            if self._owns(name):
                self.cfg.interfaces.append(Interface(
                    name=name, kind="aggregate-member", parent=grp,
                    source=ref))
            return
        itf = Interface(name=name,
                        kind="aggregate" if is_agg else "physical",
                        source=ref)
        if is_agg:
            itf.lacp_mode = self._lacp_mode(node)
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
                if not self._owns(uname):
                    continue
                sub = Interface(name=uname, parent=name, kind="vlan",
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
        # only emit the base interface's own config into the VDOM that
        # owns it (not every VDOM that merely imports a subinterface)
        if self._owns(name):
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
                if ":" in value:  # IPv6
                    try:
                        net = ipaddress.IPv6Network(
                            value if "/" in value else value + "/128",
                            strict=False)
                    except ValueError:
                        self.note("warn", "addresses",
                                  f"address {name}: '{value}' invalid",
                                  ref)
                        continue
                    if net.prefixlen == 128:
                        self.cfg.addresses.append(Address(
                            name=name, type="host",
                            value=str(net.network_address),
                            comment=comment, source=ref))
                    else:
                        self.cfg.addresses.append(Address(
                            name=name, type="subnet", value=str(net),
                            comment=comment, source=ref))
                    continue
                try:
                    net = ipaddress.IPv4Network(value if "/" in value
                                                else value + "/32",
                                                strict=False)
                except ValueError:
                    self.note("warn", "addresses",
                              f"address {name}: '{value}' invalid", ref)
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

    def parse_applications(self, vsys: dict) -> None:
        """Custom application objects / groups / filters. Custom apps
        carry their own default ports in the file — exact data for
        tightening `service application-default` rules."""
        self._custom_apps: dict[str, list[tuple[str, str]] | None] = {}
        self._app_groups: dict[str, list[str]] = {}
        self._app_filters: set[str] = set()
        for name, node in _entries(vsys.get("application")):
            specs: list[tuple[str, str]] | None = []
            default = node.get("default") if isinstance(node, dict) else None
            if isinstance(default, dict):
                if "ident-by-ip-protocol" in default:
                    proto = str(default["ident-by-ip-protocol"])
                    specs = [("ip", proto)] if proto.isdigit() else None
                elif "ident-by-icmp-type" in default:
                    specs = [("icmp", "")]
                else:
                    port = default.get("port")
                    members = _as_list(port) if port is not None else []
                    for m in members:
                        proto, _, spec = m.partition("/")
                        spec = spec.replace(",", " ").strip()
                        if proto == "icmp":
                            specs.append(("icmp", ""))
                        elif proto in ("tcp", "udp") and spec \
                                and "dynamic" not in spec:
                            specs.append((proto, spec))
                        else:
                            specs = None  # dynamic/unknown -> not tightenable
                            break
                    else:
                        if not members:
                            specs = None
            else:
                specs = None
            self._custom_apps[name] = specs if specs else None
        for name, node in _entries(vsys.get("application-group")):
            self._app_groups[name] = _as_list(
                node.get("members") if isinstance(node, dict)
                and "members" in node else node)
        for name, _node in _entries(vsys.get("application-filter")):
            self._app_filters.add(name)

    def _app_port_specs(self, app: str,
                        seen: set | None = None
                        ) -> list[tuple[str, str]] | None:
        """Default-port specs for one app: the file's own custom
        definitions win, then groups expand, then the curated table."""
        seen = seen or set()
        if app in seen:
            return None
        seen.add(app)
        if app in self._custom_apps:
            return self._custom_apps[app]
        if app in self._app_groups:
            merged: list[tuple[str, str]] = []
            for m in self._app_groups[app]:
                specs = self._app_port_specs(m, seen)
                if specs is None:
                    return None
                merged += specs
            return merged or None
        if app in self._app_filters:
            return None  # criteria-based; membership needs the app DB
        return pan_appid.default_ports(app)

    def _appdefault_services(self, apps: list[str], rule: str,
                             ref: SourceRef) -> list[str] | None:
        """Synthesize tight services for a `service application-default`
        rule. Returns service names, or None when any app's default
        ports are unknown (caller falls back to ALL + warning)."""
        if apps == ["any"] or not apps:
            return None
        # expand application-groups to leaves first so each real app maps
        # individually (ssh inside a group -> built-in SSH, not merged)
        apps = self._expand_app_groups(apps)
        # resolve PER APP (not merged) so each app keeps its own service —
        # a FortiOS BUILT-IN name when there is one (SMB, HTTPS, DNS, ...),
        # else a synthesized custom service from the app's ports
        out: list[str] = []
        unresolved: list[str] = []

        def add(nm: str) -> None:
            if nm not in out:
                out.append(nm)

        for app in apps:
            if app in ("any", "application-default"):
                continue
            builtins = pan_appid.builtin_services(app)
            if builtins:
                for b in builtins:
                    add(b)
                continue
            specs = self._app_port_specs(app)
            if specs is None:
                unresolved.append(app)
                continue
            # merge THIS app's ports by protocol into one service per
            # proto (one tidy object per app), but never across apps
            by_proto: dict[str, set[str]] = {}
            for proto, ports in specs:
                if proto == "icmp":
                    add("ALL_ICMP")
                elif proto == "ip":
                    nm = f"proto_{ports}"
                    if not any(s.name == nm for s in self.cfg.services):
                        self.cfg.services.append(Service(
                            name=nm, protocol="ip",
                            proto_number=int(ports), source=ref))
                    add(nm)
                else:
                    by_proto.setdefault(proto, set()).update(ports.split())
            for proto in sorted(by_proto):
                ports = " ".join(sorted(by_proto[proto],
                                        key=lambda p: int(p.split("-")[0])))
                nm = f"appdef-{proto.replace('/', '')}-" \
                     + ports.replace(" ", "_")
                if not any(s.name == nm for s in self.cfg.services):
                    self.cfg.services.append(Service(
                        name=nm, protocol=proto, dst_ports=ports,
                        comment="from PAN application-default ports",
                        source=ref))
                add(nm)
        if unresolved:
            self.note(
                "warn", "policies",
                f"rule '{rule}': service=application-default kept as ALL "
                f"— no default-port data for: {', '.join(unresolved)} "
                "(dynamic-port or unknown app); tighten manually", ref)
            return None
        return out or None

    def _app_service(self, apps: list[str], rule: str,
                     ref: SourceRef) -> list[str] | None:
        """Convert a rule's App-IDs into the policy SERVICE: the apps'
        resolved port-services, collapsed into a named service GROUP
        (port group) when there is more than one. Returns the service /
        group name(s), or None when any app's ports are unknown (the
        rule then safely stays at ALL — restricting to the known ports
        would wrongly block the unresolved app)."""
        svc_names = self._appdefault_services(apps, rule, ref)
        if not svc_names:
            return None
        svc_names = list(dict.fromkeys(svc_names))
        if len(svc_names) == 1:
            return svc_names
        key = tuple(sorted(svc_names))
        cache = self.cfg.meta.setdefault("_appsvcgrp_cache", {})
        if key not in cache:
            gname = f"appsvc-grp-{len(cache) + 1}"
            self.cfg.svc_groups.append(ServiceGroup(
                name=gname, members=svc_names,
                comment="port group from PAN App-IDs", source=ref))
            cache[key] = gname
        return [cache[key]]

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
        self.parse_rules_entries(_entries(rules))

    def parse_rules_entries(self, entries: list):
        for name, r in entries:
            ref = self.ref(r, f"security rule '{name}'")
            action = str(r.get("action", "allow"))
            apps = _as_list(r.get("application")) or ["any"]
            pan_services = _as_list(r.get("service")) or ["any"]
            # Convert App-IDs into the policy SERVICE (ports / port group).
            # A rule's apps resolve to their standard ports; that service
            # fills the 'any' and 'application-default' slots so the policy
            # is port-based. None when the ports are unknown -> stays ALL.
            app_svc = (self._app_service(apps, name, ref)
                       if apps != ["any"] else None)
            services: list[str] = []
            filled_from_apps = False
            for svc in pan_services:
                if svc in ("any", "application-default"):
                    if app_svc:
                        services.extend(app_svc)
                        filled_from_apps = True
                    else:
                        services.append("ALL")
                else:
                    self._ensure_service(svc, ref)
                    services.append(svc)
            services = list(dict.fromkeys(services)) or ["ALL"]

            comment_bits: list[str] = []
            desc = r.get("description")
            if isinstance(desc, str):
                comment_bits.append(desc)
            # keep app-control on top of the port-based service (both)
            app_list = self._app_list_for(apps, name, ref)
            if apps != ["any"]:
                shown = ", ".join(apps[:6]) + (" ..." if len(apps) > 6
                                               else "")
                comment_bits.append(f"PAN apps: {shown}")
            sched = r.get("schedule")
            if isinstance(sched, str) and sched:
                comment_bits.append(f"PAN schedule: {sched}")
                self.note(
                    "warn", "policies",
                    f"rule '{name}': schedule '{sched}' not converted - "
                    "policy is emitted always-on; recreate a firewall "
                    "schedule and set it on the policy", ref)
            if filled_from_apps:
                how = ("service=application-default"
                       if "application-default" in pan_services
                       else "service=any")
                self.note(
                    "info", "policies",
                    f"rule '{name}': App-IDs -> port-based service "
                    f"{', '.join(app_svc)} ({how}; from the apps' standard "
                    "ports). App-control profile kept on top; verify the "
                    "apps use standard ports.", ref)
            elif "application-default" in pan_services and apps == ["any"]:
                self.note(
                    "warn", "policies",
                    f"rule '{name}' uses service=application-default with "
                    "application=any — converted as ALL, tighten manually",
                    ref)
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

    def _expand_app_groups(self, apps: list[str],
                           seen: set | None = None) -> list[str]:
        """Flatten PAN application-groups to their leaf App-IDs (order-
        preserving, de-duplicated) so the app-control mapping sees the
        real apps a group contains, not the group's custom name. Custom
        application objects and filters stay as-is (no leaf apps to
        map)."""
        seen = seen if seen is not None else set()
        out: list[str] = []
        for a in apps:
            if a in self._app_groups and a not in seen:
                seen.add(a)
                for leaf in self._expand_app_groups(
                        self._app_groups[a], seen):
                    if leaf not in out:
                        out.append(leaf)
            elif a not in out:
                out.append(a)
        return out

    def _app_list_for(self, apps: list[str], rule: str,
                      ref: SourceRef) -> str:
        """Map a rule's PAN App-IDs to a FortiOS application-list profile
        (deduped across rules). Returns the profile name, or ''."""
        if apps == ["any"] or not apps:
            return ""
        # expand application-groups to leaves first — a rule that
        # references a custom group (jabil_serv_mysql_smb_app) should map
        # the apps inside it (mysql, smb), not fail on the group name
        apps = self._expand_app_groups(apps)
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

    def _parse_vr_protocols(self, vrname: str, vr: dict) -> None:
        """Dynamic routing inside a PAN virtual-router -> IR BGP/OSPF."""
        prot = vr.get("protocol")
        if not isinstance(prot, dict):
            return
        from ..model import BgpConfig, BgpNeighbor, OspfArea, OspfConfig
        bgp = prot.get("bgp")
        if isinstance(bgp, dict) and str(bgp.get("enable", "no")) == "yes":
            ref = self.ref(bgp, f"vr {vrname} bgp")
            if self.cfg.bgp is not None:
                self.note("warn", "routing",
                          f"vr '{vrname}': a second BGP instance — only "
                          "the first virtual-router's BGP converted", ref)
            else:
                cfg = BgpConfig(
                    asn=str(bgp.get("local-as", "")) or "0",
                    router_id=str(bgp.get("router-id", "")), source=ref)
                for gname, grp in _entries(bgp.get("peer-group")):
                    for pname, peer in _entries(grp.get("peer")
                                                if isinstance(grp, dict)
                                                else None):
                        pa = peer.get("peer-address", {})
                        ip = str(pa.get("ip", "")) if isinstance(pa, dict) \
                            else ""
                        if not ip:
                            continue
                        cfg.neighbors.append(BgpNeighbor(
                            ip=ip.split("/")[0],
                            remote_as=str(peer.get("peer-as", "")),
                            description=f"{gname}/{pname}",
                            source=self.ref(peer, f"bgp peer {pname}")))
                if "redist-rules" in bgp or "redistribution-profile" in bgp:
                    self.note("warn", "routing",
                              f"vr '{vrname}': BGP redistribution "
                              "profiles not converted — recreate as "
                              "FortiOS redistribute/route-maps", ref)
                self.cfg.bgp = cfg
        ospf = prot.get("ospf")
        if isinstance(ospf, dict) \
                and str(ospf.get("enable", "no")) == "yes":
            ref = self.ref(ospf, f"vr {vrname} ospf")
            if self.cfg.ospf is not None:
                self.note("warn", "routing",
                          f"vr '{vrname}': a second OSPF instance — only "
                          "the first virtual-router's OSPF converted", ref)
                return
            ocfg = OspfConfig(router_id=str(ospf.get("router-id", "")),
                              source=ref)
            for aid, area in _entries(ospf.get("area")):
                a = OspfArea(id=aid, source=self.ref(area, f"area {aid}"))
                for ifname, inode in _entries(area.get("interface")
                                              if isinstance(area, dict)
                                              else None):
                    itf = self.cfg.interface_by_name(ifname)
                    if itf and itf.ip:
                        net = str(ipaddress.ip_interface(itf.ip).network)
                        if net not in a.networks:
                            a.networks.append(net)
                    else:
                        self.note("warn", "routing",
                                  f"OSPF area {aid}: interface {ifname} "
                                  "has no known address — add its network "
                                  "statement manually", a.source)
                    if isinstance(inode, dict) \
                            and str(inode.get("passive", "no")) == "yes":
                        a.passive.append(ifname)
                ocfg.areas.append(a)
            self.cfg.ospf = ocfg

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

    def _resolve_range(self, token: str) -> tuple[str, int] | None:
        """(fortios_range, address_count) for a host / subnet / range
        address object — the form a FortiOS VIP's extip/mappedip want for
        a 1:1 netmap. '10.65.226.0/24' -> ('10.65.226.0-10.65.226.255',
        256). None if it cannot be resolved to IPv4 ranges."""
        val = token
        addr = self.cfg.address_by_name(token)
        if addr:
            if addr.type not in ("host", "subnet", "range"):
                return None
            val = addr.value
        val = (val or "").strip()
        try:
            if "-" in val and "/" not in val:
                lo, hi = (p.strip() for p in val.split("-", 1))
                n = (int(ipaddress.IPv4Address(hi))
                     - int(ipaddress.IPv4Address(lo)) + 1)
                return (f"{lo}-{hi}", n) if n >= 1 else None
            if "/" in val:
                net = ipaddress.ip_network(val, strict=False)
                return (f"{net[0]}-{net[-1]}", net.num_addresses)
            ipaddress.IPv4Address(val)
            return (val, 1)
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
                    # not single hosts — try a 1:1 subnet/range netmap
                    # (PAN /24 -> /24); FortiOS maps equal-length extip and
                    # mappedip ranges one-to-one
                    ext_r = self._resolve_range(dsts[0]) if dsts else None
                    mapped_r = self._resolve_range(
                        str(dt.get("translated-address", "")))
                    if ext_r and mapped_r and ext_r[1] == mapped_r[1]:
                        self.cfg.vips.append(Vip(
                            name=f"vip-{name}", ext_ip=ext_r[0],
                            mapped_ip=mapped_r[0],
                            ext_intf=self._zone_single_member(frm[0]),
                            comment=f"from PAN 1:1 subnet destination NAT "
                                    f"'{name}'", source=ref))
                        self.note(
                            "info", "nat",
                            f"nat rule '{name}': 1:1 subnet destination NAT "
                            f"{ext_r[0]} -> {mapped_r[0]} ({ext_r[1]} "
                            "addresses) converted to a range VIP — FortiOS "
                            "maps the ranges one-to-one", ref)
                        handled = True
                    elif ext_r and mapped_r:
                        self.note(
                            "error", "nat",
                            f"nat rule '{name}': destination NAT maps "
                            f"{ext_r[1]} addresses to {mapped_r[1]} — sizes "
                            "differ, cannot 1:1 map; convert manually", ref)
                    else:
                        self.note(
                            "error", "nat",
                            f"nat rule '{name}': destination NAT could not "
                            "be resolved to host IPs or a 1:1 subnet — "
                            "convert manually", ref)

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
            if self._import_vrs is not None \
                    and vrname not in self._import_vrs:
                continue  # virtual-router belongs to another vsys
            self._parse_vr_protocols(vrname, vr)
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

    def _claim_template(self, dev: tuple, claims: set) -> None:
        """Claim only the network/* and vsys/*/zone subtrees actually
        read from the selected template, by their real tree paths."""
        tnode = self.tree
        for part in dev + ("template", self._tmpl, "config", "devices"):
            tnode = tnode.get(part) if isinstance(tnode, dict) else None
            if tnode is None:
                return
        base = dev + ("template", self._tmpl, "config", "devices")
        for dname, dnode in _entries(tnode):
            dbase = base + (dname,)
            for sub in ("interface", "virtual-router", "ike", "tunnel"):
                claims.add(dbase + ("network", sub))
            tvsys = dnode.get("vsys") if isinstance(dnode, dict) else None
            for vname, _vn in _entries(tvsys):
                claims.add(dbase + ("vsys", vname, "zone"))

    # subtree paths the parse functions consume; everything outside these
    # shows up in the coverage map
    def _claims(self) -> set[tuple]:
        dev = ("devices", self._dev_key) if self._dev_key else ()
        claims: set[tuple] = set()
        vsys_parts = ("zone", "address", "address-group", "service",
                      "service-group", "application", "application-group",
                      "application-filter", "import")
        for part in vsys_parts:
            claims.add(("shared", part))
        if self._dg:
            dg = dev + ("device-group", self._dg)
            for part in vsys_parts:
                claims.add(dg + (part,))
            for rb in ("pre-rulebase", "post-rulebase"):
                claims.add(dg + (rb, "security"))
                claims.add(("shared", rb, "security"))
            if self._tmpl:
                # only the template's network + zone subtrees are read;
                # claim them by their REAL paths (discovered from the
                # tree) so unread template config (log-settings, snmp,
                # ...) still shows as unread
                self._claim_template(dev, claims)
            return claims
        for sub in ("interface", "virtual-router", "ike", "tunnel"):
            claims.add(dev + ("network", sub))
        claims.add(dev + ("deviceconfig", "system", "hostname"))
        # every vsys is consumed — siblings convert into their own VDOMs
        for vn in [self._vsys_key] + self._sibling_names:
            if not vn:
                continue
            vs = dev + ("vsys", vn)
            for part in vsys_parts:
                claims.add(vs + (part,))
            for rb in ("security", "nat"):
                claims.add(vs + ("rulebase", rb))
        # Panorama-pushed config on a managed firewall
        for rb in ("pre-rulebase", "post-rulebase"):
            claims.add(("panorama", rb, "security"))
        claims.add(("panorama", "vsys"))
        for part in vsys_parts:
            claims.add(("panorama", part))
        return claims

    def _leaves(self, node) -> int:
        if isinstance(node, dict):
            n = sum(self._leaves(v) for k, v in node.items() if k != LINE)
            return n or 1
        if isinstance(node, list):
            return len(node) or 1
        return 1

    def report_xml_coverage(self) -> None:
        """Quantified nothing-dropped-silently: walk the WHOLE config
        tree, count leaf values under subtrees the parser consumed vs
        everything else, and name the unread subtrees."""
        claims = self._claims()

        def walk(path: tuple, node) -> tuple[int, list]:
            if path in claims:
                return self._leaves(node), []
            if not isinstance(node, dict):
                return 0, [(path, self._leaves(node))]
            claimed = 0
            unread: list = []
            for k, v in node.items():
                if k == LINE:
                    continue
                c, u = walk(path + (k,), v)
                claimed += c
                unread += u
            if claimed == 0 and unread:
                # nothing below was read: report the whole subtree once
                return 0, [(path, sum(n for _, n in unread))]
            return claimed, unread

        claimed, unread = walk((), self.tree)
        total = claimed + sum(n for _, n in unread)
        if not total:
            return
        pct = 100.0 * claimed / total
        unread.sort(key=lambda x: -x[1])
        self.cfg.meta["xml_coverage"] = (
            f"{pct:.0f}% of {total} config values read by the converter")
        shown = 0
        for path, n in unread:
            if shown >= 15:
                rest = len(unread) - shown
                self.note("info", "coverage",
                          f"... {rest} further unread subtree(s); see "
                          "xml_coverage in the report meta")
                break
            label = "/".join(path) or "(root)"
            self.note("info", "coverage",
                      f"unread subtree: {label} ({n} value(s)) — nothing "
                      "here was converted or flagged individually")
            shown += 1
        if unread:
            self.note(
                "warn", "coverage",
                f"XML coverage: {pct:.0f}% — {total - claimed} of {total} "
                f"config values sit in {len(unread)} subtree(s) the "
                "converter does not read; review the unread list")
        else:
            self.note("info", "coverage",
                      f"XML coverage: 100% — all {total} config values "
                      "were inside subtrees the converter reads")

    def report_unconverted_sections(self, device, vsys, rulebase):
        consumed_vsys = {"zone", "address", "address-group", "service",
                         "service-group", "rulebase", "import",
                         "application", "application-group",
                         "application-filter",
                         # device-group / Panorama mode: these ARE read
                         "pre-rulebase", "post-rulebase", "parent-dg",
                         LINE}
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


def parse(text: str, filename: str = "",
          vsys: str | None = None,
          device_group: str | None = None,
          template: str | None = None) -> FirewallConfig:
    p = PaloParser(text, filename, vsys=vsys,
                   device_group=device_group, template=template)
    cfg = p.parse()
    if p._sibling_names and vsys is None:
        # multi-vsys: every additional vsys parses into its own
        # FirewallConfig; the pipeline turns the set into VDOM blocks
        cfgs = [(p._vsys_key, cfg)]
        for n in p._sibling_names:
            sib = PaloParser(text, filename, vsys=n,
                             device_group=device_group, template=template)
            cfgs.append((n, sib.parse()))
        cfg.meta["vsys_cfgs"] = cfgs
    return cfg
