"""Juniper SRX (Junos) configuration parser -> fwforge IR.

Accepts both Junos export formats and normalizes them into one tree:

- curly-brace hierarchy (`show configuration`)
- `set` lines (`show configuration | display set`)

SRX is zone-based like FortiOS, so the conversion is comparatively clean:
security zones -> zones, zone-pair `from-zone A to-zone B` policies ->
FortiOS policies with srcintf/dstintf, route-based `st0` IPsec ->
phase1/2-interface, source/destination/static NAT -> nat enable / VIPs.

Smoothness features that a naive converter misses, handled here:
- **apply-groups** inheritance is expanded before parsing (a Junos config
  is half-invisible otherwise)
- **zone address books** are scoped per zone; cross-zone name collisions
  are flattened with rename findings
- **junos-* predefined applications** resolve to real ports (junos_apps)
- both formats produce an identical tree (a parity test guards it)

v1 scope flags rather than converts: routing-instances (each is a VDOM —
queued), application-sets nesting depth beyond one level is handled,
chassis-cluster/redundancy and dynamic routing are reported.
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
    Service,
    ServiceGroup,
    SourceRef,
    Vip,
    Zone,
)
from . import _vpn_common as vpn
from . import junos_apps


# --- tree node --------------------------------------------------------------

class JNode:
    """A Junos config node: named sub-containers plus terminal leaves.

    containers: list of (key-tuple, JNode) where the key-tuple is the
    tokens before the `{` (e.g. ("security-zone", "trust")).
    leaves: list of token lists for terminal `... ;` statements.
    """

    __slots__ = ("containers", "leaves", "line")

    def __init__(self, line: int = 0):
        self.containers: list[tuple[tuple, JNode]] = []
        self.leaves: list[list[str]] = []
        self.line = line

    def get(self, *key) -> "JNode | None":
        for k, node in self.containers:
            if k == key:
                return node
        return None

    def find(self, first: str):
        """Yield (key-tuple, node) for containers whose key starts with
        `first` (e.g. every 'security-zone <name>')."""
        for k, node in self.containers:
            if k and k[0] == first:
                yield k, node

    def has_leaf(self, first: str) -> bool:
        return any(toks and toks[0] == first for toks in self.leaves)

    def leaf(self, first: str) -> list[str] | None:
        """Tokens after `first` for the first matching leaf."""
        for toks in self.leaves:
            if toks and toks[0] == first:
                return toks[1:]
        return None

    def leaf_str(self, first: str, default: str = "") -> str:
        v = self.leaf(first)
        return " ".join(v) if v else default

    def leaf_all(self, first: str) -> list[list[str]]:
        return [toks[1:] for toks in self.leaves if toks and toks[0] == first]


# --- tokenizer + curly reader ----------------------------------------------

_TOKEN = re.compile(r'"[^"]*"|[{};]|[^\s{};]+')


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)   # /* ... */
    out = []
    for line in text.splitlines():
        s = line.lstrip()
        if s.startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


def _line_starts(text: str) -> list[int]:
    pos = [0]
    for ch in text:
        pos.append(pos[-1] + 1)
    return pos


def _tree_from_curly(text: str) -> JNode:
    text = _strip_comments(text)
    root = JNode()
    stack = [root]
    cur: list[str] = []
    cur_line = 1
    line = 1
    i = 0
    for m in _TOKEN.finditer(text):
        line += text.count("\n", i, m.start())
        i = m.start()
        tok = m.group(0)
        if tok == "{":
            node = JNode(cur_line)
            stack[-1].containers.append((tuple(_clean(t) for t in cur), node))
            stack.append(node)
            cur = []
        elif tok == ";":
            if cur:
                stack[-1].leaves.append([_clean(t) for t in cur])
            cur = []
        elif tok == "}":
            cur = []
            if len(stack) > 1:
                stack.pop()
        else:
            if not cur:
                cur_line = line
            cur.append(tok)
    _coalesce(root)
    return root


def _coalesce(node: JNode) -> None:
    """Merge sibling containers that share a key (Junos lets the same
    stanza be opened more than once; the curly reader would otherwise
    keep them separate)."""
    merged: list[tuple[tuple, JNode]] = []
    index: dict[tuple, JNode] = {}
    for key, child in node.containers:
        if key in index:
            index[key].leaves.extend(child.leaves)
            index[key].containers.extend(child.containers)
        else:
            index[key] = child
            merged.append((key, child))
    node.containers = merged
    for _key, child in merged:
        _coalesce(child)


def _clean(tok: str) -> str:
    if len(tok) >= 2 and tok[0] == '"' and tok[-1] == '"':
        return tok[1:-1]
    return tok


# --- set-format reader (builds the SAME tree) ------------------------------

# keywords that open a sub-container taking no name token
_PLAIN = {
    "security", "policies", "applications", "nat", "source", "destination",
    "static", "ike", "ipsec", "routing-options", "routing-instances",
    "address-book", "match", "then", "source-nat", "destination-nat",
    "static-nat", "system", "groups", "zones", "global", "proposals",
    "traceoptions", "screen", "flow", "forwarding-options", "interfaces",
    "vlans", "protocols", "scheduler", "schedulers", "bgp", "ospf",
    "advanced-policy-based-routing", "tcp-options", "permit", "deny",
}
# keywords that open a sub-container consuming the next token as its name
_NAMED = {
    "security-zone", "policy", "rule-set", "rule", "application",
    "application-set", "address-set", "proposal", "vpn",
    "unit", "family", "profile", "pool", "route", "instance",
    "scheduler", "traffic-selector", "area", "group", "neighbor",
}
# parents whose immediate child token is a bare-name container
_BARE_NAME_PARENT = {"interfaces", "routing-instances", "vlans", "groups"}
# leaf keywords: everything after them on the line is the value
_LEAF = {
    "source-address", "destination-address", "source-port",
    "destination-port", "application", "protocol", "next-hop", "address",
    "pre-shared-key", "ike-policy", "ipsec-policy", "external-interface",
    "bind-interface", "perfect-forward-secrecy", "proposals",
    "authentication-method", "authentication-algorithm",
    "encryption-algorithm", "dh-group", "lifetime-seconds", "version",
    "mode", "local-ip", "remote-ip", "local", "remote", "prefix",
    "routing-instance", "interface", "off", "log", "count",
    "system-services", "host-inbound-traffic", "no-nat-traversal",
    "establish-tunnels", "df-bit", "vlan-id", "vlan-tagging", "mtu",
    "description", "disable", "inactive", "then", "deactivate",
}


def _is_set_format(text: str) -> bool:
    """A `display set` config is a flat list of `set ...` lines (no
    braces); a hierarchical config has braces and no leading `set `."""
    for raw in _strip_comments(text).splitlines():
        s = raw.strip()
        if not s:
            continue
        return s.startswith(("set ", "deactivate "))
    return False


def _set_tokens(line: str) -> list[str]:
    toks: list[str] = []
    for m in _TOKEN.finditer(line):
        t = m.group(0)
        if t in "{};":
            continue
        toks.append(_clean(t))
    return toks


def _tree_from_set(text: str) -> JNode:
    text = _strip_comments(text)
    root = JNode()
    lineno = 0
    for raw in text.splitlines():
        lineno += 1
        s = raw.strip()
        if not s:
            continue
        toks = _set_tokens(s)
        if not toks or toks[0] not in ("set", "deactivate"):
            continue
        inactive = toks[0] == "deactivate"
        toks = toks[1:]
        if not toks:
            continue
        _insert_set(root, toks, lineno, inactive)
    return root


def _is_named(tok: str, path: list[str]) -> bool:
    """Whether `tok` opens a name-consuming container in this context.
    Several Junos keywords are a named container in one place and a leaf
    reference in another:
    - `gateway`: container under `security ike`, leaf under `ipsec vpn`
    - `application`: container under `applications` (definition), leaf
      under `match` / `application-set` (reference)"""
    if tok == "gateway":
        return "vpn" not in path
    if tok == "application":
        return bool(path) and path[-1] == "applications"
    return tok in _NAMED


def _insert_set(root: JNode, toks: list[str], lineno: int,
                inactive: bool) -> None:
    node = root
    path: list[str] = []
    i = 0
    n = len(toks)
    while i < n:
        t = toks[i]
        # from-zone X to-zone Y  -> a single 4-token container key
        if t == "from-zone" and i + 3 < n and toks[i + 2] == "to-zone":
            key = ("from-zone", toks[i + 1], "to-zone", toks[i + 3])
            node = _descend(node, key, lineno)
            path.append("from-zone")
            i += 4
            continue
        if _is_named(t, path) and i + 1 < n:
            node = _descend(node, (t, toks[i + 1]), lineno)
            path.append(t)
            i += 2
            continue
        if t in _PLAIN:
            node = _descend(node, (t,), lineno)
            path.append(t)
            i += 1
            # bare-name child container (interfaces ge-0/0/0, instances)
            if t in _BARE_NAME_PARENT and i < n \
                    and toks[i] not in _LEAF and toks[i] not in _PLAIN:
                node = _descend(node, (toks[i],), lineno)
                path.append(toks[i])
                i += 1
            continue
        # otherwise: a leaf (this token + the remainder)
        leaf = toks[i:]
        if inactive:
            leaf = ["inactive"] + leaf
        node.leaves.append(leaf)
        return


def _descend(node: JNode, key: tuple, lineno: int) -> JNode:
    for k, child in node.containers:
        if k == key:
            return child
    child = JNode(lineno)
    node.containers.append((key, child))
    return child


# --- apply-groups expansion -------------------------------------------------

def _expand_groups(root: JNode, reporter) -> None:
    """Merge `groups { NAME { ... } }` into the tree wherever
    `apply-groups NAME` appears. v1 handles top-level apply-groups and
    direct group bodies; wildcard interface groups (`<*>`) are flagged."""
    groups_node = root.get("groups")
    if groups_node is None:
        return
    groups: dict[str, JNode] = {}
    for key, node in groups_node.containers:
        if len(key) == 1:
            groups[key[0]] = node
    applied = [g for toks in root.leaf_all("apply-groups") for g in toks]
    if not applied:
        # apply-groups can be nested; v1 only auto-applies top-level
        nested = _has_nested_apply_groups(root)
        if nested:
            reporter("warn", "groups",
                     "apply-groups used inside nested stanzas — only "
                     "top-level groups auto-expanded; verify inherited "
                     "config converted")
        return
    merged = 0
    for gname in applied:
        g = groups.get(gname)
        if g is None:
            reporter("warn", "groups",
                     f"apply-groups '{gname}' has no matching group "
                     "definition — skipped")
            continue
        if any("<" in k0 for k, _ in g.containers for k0 in k):
            reporter("warn", "groups",
                     f"group '{gname}' uses wildcard matching (<*>) — "
                     "not expanded; apply its settings manually")
        _merge_into(root, g)
        merged += 1
    if merged:
        reporter("info", "groups",
                 f"apply-groups expanded {merged} top-level group(s): "
                 f"{', '.join(applied)}")


def _has_nested_apply_groups(node: JNode, depth: int = 0) -> bool:
    if depth and node.has_leaf("apply-groups"):
        return True
    return any(_has_nested_apply_groups(c, depth + 1)
               for _k, c in node.containers)


def _merge_into(dst: JNode, src: JNode) -> None:
    """Deep-merge src's containers/leaves into dst (dst wins on leaf
    conflicts — explicit config overrides inherited group config)."""
    for key, snode in src.containers:
        existing = None
        for k, node in dst.containers:
            if k == key:
                existing = node
                break
        if existing is None:
            dst.containers.append((key, snode))
        else:
            _merge_into(existing, snode)
    have = {tuple(t) for t in dst.leaves}
    for leaf in src.leaves:
        if tuple(leaf) not in have:
            dst.leaves.append(leaf)


# --- detection --------------------------------------------------------------

def detect(text: str) -> float:
    head = text[:8000]
    score = 0.0
    if re.search(r"^\s*security\s*\{", text, re.M) \
            and "from-zone" in text:
        score = 0.9
    elif re.search(r"set security (zones|policies|nat) ", text):
        score = 0.9
    elif "security-zone" in head and ("host-inbound-traffic" in text
                                      or "address-book" in text):
        score = 0.8
    elif re.search(r"^\s*system\s*\{", text, re.M) \
            and "host-name" in head and "junos" in text.lower():
        score = 0.5
    return score


# --- parser -----------------------------------------------------------------

class JunosParser:
    def __init__(self, text: str, filename: str = ""):
        self.filename = filename
        self.cfg = FirewallConfig(vendor="juniper-srx")
        self._findings: list[tuple[str, str, str, SourceRef | None]] = []
        if _is_set_format(text):
            self.tree = _tree_from_set(text)
            self._fmt = "set"
        else:
            self.tree = _tree_from_curly(text)
            self._fmt = "curly"
        _expand_groups(self.tree, self.note)
        # zone-book address name -> flattened global name
        self._addr_alias: dict[tuple[str, str], str] = {}

    def note(self, level: str, area: str, msg: str,
             ref: SourceRef | None = None):
        self._findings.append((level, area, msg, ref))

    def ref(self, node: JNode | None, label: str) -> SourceRef:
        return SourceRef(self.filename, node.line if node else 0, label)

    # -- entry ----------------------------------------------------------

    def parse(self) -> FirewallConfig:
        sec = self.tree.get("security")
        self._sec = sec or JNode()
        self.parse_system()
        self.parse_interfaces()
        self.parse_applications()
        self.parse_zones_and_books()
        self.parse_policies()
        self.parse_nat()
        self.parse_routes()
        self.parse_protocols()
        self.parse_vpn()
        self.flag_routing_instances()
        self.report_coverage()
        self.cfg.meta["findings"] = self._findings
        return self.cfg

    # -- system ---------------------------------------------------------

    def parse_system(self) -> None:
        sysn = self.tree.get("system")
        if sysn:
            host = sysn.leaf_str("host-name")
            if host:
                self.cfg.hostname = host

    # -- interfaces -----------------------------------------------------

    def parse_interfaces(self) -> None:
        ifs = self.tree.get("interfaces")
        if ifs is None:
            return
        for key, dev in ifs.containers:
            if not key:
                continue
            devname = key[0]
            for ukey, unit in dev.find("unit"):
                uno = ukey[1] if len(ukey) > 1 else "0"
                full = f"{devname}.{uno}"
                descr = unit.leaf_str("description") or None
                vid = unit.leaf_str("vlan-id")
                vlan = int(vid) if vid.isdigit() else None
                ipaddr = ""
                inet = unit.get("family", "inet")
                if inet is not None:
                    for atoks in inet.leaf_all("address"):
                        if atoks:
                            ipaddr = atoks[0]
                            break
                    if not ipaddr:
                        for akey, _an in inet.find("address"):
                            if len(akey) > 1:
                                ipaddr = akey[1]
                                break
                # a VLAN sub-interface only when it carries an explicit
                # vlan-id; a bare `unit 0` is a plain L3 interface (never
                # emit vlanid 0, which FortiOS rejects)
                self.cfg.interfaces.append(Interface(
                    name=full, ip=ipaddr or None, description=descr,
                    vlan_id=vlan,
                    parent=devname if vlan is not None else None,
                    source=self.ref(unit, f"interface {full}")))

    # -- applications ---------------------------------------------------

    def parse_applications(self) -> None:
        apps = self.tree.get("applications")
        self._app_specs: dict[str, list[tuple[str, str]] | None] = {}
        self._app_sets: dict[str, list[str]] = {}
        if apps is None:
            return
        for key, app in apps.find("application"):
            if len(key) < 2:
                continue
            name = key[1]
            self._app_specs[name] = self._app_to_specs(app)
        for key, aset in apps.find("application-set"):
            if len(key) < 2:
                continue
            self._app_sets[key[1]] = [
                t[0] for t in aset.leaf_all("application") if t]

    def _app_to_specs(self, app: JNode) -> list[tuple[str, str]] | None:
        # an application can be a single term or a set of `term` blocks
        terms = list(app.find("term"))
        specs: list[tuple[str, str]] = []
        sources = [app] + [t for _k, t in terms]
        for node in sources:
            proto = node.leaf_str("protocol").lower()
            if not proto:
                continue
            if proto in ("tcp", "udp"):
                dport = node.leaf_str("destination-port")
                if not dport:
                    return None
                specs.append((proto, self._port(dport)))
            elif proto in ("icmp", "icmp6", "icmpv6"):
                specs.append(("icmp", ""))
            elif proto.isdigit():
                specs.append(("ip", proto))
            else:
                return None  # ALG / unknown -> not tightenable
        return specs or None

    @staticmethod
    def _port(spec: str) -> str:
        # "8000-8002" or "443" or "80" ; Junos uses '-' for ranges
        return spec.replace(" ", "")

    def _resolve_app(self, name: str,
                     seen: set | None = None) -> list[tuple[str, str]] | None:
        seen = seen or set()
        if name in seen:
            return None
        seen.add(name)
        if name in self._app_specs:
            return self._app_specs[name]
        if name in self._app_sets:
            merged: list[tuple[str, str]] = []
            for m in self._app_sets[name]:
                s = self._resolve_app(m, seen)
                if s is None:
                    return None
                merged += s
            return merged or None
        return junos_apps.junos_app(name)

    def _service_names_for(self, apps: list[str], rule: str,
                           ref: SourceRef) -> list[str]:
        """Resolve a policy's applications to FortiOS service names,
        synthesizing custom services from ports."""
        if not apps or apps == ["any"]:
            return ["ALL"]
        out: list[str] = []
        unresolved: list[str] = []
        for app in apps:
            if app == "any":
                return ["ALL"]
            specs = self._resolve_app(app)
            if specs is None:
                unresolved.append(app)
                continue
            out += [self._ensure_service(app, specs, ref)]
        if unresolved:
            self.note("warn", "services",
                      f"policy '{rule}': application(s) "
                      f"{', '.join(unresolved)} have no port definition "
                      "(custom ALG or unknown junos-*) — service set to "
                      "ALL for those; define them on the FortiGate", ref)
            out.append("ALL")
        # dedup, keep order
        seen: set[str] = set()
        return [s for s in out if not (s in seen or seen.add(s))]

    def _ensure_service(self, name: str, specs: list[tuple[str, str]],
                        ref: SourceRef) -> str:
        # one Service per (name); multi-proto specs become a group
        clean = name.replace("junos-", "")
        if len(specs) == 1:
            proto, ports = specs[0]
            return self._single_service(clean, proto, ports, ref)
        members = []
        for i, (proto, ports) in enumerate(specs, 1):
            members.append(self._single_service(
                f"{clean}-{proto}{i}", proto, ports, ref))
        if not any(g.name == clean for g in self.cfg.svc_groups):
            self.cfg.svc_groups.append(ServiceGroup(
                name=clean, members=members,
                comment=f"from Junos application {name}", source=ref))
        return clean

    def _single_service(self, name: str, proto: str, ports: str,
                        ref: SourceRef) -> str:
        if proto == "icmp":
            return "ALL_ICMP"
        if proto == "ip":
            nm = f"proto-{ports}"
            if not any(s.name == nm for s in self.cfg.services):
                self.cfg.services.append(Service(
                    name=nm, protocol="ip", proto_number=int(ports),
                    source=ref))
            return nm
        if not any(s.name == name for s in self.cfg.services):
            self.cfg.services.append(Service(
                name=name, protocol=proto,
                dst_ports=ports.replace(",", " "), source=ref))
        return name

    # -- zones + address books ------------------------------------------

    def parse_zones_and_books(self) -> None:
        zones = self._sec.get("zones")
        # global address book: `address-book { global { address ... } }`
        # or the older flat `address-book { address ... }`
        abook = self._sec.get("address-book")
        if abook is not None:
            gnode = abook.get("global")
            self._read_book(gnode if gnode is not None else abook,
                            scope="", ref_label="global address-book")
        if zones is None:
            return
        for key, zn in zones.find("security-zone"):
            if len(key) < 2:
                continue
            zname = key[1]
            members = []
            ifn = zn.get("interfaces")
            if ifn is not None:
                for toks in ifn.leaves:
                    if toks:
                        members.append(toks[0])
                for ikey, _ in ifn.containers:
                    if ikey:
                        members.append(ikey[0])
            self.cfg.zones.append(Zone(
                name=zname, members=members,
                source=self.ref(zn, f"zone {zname}")))
            book = zn.get("address-book")
            if book is not None:
                self._read_book(book, scope=zname,
                                ref_label=f"zone {zname} address-book")

    def _book_name(self, scope: str, name: str, ref: SourceRef) -> str:
        """Flatten a (possibly zone-scoped) book entry to a global IR
        name, renaming on cross-zone collision."""
        if not any(a.name == name for a in self.cfg.addresses) \
                and not any(g.name == name for g in self.cfg.addr_groups):
            final = name
        elif (scope, name) in self._addr_alias:
            return self._addr_alias[(scope, name)]
        else:
            final = f"{scope}_{name}" if scope else name
            if final != name:
                self.note("info", "addresses",
                          f"address '{name}' exists in more than one zone "
                          f"book — zone '{scope}' copy renamed '{final}'",
                          ref)
        self._addr_alias[(scope, name)] = final
        return final

    def _read_book(self, book: JNode, scope: str, ref_label: str) -> None:
        ref = self.ref(book, ref_label)
        for key, anode in book.find("address"):
            if len(key) < 2:
                continue
            name = key[1]
            val = self._addr_value(anode, key)
            if val:
                self._add_address(scope, name, val, anode, ref)
        for atoks in book.leaf_all("address"):
            if len(atoks) >= 2:
                self._add_address(scope, atoks[0], atoks[1:], book, ref)
        for key, aset in book.find("address-set"):
            if len(key) < 2:
                continue
            sname = key[1]
            members = []
            for mt in aset.leaf_all("address"):
                if mt:
                    members.append(self._alias(scope, mt[0]))
            for mt in aset.leaf_all("address-set"):
                if mt:
                    members.append(self._alias(scope, mt[0]))
            gname = self._book_name(scope, sname, ref)
            self.cfg.addr_groups.append(AddressGroup(
                name=gname, members=members,
                source=self.ref(aset, f"address-set {sname}")))

    def _alias(self, scope: str, name: str) -> str:
        return self._addr_alias.get((scope, name),
                                    self._addr_alias.get(("", name), name))

    def _addr_value(self, anode: JNode, key: tuple) -> list[str] | None:
        # `address NAME 10.0.0.0/24;` -> value in the key tail
        if len(key) > 2:
            return list(key[2:])
        dns = anode.leaf_str("dns-name")
        if dns:
            return ["__fqdn__", dns]
        rng = anode.get("range-address")
        if anode.has_leaf("range-address"):
            return ["__range__"] + (anode.leaf("range-address") or [])
        wc = anode.leaf("wildcard-address")
        if wc:
            return ["__wild__"] + wc
        return None

    def _add_address(self, scope: str, name: str, val: list[str],
                     node: JNode, ref: SourceRef) -> None:
        gname = self._book_name(scope, name, ref)
        if not val:
            return
        if val[0] == "__fqdn__":
            self.cfg.addresses.append(Address(
                name=gname, type="fqdn", value=val[1], source=ref))
            return
        if val[0] == "__range__":
            # `range-address LOW to HIGH`
            toks = [t for t in val[1:] if t != "to"]
            if len(toks) >= 2:
                self.cfg.addresses.append(Address(
                    name=gname, type="range",
                    value=f"{toks[0]}-{toks[1]}", source=ref))
            return
        if val[0] == "__wild__":
            self.note("warn", "addresses",
                      f"address '{name}' is a wildcard (non-contiguous "
                      "mask) — FortiOS needs a wildcard-type address; "
                      "set it manually", ref)
            return
        cidr = val[0]
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            self.note("warn", "addresses",
                      f"address '{name}': unrecognized value '{cidr}'",
                      ref)
            return
        if net.prefixlen in (32, 128):
            self.cfg.addresses.append(Address(
                name=gname, type="host",
                value=str(net.network_address), source=ref))
        else:
            self.cfg.addresses.append(Address(
                name=gname, type="subnet", value=str(net), source=ref))

    def _addr_ref(self, scope: str, token: str) -> str:
        if token in ("any", "any-ipv4", "any-ipv6"):
            return "all"
        return self._alias(scope, token)

    # -- policies -------------------------------------------------------

    def parse_policies(self) -> None:
        pols = self._sec.get("policies")
        if pols is None:
            return
        for key, zp in pols.find("from-zone"):
            if len(key) < 4:
                continue
            src_zone, dst_zone = key[1], key[3]
            for pkey, pol in zp.find("policy"):
                if len(pkey) < 2:
                    continue
                self._one_policy(pkey[1], pol, src_zone, dst_zone)
        gl = pols.get("global")
        if gl is not None:
            for pkey, pol in gl.find("policy"):
                if len(pkey) < 2:
                    continue
                self._one_policy(pkey[1], pol, "any", "any", glob=True)

    def _one_policy(self, name: str, pol: JNode, src_zone: str,
                    dst_zone: str, glob: bool = False) -> None:
        ref = self.ref(pol, f"policy {name}")
        match = pol.get("match") or JNode()
        then = pol.get("then") or JNode()
        src = [t for ts in match.leaf_all("source-address") for t in ts]
        dst = [t for ts in match.leaf_all("destination-address")
               for t in ts]
        apps = [t for ts in match.leaf_all("application") for t in ts]
        src_scope = "" if glob else src_zone
        dst_scope = "" if glob else dst_zone
        src_addrs = [self._addr_ref(src_scope, t) for t in src] or ["all"]
        dst_addrs = [self._addr_ref(dst_scope, t) for t in dst] or ["all"]
        # negation
        src_neg = match.has_leaf("source-address-excluded")
        dst_neg = match.has_leaf("destination-address-excluded")
        action = "accept" if then.has_leaf("permit") \
            or then.get("permit") is not None else "deny"
        if then.has_leaf("reject"):
            action = "deny"
        log = then.get("log") is not None or then.has_leaf("log")
        disabled = pol.has_leaf("inactive") or any(
            l and l[0] == "inactive" for l in pol.leaves)
        services = self._service_names_for(apps, name, ref)
        comment_bits = []
        descr = pol.leaf_str("description")
        if descr:
            comment_bits.append(descr)
        if glob:
            comment_bits.append("Junos global policy")
        if then.get("permit") is not None:
            permit = then.get("permit")
            if permit.get("tunnel") is not None \
                    or permit.has_leaf("tunnel"):
                self.note("info", "policies",
                          f"policy '{name}': permit tunnel (policy-based "
                          "VPN) — convert to a route-based tunnel; the "
                          "policy is emitted as a normal accept", ref)
            if permit.get("application-services") is not None:
                self.note("info", "policies",
                          f"policy '{name}': UTM/application-services "
                          "profile not converted — attach FortiOS "
                          "security profiles manually", ref)
        pol_obj = Policy(
            name=name, src_zones=[src_zone], dst_zones=[dst_zone],
            src_addrs=src_addrs, dst_addrs=dst_addrs, services=services,
            action=action, log=log, disabled=disabled,
            src_negate=src_neg, dst_negate=dst_neg,
            comment="; ".join(comment_bits)[:1023] or None, source=ref)
        self.cfg.policies.append(pol_obj)

    # -- NAT ------------------------------------------------------------

    def parse_nat(self) -> None:
        nat = self._sec.get("nat")
        if nat is None:
            return
        self._parse_src_nat(nat.get("source"))
        self._parse_dst_nat(nat.get("destination"))
        self._parse_static_nat(nat.get("static"))

    def _from_to(self, rs: JNode, which: str) -> str:
        """`from zone trust;` is a leaf (["zone","trust"]); some versions
        use a `from { zone trust; }` container. Handle both."""
        leaf = rs.leaf(which)
        if leaf and len(leaf) >= 2:
            return leaf[1]
        node = rs.get(which)
        if node is not None:
            return (node.leaf_str("zone") or node.leaf_str("interface")
                    or node.leaf_str("routing-instance"))
        return ""

    def _ruleset_zones(self, rs: JNode) -> tuple[str, str]:
        return (self._from_to(rs, "from") or "any",
                self._from_to(rs, "to") or "any")

    def _parse_src_nat(self, src: JNode | None) -> None:
        if src is None:
            return
        pools = {}
        for key, pool in src.find("pool"):
            if len(key) > 1:
                pools[key[1]] = pool
        for key, rs in src.find("rule-set"):
            fz, tz = self._ruleset_zones(rs)
            for rkey, rule in rs.find("rule"):
                rname = rkey[1] if len(rkey) > 1 else "rule"
                ref = self.ref(rule, f"source-nat {rname}")
                then = rule.get("then") or JNode()
                snat = then.get("source-nat") or JNode()
                if snat.get("interface") is not None \
                        or snat.has_leaf("interface"):
                    self.cfg.nats.append(NatRule(
                        kind="dynamic-interface", real_ifc=fz,
                        mapped_ifc=tz, source=ref))
                elif snat.has_leaf("off") or snat.get("off") is not None:
                    self.note("info", "nat",
                              f"source-nat rule '{rname}': nat off "
                              "(exempt) — no FortiOS nat on matching "
                              "policies; verify", ref)
                else:
                    pool_names = [t[0] for t in snat.leaf_all("pool") if t]
                    for pk, _pn in snat.find("pool"):
                        if len(pk) > 1:
                            pool_names.append(pk[1])
                    self.note("warn", "nat",
                              f"source-nat rule '{rname}' uses pool "
                              f"{', '.join(pool_names) or '(unnamed)'} — "
                              "IP-pool source NAT not converted; recreate "
                              "as a FortiOS IP pool + set nat enable", ref)

    def _parse_dst_nat(self, dst: JNode | None) -> None:
        if dst is None:
            return
        pools: dict[str, JNode] = {}
        for key, pool in dst.find("pool"):
            if len(key) > 1:
                pools[key[1]] = pool
        for key, rs in dst.find("rule-set"):
            for rkey, rule in rs.find("rule"):
                rname = rkey[1] if len(rkey) > 1 else "rule"
                ref = self.ref(rule, f"destination-nat {rname}")
                match = rule.get("match") or JNode()
                then = rule.get("then") or JNode()
                dnat = then.get("destination-nat") or JNode()
                pool_name = dnat.leaf_str("pool")
                for pk, _pn in dnat.find("pool"):
                    if len(pk) > 1:
                        pool_name = pk[1]
                ext = match.leaf_str("destination-address")
                ext_port = match.leaf_str("destination-port")
                pool = pools.get(pool_name)
                if pool is None or not ext:
                    self.note("warn", "nat",
                              f"destination-nat '{rname}': pool "
                              f"'{pool_name}' or match address unresolved "
                              "— convert to a VIP manually", ref)
                    continue
                mapped = pool.leaf_str("address")
                mapped_ip = mapped.split("/")[0]
                mapped_port = pool.leaf_str("address port") \
                    or pool.leaf_str("port")
                vip = Vip(
                    name=f"vip-{rname}",
                    ext_ip=ext.split("/")[0], mapped_ip=mapped_ip,
                    ext_intf=self._ruleset_zones(rs)[1],
                    comment=f"from Junos destination-nat {rname}",
                    source=ref)
                # `pool { address 10.1.1.10/32 port 8443; }` packs port
                mt = pool.leaf("address")
                if mt and len(mt) >= 3 and mt[1] == "port":
                    mapped_port = mt[2]
                if ext_port:
                    vip.protocol = "tcp"
                    vip.ext_port = ext_port
                    vip.mapped_port = mapped_port or ext_port
                self.cfg.vips.append(vip)

    def _parse_static_nat(self, stat: JNode | None) -> None:
        if stat is None:
            return
        for key, rs in stat.find("rule-set"):
            etz = self._ruleset_zones(rs)[1]
            for rkey, rule in rs.find("rule"):
                rname = rkey[1] if len(rkey) > 1 else "rule"
                ref = self.ref(rule, f"static-nat {rname}")
                match = rule.get("match") or JNode()
                then = rule.get("then") or JNode()
                snat = then.get("static-nat") or JNode()
                ext = match.leaf_str("destination-address") \
                    or (rkey[1] if len(rkey) > 1 else "")
                prefix = snat.leaf_str("prefix")
                if not prefix:
                    pfx = snat.get("prefix")
                    if pfx:
                        prefix = pfx.leaf_str("__first__") or ""
                for pk, _pn in snat.find("prefix"):
                    if len(pk) > 1:
                        prefix = pk[1]
                if not ext or not prefix:
                    self.note("warn", "nat",
                              f"static-nat '{rname}': external or mapped "
                              "prefix unresolved — convert manually", ref)
                    continue
                self.cfg.vips.append(Vip(
                    name=f"vip-{rname}",
                    ext_ip=ext.split("/")[0],
                    mapped_ip=prefix.split("/")[0],
                    ext_intf=etz,
                    comment=f"from Junos static-nat {rname} (1:1)",
                    source=ref))

    # -- routes ---------------------------------------------------------

    def parse_routes(self) -> None:
        ro = self.tree.get("routing-options")
        if ro is None:
            return
        static = ro.get("static")
        if static is None:
            return
        # container form: route X { next-hop Y; discard; }
        for key, rt in static.find("route"):
            if len(key) < 2:
                continue
            gw = rt.leaf_str("next-hop")
            if not gw:
                for nk, _nn in rt.find("qualified-next-hop"):
                    if len(nk) > 1:
                        gw = nk[1]
                        break
            blackhole = rt.has_leaf("discard") \
                or rt.get("discard") is not None \
                or rt.has_leaf("reject")
            self._add_route(key[1], gw, blackhole, self.ref(rt, "route"))
        # one-liner leaf form: route X next-hop Y; (curly show-config)
        for toks in static.leaf_all("route"):
            if not toks:
                continue
            dest = toks[0]
            gw = ""
            if "next-hop" in toks:
                j = toks.index("next-hop")
                if j + 1 < len(toks):
                    gw = toks[j + 1]
            blackhole = "discard" in toks or "reject" in toks
            self._add_route(dest, gw, blackhole, self.ref(static, "route"))

    def _add_route(self, dest: str, gw: str, blackhole: bool,
                   ref) -> None:
        from ..model import Route
        if blackhole:
            self.note("info", "routes",
                      f"route {dest}: discard/blackhole — recreate as a "
                      "blackhole static route on FortiOS", ref)
            return
        try:
            net = ipaddress.ip_network(dest, strict=False)
        except ValueError:
            self.note("warn", "routes",
                      f"route '{dest}' invalid — skipped", ref)
            return
        if not gw:
            self.note("warn", "routes",
                      f"route {dest}: no next-hop resolved — skipped", ref)
            return
        if any(r.dest == str(net) and r.gateway == gw
               for r in self.cfg.routes):
            return
        self.cfg.routes.append(Route(
            dest=str(net), gateway=gw, interface="", source=ref))

    # -- dynamic routing (BGP / OSPF) ------------------------------------

    def parse_protocols(self) -> None:
        prot = self.tree.get("protocols")
        if prot is None:
            return
        ro = self.tree.get("routing-options") or JNode()
        local_as = ""
        asn = ro.leaf("autonomous-system")
        if asn:
            local_as = asn[0]
        router_id = ro.leaf_str("router-id")
        bgp = prot.get("bgp")
        if bgp is not None:
            self._parse_bgp(bgp, local_as, router_id)
        ospf = prot.get("ospf")
        if ospf is not None:
            self._parse_ospf(ospf, router_id)

    def _parse_bgp(self, bgp: JNode, local_as: str,
                   router_id: str) -> None:
        from ..model import BgpConfig, BgpNeighbor
        ref = self.ref(bgp, "protocols bgp")
        if not local_as:
            self.note("warn", "routing",
                      "BGP configured but routing-options "
                      "autonomous-system is missing — set 'set as' "
                      "manually", ref)
        cfg = BgpConfig(asn=local_as or "0", router_id=router_id,
                        source=ref)
        exports: list[str] = []
        for toks in bgp.leaf_all("export"):
            exports += toks
        for gkey, grp in bgp.find("group"):
            gname = gkey[1] if len(gkey) > 1 else "group"
            gtype = grp.leaf_str("type")
            g_as = grp.leaf_str("peer-as")
            if gtype == "internal" and not g_as:
                g_as = local_as
            g_auth = bool(grp.leaf_str("authentication-key"))
            g_descr = grp.leaf_str("description")
            for toks in grp.leaf_all("export"):
                exports += toks
            # bare `neighbor 10.0.0.2;` leaves
            for toks in grp.leaf_all("neighbor"):
                if toks:
                    cfg.neighbors.append(BgpNeighbor(
                        ip=toks[0], remote_as=g_as,
                        description=g_descr or gname,
                        has_password=g_auth,
                        source=self.ref(grp, f"bgp group {gname}")))
            # `neighbor 10.0.0.2 { peer-as ...; }` containers
            for nkey, nb in grp.find("neighbor"):
                if len(nkey) < 2:
                    continue
                cfg.neighbors.append(BgpNeighbor(
                    ip=nkey[1],
                    remote_as=nb.leaf_str("peer-as") or g_as,
                    description=nb.leaf_str("description")
                    or g_descr or gname,
                    has_password=g_auth
                    or bool(nb.leaf_str("authentication-key")),
                    source=self.ref(nb, f"bgp neighbor {nkey[1]}")))
        if exports:
            self.note("warn", "routing",
                      "BGP export policies "
                      f"({', '.join(dict.fromkeys(exports))}) are how "
                      "Junos advertises routes — NOT converted; recreate "
                      "as FortiOS route-maps / network statements and "
                      "verify advertisements", ref)
        self.cfg.bgp = cfg

    def _parse_ospf(self, ospf: JNode, router_id: str) -> None:
        from ..model import OspfArea, OspfConfig
        ref = self.ref(ospf, "protocols ospf")
        cfg = OspfConfig(router_id=router_id, source=ref)
        exports = [t for toks in ospf.leaf_all("export") for t in toks]
        for akey, area in ospf.find("area"):
            if len(akey) < 2:
                continue
            aid = self._area_id(akey[1])
            a = OspfArea(id=aid, source=self.ref(area, f"area {aid}"))
            entries: list[tuple[str, bool]] = []
            for toks in area.leaf_all("interface"):
                if toks:
                    entries.append((toks[0], "passive" in toks[1:]))
            for ikey, inode in area.find("interface"):
                if len(ikey) > 1:
                    entries.append((ikey[1],
                                    inode.has_leaf("passive")))
            for ifname, passive in entries:
                if ifname == "all":
                    self.note("warn", "routing",
                              f"OSPF area {aid}: 'interface all' — "
                              "FortiOS needs explicit network "
                              "statements; add them per interface",
                              a.source)
                    continue
                net = self._connected_net(ifname)
                if net:
                    if net not in a.networks:
                        a.networks.append(net)
                else:
                    self.note("warn", "routing",
                              f"OSPF area {aid}: interface {ifname} has "
                              "no known address — add its network "
                              "statement manually", a.source)
                if passive:
                    a.passive.append(ifname)
            cfg.areas.append(a)
        if exports:
            self.note("warn", "routing",
                      "OSPF export policies "
                      f"({', '.join(dict.fromkeys(exports))}) not "
                      "converted — recreate as FortiOS redistribute / "
                      "route-maps", ref)
        self.cfg.ospf = cfg

    @staticmethod
    def _area_id(raw: str) -> str:
        if raw.isdigit():
            n = int(raw)
            return (f"{(n >> 24) & 255}.{(n >> 16) & 255}."
                    f"{(n >> 8) & 255}.{n & 255}")
        return raw

    def _connected_net(self, ifname: str) -> str:
        itf = self.cfg.interface_by_name(ifname)
        if itf is None or not itf.ip:
            return ""
        try:
            return str(ipaddress.ip_interface(itf.ip).network)
        except ValueError:
            return ""

    # -- VPN (route-based st0) ------------------------------------------

    def parse_vpn(self) -> None:
        ike = self._sec.get("ike")
        ipsec = self._sec.get("ipsec")
        if ipsec is None:
            return
        ike_props = self._ike_proposals(ike)
        ike_pols = self._ike_policies(ike, ike_props)
        ike_gws = self._ike_gateways(ike)
        ips_props = self._ipsec_proposals(ipsec)
        ips_pols = self._ipsec_policies(ipsec, ips_props)

        from ..transforms.routes import RouteTable
        table = RouteTable(self.cfg)
        used: set[str] = set()
        for key, vpnnode in ipsec.find("vpn"):
            if len(key) < 2:
                continue
            self._one_vpn(key[1], vpnnode, ike_pols, ike_gws, ips_pols,
                          table, used)

    def _ike_proposals(self, ike: JNode | None) -> dict:
        out: dict[str, dict] = {}
        if ike is None:
            return out
        for key, p in ike.find("proposal"):
            if len(key) < 2:
                continue
            out[key[1]] = {
                "enc": vpn.ENC.get(p.leaf_str("encryption-algorithm"), ""),
                "hash": vpn.HASH.get(self._auth(
                    p.leaf_str("authentication-algorithm")), ""),
                "dh": p.leaf_str("dh-group").replace("group", ""),
                "life": self._int(p.leaf_str("lifetime-seconds")),
            }
        return out

    def _ipsec_proposals(self, ipsec: JNode | None) -> dict:
        out: dict[str, dict] = {}
        if ipsec is None:
            return out
        for key, p in ipsec.find("proposal"):
            if len(key) < 2:
                continue
            out[key[1]] = {
                "enc": vpn.ENC.get(p.leaf_str("encryption-algorithm"), ""),
                "hash": vpn.HASH.get(self._auth(
                    p.leaf_str("authentication-algorithm")), ""),
                "life": self._int(p.leaf_str("lifetime-seconds")),
            }
        return out

    @staticmethod
    def _auth(a: str) -> str:
        # hmac-sha-256-128 / hmac-sha1-96 -> sha256 / sha1
        a = a.lower()
        a = a.replace("hmac-", "").replace("-96", "").replace("-128", "")
        a = a.replace("-160", "")
        return a

    @staticmethod
    def _int(s: str) -> int:
        return int(s) if s.isdigit() else 0

    def _ike_policies(self, ike: JNode | None, props: dict) -> dict:
        out: dict[str, dict] = {}
        if ike is None:
            return out
        for key, pol in ike.find("policy"):
            if len(key) < 2:
                continue
            pnames = [t for ts in pol.leaf_all("proposals") for t in ts]
            psk = ""
            psknode = pol.get("pre-shared-key")
            raw = pol.leaf_str("pre-shared-key")
            if psknode is not None:
                raw = psknode.leaf_str("ascii-text") \
                    or psknode.leaf_str("hexadecimal")
            else:
                v = pol.leaf("pre-shared-key")
                if v and v[0] in ("ascii-text", "hexadecimal"):
                    raw = " ".join(v[1:])
            out[key[1]] = {"proposals": pnames, "psk": raw,
                           "props": props}
        return out

    def _ipsec_policies(self, ipsec: JNode | None, props: dict) -> dict:
        out: dict[str, dict] = {}
        if ipsec is None:
            return out
        for key, pol in ipsec.find("policy"):
            if len(key) < 2:
                continue
            pnames = [t for ts in pol.leaf_all("proposals") for t in ts]
            pfs = ""
            pfsnode = pol.get("perfect-forward-secrecy")
            if pfsnode is not None:
                pfs = pfsnode.leaf_str("keys").replace("group", "")
            else:
                v = pol.leaf("perfect-forward-secrecy")
                if v and "keys" in v:
                    pfs = v[v.index("keys") + 1].replace("group", "") \
                        if v.index("keys") + 1 < len(v) else ""
            out[key[1]] = {"proposals": pnames, "pfs": pfs, "props": props}
        return out

    def _ike_gateways(self, ike: JNode | None) -> dict:
        out: dict[str, dict] = {}
        if ike is None:
            return out
        for key, gw in ike.find("gateway"):
            if len(key) < 2:
                continue
            ver = gw.leaf_str("version")
            out[key[1]] = {
                "policy": gw.leaf_str("ike-policy"),
                "remote": gw.leaf_str("address"),
                "ext_if": gw.leaf_str("external-interface"),
                "ikev2": "v2" in ver,
            }
        return out

    def _one_vpn(self, name, vpnnode, ike_pols, ike_gws, ips_pols,
                 table, used) -> None:
        ref = self.ref(vpnnode, f"ipsec vpn {name}")
        bind = vpnnode.leaf_str("bind-interface")
        if not bind:
            self.note("info", "vpn",
                      f"vpn '{name}': no bind-interface (policy-based "
                      "VPN) — convert to route-based; skipped", ref)
            return
        ikeblk = vpnnode.get("ike") or JNode()
        gwname = ikeblk.leaf_str("gateway")
        ipsec_polname = ikeblk.leaf_str("ipsec-policy")
        gw = ike_gws.get(gwname)
        if gw is None:
            self.note("warn", "vpn",
                      f"vpn '{name}': IKE gateway '{gwname}' not found — "
                      "skipped", ref)
            return
        ikp = ike_pols.get(gw["policy"], {})
        ike_prop_names = ikp.get("proposals", [])
        ike_props = ikp.get("props", {})
        encs = [ike_props[p]["enc"] for p in ike_prop_names
                if p in ike_props and ike_props[p]["enc"]]
        hashes = [ike_props[p]["hash"] for p in ike_prop_names
                  if p in ike_props and ike_props[p]["hash"]]
        dh = [ike_props[p]["dh"] for p in ike_prop_names
              if p in ike_props and ike_props[p]["dh"]]
        p1_life = next((ike_props[p]["life"] for p in ike_prop_names
                        if p in ike_props and ike_props[p]["life"]), 0)
        ipp = ips_pols.get(ipsec_polname, {})
        ips_prop_names = ipp.get("proposals", [])
        ips_props = ipp.get("props", {})
        p2_encs = [ips_props[p]["enc"] for p in ips_prop_names
                   if p in ips_props and ips_props[p]["enc"]]
        p2_hashes = [ips_props[p]["hash"] for p in ips_prop_names
                     if p in ips_props and ips_props[p]["hash"]]
        p2_life = next((ips_props[p]["life"] for p in ips_prop_names
                        if p in ips_props and ips_props[p]["life"]), 0)
        pfs = ipp.get("pfs", "")

        psk = self._psk(ikp.get("psk", ""), name, ref)
        p1_props = vpn.esp_combos(encs, hashes) or ["aes256-sha256"]
        p2_props = vpn.esp_combos(
            list(dict.fromkeys(p2_encs)),
            list(dict.fromkeys(p2_hashes))) or ["aes256-sha256"]
        if not encs or not p2_encs:
            self.note("warn", "vpn",
                      f"vpn '{name}': crypto proposal incomplete — "
                      "defaulted to aes256-sha256; match the peer", ref)

        selectors = self._vpn_selectors(vpnnode)
        tname = f"vpn-{name}"[:15]
        if tname in used:
            base, k = tname, 2
            while tname in used:
                suffix = f"~{k}"
                tname = base[:15 - len(suffix)] + suffix
                k += 1
            self.note("warn", "vpn",
                      f"vpn '{name}': truncated tunnel name collided — "
                      f"renamed {tname}", ref)
        used.add(tname)
        vpn.add_route_based_tunnel(
            self.cfg, _Reporter(self), table, name=tname,
            interface=gw["ext_if"] or bind, remote_gw=gw["remote"],
            ike_version=2 if gw["ikev2"] else 1,
            p1_proposals=p1_props, p1_dhgrp=dh or ["14"], psk=psk,
            p1_keylife=p1_life, selectors=selectors,
            p2_proposals=p2_props, pfs_group=pfs, p2_keylife=p2_life,
            comment=f"Junos vpn {name} (peer {gw['remote']})", source=ref)

    def _vpn_selectors(self, vpnnode: JNode) -> list[tuple[str, str]]:
        sels = []
        for key, ts in vpnnode.find("traffic-selector"):
            local = ts.leaf_str("local-ip")
            remote = ts.leaf_str("remote-ip")
            if local and remote:
                sels.append((local, remote))
        ikeblk = vpnnode.get("ike")
        if ikeblk is not None:
            pid = ikeblk.get("proxy-identity")
            if pid is not None:
                local = pid.leaf_str("local")
                remote = pid.leaf_str("remote")
                if local and remote:
                    sels.append((local, remote))
        if not sels:
            sels = [("0.0.0.0/0", "0.0.0.0/0")]
            self.note("info", "vpn",
                      "tunnel has no traffic-selector/proxy-identity — "
                      "using 0.0.0.0/0 <-> 0.0.0.0/0 (route-based)")
        return sels

    def _psk(self, raw: str, name: str, ref: SourceRef) -> str:
        if not raw:
            self.note("error", "vpn",
                      f"vpn '{name}': no pre-shared-key — placeholder "
                      "emitted, set it manually", ref)
            return "CHANGEME-PSK"
        if raw.startswith("$9$") or raw.startswith("$8$"):
            self.note("error", "vpn",
                      f"vpn '{name}': PSK is Junos-encrypted ($9$) and "
                      "cannot be recovered — placeholder emitted, set the "
                      "real PSK", ref)
            return "CHANGEME-PSK"
        return raw

    # -- routing-instances (VDOM candidates) ----------------------------

    def flag_routing_instances(self) -> None:
        ri = self.tree.get("routing-instances")
        if ri is None:
            return
        names = [k[0] for k, _ in ri.containers if k]
        if names:
            self.note("warn", "routing-instances",
                      f"{len(names)} routing-instance(s) "
                      f"({', '.join(names)}) not converted — each maps to "
                      "a FortiOS VDOM; convert the main instance now and "
                      "re-run per instance (VDOM mapping queued)")

    # -- coverage map ---------------------------------------------------

    def report_coverage(self) -> None:
        consumed_top = {"security", "interfaces", "applications",
                        "routing-options", "system", "groups",
                        "apply-groups", "version", "protocols"}
        consumed_sec = {"zones", "policies", "nat", "address-book",
                        "ike", "ipsec"}
        consumed_prot = {"bgp", "ospf"}
        unread: list[tuple[str, int]] = []
        for key, node in self.tree.containers:
            if not key or key[0] in consumed_top:
                continue
            unread.append((" ".join(key), self._leaves(node)))
        for key, node in self._sec.containers:
            if not key or key[0] in consumed_sec:
                continue
            unread.append((f"security {' '.join(key)}", self._leaves(node)))
        prot = self.tree.get("protocols")
        if prot is not None:
            for key, node in prot.containers:
                if not key or key[0] in consumed_prot:
                    continue
                unread.append((f"protocols {' '.join(key)}",
                               self._leaves(node)))
        for label, n in sorted(unread, key=lambda x: -x[1])[:15]:
            self.note("info", "coverage",
                      f"unread stanza: {label} ({n} statement(s)) — not "
                      "converted or flagged individually")
        if unread:
            self.note("warn", "coverage",
                      f"{len(unread)} top-level stanza(s) not read by the "
                      "converter (see the unread list) — review for config "
                      "that needs manual carry-over")
        self.cfg.meta["stanzas_unread"] = len(unread)

    def _leaves(self, node: JNode) -> int:
        n = len(node.leaves)
        for _k, c in node.containers:
            n += self._leaves(c)
        return n or 1


class _Reporter:
    """Adapter so _vpn_common can append findings via note()."""

    def __init__(self, parser):
        self._p = parser

    def add(self, level, area, msg, ref=None):
        self._p.note(level, area, msg, ref)


def parse(text: str, filename: str = "") -> FirewallConfig:
    return JunosParser(text, filename).parse()
