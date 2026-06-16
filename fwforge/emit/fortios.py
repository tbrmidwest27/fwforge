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
    # built-in NTP is tcp+udp/123 and SNMP is tcp+udp/161-162 — mapping
    # plain udp/123 / udp/161 to them would silently broaden the rule
    ("tcp/udp", "123", "", None, None): "NTP",
    ("tcp/udp", "161-162", "", None, None): "SNMP",
    ("udp", "514", "", None, None): "SYSLOG",
    ("icmp", "", "", 8, None): "PING",
    ("icmp", "", "", None, None): "ALL_ICMP",
    ("ip", "", "", None, 47): "GRE",
    ("ip", "", "", None, 50): "ESP",
    ("ip", "", "", None, 51): "AH",
}


def _q(value: str) -> str:
    # escape backslash/quote, and fold newlines to literal \n so a value
    # never spans physical lines (a comment line that strips to exactly
    # "end" or starts with "config " would otherwise break branch
    # splitting on output)
    return '"' + (value.replace("\\", "\\\\").replace('"', '\\"')
                  .replace("\r", "").replace("\n", "\\n")) + '"'


def _is_v6(value: str) -> bool:
    return ":" in value


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


def _dependency_order(rows: list) -> list:
    """Order interfaces so each is defined after anything it depends on.
    A VLAN's parent (an aggregate we build, or another VLAN for QinQ) must
    already exist or FortiOS rejects 'set interface' when the script
    loads; aggregates/loopbacks carry no such dependency, so they lead.
    VLANs nested on a physical port need no ordering — the port already
    exists on the target."""
    non_vlan = [i for i in rows if i.kind != "vlan"]
    vlans = [i for i in rows if i.kind == "vlan"]
    by_name = {i.name: i for i in vlans}   # only VLAN-on-VLAN (QinQ) here
    ordered: list = []
    seen: set[str] = set()

    def place(v):
        if v.name in seen:
            return
        seen.add(v.name)
        parent = by_name.get(v.parent)
        if parent is not None:
            place(parent)
        ordered.append(v)

    for v in vlans:
        place(v)
    return non_vlan + ordered


# A safe, widely-interoperable IKE/IPsec proposal to substitute when the source
# yielded none — never emit a bare `set proposal` (FortiOS rejects it).
_DEFAULT_PROPOSAL = "aes256-sha256 aes128-sha256"


def _group_dependency_order(groups: list, report=None, area: str = "") -> list:
    """Order groups so each is emitted after any group it lists as a member.
    FortiOS rejects `set member <g>` when <g> is not yet defined, so a parent
    group defined before its child group (common from ASA `group-object` /
    nested PAN members) would silently drop the member on restore. Members that
    are not themselves groups in this list don't affect ordering. Cycle-safe:
    a membership cycle can't recurse forever and every group is emitted exactly
    once (best-effort order), with one error reported."""
    by_name = {g.name: g for g in groups}
    ordered: list = []
    done: set[str] = set()
    onstack: set[str] = set()
    cycles: list[str] = []

    def place(g):
        if g.name in done:
            return
        if g.name in onstack:           # back-edge -> membership cycle
            cycles.append(g.name)
            return
        onstack.add(g.name)
        for m in g.members:
            child = by_name.get(m)
            if child is not None and child is not g:
                place(child)
        onstack.discard(g.name)
        done.add(g.name)
        ordered.append(g)

    for g in groups:
        place(g)
    if cycles and report is not None:
        report.add("error", area,
                   "group membership cycle involving "
                   f"{', '.join(sorted(set(cycles)))} — emitted in best-effort "
                   "order; FortiOS may reject it", None)
    return ordered


class Emitter:
    def __init__(self, cfg: FirewallConfig, report, target: str = "7.4",
                 nat_mode: str = "policy"):
        self.cfg = cfg
        self.report = report
        self.target = target
        self.nat_mode = nat_mode  # "policy" | "central"
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
        if self.nat_mode == "central":
            self.line()
            self.line("config system settings")
            self.line("    set central-nat enable")
            self.line("end")
        self.interfaces()
        self.zones()
        self.addresses()
        self.addr_groups()
        self.services()
        self.svc_groups()
        self.app_lists()
        self.webfilter()
        self.file_filter()
        self.antivirus()
        self.ips()
        self.vpn()
        self.vips()
        if self.nat_mode == "central":
            self.central_snat()
        self.routes()
        self.bgp()
        self.ospf()
        self.policies()
        return "\n".join(self.out) + "\n"

    def central_snat(self):
        rules = [n for n in self.cfg.nats if n.kind == "dynamic-interface"]
        if not rules:
            return
        addr_names = {a.name for a in self.cfg.addresses} \
            | {g.name for g in self.cfg.addr_groups}
        self.line()
        self.line("config firewall central-snat-map")
        for i, n in enumerate(rules, start=1):
            src = "any" if n.real_ifc == "*" else _intf(self.cfg, n.real_ifc)
            self.line(f"    edit {i}")
            self.line(f"        set srcintf {_q(src)}")
            self.line(f"        set dstintf "
                      f"{_q(_intf(self.cfg, n.mapped_ifc))}")
            orig = n.real_obj if n.real_obj in addr_names else "all"
            self.line(f"        set orig-addr {_q(orig)}")
            self.line('        set dst-addr "all"')
            self.line("        set nat enable")
            self.line("    next")
        self.line("end")
        self.report.add(
            "info", "nat",
            f"central NAT: {len(rules)} central-snat-map rule(s) generated "
            "from the source's NAT intent; firewall policies carry no "
            "per-policy NAT")

    def interfaces(self):
        """Create the logical interfaces that don't exist on a target by
        default: aggregates (the LAG — set type aggregate + member ports
        + LACP), VLAN subinterfaces (carry the L3 / IPs), and loopbacks.
        Physical ports are assumed to already exist on the target and are
        only referenced; aggregate-member ports are consumed by the
        bundle; tunnels are built by the VPN section."""
        cfg = self.cfg
        rows = [i for i in cfg.interfaces
                if i.kind in ("aggregate", "vlan", "loopback")]
        if not rows:
            return
        rows = _dependency_order(rows)
        self.line()
        self.line("config system interface")
        for i in rows:
            self.line(f"    edit {_q(i.mapped)}")
            self.line('        set vdom "root"')
            if i.kind == "aggregate":
                self.line("        set type aggregate")
                members = [_intf(cfg, m) for m in i.members]
                if members:
                    self.line("        set member "
                              + " ".join(_q(m) for m in members))
                self.line("        set lacp-mode "
                          f"{i.lacp_mode or 'active'}")
            elif i.kind == "vlan":
                self.line("        set type vlan")
                if i.parent:
                    self.line("        set interface "
                              f"{_q(_intf(cfg, i.parent))}")
                if i.vlan_id:
                    self.line(f"        set vlanid {i.vlan_id}")
            elif i.kind == "loopback":
                self.line("        set type loopback")
            if i.ip and "/" in i.ip and not _is_v6(i.ip):
                addr, prefix = i.ip.split("/")
                try:
                    self.line(f"        set ip {addr} {_mask(int(prefix))}")
                    self.line("        set allowaccess ping")
                except ValueError:
                    self.report.add(
                        "error", "interfaces",
                        f"interface '{i.name}': invalid ip '{i.ip}' — "
                        "emitted without an address", i.source)
            if i.description:
                self.line(f"        set description "
                          f"{_q(i.description[:255])}")
            self.line("    next")
        self.line("end")
        aggs = [i for i in rows if i.kind == "aggregate"]
        if aggs:
            modes = sorted({i.lacp_mode or "active" for i in aggs})
            defaulted = [i.mapped for i in aggs if not i.lacp_mode]
            msg = (f"rebuilt {len(aggs)} aggregate(s) as FortiOS 802.3ad "
                   "LAGs (set type aggregate + member ports), emitted "
                   "before their VLAN subinterfaces; LACP mode(s): "
                   f"{', '.join(modes)}. Verify the member ports map to "
                   "real target ports")
            if defaulted:
                msg += ("; no LACP mode found in the source for "
                        f"{', '.join(defaulted)} — defaulted to 'active', "
                        "confirm active/passive/static")
            self.report.add("info", "interfaces", msg)

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

    def _family_map(self) -> dict[str, int]:
        """addr/group name -> 4 or 6."""
        cached = getattr(self, "_fam_cache", None)
        if cached is not None:
            return cached   # emit is read-only; compute once, reuse
        fam: dict[str, int] = {}
        for a in self.cfg.addresses:
            fam[a.name] = 6 if _is_v6(a.value) else 4
        for v in self.cfg.vips:
            fam[v.name] = 4
        # groups inherit from their first family-known member
        for g in self.cfg.addr_groups:
            for m in g.members:
                if m in fam:
                    fam[g.name] = fam[m]
                    break
        self._fam_cache = fam
        return fam

    def addresses(self):
        v4 = [a for a in self.cfg.addresses if not _is_v6(a.value)]
        v6 = [a for a in self.cfg.addresses if _is_v6(a.value)]
        if v4:
            self.line()
            self.line("config firewall address")
            for a in v4:
                self.line(f"    edit {_q(a.name)}")
                try:
                    if a.type == "host":
                        self.line(f"        set subnet {a.value} "
                                  "255.255.255.255")
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
        if v6:
            self.line()
            self.line("config firewall address6")
            for a in v6:
                self.line(f"    edit {_q(a.name)}")
                if a.type == "host":
                    self.line(f"        set ip6 {a.value}/128")
                elif a.type == "subnet":
                    self.line(f"        set ip6 {a.value}")
                elif a.type == "range":
                    lo, hi = a.value.split("-", 1)
                    self.line("        set type iprange")
                    self.line(f"        set start-ip {lo}")
                    self.line(f"        set end-ip {hi}")
                if a.comment:
                    self.line(f"        set comment {_q(a.comment[:255])}")
                self.line("    next")
            self.line("end")
            self.report.add("info", "addresses",
                            f"{len(v6)} IPv6 address object(s) emitted as "
                            "firewall address6")

    def addr_groups(self):
        if not self.cfg.addr_groups:
            return
        fam = self._family_map()
        v4 = [g for g in self.cfg.addr_groups if fam.get(g.name, 4) != 6]
        v6 = [g for g in self.cfg.addr_groups if fam.get(g.name) == 6]
        for section, groups in (("addrgrp", v4), ("addrgrp6", v6)):
            if not groups:
                continue
            gfam = 6 if section == "addrgrp6" else 4
            self.line()
            self.line(f"config firewall {section}")
            for g in _group_dependency_order(groups, self.report, "addresses"):
                # FortiOS groups are single-family: a member of the other
                # family doesn't exist in this table and would sink the
                # whole group on load
                members = [m for m in g.members
                           if fam.get(m, gfam) == gfam]
                dropped = [m for m in g.members if m not in members]
                if dropped:
                    self.report.add(
                        "error", "addresses",
                        f"group '{g.name}': member(s) "
                        f"{', '.join(dropped)} are IPv"
                        f"{6 if gfam == 4 else 4} — removed (FortiOS "
                        "groups are single-family); create a separate "
                        f"{'addrgrp6' if gfam == 4 else 'addrgrp'} if "
                        "needed", g.source)
                self.line(f"    edit {_q(g.name)}")
                if members:
                    self.line("        set member "
                              + " ".join(_q(m) for m in members))
                else:
                    self.report.add(
                        "warn", "addresses",
                        f"address group '{g.name}' has no members — FortiOS "
                        "rejects empty groups; emitted with placeholder "
                        "'all'", g.source)
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
        for g in _group_dependency_order(self.cfg.svc_groups, self.report,
                                          "services"):
            self.line(f"    edit {_q(g.name)}")
            if g.members:
                self.line("        set member "
                          + " ".join(_q(m) for m in g.members))
            else:
                self.report.add(
                    "warn", "services",
                    f"service group '{g.name}' has no members — FortiOS "
                    "rejects empty groups; emitted with placeholder 'ALL'",
                    g.source)
                self.line('        set member "ALL"')
            if g.comment:
                self.line(f"        set comment {_q(g.comment[:255])}")
            self.line("    next")
        self.line("end")

    def app_lists(self):
        if not self.cfg.app_lists:
            return
        self.line()
        self.line("config application list")
        sig_total = 0
        for al in self.cfg.app_lists:
            sig_total += len(al.applications)
            self.line(f"    edit {_q(al.name)}")
            self.line("        set other-application-action block")
            if al.apps:
                self.line("        set comment "
                          + _q(("from PAN App-ID: "
                                + ", ".join(al.apps))[:255]))
            self.line("        config entries")
            eid = 1
            # per-application signatures first, then any category fallback
            if al.applications:
                self.line(f"            edit {eid}")
                self.line("                set application "
                          + " ".join(str(a) for a in al.applications))
                self.line("                set action pass")
                self.line("            next")
                eid += 1
            if al.categories:
                self.line(f"            edit {eid}")
                self.line("                set category "
                          + " ".join(str(c) for c in al.categories))
                self.line("                set action pass")
                self.line("            next")
            self.line("        end")
            self.line("    next")
        self.line("end")
        if sig_total:
            self.report.add(
                "info", "policies",
                f"{len(self.cfg.app_lists)} application-list profile(s) from "
                f"PAN App-ID with {sig_total} per-application signature(s) "
                "(matched to the FortiGuard app DB) plus category fallbacks. "
                "Policies get 'set application-list'; attach a deep-inspection "
                "ssl-ssh profile for control over encrypted apps.")
        else:
            self.report.add(
                "info", "policies",
                f"{len(self.cfg.app_lists)} application-list profile(s) created "
                "from PAN App-ID (category-level). Policies using them get "
                "'set application-list'; attach a deep-inspection ssl-ssh "
                "profile if you need control over encrypted apps.")

    def webfilter(self):
        """Webfilter profiles (FortiGuard categories + custom URL lists)."""
        if not self.cfg.webfilters:
            return
        # urlfilter tables first — the profile references them by numeric id
        url_table_id: dict[str, int] = {}
        with_urls = [wf for wf in self.cfg.webfilters if wf.urls]
        if with_urls:
            self.line()
            self.line("config webfilter urlfilter")
            for n, wf in enumerate(with_urls, start=1):
                url_table_id[wf.name] = n
                self.line(f"    edit {n}")
                self.line(f"        set name {_q(wf.name + '-urls')}")
                self.line("        config entries")
                for j, (url, utype, action) in enumerate(wf.urls, start=1):
                    self.line(f"            edit {j}")
                    self.line(f"                set url {_q(url)}")
                    self.line(f"                set type {utype}")
                    self.line(f"                set action {action}")
                    self.line("            next")
                self.line("        end")
                self.line("    next")
            self.line("end")
        self.line()
        self.line("config webfilter profile")
        for wf in self.cfg.webfilters:
            self.line(f"    edit {_q(wf.name)}")
            if wf.comment:
                self.line(f"        set comment {_q(wf.comment[:255])}")
            if wf.filters:
                self.line("        config ftgd-wf")
                self.line("            config filters")
                for i, (cat, action) in enumerate(wf.filters, start=1):
                    self.line(f"                edit {i}")
                    self.line(f"                    set category {cat}")
                    self.line(f"                    set action {action}")
                    self.line("                next")
                self.line("            end")
                self.line("        end")
            if wf.name in url_table_id:
                self.line("        config web")
                self.line("            set urlfilter-table "
                          f"{url_table_id[wf.name]}")
                self.line("        end")
            self.line("    next")
        self.line("end")
        nurls = sum(len(wf.urls) for wf in self.cfg.webfilters)
        msg = (f"{len(self.cfg.webfilters)} webfilter profile(s) created from "
               "PAN url-filtering (FortiGuard category-level")
        if nurls:
            msg += (f" + {nurls} explicit URL(s) in {len(with_urls)} urlfilter "
                    "table(s) — per-URL allow/block carried over")
        msg += ("). Attached policies use the built-in 'certificate-inspection' "
                "SSL profile; switch to 'deep-inspection' for full URL-path / "
                "HTTPS content filtering.")
        self.report.add("info", "policies", msg)

    def file_filter(self):
        """File-filter profiles (from PAN file-blocking)."""
        if not self.cfg.file_filters:
            return
        self.line()
        self.line("config file-filter profile")
        for ff in self.cfg.file_filters:
            self.line(f"    edit {_q(ff.name)}")
            if ff.comment:
                self.line(f"        set comment {_q(ff.comment[:255])}")
            self.line("        config rules")
            for r in ff.rules:
                self.line(f"            edit {_q(r['name'])}")
                self.line(f"                set action {r['action']}")
                self.line("                set direction any")
                self.line("                set protocol http ftp smtp imap "
                          "pop3 mapi cifs ssh")
                self.line("                set file-type "
                          + " ".join(_q(t) for t in r["file_types"]))
                self.line("            next")
            self.line("        end")
            self.line("    next")
        self.line("end")
        self.report.add(
            "info", "policies",
            f"{len(self.cfg.file_filters)} file-filter profile(s) created from "
            "PAN file-blocking. Inspects HTTP/FTP/SMTP/IMAP/POP3/MAPI/CIFS/SSH; "
            "encrypted-archive detection is an antivirus feature, not "
            "file-filter — review if the source blocked encrypted files.")

    def antivirus(self):
        """Antivirus profiles (from PAN antivirus/virus)."""
        if not self.cfg.av_profiles:
            return
        self.line()
        self.line("config antivirus profile")
        for av in self.cfg.av_profiles:
            self.line(f"    edit {_q(av.name)}")
            if av.comment:
                self.line(f"        set comment {_q(av.comment[:255])}")
            for proto, action in av.protocols.items():
                self.line(f"        config {proto}")
                self.line(f"            set av-scan {action}")
                self.line("        end")
            self.line("    next")
        self.line("end")
        self.report.add(
            "info", "policies",
            f"{len(self.cfg.av_profiles)} antivirus profile(s) created from "
            "PAN antivirus (per-protocol scan intent). The FortiGuard AV "
            "engine and signatures do the scanning; scanning HTTPS needs a "
            "deep-inspection ssl-ssh profile (policies attach the built-in "
            "certificate-inspection by default).")

    def ips(self):
        """IPS sensors (from PAN anti-spyware / vulnerability)."""
        if not self.cfg.ips_sensors:
            return
        self.line()
        self.line("config ips sensor")
        for s in self.cfg.ips_sensors:
            self.line(f"    edit {_q(s.name)}")
            if s.comment:
                self.line(f"        set comment {_q(s.comment[:255])}")
            self.line("        config entries")
            for i, e in enumerate(s.entries, start=1):
                self.line(f"            edit {i}")
                if e.get("severity"):
                    self.line("                set severity "
                              + " ".join(e["severity"]))
                if e.get("cve"):
                    self.line("                set cve " + " ".join(e["cve"]))
                self.line(f"                set action {e['action']}")
                if e.get("quarantine"):
                    self.line("                set quarantine "
                              f"{e['quarantine']}")
                if e.get("log"):
                    self.line(f"                set log {e['log']}")
                self.line("            next")
            self.line("        end")
            self.line("    next")
        self.line("end")
        self.report.add(
            "info", "policies",
            f"{len(self.cfg.ips_sensors)} IPS sensor(s) created from PAN "
            "anti-spyware/vulnerability, mapped at severity + CVE level with "
            "FortiGuard-recommended actions as the baseline. Cross-vendor IPS "
            "is posture parity, NOT signature-for-signature — validate and "
            "tune before enforcing.")

    def vpn(self):
        cfg = self.cfg
        if not cfg.phase1s:
            return
        self.line()
        self.line("config vpn ipsec phase1-interface")
        for p1 in cfg.phase1s:
            self.line(f"    edit {_q(p1.name)}")
            self.line(f"        set interface "
                      f"{_q(_intf(cfg, p1.interface))}")
            if p1.ike_version == 2:
                self.line("        set ike-version 2")
            self.line("        set peertype any")
            if p1.proposals:
                self.line("        set proposal " + " ".join(p1.proposals))
            else:
                # never emit a bare 'set proposal' (FortiOS rejects it and can
                # abort the rest of the edit block) -- substitute a safe default
                # and flag it for verification.
                self.line("        set proposal " + _DEFAULT_PROPOSAL)
                self.report.add(
                    "warn", "vpn",
                    f"phase1 '{p1.name}': no IKE proposal parsed from source; "
                    f"emitted default '{_DEFAULT_PROPOSAL}' -- verify against "
                    "the peer", p1.source)
            if p1.dhgrp:
                self.line("        set dhgrp " + " ".join(p1.dhgrp))
            self.line(f"        set remote-gw {p1.remote_gw}")
            self.line(f"        set psksecret {_q(p1.psk)}")
            if p1.psk_remote:
                self.line(f"        set psksecret-remote "
                          f"{_q(p1.psk_remote)}")
            if p1.keylife:
                self.line(f"        set keylife {p1.keylife}")
            if p1.comment:
                self.line(f"        set comments {_q(p1.comment[:255])}")
            self.line("    next")
        self.line("end")
        self.line()
        self.line("config vpn ipsec phase2-interface")
        for p2 in cfg.phase2s:
            self.line(f"    edit {_q(p2.name)}")
            self.line(f"        set phase1name {_q(p2.phase1)}")
            if p2.proposals:
                self.line("        set proposal " + " ".join(p2.proposals))
            else:
                self.line("        set proposal " + _DEFAULT_PROPOSAL)
                self.report.add(
                    "warn", "vpn",
                    f"phase2 '{p2.name}': no IPsec proposal parsed from source; "
                    f"emitted default '{_DEFAULT_PROPOSAL}' -- verify against "
                    "the peer", p2.source)
            if p2.pfs_group:
                self.line(f"        set dhgrp {p2.pfs_group}")
            else:
                # ASA's default is PFS off; FortiOS default is PFS on —
                # without this line the SAs silently fail to match
                self.line("        set pfs disable")
            if p2.keylife:
                self.line(f"        set keylifeseconds {p2.keylife}")
            try:
                src = ipaddress.IPv4Network(p2.src, strict=False)
                dst = ipaddress.IPv4Network(p2.dst, strict=False)
            except ValueError:
                self.report.add("error", "vpn",
                                f"phase2 '{p2.name}': bad selector "
                                f"{p2.src} -> {p2.dst}", p2.source)
                self.line("    next")
                continue
            self.line(f"        set src-subnet {src.network_address} "
                      f"{src.netmask}")
            self.line(f"        set dst-subnet {dst.network_address} "
                      f"{dst.netmask}")
            self.line("    next")
        self.line("end")
        self.report.add(
            "info", "vpn",
            f"{len(cfg.phase1s)} route-based tunnel(s) emitted with "
            f"{len(cfg.phase2s)} phase2 selector(s), plus tunnel routes "
            "and VPN policies. Verify proposals/PSKs against the peer and "
            "bring the tunnel up with: diagnose vpn ike gateway list")

    def vips(self):
        emittable = [v for v in self.cfg.vips
                     if v.ext_ip and not v.ext_ip.startswith("<")
                     and v.mapped_ip and not v.mapped_ip.startswith("<")]
        for v in self.cfg.vips:
            if v not in emittable:
                self.report.add(
                    "error", "nat",
                    f"VIP '{v.name}' incomplete (external or mapped ip "
                    "unresolved) — not emitted, convert manually", v.source)
        if not emittable:
            return
        if self.nat_mode == "central":
            self.report.add(
                "info", "nat",
                f"{len(emittable)} VIP(s) created. In central NAT mode "
                "they act as the central DNAT table — policies referencing "
                "the internal hosts (as emitted) are correct.")
        else:
            self.report.add(
                "info", "nat",
                f"{len(emittable)} VIP(s) created from static NAT. FortiOS "
                "matches inbound DNAT traffic on the VIP object — review "
                "policies whose dstaddr is the VIP's internal host and "
                "decide whether they should reference the VIP instead.",
            )
        self.line()
        self.line("config firewall vip")
        for v in emittable:
            self.line(f"    edit {_q(v.name)}")
            self.line(f"        set extip {_q(v.ext_ip)}")
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
        v4 = [r for r in self.cfg.routes if not _is_v6(r.dest)]
        v6 = [r for r in self.cfg.routes if _is_v6(r.dest)]
        if v4:
            self.line()
            self.line("config router static")
            for i, rt in enumerate(v4, start=1):
                try:
                    net = ipaddress.IPv4Network(rt.dest, strict=False)
                except ValueError:
                    self.report.add("error", "routes",
                                    f"route to '{rt.dest}' invalid — skipped",
                                    rt.source)
                    continue
                self.line(f"    edit {i}")
                if net.prefixlen or net.network_address != \
                        ipaddress.IPv4Address("0.0.0.0"):
                    self.line(f"        set dst {net.network_address} "
                              f"{net.netmask}")
                if rt.gateway:
                    self.line(f"        set gateway {rt.gateway}")
                self.line("        set device "
                          + _q(_intf(self.cfg, rt.interface)))
                if rt.distance != 10:
                    self.line(f"        set distance {rt.distance}")
                self.line("    next")
            self.line("end")
        if v6:
            self.line()
            self.line("config router static6")
            for i, rt in enumerate(v6, start=1):
                self.line(f"    edit {i}")
                self.line(f"        set dst {rt.dest}")
                if rt.gateway:
                    self.line(f"        set gateway {rt.gateway}")
                self.line("        set device "
                          + _q(_intf(self.cfg, rt.interface)))
                if rt.distance != 10:
                    self.line(f"        set distance {rt.distance}")
                self.line("    next")
            self.line("end")
            self.report.add("info", "routes",
                            f"{len(v6)} IPv6 route(s) emitted as router "
                            "static6")

    def _derived_router_id(self, proto: str) -> str:
        """A usable router-id when the source relied on auto-derivation:
        the first interface IP (deterministic), loudly reported."""
        for itf in self.cfg.interfaces:
            if itf.ip:
                rid = itf.ip.split("/")[0]
                self.report.add(
                    "warn", "routing",
                    f"{proto}: source had no explicit router-id (Junos/"
                    f"PAN auto-derive theirs) — set to {rid} (first "
                    "interface IP); change it if the design expects "
                    "another")
                return rid
        self.report.add(
            "error", "routing",
            f"{proto}: no router-id and no interface IP to derive one — "
            "set 'set router-id' manually before this section loads")
        return ""

    def bgp(self):
        b = self.cfg.bgp
        if b is None:
            return
        rid = b.router_id or self._derived_router_id("BGP")
        self.line()
        self.line("config router bgp")
        self.line(f"    set as {b.asn}")
        if rid:
            self.line(f"    set router-id {rid}")
        if b.neighbors:
            self.line("    config neighbor")
            for n in b.neighbors:
                self.line(f"        edit {_q(n.ip)}")
                if n.remote_as:
                    self.line(f"            set remote-as {n.remote_as}")
                else:
                    self.report.add(
                        "error", "routing",
                        f"BGP neighbor {n.ip}: no remote-as — FortiOS "
                        "requires it; set it manually before this loads",
                        n.source)
                if n.description:
                    self.line(f"            set description "
                              f"{_q(n.description[:63])}")
                self.line("        next")
                if n.has_password:
                    self.report.add(
                        "error", "routing",
                        f"BGP neighbor {n.ip}: source uses MD5/auth "
                        "password — not carried over; set 'set password' "
                        "on the neighbor", n.source)
            self.line("    end")
        if b.networks:
            self.line("    config network")
            for i, net in enumerate(b.networks, start=1):
                try:
                    n4 = ipaddress.IPv4Network(net, strict=False)
                except ValueError:
                    self.report.add("warn", "routing",
                                    f"BGP network '{net}' invalid — "
                                    "skipped", b.source)
                    continue
                self.line(f"        edit {i}")
                self.line(f"            set prefix {n4.network_address} "
                          f"{n4.netmask}")
                self.line("        next")
            self.line("    end")
        for r in b.redistribute:
            self.line(f"    config redistribute {_q(r)}")
            self.line("        set status enable")
            self.line("    end")
        self.line("end")
        self.report.add(
            "info", "routing",
            f"BGP converted: AS {b.asn}, {len(b.neighbors)} neighbor(s), "
            f"{len(b.networks)} network(s)"
            + (f", redistribute {', '.join(b.redistribute)}"
               if b.redistribute else "")
            + ". Import/export routing policies are NOT converted — "
            "recreate as route-maps and verify advertisements before "
            "cutover")

    def ospf(self):
        o = self.cfg.ospf
        if o is None:
            return
        rid = o.router_id or self._derived_router_id("OSPF")
        self.line()
        self.line("config router ospf")
        if rid:
            self.line(f"    set router-id {rid}")
        passive = sorted({p for a in o.areas for p in a.passive})
        if passive:
            self.line("    set passive-interface "
                      + " ".join(_q(_intf(self.cfg, p)) for p in passive))
        if o.areas:
            self.line("    config area")
            for a in o.areas:
                self.line(f"        edit {a.id}")
                self.line("        next")
            self.line("    end")
            nets_total = sum(len(a.networks) for a in o.areas)
            if nets_total:
                self.line("    config network")
                i = 0
                for a in o.areas:
                    for net in a.networks:
                        try:
                            n4 = ipaddress.IPv4Network(net, strict=False)
                        except ValueError:
                            self.report.add(
                                "warn", "routing",
                                f"OSPF network '{net}' (area {a.id}) "
                                "invalid — skipped", a.source)
                            continue
                        i += 1
                        self.line(f"        edit {i}")
                        self.line(f"            set prefix "
                                  f"{n4.network_address} {n4.netmask}")
                        self.line(f"            set area {a.id}")
                        self.line("        next")
                self.line("    end")
        for r in o.redistribute:
            self.line(f"    config redistribute {_q(r)}")
            self.line("        set status enable")
            self.line("    end")
        self.line("end")
        nets = sum(len(a.networks) for a in o.areas)
        self.report.add(
            "info", "routing",
            f"OSPF converted: {len(o.areas)} area(s), {nets} network "
            "statement(s)"
            + (f", passive: {', '.join(passive)}" if passive else "")
            + ". Costs, timers, and authentication are NOT carried — "
            "verify adjacencies form before cutover")

    def policies(self):
        if not self.cfg.policies:
            return
        # apply interface-PAT NAT intents (policy NAT mode only; central
        # mode carries NAT in central-snat-map instead)
        nat_pairs = set() if self.nat_mode == "central" else {
            (n.real_ifc, n.mapped_ifc) for n in self.cfg.nats
            if n.kind == "dynamic-interface"}
        applied_nat = 0
        fam = self._family_map()
        v6_policies = 0
        mixed_policies = 0
        self.line()
        self.line("config firewall policy")
        for i, p in enumerate(self.cfg.policies, start=1):
            src_i = [_intf(self.cfg, z) for z in (p.src_zones or ["any"])]
            dst_i = [_intf(self.cfg, z) for z in (p.dst_zones or ["any"])]
            pfam = self._policy_family(p, fam)
            if pfam == 6:
                v6_policies += 1
            elif pfam == 0:
                mixed_policies += 1
            self.line(f"    edit {i}")
            if p.name:
                self.line(f"        set name {_q(p.name)}")
            self.line("        set srcintf "
                      + " ".join(_q(z) for z in src_i))
            self.line("        set dstintf "
                      + " ".join(_q(z) for z in dst_i))
            self._addr_lines("srcaddr", p.src_addrs or ["all"], pfam, fam)
            if p.src_negate:
                for neg in (("srcaddr-negate", "srcaddr6-negate")
                            if pfam == 0 else
                            ("srcaddr6-negate",) if pfam == 6 else
                            ("srcaddr-negate",)):
                    self.line(f"        set {neg} enable")
            self._addr_lines("dstaddr", p.dst_addrs or ["all"], pfam, fam)
            if p.dst_negate:
                for neg in (("dstaddr-negate", "dstaddr6-negate")
                            if pfam == 0 else
                            ("dstaddr6-negate",) if pfam == 6 else
                            ("dstaddr-negate",)):
                    self.line(f"        set {neg} enable")
            if p.action == "accept":
                self.line("        set action accept")
            self.line('        set schedule "always"')
            self.line("        set service "
                      + " ".join(_q(s) for s in (p.services or ["ALL"])))
            self.line("        set logtraffic "
                      + ("all" if p.log else "disable"))
            if (p.app_list or p.webfilter or p.file_filter or p.antivirus
                    or p.ips_sensor):
                self.line("        set utm-status enable")
                # webfilter / file-filter / antivirus / IPS on HTTPS need an
                # SSL-inspection profile; the built-in certificate-inspection
                # (SNI-based) needs no CA rollout. app-control alone keeps
                # prior behavior (no ssl-ssh-profile line).
                if p.webfilter or p.file_filter or p.antivirus or p.ips_sensor:
                    self.line('        set ssl-ssh-profile '
                              '"certificate-inspection"')
                if p.app_list:
                    self.line(f"        set application-list {_q(p.app_list)}")
                if p.antivirus:
                    self.line(f"        set av-profile {_q(p.antivirus)}")
                if p.ips_sensor:
                    self.line(f"        set ips-sensor {_q(p.ips_sensor)}")
                if p.webfilter:
                    self.line("        set webfilter-profile "
                              f"{_q(p.webfilter)}")
                if p.file_filter:
                    self.line("        set file-filter-profile "
                              f"{_q(p.file_filter)}")
            nat_hit = any(
                (sz, dz) in nat_pairs or ("*", dz) in nat_pairs
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
        if v6_policies:
            self.report.add(
                "info", "policies",
                f"{v6_policies} IPv6 policy(ies) emitted with srcaddr6/"
                "dstaddr6 (unified policy table; target FortiOS 7.0+)")
        if mixed_policies:
            self.report.add(
                "info", "policies",
                f"{mixed_policies} mixed-family policy(ies) emitted with "
                "complete v4 AND v6 address pairs (a side with no objects "
                "of one family gets the built-in 'none' so that leg "
                "matches nothing, as in the source)")

    def _policy_family(self, p, fam: dict[str, int]) -> int:
        if p.family in (4, 6):
            return p.family
        names = [n for n in (p.src_addrs + p.dst_addrs) if n != "all"]
        has6 = any(fam.get(n) == 6 for n in names)
        has4 = any(fam.get(n, 4) == 4 for n in names)
        if has6 and not has4:
            return 6
        if has6 and has4:
            return 0  # mixed — emit both families
        return 4

    def _addr_lines(self, attr: str, names: list[str], pfam: int,
                    fam: dict[str, int]) -> None:
        if pfam == 6:
            self.line(f"        set {attr}6 "
                      + " ".join(_q(a) for a in names))
        elif pfam == 4:
            self.line(f"        set {attr} "
                      + " ".join(_q(a) for a in names))
        else:  # mixed: FortiOS needs a COMPLETE src/dst pair per family,
            # so emit this side for both. "all" passes to both tables; a
            # side with no names of one family gets the built-in "none"
            # so that family's leg keeps matching nothing — exactly the
            # source semantics, and still correct under negate (NOT none
            # = everything, matching how the source rule evaluates).
            v4 = [a for a in names if fam.get(a, 4) != 6 or a == "all"]
            v6 = [a for a in names if fam.get(a) == 6 or a == "all"]
            self.line(f"        set {attr} "
                      + " ".join(_q(a) for a in (v4 or ["none"])))
            self.line(f"        set {attr}6 "
                      + " ".join(_q(a) for a in (v6 or ["none"])))


def emit(cfg: FirewallConfig, report, target: str = "7.4",
         nat_mode: str = "policy") -> str:
    map_builtin_services(cfg, report)
    return Emitter(cfg, report, target, nat_mode).emit()
