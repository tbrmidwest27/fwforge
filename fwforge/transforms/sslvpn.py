"""SSL-VPN -> IPsec dial-up migration assistant.

FortiOS 7.6 removed SSL-VPN tunnel mode and 8.0 finished the job, so a
config carrying `config vpn ssl settings` with a tunnel-mode portal won't
provide remote access on a current target. The Fortinet-recommended
replacement is an IKEv2 dial-up IPsec tunnel (FortiClient), and this builds
that scaffold from the SSL-VPN config:

  SSL-VPN                              ->  IPsec phase1-interface (dial-up)
  source-interface                    ->  set interface
  tunnel-ip-pools (iprange object)    ->  mode-cfg ipv4-start-ip/end-ip
  portal split-tunneling-routing-addr ->  set ipv4-split-include
  authentication-rule groups          ->  set authusrgrp (+ EAP)
  policies on ssl.<vdom>              ->  rewritten to the new tunnel intf

This is a *scaffold*, exactly like FortiConverter's assistant: the result
needs a real PSK, client reprovisioning to FortiClient IKEv2, and review
of features with no IPsec equivalent (web-mode bookmarks, host-check). All
of that is reported, never silent. SSL-VPN sections are removed (they fail
to load on the target). Web-mode-only SSL-VPN is left untouched + flagged
(IPsec replaces tunnel mode only).

Operates per VDOM scope, so it is correct on multi-VDOM configs.
"""
from __future__ import annotations

from ..parsers.fortios_tree import (
    ConfigNode,
    CTree,
    EditNode,
    SetLine,
    Token,
    find_config_under,
    vdom_scopes,
)
from .tree_refs import insert_in_scope


def _scope_containers(tree: CTree):
    scopes = vdom_scopes(tree)
    if len(scopes) == 1 and scopes[0][0] is None:
        return [("root", tree)]
    return [(n, c) for n, c in scopes if n not in (None, "global")]


def _get(node: ConfigNode, attr: str) -> list[str]:
    for c in node.children:
        if isinstance(c, SetLine) and c.attr == attr:
            return [t.value for t in c.values]
    return []


def _one(node: ConfigNode, attr: str, default: str = "") -> str:
    v = _get(node, attr)
    return v[0] if v else default


def _child_config(node: ConfigNode, name: str) -> ConfigNode | None:
    for c in node.children:
        if isinstance(c, ConfigNode) and c.path == [name]:
            return c
    return None


def _find_edit(node: ConfigNode, name: str) -> EditNode | None:
    for c in node.children:
        if isinstance(c, EditNode) and c.name.value == name:
            return c
    return None


def _address_range(container, name: str) -> tuple[str, str] | None:
    addrs = find_config_under(container, "firewall", "address")
    if addrs is None:
        return None
    edit = _find_edit(addrs, name)
    if edit is None:
        return None
    start = _one(edit, "start-ip")
    end = _one(edit, "end-ip")
    if start and end:
        return start, end
    return None


def _upsert_ipsec(container, phase: str, name: str,
                  lines: list[SetLine]) -> None:
    node = find_config_under(container, "vpn", "ipsec", phase)
    if node is None:
        node = ConfigNode(["vpn", "ipsec", phase])
        insert_in_scope(container, node)
    if _find_edit(node, name):
        return
    edit = EditNode(Token(name, True))
    edit.children = lines
    node.children.append(edit)


def _sl(attr: str, *values: str) -> SetLine:
    return SetLine(attr, [Token(v, not v.replace(".", "").replace("-", "")
                                .replace("_", "").isalnum() or v == "")
                          for v in values])


def _convert_scope(vdom: str, container, report, psk: str,
                   tunnel_name: str) -> int:
    settings = find_config_under(container, "vpn", "ssl", "settings")
    if settings is None:
        return 0

    portals = find_config_under(container, "vpn", "ssl", "web", "portal")
    tunnel_portals = []
    if portals is not None:
        for e in portals.children:
            if isinstance(e, EditNode) and _one(e, "tunnel-mode") == "enable":
                tunnel_portals.append(e)
    if not tunnel_portals:
        report.add(
            "warn", "sslvpn",
            f"[{vdom}] SSL-VPN has no tunnel-mode portal (web-mode only) — "
            "IPsec replaces tunnel mode only; left SSL-VPN untouched, "
            "review separately")
        return 0

    src_if = _one(settings, "source-interface", "wan1")
    servercert = _one(settings, "servercert")
    pools = _get(settings, "tunnel-ip-pools")

    groups: list[str] = []
    auth = _child_config(settings, "authentication-rule")
    if auth is not None:
        for e in auth.children:
            if isinstance(e, EditNode):
                groups += _get(e, "groups")
    seen: set[str] = set()
    groups = [g for g in groups if not (g in seen or seen.add(g))]

    # split-tunnel destination from the (first) tunnel portal
    split_addr = ""
    for p in tunnel_portals:
        if _one(p, "split-tunneling") == "enable":
            split_addr = _one(p, "split-tunneling-routing-address")
            if split_addr:
                break

    # mode-cfg pool from the tunnel-ip-pools address object
    rng = None
    pool_name = pools[0] if pools else ""
    if not pool_name and tunnel_portals:
        ipp = _get(tunnel_portals[0], "ip-pools")
        pool_name = ipp[0] if ipp else ""
    if pool_name:
        rng = _address_range(container, pool_name)

    p1: list[SetLine] = [
        _sl("type", "dynamic"),
        SetLine("interface", [Token(src_if, True)]),
        _sl("ike-version", "2"),
        _sl("peertype", "dialup"),
        _sl("net-device", "disable"),
        _sl("mode-cfg", "enable"),
        _sl("proposal", "aes256-sha256", "aes128-sha256"),
        _sl("dhgrp", "14"),
        _sl("eap", "enable"),
        _sl("eap-identity", "send-request"),
    ]
    if groups:
        p1.append(SetLine("authusrgrp", [Token(groups[0], True)]))
        if len(groups) > 1:
            report.add("info", "sslvpn",
                       f"[{vdom}] SSL-VPN had multiple groups "
                       f"({', '.join(groups)}); phase1 'authusrgrp' takes "
                       "one — combine them into a single user group")
    if rng:
        p1.append(_sl("ipv4-start-ip", rng[0]))
        p1.append(_sl("ipv4-end-ip", rng[1]))
        p1.append(_sl("ipv4-netmask", "255.255.255.255"))
        report.add("info", "sslvpn",
                   f"[{vdom}] mode-cfg pool {rng[0]}-{rng[1]} taken from "
                   f"'{pool_name}'; verify ipv4-netmask (set to /32 per "
                   "client — adjust if your clients need a wider mask)")
    else:
        report.add("warn", "sslvpn",
                   f"[{vdom}] could not resolve the SSL-VPN tunnel IP pool "
                   f"'{pool_name}' to a range — set mode-cfg "
                   "ipv4-start-ip/ipv4-end-ip on the new phase1 manually")
    if split_addr:
        p1.append(SetLine("ipv4-split-include", [Token(split_addr, True)]))
    else:
        report.add("info", "sslvpn",
                   f"[{vdom}] no split tunnel on the SSL-VPN portal — "
                   "FortiClient will full-tunnel; set ipv4-split-include "
                   "if you want split tunneling")
    p1.append(SetLine("psksecret", [Token(psk, True)]))
    if servercert:
        p1.append(SetLine("comments", [Token(
            f"from SSL-VPN; servercert was {servercert} — switch to "
            "authmethod signature if you prefer cert auth over PSK+EAP",
            True)]))

    # phase2 first, then phase1, so phase1 lands ahead of phase2 in the
    # output (phase2 references phase1name; correct CLI paste order)
    _upsert_ipsec(container, "phase2-interface", f"{tunnel_name}-p2", [
        SetLine("phase1name", [Token(tunnel_name, True)]),
        _sl("src-subnet", "0.0.0.0", "0.0.0.0"),
        _sl("dst-subnet", "0.0.0.0", "0.0.0.0"),
    ])
    _upsert_ipsec(container, "phase1-interface", tunnel_name, p1)

    # rewrite policies that came in on the SSL-VPN interface
    rewired = 0
    policy = find_config_under(container, "firewall", "policy")
    if policy is not None:
        for e in policy.children:
            if not isinstance(e, EditNode):
                continue
            for line in e.children:
                if isinstance(line, SetLine) and line.attr == "srcintf":
                    new_vals = []
                    hit = False
                    for t in line.values:
                        if t.value.startswith("ssl."):
                            new_vals.append(Token(tunnel_name, True))
                            hit = True
                        else:
                            new_vals.append(t)
                    if hit:
                        line.values = new_vals
                        rewired += 1
    if rewired:
        report.add("info", "sslvpn",
                   f"[{vdom}] rewired {rewired} policy(ies) from the SSL-VPN "
                   f"interface to '{tunnel_name}' (user groups preserved)")

    # remove the SSL-VPN sections (they don't load on 7.6+/8.0)
    removed = []
    keep = []
    for c in container.children:
        if isinstance(c, ConfigNode) and c.path in (
                ["vpn", "ssl", "settings"], ["vpn", "ssl", "web", "portal"],
                ["vpn", "ssl", "web"]):
            removed.append(" ".join(c.path))
        else:
            keep.append(c)
    container.children = keep
    if removed:
        report.add("info", "sslvpn",
                   f"[{vdom}] removed SSL-VPN config ({', '.join(removed)})")

    report.add(
        "warn", "sslvpn",
        f"[{vdom}] SSL-VPN -> IPsec dial-up scaffold created as "
        f"'{tunnel_name}'. ACTION REQUIRED: (1) set a real PSK (placeholder "
        "emitted), (2) reprovision clients to FortiClient IKEv2 / native "
        "IPsec — SSL-VPN web portals, bookmarks, and host-check have no "
        "IPsec equivalent, (3) confirm the user group does EAP auth.")
    return 1


def convert(tree: CTree, report, psk: str = "CHANGEME-SET-A-REAL-PSK",
            tunnel_name: str = "dialup-ipsec") -> dict:
    total = 0
    for vdom, container in _scope_containers(tree):
        total += _convert_scope(vdom, container, report, psk, tunnel_name)
    if total == 0:
        report.add("info", "sslvpn",
                   "no convertible SSL-VPN tunnel-mode config found")
    return {"tunnels": total}
