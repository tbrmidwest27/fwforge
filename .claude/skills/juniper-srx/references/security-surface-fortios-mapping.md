# Juniper SRX / Junos OS — SECURITY Configuration Surface & FortiOS Mapping

**Authoritative converter reference + SRX expertise. Every Junos fact below is grounded in Juniper's official TechLibrary (`www.juniper.net/documentation`); FortiOS mapping targets cite `docs.fortinet.com`. Exact URLs are cited per section.**

> **Why this document exists.** A converter silently dropped an `lo0` stateless firewall filter — the SRX's control-plane protection — because nobody had a complete checklist of *"what an SRX security config contains."* This reference is that checklist. Two principles run through every section:
> 1. **Nothing is dropped silently.** Anything non-convertible goes in the report with its source file + line.
> 2. **No silent rule-broadening.** Where FortiOS has no 1:1 equivalent, the doc says **"re-model required"** and describes the re-model — it never implies a clean mapping. Negations, `reject` semantics, screens, and `inactive:` are the classic broadening/loss landmines.
>
> Landmine sections (silent protection loss if dropped) are flagged 🔴.

---

## 1. Security Zones + `host-inbound-traffic` 🔴 (control-plane access to the box)

**What it is.** A *security zone* is a logical grouping of interfaces with similar security requirements; policies are written `from-zone X to-zone Y`. A *functional zone* serves a special purpose — **only `management` is currently supported** ("functional-zone management"), is for dedicated OOB management interfaces, **cannot be named in a policy, and traffic arriving on it cannot transit the device**. A predefined, non-deletable **`junos-host`** zone exists for self/host traffic and (unlike `host-inbound-traffic`) *can* have policies, can restrict **outgoing** device traffic, and can apply NAT/IDP/Content-Security to device traffic.

**CLI shape.**
```
set security zones security-zone <name> interfaces <if>
set security zones security-zone <name> host-inbound-traffic system-services <svc>
set security zones security-zone <name> host-inbound-traffic protocols <proto>
# per-interface override (interface config overrides zone config):
set security zones security-zone <name> interfaces <if> host-inbound-traffic system-services <svc>
set security zones functional-zone management host-inbound-traffic system-services <svc>
```

**Security purpose — what `host-inbound-traffic` actually controls.** It governs **traffic destined to the SRX device itself (the Routing Engine)** arriving on that zone's interfaces — i.e. the **management/control plane**, NOT transit traffic. **It is deny-by-default**: "Inbound traffic destined to this device is dropped by default" — nothing reaches the RE until explicitly permitted. It only controls **incoming** to-the-box traffic (outgoing is the `junos-host` zone's job). Settable at zone level (all interfaces) or per-interface (override).

**Two SEPARATE knobs** (a converter must handle independently — permitting `ssh` does nothing for `ospf`):

- **`system-services`** — management/application services to the RE. Authoritative complete value set (verified identically on both zone-level and interface-level CLI references; introduced 8.5):
  `all`, `any-service`, `bootp`, `dhcp`, `dhcpv6`, `dns`, `finger`, `ftp`, `http`, `https`, `ident-reset`, `ike`, `lsping`, `netconf`, `ntp`, `ping`, `r2cp`, `reverse-ssh`, `reverse-telnet`, `rlogin`, `rpm`, `rsh`, `snmp`, `snmp-trap`, `ssh`, `telnet`, `tftp`, `traceroute`, `xnm-clear-text`, `xnm-ssl` — plus modifier `except` (subtract after `all`). `all` = all *defined* RE services; `any-service` = all services over the *entire port range*.
  > **Converter caveat — do not invent tokens.** `sip`, `sql-monitor`, `tcp-encap`, `webapi-clear-text`, `webapi-ssl` are **NOT** valid host-inbound-traffic system-services in the current CLI reference. Treat the list above as the closed set; report anything outside it.
- **`protocols`** — dynamic-routing / control-plane protocol packets to the RE. Authoritative complete set (introduced 8.5):
  `all`, `bfd`, `bgp`, `dvmrp`, `igmp`, `ldp`, `msdp`, `nhrp`, `ospf`, `ospf3`, `pgm`, `pim`, `rip`, `ripng`, `router-discovery`, `rsvp`, `sap`, `vrrp` — plus `except`.

**FortiOS mapping.** There is **no single equivalent**. To-the-box access on FortiGate is per-interface **`allowaccess`** (admin/mgmt protocols) plus **`local-in-policy`** (arbitrary services to the device). FortiGate has **no zone-level host-inbound concept** — a zone-level Junos stanza must **fan out onto every member interface**. FortiOS also *implicitly accepts* routing protocols where the routing process is configured (the inverse of Junos deny-by-default) — so the Junos `protocols` *restriction* is **lost** unless reproduced via `local-in-policy`.

| SRX item | FortiOS mechanism | Notes |
|---|---|---|
| `ping`/`ssh`/`https`/`http`/`snmp`/`telnet` | `allowaccess <token>` | Clean 1:1. |
| `snmp-trap` | SNMP config (outbound) | Box *sources* traps; no `allowaccess` token. Re-model. |
| `netconf` | `allowaccess ssh` + REST API | No `allowaccess netconf`. Re-model. |
| `ntp`/`dns`/`dhcp`/`bootp`/`dhcpv6` | feature config / `local-in-policy` | Only if FortiGate is the server/relay. Re-model. |
| `ike` | implicit on phase1-interface; restrict via `local-in-policy` | No `allowaccess` token. |
| `ftp`/`tftp`/`traceroute` | `local-in-policy` / `allowaccess ping` | Partial. |
| `finger`,`ident-reset`,`rlogin`,`rsh`,`r2cp`,`lsping`,`rpm`,`reverse-ssh`,`reverse-telnet`,`sap`,`xnm-*`,`any-service` | **None** | Report-only; never broaden to blanket `allowaccess`. |
| `protocols` bgp/ospf/ospf3/rip/ripng/pim/igmp/msdp/ldp/rsvp/bfd/dvmrp/nhrp/pgm/router-discovery | **Implicitly allowed**; restrict via `local-in-policy` | No `allowaccess` tokens. Junos restriction LOST unless reproduced. Re-model. |
| `protocols vrrp` | per-interface VRRP config | Not `allowaccess`. |

🔴 **Silent-loss flag.** `host-inbound-traffic` is **deny-by-default management/control-plane access control**. Dropping it causes one of two invisible regressions: **(1) over-open** — if the converter emits a permissive default `allowaccess`, the FortiGate becomes manageable on interfaces (e.g. WAN/untrust) the SRX deliberately kept closed; or **(2) over-restrict/breakage** — if it emits nothing, SSH/HTTPS admin and OSPF/BGP/BFD the SRX permitted are black-holed. Because silence on the SRX side means *blocked*, **dropping the stanza flips intent to *allowed***. The converter must translate `system-services`→per-interface `allowaccess`, `protocols`→`local-in-policy` (or at least a report entry), and report every no-equivalent token.

**Sources:** [system-services (zone)](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-system-service-zone-host-inbound-traffic.html) · [system-services (interface)](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-system-service-interface-host-inbound-traffic.html) · [protocols](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-protocols-zone-host-inbound-traffic.html) · [host-inbound-traffic concept](https://www.juniper.net/documentation/en_US/junos/topics/concept/zone-host-inbound-traffic-how-to-control-based-on-traffic-type-understanding.html) · [Security Zones](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-zone-configuration.html) · [functional-zone](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/security-edit-functional-zone.html) · [Configuring Security Policies (junos-host)](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html)

---

## 2. Security Policies 🔴 (negation, reject, scheduler are landmines)

**CLI shape.** A policy is a zone-pair-scoped, ordered rule with `match` (conditions) + `then` (action); `scheduler-name` is a **sibling of match/then, not under `then`**.
```
set security policies from-zone <s> to-zone <d> policy <name> match  source-address <a> destination-address <b> application <app>
set security policies from-zone <s> to-zone <d> policy <name> then   permit | deny | reject
set security policies from-zone <s> to-zone <d> policy <name> scheduler-name <sched>
set security policies global policy <name> ...            # cross-zone, evaluated last
set security policies default-policy deny-all | permit-all # default = deny-all
```

**MATCH criteria.** `source-address`/`destination-address` (address-book names, sets, or `any`); **`source-address-excluded`/`destination-address-excluded`** (NEGATION — exclude the set; **IPv6 does NOT support address-excluded**); `application` (predefined `junos-*`, custom under `[edit applications]`, `application-set`, or `any`); `source-identity` (user-role firewall: usernames/roles + `authenticated-user`/`unauthenticated-user`/`unknown-user`/`any`); `dynamic-application`/`dynamic-application-group` (L7 AppID; special values `any`=wildcard, `none`=ignore AppID); `url-category` (web-filter category as match, 18.4R1+).

**THEN actions.**
- **`permit`** / **`deny`** (silent drop — "device drops the packets") / **`reject`** — verbatim: *"drops the packet and sends a TCP reset (RST) … for TCP traffic and an ICMP 'destination unreachable, port unreachable' (type 3, code 3) for UDP"*; behaves like `deny` (silent) for non-TCP/UDP. **`deny` ≠ `reject`** — load-bearing semantic difference.
- **`log session-init | session-close`**, **`count`** (byte counter, optional alarm thresholds).
- **`permit tunnel ipsec-vpn <vpn> [pair-policy <rev>]`** (policy-based VPN; `pair-policy` shares one SA/proxy-ID).
- **`permit application-services`**: `utm-policy`, `idp` / `idp-policy <name>` (per-policy IDP, 18.2R1+, deprecates device-wide `active-policy`), `security-intelligence-policy`, `ssl-proxy {profile-name}`, `application-firewall {rule-set}`, `uac-policy`, `gprs-gtp-profile`/`gprs-sctp-profile`, `redirect-wx`/`reverse-redirect-wx`.

**Global / default / ordering.** Evaluation order verbatim: *"intra-zone (trust-to-trust), inter-zone (trust-to-untrust), then global."* `default-policy` default is **deny-all** (implicit, **cannot log** — add explicit terminal deny to log drops). **First-match wins** ("when it finds a match … it does not look any lower"); new policies append; reorder with `insert ... before|after`; detect eclipsed rules with `show security shadow-policies`. **Scheduler**: `set schedulers scheduler <name> daily|<weekday> start-time hh:mm:ss stop-time hh:mm:ss` then `... policy <p> scheduler-name <name>`.

**FortiOS mapping.**

| SRX policy field | FortiOS (`config firewall policy`) | Notes |
|---|---|---|
| `from-zone`/`to-zone` | `srcintf`/`dstintf` (zone or member ifs) | |
| `match source/destination-address` | `srcaddr`/`dstaddr` | If paired with DNAT/static NAT, `dstaddr` should be the **VIP** (see §3). |
| `source-address-excluded`/`destination-address-excluded` | `set srcaddr-negate enable` / `set dstaddr-negate enable` | 🔴 Dropping = rule BROADENED. IPv6 never has this. |
| `application junos-*/custom/set` | `service` (built-in only on **exact** semantic match; else custom) | `junos-https`→`HTTPS`; never reuse on loose match. |
| `application any` | `service ALL` | |
| `dynamic-application`/`-group` | `application-list` (App Control sensor) + `utm-status enable` | |
| `url-category` | `webfilter-profile` | |
| `source-identity` | `groups`/`users` (FSSO) | |
| `then permit` | `action accept` | |
| `then deny` | `action deny` (`send-deny-packet disable`) | Silent drop = default. |
| `then reject` | `action deny` + **`set send-deny-packet enable`** | 🔴 Plain `deny` LOSES RST/ICMP-unreachable. |
| `log session-init/close` | `logtraffic all` | Closest single knob. |
| `count` | `logtraffic all` (byte counters via logs) | No 1:1. |
| `permit tunnel ipsec-vpn` | route-based phase1/2-interface + route + policy on tunnel if | Policy-based VPN → route-based re-model. |
| `application-services` (utm/idp/appfw/ssl-proxy) | `utm-status` + `av/webfilter/ips-sensor/application-list/ssl-ssh-profile` | Profile re-models (see §7). |
| `scheduler-name` | `schedule` (`config firewall schedule recurring`) | 🔴 Dropping = always-on. |
| global policy | policy with `srcintf/dstintf any`, placed last | Preserve "evaluated last." |
| policy order | sequence of policy entries | Preserve exactly — both first-match. |

🔴 **Silent-loss flags.** (1) **address-excluded negation dropped → rule broadened** (the exact over-permit class the tool exists to prevent). (2) **`reject`→`deny`** changes behavior (apps that relied on fast RST/ICMP hang on timeout). (3) **`scheduler-name` dropped → policy 24/7** (exposure window). (4) **`application-services`/`dynamic-application`/`url-category` dropped → UTM/IDP/AppFW/AppID enforcement silently lost.**

**Sources:** [Configuring Security Policies](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html) · [source-address-excluded](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/ref/statement/source-address-excluded-edit-security.html) · [destination-address-excluded](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/destination-address-excluded-edit-security.html) · [reject](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-reject.html) · [deny](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-deny-policy.html) · [application-services](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-application-services.html) · [Global Security Policies](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-global-policies.html) · [default-policy](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-default-policy.html) · [Reordering Policies](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-reordering-policies.html) · [Scheduling Policies](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/scheduling-security-policy.html) · [Unified Policies](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/configuring-unified-policies.html) · [User Role Firewall](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-user-role-firewall-policy.html)

---

## 3. NAT 🔴 (post-DNAT/pre-SNAT policy match + proxy-arp are commonly mishandled)

Junos uses a unified rule-set model under `[edit security nat]` with three independent types — **source**, **destination**, **static** — each evaluated at a different point.

**Source NAT.** Actions `interface` (egress IP, **always PAT**, no pool/proxy-arp needed) | `pool` | `off`. Pool options: PAT default (up to 63,488 hosts/IP); `port no-translation` (disable PAT, host count = pool size); `port range`; `overflow-pool {interface|pool}`; `pool-utilization-alarm`; global `address-persistent` (same host→same pool IP across sessions). proxy-arp required when the pool overlaps the egress subnet.
```
set security nat source pool <p> address <ip>/<pfx> [to <ip>/<pfx>]
set security nat source pool <p> port no-translation
set security nat source rule-set <rs> from {zone|interface|routing-instance}
set security nat source rule-set <rs> to   {zone|interface|routing-instance}
set security nat source rule-set <rs> rule <r> match source-address <a> destination-address <b>
set security nat source rule-set <rs> rule <r> then source-nat {interface | pool <p> | off}
```

**Destination NAT.** `pool` (address + optional port = port-forward target) | `off`. Rule-set takes **`from` only** (no `to` — runs before route lookup). proxy-arp typically required.
```
set security nat destination pool <p> address <ip> [port <port>]
set security nat destination rule-set <rs> from {zone|interface|routing-instance}
set security nat destination rule-set <rs> rule <r> match destination-address <ip/pfx> [destination-port <port>]
set security nat destination rule-set <rs> rule <r> then destination-nat pool <p>
```

**Static NAT.** One-to-one, **bidirectional + auto-reverse** ("connections … from either side"; reverse direction reverse-matches the rule). `mapped-port` for port mapping. `from` only. proxy-arp required.
```
set security nat static rule-set <rs> from {zone|interface|routing-instance}
set security nat static rule-set <rs> rule <r> match destination-address <public-pfx>
set security nat static rule-set <rs> rule <r> then static-nat prefix <private-pfx> [mapped-port <port|range>]
```

**Persistent NAT** (full-cone / VoIP), on source rules: `persistent-nat permit {any-remote-host (full-cone) | target-host (restricted-cone) | target-host-port (port-restricted-cone)}`. Distinct from `address-persistent` (which is source-pool stickiness, not external-device mapping).

**proxy-arp.** SRX must answer ARP for NAT addresses it doesn't own but that live in an interface's subnet: `set security nat proxy-arp interface <if> address <ip | to-range>` (IPv6: `proxy-ndp`).

**🔴 Processing order & the commonly-mishandled policy-match rule.** Verbatim flow: **1 static → 2 destination → 3 route lookup → 4 security policy lookup → 5 reverse-static → 6 source.** Precedence: **static > destination > source**, with **policy lookup BETWEEN destination NAT and source NAT.** Therefore a Junos policy matches on the **POST-destination-NAT (private) destination** and the **PRE-source-NAT (original) source** — written `original-source → translated(private)-destination`. (This is also why dest/static rule-sets take only `from`.)

**FortiOS mapping.**

| SRX NAT | FortiOS | Notes |
|---|---|---|
| Source NAT, interface (egress PAT) | policy `set nat enable` / central-SNAT, no IP pool | Outbound PAT to interface IP. |
| Source NAT pool **with** PAT | IP pool `type overload` | |
| Source NAT pool **without** PAT (`port no-translation`) | IP pool `type one-to-one` (or `fixed-port-range`) | |
| `source pool port range` | IP pool `type fixed-port-range` | |
| `address-persistent` | one-to-one / sticky pool | When "same host→same IP" required. |
| Destination NAT (+ port) | **VIP** (`extip`=public, `mappedip`=private, `portforward`, `extport`/`mappedport`) | Reference VIP in policy `dstaddr`. |
| Static NAT (1:1 bidir) | **VIP** + `set nat-source-vip enable` (or paired pool) | 🔴 VIP alone = inbound only; reverse SNAT needs nat-source-vip. |
| Static NAT `mapped-port` | VIP `portforward` + `mappedport` | |
| `persistent-nat any-remote-host` | IP pool `type one-to-one` (NOT overload) | 🔴 overload destroys full-cone/STUN. |
| `persistent-nat target-host[-port]` | one-to-one pool + note | No exact knob. |
| `proxy-arp` | **automatic** — VIP/pool `arp-reply` (default on) | 🔴 Verify arp-reply stays enabled; don't drop the intent. |
| NAT mode | `central-nat enable` (mirrors SRX separate-from-policy) vs policy-NAT | Pick one consistently. |

🔴 **Commonly mishandled.** (1) **Policy-matches-on-post-DNAT/pre-SNAT** — FortiOS is the opposite for DNAT (policy `dstaddr` = the VIP/public side). Build the VIP so `mappedip` = SRX policy destination, `extip` = SRX DNAT `match destination-address`; set policy `dstaddr` to the VIP. Inverting it silently breaks reachability or broadens the policy. (2) **proxy-arp silently dropped** → NAT addresses go unanswered. (3) **Static NAT bidirectionality** — emitting just the VIP loses the outbound half. (4) **persistent-nat → wrong pool type** (overload instead of one-to-one) destroys VoIP behavior.

**Sources:** [NAT Overview (order)](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-nat-overview.html) · [Source NAT](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/nat-security-source-and-source-pool.html) · [Destination NAT](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-nat-destination.html) · [Static NAT](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-nat-static.html) · [Persistent NAT/NAT64](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-persistent-nat-and-nat64.html) · [Destination NAT understanding (DNAT-then-policy)](https://www.juniper.net/documentation/en_US/junos/topics/concept/nat-security-destination-understanding.html) · [Proxy ARP](https://www.juniper.net/documentation/en_US/junos/topics/task/configuration/nat-security-proxy-arp-configuring-cli.html) · [NAT User Guide PDF](https://www.juniper.net/documentation/us/en/software/junos/nat/nat.pdf)

---

## 4. Screens (`security screen ids-option`) 🔴🔴 COMMONLY DROPPED SILENTLY

**What it is.** A named IDS profile (`ids-option`) defined once, **bound per-zone**, evaluated on **ingress before policy lookup**. One screen object per zone (one profile reusable on many zones).
```
set security screen ids-option <name> tcp syn-flood attack-threshold 200
set security screen ids-option <name> icmp flood threshold 1000
set security screen ids-option <name> ip spoofing
set security zones security-zone <zone> screen <name>
```

**Full category list** (Junos names + key defaults from per-statement CLI-ref leaf pages; `pps`=packets/sec, `µs`=microseconds; ranges vary by platform):

- **ICMP** `icmp{}`: `flood threshold` (default **1000 pps**), `ip-sweep threshold` (default **5000 µs**), `fragment`, `large` (>1024 B), `ping-death`, `icmpv6-malformed`. (ICMP sweep is `ip-sweep`; there is no bare `sweep`.)
- **IP** `ip{}`: `bad-option`, `record-route-option`, `timestamp-option`, `security-option`, `stream-option`, `spoofing`, `source-route-option`, `loose-source-route-option`, `strict-source-route-option`, `unknown-protocol`, `tear-drop`, `block-frag`, `ipv6-malformed-header`, `ipv6-extension-header-limit <0–32>`, `ipv6-extension-header {AH/ESP/HIP/destination/fragment/hop-by-hop/mobility/no-next/routing/shim6/user-defined}`. (IP fragment screening is `block-frag`+`tear-drop`; `fragment` exists only under `icmp`.)
- **TCP** `tcp{}`: `syn-flood {attack-threshold (200 pps), alarm-threshold (see conflict note), source-threshold (4000/s), destination-threshold (4000/s), timeout (20s), white-list}`, `syn-fin`, `fin-no-ack`, `tcp-no-flag`, `syn-frag`, `port-scan threshold` (5000 µs), `land`, `winnuke`, `syn-ack-ack-proxy threshold` (512), `tcp-sweep threshold` (5000 µs).
- **UDP** `udp{}`: `flood threshold` (1000 pps), `udp-sweep threshold` (5000 µs).
- **limit-session** `limit-session{}`: `source-ip-based <n>`, `destination-ip-based <n>`.
- **General** (children of `ids-option`): `alarm-without-drop` (detect/alarm only — DO NOT drop), `description`.

> **DATA CONFLICT to carry into the skill:** `alarm-threshold` default is stated as **1024/sec** on the CLI-reference leaf page but **512** on the older "Network DoS Attacks" topic page. Prefer **1024** (leaf/CLI-ref canonical); don't rely on the default blindly.

**FortiOS mapping — DoS policy** (`config firewall DoS-policy`/`DoS-policy6`), applied at ingress interface, pre-policy (same position as a screen). Canonical anomaly names (exact, lowercase+underscore): `tcp_syn_flood`, `tcp_port_scan`, `tcp_src_session`, `tcp_dst_session`, `udp_flood`, `udp_scan`, `udp_src_session`, `udp_dst_session`, `icmp_flood`, `icmp_sweep`, `icmp_src_session`, `icmp_dst_session`, `ip_src_session`, `ip_dst_session` (+ 4 sctp_*). `action proxy` exists **only for `tcp_syn_flood` on NP6/NP7/SP hardware** — default to `block` portably.

| SRX screen | FortiOS | Notes |
|---|---|---|
| `tcp syn-flood` (+ 4 thresholds, timeout) | DoS `tcp_syn_flood` | SRX's multi-threshold model collapses to one `threshold` → re-model; `white-list`→srcaddr exclude. |
| `tcp port-scan` | DoS `tcp_port_scan` | SRX µs-window vs FortiOS count → unit re-model. |
| `tcp-sweep` | DoS `tcp_*_session` (no exact "sweep") | approximate. |
| `tcp land/winnuke/syn-fin/fin-no-ack/tcp-no-flag/syn-frag` | **IPS** / kernel anomaly | Not DoS anomalies → re-model. |
| `tcp syn-ack-ack-proxy` | (no direct anomaly) | nearest = src-session limiting. |
| `icmp flood` | DoS `icmp_flood` | direct (pps→pps). |
| `icmp ip-sweep` | DoS `icmp_sweep` | direct. |
| `icmp fragment/large/ping-death/icmpv6-malformed` | **IPS** / kernel | re-model. |
| `udp flood` | DoS `udp_flood` | direct. |
| `udp-sweep` | DoS `udp_scan` | nearest. |
| `limit-session source-ip-based`/`destination-ip-based` | DoS `ip_src_session`/`ip_dst_session` (or per-proto) | session-count limit. |
| `ip spoofing` | **RPF** (`set src-check` per-if + `strict-src-check` per-VDOM) | NOT a DoS anomaly. Map strict-RPF intent → `strict-src-check enable`. |
| `ip bad-option / *-route-option / record-route / timestamp / security / stream-option / unknown-protocol` | **IPS** / kernel | no per-option toggle → re-model + list each. |
| `ip tear-drop / block-frag` | kernel/IPS | no direct toggle. |
| `ipv6-extension-header* / ipv6-malformed-header` | IPS / kernel | DoS-policy6 covers floods/sessions only. |
| `alarm-without-drop` | DoS anomaly `action pass` + `log enable` | 🔴 NOT `block` — mistranslating *adds* drops. |

🔴🔴 **Silent-loss flag (loud).** Screens contribute **no policy/object/service lines** — the easiest thing in an SRX config to lose silently. Dropped → the FortiGate has **ZERO** flood/scan/sweep/session-limit/malformed-packet protection the SRX had, and nothing in the output reveals it. Only flood/scan/session-limit screens map cleanly to DoS anomalies (and even then thresholds re-model); malformed-packet/IP-option/TCP-flag-anomaly screens → IPS or kernel; `ip spoofing`→RPF. Converter MUST: parse every `ids-option`, record zone→screen binding, emit a DoS policy on the mapped ingress for every mappable anomaly, list every non-mappable option in the report with source file+line, and preserve `alarm-without-drop` as pass+log.

**Sources:** [ids-option](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/security-edit-ids-option.html) · [screen (zone binding)](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/security-edit-screen-zones.html) · [Screens / ADP intro](https://www.juniper.net/documentation/us/en/software/junos/denial-of-service/topics/topic-map/security-introduction-to-adp.html) · [syn-flood](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-syn-flood.html) · [alarm-threshold (1024)](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/ref/statement/security-edit-alarm-threshold.html) · [Network DoS Attacks (512)](https://www.juniper.net/documentation/us/en/software/junos/denial-of-service/topics/topic-map/security-network-dos-attack.html) · [FortiOS DoS-policy](https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/771644/dos-policy) · [config firewall DoS-policy](https://docs.fortinet.com/document/fortigate/7.4.6/cli-reference/561707922/config-firewall-dos-policy) · (plus per-option leaf pages cited in the area research)

---

## 5. Stateless Firewall Filters (`firewall family inet/inet6 filter`) 🔴🔴🔴 THE lo0 LANDMINE

**What it is.** Stateless ACLs of ordered **terms** (first-match; **implicit default action = `discard`** — silent drop of anything unmatched), bound per logical unit / per family / per direction. The opposite of stateful `security policies`.
```
set firewall family inet filter <name> term <t> from <match>
set firewall family inet filter <name> term <t> then <action>
set interfaces <ifd> unit <u> family inet filter input  <name>
set interfaces <ifd> unit <u> family inet filter output <name>
```

**The lo0 / loopback filter — control-plane protection.** `set interfaces lo0 unit 0 family inet filter input <name>`. **lo0 is the interface to the Routing Engine** — *"Standard firewall filters applied to the loopback interface affect the local packets destined for or transmitted from the Routing Engine."* So an `lo0 ... filter input` filters **all traffic to the box's own control plane** (SSH, BGP, OSPF, SNMP, ICMP) and is the standard, recommended RE protection: without it the device *"is vulnerable to TCP and ICMP flood … denial-of-service attacks."* Canonical "protect-RE" shape: permit specific mgmt/routing protocols from trusted sources, then `discard-rest`:
```
set firewall family inet filter protect-RE term ssh-term from source-address 192.168.122.0/24
set firewall family inet filter protect-RE term ssh-term from protocol tcp
set firewall family inet filter protect-RE term ssh-term from destination-port ssh
set firewall family inet filter protect-RE term ssh-term then accept
set firewall family inet filter protect-RE term bgp-term ... then accept
set firewall family inet filter protect-RE term discard-rest-term then discard
set interfaces lo0 unit 0 family inet filter input protect-RE
```

**`from` / `then`.** `from`: `source-address`/`destination-address`/`prefix-list`, `protocol`, `source-port`/`destination-port`/`port` (named or numeric), `tcp-flags`, `tcp-established`, `icmp-type`/`icmp-code`, `ttl`, `dscp`, `fragment-*`. `then`: `accept`, `discard` (silent), `reject` (drop **with** ICMP error — distinct from discard), `next term`, `count`, `log`, `syslog`, `policer` (rate-limit, e.g. ~1 Mbps/15000-byte burst for TCP/ICMP-to-RE). Best practice: apply via `apply-groups` so it's inherited on every loopback unit.

**Why NO direct FortiOS line-translation — the re-model.** FortiOS has **no stateless interface ACL** in the Junos sense, and the lo0 input filter targets **traffic to the box itself**, so it does **not** map to `config firewall policy` (transit) at all. Re-model into the control-plane toolset:

| lo0 / stateless element | FortiOS re-model | Detail |
|---|---|---|
| `lo0 filter input` accept terms (src/proto/dst-port → RE) | **`config firewall local-in-policy`** | "control inbound traffic going **to** a FortiGate interface" — closest equivalent. Fields `intf`,`srcaddr`,`dstaddr`,`service`,`action`,`schedule`,`status`,`logtraffic`. |
| coarse "which mgmt protocols reach the box" | **`set allowaccess`** | Harden to `https ssh` only. |
| ssh-term `source-address` (admin-source restriction) | **`config system admin set trusthost1..10`** (+ ip6) | per-admin source IP/subnet. |
| `policer` rate-limiting TCP/ICMP to RE | **DoS-policy** anomalies (`tcp_syn_flood`, `icmp_flood`, `*_src_session`) | carry policer intent as thresholds. |
| `ip spoofing`-style source validation | **RPF** (`src-check` + `strict-src-check`) | |

**Recipe:** each `accept` term → `local-in-policy action accept` (srcaddr from `source-address`, service from `protocol`+`destination-port`, intf = mgmt interface(s)); trailing/implicit `discard` → trailing `local-in-policy action deny` + tighten `allowaccess`; mgmt-protocol terms → also `allowaccess`; admin-source → `trusthost`; policer terms → DoS thresholds; `reject` terms → `local-in-policy action deny` **+ report note** that FortiOS won't send the ICMP-unreachable the way Junos `reject` does.

🔴🔴🔴 **Silent-loss flag (loudest — the exact bug this reference exists to prevent).** Dropping `lo0 unit 0 family inet filter input` silently removes **ALL control-plane protection** from the converted FortiGate. The lo0 filter contributes no transit policy/address/zone — purely control-plane, the highest-impact thing to lose silently. Lose it and the management plane (SSH/HTTPS-admin/SNMP/routing daemons) is exposed to every source the SRX was blocking/rate-limiting, with nothing in the output showing the protection ever existed. Converter MUST: parse every `firewall family inet|inet6 filter`, detect any bound to `lo0`, surface each to the report with source file+line, re-model accept terms → `local-in-policy` (+ allowaccess + trusthost), trailing discard/reject → `local-in-policy action deny`, policers → DoS thresholds, NEVER emit the box without the equivalent posture, and flag the reject→deny ICMP-notification gap. Non-lo0 transit filters likewise have no clean equivalent → surface, don't drop.

**Sources:** [Firewall filter overview](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/firewall-filter-overview.html) · [Stateless filter basic uses / RE protection](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/firewall-filter-stateless-basic-uses-for.html) · [Protect against TCP/ICMP flood (lo0)](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/example/routing-stateless-firewall-filter-security-protect-against-tcp-and-icmp-flood-configuring.html) · [Accept traffic from trusted source (protect-RE)](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/example/routing-stateless-firewall-filter-security-accept-traffic-from-trusted-source-configuring.html) · [FortiOS local-in-policy](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/363127/local-in-policy) · [allowaccess/interface settings](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/574723/interface-settings) · [system admin trusthost](https://docs.fortinet.com/document/fortigate/7.4.1/cli-reference/13620/config-system-admin)

---

## 6. ALGs (`security alg`) (default-on divergence is a silent-broadening trap)

**What it is.** ALGs open dynamic pinholes and rewrite IP/port info embedded in payloads (FTP PORT/PASV, SIP/SDP, H.323). `set security alg <name> ...`; disable with `set security alg <name> disable` (stays defined, inactive).

**🔴 Many ALGs are ON by default — and the default set is platform-dependent** (absence of `set security alg` lines does NOT mean "no ALGs"):
- **Branch SRX300/320/340/380:** all supported ALGs ON **except** IKE-ESP, RSH, SQL, TWAMP.
- **High-end (SRX1500/4100/4200/5400/5600/5800):** ON = FTP, TFTP, DNS, MS-RPC, PPTP, SUNRPC, RSH, TALK; everything else (incl. SIP, H323, MGCP, SCCP, RTSP, SQL, IKE-ESP, TWAMP) OFF.
- **SIP** specifically is **OFF by default on SRX** (ON on other devices).

**The 16 ALGs** (`show security alg status` target list): `dns, ftp, h323, mgcp, msrpc, pptp, rsh, rtsp, sccp, sip, sql, sunrpc, talk, tftp, ike-esp, twamp` (12 data + 4 VoIP: sip/h323/mgcp/sccp). Config knob for IKE-ESP is `ike-esp-nat`; RAS is the H.225 component of `h323`, not a separate knob.

**FortiOS equivalents** split across three places: **`config system session-helper`** (kernel helpers — ftp, tftp, h323, ras, tns, rtsp, pptp, rsh, dcerpc, mgcp, dns-udp/dns-tcp, pmap, sip, mms; enabled by default; disable by deleting the entry), the **VoIP profile** (`config voip profile` → `config sip`/`sccp`/`msrp`; proxy-based; **no MGCP subsection**), and **`config system settings`** (`default-voip-alg-mode {proxy-based|kernel-helper-based}` default proxy-based; `sip-helper`; `sip-nat-trace`).

| Junos ALG | FortiOS | Re-model? |
|---|---|---|
| `dns` | session-helper `dns-udp` + `dns-tcp` | add both. |
| `ftp` / `tftp` / `rtsp` / `pptp` / `rsh` | session-helper of same name | Direct. |
| `sql` (TNS) | session-helper `tns` | Partial — flag best-effort. |
| `sunrpc` | session-helper `pmap` | Partial. |
| `msrpc` (135) | session-helper `dcerpc` | Partial — keep distinct from pmap. |
| `h323` | session-helper `h323` + `ras` | enable both. |
| `sip` | **VoIP profile** `config sip` (proxy, default) **or** session-helper `sip` | see disable mapping below. |
| `sccp` | **VoIP profile** `config sccp` only | re-model (no session-helper). |
| `mgcp` | session-helper `mgcp` if build ships it; no VoIP-profile MGCP | weak / accept loss. |
| `ike-esp-nat` | **None** | re-model: native NAT-T on endpoints or pinhole policy for 500/4500+ESP. |
| `talk` | **None** | re-model / accept loss (static service, no fixup). |
| `twamp` | **None** | re-model / accept loss. |

**Behavioral mapping notes.** (1) `set security alg <x> disable` → **REMOVE** the FortiOS session-helper entry (leaving FortiOS's default helper *adds* fixup the admin turned off). (2) **SIP disable is a 3-part FortiOS op**: delete the sip session-helper, `set sip-helper disable` + `sip-nat-trace disable`, `set default-voip-alg-mode kernel-helper-based`, **and** ensure no VoIP profile is attached (else SIP still hits the proxy ALG via the default profile). (3) **🔴 Default-state divergence is the silent-broadening trap** — FortiOS ships helpers enabled; a "copy explicit `set security alg` lines only" converter yields a box with *more* ALGs active than the source. Reconcile against the source platform default; emit explicit `delete <id>` for FortiOS default helpers whose Junos ALG was off, or report. Per no-silent-broadening, ALGs that can't be faithfully reproduced (TWAMP, TALK, IKE-ESP, partial MGCP) → report as loss, never approximated by leaving a broader helper on.

**Sources:** [show security alg status (platform defaults)](https://www.juniper.net/documentation/us/en/software/junos/alg/topics/ref/command/show-security-alg-status.html) · [ALG Overview](https://www.juniper.net/documentation/us/en/software/junos/alg/topics/topic-map/security-introduction-to-algs.html) · [Data ALG Types](https://www.juniper.net/documentation/us/en/software/junos/alg/topics/concept/data-alg-security-types-understanding.html) · [VoIP ALG Types](https://www.juniper.net/documentation/us/en/software/junos/alg/topics/concept/VoIP-alg-security-types-understanding.html) · [SIP ALG](https://www.juniper.net/documentation/us/en/software/junos/alg/topics/topic-map/security-sip-alg.html) · [FortiOS session-helper](https://docs.fortinet.com/document/fortigate/7.6.5/cli-reference/180488892/config-system-session-helper) · [VoIP profile](https://docs.fortinet.com/document/fortigate/7.4.3/cli-reference/494620/config-voip-profile) · [SIP ALG vs session helper](https://docs.fortinet.com/document/fortigate/7.6.3/administration-guide/147933/sip-alg-and-sip-session-helper)

---

## 7. IDP/IPS + UTM/AppSecure/Content-Security (PROFILE RE-MODELS, not line translations)

> **Cross-cutting:** Junos and FortiOS each have **independent signature DBs, independent category catalogs, and independent app-signature catalogs.** Rule *actions* map; signature/category/app *identity* does not. Every item here is a profile re-model — emit the closest faithful FortiOS profile + record the loss/approximation; never broaden.

### 7a. IDP / IPS

**Junos.** IDP policy = ordered **rule bases** (`rulebase-ips` detection + `rulebase-exempt` false-positive suppression). Rule `match`: `from-zone`/`to-zone`, `source-address`/`source-except`, `destination-address`/`destination-except`, `application` (`default`=protocols of referenced attacks), `attacks {predefined-attacks | predefined-attack-groups (dynamic) | custom-attacks | custom-attack-groups | dynamic-attack-groups (filter-based)}`. **Matching semantics:** non-terminal default applies **"the most severe action"** across matching rules; `terminal` stops further checks. `then action`: `recommended`, `no-action`, `ignore-connection`, `drop-packet`, `drop-connection` (silent), `close-client`/`close-server`/`close-client-and-server` (RST), `mark-diffserv`/`class-of-service` (forwards!). `then ip-action`: `ip-notify`/`ip-block`/`ip-close` (+ timeout/target). **Active policy:** legacy device-wide `set security idp active-policy <name>` (+ policy `then permit application-services idp`) **or** unified per-policy `idp-policy <name>` (18.2R1+, + `set security idp default-policy`). `security-package` DB updates = device-side, **emit nothing**.

**FortiOS.** **IPS sensor** (`config ips sensor` → ordered `entries`, each a filter or specific `rule <id>`), attached via policy `set ips-sensor`. Actions: `pass`/`block`/`reset`/`default`; `set quarantine attacker` + `quarantine-expiry` = the `ip-action` analogue. **No per-rule terminal, no most-severe-wins** — collapse to one sensor + document lost arbitration.

| SRX IDP action | FortiOS IPS | Notes |
|---|---|---|
| `recommended` | entry `default` | underlying recommendations differ per DB. |
| `no-action` | `pass` + log | |
| `ignore-connection` | `pass` + log | re-model (can't stop-scanning-rest-of-flow). |
| `drop-packet`/`drop-connection` | `block` | no packet-vs-connection distinction. |
| `close-client`/`close-server` | `reset` | re-model (FortiOS RST is both-sided). |
| `close-client-and-server` | `reset` | clean. |
| `mark-diffserv`/`class-of-service` | `pass` + shaper/policy DSCP | re-model — NEVER block (it forwards in Junos). |
| `ip-action ip-block` | `quarantine attacker` (+ expiry from timeout) | |
| `ip-action ip-close` | `quarantine attacker` | partial (no RST of future sessions). |

**🔴 Key caveat:** signature identity does NOT map 1:1 (Juniper IDP DB vs FortiGuard IPS DB; no authoritative cross-map — do not fabricate). Severity crosswalk (info/warning/minor/major/critical → low…critical) is approximate. **Recommended converter behavior:** emit a sensible default FortiOS sensor (e.g. severity high/critical → block, keep logging), set `ips-sensor` on the policy, **FLAG for review**. `custom-attacks` have **no automatic equivalent** — flag each for manual re-authoring, echoing the Junos definition in the report.

### 7b. UTM / AppSecure / Content Security

**Junos (`set security utm` — rebranded "Content Security" in docs, CLI unchanged).** Walk custom-objects → feature-profile → utm-policy → security policy. Bind: `... then permit application-services utm-policy <name>`.
- **anti-virus:** live engine `sophos-engine` (cloud); Express/Kaspersky EOL 15.1X49-D10, on-box full-file AV EOL ~17.3R1, Avira on-box reintroduced 18.4R1.
- **web-filtering:** `juniper-enhanced` (EWF, Websense ThreatSeeker categories like `Enhanced_Adult_Material`) | `juniper-local` | `websense-redirect`. Eval order: blocklist → allowlist → custom category → predefined.
- **content-filtering:** block by MIME pattern / file extension / protocol command / content-type (ActiveX, Java, cookies, EXE, ZIP).
- **anti-spam:** SBL (server block lists) + local address-blacklist/whitelist.
- **custom-objects:** url-pattern, custom-url-category, mime-pattern, filename-extension, protocol-command (resolve and carry members, not just the reference).

**AppSecure:** application-identification (AppID/DPI, ASC cache); application-firewall (legacy, **deprecated 18.2R1**) / modern `match dynamic-application` in unified policy (treat both as the same input); application-tracking (AppTrack — logging only); AppQoS (`class-of-service application-traffic-control`); APBR (`advance-policy-based-routing` — steer an app to a routing-instance).

| SRX / Junos feature | FortiOS | Re-model notes |
|---|---|---|
| anti-virus (sophos/avira) | `config antivirus profile` + policy `av-profile` | FortiGuard AV ≠ Sophos/Avira — engine doesn't carry; map scanned protocols + action. |
| web-filtering `juniper-enhanced` | `config webfilter profile` → `ftgd-wf` (**numeric** FortiGuard IDs) | 🔴 HIGH category-mapping risk (Websense names ≠ FortiGuard IDs) — build explicit crosswalk; report unmapped. Carry blacklist/whitelist/custom-url-category. |
| content-filtering | `config file-filter profile` (+ DLP) | file-filter is standalone since 6.4.1. `protocol-command` has **no** equivalent → re-model. |
| anti-spam | `config emailfilter profile` | SBL/Spamhaus ≠ FortiGuard antispam source; local lists map. |
| application-firewall + `match dynamic-application` | App Control: `config application list` + policy `application-list` | 🔴 App-signature catalog mismatch (junos:* ≠ FortiGuard IDs) — crosswalk; unmapped apps → report, **never broaden to "all".** |
| AppTrack | app-list + `logtraffic all` (behavior, not object) | record intent. |
| AppQoS | `config firewall shaping-policy` + `set application <id>` | same catalog mismatch. |
| APBR | `config system sdwan` service rules (app-ctrl) / policy route | architectural re-model — needs SD-WAN zones/members; no routing-instance concept. |

**Sources:** [IDP rules/rulebases](https://www.juniper.net/documentation/us/en/software/junos/idp-policy/topics/topic-map/security-idp-policy-rules-and-rulebases.html) · [IDP action](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-action.html) · [IDP attack objects/groups](https://www.juniper.net/documentation/us/en/software/junos/idp-policy/topics/topic-map/security-idp-attack-objects-groups.html) · [idp-policy unified](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-idp-security-unified-policy.html) · [Content Security Overview](https://www.juniper.net/documentation/us/en/software/junos/utm/topics/topic-map/security-utm-overview.html) · [Enhanced Web Filtering](https://www.juniper.net/documentation/us/en/software/junos/utm/topics/topic-map/security-utm-web-filtering.html) · [Content Filtering](https://www.juniper.net/documentation/us/en/software/junos/utm/topics/topic-map/security-utm-content-filtering.html) · [Sophos AV](https://www.juniper.net/documentation/us/en/software/junos/utm/topics/topic-map/security-sophos-antivirus-protection-overview.html) · [Application Firewall (deprecated)](https://www.juniper.net/documentation/us/en/software/junos/application-identification/topics/topic-map/security-application-firewall.html) · [APBR](https://www.juniper.net/documentation/us/en/software/junos/application-identification/topics/topic-map/security-application-advanced-policy-based-routing.html) · [FortiOS ips sensor](https://docs.fortinet.com/document/fortigate/7.4.1/cli-reference/354620/config-ips-sensor) · [webfilter profile](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/348620/config-webfilter-profile) · [FortiGuard web categories](https://docs.fortinet.com/document/fortigate/7.4.0/fortios-log-message-reference/755423/fortiguard-web-filter-categories) · [Application control](https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/302748/application-control)

---

## 8. Chassis Cluster (HA) (topology droppable; reth IPs and node-groups are NOT)

**What it is.** Two SRX nodes (node0/node1), active/passive or active/active. Cluster ID + node ID set in **operational mode** (writes EPROM, reboots): `set chassis cluster cluster-id <0–255, 0=disable> node <0|1> reboot`. **Control link** (often a fixed port) + **fabric link** `fab0`/`fab1` (`set interfaces fab0 fabric-options member-interfaces ge-x/x/x`) sync RTOs (auth/NAT/ALG/IPsec). **Redundancy groups:** RG0 = Routing-Engine primacy; RG1–128 = data-plane reth groups; per-node `priority` (higher wins; tie→lower node-id), `preempt` (not on RG0), `hold-down-interval`, `interface-monitor`, `ip-monitoring`. **reth (redundant ethernet):** `set chassis cluster reth-count <1–128>`; physical children `gigether-options redundant-parent rethN`; `set interfaces rethN redundant-ether-options redundancy-group N`; **IP/zone assigned to the reth itself**. **Per-node config groups:** `set groups node0/node1 ...` + `set apply-groups "${node}"`; fxp0 mgmt + host-name live here and are not replicated.

**FortiOS equivalent.** FGCP HA (`config system ha`: `mode a-p`/`a-a`, `group-id`/`group-name`, `hbdev`, `priority`, `override`≈preempt, `session-pickup` for stateful sync). reth concept → **none needed** (cluster is one device; use the normal physical/aggregate interface, its IP is the cluster IP). interface-monitor/ip-monitoring → HA `monitor` + `config system link-monitor`. node0/node1 groups → mostly N/A (per-unit `hostname` + `ha-mgmt-interface`).

**Relevant vs droppable for a single-FortiGate target.** **Droppable** (re-create HA natively): cluster-id/node-id, control/fabric links, reth-count, RG definitions/priorities/preempt/hold-down (note interface-monitor/ip-monitoring *intent* in the report). **🔴 MUST carry over:** (a) **per-node config groups can HIDE real config** — node-specific fxp0 mgmt IPs and host-names; inspect before discarding. (b) **reth interface IP/zone bindings ARE the data-plane addresses** — the reth's `unit 0 family inet address` is the firewall's actual interface IP, its zone membership the actual zone. Convert each reth → a FortiGate interface carrying its IP/zone; physical children (redundant-parent, no IP) → the FortiGate ports backing it. Only the failover wrapper is HA scaffolding. Dropping reth config = losing real interface addressing, not HA plumbing.

**Sources:** [Redundancy Groups](https://www.juniper.net/documentation/us/en/software/junos/chassis-cluster-security-devices/topics/topic-map/security-chassis-cluster-redundancy-groups.html) · [Fabric/data-plane interfaces](https://www.juniper.net/documentation/us/en/software/junos/chassis-cluster-security-devices/topics/topic-map/security-chassis-cluster-data-plane-interfaces.html) · [Redundant Ethernet Interfaces](https://www.juniper.net/documentation/us/en/software/junos/chassis-cluster-security-devices/topics/topic-map/security-chassis-cluster-redundant-ethernet-interfaces.html) · [set chassis cluster cluster-id node reboot](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/set-chassis-cluster-clusterid-node-reboot.html) · [Management interfaces (node groups)](https://www.juniper.net/documentation/us/en/software/junos/chassis-cluster-security-devices/topics/topic-map/security-chassis-cluster-management-interfaces.html) · [apply-groups ${node}](https://www.juniper.net/documentation/us/en/software/junos/chassis-cluster-security-devices/topics/ref/statement/apply-groups-edit-chassis.html)

---

## 9. Logical Systems & Tenant Systems (map to VDOMs; converters often only FLAG these)

**What they are.** Native multitenancy partitioning one device into independent virtual firewalls. **Logical systems** (`set logical-systems <name> ...`): full partitions — own zones, policies, interfaces, and **multiple routing instances**; a **primary/root** logical system holds device-wide control. **Tenant systems** (`set tenants <name> ...`): lighter-weight, higher-scale, but **exactly one routing instance** (shares the primary's single routing process). Both have their own security profile (resource quotas), zones, policies, interfaces, and are isolated namespaces. **Interface assignment is exclusive** — any logical unit binds to only one system.

| | Logical system | Tenant system |
|---|---|---|
| Routing instances | default + **multiple** | **exactly one** (shared process) |
| Scale | lower (≈27–32) | much higher (200–500) |

**FortiOS equivalent: VDOMs**, one-to-one. Each `logical-systems`/`tenants` → one VDOM (`config vdom / edit <name>`); primary/root lsys → `root` VDOM. A logical system's multiple RIs → VRF/multiple routing tables inside its VDOM; a tenant's single RI → the per-VDOM routing table. Security-profile quotas have no FortiOS equivalent → drop/report.

**🔴 Silent-loss risk (converters often only FLAG these).** A partition wrapper carries policy **scope**: (a) **flattening / namespace collision** (the dangerous one) — merge partitions into one flat config and a tenant-A permit becomes device-wide, same-named zones (`trust`/`untrust` recurring per lsys) collide/overwrite → silent rule-broadening / wrong scope (output looks "0-error" but grants access never granted); (b) **dropping the nested stanza** — whole tenants vanish. **Correct handling:** one VDOM per lsys/tenant, preserving each partition's zones/policies/objects/interfaces/routing **scoped to that VDOM only**, never hoisted to root; use the exclusive unit→lsys binding to attribute interfaces; keep namespaces isolated; surface anything not faithfully expandable (quotas, multi-RI collapse). In `migrate` mode, preserve VDOM boundaries and keep reference-aware renames within-VDOM.

**Sources:** [Logical/Tenant Systems Overview](https://www.juniper.net/documentation/us/en/software/junos/logical-system-security/topics/concept/overview.html) · [Logical Systems Overview](https://www.juniper.net/documentation/us/en/software/junos/logical-system-security/topics/topic-map/logical-systems-overview.html) · [Tenant Systems Overview](https://www.juniper.net/documentation/us/en/software/junos/logical-system-security/topics/topic-map/tenant-systems-overview.html) · [Logical-systems interfaces (exclusive unit)](https://www.juniper.net/documentation/us/en/software/junos/logical-systems/topics/topic-map/logical-systems-interfaces.html) · [Security Profiles](https://www.juniper.net/documentation/us/en/software/junos/logical-system-security/topics/topic-map/security-profile-logical-system.html)

---

## 10. Routing Relevant to Security (policy-options is easy to silently drop)

**routing-instances** (`set routing-instances <name> instance-type ...`) = VRF/VDOM-like separation. `virtual-router` (simple isolated table, no RD/vrf-import/export) vs `vrf` (MPLS-L3VPN; **requires route-distinguisher + vrf-import/vrf-export** for leaking). Also `forwarding`/`no-forwarding` (default)/`l2vpn`/`vpls`/`evpn`/`mac-vrf`/`virtual-switch`. **FortiOS:** VDOM (strongest isolation) or per-VRF routing (7.x: `set vrf <id>` on interface + in `config router static`; ID 0–63, →0–511 in 7.6). **Caveat:** `vrf-import`/`vrf-export` (route-target) leaking does NOT translate 1:1 (FortiOS leaks via inter-VRF static/policy) → flag for review.

**policy-options** (the route-maps/prefix-lists BGP/OSPF/VRF-leaking consume — they do nothing alone, only via `import`/`export`/`vrf-import`/`vrf-export`; that indirection is why naive parsers drop them):
- `prefix-list <name> <prefix/len>` → FortiOS `config router prefix-list`.
- `policy-statement <name> term <t> from ... then ...` (`from`: prefix-list/route-filter exact|longer|orlonger/protocol/community/as-path/neighbor/tag; `then`: accept/reject/next/community/metric/local-preference/next-hop) → FortiOS `config router route-map` (match-*/set-*).
- `community <name> members [...]` → FortiOS `config router community-list`.
- Consumed: BGP `set protocols bgp import/export <policy>` (global→group→neighbor, first match) → FortiOS `route-map-in`/`route-map-out` per neighbor; OSPF `set protocols ospf import/export` (import filters route *installation*, not LSA flooding) → FortiOS redistribution.

**static routes** `set routing-options static route <prefix> next-hop <addr>` (global) / per-instance (`qualified-next-hop` for per-NH preference/metric/BFD) → FortiOS `config router static` (+ `set vrf` per instance).

🔴 **Silent-loss flag.** Drop `policy-options` (with their import/export refs) and route filtering disappears — fail-open on correctness AND security: lost **BGP import** → rejected routes get installed (worse: implicit EBGP accept 20.3R1+); lost **BGP export** → re-advertise prefixes it shouldn't (route-leak/hijack-adjacent); lost **OSPF import** → default accept-all installs filtered externals; lost **VRF import/export** → route-target containment gone, segmentation collapses to flat. Config still *forwards* (looks working) but filtered routes are now accepted/advertised. Emit each unconverted policy-options object and each orphaned import/export/vrf-import/vrf-export reference to the report with source file+line; flag what can't be reproduced.

**Sources:** [Routing Instances Overview](https://www.juniper.net/documentation/us/en/software/junos/routing-overview/topics/concept/routing-instances-overview.html) · [instance-type](https://www.juniper.net/documentation/us/en/software/junos/mpls/topics/ref/statement/instance-type-edit-routing-instances-vp.html) · [policy-statement](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/policy-statement-edit-policy-options.html) · [Prefix Lists](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/policy-configuring-prefix-lists-for-use-in-routing-policy-match-conditions.html) · [Basic BGP Routing Policies](https://www.juniper.net/documentation/us/en/software/junos/bgp/topics/topic-map/basic-routing-policies.html) · [OSPF Routing Policy](https://www.juniper.net/documentation/us/en/software/junos/ospf/topics/topic-map/configuring-ospf-routing-policy.html) · [Default Routing Policies](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/policy-routing-policies-actions-defaults.html) · [Configure Static Routes](https://www.juniper.net/documentation/us/en/software/junos/static-routing/topics/topic-map/config_static-routes.html) · [FortiOS VRF routing](https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/509828/vrf-routing-support) · [FortiOS route-map](https://docs.fortinet.com/document/fortigate/7.2.0/cli-reference/556620/config-router-route-map)

---

## 11. `apply-groups` Inheritance, `${...}` Variables, `inactive:`/`deactivate` (parsing gotchas) 🔴

**apply-groups inheritance — the effective config is a MERGE.** Junos builds the committed config by **merging inherited configuration groups into explicit statements**. Define `set groups <g> <hierarchy> ...`; inherit `set apply-groups [ g1 g2 ]` (global, listed in priority order — first wins; nested beats outer) or scoped `set <hierarchy> apply-groups <g>`. **Wildcards** in group hierarchies use angle brackets (`<so-*>`, `<ge-*>`, `<*>`) to distribute config across matching interfaces/units; `apply-groups-except` disables inheritance below a level; the hidden immutable **`junos-defaults`** group is auto-applied (why predefined apps/services appear without explicit config).

> 🔴 **PARSING GOTCHA (silent loss of inherited config):** a parser reading only explicit stanzas **misses inherited config** — e.g. a zone's `host-inbound-traffic`/`screen` defined in a group (zone *looks* empty but permits mgmt traffic), or interface family/MTU/units from a wildcard group (interface *looks* unconfigured). **Mitigation:** resolve inheritance first — ingest `show configuration | display inheritance [no-comments]` (the merged view) or expand groups in-parser; at minimum, if `groups`/`apply-groups` are present and unresolved, **report it.**

**`${...}` variables.** `${node}` in chassis cluster = conditional inheritance (`apply-groups "${node}"` → node0 on node0, node1 on node1 — NOT a literal group named `${node}`). Related dynamic constructs a parser must expand: **`apply-path`** (expands a prefix-list from a config path, e.g. BGP neighbors — contents not literal) and **`interface-range`** (one stanza configures many physical interfaces — members inherit groups; foreground config wins).

**`inactive:` / `deactivate` — a disabled state.** `deactivate` marks a stanza `inactive:`: it **stays in the file but is excluded from the committed/running config** ("do not take effect when you issue commit"). Distinguish from siblings: **`delete`** = removed entirely; **`deactivate`/`inactive:`** = present in text, **not committed**; **`disable`** = a *committed, active* statement that admin-downs a function (IS in the running config). `inactive:` is the analogue of a disabled FortiOS object → map to `set status disable` or skip-and-report (FortiOS `set status disable` ≈ `inactive:`; Junos `disable` ≈ enabled-but-admin-down).

> 🔴 **SILENT-LOSS / SILENT-ACTIVATION (both directions wrong):** **(a) Silent ACTIVATION (dangerous)** — ignore `inactive:` and convert as live → you **re-enable a rule the admin deliberately turned off** (e.g. a deactivated broad `permit-any` comes back live). Since Junos already excludes `inactive:` from the running config, correct effective behavior is "rule absent"; emitting it enabled is strictly more permissive. **(b) Silent LOSS** — strip `inactive:` lines as comments → drop the config entirely (lose the record it exists disabled). **Correct handling:** parse the `inactive:` prefix, preserve the object, mark it disabled (`set status disable`), record in the report with source file+line + "was deactivated in source." Never emit enabled, never silently discard.

**Sources:** [Configuration Groups Overview](https://www.juniper.net/documentation/us/en/software/junos/junos-overview/cli/topics/concept/junos-software-configuration-groups-understanding.html) · [Use Configuration Groups](https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/configuration-groups-usage.html) · [apply-path](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/apply-path-edit-policy-options.html) · [Interface Ranges](https://www.juniper.net/documentation/us/en/software/junos/interfaces-fundamentals/topics/task/interfaces-interface-ranges-multi-task.html) · [deactivate](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/deactivate.html) · [Deactivate/Reactivate config](https://www.juniper.net/documentation/en_US/junos/topics/task/configuration/junos-software-configuration-statements-identifiers-deactivating-reactivating.html) · [Active/Passive Cluster (${node})](https://www.juniper.net/documentation/us/en/software/junos/chassis-cluster-security-devices/topics/topic-map/security-chassis-cluster-active-passive-deployments.html)

---

## 12. CONSOLIDATED — SRX Security Config Surface: Silent-Loss Checklist

Every security-relevant stanza | converts to | **risk if dropped/mishandled** (🔴 = silent protection loss).

| SRX stanza / construct | Converts to (FortiOS) | Risk if dropped / mishandled |
|---|---|---|
| `security zones security-zone … host-inbound-traffic system-services` | per-interface `allowaccess` (fan out from zone) | 🔴 **Over-open** (mgmt reachable on interfaces SRX kept closed) or over-restrict/breakage. Deny-by-default intent inverted. |
| `… host-inbound-traffic protocols` (bgp/ospf/bfd/…) | `local-in-policy` (FortiOS implicitly accepts routing protos) | 🔴 SRX *restriction* on control-plane protocols silently lost. |
| `functional-zone management` | dedicated mgmt interface / `ha-mgmt-interface` | OOB mgmt-only semantics lost (interface may become transit-capable). |
| no-equivalent system-services (`finger`,`xnm-*`,`r2cp`,`netconf`,`any-service`,…) | report-only | Misleading if "mapped"; never broaden to blanket allowaccess. |
| `security policies … then permit/deny` | `firewall policy action accept/deny` | Core ruleset; order must be preserved (first-match). |
| `source-address-excluded` / `destination-address-excluded` | `srcaddr-negate`/`dstaddr-negate enable` | 🔴 **Rule BROADENED** — exclude becomes include. The canonical over-permit bug. |
| `then reject` | `action deny` + `send-deny-packet enable` | 🔴 RST/ICMP-unreachable semantics lost → apps hang on timeout. |
| `scheduler-name` | `firewall schedule` | 🔴 Time-restricted policy becomes **always-on** (exposure window). |
| `then permit application-services` (utm/idp/appfw/ssl-proxy/secintel) | `utm-status` + profiles | 🔴 UTM/IDP/AppFW/SSL/SecIntel enforcement silently lost. |
| `match dynamic-application` / `source-identity` / `url-category` | app-list / FSSO groups / webfilter | 🔴 L7/identity/URL enforcement lost or broadened to "all". |
| `default-policy permit-all` | (default is deny in FortiOS) | 🔴 If unhandled, posture flips from permit-all to deny-all (breakage) — surface it. |
| NAT source (interface/pool/PAT) | central-SNAT / IP pool (overload/one-to-one/fixed-port) | Outbound connectivity; wrong pool type breaks PAT scale. |
| NAT destination / static (+port) | **VIP** (+ `nat-source-vip` for static reverse) | 🔴 Static bidirectionality / port-forward lost; VIP alone = inbound only. |
| **policy match vs NAT order** (post-DNAT/pre-SNAT) | VIP: `mappedip`=SRX dst, `extip`=public; policy `dstaddr`=VIP | 🔴 Inverting silently breaks reachability or broadens the policy. |
| `proxy-arp` / `proxy-ndp` | VIP/pool `arp-reply` (auto) | 🔴 NAT addresses unanswered → reachability breaks. Don't drop the intent. |
| `persistent-nat permit any-remote-host` | IP pool `type one-to-one` (NOT overload) | 🔴 Full-cone/STUN/VoIP behavior destroyed if mapped to overload. |
| **`security screen ids-option` (all)** | `firewall DoS-policy` anomalies (+ IPS/RPF/kernel) | 🔴🔴 **ALL flood/scan/sweep/session/malformed protection lost, invisibly.** Most commonly dropped. |
| screen `ip spoofing` | RPF (`src-check` + `strict-src-check`) | 🔴 Anti-spoof lost (not a DoS anomaly). |
| screen `alarm-without-drop` | DoS anomaly `action pass` + `log` | 🔴 Mistranslating to `block` *adds* drops the SRX never made. |
| **`firewall family inet|inet6 filter` on `lo0` (input)** | `local-in-policy` + `allowaccess` + `trusthost` + DoS (rate) | 🔴🔴🔴 **ALL control-plane/RE protection silently removed — THE motivating bug.** |
| stateless filter `then reject` | `local-in-policy action deny` + report note | Reject ICMP-notification fidelity gap. |
| stateless filters on transit interfaces | (no clean equivalent) | 🔴 Stateless transit ACL silently lost → surface, don't drop. |
| `security alg <x>` (and platform defaults) | `system session-helper` / VoIP profile / settings | 🔴 Default-state divergence → FortiOS runs **more** ALGs than source (silent broadening). |
| `set security alg <x> disable` | **delete** the FortiOS session-helper | 🔴 Leaving FortiOS default helper re-adds fixup admin turned off. |
| ALGs with no equivalent (ike-esp-nat, talk, twamp; sccp; partial mgcp) | re-model / VoIP profile / accept loss + report | NAT-traversal for those protocols silently broken; never approximate with a broader helper. |
| `security idp` policy / rules / actions | `ips-sensor` (default sensor) + policy `ips-sensor` | 🔴 Signatures don't map 1:1 — emit default sensor + **FLAG**; never fabricate equivalence. IPS silently absent if dropped. |
| `idp custom-attack` | (manual re-author) | 🔴 Custom detections lost — flag each, echo definition in report. |
| `security utm` anti-virus | `antivirus profile` | 🔴 AV scanning lost if dropped (engine differs — re-model). |
| `security utm web-filtering` (juniper-enhanced) | `webfilter profile` ftgd-wf (numeric IDs) | 🔴 Category mismatch (Websense names ≠ FortiGuard) → crosswalk; report unmapped, never broaden. |
| `security utm content-filtering` | `file-filter profile` (+ DLP) | 🔴 `protocol-command` has no equivalent → re-model; file blocks lost if dropped. |
| `security utm anti-spam` | `emailfilter profile` | Anti-spam lost (source differs). |
| AppSecure: app-firewall / `dynamic-application` | App Control `application list` | 🔴 App enforcement lost or broadened to "all" — crosswalk; report unmapped apps. |
| AppTrack / AppQoS / APBR | logging / shaping-policy / SD-WAN | Visibility/QoS/app-routing re-models; flag (no clean objects). |
| chassis cluster topology (cluster-id, control/fabric, reth-count, RG) | rebuild via `config system ha` | Droppable, but **note HA-monitor intent**; don't emit literal stanzas. |
| **reth interface IP/zone** | FortiGate interface IP/zone | 🔴 **Real interface addressing lost** if treated as HA plumbing. |
| `groups node0/node1` (fxp0 IP, host-name) | per-unit mgmt / `ha-mgmt-interface` | 🔴 Node-specific **mgmt IPs/host-names hidden** in groups — inspect before discarding. |
| `logical-systems <name>` / `tenants <name>` | **one VDOM each** | 🔴 Flatten → wrong policy scope / namespace collision (rule broadened); or whole tenant dropped. |
| `routing-instances` (virtual-router/vrf) | VDOM or per-VRF routing | VRF route-target leaking ≠ 1:1 → flag; isolation lost if dropped. |
| **`policy-options`** (prefix-list/policy-statement/community) | `route-map` + `prefix-list` + `community-list` | 🔴 BGP/OSPF/VRF import-export **filtering silently lost** → routes accepted/advertised that shouldn't be (routing + security breach). Easy to drop (indirection). |
| `routing-options static` (global/per-instance) | `config router static` (+ vrf) | Forwarding lost if dropped. |
| **`apply-groups` / `groups` / wildcards / `junos-defaults`** | resolve to merged config before parse | 🔴 Inherited config (zone host-inbound, interface settings) **silently missed** by literal-only parsers. Use `display inheritance`. |
| `${node}` / `apply-path` / `interface-range` | conditional/expanded inheritance | Many interfaces/prefixes appear unconfigured if not expanded. |
| **`inactive:` / `deactivate`** | `set status disable` (or skip + report) | 🔴 **Silent ACTIVATION** (re-enable a rule admin turned off — dangerous) or silent loss. Junos excludes `inactive:` from running config. |
| `disable` (committed admin-down) | enabled-but-admin-down (where available) | Don't conflate with `inactive:` — different running-config presence. |
| `security idp security-package` / `request …` / AV `pattern-update` | nothing (device-side DB ops) | Parse-and-report only; no FortiOS emission. |

---

### Notes on verification confidence (for skill authoring)

- All Junos facts were fetched live from `www.juniper.net/documentation` (not from memory); FortiOS mapping targets cite `docs.fortinet.com` (+ a few Fortinet community tech-tips where admin-guide pages render via JavaScript). The four load-bearing converter-correctness semantics — `deny` (silent) vs `reject` (RST/ICMP); `*-excluded` = negation (no IPv6); NAT order static>dest>source with policy lookup between DNAT and SNAT; policy matches post-DNAT/pre-SNAT — are quoted directly from the cited pages.
- **Two SRX facts to keep version-current:** (1) AV engine — Sophos (cloud) is live; Express/Kaspersky EOL 15.1X49-D10, on-box full-file AV EOL ~17.3R1, Avira on-box reintroduced 18.4R1. (2) application-firewall deprecated 18.2R1 in favor of unified-policy `match dynamic-application`. Accept both legacy and unified input forms for IDP-application and L7 app matching.
- **Two data caveats:** (1) `host-inbound-traffic system-services` is a closed set — do NOT add `sip`/`sql-monitor`/`tcp-encap`/`webapi-*`. (2) screen `alarm-threshold` default conflicts across Juniper pages (leaf **1024** vs topic **512**) — prefer 1024, don't trust the default blindly. FortiOS DoS `action proxy` is hardware-conditional (`tcp_syn_flood`, NP/SP only) — default to `block`.
- Where Juniper CLI-reference brace blocks were JavaScript-gated, deep sub-option token order (e.g. persistent-nat `inactivity-timeout`/`max-session-number`, source-pool `port-overloading-factor`) should be spot-checked against Juniper's CLI Explorer / the NAT PDF before relying on exact emission strings.
