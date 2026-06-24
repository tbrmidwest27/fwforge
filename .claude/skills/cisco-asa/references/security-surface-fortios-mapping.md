# Cisco ASA — SECURITY Configuration Surface & FortiOS Mapping

**Authoritative converter reference + ASA expertise. Every ASA fact below is grounded in Cisco's official Secure Firewall ASA Series CLI/configuration guides (`cisco.com`); FortiOS mapping targets cite `docs.fortinet.com`. Exact URLs are cited per section.** (Cisco serves HTTP 403 to automated fetchers, so wording was confirmed via the search index of the exact, version-pinned guide pages; ASA syntax/semantics below are stable across 9.8–9.23.)

> **Why this document exists.** An ASA's protection is **not** all in its ACLs. A huge fraction of an ASA's security posture is *implicit* — the **interface security-level** model permits whole classes of traffic with no ACL line to convert, and the **Modular Policy Framework** does the L7 enforcement with no firewall-policy line to convert. A converter that walks only `access-list` / `nat` / `object` lines silently loses both. This reference is the complete checklist of *"what an ASA security config actually contains."* Two principles run through every section:
> 1. **Nothing is dropped silently.** Anything non-convertible goes in the report with its source file + line.
> 2. **No silent rule-broadening.** Where FortiOS has no 1:1 equivalent, the doc says **"re-model required"** — it never implies a clean mapping. Security-level implicit-permit, MPF inspection, `neq` operators, `inactive`, NAT real-vs-mapped, and twice-NAT are the classic broadening/loss landmines.
>
> Landmine sections (silent protection loss or rule-broadening if dropped) are flagged 🔴; the two highest-impact get 🔴🔴.
>
> **fwforge grounding.** Each section ends with a **fwforge status** note: ✅ handled, ⚠️ partial, or ❌ GAP (silent drop / broadening), based on `fwforge/parsers/cisco_asa.py`. These seed a later parser audit.

---

## 1. Interfaces + security-level 🔴🔴 — the #1 ASA silent-broadening/loss trap

**CLI shape.**
```
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 198.51.100.1 255.255.255.0
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 10.1.1.1 255.255.255.0
same-security-traffic permit inter-interface
same-security-traffic permit intra-interface
```

**What it is.**
- An interface carries no traffic until it has a **`nameif`** — the logical name is used in all later commands (ACLs, NAT, `access-group`). An interface with **no `nameif` is unusable for transit**.
- **`security-level`** is **0 (lowest) … 100 (highest)**. If you name an interface **`inside`** and don't set a level, the ASA defaults it to **100**; **`outside`** defaults to **0**. Any other name gets no automatic level — you must set it.

**🔴🔴 THE implicit rule (the trap).** With **no ACL applied**, the ASA permits traffic by security-level alone:
- **Higher → lower security-level = permitted by default** (e.g. `inside`(100) → `outside`(0), "outbound"). Hosts on the higher interface may reach any host on a lower interface.
- **Lower → higher = denied by default.**
- **Same security-level (two different interfaces) = blocked** unless `same-security-traffic permit inter-interface`.
- **Same ingress = egress interface (hairpin / U-turn)** = blocked unless `same-security-traffic permit intra-interface` (used for hub-and-spoke VPN spoke-to-spoke, or VPN client internet hairpin).

So an ASA with **sparse ACLs relies on security-levels for most of its allow policy.** A trust-zone-to-DMZ-to-internet ASA may have only a couple of inbound ACLs and let *all* outbound flow on the implicit higher→lower permit.

**🔴 ACL override.** Applying an ACL via `access-group` to an interface **replaces** the implicit security-level behavior for that direction: the explicit ACL is evaluated and every ACL ends with an **implicit deny**, so "permit everything higher→lower" becomes "permit only what's listed, deny the rest."

**FortiOS re-model.** FortiOS has **NO security-level concept** and is **default-deny between all interfaces** — every allowed flow needs an explicit `config firewall policy`; non-matching traffic hits the implicit deny and is dropped. There is no "outbound is free" default.

| ASA construct | FortiOS | 🔴 risk |
|---|---|---|
| `nameif` | interface logical name / `set alias` | 1:1; un-named iface = no transit (skip) |
| `security-level <n>` | **no equivalent** | informational only — but the *implied permits* must be synthesized |
| implicit higher→lower permit (no ACL) | **synthesize** an explicit `firewall policy` (srcintf=higher, dstintf=lower, all/all/ALL, accept) | 🔴🔴 **drop it → all that outbound traffic is denied** (under-permit / breakage); **or** if a converter "helpfully" emits any-any everywhere → over-broaden |
| `same-security-traffic permit inter-interface` | explicit policy between those same-level interfaces | 🔴 drop → same-level flow denied |
| `same-security-traffic permit intra-interface` | policy with `srcintf == dstintf` (FortiOS intra-zone defaults to **deny**) | 🔴 hairpin/VPN-spoke traffic denied |
| interface with applied `access-group` | the ACEs become the policy set (§2) | the explicit ACL *is* the policy — implicit permit no longer applies |

🔴🔴 **Silent-loss flag.** Security-level is **deny-by-omission on the FortiOS side but permit-by-omission on the ASA side** — opposite polarity. An ASA interface pair relying on the implicit higher→lower permit contributes **zero ACL lines**, so a converter reading only `access-list` produces a FortiGate that **silently denies all that traffic** (looks "clean," breaks production), or — if it papers over the gap with broad any-any policies — **over-permits**. The converter MUST: read every interface's security-level, and for each interface *not* governed by an applied `access-group`, synthesize the implied permit policy (and report it as synthesized, not 1:1), honoring `same-security-traffic` toggles; never emit blanket any-any to "be safe."

**fwforge status: ❌ GAP (high).** `parse_interface` (cisco_asa.py:411) reads `nameif`, `ip address`, `shutdown`, `vlan`, `description` but **explicitly discards `security-level`** (`elif t[0] in ("security-level", "management-only", …): pass`, line 439). There is no synthesis of implicit higher→lower permits and no handling of `same-security-traffic`. An ASA whose outbound policy is implicit will convert with that policy **silently missing**. This is the top audit item.

**Sources:** [ASA Routed/Transparent Interfaces (nameif, security-level, defaults, implicit permit, ACL limiting)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/general/asa-920-general-config/interface-routed-tfw.html) · [ASA Access Rules — Information About Access Rules / Implicit Permits](https://www.cisco.com/c/en/us/td/docs/security/asa/asa923/configuration/firewall/asa-923-firewall-config/access-rules.html) · [ASA Command Reference — nameif](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/n-commands.html) · [ASA Command Reference — same-security-traffic](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/S/asa-command-ref-S/sa-shov-commands.html) · [FortiOS Firewall policy (default-deny / implicit deny)](https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/656084/firewall-policy)

---

## 2. Access-lists / ACEs + access-group 🔴 (log / time-range / inactive are must-carry)

**CLI shape.**
```
access-list OUTSIDE_IN remark -- inbound web --
access-list OUTSIDE_IN extended permit tcp any object WEB eq www log warnings interval 60 time-range BIZHOURS
access-list OUTSIDE_IN extended deny   ip any any log
access-list OUTSIDE_IN extended permit tcp any host 10.1.1.9 eq 22 inactive
access-group OUTSIDE_IN in interface outside
access-group GLOBAL_ACL global
```

**ACL types.** An ACL is one or more **ACEs**.
- **Extended** (`access-list NAME extended permit|deny <proto> <src> <dst> [ports] …`) — the general-purpose, interface-bindable type. The **only** type used for through-the-box packet filtering via `access-group`.
- **Standard** (destination address only) — used by **route-maps and VPN filters**, **not** interface filtering. Do not emit as a firewall policy.
- **EtherType** ACL — non-IP L2 filtering, **transparent mode only** (§8.2).
- **Webtype** ACL — clientless SSL-VPN URL/dest filtering. No firewall-policy equivalent.

**ACE options (must-carry).**
- **`log [level] [interval secs] | disable | default`** — bare `log` raises syslog **106100** at default level **6 (informational)**, default interval **300 s** (range 1–600). `log disable` silences the ACE; without `log`, a *deny* still raises **106023**. 🔴 dropping the log setting = lost SIEM visibility.
- **`time-range NAME`** — references a named time range (`time-range NAME` with one `absolute` and/or many `periodic` entries). 🔴 dropping = rule runs 24/7.
- **`inactive`** — disables the ACE **without deleting it** (present but not enforced). 🔴 dropping = silently **activates** a disabled rule.
- **`remark`** — free-text comment line attached to the next ACEs.
- **`object-group-search access-control`** — a memory optimization (match object-group members at match time vs expanding combinations); no FortiOS equivalent and no security meaning — informational.
- **Per-ACE hit counts** (`show access-list … (hitcnt=N)`) — runtime only, not in saved config.

**`access-group` direction + order.**
- `access-group NAME in interface IFC` — inbound on that interface (the common case).
- `access-group NAME out interface IFC` — outbound on that interface.
- `access-group NAME global` — applies to the **inbound direction of all interfaces**; global/management rules are **always inbound**.
- **Evaluation order:** the **interface (in) ACL is evaluated first; the global ACL after** it (only if no interface rule matched), then the implicit deny.

**FortiOS mapping.**

| ASA ACE field | FortiOS (`config firewall policy`) | Notes / 🔴 risk |
|---|---|---|
| `access-group … in interface IFC` | policy `srcintf = IFC` | the bound ACL becomes that interface's policy set |
| `access-group … out interface IFC` | policy `dstintf = IFC` | 🔴 `out` direction + ordering vs global has no clean FortiOS analog — surface, don't silently flatten |
| `access-group … global` | policy with `srcintf any`, placed appropriately | 🔴 global-after-interface ordering not replicated 1:1 — report |
| `permit` / `deny` | `set action accept` / `set action deny` | FortiOS deny = silent drop |
| `<proto> <src> <dst>` | `service` / `srcaddr` / `dstaddr` | `any`→`all`; with DNAT, `dstaddr` = VIP (§3); real (untranslated) addresses (§3.6) |
| `eq/range/gt/lt <port>` | `config firewall service custom` (`tcp-portrange`/`udp-portrange`) | `dst:src` colon form for source ports |
| **`neq <port>`** | **none** | 🔴 not-equal can't be expressed — converting as any-port **broadens**; emit policy **disabled** + review |
| `log [level\|interval]` | `set logtraffic all` (+ `disable` for `log disable`) | 🔴 drop = visibility lost |
| `time-range NAME` | `config firewall schedule recurring` (periodic) / `onetime` (absolute) + `set schedule` | 🔴 drop = 24/7 |
| `inactive` | `set status disable` | 🔴 drop = re-activates disabled rule |
| `remark` | policy `comment` | carry |
| ACE order | policy sequence | preserve — both first-match top-down |

🔴 **Silent-loss flags.** (1) **`neq` / unresolvable named ports → broadening** (the exact class the tool exists to prevent — emit disabled, never any-port). (2) **`inactive` dropped → disabled rule goes live.** (3) **`time-range` dropped → always-on.** (4) **`log`-setting dropped → SIEM blind.** (5) **`out`/`global` direction + ordering** silently flattened changes the match winner.

**fwforge status: ✅/⚠️ mostly handled.** `parse_access_list` (cisco_asa.py:743) handles extended ACEs, `remark`, `log` (+level/interval), `inactive`→`disabled`, protocol/service/icmp objects, and correctly **fails closed on `neq` and `gt 65535`/`lt 1`** (emits the policy disabled for review — lines 263-266, 838-856) — exactly the no-broadening rule. `access-group in interface` and `global` are handled (cisco_asa.py:909). **GAPs:** `time-range` is **noted but NOT converted** to a FortiOS schedule (cisco_asa.py:823 — "policy emitted without schedule restriction" → rule runs 24/7, a real silent-broadening of the time window); **`access-group … out interface`** is not handled (falls to `unparsed`); standard/webtype/ethertype ACLs are skipped (correctly, with a note). Source ports via `gt`/`lt` are converted to ranges; named-port resolution failures fail closed.

**Sources:** [ASA Access Control Lists (ACEs, remark, hitcnt, object-group-search)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa918/configuration/firewall/asa-918-firewall-config/access-acls.html) · [ASA Extended ACLs (inactive, line edit)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/general/asa-general-cli/acl-extended.html) · [ASA Logging for Access Lists (106100, level 6, interval 300)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/general/asa-general-cli/acl-logging.pdf) · [ASA Objects for Access Control (time-range)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa917/configuration/firewall/asa-917-firewall-config/access-objects.html) · [ASA Access Rules (access-group in/out/global, order)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/access-rules.html) · [FortiOS firewall policy](https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/656084/firewall-policy) · [FortiOS firewall schedule recurring](https://docs.fortinet.com/document/fortigate/7.6.5/cli-reference/161573977/config-firewall-schedule-recurring) · [onetime](https://docs.fortinet.com/document/fortigate/7.0.11/cli-reference/296620/config-firewall-schedule-onetime)

---

## 3. NAT 🔴 (real-vs-mapped ACL semantics + twice-NAT-with-destination are the subtle ones)

ASA NAT lives in a single table evaluated in three sections; rules are object (auto) NAT or twice (manual) NAT.

**Auto NAT / object NAT** — configured **inside** an `object network` (`nat (real_ifc,mapped_ifc) static|dynamic …`). Simple 1:1 static, static PAT, or dynamic/PAT. The ASA **auto-orders** these. A single object may have **one static + one dynamic** rule and **cannot match on the destination**.
```
object network WEB
 host 10.1.1.100
 nat (inside,outside) static 198.51.100.100              ! 1:1 static DNAT
object network WEB80
 host 10.1.1.100
 nat (inside,outside) static interface service tcp www www ! static PAT to iface IP
object network INSIDE_NET
 subnet 10.1.1.0 255.255.255.0
 nat (inside,outside) dynamic interface                  ! outbound PAT to egress IP
```

**Twice NAT / manual NAT** — the network objects are parameters of the `nat` line (not the object):
```
nat (inside,outside) source dynamic INSIDE_NET interface
nat (inside,outside) source static SRV_REAL SRV_MAP destination static DST_MAP DST_REAL service SVC_REAL SVC_MAP
nat (inside,outside) after-auto source dynamic ANY interface   ! section 3
```
🔴 **The subtle one.** Twice NAT identifies **both source and destination (and service)** in one rule — the only way to do **policy NAT** (sourceA/destA translates differently from sourceA/destB). Note the **destination operand order is reversed** (`destination static MAPPED REAL`).

**NAT ordering / sections.** One table, three sections, first match wins:
- **Section 1** = twice/manual NAT (applied **first**, in config order).
- **Section 2** = object/auto NAT (ASA **auto-orders**: static before dynamic, more-specific first).
- **Section 3** = twice NAT with **`after-auto`** (evaluated **last**).
If a Section-1 match is found, Sections 2–3 are not evaluated.

**Identity NAT / NAT exemption** — translate an address to **itself** (real == mapped) = no translation; the canonical VPN-traffic exemption:
```
nat (inside,outside) source static LOCAL LOCAL destination static REMOTE REMOTE no-proxy-arp route-lookup
```
`no-proxy-arp` suppresses ARP for the (un)translated subnet; `route-lookup` (identity-NAT only) uses the routing table for egress. On a FortiOS **route-based** VPN this exemption is generally **unnecessary** (no policy-NAT on tunnel traffic), so it can often be dropped — *but only after confirming it's a VPN exemption*, not a real no-translate requirement.

**PAT.** `dynamic interface` = PAT to the egress interface IP (overload); `dynamic pat-pool OBJ` = PAT pool; `dynamic OBJ` (no overload) = 1:1 dynamic NAT pool (no port reuse).

**🔴 Real-vs-mapped ACL semantics (ASA 8.3+) — critical.** Since 8.3 the ASA **untranslates the packet before checking ACLs**, so **ACLs and policies are written with the REAL (untranslated / pre-NAT) address, not the mapped/public IP.** An inbound rule for a DNAT'd server names the **internal** IP. This maps *cleanly* to FortiOS: a FortiOS policy's `dstaddr` for inbound DNAT is the **VIP object**, whose `mappedip` is that same real/internal IP. **Do NOT rewrite ASA ACL operands to the public IP during conversion.**

**FortiOS mapping.**

| ASA NAT | FortiOS | 🔴 risk |
|---|---|---|
| object NAT `static` (1:1) | `firewall vip` (`extip`=public, `mappedip`=real); policy `dstaddr`=VIP | 🔴 raw address instead of VIP → no DNAT (blackhole) |
| object NAT static **PAT** (`static interface service tcp …`) | VIP `set portforward enable` + `protocol`/`extport`/`mappedport`; `extip = <egress-iface-IP>` | 🔴 NAT-to-interface IP is **not in the config** — extip must be filled in manually |
| object NAT `dynamic interface` | policy `set nat enable` (egress-iface IP) | wrong egress IP if forced to a pool |
| object NAT `dynamic` pool | `firewall ippool` (`overload`=PAT, `one-to-one`=dynamic-NAT) + policy `nat enable`/`poolname` | 🔴 `one-to-one`→`overload` silently **adds PAT** |
| twice NAT `source static … destination static … service …` (policy NAT) | VIP (dst side) **and/or** `central-snat-map` (`orig-addr`+`dst-addr`+`nat-ippool`) | 🔴 dst+service condition is the policy-NAT case — flatten loses the conditional translation |
| identity NAT / NAT-exempt | central-snat-map `nat disable` (or, on route-based VPN, often droppable) | 🔴 only drop after confirming it's a VPN exemption, not a real no-translate |
| static NAT bidirectionality | VIP inbound + policy `nat enable` (or `nat-source-vip`) outbound | reverse/outbound half lost if only the VIP is emitted |

🔴 **Silent-loss flags.** (1) **DNAT as raw address instead of a VIP → blackhole.** (2) **`one-to-one` pool mapped to `overload` → silently adds PAT** (the no-broadening class). (3) **Twice-NAT-with-destination/service flattened → conditional policy-NAT lost.** (4) **NAT-to-interface-IP** static PAT: the public IP isn't in the config — must be flagged for manual entry, never guessed. (5) **Section ordering** (1→2→3) collapsed → wrong rule wins.

**fwforge status: ⚠️ partial — twice-NAT is a hard GAP.** `parse_object_nat` (cisco_asa.py:498) handles **object NAT only**: `static` → VIP (with `service` → portforward; NAT-to-interface flagged for manual extip — lines 520-528, 542-549), and `dynamic interface` → PAT intent. **Dynamic-to-pool object NAT is NOT converted** (noted, line 514). **All twice/manual NAT (`nat (...)` lines) is explicitly NOT converted** — `parse` emits an `error` finding and pushes to `unparsed` (cisco_asa.py:362-370), with a helpful note that VPN NAT-exemption identity rules are usually unnecessary on route-based FortiOS VPNs. So **policy NAT (twice NAT with destination/service), NAT pools, and section ordering are current gaps** — surfaced loudly (good, per "nothing dropped silently") but not converted.

**Sources:** [ASA NAT Basics (object NAT, twice NAT, sections, identity NAT, real-IP ACLs)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/nat-basics.html) · [ASA NAT Reference (no-proxy-arp, route-lookup)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa98/configuration/firewall/asa-98-firewall-config/nat-reference.html) · [ASA ACL real-IP example (8.3+)](https://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-next-generation-firewalls/115904-asa-config-dmz-00.html) · [ASA NAT-exemption technote](https://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-next-generation-firewalls/116388-technote-nat-00.html) · [FortiOS config firewall vip](https://docs.fortinet.com/document/fortigate/7.6.0/cli-reference/293620/config-firewall-vip) · [FortiOS config firewall ippool](https://docs.fortinet.com/document/fortigate/7.0.0/cli-reference/296620/config-firewall-ippool) · [FortiOS central SNAT](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/421028/central-snat) · [FortiOS policy with source NAT](https://docs.fortinet.com/document/fortigate/7.2.4/administration-guide/188051/policy-with-source-nat)

---

## 4. Modular Policy Framework (MPF) 🔴🔴 — ASA's L7; dropping it loses all application enforcement

**What it is.** MPF is the ASA's L7/advanced-feature engine — **`class-map`** identifies traffic (via `match` or an ACL), **`policy-map`** binds actions to classes, **`service-policy`** activates a policy-map **globally or per-interface** (interface beats global for the same traffic; only **one global policy**).

**The default global policy (present on nearly every ASA).** The default L3/4 class `inspection_default` uses `match default-inspection-traffic` (a shortcut for every inspection's default ports); the default `global_policy` enables a baseline of inspections on all interfaces:
```
class-map inspection_default
 match default-inspection-traffic
policy-map global_policy
 class inspection_default
  inspect dns preset_dns_map
  inspect ftp
  inspect h323 h225
  inspect h323 ras
  inspect rsh
  inspect rtsp
  inspect esmtp
  inspect sqlnet
  inspect skinny
  inspect sunrpc
  inspect xdmcp
  inspect sip
  inspect netbios
  inspect tftp
service-policy global_policy global
```

**Application inspection (`inspect …`).** Available engines: `ctiqbe, dcerpc, dns, esmtp, ftp, gtp, h323 (h225/ras), http, icmp, icmp error, ils, ip-options, ipsec-pass-thru, m3ua, mgcp, mmp, netbios, pptp, radius-accounting, rsh, rtsp, sctp, sip, skinny (sccp), snmp, sqlnet, stun, sunrpc, tftp, waas, xdmcp`. The 14 in the block above are **ON by default**; the rest (CTIQBE, DCERPC, GTP, HTTP-deep, ICMP, MGCP, SNMP, STUN, WAAS, …) are **OFF** unless explicitly enabled.

**🔴🔴 What inspection actually does** — protocols that **embed IP/port info in the payload** or **open secondary channels on dynamic ports** need an ALG: inspection (a) **opens dynamic pinholes** (FTP data, SIP/H.323/SCCP media, SunRPC/DCERPC), (b) **NAT-rewrites embedded addresses**, and (c) **enforces protocol conformance**. Drop it and the flow either **breaks** (the dynamic channel is never opened) or **passes with zero L7 checks**.

**Deep L7 inspection policy maps** — `policy-map type inspect http|dns|ftp|esmtp …` add match/regex conditions with **drop / drop-connection / reset / log / rate-limit** actions (block FTP commands, match HTTP methods/URLs, DNS regex). This is real L7 enforcement, not just pinholing.

**Other MPF actions.**
- **`set connection`** — `conn-max`, `embryonic-conn-max`, `per-client-max`, `per-client-embryonic-max` (0 = unlimited), timeouts (`conn`, `embryonic`, `half-closed`, `dcd`). Embryonic limits = SYN-flood protection (TCP Intercept).
- **TCP normalization** — always-on normalizer, customized by a `tcp-map` applied via `set connection advanced-options <tcp-map>`.
- **QoS** — priority queueing / policing / shaping (unidirectional).
- **Module redirect** — `ips` (AIP), `sfr` (ASA FirePOWER), `cxsc` (ASA CX) hand traffic to a service module for IPS/NGFW. One module per traffic set.

**FortiOS re-model.**

| ASA MPF action | FortiOS | Re-model notes |
|---|---|---|
| `inspect ftp/tftp/rtsp/pptp/rsh/dns/sunrpc/dcerpc/mgcp/h323` | `config system session-helper` (ftp, tftp, rtsp, dns-udp/dns-tcp, pmap, dcerpc, mgcp, h323+ras, pptp, rsh, …) | direct ALG equivalents; map each engine to its helper |
| `inspect sip` / `inspect skinny (sccp)` | **`config voip profile`** (`config sip`/`sccp`) on the policy, or session-helper `sip` | proxy ALG; SCCP has no session-helper |
| `inspect esmtp/http` deep (`policy-map type inspect …`) | application control (`config application list`) + IPS (`config ips sensor`) + `config firewall profile-protocol-options` | deep-L7 → App-Control/IPS; protocol conformance/ports → protocol-options |
| `inspect http` enhanced (methods/URLs/regex) | webfilter + app-control + IPS | re-model; no single knob |
| `set connection conn-max / per-client-max` | DoS policy `tcp_dst_session`/`tcp_src_session` (+ udp/icmp variants) | concurrent-session caps |
| `set connection embryonic-conn-max` | DoS policy `tcp_syn_flood` | SYN-flood / embryonic |
| `set connection timeout …` | `config system session-ttl` / session settings | timeouts |
| `tcp-map` / TCP normalization | IPS engine + `profile-protocol-options` | no standalone tcp-map; FortiOS normalizes in IPS |
| QoS (priority/police/shape) | `config firewall shaping-policy` + shapers | lossy priority mapping |
| `ips` / `sfr` / `cxsc` redirect | native inline IPS: `config ips sensor` + policy `set ips-sensor` | no redirect needed — IPS runs inline; FirePOWER policy itself doesn't export |

🔴🔴 **Silent-loss flag (loud).** MPF contributes **no firewall-policy / object / service lines** — like SRX screens and the lo0 filter, it's among the easiest things in an ASA config to lose silently. Drop the `global_policy` inspections and the FortiGate has **no ALG pinholing** (FTP/SIP/H.323 break or pass blind) and **no L7 conformance enforcement** the ASA had, with nothing in the output revealing it. Even the *default* `global_policy` — which a converter is tempted to ignore as "just defaults" — carries 14 active inspections. The converter MUST: parse `class-map`/`policy-map`/`service-policy`, enable the corresponding FortiOS session-helpers / VoIP profile / protocol-options, re-model `set connection` limits to DoS, FirePOWER/IPS redirect to a native sensor, and **report every inspection engine and deep-inspect map it could not faithfully reproduce** — never silently omit, never leave a broader-than-source helper enabled.

> **Default-state divergence trap** (mirrors the SRX ALG trap): FortiOS ships session-helpers **enabled by default**. Reconcile against the ASA's actual inspection set — if the ASA *disabled* a default inspection, emit an explicit `delete` of the FortiOS helper (or report), so you don't leave the FortiGate with *more* ALGs active than the source.

**fwforge status: ❌ GAP (high).** There is **no MPF parsing** in cisco_asa.py — `class-map`, `policy-map`, `service-policy`, `inspect`, `set connection`, `tcp-map`, `ips`/`sfr`/`cxsc` are not in the dispatch table (`parse`, cisco_asa.py:317-397); each lands in the catch-all `else` → `unparsed` + `_swallow_block`. So **all L7 inspection (including the default global policy), connection limits, TCP normalization, and FirePOWER redirect are silently un-converted** (recorded in `unparsed`, but with no targeted finding and no FortiOS equivalent emitted). Second-highest audit item after security-level.

**Sources:** [ASA Modular Policy Framework / Service Policy](https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/firewall/asa-firewall-cli/mpf-service-policy.html) · [ASA Getting Started with Application Inspection (default global_policy)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa912/configuration/firewall/asa-912-firewall-config/inspect-overview.html) · [ASA Inspection of Basic Internet Protocols (ALG behavior)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa912/configuration/firewall/asa-912-firewall-config/inspect-basic.html) · [ASA Inspection Policy Maps (deep L7)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/firewall/asa-firewall-cli/mpf-inspect-maps.html) · [ASA Connection Settings (set connection, tcp-map)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa912/configuration/firewall/asa-912-firewall-config/conns-connlimits.html) · [ASA inspect command reference](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/m_inspect-a-inspect-z.html) · [FortiOS session-helper](https://docs.fortinet.com/document/fortigate/6.4.6/cli-reference/116620/config-system-session-helper) · [FortiOS SIP ALG vs session helper](https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/147933/sip-alg-and-sip-session-helper) · [FortiOS DoS policy](https://docs.fortinet.com/document/fortigate/7.4.1/administration-guide/771644/dos-policy) · [FortiOS profile-protocol-options](https://docs.fortinet.com/document/fortigate/7.4.2/cli-reference/287620/config-firewall-profile-protocol-options)

---

## 5. Management-plane access 🔴 (`ssh`/`http`/`telnet`/`icmp`/`snmp` — control-plane protection)

**What it is.** ASA to-the-box management is governed by per-interface **permitted-source lists** — the analogue of SRX `host-inbound-traffic` / the lo0 filter:
```
ssh    192.168.1.0 255.255.255.0 inside
ssh    0.0.0.0     0.0.0.0       outside   ! (all sources — the open form)
http   192.168.1.0 255.255.255.0 inside
http server enable
telnet 10.0.0.0    255.255.255.0 inside
icmp permit 192.168.1.0 255.255.255.0 inside
snmp-server host inside 192.168.1.50 community SECRET
```
These are **access control, not enable flags** — they specify *which source subnets* may reach SSH/ASDM-HTTPS/Telnet/ICMP on a named interface. `http server enable` turns on ASDM/HTTPS. Once any `icmp` control entry exists on an interface, the ASA applies an **implicit deny** to all other ICMP to that interface (deny-by-default once a list exists; with no entries, ICMP is allowed). `snmp-server host` defines the NMS and auto-permits inbound SNMP from it; `snmp-server community` sets the v1/v2c string.

**FortiOS re-model — two separate axes.** FortiOS splits "which services" from "which sources":

| ASA item | FortiOS mechanism | Notes |
|---|---|---|
| service reachable on interface (ssh/https/telnet/ping/snmp/http) | per-interface **`set allowaccess ssh https telnet ping snmp http`** | the "which protocols" axis only — applies to **all** source IPs |
| permitted **source** subnet list | **`config firewall local-in-policy`** (intf/srcaddr/dstaddr/service/action) | 🔴 **no implicit deny** — you must add an explicit trailing **deny-all** or every source still reaches the box |
| admin-source restriction | `config system admin` → `set trusthost1..10` (+ `ip6-trusthost`) | per-admin login source subnets |
| `snmp-server host`/`community` | SNMP config + `allowaccess snmp` + local-in-policy for the source | re-model |

🔴 **Silent-loss flag (two opposite failures, mgmt-plane = high severity).** (1) **Emit `allowaccess` but drop the permitted-source list** → mgmt **exposed to every source IP** (the worse failure — `allowaccess` carries no source restriction, and FortiOS local-in-policy has **no implicit deny**, so you must synthesize the trailing deny). (2) **Emit nothing** → admin **lockout**. The converter MUST translate `ssh/http/telnet/icmp permit <src> <iface>` into `allowaccess` (services) **plus** `local-in-policy` and/or admin `trusthost` (sources, with an explicit terminal deny), and report anything it can't reproduce.

**fwforge status: ❌ GAP.** None of `ssh`, `http`, `http server enable`, `telnet`, `icmp`, `snmp-server` appear in the `parse` dispatch table — all fall to the catch-all `else` → `unparsed` (cisco_asa.py:395-397). So the **management-plane source allow-lists are not converted**: no `allowaccess`, no `local-in-policy`, no `trusthost` is emitted. The lines are recorded in `unparsed` (not silently gone), but the FortiGate ships with **no derived mgmt restriction** — exactly the "mgmt exposed to all / or lockout" trap. Audit item.

**Sources:** [ASA Management Access (ssh/telnet/http/icmp, http server enable)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa922/configuration/general/asa-922-general-config/admin-management.html) · [ASA SNMP](https://www.cisco.com/c/en/us/td/docs/security/asa/asa922/configuration/general/asa-922-general-config/monitor-snmp.html) · [FortiOS interface settings / allowaccess](https://docs.fortinet.com/document/fortigate/7.6.2/administration-guide/574723/interface-settings) · [FortiOS local-in-policy (no implicit deny)](https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/363127/local-in-policy) · [FortiOS config system admin (trusthost)](https://docs.fortinet.com/document/fortigate/7.4.1/cli-reference/13620/config-system-admin)

---

## 6. VPN 🔴 (policy-based crypto map → route-based; remote-access is a GAP)

**Site-to-site — policy-based crypto map (the common ASA form).**
```
crypto ikev1 policy 10
 encryption aes-256
 hash sha
 group 14
 lifetime 28800
crypto ipsec ikev1 transform-set TS esp-aes-256 esp-sha-hmac
crypto map CMAP 10 match address VPN_ACL
crypto map CMAP 10 set peer 203.0.113.5
crypto map CMAP 10 set ikev1 transform-set TS
crypto map CMAP 10 set pfs group14
crypto map CMAP interface outside
tunnel-group 203.0.113.5 type ipsec-l2l
tunnel-group 203.0.113.5 ipsec-attributes
 ikev1 pre-shared-key SECRET
```
The crypto ACL (`match address`) defines interesting traffic (proxy-IDs); `set peer`/`transform-set`/`pfs` set the SA; `crypto map … interface` binds it. **IKEv1** uses a transform-set; **IKEv2** a `crypto ikev2 policy` + `set ikev2 ipsec-proposal`. **`tunnel-group`** is the connection profile (`type ipsec-l2l` vs `remote-access`; PSK under `ipsec-attributes`). **`group-policy`** holds user attributes: **split-tunnel policy/ACL**, address pools, `vpn-tunnel-protocol`.

**Site-to-site — route-based VTI.** `crypto ipsec profile` + `interface Tunnel N` (`tunnel mode ipsec ipv4`, `tunnel source/destination`, `tunnel protection ipsec profile`) — no crypto-map ACL.

**Remote-access.** `webvpn` (`anyconnect enable`/`image`) + `tunnel-group type remote-access` + `group-policy` = AnyConnect / SSL-VPN / IKEv2-RA client VPN. FortiOS = SSL-VPN or IPsec **dialup** (dynamic phase1).

**FortiOS re-model.** Policy-based interface-bound crypto maps must become **route-based** `config vpn ipsec phase1-interface` + `phase2-interface` (the crypto ACL → phase2 `src-subnet`/`dst-subnet` selectors and/or per-tunnel firewall policies + a route to the remote subnet).

| ASA VPN | FortiOS | 🔴 risk |
|---|---|---|
| `crypto ikev1/2 policy` (enc/hash/group/lifetime) | phase1-interface `proposal`/`dhgrp`/`keylife` | algorithm-token mapping |
| transform-set / ipsec-proposal | phase2-interface `proposal` | GCM = no auth suffix |
| `crypto map … match address ACL` | phase2 selectors `src-subnet`/`dst-subnet` (+ route + policies) | 🔴 deny ACEs in crypto ACL have no selector equiv; group/range selectors need expansion |
| `set peer` (multiple) | phase1 `remote-gw` (one) | 🔴 backup peers → 2nd phase1/SD-WAN, not auto |
| `tunnel-group … ikev1 pre-shared-key` | phase1 `psksecret` | 🔴 masked `*****` exports → placeholder, must re-enter |
| `group-policy` (split-tunnel ACL, pools, attrs) | **not assembled** | 🔴 split-tunnel scoping / address pools lost |
| AnyConnect / webvpn / RA | SSL-VPN or IPsec dialup | 🔴 **not auto-converted** |
| VTI | phase1-interface (route-based) | maps naturally |
| `trustpoint` / cert auth | phase1 `authmethod signature` + imported certs | 🔴 certs not in config — manual |
| aggressive mode / dynamic-map (dial-up) | `set mode aggressive` / dial-up phase1 | flagged, manual |

🔴 **Silent-loss flags.** (1) **Masked PSKs** → placeholder, never a real key. (2) **Backup peers** silently dropped → no failover. (3) **group-policy split-tunnel ACL / address pools** not assembled → tunnel scope lost. (4) **Remote-access / AnyConnect** not converted. (5) **Crypto-ACL deny ACEs** have no FortiOS selector — must be reported, not silently treated as permit.

**fwforge status: ⚠️ partial (L2L only).** `parse_crypto`/`parse_tunnel_group`/`finish_vpn` (cisco_asa.py:922-1334) assemble **site-to-site IKEv1/IKEv2 crypto-map VPNs** into route-based phase1/phase2 + routes + auto-generated in/out policies, with solid edge-case findings: masked/missing PSK → `CHANGEME-PSK` (lines 1119-1134), backup peers flagged (1205-1210), aggressive mode / trustpoint / dynamic-map flagged (994-1014), crypto-ACL deny ACEs noted as ignored (1280-1284), group/non-host selectors flagged (1157-1174). **GAPs (explicitly flagged, not converted):** `group-policy` is swallowed with an info note (cisco_asa.py:390-394) so **split-tunnel ACLs / address pools are lost**; `crypto dynamic-map` and remote-access/AnyConnect `tunnel-group type remote-access` are not converted (1003-1007, 1096-1100); VTI (`interface Tunnel`) is not specifically parsed (falls to `unparsed`). LAN-side interface for VPN policies is inferred from the route table, with `any` + a warning on failure.

**Sources:** [ASA Site-to-Site VPN (crypto map)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa923/configuration/vpn/asa-923-vpn-config/vpn-site2site.html) · [ASA IPsec/ISAKMP (IKEv1/v2)](https://www.cisco.com/c/en/us/td/docs/security/asa/asa918/configuration/vpn/asa-918-vpn-config/vpn-ike.html) · [ASA VTI](https://www.cisco.com/c/en/us/td/docs/security/asa/asa923/configuration/vpn/asa-923-vpn-config/vpn-vti.html) · [ASA connection profiles / group-policy](https://www.cisco.com/c/en/us/td/docs/security/asa/asa914/configuration/vpn/asa-914-vpn-config/vpn-groups.html) · [ASA AnyConnect](https://www.cisco.com/c/en/us/td/docs/security/asa/asa923/configuration/vpn/asa-923-vpn-config/vpn-anyconnect.html) · [FortiOS phase1-interface](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/331620/config-vpn-ipsec-phase1-interface) · [phase2-interface](https://docs.fortinet.com/document/fortigate/7.6.3/cli-reference/252893715/config-vpn-ipsec-phase2-interface)

---

## 7. Routing 🔴 (fwforge parses static only — dynamic routing is a silent drop)

**ASA.** Static/default `route <iface> <dest> <mask> <gw> [distance]` (default AD = 1; default route = `route outside 0.0.0.0 0.0.0.0 <gw>`). Dynamic: **OSPF** (`router ospf <pid>`, up to two), **BGP** (`router bgp <as>`), **EIGRP** (`router eigrp <as>`, routed mode), **RIP** (`router rip`).

**FortiOS.** `config router static` (per-route `distance`), `config router ospf` / `bgp` / `rip`. **No EIGRP in FortiOS** — `router eigrp` has **no target** and must be reported non-convertible, never silently remapped to another protocol.

| ASA | FortiOS | 🔴 risk |
|---|---|---|
| `route IFC dest mask gw [dist]` | `config router static` | clean; AD→`distance` |
| `ipv6 route …` | `config router static6` | |
| `router ospf` / `bgp` / `rip` | `config router ospf` / `bgp` / `rip` | re-model (process/area/neighbor config) |
| `router eigrp` | **none** | 🔴 no equivalent — report, never remap |

🔴 **Silent-loss flag.** Routing isn't security policy, but a **missing route silently breaks reachability** (and on FortiOS, a route to a tunnel interface is what makes a route-based VPN pass traffic). Dropping a dynamic-routing process that injects the default or transit routes blackholes everything that depended on it.

**fwforge status: ⚠️ static only — dynamic routing is a GAP.** `parse_route` (cisco_asa.py:1357) handles `route IFC dest mask gw [dist]` and `ipv6 route` (cisco_asa.py:371-378). **`router ospf`/`bgp`/`eigrp`/`rip` are NOT parsed** — they hit the catch-all `else` → `unparsed` + `_swallow_block` (so recorded, not silent at the report level, but no routes emitted and no targeted finding). VPN routes to tunnel interfaces are synthesized in `finish_vpn`.

**Sources:** [ASA Static Routes](https://www.cisco.com/c/en/us/td/docs/security/asa/asa919/configuration/general/asa-919-general-config/route-static.html) · [OSPF](https://www.cisco.com/c/en/us/td/docs/security/asa/asa919/configuration/general/asa-919-general-config/route-ospf.html) · [BGP](https://www.cisco.com/c/en/us/td/docs/security/asa/asa919/configuration/general/asa-919-general-config/route-bgp.html) · [EIGRP](https://www.cisco.com/c/en/us/td/docs/security/asa/asa919/configuration/general/asa-919-general-config/route-eigrp.html) · [FortiOS config router static](https://docs.fortinet.com/document/fortigate/7.4.1/cli-reference/527620/config-router-static)

---

## 8. System-level features (HA, transparent/ethertype, contexts→VDOM, threat-detection, botnet, AAA/identity)

### 8.1 HA / failover
Two identical ASAs + failover link (+ optional state link); **Active/Standby** or **Active/Active** (A/A requires multiple-context mode, failover groups). `failover lan unit primary|secondary`, `failover lan interface`, `failover link`, `monitor-interface`. → FortiOS **HA** (`config system ha`, A-P/A-A, `set priority`). **Converter: flag as device-pairing infrastructure — do NOT translate to any policy/object.** ([ASA failover](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/general/asa-920-general-config/ha-failover.html) · [FortiOS HA A-P](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/900885/ha-active-passive-cluster-setup))

### 8.2 Transparent vs routed firewall mode + EtherType ACLs 🔴
Default is **routed** (L3). **`firewall transparent`** = L2 bridging firewall ("bump in the wire"). In transparent mode, **EtherType ACLs** (`access-list NAME ethertype permit|deny {ipx|bpdu|mpls-unicast|mpls-multicast|isis|<hex≥0x600>}`) filter **non-IP L2 traffic**. → FortiOS **transparent operation mode** (VDOM as a bridge) or **virtual-wire-pair**. 🔴 **EtherType ACLs have NO clean FortiOS equivalent** — report each ACE as non-convertible with its source line; never flatten to a firewall policy. ([ASA ethertype ACL](https://www.cisco.com/c/en/us/td/docs/security/asa/asa91/configuration/general/asa_91_general_config/acl_ethertype.html) · [FortiOS transparent mode](https://docs.fortinet.com/document/fortigate/7.4.5/administration-guide/302871/transparent-mode) · [virtual-wire-pair](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/166804/virtual-wire-pair))

### 8.3 Multiple-context mode → VDOM
`mode multiple` partitions the ASA into **security contexts** (each its own policy/interfaces/admins) from the **system execution space**: `context NAME`, `config-url`, `allocate-interface`; plus the **admin context**. → FortiOS **VDOMs** (`config vdom`): context ⇒ VDOM, system space ⇒ global config, admin context ⇒ management VDOM (root), `allocate-interface` ⇒ per-VDOM interface assignment. (fwforge already has a VDOM-mode wrapper — see `transforms/vdommode.py`.) 🔴 Watch cross-VDOM scope/namespace corruption (CLAUDE.md class) when multiple contexts merge. ([ASA contexts](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/general/asa-920-general-config/ha-contexts.html) · [FortiOS VDOM](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/597696/vdom-overview))

### 8.4 Threat detection
`threat-detection basic-threat` (rate-based drop-event syslogs, no blocking), `threat-detection statistics` (host/port/proto/ACL counters), `threat-detection scanning-threat [shun]` (suspicious-host DB; on scan-rate exceed, syslog 733101 and — with `shun` — **proactively blocks the attacker**). → FortiOS composite: rate/flood ⇒ **DoS policy**, signature scan/exploit ⇒ **IPS**, auto-block ⇒ **Automation Stitch / quarantine (ban source IP)**. 🔴 **`scanning-threat shun` is a dynamic enforcement action** — flag as behavioral, not a direct policy/object; basic-threat/statistics are monitoring-only (report informational). ([ASA threat detection](https://www.cisco.com/c/en/us/td/docs/security/asa/asa912/configuration/firewall/asa-912-firewall-config/conns-threat.html))

### 8.5 Botnet traffic filter (`dynamic-filter`)
Checks connections against a **dynamic DB of malicious domains/IPs** from the Cisco update server (+ optional static blacklist/whitelist). **Legacy/subscription-gated:** the per-device `*-BOT-1YR` license SKUs are EOL on third-party trackers and the feature did **not** carry to FTD/Secure Firewall; without an active license the dynamic feed doesn't update. → FortiOS **FortiGuard botnet/IP-reputation**: Botnet C&C **domain** blocking in a **DNS filter** profile + Botnet C&C **IP** blocking via **IPS** (`scan-botnet-connections`). 🔴 Carry **static** blacklist/whitelist entries (→ address objects / external blocklists); enable FortiGuard botnet for the dynamic part. ([ASA botnet filter](https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/firewall/asa-firewall-cli/protect-botnet.html) · [FortiOS botnet C&C domain](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/105208/botnet-c-c-domain-blocking))

### 8.6 AAA / identity firewall
`aaa authentication` (cut-through proxy — authenticate the user, then permit), `aaa-server` (RADIUS/TACACS+/LDAP/Kerberos groups), **Identity Firewall** (`user-identity` + external AD Agent maps IP↔AD user/group; **user/group used directly in ACLs**). → FortiOS **FSSO** (`config user fsso`) + FSSO groups in policy via **`set groups`**; interactive auth ⇒ FSSO firewall authentication. The AD-Agent appliance itself = external infrastructure (flag). 🔴 **User/group in an ASA ACL → policy `set groups`** *is* translatable (unlike §1/§5) — dropping it removes the identity scoping and **broadens the rule to all users**. ([ASA identity firewall / AAA](https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/general/asa-general-cli/aaa-idfw.html) · [FortiOS FSSO firewall auth](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/576158/configuring-fsso-firewall-authentication))

**fwforge status (§8): ❌ GAP across the board.** None of `failover`, `firewall transparent`, ethertype ACLs, `mode multiple`/`context`, `threat-detection`, `dynamic-filter`/botnet, `aaa`/`user-identity` are in the parser dispatch — all fall to `unparsed`. Multiple-context mode is the highest-value §8 gap (the VDOM-mode wrapper exists but the ASA parser doesn't split contexts); identity-firewall user-in-ACL is the one with a silent-broadening edge.

---

## Consolidated — ASA silent-loss checklist

Ranked by blast radius. Drop or mis-map any of these and the FortiGate **silently loses protection or broadens a rule** while the output looks complete.

| # | ASA construct | Converts to | 🔴 Risk if dropped / mis-mapped | fwforge |
|---|---|---|---|---|
| 1 | 🔴🔴 **Security-level implicit permit** (higher→lower, no ACL) + `same-security-traffic` | synthesized explicit `firewall policy` per interface pair | **all implicit outbound/same-level policy lost → mass denial (breakage)** or, if papered over, over-broadened any-any | ❌ GAP (level discarded) |
| 2 | 🔴🔴 **MPF inspection** (`inspect …`, incl. default `global_policy`) | session-helpers / VoIP profile / protocol-options / IPS | **all L7/ALG enforcement gone** — FTP/SIP/H.323 break or pass blind; zero protocol conformance | ❌ GAP (no MPF parse) |
| 3 | 🔴 **Mgmt-plane source lists** (`ssh/http/telnet/icmp/snmp <src> <iface>`) | `allowaccess` + `local-in-policy` (+ explicit deny) + `trusthost` | mgmt **exposed to all source IPs** (allowaccess has no source filter; local-in has no implicit deny) — or admin lockout | ❌ GAP |
| 4 | 🔴 **Twice/policy NAT** (`source static … destination static … service …`) + NAT pools + section order | VIP + `central-snat-map`; `ippool` type-correct | conditional policy-NAT lost; `one-to-one`→`overload` silently adds PAT; wrong section wins | ❌ GAP (object NAT only) |
| 5 | 🔴 **`neq` / unresolved named port operators** in ACEs | policy emitted **disabled** for review | converting as any-port **broadens** the rule (the core bug class) | ✅ fails closed (disabled) |
| 6 | 🔴 **`inactive` ACE** | `set status disable` | silently **activates** a disabled rule | ✅ handled |
| 7 | 🔴 **`time-range` on ACE** | `firewall schedule recurring`/`onetime` + `set schedule` | rule runs **24/7** (time window broadened) | ⚠️ noted, NOT converted |
| 8 | 🔴 **`log` setting** on ACE | `set logtraffic all` / `disable` | SIEM/audit visibility lost | ✅ handled |
| 9 | 🔴 **DNAT real-vs-mapped + VIP** (ASA ACL = real IP) | VIP (`mappedip`=real, `extip`=public); policy `dstaddr`=VIP | raw address instead of VIP → blackhole; rewriting ACL to public IP → no match | ⚠️ object-static handled |
| 10 | 🔴 **Static-PAT to interface IP** (`static interface service …`) | VIP `portforward`, extip = egress-iface IP (manual) | public IP not in config — must flag, never guess | ⚠️ flagged for manual |
| 11 | 🔴 **VPN PSK masked / group-policy split-tunnel / remote-access** | `psksecret` placeholder; phase2 selectors; SSL-VPN/dialup | placeholder-not-real-key; split-tunnel scope lost; RA not converted | ⚠️ L2L only; RA/group-policy GAP |
| 12 | 🔴 **`access-group out` / `global` direction + order** | `dstintf` / any-srcintf policy, ordered | eval order (global after interface, out vs in) flattened → wrong winner | ⚠️ `in`/`global` only |
| 13 | 🔴 **EtherType ACLs** (transparent mode) | none (report) | non-IP L2 filtering silently dropped | ❌ GAP |
| 14 | 🔴 **Dynamic routing** (`router ospf/bgp/eigrp/rip`) | `config router ospf/bgp/rip` (no EIGRP) | missing routes blackhole traffic / VPN; EIGRP no target | ❌ GAP (static only) |
| 15 | 🔴 **Multiple-context mode** | one VDOM per context | contexts merged → cross-VDOM scope/namespace corruption | ❌ GAP (wrapper exists) |
| 16 | 🔴 **Identity-firewall user/group in ACL** | policy `set groups` (FSSO) | identity scoping dropped → rule **broadened to all users** | ❌ GAP |
| 17 | 🟠 `set connection` limits / TCP-normalization (`tcp-map`) | DoS policy session/SYN limits; IPS/protocol-options | SYN-flood / conn-exhaustion protection lost | ❌ GAP (part of MPF) |
| 18 | 🟠 Threat-detection `scanning-threat shun` / botnet `dynamic-filter` | DoS + IPS + automation/quarantine; FortiGuard botnet | scan-shun + malicious-domain/IP blocking lost (botnet is legacy) | ❌ GAP |
| 19 | 🟠 HA / failover | `config system ha` | infrastructure — flag, never emit as policy | ❌ GAP (correctly out-of-band) |

> **fwforge anchors:** security-level synthesis, MPF parsing, mgmt-plane source lists, twice-NAT, dynamic routing, ethertype ACLs, multiple-context split, and identity-in-ACL are the un-handled surfaces in `fwforge/parsers/cisco_asa.py` (each currently lands in `unparsed` or is discarded). Adding them needs IR support in `model.py` (security-level/implicit-permit synthesis, a local-in-policy / allowaccess representation, central-SNAT + policy-NAT, dynamic-routing objects, FSSO groups) behind tests; name-collision/clamps via `transforms/names.py`+`limits.py`; emit gating (disabled-on-neq, VIP-vs-raw, local-in trailing deny, ethertype report) in `emit/fortios.py`; multi-context → VDOM via `transforms/vdommode.py`. Every synthesis/flatten/disable/skip must hit the report — nothing dropped silently, nothing broadened.
