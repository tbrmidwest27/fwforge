# pfSense (config.xml) — SECURITY Configuration Surface & FortiOS Mapping

**Authoritative converter reference + pfSense expertise. Every pfSense fact below is grounded in Netgate's official pfSense documentation (`docs.netgate.com`); FortiOS mapping targets cite `docs.fortinet.com`. Exact URLs are cited per section.** (pfSense docs use rolling `/en/latest/` URLs; semantics below are stable across pfSense CE 2.6–2.8 / Plus 23.x–24.x. The literal `<...>` config.xml element names are parser-empirical — Netgate documents the GUI/feature surface, not the XML schema element-by-element — so element names are stated as observed in real configs, not doc-cited.)

> **Why this document exists.** A pfSense firewall's protection is **not** all in its `<filter>` rules. A large fraction lives **outside** the visible ruleset: **auto-added implicit rules** (anti-lockout, block-private/bogon, VPN pass rules, the default-deny) that appear nowhere in `<filter>` but are live policy; **`<installedpackages>`** (pfBlockerNG, Suricata/Snort, Squid/SquidGuard, HAProxy, Captive Portal) that carry all of the L7 / IDS-IPS / URL-filter / threat-feed protection; and **floating rules** whose match-order semantics have no FortiOS analog. A converter that walks only `<filter>`/`<nat>`/`<ipsec>` silently loses all of these. This reference is the complete checklist of *"what a pfSense security config actually contains."* Two principles run through every section:
> 1. **Nothing is dropped silently.** Anything non-convertible goes in the report with its source file + line.
> 2. **No silent rule-broadening.** Where FortiOS has no 1:1 equivalent, the doc says **"re-model required"** — it never implies a clean mapping. Floating-rule last-match, `reject` semantics, `<not/>` negation, per-rule gateways, 1:1-NAT-with-destination, NAT reflection, and the security packages are the classic broadening/loss landmines.
>
> Landmine sections (silent protection loss or rule-broadening if dropped) are flagged 🔴; the two highest-impact get 🔴🔴.
>
> **fwforge grounding.** Each section ends with a **fwforge status** note: ✅ handled, ⚠️ partial, or ❌ GAP (silent drop / broadening), based on `fwforge/parsers/pfsense.py`. These seed a later parser audit.

---

## 1. Packages (`<installedpackages>`) 🔴🔴 — the #1 pfSense silent-loss surface (all L7 / IDS-IPS / URL-filter / threat-feeds live here)

**What it is.** pfSense's base firewall is L3/L4 packet filtering only. **Everything resembling NGFW protection is an add-on package** stored under `<installedpackages>` (and, for Captive Portal, the base `<captiveportal>` element). These packages contribute **zero `<filter>` / `<nat>` lines** — they are the pfSense analog of ASA's Modular Policy Framework and SRX's UTM/IDP/screens. Drop them and the FortiGate ships with **no IPS, no URL filtering, no DNS blocklists, no GeoIP blocking, no proxy, no portal**, with nothing in the converted ruleset revealing the loss.

| pfSense package | What it does | FortiOS re-model | 🔴 risk |
|---|---|---|---|
| **pfBlockerNG** (DNSBL) | DNS-based blocklists (malware/ad/category domains) resolved by the resolver | **DNS filter profile** (`config dnsfilter profile`) on the policy | 🔴 domain-level blocking silently gone |
| **pfBlockerNG** (IP/URL feeds) | IPv4/IPv6 feed lists, alias/deny by feed | **External threat feeds** (`config system external-resource`, type address/domain) → address-group in a deny policy | 🔴 IP-reputation/feed blocking gone |
| **pfBlockerNG** (GeoIP) | country-based block/allow | **Geography address objects** (`config firewall address` `type geography`) | 🔴 geo-block gone → exposure broadens |
| **Suricata / Snort** | inline or passive **IDS/IPS** (signature rules, per-interface) | **IPS sensor** (`config ips sensor`) + `set ips-sensor` on the policy | 🔴🔴 **all intrusion prevention gone** |
| **Squid + SquidGuard** | caching/forward proxy + **URL/category filtering** (deprecated in pfSense, but live in many configs) | **Explicit web proxy** (`config web-proxy explicit`) + **web filter** (`config webfilter profile`) | 🔴 URL filtering + proxy gone |
| **HAProxy** | reverse proxy / **L7 load balancer** (frontends/backends, ACLs, SSL offload) | **Virtual server / server-load-balance VIP** (`config firewall vip set type server-load-balance`) — LB only, not full L7 ACL parity (FortiWeb territory) | 🔴 published services lost / unbalanced |
| **Captive Portal** (`<captiveportal>`) | per-interface guest auth / voucher / RADIUS portal | **FortiOS captive portal** (interface security mode + firewall auth + FSSO) | 🔴 guest auth gone → open network |
| **ntopng** | flow visibility | **FortiView** dashboard — no converted object (informational) | 🟠 monitoring only |
| **avahi** | mDNS reflector | no 1:1 (multicast-forwarding / Bonjour profile) — informational | 🟠 |

🔴🔴 **Silent-loss flag (loud).** Like ASA MPF and SRX screens, packages are the **easiest thing in a pfSense config to lose silently** — they live in a different XML tree and contribute no firewall-rule lines. A converter reading only `<filter>`/`<nat>` produces a FortiGate that **looks complete but has no IPS, URL filtering, DNS/IP blocklists, GeoIP, proxy, or captive portal.** The converter MUST: enumerate every `<installedpackages>` child and `<captiveportal>`, map each to its FortiOS feature (IPS sensor / webfilter / dnsfilter / external-resource / geography address / explicit-proxy / captive portal), and **report every package it cannot faithfully reproduce** — never silently omit, never leave the source's L7/threat protection un-emitted.

**fwforge status: ❌ GAP (highest).** `report_unconverted` (pfsense.py:867) walks every top-level XML key **not** in the `CONSUMED` set (pfsense.py:62-64) and emits an `info`-level coverage finding — so `installedpackages` and `captiveportal` are **recorded, not silently gone at the report level** — but there is **no targeted parsing or FortiOS emission** for any package. pfBlockerNG, Suricata/Snort, Squid/SquidGuard, HAProxy, and Captive Portal produce **no IPS sensor, no webfilter, no dnsfilter, no threat-feed, no geo object, no portal**. This is the top audit item — the L7/threat surface is entirely un-converted (and only an `info` finding, not a `warn`/`error`, which understates the blast radius).

**Sources:** [pfBlockerNG](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html) · [Block websites w/ pfBlockerNG](https://docs.netgate.com/pfsense/en/latest/recipes/block-websites.html) · [Snort/Suricata IDS-IPS](https://docs.netgate.com/pfsense/en/latest/packages/snort/index.html) · [Squid/SquidGuard](https://docs.netgate.com/pfsense/en/latest/packages/cache-proxy/squidguard.html) · [HAProxy](https://docs.netgate.com/pfsense/en/latest/packages/haproxy.html) · [Captive Portal](https://docs.netgate.com/pfsense/en/latest/captiveportal/index.html) · [avahi](https://docs.netgate.com/pfsense/en/latest/packages/avahi.html) · [FortiOS DNS filter profile](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/572589/configuring-a-dns-filter-profile) · [FortiOS threat feeds (external-resource)](https://docs.fortinet.com/document/fortigate/7.0.1/administration-guide/9463/threat-feeds) · [FortiOS geography addresses](https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/286826/geography-based-addresses) · [FortiOS IPS sensor](https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/583477/configuring-an-ips-sensor) · [FortiOS explicit web proxy](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/300428/explicit-web-proxy) · [FortiOS web filter profile](https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/267887/configuring-a-web-filter-profile) · [FortiOS server load balance VIP](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/713497/virtual-server-load-balance) · [FortiOS captive portals](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/934626/captive-portals)

---

## 2. Firewall filter rules `<filter><rule>` 🔴 (floating + quick/direction, `<not/>`, per-rule gateway, schedule/disabled/log are the must-carries)

**XML shape.** Each `<rule>` is, like ASA, **per-interface and inbound by default**: `<interface>` is the ingress (→ FortiOS `srcintf`), `dstintf` is inferred route-based by fwforge.
```xml
<rule>
  <type>pass</type>                  <!-- pass | block | reject -->
  <interface>lan</interface>
  <ipprotocol>inet</ipprotocol>      <!-- inet | inet6 | inet46 -->
  <protocol>tcp</protocol>
  <source><network>lan</network></source>
  <destination><address>WebServers</address><port>443</port></destination>
  <descr>allow web</descr>
  <tracker>1700000000</tracker>      <!-- stable rule ID -->
  <log/>  <disabled/>  <sched>BIZHOURS</sched>  <gateway>WAN_DHCP</gateway>
</rule>
```

**Rule action — `<type>` pass / block / reject.**
- **`pass`** — allows the packet; with state tracking, a state entry is created so return traffic passes. → FortiOS `set action accept`.
- **`block`** — **silently drops** (client waits for timeout). → FortiOS `set action deny` (also a silent drop — clean match).
- **`reject`** — actively refuses: **TCP → RST**, **UDP → ICMP unreachable** (reject only works for TCP/UDP; other protocols fall back to block). 🔴 **FortiOS `deny` is always a silent drop — there is no RST/ICMP-unreachable action**, so `reject` cannot be reproduced; carry it as a comment/flag, never silently treat it as identical to block.

**🔴🔴 Floating rules (`<floating>yes</floating>`) — the subtle one.** Floating rules are an advanced rule type that act across **multiple interfaces** and in directions plain interface rules cannot:
- **`<direction>`** = `in` / `out` / `any`. **Outbound matching is unique to floating rules** (interface rules are inbound-only). An outbound floating rule on WAN sees the **post-NAT source IP**, not the original private source.
- **`<quick>`** — **the landmine.** Interface/group rules are always first-match-wins ("quick"). On floating rules `quick` is **optional**: **with `quick` → first-match-wins**; **without `quick` → LAST-match-wins** (the rule applies only if no later rule matches). FortiOS policies are a single ordered **first-match** list — **non-quick (last-match) floating rules have NO FortiOS analog** and must be re-modeled/flagged, not flattened into the first-match order (doing so silently changes which rule wins).
- Match-order overall: **floating → interface-group → per-interface** rules, then the implicit default-deny (§3).

**Source/destination negation `<not/>` 🔴.** The "Invert match" checkbox serializes as `<not/>` under `<source>`/`<destination>` — matches everything **except** the named address. → FortiOS `set srcaddr-negate enable` / `set dstaddr-negate enable` (clean 1:1). 🔴 dropping the negation **inverts the rule's meaning** (a deny-all-except becomes deny-only-that, or an allow broadens).

**Per-rule `<gateway>` (policy routing) 🔴.** Selecting a gateway or gateway-group on a rule enforces **policy-based routing** — matching traffic is forced out that gateway, **overriding the routing table** (the multi-WAN mechanism). FortiOS has **no per-policy gateway field**: this must become a separate **`config router policy`** (policy route: match src/dst/proto → `set gateway`/`set output-device`) or, when the gateway is a gateway-group, an **SD-WAN rule** (§7). 🔴 dropping it silently sends the traffic out the default WAN — wrong egress, possibly bypassing the intended link/policy.

**Other per-rule fields (must-carry).**
- **`<sched>`** (schedule) — rule active only inside the named time window; outside it the rule is simply absent (action not reversed). → FortiOS `set schedule <name>` (`firewall schedule recurring`/`onetime`, §8). 🔴 drop = rule runs **24/7**.
- **`<disabled/>`** — rule present but not enforced. → `set status disable`. 🔴 drop = silently **activates** a disabled rule.
- **`<log/>`** — log on match. → `set logtraffic all`. 🔴 drop = SIEM/audit blind.
- **`<statetype>`** — `keep state` (default) / `sloppy` (relaxed, asymmetric routing) / `synproxy` (PF SYN-proxy, SYN-flood protection) / `none` (no state). FortiOS is stateful by default; **sloppy ≈ `set asymroute`/asymmetric handling, synproxy ≈ DoS-policy `tcp_syn_flood`, none has no equivalent** — flag non-default state types, don't silently normalize to keep-state.
- **`<tcpflags>`** — "flags that must be set / out of" match. **No FortiOS per-policy TCP-flag match** — flag non-convertible.
- **`<icmptype>`** — ICMP subtype(s) to match (protocol=icmp). → FortiOS custom service `protocol ICMP` + `icmptype`/`icmpcode`.
- **`<tracker>`** — stable unique rule ID across ruleset/logs/tooling. Best used as fwforge's **provenance/source-line key** (FortiOS policy IDs are independent).
- **`<ipprotocol>`** — `inet` (v4) / `inet6` (v6) / `inet46` (dual). `inet46` needs **two** FortiOS policies (one per family) — emitting only one silently drops the other family.

**FortiOS mapping.**

| pfSense rule field | FortiOS (`config firewall policy`) | Notes / 🔴 risk |
|---|---|---|
| `<interface>` (inbound) | `srcintf` (route-based `dstintf` inference) | per-interface inbound, like ASA |
| `<floating> + <direction>out` | `dstintf` policy / re-model | 🔴 outbound + post-NAT source has no clean analog |
| `<floating>` without `<quick>` | **none** (last-match) | 🔴🔴 last-match-wins not expressible in first-match FortiOS — re-model/flag |
| `pass` / `block` / `reject` | `accept` / `deny` / `deny`(+flag) | 🔴 `reject` loses RST/ICMP-unreachable |
| `<not/>` | `srcaddr-negate` / `dstaddr-negate` | 🔴 drop inverts rule meaning |
| `<gateway>` | `router policy` / SD-WAN rule (separate object) | 🔴 drop → wrong egress / bypass |
| `<sched>` | `set schedule` | 🔴 drop = 24/7 |
| `<disabled/>` | `set status disable` | 🔴 drop = re-activates |
| `<log/>` | `set logtraffic all` | 🔴 drop = SIEM blind |
| `<statetype>` non-keep | asymroute / DoS / none(no eq) | flag, don't normalize |
| `<tcpflags>` | none | flag non-convertible |
| `<icmptype>` | custom ICMP service | carry type/code |
| `inet46` | two policies (v4 + v6) | 🔴 one-family-only drops the other |
| source-port restriction | service object (src side) | 🔴 if not carried, source-port narrowing is lost |

🔴 **Silent-loss flags.** (1) **Non-quick floating rules → last-match semantics lost** (wrong winner). (2) **`<not/>` dropped → rule meaning inverted.** (3) **`<gateway>` dropped → policy routing lost, wrong egress.** (4) **`reject` flattened to silent deny.** (5) **schedule/disabled/log dropped** → 24/7 / re-activated / blind. (6) **`inet46` emitted as v4-only** → IPv6 policy silently missing.

**fwforge status: ✅/⚠️ mostly handled, with known gaps.** `parse_rules` (pfsense.py:508) handles pass/block/reject (with a `reject`→deny comment, pfsense.py:547-549), `<interface>`→`src_zones`, `<not/>`→`src_negate`/`dst_negate` (pfsense.py:528-531, 563), `<log/>`→`log`, `<disabled/>`→`disabled` (pfsense.py:562), and ICMP/protocol/port → services (pfsense.py:467). **Floating rules are detected and *flagged* but flattened** — converted with their srcintf and a warning that "match-order semantics differ, review placement" (pfsense.py:519-527); the `<direction>` and `<quick>` fields are **not modeled** (last-match floating rules silently become first-match — flagged but not faithfully reproduced). **Per-rule `<gateway>` is flagged but NOT converted** — emits a `warn` + a policy comment, no router-policy/SD-WAN rule (pfsense.py:550-556) → policy routing lost. **`<sched>` (schedule) is NOT consumed at all** — the rule is emitted with no `schedule`, so a time-restricted rule runs 24/7 (a real silent-broadening; schedules also flagged only via `report_unconverted`). **`<statetype>`/`<tcpflags>` are not handled.** `inet46` is emitted as IPv4 with a warning to add the v6 policy manually (pfsense.py:514-517). Source-port restriction is explicitly flagged as not carried (pfsense.py:537-541).

**Sources:** [pfSense firewall rule config (actions, invert, gateway, schedule, statetype, tcpflags, tracker)](https://docs.netgate.com/pfsense/en/latest/firewall/configure.html) · [Firewall fundamentals (pass/block state)](https://docs.netgate.com/pfsense/en/latest/firewall/fundamentals.html) · [Best practices (block-on-WAN, reject-internal)](https://docs.netgate.com/pfsense/en/latest/firewall/best-practices.html) · [Floating rules (direction, quick, last-match, post-NAT)](https://docs.netgate.com/pfsense/en/latest/firewall/floating-rules.html) · [Rule processing order](https://docs.netgate.com/pfsense/en/latest/firewall/rule-methodology.html) · [Policy routing (multi-WAN)](https://docs.netgate.com/pfsense/en/latest/multiwan/policy-route.html) · [FortiOS firewall policy](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/656084/firewall-policy) · [FortiOS firewall policy CLI (negate)](https://docs.fortinet.com/document/fortigate/7.2.3/cli-reference/323620/config-firewall-policy) · [FortiOS policy routes](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/144044/policy-routes) · [FortiOS schedule recurring](https://docs.fortinet.com/document/fortigate/7.4.3/cli-reference/267620/config-firewall-schedule-recurring)

---

## 3. Implicit / automatic rules 🔴 — live policy that appears NOWHERE in `<filter>`

**What it is.** pfSense **auto-adds hidden rules** that are not user `<rule>` entries but are absolutely live policy. A converter that walks only `<filter>` misses every one of them — and because the polarity flips on FortiOS (default-deny everywhere), some omissions cause **lockout**, others cause **silent breakage**, and skipping block-private/bogon **broadens exposure**.

| pfSense implicit rule | Where it comes from | FortiOS handling | 🔴 risk if dropped |
|---|---|---|---|
| **Default deny** (silent block-all at end; pfSense logs it) | implicit; posture = deny-WAN / allow-LAN | FortiOS built-in **Implicit Deny** at list end — clean 1:1, no emit | none (FortiOS already default-denies). Minor delta: FortiOS implicit-deny doesn't log by default |
| **Anti-lockout rule** | auto, overrides user rules: permits LAN-subnet → firewall admin (TCP 443 GUI, 80 redirect, 22 SSH) on the LAN IP; toggle `<webgui><noantilockout/>` | **NOT a firewall policy** → interface `set allowaccess https http ssh ping` (+ admin `trusthost` / `local-in-policy`) | 🔴 drop → **admin lockout** on the LAN interface |
| **Default allow LAN → any** (v4 + v6) | shipped on fresh install; these ARE editable `<rule>` entries (default-authored, so present in `<filter>`) | becomes an explicit accept policy | 🔴 if normalized away → **all LAN traffic denied** (FortiOS is default-deny — the LAN allow MUST become an explicit policy) |
| **Block private networks** (`<blockpriv>` on WAN) | per-interface; hidden RFC1918 block at top of WAN ruleset | **no auto-equivalent** → explicit RFC1918 address-group + deny policy on WAN | 🔴 drop → **spoofed/private inbound exposure broadens** |
| **Block bogon networks** (`<blockbogons>` on WAN) | per-interface; hidden bogon/reserved block (auto-updated v4+v6) | **no auto-equivalent** → explicit bogon address-group + deny policy on WAN | 🔴 drop → bogon exposure broadens |
| **Implicit IPsec/OpenVPN pass rules** | auto-added: **UDP 500 (IKE), UDP 4500 (NAT-T), ESP** for tunnel establishment; toggle `<system><disablevpnrules/>`. In-tunnel traffic filtered separately on the `enc0` (IPsec) / OpenVPN interface tabs | FortiOS does **not** auto-add: emit interface `allowaccess`/`local-in` for IKE/NAT-T **and** explicit transit policies for in-tunnel traffic | 🔴 drop → **VPN silently won't establish or won't pass traffic** |

🔴 **Silent-loss flag (polarity-flip trap).** Because pfSense silence on the WAN side means *blocked* and FortiOS silence means *blocked everywhere*, the dangerous cases are: **(a) anti-lockout dropped → admin lockout**, **(b) the LAN-default-allow normalized away → mass LAN denial**, **(c) block-private/bogon dropped → exposure broadens** (the WAN was deny-by-default-plus-anti-spoof; the FortiGate has no anti-spoof unless you synthesize it), **(d) VPN pass rules dropped → tunnels silently dead.** The converter MUST synthesize each implicit rule explicitly (allowaccess + local-in for anti-lockout, RFC1918/bogon deny policies on WAN, explicit IKE/ESP local-in + in-tunnel transit policies) and report every synthesis — never assume "FortiOS default-deny covers it."

**fwforge status: ⚠️ partial.** The **default-deny** is covered by FortiOS's built-in implicit deny (nothing to emit — correct). The **Default-allow-LAN-to-any** rules are real `<rule>` entries so they ARE converted by `parse_rules` (good — LAN traffic stays allowed). **GAPs:** the **anti-lockout rule** is not synthesized (no `allowaccess`/`trusthost`/`local-in` derived — relies on the converter operator to set mgmt access; `<webgui>` lands in `report_unconverted` as a coverage `info`). **`<blockpriv>`/`<blockbogons>` are NOT honored** — no RFC1918/bogon deny policy is emitted, so the WAN's anti-spoof posture is silently lost. The **implicit IPsec/OpenVPN pass rules** are not synthesized (IPsec tunnels are built by `parse_ipsec`, but the IKE/NAT-T/ESP local-in access and in-tunnel transit policies are not auto-emitted). These are audit items — currently the box's self-protection and WAN anti-spoof depend on manual post-conversion work.

**Sources:** [Rule processing & default deny / hidden rules](https://docs.netgate.com/pfsense/en/latest/firewall/rule-methodology.html) · [Default allow LAN (setup wizard)](https://docs.netgate.com/pfsense/en/latest/config/setup-wizard.html) · [Rule list intro (default rules)](https://docs.netgate.com/pfsense/en/latest/firewall/rule-list-intro.html) · [Anti-lockout toggle (Advanced > Admin Access)](https://docs.netgate.com/pfsense/en/latest/config/advanced-admin.html) · [Block RFC1918 on WAN](https://docs.netgate.com/pfsense/en/latest/firewall/preventing-rfc1918-traffic-from-exiting-a-wan-interface.html) · [IPsec auto firewall rules](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/firewall-rules.html) · [VPN firewall rules + disablevpnrules](https://docs.netgate.com/pfsense/en/latest/config/advanced-firewall-nat.html) · [FortiOS local-in-policy (no implicit deny)](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/363127/local-in-policy)

---

## 4. NAT (`<nat>`) 🔴 (outbound mode + 1:1 + reflection are the subtle ones)

**Port forwards (`<rule>` under `<nat>`).** Inbound **destination NAT**: `<interface>` (ingress, usually WAN), `<protocol>`, `<destination>` (external IP / WAN-address / VIP, with `<port>`), `<target>` (internal redirect IP), `<local-port>` (allows external→different internal port). 🔴 A port forward **alone does not pass traffic** — pfSense auto-adds (or you add) an associated filter pass rule; without it the packets are dropped. → FortiOS `config firewall vip` `type static-nat` + `set portforward enable` (`extip`/`extport`→`mappedip`/`mappedport`, `set protocol`); the VIP must be the **`dstaddr` of a firewall policy** (the FortiOS analog of the associated filter rule) or it does nothing.

**Outbound NAT modes (`<outbound><mode>`) 🔴 — the subtle one.**
- **`automatic`** (default) — pfSense auto-generates SNAT for all internal→external traffic; **no explicit rules in config**. → FortiOS per-policy `set nat enable` (default source NAT to egress IP).
- **`hybrid`** — manual rules **plus** auto rules for whatever the manual rules don't match. → **no exact FortiOS toggle**; emulate with ordered `central-snat-map` + a catch-all.
- **`manual`** — **only** the explicit `<rule>` entries; no auto SNAT. → **Central SNAT** (`config system settings set central-nat enable` + ordered `config firewall central-snat-map`, with `nat-ippool`).
- **`disabled`** — **no** outbound SNAT at all. → policy `set nat disable`.

🔴 **Why this matters:** in `automatic`/`hybrid` modes the SNAT rules are **not present in the XML** — a converter that only translates explicit `<outbound><rule>` entries silently drops all the implicit SNAT (and the FortiGate then doesn't NAT outbound at all, breaking internet access), while in `manual` mode the explicit rules (with `<sourceport>`/`<natport>`/pool) **must** be carried or SNAT is lost.

**1:1 NAT (`<onetoone>`) 🔴.** Bidirectional single-IP map (external ↔ internal, **all ports, ports unchanged** — the key difference from a port forward). Optional `<destination>` restricts which destinations the mapping applies to. → FortiOS splits into **two** objects: inbound = a `type static-nat` VIP **without** portforward (full-IP); outbound = `config firewall ippool` `type one-to-one` (PAT disabled, ports static). 🔴 **A `<destination>`-restricted 1:1 maps to ALL destinations on the FortiOS VIP** — the converted VIP is **broader** than the source; the restriction must be restored as a policy `dstaddr` match (the no-broadening class).

**NAT reflection / hairpin (`<natreflection>`) 🔴.** Lets internal clients reach a port-forward/1:1 by its **external WAN IP**. Modes: **pure NAT** (PF rules only, scalable), **NAT + proxy** (helper proxy; TCP-only, no ranges > 500, server loses real client IP), **disabled**. → FortiOS has **no reflection toggle**; the equivalent is **hairpin NAT** built from explicit objects — VIP + a DNAT policy + an SNAT policy with **`set nat-source-vip enable`** on the VIP (so the internal client's return traffic is SNAT'd to the VIP, avoiding asymmetry). Split DNS is the cleaner alternative on both platforms. 🔴 silently dropping reflection → internal clients can't reach published services by external IP.

**FortiOS mapping.**

| pfSense NAT | FortiOS | 🔴 risk |
|---|---|---|
| port forward `<rule>` | `firewall vip` portforward + dstaddr=VIP in a policy | 🔴 VIP without a policy → no traffic (needs the associated pass rule) |
| outbound `automatic`/`hybrid` (implicit SNAT) | per-policy `nat enable` on egress policies | 🔴 implicit rules not in XML → must synthesize or outbound SNAT is lost |
| outbound `manual` (`<rule>` + sourceport/natport/pool) | `central-snat-map` + `ippool` | 🔴 drop explicit rules → SNAT lost |
| outbound `disabled` | policy `nat disable` | carry intent |
| `<onetoone>` | VIP (no portforward) **+** `ippool one-to-one` | 🔴 dest-restricted 1:1 → VIP broadens to all dest |
| NAT reflection | hairpin: VIP + DNAT + SNAT (`nat-source-vip`) | 🔴 no toggle — must synthesize |

🔴 **Silent-loss flags.** (1) **Implicit auto/hybrid SNAT not in XML → outbound NAT silently absent.** (2) **dest-restricted 1:1 → VIP broadens to all destinations.** (3) **NAT reflection has no toggle → hairpin must be synthesized.** (4) **manual outbound rules dropped → SNAT lost.** (5) **port-forward VIP without an accompanying policy → blackhole.**

**fwforge status: ⚠️ partial.** `parse_nat` (pfsense.py:570) handles **automatic/hybrid** by emitting `dynamic-interface` NAT on every WAN/egress interface (pfsense.py:576-587) — matching automatic SNAT (good), with a warning if no egress interface is found. **Manual outbound rules are flagged but NOT converted** (pfsense.py:594-599 — "recreate as IP pools / central SNAT"). **Port forwards** are converted to VIPs (pfsense.py:601-654), including alias-port splitting into one VIP per range (flagged) and tcp/udp expansion; disabled forwards skipped with an info note; unresolved external IP/target flagged. **1:1 NAT** is converted to a VIP (pfsense.py:656-686) — and **correctly flags the dest-restricted-1:1 broadening** ("the FortiOS VIP applies to ALL destinations… the converted VIP is broader", pfsense.py:668-676) and subnet-style/unresolved mappings. **GAPs:** **NAT reflection is NOT handled** (no hairpin synthesis; `<natreflection>`/reflection settings fall to coverage); manual outbound NAT not converted; the associated-pass-rule requirement for port-forwards is not auto-synthesized (relies on the matching filter rule existing in `<filter>`).

**Sources:** [Port forwards (associated filter rule)](https://docs.netgate.com/pfsense/en/latest/nat/port-forwards.html) · [Outbound NAT modes](https://docs.netgate.com/pfsense/en/latest/nat/outbound.html) · [1:1 NAT](https://docs.netgate.com/pfsense/en/latest/nat/1-1.html) · [NAT reflection](https://docs.netgate.com/pfsense/en/latest/nat/reflection.html) · [NAT vs filter process order](https://docs.netgate.com/pfsense/en/latest/nat/process-order.html) · [FortiOS firewall vip CLI](https://docs.fortinet.com/document/fortigate/7.2.0/cli-reference/303620/config-firewall-vip) · [FortiOS central SNAT](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/421028/central-snat) · [FortiOS ippool CLI](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/267620/config-firewall-ippool) · [FortiOS hairpin NAT](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/736522/hairpin-nat)

---

## 5. Interfaces / VLANs / Virtual IPs 🔴 (dropping virtual IPs breaks NAT and HA)

**Interfaces & VLANs.** `<interfaces>` holds logical roles **wan / lan / optN**; each maps to a hardware port or VLAN device via `<if>`. RULES reference the **logical name**, not the NIC. **`<vlans>`** are separate 802.1Q entries (`<vlanif>` like `igc1.10`, `<tag>` VID, `<if>` parent) that interfaces then bind to. → FortiOS interface + `config system interface` VLAN sub-interface (`set vlanid` + `set interface <parent>`). FortiOS **interface names are limited to 15 chars** — clamp/rename reference-aware (`transforms/names.py`).

**Virtual IPs (`<virtualip>`) — four types 🔴 (each maps to a *different* FortiOS construct).**

| pfSense VIP type | What it is | FortiOS target | 🔴 risk |
|---|---|---|---|
| **IP Alias** | secondary IP on an interface, answers ARP, no unique MAC | `config system interface` → `config secondaryip` | 🔴 drop → secondary subnet / extra NAT IP gone |
| **CARP** | shared VIP + unique (VHID-derived) MAC, primarily for **HA/failover** | `config system interface` → `config vrrp` (gateway redundancy) and/or `config system ha` | 🔴 drop → HA virtual address / VRRP gone |
| **Proxy ARP** | firewall answers ARP for an address/range not bound to any interface; common **NAT target** | `config firewall vip` (DNAT) / `config firewall ippool` (SNAT) | 🔴🔴 drop → the NAT target IP doesn't exist → all NAT using it blackholes |
| **Other** | like Proxy ARP but does **not** answer ARP (for upstream-routed blocks) | same VIP/ippool target (collapses with Proxy ARP) | 🔴 drop → routed NAT block lost |

> FortiOS behavior to carry into the report: once a VIP or ippool is configured, the FortiGate treats that address as locally owned and will not route it — the analog of pfSense answering ARP for the VIP. So a Proxy-ARP/Other VIP that a port-forward/1:1/outbound rule references **must** exist as a FortiOS VIP/ippool or the NAT silently has no usable external address.

**CARP & HA (`<hasync>` / `<carp>`).** pfSense HA = **three separate components**: **CARP** (IP/address redundancy), **XMLRPC** (config sync), **pfsync** (state-table sync). → FortiOS **FGCP HA** (`config system ha`) is one integrated protocol (heartbeat TCP/UDP 703), not three features. **Converter: flag HA/CARP as device-pairing infrastructure — do NOT translate to any firewall policy/object**; but a **CARP VIP that NAT references** still has to become a real FortiOS VIP/secondary-IP.

🔴 **Silent-loss flag.** **Dropping Proxy-ARP/Other virtual IPs breaks every NAT rule that targets them** (the external IP simply doesn't exist on the FortiGate → blackhole). Dropping **CARP** loses the HA virtual address; dropping **IP Alias** loses secondary-subnet addressing. The converter MUST emit each `<virtualip>` to its type-correct FortiOS construct and report any it can't place — never silently omit a VIP that a NAT/HA rule depends on.

**fwforge status: ⚠️ partial — virtual IPs are a GAP.** `parse_interfaces` (pfsense.py:234) handles interface roles, IP/subnet, descriptions, enabled state, and **VLANs** (parent + tag from `<vlans>`, pfsense.py:240-243, 267-270) — solid. Egress/WAN detection is via `<gateway>` (pfsense.py:271-272). **`<virtualip>` is NOT parsed at all** — no IP-alias→secondaryip, no CARP→VRRP/HA, no Proxy-ARP/Other→VIP/ippool. It lands in `report_unconverted` as a coverage `info` only. So a port-forward/1:1 that targets a Proxy-ARP VIP, and any HA/CARP address, are silently un-emitted — exactly the "NAT target doesn't exist" trap. **CARP/HA (`<hasync>`)** likewise only hits coverage. Audit item (note: a CARP VIP referenced by NAT is the high-severity case).

**Sources:** [Interface configuration](https://docs.netgate.com/pfsense/en/latest/config/interface-configuration.html) · [VLAN configuration](https://docs.netgate.com/pfsense/en/latest/vlan/configuration.html) · [Virtual IP addresses (4 types)](https://docs.netgate.com/pfsense/en/latest/firewall/virtual-ip-addresses.html) · [Virtual IP comparison](https://docs.netgate.com/pfsense/en/latest/firewall/virtual-ip-address-comparison.html) · [High availability (CARP + XMLRPC + pfsync)](https://docs.netgate.com/pfsense/en/latest/highavailability/index.html) · [FortiOS system interface CLI (secondaryip/vrrp)](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/8620/config-system-interface) · [FortiOS VRRP](https://docs.fortinet.com/document/fortigate/7.6.1/administration-guide/850547/vrrp) · [FortiOS static virtual IPs (locally-owned)](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/510402/static-virtual-ips) · [FortiOS FGCP HA](https://docs.fortinet.com/document/fortigate/7.4.1/administration-guide/62403/introduction-to-the-fgcp-cluster)

---

## 6. Management-plane / box access 🔴 (same "expose-to-all vs lockout" trap as ASA)

**What it is.** Access to the firewall itself: the **webGUI** (`<system><webgui>`: `<protocol>` https/http, `<port>`), **SSH** (`<system><enablesshd>` + `<ssh><port>`), the **anti-lockout rule** (§3), and admin-source restriction. pfSense's anti-lockout permits the **LAN subnet → admin protocols on the LAN IP**; everything else to-the-box is governed by filter rules on each interface (there's no separate per-service source allow-list like ASA's `ssh <src> <iface>` — to restrict WAN admin you write explicit interface rules, or disable the service).

**FortiOS re-model — two separate axes** (identical structure to the ASA mapping):

| pfSense item | FortiOS mechanism | Notes |
|---|---|---|
| webGUI https/http on a port | per-interface `set allowaccess https http` (+ `set admin-sport`/admin port) | the "which protocols" axis — applies to **all** source IPs on that interface |
| `<enablesshd>` (SSH) | `set allowaccess ssh` (+ admin-ssh-port) | service reachability |
| ping/ICMP to box | `set allowaccess ping` | |
| anti-lockout (LAN→admin) | `allowaccess` on the LAN interface (+ optional `local-in-policy`) | 🔴 **no implicit deny** in local-in — to restrict admin sources you must add an explicit trailing deny |
| admin-source restriction | `config system admin` → `set trusthost1..10` (+ ip6-trusthost) | per-admin login source subnets |

🔴 **Silent-loss flag (two opposite failures, mgmt-plane = high severity).** (1) **Emit broad `allowaccess` (or none) without honoring which interfaces pfSense exposed admin on** → either mgmt **exposed to every source IP** (FortiOS `allowaccess` carries no source filter, and `local-in-policy` has **no implicit deny**, so you must synthesize a trailing deny), or **admin lockout** if nothing is emitted on the LAN interface. The converter MUST derive `allowaccess` (services) per interface from the webGUI/SSH settings + the anti-lockout intent, and use `local-in-policy` / admin `trusthost` for source restriction, reporting anything it can't reproduce — exactly the ASA trap.

**fwforge status: ❌ GAP.** `<system><webgui>`, `<enablesshd>`, `<ssh>` and the anti-lockout intent are **not parsed** into any `allowaccess`/`local-in-policy`/`trusthost` — `<system>` is partially consumed (hostname/dns/ntp at pfsense.py:216-221) but the management-access sub-elements are not, so they surface only via `report_unconverted` coverage `info`. The FortiGate ships with **no derived mgmt restriction** — the "mgmt exposed to all / or lockout" trap. Audit item (pairs with §3 anti-lockout synthesis).

**Sources:** [Advanced Admin Access (webGUI, anti-lockout, SSH)](https://docs.netgate.com/pfsense/en/latest/config/advanced-admin.html) · [Secure Shell (SSH) access](https://docs.netgate.com/pfsense/en/latest/recipes/ssh-access.html) · [FortiOS interface settings / allowaccess](https://docs.fortinet.com/document/fortigate/7.6.2/administration-guide/574723/interface-settings) · [FortiOS local-in-policy (no implicit deny)](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/363127/local-in-policy) · [FortiOS config system admin (trusthost)](https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/390485493/config-system-admin)

---

## 7. VPN 🔴 (IPsec maps cleanly; OpenVPN entirely dropped = remote access lost)

**IPsec (`<ipsec>` phase1/phase2).** Phase 1 (`<phase1>`: IKEv1/v2/auto, `<remote-gateway>`, PSK or cert, encryption/hash/DH) + one-or-more Phase 2 (`<phase2>`: child SA / traffic selectors `<localid>`/`<remoteid>`, multiple subnets per tunnel, PFS group). → FortiOS **route-based** `config vpn ipsec phase1-interface` + `phase2-interface` (selectors → phase2 `src-subnet`/`dst-subnet` + a route to the remote subnet + transit policies). Maps naturally (this is what fwforge handles).

**🔴 OpenVPN (`<openvpn>` server/client) — the big one.** Remote-access (SSL/TLS server, the common pfSense RA VPN) + site-to-site (TLS or shared-key). **FortiOS has NO OpenVPN** — it cannot be converted 1:1 and must be re-modeled, never silently dropped.
- 🔴 **Do NOT target FortiOS SSL-VPN** as the destination — SSL-VPN **tunnel mode is being removed** (7.6.0–7.6.2 removed on ≤2 GB-RAM models; **7.6.3 removes tunnel mode on ALL models**; web mode renamed "Agentless VPN" and unsupported on several series; 7.4.x already drops it on G-series). Migrating OpenVPN onto SSL-VPN walks straight into a deprecated feature.
- **Migration target:** remote-access → **IPsec dial-up** (FortiClient; can run over TCP 443); site-to-site → route-based IPsec; web-portal use cases → **ZTNA**. Flag, don't auto-convert 1:1.

**L2TP (`<l2tp>`)** — L2TP server (UDP 1701), usually L2TP/IPsec → FortiOS `config vpn l2tp` (L2TP-over-IPsec). **WireGuard** (package) → no native FortiOS equivalent; re-model to IPsec or flag non-convertible.

🔴 **Silent-loss flags.** (1) **OpenVPN dropped → all remote access (and any OpenVPN S2S) silently lost.** (2) **OpenVPN "converted" onto SSL-VPN → lands on a deprecated/removed feature.** (3) **IPsec PSK masked/absent → placeholder, never a real key.** (4) **Cert-auth phase1 → can't carry the cert from config.** (5) **L2TP/WireGuard not converted.**

**fwforge status: ⚠️ partial (IPsec only).** `parse_ipsec` (pfsense.py:730) assembles **site-to-site IPsec** into route-based phase1/phase2 via `_vpn_common.add_route_based_tunnel`: IKEv1/v2 detection, encryption/hash/DH mapping (`_pf_enc`/`vpn.HASH`), phase2 selectors with dotted-mask→prefix conversion (`_pf_selector`, pfsense.py:697-728), PFS, and route synthesis. Solid edge-case handling: **disabled phase1/phase2 skipped** (pfsense.py:739-744, 753-757); **cert-auth or missing PSK → `CHANGEME-PSK` placeholder + error finding** (pfsense.py:773-783); **incomplete proposal → defaulted to aes256-sha256 with a warning** (pfsense.py:837-840); phase1-with-no-phase2 skipped cleanly. **OpenVPN is flagged but NOT converted** — `flag_vpn_and_misc` (pfsense.py:850-861) emits a `warn` ("FortiOS has no OpenVPN; migrate remote access to IKEv2 dial-up IPsec (FortiClient)") and correctly steers **away** from SSL-VPN (the module docstring notes "SSL-VPN is gone in 7.6+"). **L2TP and WireGuard** are not specifically parsed (coverage `info`). So **OpenVPN/L2TP/WireGuard are current gaps** — surfaced loudly (good) but not converted.

**Sources:** [pfSense IPsec phase 1](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/configure-p1.html) · [IPsec phase 2](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/configure-p2.html) · [OpenVPN](https://docs.netgate.com/pfsense/en/latest/vpn/openvpn/index.html) · [L2TP](https://docs.netgate.com/pfsense/en/latest/vpn/l2tp/configuration.html) · [WireGuard](https://docs.netgate.com/pfsense/en/latest/vpn/wireguard/index.html) · [FortiOS phase1 config](https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/790613/phase-1-configuration) · [FortiOS SSL-VPN tunnel mode removed 7.6.3](https://docs.fortinet.com/document/fortigate/7.6.3/fortios-release-notes/173430/ssl-vpn-tunnel-mode-no-longer-supported) · [FortiOS FortiClient dialup](https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/785501/forticlient-as-dialup-client) · [FortiOS L2TP-over-IPsec](https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/386346/l2tp-over-ipsec)

---

## 8. Routing 🔴 (gateway-group multi-WAN → SD-WAN; FRR dynamic routing is a GAP) + Schedules + Shaping

### 8.1 Static routes + gateways
`<staticroutes><route>` (destination network + gateway + descr + disabled) → `config router static`. **`<gateways><gateway_item>`** is a two-part object: a next-hop (interface + gateway IP) **plus an embedded health-check** (monitor IP, latency 200/500 ms, loss 10/20 %, probe interval). The health-check half has **no home in a FortiOS static route** — it only fits **SD-WAN `config health-check`** — so flag it as partial when a gateway carries monitoring. Dynamic (DHCP/PPPoE) gateways store no usable IP → the default route can't be emitted (the FortiGate learns it from the WAN).

### 8.2 Gateway groups (multi-WAN) 🔴 → SD-WAN
**`<gateways><gateway_group>`** = multi-WAN: **Tiers 1–5** (lower tier = higher priority; **different tiers = failover**, **same tier = round-robin load balance**) + **Trigger Level** (member down / packet loss / high latency / either). Multi-WAN is driven by **per-rule policy routing** (a firewall rule's `<gateway>` points at the group — §2). → FortiOS **SD-WAN** (`config system sdwan`: members = interface/zone/gateway/cost/weight/priority; tiers/failover → member `priority`; same-tier LB → load-balance strategy; Trigger Level → `config health-check` SLA; the per-rule gateway → an **SD-WAN rule**). 🔴 a gateway-group + per-rule-gateway combination is a **multi-construct re-model** (SD-WAN zone + members + health-check + rule) — flattening loses the failover/LB behavior.

### 8.3 Dynamic routing (FRR / OpenBGPD / Quagga) 🔴 GAP
Current package = **FRR** → **BGP, OSPFv2, OSPFv3 only (no RIP)**; OpenBGPD/Quagga deprecated in 2.5.0/21.02. → FortiOS `config router ospf` / `config router bgp`. 🔴 a dynamic-routing process that injects the default or transit routes **blackholes everything that depended on it** if dropped — report, re-model the process/area/neighbor config; never silently remap protocols.

### 8.4 Schedules (`<schedules><schedule>`)
Multiple time ranges, days-of-week and/or specific dates, 24h start/stop (a single range cannot span midnight). Semantic: **outside the window the rule is simply absent** — its action is *not* reversed (matches FortiOS schedule attachment exactly). → FortiOS `config firewall schedule recurring` (weekly days + start/end) / `onetime` (specific datetime). 🔴 referenced by `<rule><sched>` (§2) — dropping the schedule object **or** failing to attach it makes the rule run 24/7.

### 8.5 Traffic shaping (ALTQ + Limiters) — lossy
**ALTQ shaper** (`<shaper>`): scheduler types PRIQ / CBQ / HFSC / FAIRQ / CoDel; queues with bandwidth/priority/borrow. **Limiters** (`<dnshaper>`, dummynet): per-IP/per-network rate-limit pipes (bandwidth + delay) + queues. Both are assigned in firewall/floating rules. → FortiOS **shared traffic shaper** (`config firewall shaper traffic-shaper`, guaranteed/maximum bandwidth + priority) + **per-IP shaper** (`config firewall shaper per-ip-shaper`) bound via **`config firewall shaping-policy`** (with `traffic-shaper-reverse`). 🟠 lossy: HFSC real-time guarantees → `guaranteed-bandwidth`; limiter max-only → per-IP `max-bandwidth`; scheduler nuances don't survive — flag.

🔴 **Silent-loss flag.** A **missing route silently breaks reachability** (and a route to a tunnel interface is what makes a route-based VPN pass). **Gateway-group multi-WAN flattened → failover/LB lost.** **FRR dynamic routing dropped → injected routes vanish.** **Schedule unattached → rule 24/7.**

**fwforge status: ⚠️ static only — gateway-groups, dynamic routing, schedules, and shaping are GAPs.** `parse_gateways_and_routes` (pfsense.py:349) handles `<gateway_item>` next-hops, the **default route** (`defaultgw4`/`defaultgw6`, with dynamic-gateway detection → warn, no route, pfsense.py:362-369) and `<staticroutes><route>` (with gateway-not-found / dynamic-gateway / invalid-network guards). **GAPs:** `<gateway_group>` (multi-WAN) is **NOT parsed** → no SD-WAN emitted (and the per-rule `<gateway>` policy routing is separately un-converted, §2) — multi-WAN failover/LB silently lost; **FRR/OpenBGPD dynamic routing** is not parsed (coverage `info`); **`<schedules>` is NOT parsed** → schedule objects not emitted and `<rule><sched>` not attached (rules run 24/7); **traffic shaping** (`<shaper>`/`<dnshaper>`) not parsed (coverage `info`). The gateway health-check half is dropped (no SD-WAN health-check synthesized).

**Sources:** [Static routes](https://docs.netgate.com/pfsense/en/latest/routing/static.html) · [Gateway configuration (health-check)](https://docs.netgate.com/pfsense/en/latest/routing/gateway-configure.html) · [Gateway groups (tiers/trigger)](https://docs.netgate.com/pfsense/en/latest/routing/gateway-groups.html) · [Policy routing / multi-WAN](https://docs.netgate.com/pfsense/en/latest/multiwan/policy-route.html) · [FRR package (BGP/OSPF, no RIP)](https://docs.netgate.com/pfsense/en/latest/packages/frr/index.html) · [Time-based rules / schedules](https://docs.netgate.com/pfsense/en/latest/firewall/time-based-rules.html) · [ALTQ scheduler types](https://docs.netgate.com/pfsense/en/latest/trafficshaper/altq-scheduler-types.html) · [Limiters](https://docs.netgate.com/pfsense/en/latest/trafficshaper/limiters.html) · [FortiOS SD-WAN CLI](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/256518/configuring-sd-wan-in-the-cli) · [FortiOS router static CLI](https://docs.fortinet.com/document/fortigate/7.4.2/cli-reference/536620/config-router-static) · [FortiOS schedule recurring](https://docs.fortinet.com/document/fortigate/7.4.3/cli-reference/267620/config-firewall-schedule-recurring) · [FortiOS shared traffic shaper](https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/933502/shared-traffic-shaper) · [FortiOS per-IP traffic shaper](https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/885253/per-ip-traffic-shaper)

---

## 9. Aliases / address & service objects (the object layer rules reference)

**What it is.** `<aliases><alias>` are **typed**: `host`/`network` → address objects (multi-entry → group), `port` → port lists (protocol-agnostic — they materialize per-protocol at rule-conversion time), `url`/`urltable`(`_ports`) → externally-fetched feed lists. pfSense **macros**: `<network>lan</network>` = that interface's subnet; `lanip`/`wanip` = the interface address; nested aliases reference other aliases by name. → FortiOS `firewall address`/`addrgrp`, `firewall service custom`, and (for url/urltable) **external-resource** / FQDN. 🔴 **`url`/`urltable` aliases are dynamic feed lists** — converting them as static is a broadening/staleness trap; they should become FortiOS **external resources** (or FQDN objects), not silently inlined.

**fwforge status: ✅ mostly handled.** `parse_aliases` (pfsense.py:275) classifies host/network/port aliases, builds address objects/groups (with a first-pass name set so a bare hostname member isn't mis-split, pfsense.py:280-281), materializes port aliases per-protocol at rule time (`_services`, pfsense.py:467), resolves `lan`/`lanip` macros (`_endpoint`, pfsense.py:410-465), and **flags url/urltable aliases as not convertible** ("recreate as a FortiOS external resource or FQDN objects", pfsense.py:292-296) — correct no-broadening behavior. Bare hostnames in host aliases → FQDN objects. IPv6 interface-network macros are flagged as unresolved (using `all`, pfsense.py:421-428) — a `warn`, not silent.

**Sources:** [Aliases](https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html) · [URL table aliases](https://docs.netgate.com/pfsense/en/latest/firewall/aliases-urltable.html) · [FortiOS threat feeds (external-resource)](https://docs.fortinet.com/document/fortigate/7.0.1/administration-guide/9463/threat-feeds)

---

## 10. AAA / users / certificates (flag; route admins vs VPN/portal users)

**What it is.** `<system><user>` is **one flat list** serving GUI-admin **and** VPN **and** portal users; `<system><group>` (`all`/`admins` undeletable). **`<system><authserver>`** = RADIUS (UDP 1812/1813, PAP/CHAP/MS-CHAP) and LDAP (389/636, base DN, bind, naming attrs). **`<ca>`/`<cert>`** = the certificate manager (CAs + leaf certs for GUI HTTPS, VPN, LDAP, portal). → FortiOS **splits the user list**: users with admin privilege → `config system admin`; VPN/portal users → `config user local`; groups → `config user group`; RADIUS/LDAP → `config user radius`/`config user ldap`; CAs/certs → `config vpn certificate ca`/`local`. FSSO is the identity-aware-policy analog pfSense local users lack. 🟠 **pfSense password hashes can't be carried into FortiOS — users must be reset**; cert private keys may be absent/encrypted → flag for manual import.

🟠 **Loss flag.** Mis-routing an admin user to `user local` (or vice-versa) breaks login; dropping the auth servers breaks VPN/portal/admin authentication. The converter must inspect each user's privilege to route admin-vs-user, and report auth-server + cert objects for manual completion. (Lower blast radius than the security/L7 surfaces — these are auth plumbing, flag-and-report.)

**fwforge status: ❌ GAP (flag-level).** Users/groups, `<authserver>`, and `<ca>`/`<cert>` are **not parsed** — all surface via `report_unconverted` coverage `info` (repeated `<cert>`/`<ca>` are explicitly handled as a list so they don't vanish from coverage, pfsense.py:871-877). No `system admin`/`user local`/`user radius`/`user ldap`/certificate objects are emitted. Recorded, not silently gone; not converted. Audit item (lower priority than §1–§7).

**Sources:** [User management](https://docs.netgate.com/pfsense/en/latest/usermanager/users.html) · [Groups](https://docs.netgate.com/pfsense/en/latest/usermanager/groups.html) · [RADIUS auth server](https://docs.netgate.com/pfsense/en/latest/usermanager/radius.html) · [LDAP auth server](https://docs.netgate.com/pfsense/en/latest/usermanager/ldap.html) · [Certificate Authorities](https://docs.netgate.com/pfsense/en/latest/certificates/ca.html) · [FortiOS config system admin](https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/390485493/config-system-admin) · [FortiOS config user radius](https://docs.fortinet.com/document/fortigate/7.0.0/cli-reference/506620/config-user-radius) · [FortiOS config user ldap](https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/590785459/config-user-ldap) · [FortiOS import a certificate](https://docs.fortinet.com/document/fortigate/7.4.1/administration-guide/907098/import-a-certificate)

---

## Consolidated — pfSense silent-loss checklist

Ranked by blast radius. Drop or mis-map any of these and the FortiGate **silently loses protection or broadens a rule** while the output looks complete.

| # | pfSense construct | Converts to | 🔴 Risk if dropped / mis-mapped | fwforge |
|---|---|---|---|---|
| 1 | 🔴🔴 **Security packages** (Suricata/Snort IPS, pfBlockerNG DNSBL/IP-feeds/GeoIP, Squid/SquidGuard URL filter, HAProxy, Captive Portal) in `<installedpackages>`/`<captiveportal>` | IPS sensor / dnsfilter / external-resource / geography addr / webfilter+explicit-proxy / server-LB VIP / captive portal | **all L7 / IDS-IPS / URL-filter / DNS+IP blocklist / GeoIP / proxy / guest-auth protection silently gone** — lives outside `<filter>` | ❌ GAP (coverage `info` only) |
| 2 | 🔴🔴 **Floating rules** — `direction out` + non-`quick` (last-match) | re-model / flag (no first-match analog) | **wrong rule wins** — last-match semantics silently flattened into first-match | ⚠️ flagged, flattened (direction/quick not modeled) |
| 3 | 🔴 **OpenVPN** (`<openvpn>` server/client) | IPsec dial-up / route-based IPsec / ZTNA (**NOT** deprecated SSL-VPN) | **all remote access / OpenVPN S2S lost**; "converting" onto SSL-VPN hits a removed feature | ⚠️ flagged, NOT converted |
| 4 | 🔴 **Virtual IPs** (Proxy-ARP/Other = NAT targets; CARP = HA; IP-Alias = secondary IP) `<virtualip>` | VIP / ippool / VRRP+HA / secondaryip | **NAT target IP doesn't exist → blackhole**; HA/secondary addressing lost | ❌ GAP (not parsed) |
| 5 | 🔴 **Per-rule `<gateway>`** (policy routing) + **gateway groups** (multi-WAN) | `router policy` / SD-WAN rule + `system sdwan` members/health-check | **policy routing + multi-WAN failover/LB lost** → wrong egress, no failover | ❌ GAP (flagged, not converted) |
| 6 | 🔴 **Implicit/auto rules** — anti-lockout, block-private/bogon, IPsec/OpenVPN pass | allowaccess+trusthost+local-in / RFC1918+bogon deny policy / IKE+ESP local-in + transit | **admin lockout** (anti-lockout) / **WAN anti-spoof exposure broadens** (blockpriv/bogon) / **VPN won't establish** | ⚠️ partial (LAN-allow OK; anti-lockout/blockpriv/VPN-rules not synthesized) |
| 7 | 🔴 **NAT reflection** (hairpin) `<natreflection>` | hairpin: VIP + DNAT + SNAT (`nat-source-vip`) | internal clients can't reach published services by external IP | ❌ GAP (not handled) |
| 8 | 🔴 **Outbound NAT modes** automatic/hybrid (implicit, not in XML) + manual rules | per-policy `nat enable` / `central-snat-map` + `ippool` | implicit SNAT not in XML → **outbound NAT silently absent**; manual rules dropped → SNAT lost | ⚠️ auto/hybrid handled; manual NOT converted |
| 9 | 🔴 **1:1 NAT with `<destination>` restriction** | VIP (no portforward) + `ippool one-to-one`; restore dest via policy `dstaddr` | dest-restricted 1:1 → **VIP broadens to ALL destinations** | ✅ converted + broadening flagged |
| 10 | 🔴 **`<not/>` negation** on src/dst | `srcaddr-negate` / `dstaddr-negate` | drop **inverts the rule's meaning** | ✅ handled |
| 11 | 🔴 **`reject` action** | `deny` (+ flag; no RST/ICMP-unreachable) | reject's active refusal silently becomes a black-hole | ✅ converted + flagged |
| 12 | 🔴 **`<sched>` schedule** on a rule | `firewall schedule` recurring/onetime + `set schedule` | rule runs **24/7** (time window broadened) | ❌ GAP (schedule not parsed/attached) |
| 13 | 🔴 **`<disabled/>` / `<log/>`** on a rule | `set status disable` / `set logtraffic all` | disabled rule **goes live** / SIEM-audit blind | ✅ handled |
| 14 | 🔴 **Mgmt-plane access** (webGUI/SSH + anti-lockout) | per-interface `allowaccess` + `local-in-policy` + admin `trusthost` | mgmt **exposed to all** (no source filter, no implicit deny) or **lockout** | ❌ GAP |
| 15 | 🔴 **`inet46` dual-stack rule** | two policies (v4 + v6) | emitted v4-only → **IPv6 policy silently missing** | ⚠️ v4 emitted, v6 flagged manual |
| 16 | 🔴 **FRR dynamic routing** (BGP/OSPF) | `config router bgp`/`ospf` | injected/default routes vanish → blackhole | ❌ GAP |
| 17 | 🟠 **State type / TCP-flags** (sloppy/synproxy/none; flag match) | asymroute / DoS `tcp_syn_flood` / none (no eq) | non-default state behavior silently normalized | ❌ GAP |
| 18 | 🟠 **Traffic shaping** (ALTQ / limiters) | shaping-policy + traffic/per-IP shapers (lossy) | QoS / rate-limiting lost | ❌ GAP |
| 19 | 🟠 **url/urltable aliases** | external-resource / FQDN (not static) | dynamic feed inlined as static → stale/broadened | ✅ flagged non-convertible |
| 20 | 🟠 **AAA / users / certs / auth servers** | `system admin` / `user local` / `user radius`+`ldap` / cert import | mis-routed admin-vs-user breaks login; auth/cert plumbing lost | ❌ GAP (flag-level) |
| 21 | 🟠 **L2TP / WireGuard** | `vpn l2tp` / IPsec re-model (WG no native eq) | secondary VPN access lost | ❌ GAP |

> **fwforge anchors:** the un-handled surfaces in `fwforge/parsers/pfsense.py` are **security packages** (no `installedpackages`/`captiveportal` parsing), **virtual IPs** (`<virtualip>` unparsed → NAT-target blackhole risk), **floating-rule direction/quick semantics** (flattened), **per-rule gateways + gateway-groups** (policy routing / SD-WAN not emitted), **NAT reflection** (no hairpin synthesis), **manual outbound NAT**, **schedules** (`<sched>` not attached → 24/7), **mgmt-plane/anti-lockout/blockpriv-bogon** synthesis, **FRR dynamic routing**, **traffic shaping**, and **AAA/cert** objects. Each currently lands in `report_unconverted` as an `info`-level coverage finding (recorded, not silently gone at the report level) **or** is flagged-but-not-converted in its section parser — but **none emit FortiOS config**, so the protection is absent in the output. Adding them needs IR support in `model.py` (virtual-IP/secondary-IP + VRRP/HA, SD-WAN members+health-check, router-policy, schedule objects, IPS/webfilter/dnsfilter/threat-feed/geo profile refs, local-in-policy/allowaccess, hairpin SNAT, dynamic-routing objects, users/certs); reference-aware name clamps via `transforms/names.py`+`limits.py` (interface 15, addr/svc 79, policy/UTM 35); emit gating in `emit/fortios.py` (VIP-vs-raw, 1:1-dest-restriction policy match, local-in trailing deny, reject-flag, two-policy `inet46`). Every synthesis / flatten / flag / skip must hit the report — nothing dropped silently, nothing broadened. **Severity note:** packages (#1) understate their blast radius today as `info`-level coverage findings — they should be `warn`/`error`, since they carry the entire IPS / URL-filter / blocklist / GeoIP / portal protection surface.
