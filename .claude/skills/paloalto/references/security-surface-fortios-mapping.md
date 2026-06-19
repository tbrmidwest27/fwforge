# PAN-OS Security Configuration Surface → FortiOS Mapping

The complete PAN-OS (Palo Alto Networks) security config surface and how each construct
maps to FortiOS — the **completeness checklist** for a PAN→FortiGate conversion. Grounded
in the PAN-OS Admin Guide + FortiOS CLI/Admin Guide (key URLs cited per section). App-ID /
service / `application-default` mechanics live in `references/appid-and-services.md` — only
cross-referenced here.

> **Why this exists.** A converter must translate each security-relevant construct or
> **loudly flag it** — never drop it silently, never broaden a rule. The PAN landmines that
> silently remove protection are flagged 🔴. PAN config arrives as `running-config.xml`
> (nested XML) or `set`-format CLI; both normalize to the same tree. Scope layers: **vsys** →
> **shared**; under Panorama: **device-group** (pre/post rulebase, hierarchical) + **template/
> template-stack** + **shared**.

---

## 1. Security policy rules 🔴 (`rulebase/security/rules`)

Ordered, **first-match top-down**. Match: `from`/`to` (zones, required), `source`/`destination`
(addresses), `source-user` (User-ID), `application` (App-ID), `service` (L4), `category` (URL),
`source-hip`/`destination-hip` (endpoint posture). Action: `allow|deny|drop|reset-client|
reset-server|reset-both`, plus `log-start`/`log-end`, `profile-setting`, `schedule`, `disabled`.

| PAN field | FortiOS (`config firewall policy`) | Notes / 🔴 risk |
|---|---|---|
| `from`/`to` | `srcintf`/`dstintf` (zone or interface) | L3 zones 1:1 |
| `source`/`destination` | `srcaddr`/`dstaddr` | `any`→`all`; with DNAT, `dstaddr`=VIP (§3) |
| `application` (App-ID) | `application-list` (App-Control), **not** `service` | 🔴 flattening App-ID to a port loses L7 enforcement (see appid ref) |
| `service` / `application-default` | `service` | 🔴 `application-default`→`ALL` broadens (appid ref) |
| `source-user` | `groups` (FSSO) | re-model; identity scoping lost if dropped |
| `category` (URL-as-match) | webfilter profile | re-model — FortiOS policies don't match URL category inline |
| `source-hip`/`destination-hip` | FortiClient EMS / ZTNA tags | 🔴 **no policy-match equiv** — posture lost |
| action `allow` | `set action accept` | 1:1 |
| action `deny` | `set action deny` | PAN deny is app-default-dependent; FortiOS deny = flat silent drop |
| action `drop` | `set action deny` | 1:1 (silent drop) |
| `reset-client`/`reset-server` | `deny` + `set send-deny-packet enable` | 🔴 **per-side RST has no FortiOS equiv** — directionality lost |
| `reset-both` | `deny` + `set send-deny-packet enable` | closest |
| `log-start`/`log-end` | `set logtraffic all` (+ `set logtraffic-start enable` for start) | dropping log-setting = SIEM visibility lost |
| `profile-setting` group/profiles | `av-profile`/`ips-sensor`/`webfilter-profile`/`file-filter-profile`/`ssl-ssh-profile` | 🔴 dropping = traffic passes with **zero inspection** |
| `negate-source`/`negate-destination` | **`set srcaddr-negate`/`set dstaddr-negate enable`** | 🔴 clean 1:1 — **carry it**; dropping **inverts** the rule (≠ `neq` operators, which disable) |
| `disabled yes` | `set status disable` | 🔴 dropping silently **activates** a disabled rule |
| `schedule` | `set schedule` (`config firewall schedule`) | 🔴 dropping = rule runs 24/7 |
| document order | policy order per srcintf/dstintf context | 🔴 fan-out (rule-type) can reorder → shadowing flips |

**🔴 Rule TYPES — the biggest landmine.** `rule-type` is `universal` (default), `intrazone`, or
`interzone`. FortiOS has **no rule-type** — every policy is a concrete `srcintf→dstintf` pair.
- `universal` rule = matches **both** intra- and inter-zone — NOT a single `from→to` policy.
- `intrazone` → policy with `srcintf == dstintf`.
- `interzone` → distinct `srcintf`/`dstintf` only.
- Implicit defaults: **`intrazone-default = allow`**, `interzone-default = deny`. FortiOS zone
  `intrazone` defaults to **deny** (opposite polarity) → set `config system zone … set intrazone allow`
  to preserve PAN intent. Convert/flag any *overridden* default rule.

Sources: [components-of-a-security-policy-rule](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-policy/components-of-a-security-policy-rule) · [security-policy-actions](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-policy/security-policy-actions) · [FortiOS config firewall policy](https://docs.fortinet.com/document/fortigate/6.4.5/cli-reference/311620/config-firewall-policy) · [FortiOS config system zone](https://docs.fortinet.com/document/fortigate/7.0.11/cli-reference/83620/config-system-zone)

---

## 2. Zones, zone-protection, interface-management profiles 🔴

**Zones** (`network/zone`): types **tap / virtual-wire / layer2 / layer3 / tunnel** (implicit in
which `network` child is populated). Only **layer3** → `config system zone` (`set interface`,
`set intrazone`). tap/VW/L2/tunnel have no zone equivalent (sniffer / virtual-wire-pair /
transparent / IPsec interface) — 🔴 don't flatten to an L3 zone. `enable-user-identification`
→ User-ID/FSSO scoping (no single toggle).

**🔴 Zone Protection profiles** (`network/profiles/zone-protection-profile`, attached per-zone) —
PAN's analogue of **SRX screens**: flood (SYN/ICMP/UDP/...), reconnaissance (port-scan/host-sweep),
packet-based + protocol protection. → **`config firewall DoS-policy`/`DoS-policy6`** + `config anomaly`.
**Re-model (1 profile → N DoS policies):** FortiOS DoS is **per-interface + src/dst/service**, not
per-zone; PAN's 3-tier alarm/activate/maximum rates collapse to one `threshold`; SYN-cookies-vs-RED
and most packet/protocol options are **unmappable**. **Commonly dropped silently → zero flood/scan
protection** while the output looks complete.

**🔴 Interface Management profiles** (`network/profiles/interface-management-profile`) — permitted
mgmt services to the box (ping/ssh/https/snmp/...) + a **permitted-IP source allow-list**. Splits in
FortiOS: services → per-interface `set allowaccess …`; the source allow-list → **`config firewall
local-in-policy`** (and/or admin `trusthost`). **Two opposite failures:** drop it → mgmt **lockout**;
emit `allowaccess` but drop the permitted-IP list (separate construct) → mgmt **exposed to every
source IP** — the worse one.

Sources: [zone-protection](https://docs.paloaltonetworks.com/network-security/security-policy/administration/security-profiles/security-profile-zone-protection) · [interface-management-profiles](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-networking-admin/configure-interfaces/use-interface-management-profiles-to-restrict-access) · [FortiOS DoS policy](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/771644/dos-policy) · [FortiOS local-in-policy](https://docs.fortinet.com/document/fortigate/7.4.1/cli-reference/296620/config-firewall-local-in-policy)

---

## 3. NAT 🔴 (`rulebase/nat/rules`)

**The pre-NAT/post-NAT rule (get this exactly right):** a PAN **security** rule matches on the
**pre-NAT (original) source/destination addresses** but the **post-NAT zones**. For inbound DNAT,
the security rule's `to` zone is the zone reached by routing the *translated* IP, while its
destination address is the *original/public* IP. Mishandling this is the classic PAN-conversion bug.
In FortiOS the DNAT target is a **VIP**; the policy's `dstaddr` is the VIP and FortiOS resolves
zone/address implicitly — copy PAN zones verbatim and the policy **never matches**.

| PAN NAT | FortiOS | 🔴 risk |
|---|---|---|
| Source DIPP (interface) | policy `set nat enable` | wrong egress IP if forced to a pool |
| Source DIPP (pool) | `ippool type overload` + `set ippool enable`/`poolname` | collapsing pool changes distribution |
| Source dynamic-ip (1:1, no port) | `ippool type one-to-one` | 🔴 mapping to `overload` **silently adds PAT** |
| Source static-ip | `ippool type one-to-one` (or VIP if bidir) | port semantics if mapped to overload |
| **static-ip bi-directional yes** | **VIP** (inherently bidirectional) | 🔴 reverse rule is **implicit** (not a 2nd entry) — drop it → inbound breaks |
| Dest NAT (static) | `firewall vip` (extip/mappedip); policy dstaddr=VIP | raw address instead of VIP → no DNAT (blackhole) |
| Dest NAT + port translation | VIP `set portforward enable` + extport/mappedport | forgetting `portforward enable` → port rewrite lost |
| Dest NAT one-to-many / FQDN | `vip type load-balance` (re-model) | flatten→1 backend loses LB; hash methods no exact equiv |

Source: [NAT Policy Overview](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/nat/nat-policy-rules/nat-policy-overview) · [FortiOS static VIPs](https://docs.fortinet.com/document/fortigate/7.4.4/administration-guide/510402/static-virtual-ips)

---

## 4. Security profiles & profile groups 🔴

PAN profiles do the L7 enforcement; attached via `profile-setting` (`group` | individual `profiles` | `none`).
**🔴 Dropping a profile = enforcement silently lost while the rule still passes traffic.**

| PAN profile | FortiOS | Notes |
|---|---|---|
| antivirus | `config antivirus profile` | per-protocol; HTTPS scan needs deep-inspection (§5) |
| anti-spyware (+ DNS sinkhole, botnet) | `config ips sensor` (+ DNS filter) | 🔴 DNS sinkhole has no IPS analog — re-model |
| vulnerability protection | `config ips sensor` | CVE is the clean cross-vendor key |
| URL filtering | `config webfilter profile` | 🔴 PAN cats ≠ FortiGuard cats — crosswalk; this is also where rule-level `category` lands |
| file blocking | `config file-filter profile` | file-type crosswalk |
| WildFire | FortiSandbox | 🔴 needs an appliance/Cloud — not self-contained; flag hard |
| data filtering (DLP) | `config dlp profile` | 🔴 re-model, not auto-converted |

**🔴 No FortiOS "profile group" object** — each policy gets the individual profile names directly.
If a group lookup fails, every profile on every rule using it vanishes.

Source: [Security Profiles](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-profiles)

---

## 5. Decryption 🔴 (`rulebase/decryption/rules`) — the highest-severity silent loss

**🔴 Dropping a decryption rule silently guts AV/IPS/URL/file/DLP** — those profiles can only inspect
plaintext, so without a matching decrypt rule they "succeed" while seeing only the TLS envelope.

| PAN | FortiOS `ssl-ssh-profile` | Notes |
|---|---|---|
| SSL Forward Proxy (outbound, re-sign) | deep-inspection, `server-cert-mode re-sign` + CA | needs FortiGate CA imported/trusted |
| SSL Inbound Inspection | deep-inspection, `server-cert-mode replace` + `server-cert` | 🔴 server key not in policy XML → import manually + flag |
| SSH Proxy | `config ssh … status deep-inspection` | dropping = SSH-tunnel detection lost |
| No-Decrypt (+ cert checks) | certificate-inspection / `ssl-exempt` | 🔴 mapping to deep-inspection breaks pinned/client-auth sites |
| Custom exclusions | `config ssl-exempt` | predefined/cached exclusions have no export → flag (else FortiOS MITMs pinned sites) |

A converted UTM profile **without** a converted deep-inspection profile is a quiet half-measure — flag the pair.
Source: [Create a Decryption Policy Rule](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/decryption/define-traffic-to-decrypt/create-a-decryption-policy-rule)

---

## 6. Other policy types (carry security/forwarding intent — convert or flag, never drop)

| PAN rulebase | FortiOS | Verdict / 🔴 risk |
|---|---|---|
| `authentication` | `config authentication scheme`/`rule` + policy `set groups` (MFA=`require-tfa`) | re-model; 🔴 dropping removes pre-Security auth gate |
| `dos` (DoS protection) | `config firewall DoS-policy` | convert + flag; 🔴 dropped `Protect` = no flood mitigation |
| `qos` | traffic shaping (`shaping-policy` + `shaper`) | lossy 8→3 priority; report (no access path) |
| `pbf` (policy-based forwarding) | `config router policy` (L3/L4); app-match → SD-WAN | convert L3/L4, flag app-match; 🔴 dropping reverts to default route |
| `tunnel-inspect` | re-model (`system vxlan`/`gre-tunnel`) | flag; 🔴 inner GRE/VXLAN/IPsec-null traffic passes uninspected |
| `sdwan` | `config system sdwan` | re-model; 🔴 link-quality steering/failover lost |
| `application-override` | custom service + no-UTM policy | flag; 🔴 **separate rulebase** — bypasses App-ID; converter reading only `security/rules` misrepresents inspection |

Source: [PBF](https://docs.paloaltonetworks.com/network-security/security-policy/administration/policy-based-forwarding) · [App Override](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/application-override-policy)

---

## 7. Multi-vsys & Panorama 🔴 (scope, order, collisions)

- **Multi-vsys** → **one VDOM per vsys.** 🔴 Interfaces/virtual-routers live at **device level**, owned
  per-vsys only via the `vsys/import/network/{interface,virtual-router}` list — a naive parse that
  attaches device-level network config to one config (or all VDOMs) **duplicates IPs/routes across
  VDOMs**. Bind each to exactly one VDOM via the import list. External-zone/shared-gateway → inter-VDOM
  links (re-model, never an any-any bridge).
- **Panorama device-groups** → FortiManager **ADOM packages** + a **Global ADOM** header(pre)/footer(post).
  🔴 **Exact evaluation order:** Shared-pre → ancestor-DG pre (root→leaf) → **local** → child-DG post
  (leaf→root, **reverses**) → ancestor-DG post → Shared-post → default. Wrong flatten order flips the
  first-match winner; the post block reverses vs the pre block.
- **Templates / template-stacks** push network/device config (interfaces, **zones**). 🔴 A Panorama export
  **without** the referenced template gives rules with **dangling zone refs** — ingest template+stack, or
  emit the policy disabled + report; never fabricate the zone. Stack override is **per-setting**, priority order.
- **Object scope** (shared / vsys / DG-hierarchy, descendant-wins): 🔴 flat-merging same-name-different-value
  objects collides them (FortiManager refuses dup names) → resolve per-scope, **rename to disambiguate**, report.
- **target / negate** (per-rule install scope, keyed by serial + optional vsys) → FortiManager per-policy
  **Install On**. 🔴 dropping it explodes a rule to all firewalls; losing `<vsys>` lands it on all VDOMs;
  `negate=yes` has no primitive → expand to `(DG members) − (listed)`.

Source: [device-group-policies](https://docs.paloaltonetworks.com/panorama/10-2/panorama-admin/panorama-overview/centralized-firewall-configuration-and-update-management/device-groups/device-group-policies) · [templates-and-template-stacks](https://docs.paloaltonetworks.com/panorama/11-1/panorama-admin/panorama-overview/centralized-firewall-configuration-and-update-management/templates-and-template-stacks)

---

## 8. Objects: addresses, services, tags, EDLs, URL categories

- **address**: ip-netmask→`ipmask`, ip-range→`iprange`, fqdn→`fqdn` (IPv6→`address6`); 🔴 **ip-wildcard**
  (non-contiguous IPv4 bitmask) ≠ FortiOS `wildcard-fqdn` (a DNS glob) — no clean map, gate/disable+review.
- **service**: tcp/udp/icmp/ip-proto; source-port → FortiOS `dst:src` colon form (🔴 dropping source-port
  broadens); session-timeout `override` → `session-ttl`. Never fold `udp/53` onto built-in `DNS` (tcp+udp).
- **address-group dynamic (DAG)** + **tags**: 🔴 a DAG's members are tag-matched. Drop tags → DAG empty →
  rule matches **nothing** (or "all" if mishandled — catastrophic). Snapshot to static members (report it),
  map to a fabric-connector dynamic address, or disable+review; carry tags into `comment`.
- **EDL** (`external-list`, IP/domain/URL) → `config system external-resource`. 🔴 dropping an EDL collapses
  the referencing rule's address to a dangling ref.
- **custom URL category**: URL-List → `webfilter urlfilter`; 🔴 **Category-Match** (a boolean over PAN-DB
  categories, **not** URLs) → FortiGuard categories — emitting it as a URL list matches nothing.

---

## Consolidated — PAN silent-loss checklist

| Construct | Converts to | 🔴 Risk if dropped / mis-mapped |
|---|---|---|
| `negate-source/destination` | `srcaddr/dstaddr-negate enable` | **inverts** the rule (over-permit/deny) |
| `rule-type` universal/intrazone/interzone | multiple / same-zone / distinct policies | under/over-match; intrazone-default polarity flip |
| `disabled` | `set status disable` | silently **activates** a disabled rule |
| `schedule` | `firewall schedule` | rule runs 24/7 |
| reset-client/server | `deny`+`send-deny-packet` | per-side RST lost |
| `profile-setting` | per-policy UTM profiles | **zero inspection** while traffic passes |
| **Zone Protection** | DoS-policy (per-iface, 1→N) | all flood/scan protection gone |
| **Interface Mgmt profile** | `allowaccess` + `local-in-policy` | mgmt **exposed to all** (or lockout) |
| NAT pre/post-zone + VIP | policy dstaddr=VIP | inbound DNAT never matches / blackhole |
| bi-directional NAT | IP pool + VIP | reverse reachability breaks |
| **Decryption rule** | ssl-ssh-profile deep/cert/exempt | AV/IPS/URL silently inspect ciphertext (worst) |
| Security profiles (av/ips/url/dlp/wildfire) | FortiOS profiles | enforcement lost; WildFire/DLP need re-model |
| auth / DoS / PBF / tunnel-inspect / SD-WAN / app-override | re-model per §6 | auth gate / flood / path / inner-tunnel / steering / App-ID-bypass lost |
| multi-vsys import scoping | VDOM + `set vdom` | IP/route duplication across VDOMs |
| Panorama pre/post order + target | global header/footer + Install On | wrong winner / scope explosion |
| object scope collisions | per-scope rename | cross-namespace ref corruption (CLAUDE.md class) |
| DAG / tags / EDL | dynamic addr / external-resource | match set collapses to nothing or all |
| ip-wildcard / Category-Match URL cat | gate / FortiGuard cats | empty or broadened match |

> **fwforge anchors:** scope/DAG/tag/EDL/rule-type handling belong in `fwforge/parsers/paloalto.py`
> before the IR (`model.py` lacks object-scope, dynamic/tag group, service session-timeout, and an
> `external-resource` address type — each an IR change behind tests); name-collision/clamps via
> `transforms/names.py`+`limits.py`; emit gating (ip-wildcard, empty-DAG, source-port, category-match,
> DoS, local-in-policy) in `emit/fortios.py`; FortiManager header/footer + install-target in
> `emit/fortimanager.py`. Every flatten/snapshot/disable/rename must hit the report.
