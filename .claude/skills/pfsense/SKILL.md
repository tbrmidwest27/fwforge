---
name: pfsense
description: pfSense / Netgate (config.xml) firewall expert — interfaces/VLANs & virtual IPs (CARP/IP-alias/Proxy-ARP), the alias object model (host/network/port/url/urltable), firewall filter rules (pass/block/reject, floating rules + quick/direction, `<not/>` negation, per-rule gateway/policy-routing, schedules), implicit/auto rules (anti-lockout, block-private/bogon, default-deny, VPN pass rules), NAT (port-forward, outbound automatic/hybrid/manual, 1:1, reflection/hairpin), management access, VPN (IPsec phase1/phase2 + OpenVPN/L2TP/WireGuard), multi-WAN gateway groups, schedules, traffic shaping (ALTQ/limiters), and the security packages (pfBlockerNG, Suricata/Snort, Squid/SquidGuard, HAProxy, Captive Portal). ALSO the authoritative reference for converting a pfSense config.xml to FortiOS (re-model mapping + silent-loss checklist). Use whenever the user mentions pfSense, Netgate, OPNsense, a config.xml with `<pfsense>`, an `<alias>`/`<filter>`/`<nat>`/`<virtualip>`, a floating rule, pfBlockerNG/Suricata/Snort/Squid, CARP, outbound NAT, a gateway group, OpenVPN, or wants to convert/migrate a pfSense config to a FortiGate.
---

# pfSense (config.xml) security expert

Read pfSense configs like an experienced firewall engineer, and convert them to FortiOS without
silently losing protection. pfSense's base is **L3/L4 packet filtering only** — so its defining
trait is that **most NGFW protection lives outside the visible `<filter>` ruleset**: in **packages**
(pfBlockerNG, Suricata/Snort, Squid, Captive Portal) and in **auto-added implicit rules** (anti-
lockout, block-private/bogon, VPN pass, default-deny). The conversion landmines are exactly there —
plus the constructs FortiOS re-models (floating rules, outbound-NAT modes, virtual IPs, per-rule
policy routing, OpenVPN).

## Golden rule — no device changes without written permission

Reading is free (the exported `config.xml`, `show`-equivalents, the GUI/Diagnostics). Anything
that mutates a live pfSense (editing config.xml + reload, `pfctl`, package install, reboot) needs
explicit written approval **for that specific change**, not carried from a prior session.
Conversion work is read-only on the source — you parse `config.xml`, you never push to the firewall.

## Read the config in the right form

pfSense config is a single **`config.xml`** (Diagnostics → Backup/Restore, or `/conf/config.xml`).
It is the whole device in one file. Orient yourself before reasoning:

- **`<interfaces>`** (logical roles wan/lan/optN → `<if>` NIC or VLAN) + **`<vlans>`** + **`<virtualip>`**.
- **`<aliases>`** — the object layer (host/network/port/url/urltable), referenced by name in rules.
- **`<filter><rule>`** — the firewall rules; **`<nat>`** — port-forward/outbound/1:1.
- **`<gateways>`** (+ groups = multi-WAN), **`<staticroutes>`**, **`<ipsec>`**, **`<openvpn>`**.
- **`<installedpackages>`** + **`<captiveportal>`** — **where the L7 / IDS-IPS / URL-filter /
  threat-feed protection lives.** Always read this tree; it carries no `<filter>` lines.
- **OPNsense** is a pfSense fork with a *similar but not identical* XML — treat element names as a
  guide, verify against the actual file.

## pfSense security architecture — the mental model

- **Protection lives outside `<filter>` (THE trap).** Two off-ruleset surfaces carry most of the
  security: **(1) packages** — pfBlockerNG (DNS/IP blocklists, GeoIP), Suricata/Snort (IDS/IPS),
  Squid/SquidGuard (proxy + URL filter), Captive Portal — the pfSense analog of ASA's MPF and SRX
  screens; and **(2) implicit/auto rules** that appear nowhere in `<filter>`. A converter reading
  only `<filter>`/`<nat>`/`<ipsec>` produces a FortiGate that **looks complete but has no IPS, URL
  filtering, blocklists, GeoIP, or portal**, and may be locked out or wide open.
- **Default posture + implicit rules.** WAN is **default-deny**; LAN ships a **default-allow LAN→any**
  rule (an editable `<rule>`, so it IS in `<filter>` — must become an explicit FortiOS policy or all
  LAN traffic is denied). Hidden auto rules: **anti-lockout** (LAN→admin GUI/SSH — drop it and you
  lock yourself out), **block-private/bogon** on WAN (anti-spoof — drop it and exposure broadens),
  **IPsec/OpenVPN pass** (IKE/NAT-T/ESP — drop it and tunnels silently die). FortiOS auto-adds none
  of these — they must be synthesized and reported.
- **Floating rules + quick/direction.** Floating rules match across interfaces and **outbound**
  (post-NAT source). `quick` present → first-match; **`quick` absent → LAST-match-wins**, which has
  **no analog** in FortiOS's first-match list — re-model/flag, never flatten into order.
- **NAT outbound modes.** `automatic`/`hybrid` SNAT rules are **not in the XML** (auto-generated) —
  translate the *intent* (per-policy `nat enable` on egress) or outbound NAT silently vanishes.
  `manual` → central-SNAT. **1:1 NAT** with a `<destination>` restriction → a FortiOS VIP that
  applies to **all** destinations unless the restriction is restored (broadening). **Reflection**
  (hairpin) has no toggle — synthesize VIP + DNAT + SNAT (`nat-source-vip`).
- **Virtual IPs are NAT targets.** A Proxy-ARP/Other `<virtualip>` is the external IP a port-forward/
  1:1 maps to — drop it and the NAT **blackholes** (the IP doesn't exist on the FortiGate). CARP →
  HA/VRRP; IP-alias → secondary IP.
- **Per-rule `<gateway>` = policy routing** (multi-WAN) → FortiOS `router policy` / SD-WAN rule, not
  a policy field. **`<not/>`** = invert match → `srcaddr-negate`/`dstaddr-negate` (drop it = inverts
  the rule). **OpenVPN** has **no FortiOS equivalent** — re-model to IPsec dial-up / ZTNA, and **do
  NOT target FortiOS SSL-VPN** (tunnel mode removed in 7.6.3+).

## The silent-loss landmines (drop these and protection quietly vanishes)

Full detail + FortiOS re-model + per-construct fwforge status in
`references/security-surface-fortios-mapping.md` (master checklist, ranked by blast radius).

1. 🔴🔴 **Security packages** (`<installedpackages>` + `<captiveportal>`) — Suricata/Snort IPS, pfBlockerNG DNS/IP/GeoIP, Squid/SquidGuard URL filter, Captive Portal. All L7/threat protection, off-ruleset. Map to IPS sensor / dnsfilter / external-resource / geography / webfilter / explicit-proxy / portal — or it's silently gone.
2. 🔴🔴 **Floating rules** without `quick` (last-match) — no first-match analog; flattening silently changes which rule wins.
3. 🔴 **Implicit/auto rules** — anti-lockout (drop → lockout), block-private/bogon (drop → exposure broadens), VPN pass (drop → tunnels dead), default-allow-LAN (normalized away → mass denial).
4. 🔴 **Virtual IPs** (Proxy-ARP/Other) — the external NAT target; drop → NAT blackholes. CARP → HA/VRRP.
5. 🔴 **NAT outbound mode** (automatic/hybrid implicit SNAT not in XML), **1:1 dest-restriction** (broadens to all dest), **reflection** (no toggle → hairpin).
6. 🔴 **Per-rule `<gateway>` / gateway-groups** (policy routing / multi-WAN) → `router policy` / SD-WAN; drop → wrong egress, failover/LB lost.
7. 🔴 **`<not/>` negation** dropped → rule meaning inverted; **`reject`** flattened to silent deny loses RST/ICMP-unreachable.
8. 🔴 **`<sched>`/`<disabled/>`/`<log/>`** dropped → 24/7 / re-activated / SIEM-blind; **`inet46`** emitted v4-only → IPv6 policy missing.
9. 🔴 **OpenVPN/L2TP/WireGuard** — OpenVPN has no FortiOS equivalent (→ IPsec dial-up/ZTNA, **not** the deprecated SSL-VPN); dropping = remote access lost.
10. 🔴 **Management-plane** (webGUI/SSH + anti-lockout) → `allowaccess` + `local-in-policy` (no implicit deny → add trailing deny) + `trusthost`; the ASA "expose-to-all vs lockout" trap.

**Discipline:** walk the master checklist; confirm each construct is translated or **loudly
flagged**. A converter's own output is blind to what it never modeled (packages, implicit rules,
virtual IPs) — cross-check against the checklist, not the report.

## Operational quick reference (read-only)

```
/conf/config.xml                       ! the whole device config (Backup/Restore to export)
pfctl -sr                              ! loaded filter rules (incl. expanded implicit/auto rules)
pfctl -sn                              ! loaded NAT rules
pfctl -s state                         ! state table
pfctl -t <alias> -T show               ! contents of a table-backed alias (urltable feeds)
pfSsh.php playback ...                 ! scripted read access
Status > IPsec / OpenVPN               ! tunnel status
Diagnostics > Routes / Gateways        ! routing + gateway-group (multi-WAN) state
```
`pfctl -sr`/`-sn` are the ground truth — they show the **expanded** ruleset (implicit rules,
package-injected rules, anti-lockout) that `<filter>` in config.xml does not.

## Converting pfSense → FortiOS

A **re-model, not a line translation.** fwforge (`fwforge/parsers/pfsense.py`) parses interfaces/
VLANs, aliases, gateways + static routes, `<filter>` rules, NAT (port-forward/outbound/1:1), and
IPsec, then reports the non-convertible. When working on the converter or reading its output:

- Use `references/` as the **completeness checklist** — the parser only knows what it models.
- Core promise: **nothing dropped silently, no rule broadening.** Reuse a FortiOS predefined service
  **only on exact protocol+port match** (the aliases-and-services ref is the data layer; `tcp/udp`
  proto → emit **both** transports). A dest-restricted 1:1 must keep its restriction.
- **What the parser already handles well:** pass/block/reject (reject→deny+comment), `<not/>`
  negation, `<disabled/>`/`<log/>`, VLANs, automatic/hybrid outbound SNAT, port-forward/1:1 VIPs
  (with the dest-restricted-1:1 broadening **correctly flagged**), IPsec phase1/phase2 (masked PSK →
  `CHANGEME-PSK`), and it correctly steers OpenVPN **away** from the deprecated SSL-VPN.
- **Known parser GAPs to keep in mind (each lands in `report_unconverted` as an `info` coverage
  finding — recorded, not silent, but under-flagged and un-emitted):** all `<installedpackages>` +
  `<captiveportal>` (IPS/URL-filter/blocklists/portal); `<virtualip>` (Proxy-ARP/Other NAT targets,
  CARP); floating-rule `direction`/`quick` semantics (flagged but flattened); per-rule `<gateway>`
  + gateway-groups (policy routing / multi-WAN / SD-WAN); `<schedules>` (never attached → 24/7);
  anti-lockout + block-private/bogon synthesis; mgmt-plane access; manual outbound NAT; NAT
  reflection; OpenVPN/L2TP/WireGuard; FRR dynamic routing; traffic shaping. These are the hardening
  backlog — confirm each blind spot, since most produce no targeted finding today.

## Common pitfalls

- **Reading only `<filter>`** — misses the packages (all L7/IPS/URL/blocklist) and the implicit/auto rules. The biggest losses have no rule line to grep; check `<installedpackages>` and `pfctl -sr`.
- **Resolving `LAN net` / `LAN address` / `(self)` to `all`** — opens a rule from your LAN to the whole internet (broadening). They are interface-subnet / interface-IP objects.
- **Flattening non-quick floating rules into first-match order** — silently changes which rule wins.
- **Dropping a Proxy-ARP/Other virtual IP** — every NAT rule that targets it blackholes (the external IP doesn't exist on the FortiGate).
- **Translating only explicit outbound-NAT rules** — in automatic/hybrid mode the SNAT rules aren't in the XML; outbound NAT silently disappears.
- **A dest-restricted 1:1 → an all-destinations VIP** — broadening; restore the restriction as a policy `dstaddr`.
- **Targeting FortiOS SSL-VPN for OpenVPN** — tunnel mode is removed in 7.6.3+; go to IPsec dial-up / ZTNA.
- **Dropping `<not/>`** — inverts the rule (FortiOS has the 1:1 negate; carry it).
- **Not synthesizing the anti-lockout rule** — admin lockout on the converted FortiGate.

## References

- `references/security-surface-fortios-mapping.md` — the complete pfSense security surface
  (packages, filter rules, implicit/auto rules, NAT, interfaces/VLANs/virtual-IPs, mgmt-plane, VPN,
  routing/schedules/shaping, aliases, AAA/certs) → FortiOS, with Netgate + Fortinet doc citations,
  per-section **fwforge status** (✅/⚠️/❌ grounded in `pfsense.py` line numbers), and the
  consolidated **silent-loss checklist** ranked by blast radius (packages + floating rules at the top).
- `references/aliases-and-services.md` — the pfSense alias/object model (host/network/port/url/
  urltable, nesting), the interface/address macros (`LAN net`, `(self)`, `any`), and the port/
  protocol/ICMP service data layer → exact FortiOS predefined or tight custom (the no-broadening table).
</content>
</invoke>
