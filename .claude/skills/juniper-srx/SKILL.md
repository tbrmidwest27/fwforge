---
name: juniper-srx
description: Juniper SRX / Junos OS security expert — security zones & host-inbound-traffic, security policies (deny vs reject, global, scheduler, address-excluded negation), NAT (source/destination/static/proxy-arp), screens (DoS), stateless firewall filters & lo0 control-plane protection, ALG/IDP/UTM/AppSecure, chassis cluster, logical/tenant systems, routing-instances & policy-options, and the set vs hierarchical config formats with apply-groups/${node} inheritance. ALSO the authoritative reference for converting an SRX config to FortiOS (the re-model mapping + silent-loss checklist). Use whenever the user mentions a Juniper SRX, vSRX, Junos/JunOS, `set security ...`, `host-inbound-traffic`, a Junos security policy, a Junos screen, an lo0/loopback firewall filter, `apply-groups`, `routing-instances`, a `junos-*` application, pastes Junos config (set-format or curly), or wants to convert/migrate an SRX config to a FortiGate.
---

# Juniper SRX / Junos OS security expert

Read SRX configs like an experienced firewall engineer, and convert them to FortiOS
without silently losing protection. The recurring failure mode this skill guards
against: an SRX config carries security in places that have **no 1:1 FortiOS line**
(lo0 control-plane filters, screens, host-inbound-traffic, `policy-options`), so a
naive reader or converter drops them and the box is quietly less protected.

## Golden rule — no device changes without written permission

Any operation that mutates a live device (`set`/`delete` + `commit`, `request system ...`,
NETCONF/REST edits, reboots) requires explicit written approval **for that specific
change**. Reading is free (`show ...`, `show configuration`, `monitor`, `ping`). Approval
in a prior session does not carry to today. When you find a fix, propose the exact
commands and wait. (Conversion work is read-only on the source — you parse it, you
never push to the SRX.)

## Read the config in the right format first

Junos has two textual forms — know which you're holding:

| Form | Looks like | Get it with |
| --- | --- | --- |
| **Hierarchical (curly)** | nested `{ }` blocks | `show configuration` |
| **Set** | flat `set security ...` lines | `show configuration \| display set` |

**Critical reading commands (do these before trusting what you see):**
- `show configuration | display set` — flatten to `set` lines (easiest to diff/parse).
- `show configuration | display inheritance` — **resolve `apply-groups`, `groups`, wildcards, and `junos-defaults`**. A literal-only read MISSES inherited config: a zone's `host-inbound-traffic`, interface settings, or whole stanzas can live in a group and be invisible until expanded. **Always reason from the inherited view.**
- `show configuration groups junos-defaults applications` — the real ports behind every `junos-*` predefined application.

**Disabled state — two different things, both load-bearing:**
- `inactive:` (curly) / `deactivate ...` (set) — the statement is **excluded from the running config**. Converting it as active is a **silent re-activation** of something an admin turned off (dangerous).
- `disable` — committed admin-down (present in running config). Don't conflate the two.

**`${node}` / `interface-range` / `apply-path`** — runtime/expanded constructs. `${node}`
resolves per chassis-cluster member (node0/node1 groups); if you can't resolve it,
**enumerate what's lost** (mgmt IPs, name-servers, host-names), don't just skip silently.

## SRX security architecture — the mental model

- **Zones** group interfaces; policies are `from-zone X to-zone Y`. **`host-inbound-traffic`** controls traffic *to the box itself* (the Routing Engine / control plane) and is **deny-by-default** — silence means blocked. Two independent knobs: `system-services` (ssh/https/snmp/...) and `protocols` (bgp/ospf/bfd/...). Permitting `ssh` does nothing for `ospf`.
- **Policies** are ordered, **first-match-wins**, default **deny-all** (the implicit deny **cannot log** — an explicit terminal deny is needed to log drops). Global policies evaluate **last**. Order: intra-zone → inter-zone → global.
- **`deny` ≠ `reject`.** `deny` = silent drop. `reject` = sends TCP RST / ICMP port-unreachable. Collapsing reject→deny makes apps hang on timeout instead of failing fast.
- **`source-address-excluded` / `destination-address-excluded`** = **negation**. Dropping it **broadens** the rule (IPv6 has no excluded form).
- **NAT** is a unified rule-set model: **static → destination → source**, with the **security-policy lookup happening post-DNAT / pre-SNAT** (policies match the *translated* destination but the *original* source). Source `interface` action is always PAT.
- **Screens** (`security screen ids-option`, attached per-zone) are **DoS/anti-recon protection** — SYN/ICMP/UDP floods, scans, spoofing, land/teardrop. They have no policy line; they're easy to drop and the box loses hardening.
- **lo0 stateless firewall filter** (`firewall family inet filter ... ` bound via `interfaces lo0 unit 0 family inet filter input`) is **Routing-Engine / control-plane protection** — the SRX's own firewall for traffic to itself. **No FortiOS line-translation exists** (see below).

## The silent-loss landmines (what gets dropped and quietly removes protection)

Ranked by how invisibly they vanish. Full detail + FortiOS re-model in
`references/security-surface-fortios-mapping.md` §12 checklist.

1. 🔴🔴🔴 **lo0 / stateless firewall filters** — control-plane ACL. Re-model into FortiOS **local-in-policy + interface `allowaccess` + DoS policy**. Never a 1:1 line.
2. 🔴🔴 **Screens (DoS)** — re-model into FortiOS **DoS policy** (`config firewall DoS-policy`). Per-zone in SRX.
3. 🔴 **host-inbound-traffic** — deny-by-default; dropping it flips intent to *allowed* (over-open) or emits nothing (admin/routing black-holed). Map `system-services`→per-interface `allowaccess`, `protocols`→`local-in-policy`.
4. 🔴 **address-excluded negation** → `srcaddr-negate`/`dstaddr-negate`. Dropped = rule broadened.
5. 🔴 **`reject`→`deny`** → FortiOS `action deny` + `set send-deny-packet enable` to keep RST/ICMP.
6. 🔴 **scheduler-name** → `config firewall schedule`. Dropped = policy runs 24/7.
7. 🔴 **`policy-options`** (prefix-lists / policy-statements) → `route-map`+`prefix-list`. Easy to drop via indirection; BGP/OSPF/VRF filtering silently lost.
8. 🔴 **application-services / dynamic-application / url-category** — UTM/IDP/AppFW/AppID enforcement; profile re-models, not line translations.
9. 🔴 **unresolved `junos-*` / custom apps** → never fall back to `service ALL`; expand SETs, disable+report ALGs/UUID/unknowns. See `references/predefined-applications.md`.

**The discipline:** when reading or converting an SRX config, walk the §12 checklist and
confirm each security-relevant stanza is either translated or **loudly flagged**. Treat
"nothing to report" as suspect until cross-checked against the checklist — a converter's
own output is blind to what it never modeled.

## Operational quick reference (read-only)

```
show version                                   # model + Junos release
show chassis cluster status                     # HA: node priority/state, RG failover
show security zones                             # zones + bound interfaces
show security policies [from-zone X to-zone Y]  # policy list
show security policies hit-count                # usage (prune candidates)
show security shadow-policies                    # eclipsed/never-match rules
show security flow session                       # live session table
show security nat source rule all / summary      # NAT rule-sets + translations
show security screen ids-option <name> zone <z>  # screen counters
show configuration security | display set        # the security config, flat
show route / show route forwarding-table         # FIB
```

NETCONF over SSH (port 830) and the REST API (Junos REST, off by default) exist for
automation; for one-off reads, SSH + `show ... | display set | no-more` is simplest.
`| no-more` disables the pager for scripted reads.

## Chassis cluster (HA) essentials

`node0`/`node1` configs live under `groups` and are applied with `apply-groups "${node}"`.
**reth** (redundant ethernet) interfaces carry the real data-plane IPs/zones; redundancy-groups
(RG0 = RE, RG1+ = data) define failover. For a single-FortiGate target: cluster *topology*
(cluster-id, control/fabric links) is droppable, but **reth IP/zone assignments and the
node-group mgmt IPs/host-names are real config — extract them, don't treat them as HA plumbing.**

## Converting SRX → FortiOS

This is a **re-model, not a line translation.** fwforge (`fwforge/parsers/juniper_srx.py`)
parses set + curly, expands apply-groups, and emits FortiOS with a report of everything
non-convertible. When working on the converter or interpreting its output:

- Lean on the `references/` files as the **completeness checklist** — the parser only
  knows what it models; the references know what an SRX *contains*.
- The core promise: **nothing dropped silently, no rule broadening.** An unresolvable
  app/operator must emit the policy **disabled + commented**, never broadened to `ALL`.
- Validate against a real config and read **every** report finding *and* confirm the
  things that produce no finding (lo0 filter, screens, policy-options) — those are the
  blind spots.

## References

Read these when the question hits that area:

- `references/security-surface-fortios-mapping.md` — the full SRX security config surface (zones/host-inbound, policies, NAT, screens, lo0 filters, ALG/IDP/UTM, chassis cluster, logical/tenant systems, routing/policy-options, apply-groups/inactive), each with FortiOS mapping + Juniper doc citations, ending in the §12 **silent-loss checklist**.
- `references/predefined-applications.md` — every `junos-*` predefined application → protocol/port, ALG/UUID/SET flags, and JSON ready to merge into `junos_apps.py`. Includes a confirmed `junos-radius` over-broadening bug.

## Common pitfalls

- **Reading literal config instead of `| display inheritance`** — apply-groups/junos-defaults hide real settings; you'll miss host-inbound-traffic and inherited interface config.
- **Treating `deny` and `reject` as the same** — they're not; reject sends RST/ICMP.
- **Dropping `*-address-excluded`** — silently broadens the rule (the #1 conversion bug class).
- **Mapping `junos-*` from memory** — verify ports (`groups junos-defaults applications`); `junos-radius`=1812 only, `junos-dhcp-relay`=67, MS-RPC-UUID/ALG apps have no fixed port.
- **Ignoring screens / lo0 filters** — they carry no policy line and vanish silently; both are FortiOS re-models (DoS policy / local-in-policy).
- **Flattening logical-systems / tenants** — each is a VDOM; flattening causes wrong policy scope or namespace collision.
- **Converting `inactive:`/`deactivate` as active** — silently re-enables a rule an admin disabled.
- **Assuming policy match sees the original destination** — after DNAT the policy matches the *translated* destination; build FortiOS VIPs accordingly.
