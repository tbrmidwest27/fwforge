---
name: cisco-asa
description: Cisco ASA (Adaptive Security Appliance) security expert — interface security-levels & the implicit higher→lower permit, access-lists/ACEs (extended/standard, log/time-range/inactive, object-group-search), access-group in/out/global, NAT (object/auto + twice/manual NAT, real-vs-mapped ACL semantics, identity/exemption), the Modular Policy Framework (class-map/policy-map/service-policy, application inspection/ALG, set connection, tcp-map), management-plane access (ssh/http/telnet/icmp/snmp source lists), IPsec VPN (crypto map/VTI, IKEv1/v2, tunnel-group, group-policy, AnyConnect), object/object-group model, multiple-context mode, transparent/EtherType, failover, threat-detection. ALSO the authoritative reference for converting an ASA config to FortiOS (re-model mapping + silent-loss checklist). Use whenever the user mentions a Cisco ASA, ASAv, PIX, FirePOWER/FTD-as-ASA, `access-list`/`access-group`, `nameif`/`security-level`, `object network`/`object-group`, `nat (inside,outside)`, `class-map`/`policy-map`/`service-policy`/`inspect`, a `crypto map`/`tunnel-group`, `same-security-traffic`, pastes ASA CLI/`show running-config`, or wants to convert/migrate an ASA config to a FortiGate.
---

# Cisco ASA security expert

Read ASA configs like an experienced firewall engineer, and convert them to FortiOS without
silently losing protection. The ASA's defining trait is that **most of its security posture is
implicit** — the **interface security-level** model permits whole classes of traffic with no ACL
line, and the **Modular Policy Framework** does the L7 work with no firewall-policy line. So the
conversion landmines are exactly where the ASA carries protection in constructs that have **no
line to translate** (security-levels, MPF inspection, mgmt-plane source lists) or that FortiOS
re-models (twice-NAT, crypto-map VPN, contexts).

## Golden rule — no device changes without written permission

Reading is free (`show running-config`, `show`, `packet-tracer`, `show conn`). Anything that
mutates a live ASA (`configure terminal` + `…`, `write memory`, `clear`, `reload`, `copy`) needs
explicit written approval **for that specific change**, not carried from a prior session.
Conversion work is read-only on the source — you parse the config, you never push to the firewall.

## Read the config in the right form first

ASA config is flat IOS-style text (no XML). Get the complete picture before reasoning:

```
show running-config            ! full config (may hide secrets; see below)
more system:running-config     ! includes unmasked pre-shared-keys / passwords
show running-config all        ! includes defaults (e.g. the default global_policy inspections)
show mode                      ! single vs multiple context
changeto context <name>        ! per-context config under multiple-context mode
```

**Scope to resolve first:** **single** vs **multiple-context** mode (`mode multiple` → each
`context` is its own policy/interface/admin space, fed from the **system execution space**;
maps to FortiOS **VDOMs**). A config captured from one context without the system space has
**interface allocations and failover defined elsewhere** — confirm you have both.

## ASA security architecture — the mental model

- **Security-level implicit permit (THE trap).** With **no ACL applied**, traffic from a
  **higher** security-level to a **lower** one is **permitted by default** (inside=100 → outside=0
  is free); lower→higher is denied; same-level is blocked unless `same-security-traffic permit
  inter-interface`; hairpin unless `…intra-interface`. An ASA with sparse ACLs relies on this for
  most of its allow policy. FortiOS is **default-deny between all interfaces** — opposite polarity.
  A converter reading only `access-list` produces a FortiGate that **silently denies all that
  implicit traffic** (looks clean, breaks production) — or, if it papers over with any-any,
  over-permits. The implied permits must be **synthesized and reported**, never blanket any-any.
- **An applied `access-group` replaces the implicit behavior** for that direction — the explicit
  ACL is evaluated, and every ACL ends in an **implicit deny**.
- **MPF = the ASA's L7.** `class-map`/`policy-map`/`service-policy` + `inspect …`. Even the
  **default `global_policy`** (on nearly every ASA) runs ~14 application inspections (dns, ftp,
  h323, sip, skinny, sqlnet, sunrpc, tftp, netbios, rsh, rtsp, esmtp, xdmcp). Inspection opens
  **dynamic pinholes** (FTP/SIP/H.323/RPC), NAT-rewrites embedded addresses, and enforces protocol
  conformance. Drop MPF and those flows **break or pass blind** → FortiOS session-helpers / VoIP
  profile / IPS / DoS (for `set connection` limits).
- **NAT uses real (pre-NAT) addresses in ACLs (8.3+).** ACEs name the **internal** IP of a DNAT'd
  server, not the public IP — this maps cleanly to a FortiOS **VIP** (`mappedip`=real). **Never
  rewrite ACL operands to the public IP.** **Twice/manual NAT** (`source static … destination
  static … service …`) is policy-NAT — the conditional case FortiOS splits into VIP + central-SNAT.
- **Management-plane access = control-plane protection.** `ssh`/`http`/`telnet`/`icmp`/`snmp-server
  host <src> <iface>` are **permitted-source lists** (like SRX host-inbound). FortiOS splits these
  into **`allowaccess`** (which services) + **`local-in-policy`**/admin **`trusthost`** (which
  sources). FortiOS `local-in-policy` has **no implicit deny** — you must add a trailing deny or
  mgmt stays open to all.
- **VPN:** policy-based **crypto map** (interface-bound, `match address` ACL = proxy-IDs) →
  FortiOS **route-based** phase1/phase2. `tunnel-group` = connection profile (PSK); `group-policy`
  = split-tunnel/pools/attributes.

## The silent-loss landmines (drop these and protection quietly vanishes)

Full detail + FortiOS re-model + per-construct fwforge status in
`references/security-surface-fortios-mapping.md` (master checklist, ranked by blast radius).

1. 🔴🔴 **Security-level implicit permit** (higher→lower, no ACL) + `same-security-traffic` — synthesize explicit policies or all that traffic is denied.
2. 🔴🔴 **MPF inspection** (`inspect …`, incl. the default `global_policy`) — drop it and all L7/ALG enforcement is gone; FTP/SIP/H.323 break or pass blind.
3. 🔴 **Mgmt-plane source lists** (`ssh/http/telnet/icmp/snmp <src> <iface>`) → `allowaccess` + `local-in-policy` (+ explicit deny) + `trusthost`; drop the source list → mgmt open to all.
4. 🔴 **Twice/policy NAT** + NAT pools + section order — `one-to-one`→`overload` silently adds PAT; conditional policy-NAT lost.
5. 🔴 **`neq` / unresolvable named-port operators** — converting to any-port broadens the rule; emit the policy **disabled** + review, never broaden.
6. 🔴 **`inactive` / `time-range` / `log`** on an ACE — drop and you re-activate a disabled rule, make it 24/7, or go SIEM-blind.
7. 🔴 **DNAT real-vs-mapped** — `dstaddr` = VIP (`mappedip`=real); raw address → blackhole; rewriting ACL to public IP → no match.
8. 🔴 **VPN PSK masked / group-policy split-tunnel / remote-access (AnyConnect)** — placeholder-not-key, lost tunnel scope, RA not auto-converted.
9. 🔴 **Dynamic routing** (`router ospf/bgp/eigrp/rip`) — missing routes blackhole traffic/VPN (no EIGRP target in FortiOS — report, never remap).
10. 🔴 **Multiple-context mode** → one VDOM per context (watch cross-VDOM namespace corruption); **EtherType ACLs** (transparent mode) have no equivalent; **identity-firewall user-in-ACL** → policy `set groups` (dropping broadens to all users).

**Discipline:** walk the master checklist; confirm each construct is translated or **loudly
flagged**. A converter's own output is blind to what it never modeled (security-level, MPF,
mgmt-plane) — cross-check against the checklist, not the report.

## Operational quick reference (read-only)

```
show running-config            ! full config        |  show mode  ! single/multiple context
more system:running-config     ! unmasked PSKs/secrets
show interface ip brief        ! interface/IP/up-down
show access-list               ! ACEs + hit counts (runtime)
show nat detail                ! NAT table, sections, translated/untranslated
show service-policy            ! active MPF policies + inspection counters
show run all class-map / policy-map / service-policy   ! incl. the default global_policy
packet-tracer input <ifc> tcp <src> <sp> <dst> <dp>    ! which ACL/NAT/policy a flow hits
show crypto ipsec sa / show crypto ikev2 sa            ! VPN SAs
show vpn-sessiondb / show running-config tunnel-group  ! tunnels + profiles
show failover                  ! HA state
show ssh / show run http / show run telnet / show run icmp   ! mgmt-plane source lists
```

## Converting ASA → FortiOS

A **re-model, not a line translation.** fwforge (`fwforge/parsers/cisco_asa.py`) parses interfaces
(nameif/ip), `object network`/`object service`/`object-group`, object/auto NAT, `access-list`+
`access-group`, crypto/IKEv1-2/tunnel-group VPN, and **static routes**, then reports the
non-convertible. When working on the converter or reading its output:

- Use `references/` as the **completeness checklist** — the parser only knows what it models.
- Core promise: **nothing dropped silently, no rule broadening.** `neq`/boundary `gt`/`lt`/
  unresolved port → policy **disabled** + comment, never `service ALL`. `tcp-udp` service objects
  emit **both** transports. Reuse a FortiOS built-in **only on exact protocol+port match** (the
  predefined-services ref is the table; e.g. ASA `udp domain` ≠ built-in `DNS`).
- **What the parser already handles well:** extended ACEs + `remark`/`log`/`inactive`, fail-closed
  `neq`, object NAT → VIP (static-PAT flagged for manual extip), site-to-site IKEv1/v2 crypto-map
  VPN (masked PSK → `CHANGEME-PSK`, backup peers/aggressive/dynamic-map flagged), `access-group in`/
  `global`. The ASA literal table correctly encodes the legacy/trap ports (kerberos 750, radius
  1645/1646, isakmp 500).
- **Known parser GAPs to keep in mind (each currently lands in `unparsed` or is discarded):**
  security-level implicit-permit synthesis, MPF (`class-map`/`policy-map`/`service-policy`/
  `inspect`/`set connection`), mgmt-plane source lists, **twice/manual NAT**, dynamic routing,
  `time-range`→schedule, `access-group out`, EtherType ACLs, multiple-context split, identity-in-ACL,
  group-policy/AnyConnect. These are the hardening backlog — confirm each blind spot, since several
  produce **no finding** today.

## Common pitfalls

- **Reading only the ACLs** — misses the security-level implicit permit (most of the allow policy) and MPF (all the L7). The two biggest silent losses have no line to grep for.
- **Ignoring the default `global_policy`** as "just defaults" — it carries ~14 active inspections; `show run all` to see them.
- **Rewriting ACL operands to the public/mapped IP** — ASA 8.3+ ACLs use the **real** (pre-NAT) address; the public IP belongs on the VIP `extip`, not in the policy.
- **`one-to-one` NAT pool → `overload`** — silently adds PAT (broadening).
- **Emitting `allowaccess` but dropping the mgmt source list** — opens SSH/HTTPS to every source (local-in-policy has no implicit deny; add the trailing deny).
- **Converting `neq`/`tcp-udp` carelessly** — `neq`→any-port broadens (disable instead); `tcp-udp`→one transport narrows (emit both).
- **Flattening multiple contexts into one namespace** — same-name objects collide (cross-VDOM corruption).
- **Treating `router eigrp` as remappable** — FortiOS has no EIGRP; report it, never silently convert to OSPF/BGP.

## References

- `references/security-surface-fortios-mapping.md` — the complete ASA security surface
  (security-levels, ACLs/access-group, NAT, MPF, mgmt-plane, VPN, routing, HA/transparent/
  contexts/threat-detection/AAA) → FortiOS, with Cisco + Fortinet doc citations, per-section
  **fwforge status** (✅/⚠️/❌), and the consolidated **silent-loss checklist**.
- `references/predefined-services.md` — ASA port/protocol/ICMP **literal** tables → exact FortiOS
  predefined service or tight custom (the no-broadening data layer), the object/object-group model
  (`tcp-udp` mixed form, nesting, source-port traps), and confirmed data-correctness notes
  (`domain`≠`dns`/`dnsix`, `kerberos`=750, `radius`=1645).
</content>
</invoke>
