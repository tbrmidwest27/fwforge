# fwforge roadmap — beating FortiConverter where it's weak

Competitive notes researched June 2026 (FortiConverter Tool 7.4.1 /
Service 25.1.0, installed copy inspected + docs + Fortinet community).

## Mission

**Full FortiConverter parity + a modernized feature set that does things
FortiConverter can't.** Additional vendor *parsers* (Check Point, Juniper,
SonicWall, …) are explicitly deferred — they're additive and each is ~an
hour's work. Everything else FortiConverter does, fwforge should do, and
then exceed.

## FortiConverter parity matrix (non-parser features)

Tracks every FortiConverter capability that is NOT "another source vendor".

| FortiConverter feature | fwforge status |
|---|---|
| FortiOS→FortiOS model migration, interface mapping | ✅ done (lossless tree) |
| Tuning: discard unreferenced objects | ✅ done — `--prune` (theirs is opt-in & shallow; ours iterates) |
| Tuning: rule include/exclude | ✅ done — `--only` / `--exclude` |
| Tuning: Interface Pair View Split | ✅ done — `--split-interface-pairs` |
| Merge duplicate objects | ✅ done — `--merge-dupes` (FC doesn't do this) |
| Plain-CLI output with inline warnings | ✅ done + first-class md/JSON report |
| config-all.txt + per-branch files; full-backup for FGT→FGT | ✅ done — FGT→FGT = one restorable `.conf`; cross-vendor = config-all.txt + per-branch `.txt` (findings embedded as `#` comments); GUI .zip bundle |
| Interface-mapping import/export | ✅ done — plan files + GUI grid |
| GUI workflow | ✅ done — local Flask, + live diff & artifact scan |
| VDOM mapping (config lands in right VDOM) | ✅ done (multi-VDOM aware) |
| non-VDOM ↔ VDOM **mode** conversion | ✅ done — `--vdom-mode multi/single`, scope-split, `--vdom-scope-only` for safe load into existing box |
| Hardware-switch → software-switch conversion | ✅ done — `--hw-switch convert`, drops dead switch infra, member renames flow |
| Merge into an existing target config | ⏳ todo — source + target backup, no overlap |
| SSL-VPN → IPsec migration assistant | ✅ done — `--sslvpn-to-ipsec` builds an IKEv2 dial-up scaffold (mode-cfg pool, authusrgrp, split-include), rewires policies |
| Merge into an existing target config | ❌ **declined by design owner** (2026-06-10): not a wanted feature — fwforge outputs are standalone configs/scripts, not in-place edits of a running box's backup |
| virtual-router → VRF conversion | ⏳ todo (pairs with Juniper/PAN parsers) |
| FortiManager output target | ✅ done — `--fmg ADOM[/PKG]` / GUI option emits a JSON-RPC import bundle (objects + policy package) |
| Audit / documentation report (polished) | ✅ done — self-contained `report.html`, print-to-PDF friendly, escaped/colored findings |
| VDOM Mapping page | ✅ done — wizard step + `[vdommap]` plan section + `--vdom-map`; renames config vdom edits, interface `set vdom`, management-vdom, vdom-property |
| **Modern extras FC lacks** | route-based dstintf inference, version-upgrade
  artifact scan (silent default-flips), zone/SD-WAN restructuring,
  per-line provenance, deterministic diff, fully local, free |

Build order for the ⏳ items: VDOM-mode conversion and hw→sw switch first
(directly serve the 601F/121G fleet), then SSL-VPN→IPsec assistant (8.0
relevance), then merge-into-existing, FortiManager output, doc report.

## What we learned about FortiConverter

**Architecture** (from the installed copy): Django 5.2 + React web UI +
PostgreSQL 16, but the actual conversion logic is a closed compiled
`ConversionEngine.exe` (~14 MB) plus a commercial license-activation
library. The Python layer is just the wrapper. Vendor knowledge ships as
flat mapping files (Cisco/Check Point/Palo Alto/Juniper service + app-ID
tables).

**Pricing**: Tool = $3,995/yr subscription (unlimited conversions, 1 yr).
Service = one-time per-device SKU, ~$50 (desktop models) to ~$5,000
(high-end), human-assisted with ~2-business-day turnaround, US-Pacific
business hours. FortiGate→FortiGate became free June 2025 — but runs
through Fortinet's cloud and requires consenting to data-use terms.
Trial mode deliberately disables CLI output.

**Documented/confirmed weaknesses** (each one is a fwforge feature):

| # | FortiConverter behavior | fwforge answer | status |
|---|---|---|---|
| 1 | Falls back to `dstintf any` when routing info is missing (admitted in docs) | route table built from source config (static + connected), longest-prefix-match per policy destination; `any` only when genuinely ambiguous, always reported | **shipped v1** |
| 2 | Warnings buried as comments in config-all.txt | first-class report (md + JSON) with severity + file:line provenance; nonzero exit code on errors | **shipped v1** |
| 3 | Twice-NAT unsupported; NAT-merge path documented to crash | flagged loudly as errors (conversion of common twice-NAT idioms = v2) | flag shipped; convert v2 |
| 4 | Black-box engine — no way to see why output is what it is | open source, deterministic output, per-line provenance in JSON report | **shipped v1** |
| 5 | Converts everything 1:1 incl. unreferenced objects (only an opt-in discard); no duplicate/shadow analysis | hygiene pass: duplicate objects, duplicate/shadowed policies, any/any/ALL rules, unreferenced objects — reported; `--prune` / `--merge-dupes` later | analysis shipped; auto-fix v2 |
| 6 | FGT→FGT free path = config uploaded to Fortinet cloud | fully local lossless tree migration | **shipped v1** |
| 7 | Windows-only, heavyweight install (PG16 + Django), online license checks | single zero-dependency Python package | **shipped v1** |
| 8 | Port operators it can't express get approximated | non-convertible operators (`neq`) emit the policy disabled + review comment — never silently broader | **shipped v1** |
| 9 | VPN conversion weak (GlobalProtect unsupported; EZVPN → any/any; Check Point VPN needs manual post-fix) | v2 target: ASA crypto-map / tunnel-group → FortiOS phase1/phase2-interface | not started |
| 10 | REST-API import to FortiGate reports success while incomplete | future: verify-after-apply against a live lab FortiGate (we own real hardware: 601F/121G lab) | not started |

**What FortiConverter does well — don't lose these**: huge vendor breadth
(16+ sources), interface-mapping import/export, VDOM mapping,
hardware→software switch rewrites, tuning UI (interface-pair split, rule
include/exclude), plain diffable CLI output, SSL-VPN→IPsec migration
assistant.

**Open-source landscape**: effectively empty. DirectFire_Converter stalled
("very early development"); Palo Alto Expedition EOL'd Dec 2024 (then hit
by exploited CVEs); remaining GitHub scripts are object-level partials.
A maintained open converter has no real competition.

## Build order

### v1 (done)
- [x] IR model with per-object source provenance
- [x] Cisco ASA parser (objects, groups, ACLs, object NAT, routes)
- [x] FortiOS lossless tree parser/serializer (multiline cert values,
      nested blocks)
- [x] Reference-aware interface renaming for FortiOS→FortiOS migration
- [x] Route-based dstintf inference
- [x] Conservative built-in service mapping
- [x] Name sanitization to FortiOS limits with reference remapping
- [x] Hygiene analysis (dupes, shadows, any/any/ALL, unreferenced)
- [x] md + JSON reports with coverage %; sample portmap generation
- [x] CLI: detect / inspect / convert; 23 tests

### v2 — shipped 2026-06-10
- [x] Migration plan files (`[portmap]` / `[zone …]` / `[sdwan …]`) +
      `fwforge plan` scaffolder
- [x] Zone refactor: create/extend zones, policy/central-SNAT rewrite with
      token dedup, duplicate-policy merge, same-zone flagging, leftover
      audit
- [x] SD-WAN refactor: members + gateways harvested from removed default
      routes, sdwan-zone route creation, health checks, policy rewrite,
      audit
- [x] `--target-platform`: rewrite #config-version platform code
- [x] Post-rename leftover scan (caught a real miss: SSL-VPN
      source-interface; FortiSwitch/FortiExtender names correctly skipped)
- [x] Real-config proof: live 601F backup (46k lines, FortiOS 8.0)
      converted to 701G port naming — see migrations/601f-to-701g/

### v0.3 — shipped 2026-06-10
- [x] **Multi-VDOM support**: VDOM scopes parsed (`config global` /
      `config vdom` bodies), zone & SD-WAN refactors derive the owning
      VDOM from member interfaces (optional `vdom =` assertion), sections
      and route conversion land inside the right VDOM, cross-VDOM members
      rejected. Proven against the real Top Router 121G config
      (73k lines, Management/root/FGSP): lossless roundtrip, 0 warnings.

### v0.4 — shipped 2026-06-10
- [x] **Palo Alto parser** (the gap Expedition's EOL left open): XML and
      `display set` formats normalized into one tree (expat with line
      provenance, entity declarations rejected); zones → FortiOS zones;
      negate flags; NAT (interface PAT / bi-directional static / DNAT →
      VIP); predefined services; route egress inference; App-ID and
      application-default flagged loudly, converted on service match.

### v0.5 — shipped 2026-06-10
- [x] **FortiOS version-upgrade artifact scan** for FGT→FGT migrations
      that jump versions: source version auto-read from #config-version,
      target from --fortios. Detects removed features (7.6 SSL-VPN, 8.0
      gui-dashboard/intra-vap-privacy), auto-fixes safe renames
      (hw-model→hw-version, virtual-wan-link→sdwan), and — the invisible
      class — default flips where the config relied on an old default
      (8.0 IPsec DH groups, hairpin allow-traffic-redirect, inline IPS).
      Rule table curated from Fortinet release notes; extend in
      transforms/versiondelta.py as versions land.

### v0.6 — shipped 2026-06-10
- [x] **Local web GUI** (`fwforge gui`, Flask on 127.0.0.1:4848): engine
      extracted to pipeline.py (CLI + GUI share it), mapping grid with
      VDOM badges, zone/SD-WAN builder rows, upgrade-artifact display,
      severity-grouped findings, downloads, colorized before/after diff.
      Flask is the only (optional) dependency; core stays stdlib-only.

### v0.7 — shipped 2026-06-10
- [x] **ASA site-to-site VPN conversion** (the part everyone redoes by
      hand after FortiConverter): crypto maps → route-based
      phase1/phase2-interface. IKEv1+IKEv2 policies → proposal/dhgrp
      lists, transform-sets & ipsec-proposals (incl. GCM), tunnel-group
      PSKs (asymmetric IKEv2 → psksecret-remote; masked '*****' exports
      detected → placeholder + error), per-ACE phase2 selectors, PFS
      semantics preserved (ASA default off → `set pfs disable`), SA
      lifetimes. Ramifications generated: tunnel routes, out/in VPN
      policies with route-inferred LAN interfaces, crypto-ACL consumption
      tracking. Dial-up maps / cert auth / backup peers flagged loudly.

### v0.8 — shipped 2026-06-10
- [x] **Tuning actions** (FortiConverter's "Tuning page", but acting):
      `--prune` (iterative unreferenced-object removal), `--merge-dupes`
      (collapse same-value objects — FC can't), `--split-interface-pairs`
      (their Interface Pair View Split), `--only`/`--exclude` (rule
      include/exclude). Cross-vendor path; wired into CLI + GUI checkboxes.

### v0.9 — shipped 2026-06-10
- [x] **non-VDOM ↔ VDOM mode conversion** (transforms/vdommode.py):
      wrap a flat config into config global + config vdom/edit <name>
      (scope-split curated from FortiOS docs; ambiguous roots flagged),
      flatten a single-VDOM config, `--vdom-scope-only` to drop globals
      for safe load into an existing box. Runs first in the migrate
      pipeline so all downstream transforms see the target structure.
      CLI flags + GUI select.

### v0.10 — shipped 2026-06-10
- [x] **hardware-switch → software-switch conversion**
      (transforms/hwswitch.py): `type hard-switch` -> `type switch`,
      drops dead `system virtual-switch`/`physical-switch`, flags
      `hard-switch-vlan`. Also fixed a latent gap — interface renames now
      flow into switch/aggregate `set member` lists (PATH_SCOPED_ATTRS
      suffix match, multi-VDOM safe). CLI flag + GUI checkbox.

### v0.11 — shipped 2026-06-10
- [x] **SSL-VPN → IPsec dial-up assistant** (transforms/sslvpn.py):
      builds an IKEv2 dial-up phase1/phase2 scaffold from SSL-VPN tunnel-
      mode config (source-interface, tunnel IP pool → mode-cfg, portal
      split-tunnel → ipv4-split-include, auth-rule group → authusrgrp+EAP),
      rewires ssl.<vdom> policies, removes the dead SSL-VPN sections,
      flags PSK/client-reprovision/web-mode-loss. Per-VDOM. CLI + GUI.

### v0.12 — shipped 2026-06-10
- [x] **Output packaging by conversion type** (emit/package.py): FGT→FGT
      migration writes one full restorable `<stem>.conf`; cross-vendor
      writes FortiConverter-style `<stem>.config-all.txt` + per-branch
      `<stem>.branches/NN-<section>.txt`. Findings embedded as `#` comments
      after the header (restore-safe). GUI: mode-aware download + all-files
      .zip bundle.

### v0.13 — shipped 2026-06-10
- [x] **SD-WAN refactor now GENERATES the new construct** (per Adam:
      "changing an interface to an sdwan member means creating an
      entirely new config and policies"): steering rules in
      `config service` (sla default w/ SLA target added to the health
      check; `rule = sla|load-balance|priority <member>|none` per zone),
      specific-prefix member routes converted to address-object +
      pinned manual rule (before the catch-all) + sdwan-zone route,
      conflicting post-rewrite policies flagged ("first wins").
- merge-into-existing-config: built, then **withdrawn same day** —
  declined by design owner; reverted cleanly to v0.12.

### v0.14 — shipped 2026-06-11
- [x] **GUI overhaul, FortiConverter look & feel** (design language
      learned from the installed FC frontend — MUI, #266798 steel-blue
      accent, gray surfaces; own clean-room implementation): dark sidebar
      shell + topbar, Conversions project list with status chips and
      delete, step wizard (Source & Target / Interface Mapping / Policy
      Selection / Tuning / Restructure / Convert), cross-vendor **Policy
      Selection** step (searchable checkbox table → exclude), tabbed
      results (Summary / Findings with search+severity filter / Output
      line-numbered preview / Changes diff), **persistent jobs**
      (job.json per job, reloaded at startup).

### v0.15 — shipped 2026-06-11
- [x] **VDOM Mapping** (FortiConverter's page): rename_vdoms transform
      (config vdom edits, `set vdom`, management-vdom, vdom-property;
      11-char/charset validation), `[vdommap]` plan section, `--vdom-map`
      CLI flag, wizard step for multi-VDOM sources.
- [x] **Polished HTML audit report**: self-contained print-to-PDF
      `report.html` written by CLI + GUI, download button on results.
- [x] **Output-tab file selector**: browse config-all + every per-branch
      script in the results preview.

### v0.16 — shipped 2026-06-11
- [x] **FortiManager output target** (the LAST parity-matrix row):
      emit/fortimanager.py builds a JSON-RPC import bundle —
      address/group/service/VIP object creates + policy-package create +
      policies — for an ADOM. `--fmg ADOM[/PACKAGE]` on the CLI, checkbox
      + ADOM/package fields in the wizard, download on results. Routes
      and VPN tunnels (device-level) flagged as staying in the CLI script.

### v0.17 — shipped 2026-06-11
- [x] **pfSense parser** (config.xml, hardened expat): logical
      interface names + VLANs, typed aliases (host/network/port, nested,
      colon ranges), per-interface inbound rules with `lan net`/`wanip`
      macros and `<not/>` negation, gateways/defaultgw4/static routes,
      port forwards + 1:1 → VIPs, outbound automatic → wildcard
      interface-PAT. Floating/PBR/manual-NAT/IPv6/OpenVPN/IPsec flagged.
- [x] **NAT mode option** (FortiConverter NAT-merge parity+): cross-vendor
      `--nat-mode policy|central` — central emits `set central-nat
      enable` + generated `central-snat-map` rules; VIPs become central
      DNAT; policies carry no per-policy NAT. CLI flag + GUI select.

### v0.21 — shipped 2026-06-11
- [x] **Informed zone / SD-WAN member pickers** (GUI Restructure step):
      the multi-select and free-text member inputs are now searchable
      checkbox tables showing, per interface: IP/CIDR (or dhcp/pppoe),
      alias/description, type (vlan id + parent, aggregate, tunnel...) +
      role badge, owning VDOM (multi-VDOM sources), firewall-policy
      reference count, and in-use status. Members already in a zone or
      SD-WAN are disabled with the reason; picking an interface in one
      builder row live-disables it in every other row (zone vs SD-WAN
      cross-claims included). SD-WAN rows grow per-member gateway/weight
      inputs when ticked (blank gateway = harvested from old default
      routes). Backed by portmap.tree_interface_details +
      tree_refs.interface_policy_refs; analysis meta ships
      `iface_details`; Interface Mapping grid gained ip + alias hint
      columns. Legacy text member syntax still accepted on POST.

### v0.20 — shipped 2026-06-11
- [x] **IPv6 support** (last priority-list gap): emitter family-aware —
      addresses -> address6, groups -> addrgrp6, routes -> static6,
      policies -> srcaddr6/dstaddr6 (unified table, mixed-family split).
      Palo Alto (v6 ip-netmask), pfSense (inet6 rules w/ Policy.family,
      v6 aliases/addr_for, defaultgw6 + v6 static routes, ALL_ICMP6),
      Cisco ASA (modern unified: object v6 host/subnet, any6 -> all,
      ipv6 route; dedicated 'ipv6 access-list' flagged). routes_tf /
      RouteTable already v6-safe (graceful fallback to 'any').

### v0.19 — shipped 2026-06-11
- [x] **Palo Alto App-ID -> application-control mapping** (parsers/
      pan_appid.py): curated PAN-app -> FortiOS category table (clean-room;
      FC's licensed numeric ID file not reused). Rules using App-ID get a
      generated `config application list` profile (set category + action
      pass, other-application-action block) wired onto the policy via
      `set application-list` + utm-status; profiles deduped across rules.
      Transport apps (ssl/tls) ignored, unmapped apps flagged by name.
      Category-level (coarser than per-signature) and reported as such.

### v0.18 — shipped 2026-06-11
- [x] **PAN-OS + pfSense IPsec conversion** (closing a FC-edge gap):
      shared parsers/_vpn_common.py builds route-based phase1/phase2 +
      tunnel routes + bidirectional policies (LAN side route-inferred)
      from PAN ike-gateway/crypto-profile/tunnel (proxy-ids → selectors,
      version, PSK w/ encrypted-export detection) and pfSense
      phase1/phase2 (iketype, encryption items, localid/remoteid
      selectors, pfsgroup). Cert auth / missing PSK → placeholder +
      error; phase1-without-phase2 skipped. ASA VPN keeps its own inline
      path. Three of three cross-vendor parsers now convert site-to-site
      IPsec.

## 🏁 MISSION STATUS (2026-06-11)

**The FortiConverter parity matrix is complete.** Every non-parser
FortiConverter capability is implemented (or consciously declined by the
design owner: merge-into-existing). Remaining work is by-design deferred:

- additional vendor parsers (Check Point, Juniper, SonicWall, …)
- real-hardware validation: restore the converted 601F config on the
  701G when it arrives (`diag debug config-error-log read`)
- [ ] **Load the converted config on the actual 701G** when hardware
      arrives: restore, then `diag debug config-error-log read`
- [ ] (later) more parsers: Check Point, Juniper, SonicWall
- [ ] ASA twice-NAT: the common idioms (identity NAT, source-static +
      destination-static pairs) → central-SNAT / VIP combinations
- [ ] ASA crypto map / tunnel-group → FortiOS IPsec phase1/2-interface
- [ ] `--prune` (drop unreferenced) and `--merge-dupes` (collapse duplicate
      objects, rewrite references)
- [ ] Policy merge: adjacent ACEs sharing src/dst/action → one policy with
      multiple services (counter FortiConverter's 1:1 rule bloat)
- [ ] VDOM-aware FortiOS tree migration (601F multi-VDOM → 121G)

### v3 — differentiators
- [ ] Verify-after-apply: push to a lab FortiGate VDOM via REST, diff
      intended vs accepted config, report what the FortiGate rejected
      (counters FortiConverter's silent-incomplete-import problem)
- [ ] Palo Alto parser (set-format + XML) — Expedition's EOL left PAN→FGT
      with no open tooling at all
- [ ] Annotated review mode: interleave source lines as comments above each
      emitted block for side-by-side review
- [ ] Tiny local web UI for the interface-mapping step (the one genuinely
      good part of FortiConverter's UX)
