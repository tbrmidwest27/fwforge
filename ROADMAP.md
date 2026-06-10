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
| Interface-mapping import/export | ✅ done — plan files + GUI grid |
| GUI workflow | ✅ done — local Flask, + live diff & artifact scan |
| VDOM mapping (config lands in right VDOM) | ✅ done (multi-VDOM aware) |
| non-VDOM ↔ VDOM **mode** conversion | ✅ done — `--vdom-mode multi/single`, scope-split, `--vdom-scope-only` for safe load into existing box |
| Hardware-switch → software-switch conversion | ✅ done — `--hw-switch convert`, drops dead switch infra, member renames flow |
| Merge into an existing target config | ⏳ todo — source + target backup, no overlap |
| SSL-VPN → IPsec migration assistant | ⏳ todo (we *detect* the removal; FC *converts* it) |
| virtual-router → VRF conversion | ⏳ todo (pairs with Juniper/PAN parsers) |
| FortiManager (.fmg) output target | ⏳ todo — emit per-ADOM policy package |
| Audit / documentation report (polished) | ⏳ todo — we have md/JSON; add a print/PDF doc |
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

### next (parity matrix ⏳ items, fleet-first order)
- [ ] SSL-VPN → IPsec migration assistant (8.0 dropped SSL-VPN tunnel mode)
- [ ] merge-into-existing-target-config
- [ ] FortiManager output target; polished audit/doc report
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
