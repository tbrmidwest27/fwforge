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

### v0.52.2 — shipped 2026-06-16 (PAN WildFire → FortiOS FortiSandbox, folded into the AV profile)
FortiOS submits files to FortiSandbox from *inside* the antivirus profile, so
WildFire conversion couples to AV (verified on the 601F).
- A rule's `wildfire-analysis` reference (direct or via profile-group) enables
  FortiSandbox on that rule's antivirus profile: profile-level
  `set analytics-db enable` + per-protocol `set fortisandbox block`.
- AV + WildFire on one rule → one `av-<virus>-wf` profile; WildFire with no
  antivirus → a derived `av-wildfire-wf` (AV-scan + sandbox on the common
  protocols). Deduped by (virus, wildfire) so a virus profile used with and
  without WildFire yields distinct, correctly-named profiles.
- Loudly flagged: FortiSandbox **requires** a device-level
  `config system fortisandbox` (appliance or FortiSandbox Cloud), which is not
  part of the converted policy package — PAN public-cloud ≈ FortiSandbox Cloud,
  private-cloud ≈ a FortiSandbox appliance.
- Only **Data Filtering → DLP** now remains unconverted among PAN profile types.
- model: AvProfile.sandbox. Verified e2e vs the live 601F (AV+WildFire and
  WildFire-only profiles), schema-cert clean (0 unknown tables/attrs).
  332 tests (+2).

### v0.52.1 — shipped 2026-06-16 (PAN custom URL categories → FortiOS webfilter urlfilter tables)
Per-URL fidelity to complement the FortiGuard category mapping. Real enterprise
PAN profiles lean on explicit allow/block URL lists; before this only the
predefined-category side converted.
- `parse_profiles` indexes `custom-url-category` (under profiles/ or the vsys),
  classifying each as a **"URL List"** (explicit URLs) or **"Category Match"**
  (a bundle of predefined categories).
- `_webfilter_for` now classifies every member of a url-filtering profile's
  action lists: predefined category → FortiGuard ftgd-wf filter (as before);
  custom **URL List** → entries in a FortiOS `webfilter urlfilter` table
  (`*` → wildcard, else simple; PAN action → urlfilter action block/monitor/
  allow); custom **Category Match** → expanded to its member categories.
- emit: `config webfilter urlfilter` tables (numeric id) emitted first; each
  webfilter profile references its table via `config web / set urlfilter-table
  <id>`. Profiles can now be category-only, URL-only, or both.
- model: WebFilterProfile.urls. Verified e2e vs the live 601F (wildcard +
  simple URL entries, table reference), schema-cert clean (0 unknown
  tables/attrs). 330 tests (+2).
- Builds on the other session's code-review fixes (HEAD was 59f68b7 incl. the
  names.py per-namespace fix); merged clean, all features intact.

### v0.52.0 — shipped 2026-06-16 (PAN anti-spyware/vulnerability → FortiOS IPS sensors, severity + CVE crosswalk)
Closes the last PAN security-profile gap — accurately, and stated plainly.
There is **no PA Threat-ID → FortiGuard-signature crosswalk** (for any tool, FC
included), so per-signature conversion is impossible; fwforge maps the **profile
intent** faithfully and flags what can't be carried — posture parity, never
guessed.
- `parse_profiles` reads `profiles/vulnerability` + `profiles/spyware`
  (severity, cve, host, action per rule + threat-exceptions + botnet-domains
  sinkhole). A rule's profile-setting (direct or via group) merges the vuln +
  anti-spyware refs into **one** FortiOS IPS sensor (lazy + deduped).
- Severity rules → severity-filter entries, **first-match per severity**
  (order-independent). PAN action → FortiOS (`default` = FortiGuard-recommended,
  alert → monitor, allow → pass, drop → block, reset-* → reset, block-ip →
  block + attacker quarantine).
- **The standout — CVE crosswalk:** CVE-pinned PAN rules → exact FortiOS
  `set cve` entries (FortiOS IPS supports a `cve` filter — verified). Log4Shell
  (CVE-2021-44228) etc. map precisely. This is the one real cross-vendor key.
- Built-in/undefined PAN profiles (default/strict) → FortiGuard stock sensor
  (`default` / `high_security`).
- **Not carried (flagged with PAN threat IDs, never guessed):** per-threat
  exceptions (no crosswalk), DNS sinkhole (→ FortiOS DNS filter), host
  client/server scoping. WildFire (→ FortiSandbox) and Data Filtering (→ DLP)
  are now the only unconverted PAN profile types.
- emit `config ips sensor`; policy += `set ips-sensor` + utm-status +
  ssl-ssh certificate-inspection. Also fixed AV decoder action parsing to
  handle the element form (`<action><reset-both/></action>`) via a shared
  `_pa_action`.
- model.IpsSensor + cfg.ips_sensors + Policy.ips_sensor. 293 tests (+2).
  Verified e2e vs the live 601F (severity + CVE entries + policy attach),
  schema-cert clean (0 unknown tables/attrs).

PAN security-profile coverage is now complete except WildFire / Data-Filtering:
App-ID (signature-level), URL (webfilter), file-blocking (file-filter),
antivirus, and IPS.

### v0.51.0 — shipped 2026-06-16 (PAN antivirus → FortiOS antivirus profiles + app-DB freshness warning)
- **AV conversion**: PAN antivirus/virus profiles → FortiOS antivirus profiles.
  `parse_profiles` reads `profiles/virus` decoders; a rule's profile-setting
  (direct or via profile-group) resolves to an av-profile, built lazily and
  deduped. PAN decoder protocol → FortiOS (http/smtp/imap/pop3/ftp; smb→cifs)
  and decoder action → av-scan (default / drop / reset-* → block, alert →
  monitor, allow → disable). A built-in/undefined PAN AV profile
  (default/strict) emits a sensible block-on-common-protocols profile + flag.
  emit: `config antivirus profile / config <proto> / set av-scan`; policy gets
  `set av-profile` + `set utm-status enable` + `set ssl-ssh-profile
  "certificate-inspection"` (HTTPS AV needs deep-inspection — noted). The
  FortiGuard AV engine + signatures do the scanning; only per-protocol scan
  intent is carried. Anti-spyware / vulnerability (PAN's IPS) stay unconverted
  (signature-level) but flagged. Verified e2e vs the live 601F, schema-cert
  clean (0 unknown tables/attrs).
- **App-DB freshness**: conversions use the cached FortiGuard app DB and do
  NOT phone home per run (deterministic/offline, by design). `run_cross` now
  warns when the cache is >30 days old (FortiGuard adds App-IDs continuously) —
  refresh with `fwforge app-db <host> --token`.
- model.AvProfile + cfg.av_profiles + Policy.antivirus. 291 tests (+3).

### v0.50.0 — shipped 2026-06-16 (per-application App-ID signatures via the FortiGuard app DB)
Closes the App-ID granularity gap with FortiConverter: PAN App-IDs now map to
specific FortiOS application-control **signatures**, not just FortiGuard
categories. Same clean-room model as schema-cert — the signature DB is fetched
from the user's OWN FortiGate and cached locally, never shipped in the repo.
- **NEW `fwforge/appdb.py`**: fetch the FortiGuard application signature DB
  (~3,300 sigs: id / name / category) from a live FortiGate over REST
  (`GET /api/v2/cmdb/application/name`), cache under `~/.fwforge/appdb/`, never
  commit. `build_index()` → canon(name) → {id, name, category}.
- **`pan_appid.map_to_sigs()`**: PAN App-ID → signature ID(s) via (1) a curated
  PAN→FortiOS name alias table (`PAN_SIG_ALIAS`, verified against the live 601F:
  web-browsing→HTTP.BROWSER, ms-teams→Microsoft.Teams, ms-office365→
  Microsoft.365, ms-rdp→RDP, citrix→Citrix.ICA, smb→SMB.v1/2/3, …), then (2)
  exact normalized-name match (catches Gmail/Facebook/YouTube/Zoom/Slack/
  Salesforce/… with no alias). Apps with no signature fall back to FortiGuard
  categories; transport apps (ssl/tls) ignored; nothing convertible dropped
  silently.
- **emit**: `config application list` entries now emit `set application <ids>`
  for matched signatures plus a `set category` entry for the fallback.
- **Opt-in** like schema-cert: `run_cross(app_db=…)`; CLI `fwforge app-db <host>
  --token` fetches/caches (+ `--list`), `convert --app-db/--no-app-db`; GUI
  auto-uses the newest cache. Without a DB it stays category-level (so
  conversions and tests are deterministic).
- model.AppList += `applications` / `app_sig_names`. 288 tests (+5).
- VERIFIED end-to-end against the live 601F: 8 SaaS App-IDs → 8 signature IDs
  (Facebook 15832, Gmail 15817, YouTube 31077, Microsoft.Teams 43541,
  Microsoft.365 33182, Salesforce 16920, HTTP.BROWSER 15893, Dropbox 17459),
  schema-certified clean (0 unknown tables / attrs).
- FUTURE: the 601F is the reference DB for now; a better long-term source
  (multi-version bundle / FortiGuard feed / Fortinet-sanctioned mapping) is the
  next step Adam flagged.

### v0.49.0 — shipped 2026-06-16 (PAN security profiles: URL filtering → webfilter, file blocking → file-filter)
Converts the two PAN security-profile types that are category/type-level
(clean-room-safe). Before this, only App-ID → application-control was generated;
everything else under `profile-setting` was flagged "attach manually".
- **URL filtering → FortiOS webfilter (FortiGuard category) profile.** New
  clean-room map `parsers/pan_urlcat.py` (PAN category → FortiGuard category
  id). The ~93 FortiGuard category IDs were **VERIFIED live** against the 601F
  (FortiOS 8.0.0 b0167) via `GET /api/v2/monitor/webfilter/fortiguard-categories`.
  PAN per-category action → ftgd-wf action (block→block, alert→monitor,
  continue→warning, override→authenticate; allow dropped). One PAN category can
  expand to several FortiGuard ones (alcohol-and-tobacco → Alcohol + Tobacco).
  PAN risk-level buckets (high/medium/low-risk, real-time-detection) and any
  unmapped category are FLAGGED, never guessed.
- **File blocking → FortiOS file-filter profile.** New map
  `parsers/pan_filetype.py` (PAN file-type → FortiOS file-type; valid FortiOS
  types verified live via `/cmdb/antivirus/filetype`). PAN action →
  file-filter action (block / log-only / warning). "any" + unmapped types flagged.
- **Parser**: `parse_profiles` reads `profiles/url-filtering` + `file-blocking`
  + `profile-group`; a rule's `profile-setting` (direct or via group) resolves
  to a webfilter + file-filter profile, built lazily and deduped by source
  name. Shared/Panorama profiles already merge into the vsys scope. AV /
  anti-spyware / vulnerability / WildFire / data-filtering stay UNCONVERTED
  (signature-level, clean-room-blocked) but are flagged per rule.
- **Emit**: `config webfilter profile` (ftgd-wf filters) + `config file-filter
  profile`; policies get `set utm-status enable` + `set ssl-ssh-profile
  "certificate-inspection"` (SNI-based, no CA rollout) + `set webfilter-profile`
  / `set file-filter-profile`. The whole emitted shape is **SCHEMA-CERTIFIED
  clean** (0 unknown tables/attrs) against the live 601F 8.0 schema.
- model: `WebFilterProfile`, `FileFilterProfile` + `cfg.webfilters` /
  `.file_filters` + `Policy.webfilter` / `.file_filter`. 284 tests (+6).

### v0.48.1 — shipped 2026-06-16 ("do not map" option + faceplate/LAG fixes)
Review feedback off a live PAN→701G run.
- **"— do not map —" dropdown option** on every physical-port row: leaves
  that interface unmapped (excluded server-side via the new
  `_mapping_from_form`, sentinel `__none__`) and **frees its target port to
  be bonded into a LAG**. The skipped source port no longer shows amber
  ("no home") on the faceplate, and its "maps to" isn't flagged red.
- **Faceplate / new-LAG lighting**: a LAG member that is *also* a mapped
  physical's target is a genuine collision and correctly lights **red**
  (not green) — the fix is to set that physical to "do not map", which frees
  the port and turns the LAG member green. (Root-caused from the report that
  a created aggregate's ports "didn't light up": they were double-claimed.)
- **Model-switch staleness fix**: switching the target model now drops
  invalid member ports from *created* and *promoted* LAGs too (previously
  only source-derived LAGs re-derived; a created LAG kept stale ports that
  silently failed to light). Generalizes v0.48.0's promoted-only filter.
- Note on `tunnel.1` & friends: a source tunnel interface is only emitted
  when it has an IPsec phase1 (it's built by the VPN section), so an orphan
  tunnel is already left out of the output regardless of its "maps to".
- Verified live (collision → "do not map" → green; skip persists across
  model switch; no console errors). 278 tests (+1). Changes:
  webui/templates/plan.html, webui/app.py, tests.

### v0.48.0 — shipped 2026-06-16 (VLAN inheritance + promote physical → aggregate in place)
Makes the "physical port carrying VLANs" case (PAN `ethernet1/6`) easy,
replacing the clunky "create a separate aggregate, then re-parent each VLAN
by hand" flow (whose created-LAG was hard to pick from the VLAN dropdown).
- **VLAN inheritance** (`refreshNestOptions`): each VLAN's parent dropdown
  now defaults to its parent's mapped target — `vlanParent(d)` = the
  parent's "maps to" port or LAG — so mapping (or promoting) the parent
  flows to all of its VLANs automatically. A per-VLAN override still wins.
  Also made the desired parent always selectable (a LAG renamed live in its
  "maps to" field is no longer missing from the dropdown, which had silently
  dropped the choice to the first option).
- **Promote physical → aggregate in place**: every physical interface row
  carries a `physical ↔ 802.3ad aggregate` type toggle (`ifTypeChanged`).
  Flipping to aggregate gives that row the member-chip picker + LACP control
  (reads identically to a source LAG like `ae1`), turns its "maps to" into
  the LAG name (default = sanitized source name via `safeIfName`, e.g.
  `ethernet1/6` → `ethernet1-6`), seeds the port it used to map to as the
  first member, and auto-nests its existing VLAN children onto it. Toggling
  back restores the physical port dropdown. Faceplate counters skip promoted
  ports (they light via the LAG chips, not a 1:1 map).
- emit/apply_authoring: `apply_authoring` now promotes a source physical
  interface **in place** when an aggregate spec's name equals that physical's
  mapped target (the promotion signal the GUI sends) — same Interface object,
  so its IP / description / VLAN children ride the LAG; no duplicate
  interface. A separately-named new LAG that merely bonds a port is still a
  distinct create (unchanged). VLANs resolve onto the promoted LAG and emit
  after it (`_dependency_order`).
- Verified end-to-end against the running GUI (PAN `ethernet1/6` + two
  VLANs → `set type aggregate` + members, both VLANs `set interface` the LAG,
  emitted in dependency order). 277 tests (+2). Changes:
  webui/templates/plan.html, transforms/portmap.py, tests.

### v0.47.1 — shipped 2026-06-16 (created LAGs as tree rows + description restored + faceplate lights LAG members)
- Created aggregates now render as first-class rows in the interface tree
  (buildTree: renderNewAggRows + effective-parent grouping), not a separate
  panel — "+ Add aggregate" adds an 802.3ad aggregate row with a name
  field, LACP, and a member-port chip picker; nesting a VLAN onto it (its
  parent dropdown) moves the VLAN under it.
- Restored the interface description (dropped in v0.47.0's column
  restructure) as a muted sub-line under the interface name.
- Faceplate fix: a LAG's members come from the chips (AGGS), so
  refreshFaceplates counts the chip members (skipping the absorbed
  member-rows' own dropdowns to avoid false collisions) and re-runs on chip
  edits — the LAG's FortiGate ports (x5-x8) light green as assigned.
- 275 tests. (All v0.47.1 changes are in webui/templates/plan.html.)

### v0.47.0 — shipped 2026-06-16 (cross-vendor aggregate authoring + FortiOS-style interface page)
Big interface-mapping overhaul for cross-vendor (PAN -> FortiGate):
- emit: aggregates are emitted BEFORE the VLAN subinterfaces that nest on
  them (`_dependency_order()` in emit/fortios.py) — fixes a load-breaking
  script where `set interface "ae1"` ran before ae1 existed.
- LACP mode parsed from the source aggregate (active/passive/static) and
  emitted, instead of a hardcoded `set lacp-mode active`. PAN parser reads
  <lacp>; IR gains Interface.lacp_mode.
- GUI interface page rebuilt to the FortiOS Network>Interfaces layout: a
  collapsible tree (name / type / members / ip / maps to), parent rows
  lead their group (aggregates float to top), default-expanded, member
  ports + VLANs nest beneath. Live membership: a VLAN shows its parent
  LAG's member ports.
- Aggregate authoring (transforms/portmap.apply_authoring): create a LAG
  the source didn't have, set LACP, re-nest VLANs onto any parent. A LAG's
  members are a FortiGate-port SET picker (chips + "+ port") with an
  "absorbs ethernet1/13-16" caption — no per-member dropdowns (LAG members
  are interchangeable). References (zone/route/VIP/NAT) from a bonded port
  repoint to the LAG; absorbed source ports recorded for traceability.
- 275 tests.

### v0.46.1 — shipped 2026-06-15 (cross-vendor source faceplate labeled by vendor)
Bugfix (Adam caught): the mapping-step source faceplate silkscreened
"FortiGate" for a Palo Alto (or any non-FortiOS) source. source_platform
is only set on the FortiOS path (it reads the #config-version header), so
SOURCE_PLATFORM was empty cross-vendor and srcModel fell back to a
hardcoded "FortiGate". plan.html now plumbs SOURCE_LABEL (vendor_label) +
SOURCE_FOREIGN through: the source wordmark + fp-src-name use the vendor
label ("Palo Alto", "Cisco ASA", ...), the bezel split keeps a
no-numeric-model label whole (no "Palo / ALTO"), and a foreign source
drops the Fortinet-red accent for neutral grey so the panel doesn't read
as a FortiGate. Generalizes to ASA/SRX/pfSense; destination unchanged.
Regression test + a foreign=false assertion on the FortiOS path. 270 tests.

### v0.46 — shipped 2026-06-15 (aggregate awareness on FortiOS->FortiOS too)
Adam: aggregates + nested VLANs must surface in the FGT->FGT flow, not
just cross-vendor. tree_interface_details() (the tree path's iface
details) now detects kind: aggregate/redundant bundles + their member
ports (kind=aggregate-member, type forced physical so they get a port
dropdown), VLANs (kept nested on their parent), loopbacks, tunnels —
same awareness the cross-vendor IR path got in v0.44/45. 601F verified:
fortilink (member x8) + WAN_SWITCH (member x1) detected as aggregates,
x1/x8 as members, 37 VLANs. The tree already portmapped members + kept
VLANs nested; this adds the GUI surfacing (badges + member dropdowns).
269 tests.

### v0.45 — shipped 2026-06-15 (cross-vendor mapping dropdowns + white faceplate)
(1) The destination-port dropdowns/faceplate/target-picker now work for
cross-vendor (PAN/ASA/SRX -> FortiGate), not just FortiOS->FortiOS:
iface_details built for cross-vendor sources, plan.html gated on `det`
not vendor; physical + aggregate-member rows get port dropdowns, other
kinds keep their name; new aggregate / "in <ae>" / vlan membership
badges. Verified: TIS->701G shows 10 dropdowns (6 physical + 4 ae1
members) from the 701G backup; ae1 stays a name. (2) Faceplate reskinned
WHITE like the real FortiGate (silver chassis, dark port openings,
colored link LEDs). 269 tests.

### v0.44 — shipped 2026-06-13 (rebuild aggregate interfaces as LAGs)
Adam: aggregates weren't a feature (member ports were dropped + flagged).
model.Interface += kind/members; PAN parser captures aggregate-ethernet
+ keeps member ports as kind=aggregate-member linked to the bundle;
NEW emit/fortios interfaces() section creates aggregates (set type
aggregate + mapped members + lacp-mode active), VLAN subinterfaces (type
vlan + parent + vlanid + ip), loopbacks — cross-vendor emitted NO
interfaces before. TIS: ae1 -> LAG of lan13-16, ae1.1 carries the L3.
269 tests. NEXT: GUI cross-vendor mapping dropdowns.

### v0.43 — shipped 2026-06-13 (App-IDs -> FortiOS BUILT-IN named services)
Adam: "by ports I mean services on the FortiGate." pan_appid.APP_TO_BUILTIN
(verified read-only against the live 8.0 service catalogue) maps App-IDs
to FortiOS built-in service names; _appdefault_services reworked to
resolve PER APP (groups expanded to leaves) — built-in name where one
exists (SMB, SAMBA, HTTPS, DNS, KERBEROS, LDAP, MS-SQL, MYSQL, RDP,
SNMP, SSH, ...), else a per-app appdef custom service. The old
merge-everything-by-proto is gone, so each app keeps its own service.
TIS result: native services everywhere — SMB x111, HTTPS x97, RDP x57,
SAMBA x30, KERBEROS/LDAP, MS-SQL; only genuinely-no-builtin apps
(msrpc/135) stay custom. 267 tests.

### v0.42 — shipped 2026-06-13 (PAN subnet 1:1 destination NAT -> range VIP)
The one TIS conversion error (Ericsson NAT Rules-1: /24 -> /24
destination NAT) now converts. _resolve_range() turns a subnet/range
address into the FortiOS range form; parse_nat emits a 1:1 range VIP
when extip/mappedip are equal size (FortiOS maps them one-to-one),
errors clearly on size mismatch. TIS conversion is now 0 errors.
267 tests.

### v0.41 — shipped 2026-06-13 (App-ID -> port/port-group SERVICE on policies)
Adam: "convert application ID's to ports or port group based policies."
Chosen (AskUserQuestion): scope = application-default + service=any;
app-control = keep both. paloalto._app_service() resolves a rule's
App-IDs (groups expanded) to their standard ports and fills the policy
SERVICE: a single appdef-* service, or a deduped ServiceGroup
(appsvc-grp-N "port group") when several. service=any + apps now
tightens to the apps' ports instead of ALL; unknown/dynamic-port apps
safely stay ALL. The app-control application-list profile is kept on
top (utm-status). TIS result: 190/379 policies now port-based, 44 port
groups created. 266 tests.

### v0.40 — shipped 2026-06-13 (App-ID -> ports + app-control profiles, deeper)
Adam (off the Jabil TIS PAN-OS 11.1 config): convert apps to the right
ports AND the App-IDs to the right app-control profiles, creating
profiles as needed.
- pan_appid expanded with 29 enterprise App-IDs (MS infra: msrpc/wmi/
  netlogon/smbv2-3/mssql/AD/kms/netbios-ss/winrm; SaaS: okta/azure/
  crowdstrike/defender; backup/web/diag) -> FortiGuard categories AND
  standard ports. _norm now also strips -encrypted/-unencrypted.
- paloalto._app_list_for now EXPANDS custom application-groups to their
  leaf App-IDs before mapping (a rule using jabil_serv_mysql_smb_app maps
  mysql+smb+rpc instead of failing on the group name).
- TIS result: app-default "kept as ALL" 121->25, "no app-control
  category" 80->2, 40 app-control profiles created, 67 appdef port
  services emitted, total warnings 484->388. 265 tests.

### v0.39.1 — shipped 2026-06-13 (detect Panorama template-merged PAN configs)
Real Jabil TIS PAN-OS 11.1 running-config failed detection — a
template-stack-merged export has ptpl="..." on every tag, so the bare
`<devices>` / `<entry name="localhost.localdomain">` literals never
matched. detect() now matches tag prefixes + the
urldb="paloaltonetworks" signal. The 2.5MB config then parses cleanly
(38 ifaces, 2629 addrs, 379 policies, 28 VIPs, 100% accounted). 263 tests.

### v0.39 — shipped 2026-06-13 (auto-guess positional port mappings)
Adam: auto-guess simple mappings (601F port1 -> 701G lan1) so he doesn't
map all of them. platforms.guess_portmap(src, dst): exact-name matches
keep themselves (mgmt/x1-x8), the source's largest <prefix>N series maps
by number onto the destination's largest unused series (port1->lan1 ...
port22->lan22), ambiguous ports (port23/24, spare wan1/2) left for the
user, never double-maps a destination. Computed server-side for the
backup and every inventory model, injected as GUESS_BACKUP /
GUESS_BY_MODEL; the dropdowns default to the guess (overridable, the
prompt+red-outline shows what still needs a pick). 262 tests.

### v0.38 — shipped 2026-06-13 (physical-port targets are real dropdowns)
Adam: the mapping target must be a dropdown that knows ALL the
destination model's ports (601F port1 -> 701G lan1). Physical source
ports now render a <select> populated client-side with the destination's
real ports (from the uploaded backup = authoritative all-ports, or the
model PORT_INVENTORY); same-name auto-selects, an unmatched source shows
"<name> — choose a port" + red outline. VLANs/tunnels keep free-text
(names carry over). Faceplate click-to-wire and the red-outline
validation both work with the selects. 259 tests.

### v0.37 — shipped 2026-06-13 (zone/SD-WAN membership in the mapping grid)
Pre-zoned 601F (3rd-Rail-02) — policies reference zone names, members
hidden behind zones. New "membership" column on the Interface Mapping
step: teal "zone: X" / amber "SD-WAN" badges from iface_details, so the
zone structure is visible while mapping ports (complements the
physical-only faceplate). 258 tests.

### v0.36 — shipped 2026-06-12 (destination identity carried + output named for it)
Adam: the converted config should take the destination box's identity
(hostname etc.) and the file should be saved as the destination gate.
- platforms.device_identity(): reads DEVICE_IDENTITY_ATTRS (hostname,
  alias) from a config's `config system global`; safe_filename() for
  stems.
- run_migrate(target_identity=...): _apply_device_identity rewrites the
  output's system global hostname/alias to the destination's, reported
  as an info + meta.identity_from_destination.
- Output (and all artifacts) named for the destination hostname:
  701G-TOP.conf, not the source stem. CLI derives it from
  --target-config; GUI from the stored target_hostname; download/bundle
  routes use the result stem.
- Still NOT a merge: identity only, policies/objects stay out (the
  declined feature). Notes updated to say so. Real pair: output
  701G-TOP.conf, hostname DC-Firewall-601F-A -> 701G-TOP, 0/0 clean.
  257 tests.

### v0.35.1-.3 — shipped 2026-06-12 (faceplate polish)
.1 FortiOS-look restyle (chassis, RJ45 notch/SFP latch, link-light
colors, labels outside the ports) + old-job source_platform backfill.
.2 model wordmark bezel (brand over model number, red accent; text
nominative branding, no logo artwork). .3 fixed the 601F faceplate to
split x1-x4 (10G SFP+) / x5-x8 (25G SFP28) — Adam caught all eight
x-ports lumped as 10G; verified x5-x8 = speed 25000full in the backup.
Key finding: config `set speed` = installed optic, NOT cage type (701G
SFP28 cages report 10000full with 10G optics in), so faceplates show
physical cage type from hand-authored specs — a derive-from-config
would have mislabeled the 701G. 255 tests.

### v0.35 — shipped 2026-06-12 (live faceplates on the mapping step)
Adam's design: schematic front panels for source + destination above
the mapping grid, ports lighting as you wire them. FACEPLATES specs
(600F/601F, 700G/701G per verified QSG layout, 60F/61F; generic strip
fallback from the port list), header_platform() picks the source model
off the config header. Blue glow = focused pair, green = wired,
red = collision (two sources -> one port), amber = no home on the
destination. Click a source port to jump to its row; click a
destination port to wire it. Invariant: faceplate == PORT_INVENTORY.

### v0.34.1 — shipped 2026-06-12 (lineup ceiling: 4801F)
Adam's call: no 6000/7000-series; 4801F tops the list. Added the seven
x01 bundle siblings (1801F…4801F) via the 4-char K-rule extension
(4801→FG4K81F) — least-anchored codes in the table, all * /unverified.
71 models total. 251 tests.

### v0.34 — shipped 2026-06-12 (dropdown expanded to the full retail lineup)
~35 → 64 models per Adam's "every current model" ask: full G-series
desktop, F desktop + FortiWiFi + Rugged, E-series mid-range
(H-substitution), F/G mid-range, F high-end through 4800F (thousands
K-pattern: 1800F=FG1K8F, 3001F=FG3K1F). All new entries marked * /
unverified; hardware-verified stay FGT60F / FG6H1F / FG7H1G. Excluded
on purpose (custom code or destination backup instead): x501/x801
variants (ambiguous vs the K-rule), 7000-series chassis, non-FGVM64
VM tokens. 250 tests.

### v0.33 — shipped 2026-06-12 (zone-subsystem review hardening)
Adversarial self-review pass over the zone piece; five fixes, none
triggered by Adam's config but all real: proxy-policy added to
ZONE_CAPABLE_PATHS (zone-capable, was audit-only); `set member` audit
scoped to interface-member contexts (addrgrp member named like a moved
interface = object ref, was a false warning); dedup/conflict policy
fingerprints made value-order-insensitive (srcaddr "a" "b" == "b" "a");
same-zone flag covers security-policy; zone-extend reports on both
paths. Real-pair regression guard: output byte-identical outside the
embedded report header. 249 tests.

### v0.32.1 — shipped 2026-06-12 (FG7H1G verified on real hardware)
The real 701G's first backup (701G-TOP, 7.4.11 build2878) confirmed the
derived platform code FG7H1G AND the QSG-derived 34-port inventory
exactly (zero differences). Entries promoted to verified. Platform
header-rewrite finding downgraded to info when the code comes from a
destination backup. Real-pair run (601F 8.0 → 701G 7.4.11): 0 errors,
4 warnings (24-port must-remap list + 2 legit downgrade artifacts).
NOTE: the 701G runs 7.4.11 — recommend upgrading it to 8.0.0 build0167
(matching the 601F) before the restore, then re-snapshot it as the
destination file so the version delta disappears.

### v0.32 — shipped 2026-06-12 (destination reference backup — Adam's design)
Adam: "config file in one selection and a blank config of the
destination so that you can combine them sort of like FortiConverter."
A second optional file at job creation — any backup taken ON the
destination device (factory-fresh ideal) — replaces probing and curated
tables with ground truth:
- `platforms.inventory_from_config()`: platform code + version from the
  `#config-version` header, physical port names from `config system
  interface` (modem/dotted/virtual filtered out).
- The code is authoritative (dropdown replaced by a locked display),
  the version pins the target train, the ports feed the mapping-step
  datalist/red-outline from page load.
- `run_migrate(target_device=...)`: warns with the exact must-remap
  list — physical source interfaces whose output name does not exist
  on the destination — plus an info line of the destination's ports.
- CLI `--target-config FILE` (conflicts with --target-platform raise),
  GUI second upload + path field. Reference ONLY: nothing from the
  destination file is merged into the output (standalone-config rule
  stands — this is not the declined merge feature).
Demo on the real 601F backup + QSG-derived factory 701G: instantly
lists all 24 portN names that must be remapped and the 34 valid
destination ports. 247 tests.

### v0.31 — shipped 2026-06-12 (per-model port inventories in the mapping step)
PORT_INVENTORY in platforms.py: physical interface names per platform
code, confirmed-only with provenance — 600F/601F from the real 601F
backup (ha, mgmt, port1-24, x1-x8), 700G/701G from Fortinet's FG-700G
QSG front panel (ha, mgmt, wan1/2, lan1-22, x1-x8 — NO portN names!),
60F/61F from a live lab pull (wan1/2, dmz, internal1-5, a, b).
GUI: picking a target model feeds a datalist into every portmap target
input, shows the model's full port list, and outlines red any mapped
name for a PHYSICAL source port that does not exist on the target
(VLANs/tunnels keep their names, never flagged). Found the real
601F→701G trap: not one of the 601F's port1-24 exists on the 701G —
the portmap step is mandatory, not optional, for that migration.

### v0.30 — shipped 2026-06-12 (zone ramifications round 2 + schema-check honesty)
All four driven by the live 601F→701G "core" zone migration:
- **associated-interface rebind**: apply_zones rewrites member-bound
  `set associated-interface` to the new zone (address/addrgrp, v4+v6) —
  FortiOS rejects member-bound addresses in policies that now reference
  the zone; previously the 2 affected policies would have been dropped
  on restore while 19 identical-looking warnings pointed everywhere else.
- **leftover triage**: ZONE_EXTRA_ALLOWED covers provably-legitimate
  stays (interface-subnet addresses, ntp listen, radius source-intf,
  on-demand-sniffer, multicast-policy) — the 601F report went from 27
  warnings to 1 (the platform-verify reminder).
- **--fortios defaults to the source version** for FGT→FGT (no silent
  8.0→7.4 downgrade pass); cross-vendor keeps 7.4.
- **schema-check exemptions** for what a same-build backup proves
  loadable: `config rule *` FortiGuard dumps (5,828 blocks!), replacemsg
  / gui-dashboard-collection, internal attrs (dirty, tag-uuid, vap1-8…).
  Same-build certification of the 601F backup is now CLEAN (was 8
  errors / 6,020 findings). Regression invariant: a device's own backup
  vs its own build must produce zero findings.

### v0.29 — shipped 2026-06-12 (target-model dropdown + platform-code resolver)
Born from a real migration miss: `701g` typed into the free-text platform
field produced `#config-version=701g-...`, which the target FortiGate
would reject on restore (platform token must match the device exactly).
- New `fwforge/platforms.py`: curated model→code table (codes marked
  verified were read from real headers: FG6H1F from the 601F backup,
  FGT60F from a lab FGSP member; the rest derived from the naming scheme
  — FGT prefix desktop, middle-zero→H like 601F→FG6H1F, thousands→K) +
  `resolve()` accepting code / bare model number / SKU / product name in
  any case ("701g" → FG7H1G). Garbage → PlanError with closest-model
  hints; plausible unknown codes pass with a verify note.
- GUI Target card: platform free-text replaced by a grouped **target
  model dropdown** (Desktop/Mid-range/High-end/Virtual, codes shown,
  `*` = derived + footnote) with a custom-code escape hatch; the posted
  value runs through `resolve()` server-side either way.
- CLI `--target-platform` now resolves through the same table and echoes
  the resolution (`target platform: FG7H1G (FortiGate 701G: code
  derived...)`).
- 10 new tests (resolver matrix + webui dropdown/custom/garbage paths).

### v0.28.1 — shipped 2026-06-12 (bug scrub of v0.22-v0.28)
Five parallel review agents over all code added since the last scrub
(schema engine, version-delta, PAN Panorama/vsys, Juniper SRX, BGP/OSPF,
routing-instances->VDOM, pipeline assembly, web UI). XSS/token-leak
claims came back CLEAN. ~20 real bugs fixed; 228 tests (11 new). Worst
first:
- **SRX bracketed value lists** `[ a b c ]` kept literal `[`/`]` tokens
  -> bogus address refs / services widened to ALL. Now flattened in
  both readers. (pervasive Junos idiom — high impact)
- **SRX `inactive:` marker** in `show configuration` silently dropped/
  corrupted whole stanzas; now stripped + the stanza marked disabled.
- **SRX set-format VPN** got DEFAULT crypto: `proposals` was a `_PLAIN`
  container (removed) and `proxy-identity` selectors collapsed to
  0.0.0.0/0 (added to `_PLAIN`). Both restored to curly parity.
- **Emitter newline-in-comment** (`_q`) corrupted branch-file splitting
  when a comment value line was exactly `end`/`config ` — now folded to
  literal `\n` (fixes all vendors; PAN multi-line descriptions).
- **Pipeline VDOM header-strip** dropped any body line starting with `#`
  (a `#` inside a `set comment`) — now strips only the leading header.
- SRX: nested `application-set` membership captured; `_resolve_app`
  per-path cycle set (diamond app-sets no longer -> ALL); set-format
  range/fqdn/wildcard addresses; apply-groups multi-valued leaves
  accumulate; `deactivate <stanza>` honored; static-nat nested prefix;
  dest-nat empty-pool guard.
- PAN: Panorama post-rulebase order (DG-post before shared-post);
  `application-default` + named service no longer drops the named one;
  base interface no longer duplicated into every VDOM importing a
  subinterface; false "pre/post-rulebase not converted" findings;
  template coverage-claim narrowed to network/zone.
- schema: nested-table first-token fallback now requires a real table
  (scalar attr no longer masks an unknown section); `resolve()` IPv6/
  named-port guard; `check()` friendly error without `tables`.
- versiondelta: nested-only sections (e.g. `system npu`) counted as
  present so removed/note/introduced rules fire.
- web UI: `esc()` now escapes `>` (cosmetic parity).
- Deferred by design (agent-confirmed not output bugs): per-scope
  policy-selection of same-named replicated globals (needs scope-aware
  selection UI); omitted-singleton `system settings` flip (scanner only
  sees the tree); `_save_job` silent OSError (acceptable for a local
  tool).

### v0.28 — shipped 2026-06-12 (SRX finished: routing-instances, policy-VPN, +)
- [x] **routing-instances -> VDOMs**: `_partition_by_ri` splits the
      parsed config into per-instance FirewallConfigs (default = 'root')
      and hands the pipeline `vsys_cfgs` — same VDOM-block machinery the
      PAN multi-vsys work built. Interfaces/zones/routes partition by
      instance membership; policies follow their zones (VPN policies
      follow the tunnel's interface); Junos global policies replicate
      into every VDOM; per-instance routing-options static routes land
      in their VDOM; objects replicate per VDOM (FortiOS scopes them).
      Cross-instance zones/policies flagged + kept in root. Pipeline
      `_vdom_names` clamps scope names to valid VDOM names (11 chars,
      charset) with a warning. Schema-certified CLEAN vs live 8.0.
- [x] **Policy-based VPN -> route-based**: `permit { tunnel { ipsec-vpn
      X } }` policies are captured; an ipsec vpn with no bind-interface
      now builds a route-based tunnel using the permit-tunnel policies'
      addresses as phase2 selectors (resolving address objects/groups ->
      CIDRs), and the original policies are emitted disabled + annotated.
      Range/fqdn selector addresses flagged.
- [x] **Wildcard apply-groups** (`<ge-*>`, `unit <*>`) merge into every
      existing matching stanza (real Junos wildcard semantics, any key
      position via fnmatch); per-attribute dst-wins so explicit config
      overrides inherited group leaves.
- [x] **host-inbound-traffic -> allowaccess guidance**: zone/interface
      system-services (ssh/ping/https/...) become a `set allowaccess`
      hint on the mapped port; ike/dhcp and unmappable services noted.
- [x] **logical-systems** flagged as a hard error (separate security
      contexts — convert each separately). Coverage map consumes
      routing-instances/logical-systems.
      217 tests (6 new). SRX is now feature-complete for v1.

### v0.27 — shipped 2026-06-11 (dynamic routing: BGP + OSPF)
- [x] **BGP/OSPF conversion** for SRX and Palo Alto (per Adam's
      follow-up). IR gained BgpConfig/BgpNeighbor/OspfConfig/OspfArea;
      the emitter writes `config router bgp` (as, router-id, neighbors
      with remote-as/description, network statements, redistribute
      blocks) and `config router ospf` (router-id, areas, network
      statements derived per area, passive-interface with portmap
      applied, redistribute) — emitted shape schema-certified CLEAN
      against the live FortiOS 8.0 build (named
      `config redistribute "connected"` tables included; the schema
      walker learned that named nested tables key by first token).
      SRX: `protocols bgp` groups (type internal -> local AS,
      per-neighbor peer-as overrides, bare + container neighbor forms,
      authentication-key -> error finding), `protocols ospf` areas with
      interface->connected-network derivation, `interface all` and
      export policies flagged (Junos advertises via export — warned
      loudly); router-id/AS from routing-options; coverage map now
      descends into `protocols` (bgp/ospf consumed, lldp etc. unread).
      PAN: virtual-router `protocol bgp` (local-as, peer-groups/peers)
      + `protocol ospf` (areas, passive), redistribution profiles
      flagged, second VR's instance flagged (first wins), honors the
      multi-vsys VR import filter. Missing router-id derives from the
      first interface IP with a warning (both vendors auto-derive
      theirs). FMG device-level note extended to dynamic routing.
      211 tests (5 new incl. curly<->set parity for both protocols).

### v0.26 — shipped 2026-06-11 (Juniper SRX parser + smoothness)
- [x] **Juniper SRX (Junos) parser** (4th cross-vendor source):
      parsers/juniper_srx.py. Both export formats normalized into one
      JNode tree (token-tuple containers + leaf statements); a
      curly<->set parity test guards them. Smoothness features that
      naive converters miss:
      - **apply-groups inheritance** expanded before parsing (deep
        merge, explicit config wins; wildcard `<*>` groups flagged)
      - **zone-scoped address books** flattened to global IR names with
        cross-zone collision renames; global address-book `global {}`
        and flat forms both read
      - **junos-* predefined applications** -> real ports
        (junos_apps.py, ~75 apps curated clean-room); custom
        `application`/`application-set` (recursive) synthesize exact
        services; multi-proto apps become service groups
      - **zone-pair + global policies** -> FortiOS zone policies
        (srcintf/dstintf = zones), address-excluded negation, permit/
        deny, permit-tunnel and UTM profiles flagged
      - **NAT**: source rule-set interface -> nat enable (zone pair);
        pool source-NAT flagged; destination-nat pool -> VIP w/ port
        forward; static-nat -> 1:1 VIP
      - **route-based st0 IPsec**: ike/ipsec proposal+policy+gateway
        resolved, traffic-selector / proxy-identity selectors, PFS,
        IKEv2 detection, $9$-encrypted PSK -> CHANGEME + error
      - context-sensitive set-format parsing (gateway/application are
        named-containers in one place, leaf refs in another)
      - routing-instances flagged as VDOM candidates; XML-style
        coverage map (unread top-level stanzas named + counted)
      Registered in CROSS_PARSERS + detect_vendor; --vendor juniper-srx;
      GUI vendor tile. Also added the missing pfSense home tile. 207
      tests (15 new). Queued: routing-instances -> VDOM (reuse the
      vsys machinery), policy-based VPN, dynamic routing (BGP/OSPF).

### v0.25 — shipped 2026-06-11 (PAN file-only feature wave: #2/#1/#8/#4)
- [x] **Panorama awareness (#2)**: a managed firewall's export merges
      Panorama-pushed pre-rulebase -> local -> post-rulebase in PAN
      evaluation order (pushed objects merge below local); a Panorama
      export itself converts per device-group — `--pa-device-group` /
      GUI select (auto when only one), optional `--pa-template` pulls
      network config + zones from a template; shared objects +
      shared pre/post rulebases merge in; parent-DG inheritance
      flagged (not yet traversed). Section-aware scope merge fixed a
      latent bug where one local address object dropped ALL shared
      addresses.
- [x] **vsys -> VDOM (#1)**: every vsys converts (was: first only) into
      its own FirewallConfig, scoped by the vsys' interface and
      virtual-router imports (interfaces, subinterfaces, routes, IPsec
      tunnels follow their vsys); the pipeline assembles one script
      with a VDOM-creation block + per-vsys `config vdom` blocks, and
      branch files split per VDOM section, each re-wrapped to paste
      standalone (`vsys1-firewall-policy.txt` starts with
      `config vdom / edit vsys1`). `--pa-vsys` converts one vsys only.
      GUI: vsys badge + per-rule vsys column in Policy Selection.
- [x] **XML coverage map (#8)**: the parser declares the subtrees it
      consumes; everything else is counted and named — meta
      `xml_coverage` ("N% of M config values read"), per-subtree
      "unread" findings (capped), and a summary warning when below
      100%. The quantified "nothing dropped silently".
- [x] **App-ID default-ports upgrade (#4)**: custom `application`
      objects' own port definitions (in the file) are parsed —
      including application-groups (recursive) and ip-protocol/icmp
      idents; `service application-default` rules now synthesize TIGHT
      port services (union of every app's default ports) instead of
      broadening to ALL, falling back loudly when any app is
      dynamic/unknown. Curated public default-ports table for ~80
      common predefined App-IDs (clean-room, Applipedia facts);
      application-filters stay unresolvable by design.

### v0.24 — shipped 2026-06-11
- [x] **Schema-certified output (opt-in)** — the first "FC structurally
      can't" feature: validate every emitted section and `set` attribute
      against the EXACT CLI schema of a target firmware build, fetched
      read-only from a live FortiGate (`GET /api/v2/cmdb?action=schema`,
      one request, 712 tables on 8.0) and cached structure-only under
      ~/.fwforge/schemas/ (runtime device data, never shipped —
      clean-room intact). New fwforge/schema.py (stdlib urllib; fetch /
      cache / resolve / check with nested-table + multi-VDOM walks);
      `fwforge schema <host>` + `--list` subcommand; `--schema-check
      HOST|FILE` + `--schema-token` (FWFORGE_API_TOKEN env) on convert;
      GUI checkbox with cached-schema picker or live host+token (token
      used once, never stored). Findings: unknown section = error
      (block dropped on load), unknown attribute = warn (line dropped),
      train-mismatch guard, capped + aggregated output;
      meta schema_check summary; error findings raise the exit code.
      Verified against the live 601F schema: clean fixture certifies
      ("CLEAN vs 8.0.0 build167 — 72 set lines checked"), injected
      bogus section/attr flagged at the right severities. NEXT on this
      axis: schema *diffing* to auto-generate the version-delta rule
      table per build pair.

### v0.23 — shipped 2026-06-11
- [x] **Patch-level (x.y.z) version handling** (per Adam, "what about
      7.6.x"): versions carry the patch component end to end — the
      header's full x.y.z is parsed (and preferred when a train-only
      source override matches its train), `--fortios` / the wizard
      accept `7.6.3` (the target select became an input with train
      suggestions), and the rule table supports patch-scoped `since`
      versions like (7,6,3). Semantics: a patch-less target means "this
      train" and compares EQUAL within it (target 7.6 for a 7.6.6
      source is not a downgrade); across trains it counts as .0, so
      patch rules only fire on provable crossings. Within-train
      downgrades (7.6.6 -> 7.6.1) now run the scan — closing the
      previously silent case — and always carry the config-error-log
      caveat. fortios_versions meta shows full patch labels for
      within-train moves, train labels across trains. No patch-level
      rules curated yet; the mechanics are ready as they turn up.

### v0.22 — shipped 2026-06-11
- [x] **Downgrade version scan** (per Adam): the version-delta scan now
      runs in BOTH directions. target < source applies the rule table
      backwards — renames reverted (hw-version -> hw-model,
      sdwan -> virtual-wan-link below 6.4), default flips warned with
      reverse wording (8.0 dhgrp 20->14 / 21->5, allow-traffic-redirect
      re-enabling hairpin), new `introduced-section`/`introduced-attr`
      rule kinds flag features the older build doesn't know
      (system gui-dashboard-collection before 8.0), plus a standing
      "rule-based and partial; check config-error-log after restore"
      note. Findings under area `downgrade`; meta
      downgrade_artifacts/downgrade_auto_fixed; wizard note updated.
- [x] **CLI input-overwrite guard**: `-o` pointing at the input's own
      directory no longer lets `<stem>.conf` overwrite the source —
      output shifts to `<stem>-converted.*` with a notice.
- [x] **BOM tolerance**: config reads (CLI, GUI upload, GUI path) use
      utf-8-sig so a Windows BOM no longer breaks vendor detection.

### v0.21.2 — shipped 2026-06-11
- [x] **Old jobs heal on open**: conversion projects saved before the
      informed pickers existed carry no `iface_details` in job.json, so
      the picker columns rendered empty. Opening such a job now
      re-analyzes it from the stored source (identity and prior results
      kept) and persists the upgraded meta. Verified against the real
      601F project (96 interfaces, IPs/aliases/SD-WAN flags restored).

### v0.21.1 — shipped 2026-06-11 (bug scrub)
Five parallel review agents over the whole codebase (~35 verified
findings), all fixed same day; 162 tests (11 new regression tests).
Highlights, worst first:
- **pan_appid category IDs**: 4 of 16 FortiGuard IDs were wrong
  (Web.Client/Social.Media swapped; Collaboration/Business off by one) —
  verified against a live FortiOS 8.0 FortiGuard app DB and corrected
  (also ssh->Network.Service, github->Storage.Backup,
  salesforce->Business per the live DB; exact app name now wins over
  the suffix-stripped lookup).
- **PAN parser**: loopback/tunnel/vlan interfaces live under `<units>` —
  were parsed as one bogus "units" interface and dropped; `no-pfs` now
  means PFS off (was emitted as `set dhgrp no-pfs`); per-rule schedules
  flagged; 15-char tunnel-name truncation no longer silently merges
  tunnels.
- **pfSense parser**: `<disabled/>` respected on port forwards / 1:1 /
  phase1/phase2 (disabled tunnels no longer come up enabled); pfsgroup 0
  = PFS off; dynamic (DHCP/PPPoE) gateways no longer emit `set gateway
  dynamic` or silently drop the default route; FQDN host aliases emit
  fqdn objects; port-alias forwards split into one VIP per range.
- **ASA parser**: `nat ... static interface` -> placeholder + error (was
  literal `set extip interface`); `service-object neq` no longer
  broadens to any-port; numeric ICMP types honored; service group in the
  source-port position flagged + policy disabled (was mis-read as the
  destination service, dropping a following dst group); truncated ACEs
  no longer crash.
- **FortiOS tree**: a stray quote inside a `#` comment no longer
  swallows the following config lines (roundtrip fidelity).
- **transforms**: SD-WAN no longer deletes `set dstaddr` member routes
  as "defaults" (pinned rule + dstaddr zone route; internet-service
  routes kept + warned); pre-existing `set status disable` flipped on;
  hw-switch harvests member ports from `system virtual-switch` before
  dropping it (real devices keep membership there); `--prune` keeps
  NAT-referenced addresses; portmap renames `set intf`
  (local-in-policy), switch-interface members, dns-server /
  virtual-switch port edit names, and the leftover scan now flags
  un-renamed edit names; zone/SD-WAN names colliding with interface
  names rejected; vdom-mode: system sflow is global (vdom-sflow et al
  added per-VDOM), cert-scope warning could never fire; SSL-VPN:
  multi-object split tunnels wrapped in a generated addrgrp (was
  truncated to the first object), ALL `vpn ssl *` sections removed;
  versiondelta: no more dhgrp warnings from EMPTY phase1/2 tables;
  plan members translated exactly once over the merged --map (chained
  renames double-applied before).
- **emitter/outputs**: mixed-family policies emit COMPLETE v4+v6
  address pairs ('none' for an absent side — FortiOS rejected the
  half-pairs before); mixed-family groups drop wrong-family members
  loudly; udp/123 / udp/161 no longer broadened to built-in NTP/SNMP;
  empty service groups get a placeholder; VIPs with unresolved
  external/mapped IPs are skipped with an error; findings embedded in
  CLI files are ASCII-folded; `--split-interface-pairs` re-enforces the
  35-char policy-name limit; `--exclude`/`--only` match source rule
  names again (translated through sanitization) and missing excludes
  warn; dotted input stems no longer truncate report/bundle filenames;
  FMG bundle is family-aware (address6/addrgrp6, srcaddr6/dstaddr6),
  applies the same interface-PAT `nat enable` as the CLI script, skips
  unresolved VIPs, warns that app-lists/central-SNAT stay in the CLI
  script, and a bundle failure can no longer crash the run.
- **GUI**: a new zone/SD-WAN card now greys out members other rows
  already claimed (and claims release on remove/uncheck — checked
  members could silently drop from the POST before); Enter in a text
  field no longer submits the wizard early; an added-but-untouched
  SD-WAN card no longer aborts the conversion (and a PlanError no
  longer wipes the form for that case); "clear" clears hidden
  (filtered-out) members too; policy-selection buttons relabeled
  "select/clear visible"; an upload named `source.conf` no longer gets
  clobbered by its own conversion output (source stored as
  `_source.conf`); stale FortiManager bundles from earlier runs are
  removed; headerless multi-VDOM configs are now vendor-detected.
- Deferred (known, by design): ASA source-port groups convert
  disabled-for-review (no mirrored src-port services); SD-WAN
  internet-service member routes are kept + warned, not auto-converted
  to rules; FMG bundle still omits app-list profiles / central-SNAT
  (warned); PlanError redirects still reset wizard state for genuine
  validation errors (form echo-back is future work).

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
