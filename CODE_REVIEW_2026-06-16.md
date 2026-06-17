# fwforge — Independent Code Review (2026-06-16)

Read-only bug + optimization review of the whole `fwforge` package (~13.5k LOC),
run as 9 parallel deep-trace reviewers, one per subsystem. Two highest-stakes
findings (the `names.py` Critical and the `fortios_tree` backslash question)
were re-verified by hand against the source and a real 601F backup. No files
were modified.

Severity key: **Critical** = silently corrupts the converted config / breaks
restore in a likely case. **High** = corrupts/loses config in a plausible case
or violates a core invariant. **Medium** = wrong output or crash on a
realistic-but-narrower input. **Low** = fidelity/robustness/cosmetic.

The four invariants used throughout: (1) never silently drop convertible
config, (2) never silently *broaden* a firewall rule, (3) deterministic output,
(4) reference-complete + correct dependency/load ordering.

---

## Cross-cutting themes (read this first)

These recur across subsystems and are more important than any single line.

**A. Silent service/port broadening — the #1 invariant, violated in 4 parsers.**
The single most dangerous class, because the converted rule looks tight but
permits more (or less) than the source, often with the usual warning
*suppressed*: PAN `application-default` SNMP (#6), ASA `gt/lt` boundaries (#8),
ASA ICMP-code drop (#15), SRX nested app-set drop (#10) and `junos-vnc`
narrowing (#17), pfSense 1:1 `<destination>` ignored (#21). Recommend a single
shared guard + a regression test per parser asserting "converted service is
never broader than source."

**B. Scope-confusion in reference rewriting — the Critical + two Highs.**
Three separate transforms rewrite references using a map that doesn't carry the
namespace/VDOM the reference lives in: `names.py` mixes object namespaces
(Critical #1), `tree_refs.rewrite_policy_refs` and `portmap.apply_tree` rewrite
tree-wide across VDOMs (#2, #3). Same root cause: the rewrite touches the wrong
scope. All three silently break or merge references on restore.

**C. Disabled-state loss.** SRX `inactive:` on curly leaves (#9) and deactivated
zone-pairs (#16) come back *enabled* — a disabled permit rule silently
re-activating is both #1 and #2.

**D. Systemic O(n²) name lookups — the highest-leverage perf fix.** Every parser
(`paloalto`, `cisco_asa`, `juniper_srx`, `pfsense`) and the emitter repeat the
pattern `any(x.name == … for x in cfg.services)` / linear `interface_by_name` /
`address_by_name` inside per-rule/per-object loops. On real configs (PAN 2.6k
addrs / 379 policies; FGT 46k–73k lines) this is quadratic-to-cubic. **One fix**
— add `{name: obj}` indexes on the IR model (`address_by_name`,
`service_by_name`, `interface_by_name`, group-name sets) — removes 5+ hotspots
at once. Do this before micro-optimizing anything else.

**E. Dependency ordering is half-done.** Interfaces got `_dependency_order`
(v0.47), but address-groups and service-groups did not (#4) — a parent group
listing a not-yet-defined child group drops the member on restore.

**F. Robustness / uncaught crashes on malformed input.** `paloalto._lifetime`
(#12), `plan.py` configparser errors (#13), `versiondelta.scan(None)` (#22),
and the CLI exit-code contract (#11) all turn a bad input into a traceback
instead of a clean, reported failure.

**G. What's already solid — keep it.** The loud-failure discipline mostly works:
twice-NAT flagged (not mishandled), masked `*****`/`$9$` PSKs → `CHANGEME` +
error, XXE/entity declarations rejected, HTML report fully `html.escape`d,
API tokens sent in headers and never stored/logged/reflected, `safe_filename`
has no traversal, server binds `127.0.0.1`, `debug=False`, json-only job
persistence, dedup fingerprints order-insensitive, no mutable-default-arg bugs
in `model.py`. The bugs below live in the *silent edge cases*, not the
happy path.

---

## Critical

### 1. `transforms/names.py:38–105` — cross-namespace name collision silently breaks/merges references
One shared `renames` dict + `taken` set spans `addresses`, `addr_groups`,
`services`, `svc_groups`, `vips` (lines 55–58), and the policy-name pass dumps
into the *same* `renames` (line 84). The remap (94–104) then applies that one
map to address-position, service-position, and group-member references with no
namespace tag. FortiOS namespaces are independent — an address `web` and a
service `web` both legally exist. Trace: address `web` stays; service `web` →
`web~2` (a spurious rename it never needed); then a policy's *address* reference
`web` is rewritten to `web~2`, pointing at the service (or nothing). Inverse
order silently *merges* two objects. This is exactly the #1/#2/#4 failure the
tool exists to prevent.
**Fix:** give each FortiOS namespace its own `taken`/`renames` (zones at 60–77
already do this); remap address-type refs only from the address/VIP map and
service refs only from the service map; keep policy-name renames out of the
object `renames` entirely.

---

## High

### 2. `transforms/tree_refs.py:86–120` (`rewrite_policy_refs`) — multi-VDOM rewrite not VDOM-scoped → dropped policy on restore
`apply_zones`/`apply_sdwan` build a name→zone map and rewrite `srcintf`/`dstintf`
across the **entire** tree. VLAN/aggregate/loopback/tunnel/switch interface
names are unique only *per VDOM* — two VDOMs routinely both have `vlan30`. A
policy in VDOM `FGSP` referencing its own `vlan30` gets rewritten to a zone that
exists only in VDOM `root`; on restore FortiOS rejects it (unknown srcintf) →
dropped policy (#1) and broken FGSP traffic (#2). Same root cause in
`zones.py:150` (`_rebind_associated_addresses`) and `zones.py:188`
(`_flag_same_zone_policies`). The multi-VDOM fixture uses disjoint names, so
it's untested.
**Fix:** thread the resolved VDOM `scope` through and iterate
`iter_config_nodes(scope)` not the whole tree — the builders already compute
`vdom_scope(tree, vd)`.

### 3. `transforms/portmap.py:274–317` (`apply_tree`) — interface rename tree-wide, not VDOM-scoped
Same class as #2 for renames: `vlan30 = vlan40` renames it in *every* VDOM,
including ones where `vlan30` is a different interface, and rewrites its
`system interface` edit name there too — so that VDOM's real `vlan30` definition
vanishes and its references dangle. `interface_vdoms()` exists but `apply_tree`
ignores it. Harmless for globally-unique physical ports; silent corruption for
per-VDOM-scoped names.
**Fix:** when `is_multi_vdom(tree)`, resolve each rename's owning VDOM and
rewrite only within that scope.

### 4. `emit/fortios.py:349–391` (`addr_groups`) & `:422–442` (`svc_groups`) — nested groups emitted in source order → silent member loss
Group members can be other groups (ASA `group-object`, PAN nested static
members). The emitter iterates groups in parser order with no topological sort.
A parent defined before its child child emits `set member CHILD` before `CHILD`
exists → FortiOS drops the unknown member on restore (#4/#1). Interfaces got
`_dependency_order`; groups never did.
**Fix:** topologically order `addr_groups`/`svc_groups` (DFS place, same shape as
`_dependency_order`); on a cycle, emit input order + `report.add("error", …)`.

### 5. `emit/fortios.py:589` & `:608` (`vpn`) — empty proposal list emits broken `set proposal`
`set proposal " + " ".join(p1.proposals)` yields a bare `set proposal` (no value)
when `proposals == []`. FortiOS rejects it and may abort the rest of the `edit`
block (cascading loss). `dhgrp` is guarded by `if p1.dhgrp:`; `proposal` is not.
**Fix:** if empty, emit a known-good default + `report.add("warn"/"error", …)`,
or skip — never a bare `set proposal`.

### 6. `parsers/pan_appid.py:277` (`APP_TO_BUILTIN`) + `paloalto.py:1057` — `application-default` silently broadens SNMP/snmp-trap
`_appdefault_services` trusts a built-in name with no port comparison: PAN `snmp`
(udp/161) → built-in `SNMP` (tcp+udp 161–162), and *suppresses* the "kept as ALL"
warning, so the rule looks tight but permits tcp/161, udp/162, tcp/162. Same for
`snmp-trap`. (Inverse: `ldap`/`kerberos`/`ms-ds-smbv2` narrow — connectivity, not
security.)
**Fix:** compare the built-in's signature to the app's `DEFAULT_PORTS`; if not
exact, synthesize the custom service from `DEFAULT_PORTS` (data is right there)
or attach the built-in + a loud port-delta warning. At minimum drop the
wider-than-source entries (`snmp`, `snmp-trap`) from the table.

### 7. `parsers/paloalto.py:1011–1032` (`_app_port_specs`) — custom-app vs application-group precedence mismatch
`_app_port_specs` checks `_custom_apps` before `_app_groups`; `_expand_app_groups`
(app-control path) checks groups first. When a name exists in both, the two
resolvers disagree, so a rule's *service* and its *app-control profile* are built
from different member sets.
**Fix:** make both use one precedence (group → custom-app → curated), or assert
name uniqueness and flag collisions.

### 8. `parsers/cisco_asa.py:233–244` (`parse_port_spec`) — `gt`/`lt` boundaries emit invalid ranges, policy left enabled
`gt N`→`{N+1}-65535`, `lt N`→`1-{N-1}`, both `ok=True`. `gt 65535`→`65536-65535`,
`lt 1`→`1-0`, `lt 0`→`1--1` — inverted/empty ranges, policy *enabled*. FortiOS
rejects an inverted range on load, which can blow up the whole
`config firewall service custom` block and drop *other* services (#2 + cascading
#1).
**Fix:** validate bounds; if the ASA rule matches nothing / can't be expressed,
return `("", False)` so it emits disabled + REVIEW, like `neq` already does.

### 9. `parsers/juniper_srx.py:154` — per-statement `inactive:` on curly leaves dropped → disabled config re-activated
The `;`-branch does `toks, _inact = _strip_inactive(...)` and throws `_inact`
away. A deactivated leaf (`inactive: ge-0/0/0.0;`, an address, a route, a
match-line) is stored active. Set-format handles this (parity gap). A disabled
permit silently becomes active (#1/#2).
**Fix:** store `["inactive"] + toks` when `_inact`, mirroring `_insert_set`.

### 10. `parsers/juniper_srx.py:573` — nested application-set dropped in set-format → policy service silently changed
`parse_applications` reads nested members via `leaf_all("application-set")`
(leaves only). In set-format `set applications application-set outer
application-set inner`, `inner` is descended as a *container* (`_is_named`), never
a leaf, so `outer` omits it and a policy resolves to fewer ports. Curly works
(parity gap the parity test misses).
**Fix:** also gather container-form nested set members in `parse_applications`.

### 11. `cli.py` (dispatch) / `__main__.py` — uncaught exceptions exit 1, violating the documented "2 = fatal" contract
`main()` ends `return args.fn(args)` with no wrapper. A missing input file,
unreadable `--map`/`--plan`/`--target-config`, parser crash, or `OSError` on
write surfaces as a raw traceback at **exit 1** — indistinguishable from
"converted with errors." CI keying on exit 2 can't tell fatal from recoverable.
**Fix:** wrap dispatch; map `OSError`/`PlanError` → message + `return 2`.
`cmd_detect`/`cmd_inspect`/`cmd_plan` have no `PlanError` guard at all.

### 12. `parsers/paloalto.py:531–537` (`_lifetime`) — `.isdigit()` on a value that can be a dict → crash
A malformed/empty `<seconds/>` yields a dict; `node.get("seconds","").isdigit()`
raises `AttributeError`, aborting the whole conversion instead of flagging.
**Fix:** `str(node.get("seconds",""))` or `isinstance(...,str)` guard (used safely
elsewhere for `tag`).

### 13. `transforms/plan.py:107–197` — malformed plan file raises raw `configparser` errors → CLI traceback
Duplicate `[portmap]` sections (the docstring even contemplates merging them),
duplicate keys, missing header, or any parse error raises
`configparser.DuplicateSectionError`/`MissingSectionHeaderError`/`ParsingError`,
none of which subclass `PlanError`; the CLI only catches `PlanError`.
**Fix:** wrap `cp.read()`/access in `except configparser.Error → raise PlanError`;
decide explicitly whether duplicate sections merge (`strict=False`) or are
rejected.

### 14. `transforms/versiondelta.py:262–283` — `allow-traffic-redirect` flip never fires when `config system settings` is absent
The default-flip warning only fires if the section exists but the attr is unset.
If the section is absent — the config relies 100% on the old firmware default,
the exact "invisible" artifact this feature exists to catch — no node matches and
no warning fires. Hairpin traffic silently drops on 8.0. Same gap in `_scan_down`
(344–364).
**Fix:** for `edit_table=False` singletons, add a presence check *outside* the
node loop: if no matching node was seen, the default still applies → flag the flip.

### 15. `parsers/pfsense.py:282–288` — multi-entry alias literal-vs-reference by "has `.`/`:`" → dangling group member
A multi-entry host alias whose member is a bare single-label hostname (`intranet`)
is classed as a nested-alias *reference* and emitted as an addrgrp member that
doesn't exist → group fails to load. (Single-entry path handles it via FQDN; the
multi-entry loop doesn't.)
**Fix:** classify reference-vs-literal by membership in the known-alias-name set
(two-pass), not by `.`/`:`.

---

## Medium

- **`parsers/cisco_asa.py:762–768` — ICMP code silently dropped → broadening.**
  `permit icmp any any unreachable 4` keeps only type 3; the code falls into the
  trailing comment loop. Pairs with an emitter gap: `emit/fortios.py:409` never
  emits `icmpcode`. Two-file fix (capture in IR + emit `set icmpcode`, or warn).
- **`parsers/juniper_srx.py:929–930` — deactivated zone-pair doesn't disable inner
  policies.** `_one_policy` checks `inactive` only on the policy node, not the
  enclosing `from-zone…to-zone` node. Propagate `disabled` from the zone-pair/global
  block.
- **`parsers/junos_apps.py:28` — `junos-vnc` = `tcp 5800 5900` should be the range
  `5800-5900`** (two discrete ports silently narrows the service).
- **`parsers/juniper_srx.py:534` — `family inet6` interface addresses dropped with
  no flag** (only `family inet` read). At least emit a note.
- **`parsers/juniper_srx.py:1042–1074` — dest-NAT match on a named address object
  → bogus VIP `ext_ip`** (raw token used as IP). Resolve via `address_by_name` or warn.
- **`parsers/pfsense.py:660–678` (`_pf_selector`) — phase2 selector dotted-quad
  netmask → invalid CIDR** (`10.0.0.0/255.255.255.0`), silently dropped/over-broad.
  Normalize/validate both forms.
- **`parsers/pfsense.py:550–566` — outbound NAT "automatic" with no resolvable WAN
  emits zero SNAT but reports success** (`or 'WAN'` masks the empty list). Warn when
  egress resolves to nothing.
- **`parsers/pfsense.py:817–823` (`report_unconverted`) — string/list-valued
  top-level sections silently skipped** (`not isinstance(node, dict)`). Repeated
  sections (`<cert>`, `<ca>`) become lists and vanish from the coverage report (#1).
- **`parsers/pfsense.py:629–645` — 1:1 NAT ignores a `<destination>` restriction**
  → unconditional VIP = silent broadening (#2). Flag when `<destination>` ≠ any.
- **`emit/fortios.py:799–801` & `:854–856` — BGP/OSPF `redistribute` interpolated
  into quotes bypassing `_q`.** Use `_q(r)` — the one hand-built quoted value in the
  emitter.
- **`emit/fortios.py:223–229` (`interfaces`) — interface IP parse failure swallowed
  by `except ValueError: pass`** with no report → silent IP-less interface (the
  `addresses`/`routes` paths both report). Add `report.add("error", …)`.
- **`transforms/routes.py:35–40` (`lookup_net`) — range address inference checks
  only the first/last /32, missing the interior** → can pin a range that spans a
  more-specific route to one wrong egress, silently. Use
  `summarize_address_range` or treat split ranges as ambiguous (`any` + report).
  (`routes.py` has no unit test at all.)
- **`transforms/sdwan.py:212–234` & `:317–323` (`convert_member_routes`) — two
  SD-WAN zones in one VDOM collapse into one shared default route**, pooling
  distances/priorities and steering to both zones. Track per-zone, emit one route
  per zone that lost a default.
- **`webui/templates/plan.html:1118,1140` — DOM-based XSS via a crafted config.**
  `esc()` (line 597) escapes `& < > "` but **not `'`**; destination-port names
  (read verbatim from a backup's `config system interface`) are interpolated into
  inline `onclick="…'${esc(p)}'"`. A backup with an interface named
  `x');alert(document.cookie);//` executes when rendered as a LAG-member chip.
  Third-party configs are the product's input, so not pure self-XSS. **Fix:** escape
  `'` in `esc()`, or use `addEventListener` + `data-port` like the faceplate code.
- **`transforms/tuning.py:95–124` — `--exclude` silently ignored when `--only` is
  also given** (no warning). Warn or document precedence.
- **`transforms/sslvpn.py:160–175` — only the first tunnel-mode portal is used**;
  other portals' split-include subnets / pools are dropped with no finding (#1).
  Warn enumerating the dropped portals.

---

## Low / fidelity / robustness

- **`parsers/fortios_tree.py:49–58 / 71–77` — backslash/apostrophe roundtrip
  asymmetry.** Parse drops the backslash in any `\X`; emit only re-escapes `\\`/`\"`.
  **Verified against the real 601F backup:** FortiOS *doubles* literal backslashes
  (regex `\b(\d{3})` is stored `"\\b(\\d{3})"`), which the parser decodes and
  re-encodes correctly — so regex/cert/path values roundtrip byte-identically. The
  only real artifact is FortiOS's redundant `\'` apostrophe escaping
  (`administrator\'s` → fwforge emits `administrator's`): semantically identical on
  reload, but **not byte-identical** and shows spurious diffs. Downgraded from the
  "potential Critical" the isolated reviewer feared. **Fix:** also escape `'`→`\'`
  in `format_token` to match FortiOS.
- **`parsers/fortios_tree.py:158–162,222–225` — comment/raw re-indentation
  (`pad + text.strip()`), trailing-whitespace and blank-line drop** → not strictly
  byte-faithful. Near-harmless on real backups (4-space indented, no blank lines),
  which is why the byte-identical demos pass; the existing
  `test_roundtrip_is_lossless` `normalize()`s whitespace away, masking it. Represent
  blank lines as nodes and stop `.strip()`-ing stored verbatim text if strict
  fidelity is the contract.
- **`parsers/fortios_tree.py:178,187–196` — `edit` under `edit` → RawLine; stray
  `next`/`end` dropped (warned, not preserved)** → reserialize not idempotent on
  malformed input. Preserve unrecognized structural tokens as RawLine.
- **`schema.py:128–144` (`resolve`) — IPv6-literal guard incomplete.** `2001:db8::1`
  (numeric last group) slips past and `rpartition(":")`s into host `2001:db8:` /
  port `1`. Add `if ref.count(":") > 1: raise ValueError(...)` up front.
- **`parsers/cisco_asa.py:760,195–198` — service object-group used in ACL port
  position but defined *after* the ACL is reinterpreted as a destination address
  group** (forward reference). Real `show run` emits groups first; hand-edited
  configs trip it (#1). Two-pass or validate.
- **`parsers/paloalto.py:166–169` — a quoted value literally `[` is misparsed as a
  list opener** (`"[" in toks` membership). Track quoted-ness per token.
- **`emit/fortios.py:669` vs `:670` — `set extip {ext_ip}` unquoted while `mappedip`
  uses `_q`.** Quote both for consistency.
- **`webui/app.py:357–372` (`/load`) + no CSRF/Origin check** — a cross-origin POST
  can drive `Path(path).read_text()` on attacker-chosen local paths (file-existence/
  parse oracle); `/convert` and `/job/<jid>/delete` are also CSRF-able. Add a
  `before_request` Origin/Referer check for non-GET.
- **`appdb.py:30–32` & `schema.py:52–54` — TLS verification disabled
  (`CERT_NONE`) on a user-supplied FortiGate host** while sending a real admin
  Bearer token → MITM can capture it. Reasonable default for "own box, private net,"
  but make it an explicit `--insecure` opt-in.
- **`webui/app.py` — no `MAX_CONTENT_LENGTH`, unbounded synchronous parse,
  single-threaded** → a hostile config can wedge the local tool (DoS). Set a cap;
  consider `threaded=True` (then add per-job locking on the `JOBS` dict).
- **`transforms/routes.py:30` — default routes loaded into the prefix table** can be
  longest-prefix matched, pinning a no-specific-route host to one WAN. Defensible;
  document + report when inference resolves only via `/0`.

### Suspected / needs a fixture to confirm
- `transforms/tree_refs.py:144–193` — `dedup_policies`/`flag_conflicting_policies`
  cover only `firewall policy`, not `security-policy`/`proxy-policy`/`central-snat-map`;
  after a zone fold those can become exact duplicates, kept + unflagged.
- `pipeline.py:133–152` (`_vdom_names`) — incremental collision resolution can
  attribute one vsys's output VDOM to a mangled form of another's name.
- `pipeline.py` multi-vsys — created logical interfaces emit `set vdom "root"`
  inside the `edit <vsys>` wrapper.
- `parsers/paloalto.py:305–323` (`_merge_scope`) — shared + device-group both
  defining `profiles` may shadow the shared `url-filtering` subtree.
- `parsers/paloalto.py:640–646` — IPsec proxy-id with non-string local/remote
  falls back to `0.0.0.0/0 ⇄ 0.0.0.0/0` (broadening) with only an info note.
- `parsers/pfsense.py:447–476` — nested port-alias references emitted as a literal
  port token (`set tcp-portrange <aliasname>`) → won't load.
- `parsers/juniper_srx.py:1729` — `buckets[p1_scope[p1.name]]` unguarded `[]` →
  `KeyError` if a phase1 name isn't classified (`p2`/routes use `.get(...,"root")`).
- `transforms/portmap.py:320–363` (`leftover_scan`) exempts the whole
  `system interface` subtree → a partial port-map can leave a dangling
  `member`/`interface` ref unreported.

---

## Optimization opportunities (consolidated)

Ordered by leverage.

1. **Model-level name indexes (theme D) — do this first.** Replace every
   `any(x.name == …)` / linear `interface_by_name` / `address_by_name` with
   `{name: obj}` dicts on the IR. Hotspots: `paloalto.py:1074,1086,1128,1778`,
   `cisco_asa.py:195–198,461`, `juniper_srx.py:646–678,767,1168`,
   `pfsense.py:419 et al.`, `emit/fortios.py` (`_intf` per policy/zone/route),
   `emit/fortimanager.py:250`. Quadratic→linear on the configs that matter.
2. **`emit/fortios.py` — `_family_map()` walked 2–3×** (`:352`, `:876`, plus
   `fortimanager.py:177`). Compute once, pass it.
3. **`fortios_tree.find_config`/`find_config_under` — O(n) full-tree walk per
   lookup; ~10+ full traversals per conversion** in the zone/sdwan path
   (`transforms A`), `find_config_under(scope,"router","static")` recomputed inside
   `sdwan.py:428/456` loops. Build a `path→[nodes]` index once per tree;
   hoist loop-invariant lookups.
4. **`pipeline`/`platforms` — target-config parsed twice** (`inventory_from_config`
   *and* `device_identity` both `parse_config` the same text). Parse once.
5. **`transforms/tuning.py:179–200` (`_prune`) rebuilds the full reference set every
   iteration** (O(n²) on deep group trees). Reuse the closure; reprune only affected.
6. **`fortios_tree._logical_lines:140–148` re-tokenizes the whole accumulated buffer
   per physical line** → O(L²) on a multi-thousand-line cert/script value. Carry an
   incremental open-quote flag.
7. **`transforms/versiondelta.py` — O(R×N) independent tree walks** (one per rule).
   Bucket nodes by path suffix once. Scales poorly as `RULES` grows.
8. **`transforms/sdwan.py:121` (`_next_edit_id`) rescans all children per call** →
   O(rules²). Track a running max id.
9. **Dead code: `juniper_srx.py:112–116` (`_line_starts`) is never called.** Delete.
10. Minor: `report.coverage()` re-splits `source_text`; `platforms` rebuilds the
    difflib name list per error; `webui` `/job/<jid>` recomputes `guess_by_model`
    every GET and `bundle.zip` recompresses per download.

---

## Test coverage gaps (highest-value first)

- **`names.py` cross-namespace collision** (address+service / address+VIP same name)
  — would catch the Critical. Also: two distinct names that *sanitize* to the same
  string, asserting disambiguation + correct per-namespace reference remap.
- **Multi-VDOM with a repeated interface name across VDOMs** (`vlan30` in both `root`
  and `FGSP`) folded/SD-WAN'd/renamed — catches #2 and #3. The current fixture uses
  disjoint names, masking both.
- **Per-parser "service is never broader than source"** regressions:
  PAN `application-default` SNMP/snmp-trap/ldap/kerberos; ASA `gt 65535`/`lt 1`/`lt 0`
  and `neq` in both port positions; SRX nested app-set (set-format) + `junos-vnc`;
  pfSense 1:1 with `<destination>`.
- **Empty IKE/IPsec proposal** → no bare `set proposal` line.
- **Nested address/service group where the child is defined after the parent** →
  assert emit order (the #4 fix).
- **SRX `inactive:` on a curly leaf, and a deactivated zone-pair** → assert disabled.
- **Malformed plan file** (dup section/key, missing header) → assert `PlanError`,
  not a traceback. **CLI fatal paths** (missing input) → assert clean exit 2.
- **`versiondelta` flip when `config system settings` is entirely absent.**
- **`routes.py`** has no unit test — add range-inference + default-route cases.
- **Webui:** hostile chars (`'"<>]`) in an interface/destination-port name through
  the wizard (catches the XSS); CSRF/Origin on `/load`/`/convert`/`/delete`; upload
  size cap; assert the API token is never written to the appdb/schema cache.
  `appdb.py` has no test module at all.
- **`fortios_tree`:** a byte-identical (not `normalize()`d) roundtrip fixture with an
  apostrophe, a regex value, blank lines, and tab indentation; idempotency on
  malformed `next`/`end`/`edit`-under-`edit`.

---

## Per-subsystem index

| Subsystem | Files | Headline |
|---|---|---|
| PAN parser | `paloalto.py`, `pan_appid/urlcat/filetype.py` | #6 SNMP broaden, #7 resolver mismatch, #12 crash |
| Juniper SRX | `juniper_srx.py`, `junos_apps.py` | #9 inactive-leaf, #10 nested app-set (set-fmt) |
| Cisco ASA | `cisco_asa.py`, `_vpn_common.py` | #8 gt/lt invalid range; twice-NAT/PSK verified safe |
| pfSense + tree | `pfsense.py`, `fortios_tree.py` | #15 dangling alias; tree fidelity (Low, verified) |
| Transforms A | zones/sdwan/portmap/tree_refs/routes | #2 #3 cross-VDOM rewrite |
| Transforms B | sslvpn/vdommode/hwswitch/versiondelta/tuning/optimize/names/plan | **#1 Critical**, #13 #14 |
| Emit + model | emit/fortios/fortimanager/package, model | #4 group order, #5 empty proposal; model clean |
| Core engine | pipeline/cli/platforms/schema/report | #11 exit codes; report XSS + tokens verified safe |
| Web UI + sec | webui/app.py + templates, appdb | XSS (single-quote), CSRF+file-read, TLS-off |
