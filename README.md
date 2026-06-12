# fwforge

Open firewall config converter: third-party firewall configs in, clean
FortiOS CLI out. An independent, transparent alternative to Fortinet's
FortiConverter ($3,995/yr tool, or $50–$5,000 per device as a service).

Pure Python, **zero dependencies**, runs anywhere Python 3.11+ runs. Your
configs never leave your machine (FortiConverter's free FortiGate-to-
FortiGate path requires uploading your config to Fortinet's cloud and
consenting to data-use terms).

## Why this exists

FortiConverter's conversion engine is a closed 14 MB compiled binary behind
a Django web UI — you cannot see *why* it produced what it produced, and
its own docs admit it silently falls back to `dstintf any`, can't convert
Cisco twice-NAT, and buries warnings as comments inside the output file.

fwforge's contract is different: **nothing is dropped silently.** Every
emitted line is traceable, and everything that could not be converted is in
the report with the source file and line number it came from.

## Quick start

```
# what is this config?
python -m fwforge detect myfirewall.cfg

# summarize what's inside
python -m fwforge inspect myfirewall.cfg

# convert (auto-detects vendor)
python -m fwforge convert myfirewall.cfg -o out --map ports.map
```

`convert` writes outputs whose **shape depends on the conversion**, plus
reports:

**FortiGate → FortiGate** (model migration) → one **full restorable
config**:

| file | what it is |
|---|---|
| `<name>.conf` | complete FortiOS backup — restore wholesale via *System → Configuration → Restore* or `execute restore config`. `#config-version=` stays on line 1; findings are embedded as `#` comments (ignored on load) |

**Anything → FortiGate** (Cisco ASA, Palo Alto, Juniper SRX, pfSense) →
**FortiConverter-style script files** (it's a paste-script, not a full
backup):

| file | what it is |
|---|---|
| `<name>.config-all.txt` | the whole converted script, findings embedded as `#` comments |
| `<name>.branches/NN-<section>.txt` | one file per `config` branch (firewall-address, firewall-policy, …) for selective CLI application |

Both also write `<name>.report.md`, `<name>.report.json`, and (cross-vendor,
when interfaces are unmapped) a `<name>.portmap` sample. The GUI offers the
main file, an **all-files .zip**, and the reports.

The interface map file is `source-name = target-port`, one per line:

```
outside = wan1
inside  = port1
dmz     = port5
```

## Two conversion modes

**Cross-vendor** (`--mode cross`, default for foreign configs): parse the
source into a vendor-neutral model, transform, emit FortiOS. Lossy by
nature — the report accounts for every loss.

**FortiOS migrate** (`--mode migrate`, default for FortiOS sources): for
moving a config between FortiGate models (e.g. 601F → 701G). The config is
parsed into a full structural tree and re-emitted **losslessly** — sections
the tool knows nothing about survive byte-for-byte — with interface renames
applied *reference-aware* across the entire config (policies, zones, routes,
DHCP, VPN phase1, SD-WAN members, HA heartbeat devices, SSL-VPN
source-interface...). An address object that happens to be named `port1` is
left alone, and so are FortiSwitch/FortiExtender port names that belong to
other devices. After renaming, a leftover scan reports every remaining
old-name token so nothing slips through. `--target-platform FG7H1G`
rewrites the `#config-version` header so the target model accepts the file.

### SSL-VPN → IPsec dial-up assistant

FortiOS 7.6 removed SSL-VPN tunnel mode. This converts it to the
recommended replacement — an IKEv2 dial-up IPsec tunnel (FortiClient):

```
python -m fwforge convert ras.conf --fortios 8.0 \
    --sslvpn-to-ipsec --sslvpn-psk "MyTunnelKey1"
```

It builds a phase1/phase2-interface scaffold from the SSL-VPN config:
`source-interface` → tunnel interface, the tunnel IP-pool object →
mode-config `ipv4-start-ip`/`end-ip`, the portal's split-tunnel network →
`ipv4-split-include`, the authentication-rule group → `authusrgrp` (+ EAP),
and the `ssl.<vdom>` firewall policies are rewired to the new tunnel with
their user groups intact. The dead `vpn ssl settings`/`web portal` sections
are removed. Like FortiConverter's assistant it's a **scaffold**: it emits
a placeholder PSK and loudly flags what needs you — a real PSK, client
reprovisioning to FortiClient IKEv2, and the SSL-VPN features (web-mode
bookmarks, host-check) that have no IPsec equivalent. Web-mode-only SSL-VPN
is left untouched and flagged. Per-VDOM aware.

### Hardware-switch → software-switch

When the target model lacks the source's switch fabric, rewrite its
hardware switch as a CPU software switch so the same ports keep bridging:

```
python -m fwforge convert desktop.conf --hw-switch convert --plan m.plan
```

Interfaces with `set type hard-switch` become `set type switch` (name, IP,
allowaccess and member ports preserved, so policies/routes/VLANs that
referenced the bundle keep working); the now-dead `system virtual-switch`
/ `system physical-switch` sections are dropped. Member port renames flow
through the interface mapping. `hard-switch-vlan` interfaces are flagged
for manual review rather than guessed at. Default is `keep` (untouched).

### VDOM-mode conversion

Change a FortiOS config's VDOM mode during migration (e.g. a flat 601F
config onto a multi-VDOM 121G):

```
# wrap a flat config into config global + config vdom/edit CUSTOMER-A
python -m fwforge convert flat.conf --vdom-mode multi --vdom-name CUSTOMER-A

# load into an existing multi-VDOM box WITHOUT overwriting its globals
python -m fwforge convert flat.conf --vdom-mode multi --vdom-name CUSTOMER-A --vdom-scope-only

# flatten a single-VDOM config back to non-VDOM form
python -m fwforge convert onevdom.conf --vdom-mode single
```

fwforge sorts sections by FortiOS scope — `system global/interface/admin/
ha/npu/dns/ntp` to `config global`, and `firewall`/`router`/`vpn`/`user`
plus per-VDOM `system settings/zone/sdwan/dhcp` into the VDOM — assigns
interfaces to the VDOM, sets `vdom-mode multi-vdom`, and flips the
`config-version` header. Ambiguous roots (log, certificates) default to
global and are flagged. `--vdom-scope-only` drops global scope so the
output merges into an existing VDOM safely. Flattening refuses a config
with 2+ VDOMs (a flat config holds one).

### Version-upgrade artifact scan

When a FortiGate-to-FortiGate migration also jumps FortiOS versions —
**in either direction, down to patch level** — the scanner reports what
the version change leaves behind. Source version (full x.y.z) is read
from the `#config-version` header automatically; target comes from
`--fortios`, which accepts a train (`7.6` — treated as "same train, no
move" against a 7.6.x source) or an exact patch (`7.6.3`, enabling
within-train comparisons such as a 7.6.6 backup landing on a 7.6.1
box):

```
python -m fwforge convert old-box.conf --fortios 8.0 --plan m.plan
```

Upgrading, three artifact classes, each in the report with severity and
the affected entry names:

- **removed features** — dropped silently by the new firmware on load
  (7.6: SSL-VPN; 8.0: `gui-dashboard` under admin, `intra-vap-privacy`)
- **renames** — safe ones auto-fixed and noted (`hw-model`→`hw-version`,
  `virtual-wan-link`→`sdwan`)
- **default flips** — the invisible class: settings the config never
  wrote because it relied on the old default (8.0 changed IPsec DH groups
  14/5→20/21, hairpin `allow-traffic-redirect`, inline IPS enforcement).
  No text diff can show these; only a rule base can.

Downgrading (e.g. an 8.0 backup landing on a 7.4 box), the same rule
table runs backwards: renames are **reverted** (`hw-version`→`hw-model`),
default flips warn with the reverse wording (the default goes *back* on
the older build), and features **introduced** after the target are
flagged as dropped-on-load (`system gui-dashboard-collection` before
8.0). Every downgrade also carries a standing note that the scan is
rule-based — anything the older firmware doesn't recognize is skipped
silently on load and only visible in `diag debug config-error-log read`.

The rule table (`transforms/versiondelta.py`) is curated from Fortinet's
release-notes "Changes in CLI / default behavior" pages — deliberately
conservative; extend it as versions land.

### Schema-certified output (opt-in)

```
python -m fwforge schema 10.2.10.1 --token <api-key>   # fetch + cache
python -m fwforge convert box.conf --fortios 8.0 \
    --schema-check ~/.fwforge/schemas/fortios-8.0.0-b167.json
```

Every FortiGate exposes the complete CLI schema of its exact firmware
build over REST. fwforge fetches it from **your own device** (one
read-only GET), caches it locally, and validates every emitted
`config` section and `set` attribute against it — so the report can
say *"schema check CLEAN vs 8.0.0 build167: every section and
attribute exists on the target"* before anything touches hardware.
Unknown sections are errors (the whole block is dropped on load),
unknown attributes are warnings (the line is dropped). `--schema-check`
takes a cached file or a live host (token via `--schema-token` or the
`FWFORGE_API_TOKEN` env var); the GUI has the same as a checkbox with
a cached-schema picker. Schemas are runtime device data — cached under
`~/.fwforge/schemas/`, never shipped with the tool.

### FortiManager output

```
python -m fwforge convert asa.cfg --map ports.map --fmg root/migrated-asa
```

Alongside the script package, writes `<name>.fmg.json` — a **FortiManager
JSON-RPC import bundle**: ready-to-POST requests that create the converted
address/group/service/VIP objects in the ADOM and build a policy package
with the converted policies. POST each request (in order) to
`https://<fmg>/jsonrpc` after login, then install the package to the
device. Routes and VPN tunnels are device-level and stay in the CLI
script (flagged in the report). Also a checkbox in the GUI wizard.

### Tuning (cross-vendor conversions)

FortiConverter ports a config 1:1 and offers a shallow opt-in cleanup;
these flags clean up the converted output instead:

```
python -m fwforge convert asa.cfg -o out --map ports.map \
    --prune --merge-dupes --split-interface-pairs --exclude UNUSED-1
```

- `--prune` — iteratively drop addresses/services/groups no policy uses
- `--merge-dupes` — collapse same-value objects to one name, rewrite refs
  (FortiConverter doesn't do this)
- `--split-interface-pairs` — one policy per srcintf/dstintf pair
  (their "Interface Pair View Split")
- `--exclude a,b` / `--only a,b` — rule include/exclude by policy name

All are also checkboxes on the GUI's conversion page.

### Migration plans: zones and SD-WAN refactors

Beyond renames, a migration can *restructure*. `fwforge plan <config>`
scaffolds a plan file; `convert --plan` applies it:

```ini
[portmap]
port1 = lan5

[zone lan]
intrazone = deny
member = port2, vlan30

[sdwan virtual-wan-link]
member = wan1 gateway=203.0.113.1, wan2 weight=10
health-check = ping 8.8.8.8
```

**`[zone …]`** folds interfaces into a zone with the ramifications handled:
the zone is created (`intrazone deny` by default), every policy /
central-SNAT / shaping reference is rewritten to the zone with duplicate
tokens collapsed, policies that became identical are merged (loudly),
same-zone policies are flagged, and a leftover audit warns about anything
still pointing at the members (PBR, multicast, …) that FortiOS would choke
on.

Both refactors are **multi-VDOM aware**: the owning VDOM is derived from
the members' `set vdom` assignments (add `vdom = X` to a section to assert
it), the zone / `config system sdwan` block lands inside that VDOM's body,
route conversion stays within it, and members spanning VDOMs are rejected.
Validated against a real 73k-line, 3-VDOM FortiGate-121G config (lossless
roundtrip, zero parse warnings).

**`[sdwan …]`** moves interfaces into SD-WAN members by **generating the
new construct**, not just rewriting references: `config system sdwan`
(status, zone, members with gateways harvested from the removed default
routes), a health check **with an SLA target**, and **steering rules**
(`config service`) — SLA-mode by default, controllable per zone with
`rule = sla | load-balance | priority <member> | none`. Specific-prefix
routes that lived on a member (e.g. `10.50/16 via port3`) are converted
properly: an address object + a `manual` steering rule **pinned to that
member** (placed before the catch-all rule) + an `sdwan-zone` route — the
now-invalid member static route is removed. Existing policies are
rewritten to the zone, exact duplicates merged, and policies that now
match identical traffic but differ in NAT/profiles are flagged ("first
wins — reconcile"). The leftover audit still flags what needs a human
(e.g. a VIP pinned to a member).

## What's converted today (v1)

| source | status |
|---|---|
| Cisco ASA | interfaces, name aliases, network/service objects, object-groups (incl. nested + protocol groups), extended ACLs → policies, access-group bindings, static routes, object NAT (static → VIP, dynamic → interface PAT), route-based `dstintf` inference, **site-to-site VPN**: crypto maps + tunnel-groups → route-based phase1/phase2-interface (IKEv1+IKEv2 policies → proposals, transform-sets/ipsec-proposals, PFS preserved — including ASA's off-by-default vs FortiOS's on-by-default), plus the ramifications: tunnel routes, bidirectional VPN policies with route-inferred LAN interfaces, masked-PSK detection. Dial-up/dynamic maps and cert auth are flagged, not converted |
| Palo Alto (XML **and** `display set` formats) | interfaces (incl. L3 subinterfaces), zones → real FortiOS zones (`intrazone allow` to preserve PAN's default behavior, flagged), addresses/groups, services/groups (comma port lists, source ports, predefined service-http/https), security rules incl. negate-source/destination, NAT (interface PAT, bi-directional static + destination translation → VIPs with port-forward), static routes (egress inferred when omitted). **App-ID rules convert on their service match and are loudly flagged** — FortiOS application control must be recreated as profiles. Multi-vsys: first vsys, rest flagged. |
| pfSense (config.xml) | interfaces (incl. VLANs, logical wan/lan/optN names), aliases → addresses/groups/services (multi-entry, nested, port aliases with colon ranges), per-interface filter rules → policies (`lan net`/`wanip` macros, `<not/>` → negate, reject/block, log/disabled), gateways + static routes (incl. `defaultgw4`), port forwards & 1:1 NAT → VIPs, outbound automatic/hybrid → NAT on WAN-egress policies. Floating rules, rule-level policy routing, manual outbound NAT, IPv6, OpenVPN (no FortiOS equivalent), and IPsec are flagged |
| Juniper SRX (Junos, curly **and** `display set` formats) | **apply-groups inheritance expanded** before parsing (incl. `<ge-*>`/`unit <*>` wildcard groups); interfaces (units + VLAN sub-interfaces), security zones → FortiOS zones with **host-inbound-traffic → `allowaccess` guidance**, **zone-scoped address books** flattened with cross-zone collision renames, `applications`/`application-set` + **`junos-*` predefined apps → real ports** (so policies get exact services, not `ALL`), zone-pair **and** global policies → zone policies with address-excluded negation, NAT (source rule-set interface → `nat enable`, destination-nat pool → VIP w/ port-forward, static-nat → 1:1 VIP), static routes, **BGP/OSPF** (see dynamic routing row), **route-based AND policy-based IPsec** (policy-based `permit tunnel` → route-based tunnel with selectors from the policy's addresses; ike/ipsec proposal+policy+gateway, traffic-selectors/proxy-identity, PFS, IKEv2; `$9$`-encrypted PSK → placeholder + error), and **routing-instances → VDOMs** (interfaces/zones/policies/routes partitioned per instance, default = `root`, global policies replicated). logical-systems flagged for separate conversion |
| FortiOS | full-config lossless tree migration with interface mapping, zone/SD-WAN refactors, multi-VDOM |
| site-to-site IPsec | converted to route-based phase1/phase2-interface for **all four** cross-vendor sources (ASA crypto-maps, PAN ike-gateway/tunnel, pfSense phase1/phase2, SRX ike/ipsec + st0) — proposals, PFS, PSK (encrypted-export → placeholder), tunnel routes + bidirectional policies with route-inferred LAN side |
| Palo Alto App-ID | mapped to FortiOS application-control **categories** — rules generate a `config application list` profile wired onto the policy (`set application-list`); transport apps ignored, unmapped flagged. Category-level (coarser than FortiConverter's licensed per-signature ID table, which can't be reused clean-room) |
| IPv6 | converted across all parsers — addresses → `address6`, groups → `addrgrp6`, routes → `router static6`, policies → `srcaddr6`/`dstaddr6` (unified table). PAN v6 objects, pfSense inet6 rules + v6 routes, ASA unified-ACL v6 + `ipv6 route`. (Dedicated ASA `ipv6 access-list` and v6 IPsec selectors still flagged) |
| dynamic routing (BGP/OSPF) | SRX `protocols bgp/ospf` and PAN virtual-router protocols → `config router bgp` (AS, router-id, neighbors, networks, redistribute) and `config router ospf` (areas, network statements derived from area interfaces, passive-interface). Export/import policies and redistribution profiles are flagged for manual route-maps; missing router-ids derive from the first interface IP with a warning |
| not yet | ASA twice-NAT (flagged), Check Point / SonicWall / FTD parsers |

Cross-vendor conversions choose their **NAT mode**: `--nat-mode policy`
(default — per-policy `nat enable` + VIPs) or `--nat-mode central`
(`set central-nat enable` + generated `central-snat-map` rules, VIPs as
central DNAT, policies free of per-policy NAT). Also a select in the GUI.

Built-in FortiOS services are reused only on **exact** semantic match:
`tcp/443` becomes `HTTPS`, but `udp/53` is *not* mapped to built-in `DNS`
(which is tcp+udp) — silent rule broadening is the class of bug this tool
exists to prevent. Non-convertible port operators (`neq`) emit the policy
**disabled** with a review comment instead of a broader rule.

## Web UI

```
python -m pip install flask    # the only optional dependency
python -m fwforge gui          # opens http://127.0.0.1:4848
```

A local Flask app over the same pipeline the CLI uses (no logic of its
own), styled and structured like a management tool:

- **Conversions home**: persistent project list (survives restarts) with
  vendor/status chips, re-open, results, delete
- **Step wizard** per conversion: Source & Target → Interface Mapping
  (grid with ip/alias/VDOM hints) → *cross-vendor:* Policy Selection
  (searchable checkbox table — untick rules to exclude them) and Tuning →
  *FortiOS:* Restructure (zones, SD-WAN, hw-switch, SSL-VPN→IPsec) →
  Convert
- **Informed member pickers** for zones and SD-WAN: searchable checkbox
  tables showing each interface's IP, alias/description, type + role,
  VDOM, and firewall-policy reference count. Interfaces already committed
  (existing zone, SD-WAN, or another row of the plan) are greyed out with
  the reason; ticked SD-WAN members get per-member gateway/weight fields
  (blank gateway = harvested from the old default routes)
- **Tabbed results**: Summary (downloads + apply instructions), Findings
  (search + severity filter), Output (line-numbered preview), Changes
  (colorized diff for migrations)

Binds to localhost; configs never leave the machine.

## Development

```
python -m pip install -e .[dev]
python -m pytest
```

See [ROADMAP.md](ROADMAP.md) for the competitive analysis against
FortiConverter and what's next.

fwforge is a clean-room implementation: it contains no Fortinet code or
data files, only knowledge of the documented FortiOS CLI syntax.
