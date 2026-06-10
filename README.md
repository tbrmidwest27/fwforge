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

`convert` writes four artifacts:

| file | what it is |
|---|---|
| `<name>.fos.conf` | paste-able FortiOS CLI script (deterministic — diffs cleanly between runs) |
| `<name>.report.md` | human conversion report: counts, coverage %, errors / warnings / notes |
| `<name>.report.json` | machine-readable report with full per-line provenance |
| `<name>.portmap` | sample interface map, written when interfaces are unmapped |

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

### Version-upgrade artifact scan

When a FortiGate-to-FortiGate migration also jumps FortiOS versions, the
scanner reports what the version change leaves behind. Source version is
read from the `#config-version` header automatically; target comes from
`--fortios`:

```
python -m fwforge convert old-box.conf --fortios 8.0 --plan m.plan
```

Three artifact classes, each in the report with severity and the affected
entry names:

- **removed features** — dropped silently by the new firmware on load
  (7.6: SSL-VPN; 8.0: `gui-dashboard` under admin, `intra-vap-privacy`)
- **renames** — safe ones auto-fixed and noted (`hw-model`→`hw-version`,
  `virtual-wan-link`→`sdwan`)
- **default flips** — the invisible class: settings the config never
  wrote because it relied on the old default (8.0 changed IPsec DH groups
  14/5→20/21, hairpin `allow-traffic-redirect`, inline IPS enforcement).
  No text diff can show these; only a rule base can.

The rule table (`transforms/versiondelta.py`) is curated from Fortinet's
release-notes "Changes in CLI / default behavior" pages — deliberately
conservative; extend it as versions land.

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

**`[sdwan …]`** moves interfaces into SD-WAN members with the provisions
that entails: `config system sdwan` created/extended (status, zone,
members), per-member default routes removed and their gateways harvested
onto the members, a single `sdwan-zone` static route created in their
place, kept member routes flagged, a health check generated (or
`health-check = none`), policies rewritten to the SD-WAN zone, duplicates
merged, and the same leftover audit run (a VIP pinned to a member gets
flagged, for example).

## What's converted today (v1)

| source | status |
|---|---|
| Cisco ASA | interfaces, name aliases, network/service objects, object-groups (incl. nested + protocol groups), extended ACLs → policies, access-group bindings, static routes, object NAT (static → VIP, dynamic → interface PAT), route-based `dstintf` inference |
| Palo Alto (XML **and** `display set` formats) | interfaces (incl. L3 subinterfaces), zones → real FortiOS zones (`intrazone allow` to preserve PAN's default behavior, flagged), addresses/groups, services/groups (comma port lists, source ports, predefined service-http/https), security rules incl. negate-source/destination, NAT (interface PAT, bi-directional static + destination translation → VIPs with port-forward), static routes (egress inferred when omitted). **App-ID rules convert on their service match and are loudly flagged** — FortiOS application control must be recreated as profiles. Multi-vsys: first vsys, rest flagged. |
| FortiOS | full-config lossless tree migration with interface mapping, zone/SD-WAN refactors, multi-VDOM |
| not yet | VPN (flagged, never silent), twice-NAT (flagged), Check Point / Juniper parsers |

Built-in FortiOS services are reused only on **exact** semantic match:
`tcp/443` becomes `HTTPS`, but `udp/53` is *not* mapped to built-in `DNS`
(which is tcp+udp) — silent rule broadening is the class of bug this tool
exists to prevent. Non-convertible port operators (`neq`) emit the policy
**disabled** with a review comment instead of a broader rule.

## Development

```
python -m pip install -e .[dev]
python -m pytest
```

See [ROADMAP.md](ROADMAP.md) for the competitive analysis against
FortiConverter and what's next.

fwforge is a clean-room implementation: it contains no Fortinet code or
data files, only knowledge of the documented FortiOS CLI syntax.
