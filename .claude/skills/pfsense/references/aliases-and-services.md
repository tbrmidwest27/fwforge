# pfSense Alias / Object & Service Model → FortiOS Conversion

The data layer a pfSense→FortiOS converter needs so it **never silently broadens or drops** an
object/service. pfSense keeps everything in one `config.xml`; rules reference **aliases** (typed:
host / network / port / url*) and **interface macros** ("LAN net", "LAN address", `(self)`), and
carry a `protocol` + source/dest `port`. Each must resolve to an exact FortiOS object — and a
FortiOS predefined service is reused **only on exact protocol+port match**, else a tight custom
service. The #1 broadening trap here is resolving an interface macro (`LAN net`) or a `urltable`
to `all`, and collapsing a `tcp/udp` rule to a single transport.

**Sources (verified against the official Netgate docs, not memory):**
- pfSense — *Firewall Aliases* (overview, tabs IP/Ports/URLs): https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html
- pfSense — *Alias Types* (per-type contents, the authoritative table below): https://docs.netgate.com/pfsense/en/latest/firewall/aliases-types.html
- pfSense — *Alias Features and Limitations* (Nested Aliases, Hostnames in Aliases): https://docs.netgate.com/pfsense/en/latest/firewall/aliases-features.html
- pfSense — *Configuring Firewall Rules* (Source/Destination macros, Protocol, Port Range): https://docs.netgate.com/pfsense/en/latest/firewall/configure.html
- pfSense — *Firewall Rule Processing Order / Methodology* (per-interface inbound): https://docs.netgate.com/pfsense/en/latest/firewall/rule-methodology.html
- FortiOS CLI Reference — `config firewall address` (subnet/iprange/fqdn), `config firewall addrgrp`, `config firewall service custom`, `config system external-resource`: https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference

> fwforge code map: pfSense parsing in `fwforge/parsers/pfsense.py`. Alias handling in
> `parse_aliases()` (~L275); literal IP/CIDR → address object in `addr_for()` (~L154); service
> synthesis in `_services()` (~L467) + `svc_for()` (~L205); interface-macro resolution in
> `_endpoint()` (~L410); ICMP literal table `ICMP_PF` (~L55). This reference is the audit
> checklist for those functions.

> **Accuracy over coverage.** A wrong port — or a macro widened to `all` — silently broadens a
> firewall rule, the exact bug class fwforge exists to prevent. Where the safe answer is a tight
> object, this file says **"custom"/"interface-subnet object"**, never "reuse `all`".

---

## ⚠️ Top broadening / data-correctness traps (read first)

1. **Interface macro `LAN net` / `OPTx net` resolved to `all` broadens the whole rule.**
   pfSense "**Interface Subnets**" (rendered "LAN net", "WAN net", "OPT1 net") means *"networks
   directly attached to that interface"* — i.e. the interface's own subnet, NOT any-source. "LAN
   **address**" / "Interface Address" means the interface's own IP(s) (a /32-style host), used for
   to-the-firewall and reflection rules. Mapping either to FortiOS `all` opens the rule to the
   whole internet. Emit an **interface-subnet address object** (for `…net`) or a **host address**
   (for `…address` / the interface IP). Resolving to `all` is only acceptable as a flagged,
   reported loss when the subnet genuinely can't be determined (dynamic interface). (configure.html)

2. **`protocol = tcp/udp` is BOTH transports — collapsing narrows.** A pfSense rule with
   protocol `TCP/UDP` matches the port(s) on **tcp AND udp**. FortiOS must emit a service covering
   both transports (a custom with both `tcp-portrange` and `udp-portrange`, or two services in a
   group). Emitting only tcp (or only udp) silently **blocks** the other half — a correctness
   regression, not just a style issue. (Port aliases are protocol-agnostic, so the transport comes
   from the rule's `protocol` field, never the alias — aliases-types.html / configure.html.)

3. **`urltable` (and `urltable_ports`) is a *fetched* list, not a static object.** A URL Table
   alias *"downloads the content of the URLs into a special location on the firewall"* on a refresh
   interval (days), holding 40,000+ entries — it is a live external feed, not a fixed set of
   addresses present in `config.xml`. The IP-feed form maps to a FortiOS **external resource /
   threat feed** (`config system external-resource`, type `address`/`category`) referencing the same
   URL, NOT to a frozen snapshot (which would go stale and silently drift). `urltable_ports` has
   **no FortiOS port-feed equivalent** → must be reported and recreated manually, never dropped.
   (aliases-types.html)

Honorable mention: a pfSense **Host alias accepts a range** (`192.168.1.1-192.168.1.10`) and an
FQDN; a **Port alias holds ranges + mixed single ports together** (`80 443 8000:8090`). Don't
assume one entry per alias, and don't lose the range/colon syntax.

---

## 1. The pfSense alias model (`<aliases>` in config.xml)

Every `<alias>` has a `<name>`, a `<type>`, a space-separated `<address>` (the members — IPs,
CIDRs, ports, ranges, FQDNs, or **other alias names** when nested), and `<descr>`. The `<type>`
determines the namespace and the FortiOS target.

| pfSense `type` | Holds (per *Alias Types* doc) | FortiOS target | Traps |
|---|---|---|---|
| `host` | *"Individual IP addresses or fully qualified domain names (FQDNs)."* Ranges like `192.168.1.1-192.168.1.10` are accepted and **expanded to individual IPs on save**. | `firewall address` (type `ipmask` /32 for one IP, `iprange` for a range, `fqdn` for a hostname). Multi-entry → `firewall addrgrp` of those. | A single-label hostname (`intranet`) is a valid host member → FortiOS **FQDN** address, not a phantom group ref. A range entry → `type iprange`, never widened to a subnet. |
| `network` | *"CIDR format networks/prefixes or fully qualified domain names (FQDN) for single addresses."* `/32` (v4) and `/128` (v6) allowed for single hosts; ranges auto-translated to equivalent CIDRs. | `firewall address` (type `ipmask` subnet; `/32`→host) or `addrgrp` if multi-entry. FQDN member → `fqdn` address. | `/32`/`/128` collapse to a host object (cosmetic); a 0.0.0.0/0 member effectively = any → flag, don't silently bury inside an addrgrp. |
| `port` | *"Port numbers and port ranges."* Ranges use **colon** syntax (`1194:1199`). *"Port aliases do not have a direct relationship with any protocol"* — **protocol-agnostic**; the rule supplies TCP/UDP/SCTP. | Materialized **per protocol at rule-conversion time** into `firewall service custom` (tcp-portrange / udp-portrange), or a service group when multiple ranges. | Colon `from:to` must become FortiOS `from-to`. An alias holding **mixed single ports + ranges** (`80 443 8000:8090`) → one service with all ranges, or a group. The SAME alias can be referenced under a tcp rule and a udp rule — emit the right transport each time. |
| `url` (a.k.a. *URL (IPs)*) | One-time download of up to ~3,000 IPs/CIDRs/FQDNs from a URL → becomes a **Network**-type alias (static snapshot at import). | Static: `firewall addrgrp` of the fetched members, **or** a `system external-resource` (address) if you want it live. | It is a snapshot, so a static addrgrp is faithful to pfSense behavior — but flag it as URL-sourced. |
| `url_ports` (*URL (Ports)*) | One-time download of port numbers/ranges → becomes a **Port**-type alias. | Same as `port`: per-protocol custom services from the fetched ports. | Same protocol-agnostic + colon-range handling as `port`. |
| `urltable` (*URL Table (IPs)*) | **Periodically fetched** list (refresh interval in days), 40,000+ IPs/networks/FQDNs, stored in a special file — a **live external feed**. | FortiOS **`config system external-resource`** type `address` (or `category` for an IP feed) pointing at the same URL + refresh; referenced as an external address object in policy. | **NOT a static snapshot.** Freezing it goes stale → silent drift. This is trap #3. |
| `urltable_ports` (*URL Table (Ports)*) | Periodically fetched **port** list. | **No FortiOS equivalent** (external-resource feeds are address/category/MAC, not ports). | Report + recreate manually as static custom services; never silently drop. |

**Nested aliases** (*Alias Features*): an alias may contain **other alias names** as members, but
only of **compatible types** — *"Host Aliases and Network Aliases can nest each other,"* URL nests
URL, URL-table nests URL-table; a Network alias **cannot** nest a Port alias. FortiOS `addrgrp`
supports nested groups, so keep the nesting (or flatten) — but preserve it; don't expand-and-lose
the structure. A port alias nested in another port alias → merge the port ranges. fwforge classifies
a member as a nested-alias **reference** iff its name is in the set of all alias names
(`alias_names`), else it's a literal — this correctly handles a bare-hostname member that has no
`.`/`/`/`:`.

**Hostnames / FQDN in aliases** (*Alias Features*): pfSense host/network aliases accept FQDNs,
resolved by DNS (A/AAAA only, no wildcards, default 300s refresh). A host-alias member that isn't a
valid IP/CIDR → FortiOS **`firewall address` type `fqdn`**. Don't treat an unresolved hostname as an
error/drop.

> **fwforge status — §1 alias model**
> - host / network single-entry literal → ✅ `parse_aliases()` L309-331 emits host/subnet, and a
>   non-IP single entry → `type fqdn` (L313-319). Multi-entry → `addrgrp` (L345). Good.
> - **Host alias *range* (`a-b`)** → ⚠️ **GAP**: ranges hit `addr_for()` (L154), which only accepts
>   a literal IP or CIDR (`ipaddress.ip_network`) — a `1.1.1.1-1.1.1.10` member fails both and falls
>   to the `fq-<lit>` FQDN path (L337-344), producing a bogus FQDN object instead of a FortiOS
>   `iprange`. pfSense expands ranges to individual IPs on save, so a *saved* config usually won't
>   contain a literal range — but an exported/edited one can. Add `iprange` handling.
> - nested aliases → ✅ classified via `alias_names` membership (L281, L305) and kept as addrgrp
>   members; nesting preserved. ⚠️ Port-alias-nested-in-port-alias is not merged (port aliases are
>   stored raw in `_port_aliases` L289-291; a nested name wouldn't expand) — partial.
> - `url` / `urltable` / `urltable_ports` / `url_ports` → ⚠️ all funnel to one warn at L292-297
>   ("recreate as a FortiOS external resource or FQDN objects") and are **not** emitted as objects.
>   Honest loss (reported, not silent) but no external-resource generation yet — GAP for a faithful
>   live-feed conversion.

---

## 2. pfSense interface / address macros used in rules

These are pfSense's analog of a zone/interface reference and the **most common silent-broadening
spot**. In `config.xml` they appear inside `<source>`/`<destination>` as `<any/>`, `<network>`,
`<address>`, or the bare interface keyword. The dropdown labels (configure.html) map as:

| pfSense rule macro | `config.xml` form | Meaning (doc) | FortiOS equivalent |
|---|---|---|---|
| **any** | `<any></any>` | any address | `all` |
| **Single host or alias** | `<address>NAME-or-IP</address>` | one IP or an alias | the alias/address object (or a /32 `firewall address`) |
| **Network** | `<address>CIDR</address>` | an IP + CIDR mask | `firewall address` subnet |
| **"LAN net" / "OPTx net" / "WAN net"** (*Interface Subnets*) | `<network>lan</network>` / `opt1` / `wan` | *"networks directly attached to that interface"* — the interface's own subnet | a **`firewall address` subnet** object built from the interface's IP/mask (e.g. `lan-net`) |
| **"LAN address" / "OPTx address"** (*Interface Address*) | `<network>lanip</network>` (the `…ip` suffix) | *"all IP addresses configured on that interface"* — the interface's own IP | a **host `firewall address`** (the interface IP /32), or `set srcaddr`/`dstaddr` to that object |
| **This firewall (self)** | `<network>(self)</network>` | all IPs on all firewall interfaces | typically the FortiGate itself — no single object; for to-self rules use local-in policy or the relevant interface address; flag, don't widen to `all` |
| **PPPoE clients** | `<network>pppoe</network>` | PPPoE server client address range | the PPPoE client pool subnet (recreate as an address object); flag — pool may be dynamic |
| **L2TP clients** | `<network>l2tp</network>` | L2TP server client address range | the L2TP/VPN client pool subnet (address object); flag |

**Why this is the broadening hotspot:** `…net` and `…ip` macros resolve to *narrow* objects (a
subnet or a host). If the converter can't resolve the interface's address (dynamic/DHCP/PPPoE
interface) the temptation is to substitute `all` — which **broadens** the rule from "my LAN" to
"the entire internet". The correct fail-safe is to emit the narrowest known object, and where the
subnet is genuinely unknown, **report the loss loudly** (and prefer leaving the rule disabled or
flagged over silently widening).

> **fwforge status — §2 interface macros**
> - `any` → ✅ `_endpoint()` L417-418 returns `all`.
> - **`<network>lan</network>` ("LAN net")** → ✅ L439-449 builds a `{net}-net` subnet object from
>   the interface IP. Good — narrow, not `all`.
> - **`lanip` ("LAN address")** → ✅ L429-438: `…ip` suffix resolves to the interface's host
>   address; if unknown → ⚠️ falls back to `all` **with a warn** (L435-437). The warn keeps it
>   non-silent, but the fallback **broadens** — consider emitting a placeholder/disabled instead.
> - **dynamic-interface `…net` unresolved** → ⚠️ same `all` fallback + warn (L450-453). Reported,
>   but broadening; same recommendation.
> - **IPv6 interface-network macros** → ⚠️ L421-428: returns `all` + warn (v6 subnet not resolved).
>   Reported loss, broadening — GAP for v6.
> - **`(self)`, `pppoe`, `l2tp`** → ❌ **GAP**: not special-cased. They land in the `<network>`
>   branch, fail `interface_by_name`, and fall to the `all`-with-warn path — `(self)` becoming `all`
>   is a meaningful over-broadening. Add explicit handling.
> - negation (`<not/>`) → ✅ honored as `src_negate`/`dst_negate` (L416, L563).

---

## 3. Service / port model

A pfSense rule carries `<protocol>` plus `<source><port>` / `<destination><port>` (single port,
range `from:to`, or a **port-alias name**). Per configure.html the Protocol field offers **any, TCP,
UDP, TCP/UDP, SCTP, ICMP** and the raw IP protocols **ESP, AH, GRE, IGMP, OSPF, PIM, CARP, pfsync**
(and others). Map to FortiOS `firewall service custom`:

| pfSense `protocol` | FortiOS service | Notes / trap |
|---|---|---|
| (empty / **any**) | `ALL` | any IP protocol |
| `tcp` | custom `tcp-portrange <dst>[:<src>]` | dst ports from the port field/alias |
| `udp` | custom `udp-portrange …` | |
| **`tcp/udp`** | custom with **both** `tcp-portrange` AND `udp-portrange` (or a group) | **trap #2** — emit BOTH transports; collapsing narrows |
| `sctp` | custom `sctp-portrange …` | FortiOS supports SCTP services |
| `icmp` | ICMP service by **type** (see ICMP table) or `ALL_ICMP` if no type | IPv6 rule / `ipv6-icmp` → `ALL_ICMP6` |
| `esp` | custom, `protocol IP`, `protocol-number 50` | (FortiOS built-in `ESP`/`AH` exist — reuse only on exact proto match) |
| `ah` | proto-number 51 | |
| `gre` | proto-number 47 | |
| `igmp` | proto-number 2 | |
| `ospf` | proto-number 89 | |
| `pim` | proto-number 103 | |
| (unknown proto) | **do NOT default to `ALL`** | report; emit policy disabled rather than broaden |

**Port forms.** Single port → `tcp-portrange 443`. Range `from:to` (pfSense colon) → FortiOS
`from-to` (e.g. `8000:8090` → `8000-8090`). **Port alias** → look up the alias's space-separated
ranges and materialize a custom service (one service with all ranges, or a service group). Because
port aliases are **protocol-agnostic**, the transport comes from the rule's `protocol` — the **same**
port alias used under a tcp rule and a udp rule yields two different FortiOS services.

**No-broadening doctrine (same as the ASA/PAN skills).** Reuse a FortiOS **predefined** service
**only** when its protocol AND complete port set match exactly: `tcp/443`→`HTTPS` ✓; `tcp/80`→`HTTP`
✓; `udp/53` alone → built-in `DNS` ✗ (FortiOS `DNS` is tcp+udp/53, wider). Otherwise synthesize a
tight custom service. Never widen to `ALL` for an unmapped protocol.

**Source-port note.** pfSense rules can set a **source** port (`<source><port>`). FortiOS firewall
services match on destination ports natively; a source-port constraint that can't be carried must
**not** be dropped to "any source port" (that broadens) — carry it on the service's src-port-range
or flag it.

**ICMP / icmptype.** pfSense stores ICMP subtype in `<icmptype>` using its own short tokens. Map by
type number; with no type → all-ICMP. fwforge's table (`ICMP_PF`):

| pfSense `icmptype` | Type # | | pfSense `icmptype` | Type # |
|---|---|---|---|---|
| `echoreq` | 8 (≈ PING request) | | `timex` | 11 (time exceeded) |
| `echorep` | 0 (echo reply) | | `paramprob` | 12 |
| `unreach` | 3 (dest unreachable) | | `timereq` | 13 |
| `squench` | 4 (source quench) | | `timerep` | 14 |
| `redir` | 5 (redirect) | | `inforeq` | 15 |
| `routeradv` | 9 | | `inforep` | 16 |
| `routersol` | 10 | | `maskreq` | 17 |
| `trace` | 30 (traceroute) | | `maskrep` | 18 |

For an IPv6 (`inet6`) rule or `ipv6-icmp`, emit a FortiOS **ICMP6** service (`ALL_ICMP6` / proto 58),
not an IPv4 ICMP type.

> **fwforge status — §3 service model**
> - tcp / udp / **tcp/udp** → ✅ `_services()` L484-496 passes `proto` straight through (`"tcp/udp"`
>   carried as the IR protocol → both transports downstream). Port-alias lookup + colon→dash done in
>   `parse_aliases` (L289 `.replace(":", "-")`) and `_endpoint` (L415). Good.
> - **`sctp`** → ⚠️ **partial**: not in the tcp/udp branch (L484), so it falls to the raw IP-proto
>   map (L498-499) where `sctp` → proto-number 132. That is *safe* (not broadened to ALL) but
>   **loses port granularity** — an `sctp` rule with a dest port becomes a portless proto-132
>   service. Add `sctp` to the L484 branch → `sctp-portrange` to preserve ports.
> - raw IP protos esp / ah / gre / igmp / ospf / pim / sctp → ✅ all present in the map at L498-499
>   (esp 50, ah 51, gre 47, igmp 2, ospf 89, pim 103, sctp 132); each → a custom proto-number
>   service. Good — never falls to `ALL` for these.
> - ICMP type mapping → ✅ `ICMP_PF` L55-60 + `_services()` L471-483; unmapped type → `ALL_ICMP` +
>   info note (non-silent). v6 → `ALL_ICMP6`. Good.
> - **predefined exact-match reuse** → ⚠️ `_services()` always synthesizes a custom service
>   (`{label}_{proto}`) — it never reuses FortiOS built-ins like `HTTPS`/`HTTP`. That's *safe*
>   (never broadens) but misses tidy reuse; not a correctness bug. Optional enhancement.
> - source-port → ✅ flagged (L537-541): not carried, info note. Non-silent.

---

## 4. Confirmed data-correctness notes

- **`protocol = tcp/udp` is BOTH transports.** Must emit tcp *and* udp coverage; emitting one
  silently blocks the other. (configure.html — TCP/UDP is a distinct protocol choice.)
- **Port aliases are protocol-agnostic.** The transport is on the *rule*, not the alias — the same
  port alias yields different FortiOS services under tcp vs udp rules. Never bake a transport into
  the alias. (aliases-types.html: *"Port aliases do not have a direct relationship with any
  protocol."*)
- **Port-alias colon ranges (`from:to`) and mixed members.** `1194:1199` → FortiOS `1194-1199`; an
  alias holding `80 443 8000:8090` carries three ranges in one alias — preserve all. (aliases-types)
- **Host aliases accept IP *ranges* and FQDNs.** `192.168.1.1-192.168.1.10` → FortiOS `iprange`;
  a hostname → `fqdn`. pfSense expands ranges to individual IPs on save, so most *saved* configs
  show discrete IPs, but don't assume it. (aliases-types / aliases-features)
- **`LAN net` ≠ `all`; `LAN address` ≠ `LAN net`.** "net" = the interface **subnet**; "address" =
  the interface's **own IP**. Two different narrow objects — neither is any-source. Widening either
  to `all` is the headline broadening bug. (configure.html)
- **`(self)` is the firewall itself, not `all`.** Rules to/from `(self)` are to-the-box traffic
  (FortiOS local-in / interface address), not transit to everywhere. (configure.html)
- **`urltable` / `urltable_ports` are *fetched* lists, not static objects.** The IP form → FortiOS
  external-resource feed (live, same URL + refresh); the port form has no feed equivalent → manual.
  A frozen snapshot silently drifts from the source. (aliases-types.html)
- **`url` / `url_ports` are one-time imports** that become Network/Port aliases — a static snapshot
  is faithful, but tag the provenance.
- **Unmapped protocol must fail closed.** An unknown `<protocol>` (or a non-convertible construct)
  must report + emit the policy disabled, never fall back to `ALL`. (Mirrors the ASA `neq` /
  fail-closed doctrine.)

## Sources
- https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html
- https://docs.netgate.com/pfsense/en/latest/firewall/aliases-types.html
- https://docs.netgate.com/pfsense/en/latest/firewall/aliases-features.html
- https://docs.netgate.com/pfsense/en/latest/firewall/configure.html
- https://docs.netgate.com/pfsense/en/latest/firewall/rule-methodology.html
- https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference
