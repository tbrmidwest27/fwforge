# PAN-OS App-ID & Service Model → FortiOS Conversion

How a PAN-OS security rule's `application` (App-ID, L7) and `service` (L4 port) fields
work, and how each must convert to FortiOS. The #1 silent-broadening trap here is
`service application-default`. Grounded in the PAN-OS Admin Guide + FortiOS CLI Reference
(URLs cited per section). Complements fwforge's existing App-ID layer; gaps are called out.

> fwforge code map: PAN parsing in `fwforge/parsers/paloalto.py`; App-ID→FortiGuard data
> layer in `fwforge/parsers/pan_appid.py`; app DB in `fwforge/data/pan_apps.json`
> (**504 apps** as of 2026-06-18 — the "~177" in older notes is stale); category crosswalk
> in `fwforge/data/pan_cat_xwalk.json`.

---

## 1. `application` vs `service` are two independent match dimensions

A PAN rule matches on **both** an `application` list (App-ID, L7) **and** a `service` (L4),
ANDed. FortiOS matches on `service` (port) only; App-ID-equivalent matching is a separate
Application Control sensor (`set application-list`). The `service` field takes three forms:

| PAN `service` | Meaning | WRONG conversion | Correct conversion |
|---|---|---|---|
| `any` | any TCP/UDP port (App-ID still constrains L7) | `service ALL` (ok here) | `service ALL` + app-control sensor |
| `application-default` | app may run **only on its standard port(s)** | `service ALL` — **SILENTLY BROADENS** | per-app standard-port services (§4) + app-control |
| a Service object | those ports only | — | exact-match reuse rule (§3) |

`application-default` is the critical case. PAN: *"application-default … only allowing
applications to run on their standard ports."* Converting it to `service ALL` turns a rule
that allowed `web-browsing` on tcp/80 into one allowing the traffic on all 65535 ports.
It is **NOT** `service ANY`.
Source: https://docs.paloaltonetworks.com/ngfw/administration/app-id/application-default

### App dependencies & implicit apps (fwforge GAP)
An App-ID may **depend on** other App-IDs; a subset are **implicitly used** (pulled in
automatically) — e.g. `facebook`→HTTP+SSL, `dropbox`→SSL, `kerberos`→RPC. The dependency's
ports can widen the true `application-default` set. fwforge does **not** model dependencies/
implicit apps (`pan_apps.json` has no `depends_on`/`implicit_apps`; only application-*groups*
are expanded), so an `application-default` conversion can **under-permit** (break the app).
Flag rules whose apps have known dependencies for manual port review; future: add a
`depends_on` field.
Sources: https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/app-id/applications-with-implicit-support · https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/app-id/use-application-objects-in-policy/resolve-application-dependencies

---

## 2. Application groups / filters → the two-part FortiOS conversion

| PAN construct | Definition | FortiOS target |
|---|---|---|
| Application object (App-ID) | single predefined/custom app | app-control sensor entry (signature) or its FortiGuard category |
| Application group | static named list of App-IDs/nested groups | expand to members → app-control entries (or `config application group`) |
| Application filter | **dynamic** set by category/subcategory/technology/risk/behavior | app-control category/risk/technology filter entry (closest analog) |

**The two-part conversion (core mental model).** A PAN App-ID rule is L7+L4 combined;
FortiOS splits these into two objects attached to the *same* policy:
1. **A service** (`set service`) — L4 ports (from `application-default` resolution §4, or the explicit Service object).
2. **An app-control sensor** (`set application-list`) — L7 match, independent of `set service`.

So an App-ID maps to **FortiOS Application Control, NOT a port-based service**. A faithful
conversion emits **both**. Keep only the service → lose L7 enforcement; keep only app-control
→ lose the `application-default` port restriction.
Sources: https://docs.fortinet.com/document/fortigate/7.0.0/cli-reference/436620/config-application-list · https://docs.fortinet.com/document/fortigate/7.4.2/cli-reference/391620/config-application-group

**fwforge:** `paloalto.py` builds both — `_app_list_for()`/`_app_list_sigs()` (FortiGuard
signatures, or `pan_appid.map_apps()` category fallback; groups flattened via
`_expand_app_groups()`; filters via `pan_appid.categories_for_pan_filter()` + crosswalk) →
`AppList` IR; and the service side (§4). Both attach to the same `Policy`. Application
*filters* are dynamic — FortiOS category filters approximate them (fwforge flags this);
unmapped custom App-IDs are reported UNMAPPED, never silently dropped.

---

## 3. Predefined & custom Services → FortiOS

| PAN predefined service | Protocol / ports | Notes |
|---|---|---|
| `service-http` | **tcp/80 and tcp/8080** | PAN's default HTTP includes the 8080 alt-port — don't narrow to 80 only |
| `service-https` | **tcp/443** | |

fwforge hardcodes exactly these in `PREDEFINED_SERVICES`. Custom services: TCP/UDP,
destination port (or `port1-port2` range), optional source port, comma-separated lists.
`parse_services()` handles tcp/udp/tcp+udp (splits into `<name>-tcp`/`<name>-udp` + group
when ports differ), icmp/icmp6 (with type), raw IP-proto (GRE/ESP/AH/SCTP).
Source: https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/services

**Exact-match reuse rule (do not broaden).** Reuse a FortiOS built-in only on exact
semantic match. `tcp/443→HTTPS` ✓. `udp/53→built-in DNS` ✗ (built-in DNS is tcp+udp).
fwforge uses per-app curated `builtin_services` (only where exact), else synthesizes a tight
custom service from literal ports.

---

## 4. `application-default` → where the ports come from

Allowed ports = the standard ports of each App-ID in the rule, resolved per-app. fwforge
resolution order (`_app_port_specs()`/`_appdefault_services()`):
1. **Application groups** expand to leaf apps first (service side agrees with app-control side).
2. **Custom app objects** carry their own `default→port`/`ident-by-ip-protocol`/`ident-by-icmp-type` in the PAN config — read directly (most authoritative).
3. **Curated App-ID DB** (`pan_apps.json` via `pan_appid.default_ports()`) for predefined apps — fwforge's stand-in for Applipedia, extended via `fwforge applipedia import` + the gap analyzer.
4. Per-app: FortiOS **built-in** on exact match, else a tight synthesized custom service. Ports merged per-protocol within one app, never across apps.

**App-ID with NO known port mapping — correct behavior:** keep service `ALL` **+ loud
warning** (restricting to the partial known set would wrongly block the unresolved app).
This is the honest-loss path — the loosening is reported, never silent. (Fill the gap +
tighten via the App-ID gap analyzer / `applipedia import`.) `any` in the app list dominates
→ `ALL` + app-control + note.

---

## 5. App-ID conversion gotchas / silent-loss checklist

1. **`application-default` ≠ `ANY`/`ALL`** — the #1 broadening trap; restricts apps to standard ports. Verify any `application-default` rule that landed on `ALL`.
2. **App-ID is L7, not a port — emit BOTH** a service and an app-control sensor on the policy.
3. **Dependencies/implicit apps not modeled (gap)** — `application-default` can under-permit; flag apps with known deps for port review.
4. **Exact-match service reuse only** — `udp/53` ≠ built-in DNS; prefer synthesized custom service.
5. **Application filters are dynamic** — FortiOS category filters approximate; flag unmapped criteria.
6. **Unmapped custom App-IDs** — report UNMAPPED, never silently omit (would pass traffic unenforced).
7. **tcp/udp services with differing ports** — must NOT collapse to one object (broadens one protocol).
8. **`service-http` includes tcp/8080** — don't narrow to 80.
9. **`any` app dominates a mixed app list** → `ALL` + app-control + note.
10. **`drop` vs `deny` + disabled rules** — both PAN drop/deny → FortiOS `deny` (note the lost silent-drop distinction); a `disabled` rule must convert as a disabled policy, never omitted.

## Sources
- https://docs.paloaltonetworks.com/ngfw/administration/app-id/application-default
- https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/app-id/applications-with-implicit-support
- https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/app-id/use-application-objects-in-policy/resolve-application-dependencies
- https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/services
- https://docs.fortinet.com/document/fortigate/7.0.0/cli-reference/436620/config-application-list
