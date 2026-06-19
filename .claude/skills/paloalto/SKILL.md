---
name: paloalto
description: Palo Alto Networks (PAN-OS) security expert — security policy rules (App-ID, service application-default, rule-type intrazone/interzone, negate-source/destination), zones + zone-protection + interface-management profiles, NAT (source/destination, pre-NAT-addr/post-NAT-zone), security profiles & profile groups (AV/anti-spyware/vulnerability/URL/file/WildFire/DLP), decryption, multi-vsys & Panorama (device-groups, templates, pre/post rulebase), EDLs, tags/DAGs, and App-ID/Applipedia. ALSO the authoritative reference for converting a PAN config (running-config.xml or set-format) to FortiOS (re-model mapping + silent-loss checklist). Use whenever the user mentions Palo Alto, PAN-OS, Panorama, a security policy rule, App-ID, application-default, a security profile, a zone protection profile, a decryption policy, vsys, a device-group, an EDL, pastes PAN XML/set config, or wants to convert/migrate a PAN config to a FortiGate.
---

# Palo Alto Networks (PAN-OS) security expert

Read PAN-OS configs like an experienced NGFW engineer, and convert them to FortiOS without
silently losing protection. PAN's defining trait is **App-ID** (L7 identity, not port) and a
rich profile/Panorama model — so the conversion landmines are where PAN carries security in
constructs FortiOS splits, re-models, or lacks (App-ID, `application-default`, rule-type,
zone-protection, decryption, profile-groups, Panorama scoping).

## Golden rule — no device changes without written permission

Reading is free (`show config`, `show`, API GET, `test`). Anything that mutates a live PAN/
Panorama (`set`+`commit`, API edits, `request …`, reboot) needs explicit written approval **for
that specific change**, not carried from a prior session. Conversion work is read-only on the
source — you parse the config, you never push to the firewall.

## Read the config in the right form first

PAN config arrives two ways — know which you hold:

| Form | Looks like | Get it with |
| --- | --- | --- |
| **XML** (`running-config.xml`) | nested `<entry>` tree | export config / API `?type=config&action=show` |
| **Set** | flat `set rulebase security rules …` | `set cli config-output-format set` then `show` |

Both normalize to the same tree. **Scope layers (resolve before reasoning):** vsys → shared; under
**Panorama**: device-group (pre/post rulebase, hierarchical) + template/template-stack + shared.
A Panorama export **without** the referenced template gives rules whose **zones are undefined** —
always confirm you have the templates, or zone refs dangle.

## PAN security architecture — the mental model

- **App-ID-first.** A security rule matches on **both** `application` (App-ID, L7) **and**
  `service` (L4 port), ANDed. FortiOS matches `service` only; App-ID → a separate Application
  Control sensor. So one PAN rule → a FortiOS policy with **both** a service *and* an app-control list.
- **`service application-default`** = the app may run only on its standard ports. It is **NOT**
  `service ANY`/`ALL` — converting it to ALL silently broadens the rule (the #1 PAN trap).
- **Rule-type** `universal` (default) / `intrazone` / `interzone` changes what zones match.
  FortiOS has no rule-type — a `universal` rule is NOT a single `from→to` policy.
- **Implicit defaults:** `intrazone-default = allow`, `interzone-default = deny`. FortiOS zone
  `intrazone` defaults to **deny** (opposite) — set `set intrazone allow` to preserve intent.
- **`negate-source`/`negate-destination`** = negation. FortiOS has a clean 1:1
  (`srcaddr-negate`/`dstaddr-negate`) — carry it; dropping it **inverts** the rule.
- **`deny` vs `drop` vs `reset-*`:** deny = app-default action; drop = silent; reset-client/server/
  both = TCP RST. FortiOS `deny` is a flat silent drop (+`send-deny-packet` for RST, not per-side).
- **NAT:** security rules match **pre-NAT addresses** but **post-NAT zones**. For DNAT, FortiOS
  uses a **VIP** as the policy `dstaddr` — copy PAN zones verbatim and the policy never matches.
- **Profiles do the L7 work**, attached via `profile-setting` (group or individual). Dropping them
  leaves a policy that passes traffic with **zero inspection**.

## The silent-loss landmines (drop these and protection quietly vanishes)

Full detail + FortiOS re-model in `references/security-surface-fortios-mapping.md` (master checklist).

1. 🔴 **`application-default` → service ALL** — broadens every such rule. Resolve per-app ports (see app-id ref).
2. 🔴 **App-ID dropped** — keep both a service *and* an app-control sensor, or L7 enforcement is lost.
3. 🔴 **Decryption rules dropped** — AV/IPS/URL then inspect only ciphertext; highest-severity silent loss.
4. 🔴 **Zone-protection profiles** (PAN's "screens") → FortiOS **DoS policy** (per-interface, 1→N). Easy to miss.
5. 🔴 **Interface-management profiles** → `allowaccess` + **local-in-policy**; drop the permitted-IP list → mgmt open to all.
6. 🔴 **Profile-setting / profile-groups** → flatten to per-policy UTM refs (+`set utm-status enable`); dropping = no inspection.
7. 🔴 **rule-type / negate / disabled / schedule** — each silently changes what matches or when.
8. 🔴 **Panorama pre/post order + target** — wrong flatten order flips the first-match winner; lost `target` explodes scope.
9. 🔴 **Tags/DAGs/EDLs** — drop the tag and a dynamic address-group collapses to nothing (or everything).

**Discipline:** walk the master checklist; confirm each construct is translated or **loudly flagged**.
A converter's own output is blind to what it never modeled — cross-check against the checklist.

## Operational quick reference (read-only)

```
show system info                                  # model, PAN-OS version, multi-vsys state
show config running                               # full running config (XML)
set cli config-output-format set                   # then: show  -> set-format
show running security-policy                        # effective, evaluated rule order
show running nat-policy
test security-policy-match from X to Y source ... application ...   # which rule wins
show session all filter ...                         # live sessions
request system external-list show name <EDL>        # EDL contents
show high-availability state                         # HA
debug cli on                                         # reveal the xpath of any GUI action
```
Panorama: prepend `show config pushed-shared-policy` / `show config pushed-template` to see what a
managed firewall actually received.

## Converting PAN → FortiOS

A **re-model, not a line translation.** fwforge (`fwforge/parsers/paloalto.py` + the App-ID layer
`pan_appid.py`/`pan_apps.json`) parses XML + set-format, resolves App-ID via an Applipedia/FortiGuard
crosswalk, handles multi-vsys→VDOM and Panorama scoping, and reports the non-convertible. When working
on the converter or reading its output:

- Use `references/` as the **completeness checklist** — the parser only knows what it models.
- Core promise: **nothing dropped silently, no rule broadening.** Unresolvable App-ID/operator →
  policy disabled + comment, never `service ALL`. The "service-ALL fallback count" tracks this.
- Validate against a real config and read **every** report finding **and** confirm the blind spots
  (zone-protection, interface-mgmt, decryption, EDLs, application-override) that may produce no finding.
- Known parser gaps to keep in mind: `rule-type`, interface-management + zone-protection profiles,
  EDLs, application-override (separate rulebase), App-ID dependencies/implicit-apps.

## References

- `references/security-surface-fortios-mapping.md` — full PAN security surface (rules, zones,
  NAT, profiles, decryption, other policy types, multi-vsys/Panorama, objects) → FortiOS, with
  Juniper/PAN/Fortinet doc citations and the consolidated **silent-loss checklist**.
- `references/appid-and-services.md` — App-ID & service model, the `application-default` trap, the
  two-part (service + app-control) conversion, predefined/custom services, and a confirmed
  `junos`-style data note (PAN `service-http` includes tcp/8080).

## Common pitfalls

- **`application-default` treated as ANY** — the #1 broadening trap; restrict to per-app ports.
- **Forgetting the app-control half** — an App-ID rule needs both a service and `set application-list`.
- **rule-type universal = single from→to** — it also matches intra-zone; re-model + set `intrazone allow`.
- **Dropping `negate-*`** — inverts the rule (FortiOS has the 1:1, so carry it).
- **NAT zones copied verbatim** — security rule = pre-NAT address + post-NAT zone; DNAT → VIP as dstaddr.
- **Skipping zone-protection / interface-mgmt / decryption** — they sit outside the rulebase and vanish silently.
- **Flattening Panorama scopes into one namespace** — same-name objects collide (cross-namespace corruption).
- **Treating a Category-Match custom URL category as a URL list** — it's a category boolean; matches nothing if mis-emitted.
- **PAN-DB ≠ FortiGuard categories** — URL/file-type mappings need a named crosswalk, not an ID 1:1.
