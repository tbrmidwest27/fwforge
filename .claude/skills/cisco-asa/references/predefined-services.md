# Cisco ASA Predefined Services & Object Model → FortiOS Conversion

The data layer an ASA→FortiOS converter needs so it **never silently broadens or drops** a
service/object. ASA references services by **port-literal name** (`www`, `domain`, `sip`, …)
in ACEs and service objects; each must resolve to an exact protocol+port and then to a FortiOS
predefined service **only on exact semantic match**, else a tight custom service. The #1
broadening trap here is reusing a FortiOS built-in whose transport is wider than the ASA
literal (e.g. ASA `udp domain` ≠ FortiOS `DNS`).

**Sources (verified against, not memory):**
- Cisco Secure Firewall ASA — *Addresses, Protocols, and Ports* (the canonical port/protocol/ICMP literal tables): https://www.cisco.com/c/en/us/td/docs/security/asa/asa912/configuration/general/asa-912-general-config/ref-ports.html (stable across 9.1–9.23; e.g. .../asa-923-general-config/ref-ports.html)
- Cisco Secure Firewall ASA Series Command Reference — `object-group service`, `object service`, `object network` (`o-commands`): https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/o-commands.html
- Cisco ASA Series General Operations CLI Config Guide — *Objects* / *Objects for Access Control*: https://www.cisco.com/c/en/us/td/docs/security/asa/asa917/configuration/firewall/asa-917-firewall-config/access-objects.html
- FortiOS CLI Reference — `config firewall service custom` / predefined services: https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference

> fwforge code map: ASA parsing in `fwforge/parsers/cisco_asa.py`; literal tables are
> `PORT_NAMES`, `ICMP_TYPE_NAMES`, `PROTO_NUMBERS` near the top of that file. This reference
> is the audit checklist for those tables and the object/group conversion logic.

> **Accuracy over coverage.** A wrong port — or a too-wide transport — silently broadens a
> firewall rule, the exact bug class fwforge exists to prevent. Where the FortiOS built-in is
> semantically wider than the ASA literal, this file says **"custom"**, never "reuse it".

---

## ⚠️ Top broadening / data-correctness traps (read first)

1. **`domain` is TCP **and** UDP, but transport is set by the ACE/service-object protocol.**
   ASA `access-list ... udp ... eq domain` is **udp/53 only**. The FortiOS built-in **`DNS`
   is tcp/53 + udp/53** — reusing it for a `udp domain` (or `tcp domain`) ACE **broadens** to
   both transports. Emit a custom `udp/53` (or `tcp/53`), not `DNS`. Same logic for any
   literal used under a single-transport ACE.
   - Cisco doc gotcha: *"to assign a port for DNS, use the `domain` literal, **not** `dns` —
     if you use `dns` the ASA assumes you meant the `dnsix` literal (udp/195)."* Never map a
     stray `dns` token to 53.

2. **`kerberos` literal = port 750 on the ASA, NOT 88.** The ASA `ref-ports` table defines the
   `kerberos` literal as **750** (legacy Kerberos-IV). FortiOS built-in `KERBEROS` is **tcp/88
   + udp/88**. These are different ports — do **not** map ASA `kerberos` to FortiOS `KERBEROS`.
   Emit a custom service on 750. (If the source clearly means modern Kerberos it will use a
   numeric `88`; trust the literal as written.)

3. **`radius` literal = 1645 / `radius-acct` = 1646 (legacy), NOT 1812/1813.** The ASA literals
   predate the IANA reassignment. FortiOS built-in `RADIUS` is **udp/1812** and `RADIUS-OLD`
   is udp/1645. So ASA `radius` (1645) → FortiOS **`RADIUS-OLD`** (exact) **not** `RADIUS`;
   ASA `radius-acct` (1646) → **custom udp/1646** (no exact built-in). Mapping `radius`→`RADIUS`
   would shift the port. Both literals are **UDP** in the ASA table.

Honorable mentions: `sip` is tcp+udp (don't narrow); `syslog` literal is **udp/514** in the
ASA table (FortiOS `SYSLOG` is also udp/514 — exact, OK); `h323` literal is **tcp/1720 only**
(the ALG opens more dynamically, but the literal is one port).

---

## 1. TCP/UDP port-literal names → ports → FortiOS service

ASA accepts these literals wherever a port is expected (`eq <literal>`, `range a b`,
`port-object eq <literal>`, `service tcp destination eq <literal>`, NAT `service`). **Transport
is determined by the ACE/object protocol keyword (`tcp`/`udp`/`tcp-udp`), not by the literal** —
the literal only names the *number*. The "valid for" column is which transports the ASA actually
lists the literal under (using it under the other transport is unusual but the parser should
honor the protocol keyword as written).

Legend — FortiOS column: a name = **exact** predefined match (reuse OK); **custom (proto/N)** =
no exact built-in, synthesize a tight custom service; ⚠ = broadening trap, see notes.

| ASA literal | Port | Valid for | FortiOS predefined (exact) or custom | Note |
|---|---|---|---|---|
| `ftp-data` | 20 | TCP | custom (tcp/20) | `FTP` built-in is the control channel; 20 alone has no exact built-in |
| `ftp` | 21 | TCP | `FTP` | FortiOS `FTP` = tcp/21. Does **not** imply ftp-data (see §5) |
| `ssh` | 22 | TCP | `SSH` | |
| `telnet` | 23 | TCP | `TELNET` | |
| `smtp` | 25 | TCP | `SMTP` | |
| `time` | 37 | TCP, UDP | custom | |
| `nameserver` | 42 | UDP | custom (udp/42) | host name server; **not** DNS |
| `whois` / `nicname` | 43 | TCP | `WHOIS` | |
| `tacacs` | 49 | TCP, UDP | custom (tcp/49) ⚠ | FortiOS `TACACS+` = **tcp/49 only**; if ACE is `udp tacacs` do NOT reuse `TACACS+` |
| `domain` | 53 | **TCP, UDP** | **custom (per ACE transport)** ⚠ | DNS. FortiOS `DNS` = tcp+udp/53 → reuse ONLY if ASA proto is `tcp-udp`; for `tcp domain`/`udp domain` emit custom single-transport |
| `bootps` | 67 | UDP | custom (udp/67) | FortiOS `DHCP` = udp/67+68; not an exact match for 67 alone |
| `bootpc` | 68 | UDP | custom (udp/68) | |
| `tftp` | 69 | UDP | `TFTP` | FortiOS `TFTP` = udp/69 |
| `gopher` | 70 | TCP | `GOPHER` | |
| `finger` | 79 | TCP | `FINGER` | |
| `www` / `http` | 80 | TCP | `HTTP` | FortiOS `HTTP` = tcp/80 |
| `hostname` | 101 | TCP | custom (tcp/101) | NIC hostname |
| `pop2` | 109 | TCP | `POP2` (if present) / custom | |
| `pop3` | 110 | TCP | `POP3` | |
| `sunrpc` | 111 | TCP, UDP | `ONC-RPC` (tcp+udp/111, exact only if tcp-udp) ⚠ | portmapper; honor single transport |
| `ident` | 113 | TCP | `IDENT` | |
| `nntp` | 119 | TCP | `NNTP` | |
| `ntp` | 123 | UDP | `NTP` ⚠ | FortiOS `NTP` = udp/123 (exact). ASA `ntp` literal is **UDP**; never tcp |
| `netbios-ns` | 137 | UDP | `SAMBA`/custom (udp/137) | |
| `netbios-dgm` | 138 | UDP | custom (udp/138) | |
| `netbios-ssn` | 139 | TCP | `SAMBA` (tcp/139) / custom | |
| `imap4` | 143 | TCP | `IMAP` | |
| `snmp` | 161 | UDP | `SNMP` ⚠ | FortiOS `SNMP` = udp/161+162. ASA `snmp` is **161 only** → custom udp/161 to avoid pulling in 162 |
| `snmptrap` | 162 | UDP | custom (udp/162) | 162 only |
| `xdmcp` | 177 | UDP | custom (udp/177) | |
| `irc` | 194 | TCP | `IRC` / custom | |
| `ldap` | 389 | TCP | `LDAP` | tcp/389 |
| `https` | 443 | TCP | `HTTPS` | tcp/443 |
| `isakmp` / `ike` | 500 | UDP | `IKE` ⚠ | FortiOS `IKE` = udp/500 **+ udp/4500**. ASA `isakmp` = **500 only** → custom udp/500 to avoid adding 4500 |
| `exec` | 512 | TCP | custom (tcp/512) | rexec |
| `biff` | 512 | UDP | custom (udp/512) | same number, different transport/service |
| `login` / `rlogin` | 513 | TCP | custom (tcp/513) | |
| `who` | 513 | UDP | custom (udp/513) | rwho |
| `rsh` | 514 | TCP | custom (tcp/514) | |
| `syslog` | 514 | UDP | `SYSLOG` | FortiOS `SYSLOG` = udp/514 (exact). ASA literal is **UDP** |
| `lpd` | 515 | TCP | custom (tcp/515) | |
| `talk` | 517 | TCP, UDP | custom | |
| `rip` | 520 | UDP | custom (udp/520) | routing RIP; distinct from `rip` *protocol* |
| `uucp` | 540 | TCP | custom (tcp/540) | |
| `klogin` | 543 | TCP | custom (tcp/543) | |
| `kshell` | 544 | TCP | custom (tcp/544) | |
| `ldaps` | 636 | TCP | `LDAP_UDP`? no → `LDAPS`/custom (tcp/636) | FortiOS has `LDAPS` predefined = tcp/636 |
| `kerberos` | **750** | TCP, UDP | **custom (750)** ⚠ | NOT FortiOS `KERBEROS` (which is 88). See trap #2 |
| `lotusnotes` | 1352 | TCP | custom (tcp/1352) | |
| `citrix-ica` | 1494 | TCP | custom (tcp/1494) | |
| `sqlnet` | 1521 | TCP | custom (tcp/1521) | Oracle SQL*Net (1521). No exact FortiOS built-in |
| `radius` | **1645** | UDP | **`RADIUS-OLD`** ⚠ | FortiOS `RADIUS-OLD` = udp/1645 (exact). NOT `RADIUS` (1812). Trap #3 |
| `radius-acct` | **1646** | UDP | **custom (udp/1646)** ⚠ | No exact built-in (FortiOS acct = 1813). Trap #3 |
| `h323` | 1720 | TCP | custom (tcp/1720) | literal = 1720 only; ALG opens more dynamically |
| `pptp` | 1723 | TCP | `PPTP` | tcp/1723 |
| `nfs` | **2049** | TCP, UDP | custom (per transport) | FortiOS `NFS` = tcp+udp/2049 (exact only if tcp-udp); honor single transport |
| `mgcp` | 2427 | UDP | custom (udp/2427) | |
| `ctiqbe` | 2748 | TCP | custom (tcp/2748) | |
| `vxlan` | 4789 | UDP | custom (udp/4789) | |
| `sip` | **5060** | TCP, UDP | `SIP` (tcp+udp/5060, exact only if tcp-udp) ⚠ | ASA `sip` is **both**; FortiOS `SIP` = udp/5060 (+ tcp on some) — verify; for single-transport ACE emit custom |
| `aol` | 5190 | TCP | custom (tcp/5190) | |
| `pcanywhere-data` | 5631 | TCP | custom (tcp/5631) | |
| `pcanywhere-status` | 5632 | UDP | custom (udp/5632) | |
| `echo` | 7 | TCP, UDP | custom | distinct from ICMP `echo` (§2) |
| `discard` | 9 | TCP, UDP | custom | |
| `daytime` | 13 | TCP | custom | |
| `chargen` | 19 | TCP | custom | |
| `pim-auto-rp` | 496 | TCP, UDP | custom | PIM Auto-RP discovery/announce |
| `cmd` | 514 | TCP | custom (tcp/514) | alias for `rsh` |
| `dnsix` | 195 | UDP | custom (udp/195) | the literal `dns` resolves HERE, not 53 — see trap #1 |

**Conversion rule:** the literal supplies only the **number**; the protocol comes from the ACE
(`tcp`/`udp`) or service object/group. A FortiOS built-in is reused **only** when its protocol
**and** complete port set match exactly (`tcp/80`→`HTTP` ✓; `udp/53`→`DNS` ✗ because `DNS` is
tcp+udp). Otherwise synthesize a tight custom service named e.g. `tcp_80`, `udp_53`. (fwforge
does this in `_services_for_ace` / `parse_service_group`.)

---

## 2. ICMP type literal names → FortiOS

Used in `access-list ... icmp ... <type>`, `object service ... service icmp <type>`, and
`object-group icmp-type`. FortiOS expresses ICMP as a service with a **type** number (and
optional code). No type → all-ICMP (`ALL_ICMP`). Map by **type number**, never to a named
built-in unless type+code match.

| ASA ICMP literal | Type # | FortiOS |
|---|---|---|
| `echo-reply` | 0 | custom icmp type 0 (`PING-reply`-like) |
| `unreachable` | 3 | custom icmp type 3 |
| `source-quench` | 4 | custom icmp type 4 |
| `redirect` | 5 | custom icmp type 5 |
| `alternate-address` | 6 | custom icmp type 6 |
| `echo` | 8 | custom icmp type 8 (≈ `PING`) |
| `router-advertisement` | 9 | custom icmp type 9 |
| `router-solicitation` | 10 | custom icmp type 10 |
| `time-exceeded` | 11 | custom icmp type 11 (≈ `TIMESTAMP`? no — type 11) |
| `parameter-problem` | 12 | custom icmp type 12 |
| `timestamp-request` | 13 | custom icmp type 13 |
| `timestamp-reply` | 14 | custom icmp type 14 |
| `information-request` | 15 | custom icmp type 15 |
| `information-reply` | 16 | custom icmp type 16 |
| `mask-request` | 17 | custom icmp type 17 |
| `mask-reply` | 18 | custom icmp type 18 |
| `traceroute` | 30 | custom icmp type 30 |
| `mobile-redirect` | 32 | custom icmp type 32 |
| `conversion-error` | 31 | custom icmp type 31 |
| `router-renumbering` | — | (rare; emit numeric type if present) |

Note: ASA `icmp echo` = type 8 (the **request**); ASA `icmp echo-reply` = type 0. Don't conflate
the ICMP `echo` literal with the TCP/UDP `echo` port literal (port 7, §1). For ICMPv6, ASA uses
the `icmp6` protocol with its own type names — convert to a FortiOS ICMP6 service (proto 58).

---

## 3. Protocol literal names → IP protocol numbers

Used in the protocol position of an ACE, in `object service ... service <proto>`,
`object-group protocol`, and `service-object <proto>`. A bare IP-protocol (no L4 port) → a
FortiOS custom service with `protocol-number` set (FortiOS `config firewall service custom`,
`set protocol IP`, `set protocol-number N`). `ip` → FortiOS `ALL`.

| ASA protocol literal | IP proto # | FortiOS |
|---|---|---|
| `ip` | 0 (any) | `ALL` |
| `icmp` | 1 | ICMP service (type optional) |
| `igmp` | 2 | custom proto 2 |
| `ipinip` | 4 | custom proto 4 (IP-in-IP) |
| `tcp` | 6 | tcp service |
| `udp` | 17 | udp service |
| `gre` | 47 | `GRE` (proto 47) |
| `esp` / `ipsec` | 50 | `ESP` (proto 50) |
| `ah` | 51 | `AH` (proto 51) |
| `icmp6` | 58 | ICMP6 service (proto 58) |
| `eigrp` | 88 | custom proto 88 |
| `ospf` | 89 | `OSPF` (proto 89) |
| `nos` | 94 | custom proto 94 (KA9Q/NOS) |
| `snp` | 109 | custom proto 109 |
| `pim` | 103 | custom proto 103 |
| `pcp` | 108 | custom proto 108 |
| `igrp` | 9 | custom proto 9 |
| `sctp` | 132 | custom proto 132 (FortiOS supports SCTP services) |

`tcp-udp` is **not** an IP protocol — it is an ASA *service-object/group keyword* meaning
"tcp AND udp on the same port(s)" (§4). `pptp` and `ipsec` appear in some protocol lists as
aliases (`ipsec`→esp/50). Honor the literal; never fall back to `ALL` for an unknown proto —
emit the policy disabled + report (mirrors fwforge's `neq` handling).

---

## 4. Object / object-group model → FortiOS, with traps

| ASA construct | Forms / contents | FortiOS target | Trap |
|---|---|---|---|
| `object network NAME` | `host A.B.C.D` / `subnet NET MASK` (or CIDR) / `range A B` / `fqdn NAME` | `firewall address` (subnet/iprange/fqdn) | A `host` is /32; `range`→`type iprange`; `fqdn`→`type fqdn`. A `name <ip> <alias>` table aliases IPs — resolve before emitting |
| `object service NAME` | `service <proto> [source <op port>] [destination <op port>]` | `firewall service custom` | Source-port constraint: FortiOS services match **destination** ports; an ASA `source` port has no equivalent in the service object → carry on the service as src-port-range or flag. `icmp <type>` → icmp service |
| `object-group network NAME` | `network-object host/obj/subnet`, **`group-object CHILD`** (nesting) | `firewall addrgrp` | FortiOS addrgrp **does** support nested groups → keep nesting (or flatten). An `any`/`0.0.0.0/0` member can't live in an addrgrp → reported/dropped-with-note, never silently |
| `object-group service NAME tcp-udp` | port-objects apply to **both** tcp & udp | service group + per-member tcp/udp services | `tcp-udp` is the **mixed-transport** form: each `port-object eq 53` = tcp/53 **and** udp/53. Must emit BOTH transports — collapsing to one silently narrows |
| `object-group service NAME tcp` / `... udp` | single-transport `port-object` list | service group | straightforward; port-object → one custom service of that transport |
| `object-group service NAME` (no proto) | `service-object <proto> [destination …]`, `service-object object NAME`, `service-object icmp <type>`, **`group-object`** | service group of mixed protocols | The **general form**: members can mix tcp/udp/tcp-udp/icmp/raw-proto in ONE group. FortiOS service groups are **less flexible** about mixing protocol *families* — may need to split or expand to discrete custom services. `service-object tcp-udp destination eq X` again = both transports |
| `object-group protocol NAME` | `protocol-object <proto>` (e.g. tcp, udp, gre, esp) | (no direct FortiOS analog) | fwforge stores these and **expands** them into the ACE's protocol list when the group is referenced in the protocol position. Each proto → its own service |
| `object-group icmp-type NAME` | `icmp-object <type>` (literal or number) | service group of icmp services | one icmp service per type; FortiOS groups them |

**Service-group mixing — the key FortiOS difference.** ASA's general `object-group service`
(no protocol) freely mixes tcp, udp, tcp-udp, icmp, and raw IP protocols in a single group, and
nests via `group-object`. FortiOS `firewall service group` members are individual custom/predefined
services; while a FortiOS group can hold services of different protocols, the safe conversion is
to **materialize each ASA member as its own tight custom service**, then add all to the group —
never assume "tcp-udp" collapses to one entry. (fwforge's `parse_service_group` builds one
`Service` per member and reuses by signature.)

**Source-port traps (broadening-relevant).** ASA can constrain **source** ports
(`service tcp source eq 1024`, or a service group in the *source-port position* of an ACE —
between src and dst address). FortiOS firewall services express only destination ports natively;
a source-port constraint that can't be carried **must not** be dropped to "any source port"
(that broadens). fwforge emits the policy **disabled** with a review note when a service group
lands in the source-port position. Mirror that: never silently widen a source-port match.

**`neq` and non-convertible operators.** ASA `neq <port>`, `gt`/`lt` at the boundary, and
unknown literals are **non-convertible** — converting `neq 80` to "any port" would broaden the
rule. fwforge skips the member / emits the policy **disabled** + report. Never substitute a
broader rule.

---

## 5. Confirmed data-correctness notes

- **`domain` is the only DNS literal; `dns`→`dnsix` (udp/195).** Cisco doc: *"use the `domain`
  literal for DNS; if you use `dns` the ASA assumes `dnsix`."* A stray `dns` token must resolve
  to **195**, not 53. (ref-ports doc)
- **`ftp` (21) does NOT imply `ftp-data` (20).** They are separate literals; an ACE permitting
  `eq ftp` is tcp/21 only — the data channel is handled by the FTP ALG/inspection, not the ACL.
  Don't auto-add tcp/20. FortiOS `FTP` predefined = tcp/21 (control) only as well.
- **`radius` = 1645, `radius-acct` = 1646 (legacy).** Not 1812/1813. ASA → FortiOS:
  `radius`→`RADIUS-OLD` (exact udp/1645); `radius-acct`→custom udp/1646. Both UDP. (Mirrors the
  junos `junos-radius`=1812-only correction in the SRX skill: vendor literals encode *their*
  historical port, not the modern IANA value — trust the literal, verify the FortiOS target.)
- **`kerberos` = 750, not 88.** ASA literal is legacy Kerberos-IV. FortiOS `KERBEROS` = 88 →
  not an exact match; emit custom 750.
- **`sip` = tcp+udp/5060; `nfs` = tcp+udp/2049; `domain`/`sunrpc`/`tacacs`/`pim-auto-rp` are
  tcp+udp.** When such a literal is used under a **single**-transport ACE (`tcp sip`/`udp sip`),
  emit a single-transport custom service — do **not** reuse a tcp+udp FortiOS built-in (it would
  add the other transport).
- **`snmp` literal = 161 only; FortiOS `SNMP` = 161+162.** Reusing `SNMP` for an ASA `snmp` ACE
  adds 162 → broadens. Emit custom udp/161 (and `snmptrap` separately for 162).
- **`isakmp`/`ike` literal = 500 only; FortiOS `IKE` = 500+4500.** Same broadening shape — emit
  custom udp/500 unless the source also opens 4500.
- **`syslog` literal = udp/514 (UDP).** Matches FortiOS `SYSLOG` (udp/514) exactly — reuse OK.
  Do not confuse with `rsh`/`cmd` (tcp/514).
- **ICMP `echo` (type 8) ≠ port `echo` (7).** Two different literals in two different namespaces.

---

## Audit notes for `fwforge/parsers/cisco_asa.py` (`PORT_NAMES` / `ICMP_TYPE_NAMES` / `PROTO_NUMBERS`)

The parser's tables already encode the ASA literals correctly, including the legacy/trap values
(`kerberos`:750, `radius`:1645, `radius-acct`:1646, `isakmp`/`ike`:500, `domain`:53). The
table itself is **number-only** (correct — transport comes from the ACE proto keyword). The
broadening guard lives in the *service-synthesis* step, not the literal table:

- The literal table maps name→number only; ensure downstream `_services_for_ace` /
  `parse_service_group` build **single-transport** custom services from `tcp`/`udp` ACEs and
  only reuse a FortiOS built-in on exact protocol+port match (the doctrine above).
- `tcp-udp` service objects/groups must emit **both** transports — verify the `proto == "tcp-udp"`
  → `"tcp/udp"` IR path (it does) and that the emitter doesn't collapse it.
- `dns` token (if ever seen as a literal) → 195, not 53. Not currently in `PORT_NAMES` (a `dns`
  literal would hit the "unknown port name" warn path) — acceptable, but document so a future
  edit doesn't "helpfully" add `"dns": 53`, which would be wrong.
- Non-convertible operators (`neq`, boundary `gt`/`lt`, unknown literal) already emit the policy
  **disabled** + report — the correct fail-closed behavior; keep it.
