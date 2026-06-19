# Junos OS Predefined Applications (`junos-*`) — ports + conversion notes

Authoritative reference for the predefined application objects used in SRX security
policies (`set security policies ... match application junos-*`). Ports are inherited
from the hidden, immutable `junos-defaults` group; on any box the canonical way to
see them is `show configuration groups junos-defaults applications`.

**Sources (verified against, not memory):**
- Juniper TechLibrary — Predefined Policy Applications: https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/policy-predefined-applications.html
- Juniper "Junos Default Groups" (junos-defaults sample): https://www.juniper.net/documentation/en_US/junos13.2/topics/concept/junos-groups-default.html
- Juniper KB21343 — junos-traceroute deprecated from junos-defaults
- Verbatim `show configuration groups junos-defaults` dumps (SRX300 15.1X49, SRX240 12.1X47) + cross-checks (51sec catalog, assimilator JSON, Batfish enum)

> **Accuracy over coverage.** A wrong port silently broadens a firewall rule — the
> exact bug class fwforge exists to prevent. Where a port is uncertain or the object
> is an ALG/dynamic/SET, this file says so rather than guessing.

---

## ⚠️ Confirmed bug in the current `fwforge/parsers/junos_apps.py`

`"junos-radius": [("udp", "1812 1813")]` **over-broadens**. Official junos-defaults:
**`junos-radius` = udp/1812 only**; **udp/1813 is the separate `junos-radacct`** (which
the table already has correctly). Fix to `[("udp", "1812")]`.

---

## Priority: referenced by a real production config, MISSING from the table

| name | protocol | dst-port | note |
|---|---|---|---|
| junos-dhcp-relay | udp | **67** | server-side port (NOT 68). Confirmed in 3 sources. |
| junos-lpr | tcp | 515 | |
| junos-snmp-get | udp | 161 | ALG snmp (`snmp-command get`) |
| junos-snmp-get-next | udp | 161 | ALG snmp (`snmp-command get-next`) |
| junos-ms-rpc-any | — | — | **application-SET** = {ms-rpc-tcp, ms-rpc-udp, ms-rpc-uuid-any-tcp, ms-rpc-uuid-any-udp}. Expand to members; not one port. |
| junos-ms-rpc-uuid-any-tcp | tcp | — | **DCE-RPC by wildcard UUID — no fixed dst-port.** |
| junos-ms-rpc-uuid-any-udp | udp | — | **DCE-RPC by wildcard UUID — no fixed dst-port.** |
| junos-traceroute | udp | 33435-33450 (range) | **ALG, deprecated** (KB21343). Not a single port. |
| junos-archives | — | UNCONFIRMED | Not a built-in in any official dump → almost certainly a **custom** app; resolve from the config's own `applications {}` / `application-set {}`. Do not assign a port. |
| junos-space-core | — | UNCONFIRMED | Not a standard built-in (Junos Space product). Likely custom. Do not assign a port. |
| junos-space-core-virt | — | UNCONFIRMED | Not a standard built-in (Junos Space VA). Likely custom. Do not assign a port. |

**Resolution rule for ALG/UUID/SET/UNCONFIRMED names:** never map to a single guessed
port and never fall back to `ALL`. Expand SETs to members; for UUID/ALG/unconfirmed,
surface in the report and emit the referencing **policy disabled** with a review comment.

---

## Full catalog (categorized)

Legend — `ALG`: stateful ALG term(s); `RPC/UUID`: matched by DCE-RPC UUID, no fixed L4 port;
`SET`: application-set alias; `proto`: raw IP protocol number; `range`: port range.

### Web / mail / file transfer
| name | protocol | dst-port | note |
|---|---|---|---|
| junos-http | tcp | 80 | |
| junos-https | tcp | 443 | |
| junos-http-ext | tcp | 8000-8002 | range |
| junos-smtp | tcp | 25 | |
| junos-pop3 | tcp | 110 | |
| junos-pop3s | tcp | 995 | |
| junos-imap | tcp | 143 | |
| junos-imaps | tcp | 993 | |
| junos-nntp | tcp | 119 | |
| junos-ftp | tcp | 21 | ALG ftp (data dynamic) |
| junos-tftp | udp | 69 | ALG tftp |
| junos-nfsd-tcp | tcp | 2049 | |
| junos-nfsd-udp | udp | 2049 | |
| junos-rtsp | tcp | 554 | ALG rtsp |

### Remote access
| name | protocol | dst-port | note |
|---|---|---|---|
| junos-ssh | tcp | 22 | |
| junos-telnet | tcp | 23 | |
| junos-rsh | tcp | 514 | ALG rsh |
| junos-rlogin | tcp | 513 | |
| junos-rdp | tcp | 3389 | |
| junos-vnc | tcp | 5800 5900 | |
| junos-finger | tcp | 79 | |
| junos-ident | tcp | 113 | |

### Name / directory / time / DHCP
| name | protocol | dst-port | note |
|---|---|---|---|
| junos-dns-tcp | tcp | 53 | ALG dns |
| junos-dns-udp | udp | 53 | ALG dns |
| junos-ntp | udp | 123 | |
| junos-ldap | tcp | 389 | |
| junos-dhcp-client | udp | 68 | |
| junos-dhcp-server | udp | 67 | |
| junos-dhcp-relay | udp | 67 | |
| junos-bootpc | udp | 68 | |
| junos-bootps | udp | 67 | |

### SNMP / management / AAA / logging
| name | protocol | dst-port | note |
|---|---|---|---|
| junos-snmp | udp | 161 | |
| junos-snmp-get | udp | 161 | ALG snmp (get) |
| junos-snmp-get-next | udp | 161 | ALG snmp (get-next) |
| junos-snmp-agentx | tcp | 705 | |
| junos-syslog | udp | 514 | |
| junos-radius | udp | **1812** | 1812 ONLY (accounting = junos-radacct) |
| junos-radacct | udp | 1813 | |
| junos-tacacs | tcp | 49 | |
| junos-tacacs-ds | tcp | 65 | |
| junos-lpr | tcp | 515 | |

### Windows / SMB / MS-RPC
| name | protocol | dst-port | note |
|---|---|---|---|
| junos-netbios-session | tcp | 139 | |
| junos-smb-session | tcp | 445 | |
| junos-nbname | udp | 137 | |
| junos-nbds | udp | 138 | |
| junos-ms-rpc-tcp | tcp | 135 | ALG ms-rpc |
| junos-ms-rpc-udp | udp | 135 | ALG ms-rpc |
| junos-ms-rpc-epm | tcp | — | RPC/UUID (endpoint mapper). No fixed port. |

### Databases
| name | protocol | dst-port | note |
|---|---|---|---|
| junos-sqlnet-v1 | tcp | 1525 | |
| junos-sqlnet-v2 | tcp | 1521 | ALG sqlnet-v2 |

### VoIP — all ALG/multi-term; single-service conversion is LOSSY
| name | protocol | dst-port | note |
|---|---|---|---|
| junos-sip | udp+tcp | 5060 | ALG sip |
| junos-h323 | tcp+udp | 1720/1719/1503/389/522/1731 | ALG, 6 terms — encoding as one service narrows it |
| junos-sccp | tcp | 2000 | ALG sccp |
| junos-mgcp-ua | udp | 2427 | ALG |
| junos-mgcp-ca | udp | 2727 | ALG |

### Routing / VPN / tunneling / ICMP
| name | protocol | dst-port | note |
|---|---|---|---|
| junos-bgp | tcp | 179 | |
| junos-ospf | proto 89 | — | IP proto |
| junos-rip | udp | 520 | |
| junos-vrrp | proto 112 | — | IP proto |
| junos-gre | proto 47 | — | IP proto |
| junos-ike | udp | 500 | |
| junos-ike-nat | udp | 4500 | |
| junos-l2tp | udp | 1701 | |
| junos-pptp | tcp | 1723 | ALG pptp |
| junos-icmp-all | icmp | — | all ICMP types |
| junos-icmp-ping | icmp | — | echo-request |
| junos-icmp6-all | proto 58 | — | ICMPv6 (faithful = proto 58; practical FortiOS = ALL_ICMP6) |

---

## JSON for merging into `junos_apps.py`

`junos_apps.py` stores `name -> list[(protocol, dst_ports)]` (FortiOS Service syntax:
`tcp`/`udp`/`icmp`/`ip`; ports space-separated; ranges with `-`; icmp/ip use empty/numeric).
The `flag_no_single_service` names must NOT be given a fake port — expand SETs, and
disable+report ALG/UUID/unconfirmed.

```json
{
  "resolvable": {
    "junos-http": {"protocol": "tcp", "ports": "80"},
    "junos-https": {"protocol": "tcp", "ports": "443"},
    "junos-http-ext": {"protocol": "tcp", "ports": "8000-8002"},
    "junos-smtp": {"protocol": "tcp", "ports": "25"},
    "junos-pop3": {"protocol": "tcp", "ports": "110"},
    "junos-pop3s": {"protocol": "tcp", "ports": "995"},
    "junos-imap": {"protocol": "tcp", "ports": "143"},
    "junos-imaps": {"protocol": "tcp", "ports": "993"},
    "junos-nntp": {"protocol": "tcp", "ports": "119"},
    "junos-ftp": {"protocol": "tcp", "ports": "21"},
    "junos-tftp": {"protocol": "udp", "ports": "69"},
    "junos-nfsd-tcp": {"protocol": "tcp", "ports": "2049"},
    "junos-nfsd-udp": {"protocol": "udp", "ports": "2049"},
    "junos-rtsp": {"protocol": "tcp", "ports": "554"},
    "junos-ssh": {"protocol": "tcp", "ports": "22"},
    "junos-telnet": {"protocol": "tcp", "ports": "23"},
    "junos-rsh": {"protocol": "tcp", "ports": "514"},
    "junos-rlogin": {"protocol": "tcp", "ports": "513"},
    "junos-rdp": {"protocol": "tcp", "ports": "3389"},
    "junos-vnc": {"protocol": "tcp", "ports": "5800 5900"},
    "junos-finger": {"protocol": "tcp", "ports": "79"},
    "junos-ident": {"protocol": "tcp", "ports": "113"},
    "junos-dns-tcp": {"protocol": "tcp", "ports": "53"},
    "junos-dns-udp": {"protocol": "udp", "ports": "53"},
    "junos-ntp": {"protocol": "udp", "ports": "123"},
    "junos-ldap": {"protocol": "tcp", "ports": "389"},
    "junos-dhcp-client": {"protocol": "udp", "ports": "68"},
    "junos-dhcp-server": {"protocol": "udp", "ports": "67"},
    "junos-dhcp-relay": {"protocol": "udp", "ports": "67"},
    "junos-bootpc": {"protocol": "udp", "ports": "68"},
    "junos-bootps": {"protocol": "udp", "ports": "67"},
    "junos-snmp": {"protocol": "udp", "ports": "161"},
    "junos-snmp-get": {"protocol": "udp", "ports": "161"},
    "junos-snmp-get-next": {"protocol": "udp", "ports": "161"},
    "junos-snmp-agentx": {"protocol": "tcp", "ports": "705"},
    "junos-syslog": {"protocol": "udp", "ports": "514"},
    "junos-radius": {"protocol": "udp", "ports": "1812"},
    "junos-radacct": {"protocol": "udp", "ports": "1813"},
    "junos-tacacs": {"protocol": "tcp", "ports": "49"},
    "junos-tacacs-ds": {"protocol": "tcp", "ports": "65"},
    "junos-lpr": {"protocol": "tcp", "ports": "515"},
    "junos-netbios-session": {"protocol": "tcp", "ports": "139"},
    "junos-smb-session": {"protocol": "tcp", "ports": "445"},
    "junos-nbname": {"protocol": "udp", "ports": "137"},
    "junos-nbds": {"protocol": "udp", "ports": "138"},
    "junos-ms-rpc-tcp": {"protocol": "tcp", "ports": "135"},
    "junos-ms-rpc-udp": {"protocol": "udp", "ports": "135"},
    "junos-sqlnet-v1": {"protocol": "tcp", "ports": "1525"},
    "junos-sqlnet-v2": {"protocol": "tcp", "ports": "1521"},
    "junos-sccp": {"protocol": "tcp", "ports": "2000"},
    "junos-mgcp-ua": {"protocol": "udp", "ports": "2427"},
    "junos-mgcp-ca": {"protocol": "udp", "ports": "2727"},
    "junos-bgp": {"protocol": "tcp", "ports": "179"},
    "junos-rip": {"protocol": "udp", "ports": "520"},
    "junos-ike": {"protocol": "udp", "ports": "500"},
    "junos-ike-nat": {"protocol": "udp", "ports": "4500"},
    "junos-l2tp": {"protocol": "udp", "ports": "1701"},
    "junos-pptp": {"protocol": "tcp", "ports": "1723"},
    "junos-ospf": {"protocol": "ip", "ports": "89"},
    "junos-vrrp": {"protocol": "ip", "ports": "112"},
    "junos-gre": {"protocol": "ip", "ports": "47"},
    "junos-icmp6-all": {"protocol": "ip", "ports": "58"},
    "junos-icmp-all": {"protocol": "icmp", "ports": ""},
    "junos-icmp-ping": {"protocol": "icmp", "ports": ""},
    "junos-sip": [{"protocol": "udp", "ports": "5060"}, {"protocol": "tcp", "ports": "5060"}]
  },
  "flag_no_single_service": {
    "junos-traceroute": "ALG, UDP range 33435-33450, deprecated (KB21343)",
    "junos-ms-rpc-any": "application-SET → expand to 4 members",
    "junos-ms-rpc-epm": "DCE-RPC UUID (endpoint mapper), no fixed port",
    "junos-ms-rpc-uuid-any-tcp": "DCE-RPC wildcard UUID over tcp, no fixed port",
    "junos-ms-rpc-uuid-any-udp": "DCE-RPC wildcard UUID over udp, no fixed port",
    "junos-h323": "ALG, 6 terms — single service narrows it",
    "junos-archives": "UNCONFIRMED — likely custom; resolve from config's own applications{}",
    "junos-space-core": "UNCONFIRMED — likely custom; do not assign a port",
    "junos-space-core-virt": "UNCONFIRMED — likely custom; do not assign a port"
  }
}
```
