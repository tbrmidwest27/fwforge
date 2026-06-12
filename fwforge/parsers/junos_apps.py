"""Junos predefined application (`junos-*`) -> port definitions.

SRX policies reference built-in applications by name (junos-http,
junos-ssh, ...) that the firewall resolves internally. FortiOS has no
equivalent built-in set under those names, so a smooth conversion needs
the actual ports. This is a curated table of the common predefined Junos
applications, from Junos's public documentation (port facts, clean-room
— no Juniper data files reused). Custom `applications { application ... }`
objects always win; this fills in only the `junos-*` references.

Format: name -> list of (protocol, dst_ports) with fwforge Service
syntax ("tcp"/"udp"/"tcp/udp"/"icmp", ports space-separated, ranges with
'-'). icmp/ip entries use an empty / numeric port field.
"""
from __future__ import annotations

JUNOS_APPS: dict[str, list[tuple[str, str]]] = {
    # web / proxy
    "junos-http": [("tcp", "80")],
    "junos-https": [("tcp", "443")],
    "junos-http-ext": [("tcp", "8000-8002")],
    # remote access
    "junos-ssh": [("tcp", "22")],
    "junos-telnet": [("tcp", "23")],
    "junos-rsh": [("tcp", "514")],
    "junos-rlogin": [("tcp", "513")],
    "junos-rdp": [("tcp", "3389")],
    "junos-vnc": [("tcp", "5800 5900")],
    "junos-winframe": [("tcp", "1494")],
    "junos-pc-anywhere": [("tcp", "5631"), ("udp", "5632")],
    # mail
    "junos-smtp": [("tcp", "25")],
    "junos-pop3": [("tcp", "110")],
    "junos-imap": [("tcp", "143")],
    "junos-imaps": [("tcp", "993")],
    "junos-pop3s": [("tcp", "995")],
    # file transfer
    "junos-ftp": [("tcp", "21")],
    "junos-tftp": [("udp", "69")],
    "junos-nfsd-tcp": [("tcp", "2049")],
    "junos-nfsd-udp": [("udp", "2049")],
    # name / directory / time
    "junos-dns-tcp": [("tcp", "53")],
    "junos-dns-udp": [("udp", "53")],
    "junos-dhcp-client": [("udp", "68")],
    "junos-dhcp-server": [("udp", "67")],
    "junos-bootpc": [("udp", "68")],
    "junos-bootps": [("udp", "67")],
    "junos-ntp": [("udp", "123")],
    "junos-ldap": [("tcp", "389")],
    "junos-ntalk": [("udp", "518")],
    # snmp / mgmt
    "junos-snmp": [("udp", "161")],
    "junos-snmp-agentx": [("tcp", "705")],
    "junos-syslog": [("udp", "514")],
    "junos-radius": [("udp", "1812 1813")],
    "junos-radacct": [("udp", "1813")],
    "junos-tacacs": [("tcp", "49")],
    "junos-tacacs-ds": [("tcp", "65")],
    # windows / smb / rpc
    "junos-ms-rpc-tcp": [("tcp", "135")],
    "junos-ms-rpc-udp": [("udp", "135")],
    "junos-netbios-session": [("tcp", "139")],
    "junos-smb": [("tcp", "139 445")],
    "junos-smb-session": [("tcp", "445")],
    "junos-nbname": [("udp", "137")],
    "junos-nbds": [("udp", "138")],
    "junos-ldp-tcp": [("tcp", "646")],
    "junos-ldp-udp": [("udp", "646")],
    # databases
    "junos-sql-monitor": [("tcp", "1433"), ("udp", "1434")],
    "junos-sqlnet-v1": [("tcp", "1525")],
    "junos-sqlnet-v2": [("tcp", "1521")],
    "junos-mysql": [("tcp", "3306")],
    # voip
    "junos-sip": [("tcp", "5060"), ("udp", "5060")],
    "junos-h323": [("tcp", "1720")],
    "junos-mgcp-ua": [("udp", "2427")],
    "junos-mgcp-ca": [("udp", "2727")],
    # vpn / tunneling
    "junos-ike": [("udp", "500")],
    "junos-ike-nat": [("udp", "4500")],
    "junos-l2tp": [("udp", "1701")],
    "junos-pptp": [("tcp", "1723")],
    # icmp families -> FortiOS ALL_ICMP (closest built-in)
    "junos-icmp-all": [("icmp", "")],
    "junos-icmp-ping": [("icmp", "")],
    "junos-ping": [("icmp", "")],
    "junos-icmp6-all": [("icmp", "")],
    # misc
    "junos-gre": [("ip", "47")],
    "junos-ospf": [("ip", "89")],
    "junos-vrrp": [("ip", "112")],
    "junos-ident": [("tcp", "113")],
    "junos-finger": [("tcp", "79")],
    "junos-gopher": [("tcp", "70")],
    "junos-irc": [("tcp", "6660-6669")],
    "junos-nntp": [("tcp", "119")],
    "junos-whois": [("tcp", "43")],
    "junos-discard": [("tcp", "9")],
    "junos-chargen": [("tcp", "19")],
}


def junos_app(name: str) -> list[tuple[str, str]] | None:
    """Port specs for a predefined junos-* application, or None when
    unknown (dynamic ALGs like junos-ftp-data dynamics, or names not in
    the curated table)."""
    return JUNOS_APPS.get(name.lower())
