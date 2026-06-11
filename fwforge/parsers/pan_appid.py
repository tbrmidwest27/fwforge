"""Palo Alto App-ID -> FortiOS application-control category mapping.

FortiConverter ships a licensed ~122 KB PAN-app -> FortiGuard-ID table.
That file can't be reused clean-room, and FortiOS `config application list`
entries key on FortiGuard signature IDs we'd need that table to emit
correctly. So this maps common PAN App-IDs to FortiOS application-control
**categories** — a small, public, long-stable ID set — which produces a
loadable application-list profile. It's coarser than per-signature
control, and unmapped apps are flagged by name for manual handling.

Curated by hand from the documented FortiGuard categories; extend
APP_TO_CAT as needed.
"""
from __future__ import annotations

# FortiOS application-control category name -> FortiGuard category id.
# Verified against a live FortiOS 8.0 FortiGuard application DB
# (cmdb/application/name) on 2026-06-11.
CATEGORY_ID = {
    "P2P": 2,
    "VoIP": 3,
    "Video/Audio": 5,
    "Proxy": 6,
    "Remote.Access": 7,
    "Game": 8,
    "General.Interest": 12,
    "Network.Service": 15,
    "Update": 17,
    "Email": 21,
    "Storage.Backup": 22,
    "Social.Media": 23,
    "Web.Client": 25,
    "Collaboration": 28,
    "Business": 29,
    "Cloud.IT": 30,
}

# PAN App-ID -> FortiOS category name. Base names; the "-base"/version
# suffixes PAN uses (facebook-base, youtube-base) are stripped on lookup.
APP_TO_CAT = {
    "web-browsing": "Web.Client", "http2": "Web.Client",
    "flash": "Video/Audio", "http-video": "Video/Audio",
    "dns": "Network.Service", "dns-base": "Network.Service",
    "ntp": "Network.Service", "dhcp": "Network.Service",
    "snmp": "Network.Service", "ldap": "Network.Service",
    "kerberos": "Network.Service", "radius": "Network.Service",
    "syslog": "Network.Service", "tftp": "Network.Service",
    "icmp": "Network.Service", "ping": "Network.Service",
    "netbios-ns": "Network.Service", "netbios-dg": "Network.Service",
    "ssh": "Network.Service", "telnet": "Remote.Access",
    "ms-rdp": "Remote.Access", "vnc": "Remote.Access",
    "citrix": "Remote.Access", "ica": "Remote.Access",
    "teamviewer": "Remote.Access", "pcanywhere": "Remote.Access",
    "ftp": "Network.Service", "tftp-base": "Network.Service",
    "smtp": "Email", "pop3": "Email", "imap": "Email",
    "ms-exchange": "Email", "gmail": "Email", "outlook-web": "Email",
    "yahoo-mail": "Email",
    "facebook": "Social.Media", "twitter": "Social.Media",
    "instagram": "Social.Media", "linkedin": "Social.Media",
    "pinterest": "Social.Media", "snapchat": "Social.Media",
    "tiktok": "Social.Media", "reddit": "Social.Media",
    "youtube": "Video/Audio", "netflix": "Video/Audio",
    "vimeo": "Video/Audio", "rtp": "Video/Audio", "rtsp": "Video/Audio",
    "spotify": "Video/Audio", "twitch": "Video/Audio",
    "sip": "VoIP", "skype": "VoIP", "h323": "VoIP", "mgcp": "VoIP",
    "rtcp": "VoIP",
    "zoom": "Collaboration", "ms-teams": "Collaboration",
    "webex": "Collaboration", "slack": "Collaboration",
    "gotomeeting": "Collaboration", "whatsapp": "Collaboration",
    "ms-office365": "Collaboration", "office365": "Collaboration",
    "bittorrent": "P2P", "emule": "P2P", "gnutella": "P2P",
    "edonkey": "P2P",
    "dropbox": "Storage.Backup", "google-drive": "Storage.Backup",
    "gdrive": "Storage.Backup", "onedrive": "Storage.Backup",
    "box": "Storage.Backup", "icloud": "Storage.Backup",
    "ms-ds-smb": "Storage.Backup", "smb": "Storage.Backup",
    "nfs": "Storage.Backup",
    "github": "Storage.Backup", "amazon-aws": "Cloud.IT", "aws": "Cloud.IT",
    "azure": "Cloud.IT", "gcp": "Cloud.IT", "salesforce": "Business",
    "windows-update": "Update", "apple-update": "Update",
    "ms-update": "Update", "adobe-update": "Update",
    "mysql": "Business", "mssql": "Business", "ms-sql": "Business",
    "oracle": "Business", "postgres": "Business", "ldap-base": "Network.Service",
    "http-proxy": "Proxy", "tor": "Proxy", "ultrasurf": "Proxy",
    "hotspot-shield": "Proxy", "psiphon": "Proxy",
    "google-base": "General.Interest", "apple-appstore": "General.Interest",
    "google-play": "General.Interest",
}

# apps that are transport/encryption, not really controllable applications
TRANSPORT = {"ssl", "tls", "ipsec", "ike", "gre", "ipsec-esp", "tcp", "udp",
             "ip", "quic"}

# Default destination ports for common PAN App-IDs, used to tighten
# `service application-default` rules into real port services instead of
# ALL. Curated from Palo Alto's public Applipedia listings (clean-room;
# port facts, not their data files). Apps with dynamic/negotiated ports
# (P2P, SIP media, Skype, evasive proxies) are deliberately absent — an
# absent app keeps the rule at ALL with a warning, which is honest.
# Format: app -> [(protocol, dst_ports)] with fwforge Service syntax
# ("tcp"/"udp"/"tcp/udp"/"icmp", ports space-separated, ranges with '-').
DEFAULT_PORTS: dict[str, list[tuple[str, str]]] = {
    "web-browsing": [("tcp", "80")],
    "ssl": [("tcp", "443")],
    "quic": [("udp", "443")],
    "http2": [("tcp", "80 443")],
    "flash": [("tcp", "80 443 1935")],
    "http-video": [("tcp", "80 443")],
    "dns": [("tcp/udp", "53")],
    "ntp": [("udp", "123")],
    "dhcp": [("udp", "67 68")],
    "snmp": [("udp", "161")],
    "ldap": [("tcp", "389 636 3268 3269"), ("udp", "389")],
    "kerberos": [("tcp", "88 464"), ("udp", "88 464")],
    "radius": [("udp", "1812 1813 1645 1646")],
    "syslog": [("udp", "514")],
    "tftp": [("udp", "69")],
    "icmp": [("icmp", "")],
    "ping": [("icmp", "")],
    "netbios-ns": [("udp", "137")],
    "netbios-dg": [("udp", "138")],
    "ssh": [("tcp", "22")],
    "telnet": [("tcp", "23")],
    "ms-rdp": [("tcp", "3389"), ("udp", "3389")],
    "vnc": [("tcp", "5900-5906")],
    "citrix": [("tcp", "1494 2598")],
    "ica": [("tcp", "1494 2598")],
    "teamviewer": [("tcp", "80 443 5938")],
    "pcanywhere": [("tcp", "5631"), ("udp", "5632")],
    "ftp": [("tcp", "21")],
    "smtp": [("tcp", "25 587")],
    "pop3": [("tcp", "110")],
    "imap": [("tcp", "143")],
    "gmail": [("tcp", "80 443")],
    "outlook-web": [("tcp", "80 443")],
    "yahoo-mail": [("tcp", "80 443")],
    "facebook": [("tcp", "80 443")],
    "twitter": [("tcp", "80 443")],
    "instagram": [("tcp", "80 443")],
    "linkedin": [("tcp", "80 443")],
    "pinterest": [("tcp", "80 443")],
    "snapchat": [("tcp", "80 443")],
    "tiktok": [("tcp", "80 443")],
    "reddit": [("tcp", "80 443")],
    "youtube": [("tcp", "80 443")],
    "netflix": [("tcp", "80 443")],
    "vimeo": [("tcp", "80 443")],
    "spotify": [("tcp", "80 443 4070")],
    "twitch": [("tcp", "80 443")],
    "rtsp": [("tcp", "554"), ("udp", "554")],
    "h323": [("tcp", "1720")],
    "mgcp": [("udp", "2427 2727")],
    "zoom": [("tcp", "80 443 8801-8802"),
             ("udp", "3478 3479 8801-8810")],
    "ms-teams": [("tcp", "443"), ("udp", "3478-3481")],
    "webex": [("tcp", "443 5004"), ("udp", "9000")],
    "slack": [("tcp", "443")],
    "gotomeeting": [("tcp", "443 8200")],
    "whatsapp": [("tcp", "443 5222")],
    "ms-office365": [("tcp", "80 443")],
    "office365": [("tcp", "80 443")],
    "dropbox": [("tcp", "80 443 17500"), ("udp", "17500")],
    "google-drive": [("tcp", "80 443")],
    "gdrive": [("tcp", "80 443")],
    "onedrive": [("tcp", "80 443")],
    "box": [("tcp", "80 443")],
    "icloud": [("tcp", "80 443")],
    "ms-ds-smb": [("tcp", "139 445")],
    "smb": [("tcp", "139 445")],
    "nfs": [("tcp", "111 2049"), ("udp", "111 2049")],
    "github": [("tcp", "22 443")],
    "amazon-aws": [("tcp", "443")],
    "aws": [("tcp", "443")],
    "azure": [("tcp", "443")],
    "gcp": [("tcp", "443")],
    "salesforce": [("tcp", "443")],
    "windows-update": [("tcp", "80 443")],
    "apple-update": [("tcp", "80 443")],
    "ms-update": [("tcp", "80 443")],
    "adobe-update": [("tcp", "80 443")],
    "mysql": [("tcp", "3306")],
    "mssql": [("tcp", "1433")],
    "ms-sql": [("tcp", "1433")],
    "oracle": [("tcp", "1521")],
    "postgres": [("tcp", "5432")],
    "http-proxy": [("tcp", "80 3128 8080")],
    "google-base": [("tcp", "80 443")],
    "apple-appstore": [("tcp", "80 443")],
    "google-play": [("tcp", "80 443")],
}


def default_ports(app: str) -> list[tuple[str, str]] | None:
    """Default destination ports for a PAN App-ID, or None when unknown
    / dynamic. Exact name wins over the suffix-stripped form."""
    return DEFAULT_PORTS.get(app.lower()) \
        or DEFAULT_PORTS.get(_norm(app))


def _norm(app: str) -> str:
    a = app.lower()
    for suf in ("-base", "-uploading", "-downloading", "-posting",
                "-chat", "-video", "-audio"):
        if a.endswith(suf):
            a = a[: -len(suf)]
    return a


def map_apps(apps: list[str]) -> tuple[list[str], list[int], list[str],
                                       list[str]]:
    """Return (category-names, category-ids, transport-apps, unmapped-apps)
    for a PAN application list."""
    cats: list[str] = []
    transport: list[str] = []
    unmapped: list[str] = []
    for app in apps:
        if app in ("any", "application-default"):
            continue
        n = _norm(app)
        if n in TRANSPORT or app in TRANSPORT:
            transport.append(app)
            continue
        # exact name wins over the suffix-stripped form (http-video must
        # not degrade to the missing 'http' entry)
        cat = APP_TO_CAT.get(app.lower()) or APP_TO_CAT.get(n)
        if cat and cat not in cats:
            cats.append(cat)
        elif not cat:
            unmapped.append(app)
    ids = [CATEGORY_ID[c] for c in cats]
    return cats, ids, transport, unmapped
