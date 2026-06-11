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
