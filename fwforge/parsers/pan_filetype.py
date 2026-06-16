"""Palo Alto file-blocking file-type -> FortiOS file-filter file-type.

Clean-room map from PAN predefined file types to FortiOS file-filter types.
The valid FortiOS file-type names were VERIFIED against a live FortiGate-601F
(FortiOS 8.0.0 build0167) on 2026-06-16 via `GET /api/v2/cmdb/antivirus/filetype`
(file-filter rule `file-type` references the antivirus.filetype datasource).

Unmapped PAN types (and PAN's catch-all "any") are flagged for manual handling,
never silently dropped. "encrypted-*" PAN types map to their base archive type
and are flagged — FortiOS detects encrypted/password-protected archives via a
separate antivirus mechanism, not file-filter.
"""
from __future__ import annotations

# PAN file-blocking file-type -> FortiOS file-filter file-type(s).
PAN_TO_FORTI = {
    "7z": ["7z"],
    "bat": ["bat"],
    "cab": ["cab"],
    "chm": ["chm"],
    "class": ["class"],
    "jar": ["class"],
    "dll": ["dll"],
    "dmg": ["dmg"],
    "elf": ["elf"],
    "exe": ["exe"],
    "pe": ["exe", "dll"],            # PAN "pe" = Windows portable executable
    "gzip": ["gzip"],
    "tgz": ["gzip", "tar"],
    "hlp": ["hlp"],
    "hta": ["hta"],
    "iso": ["iso"],
    "lzh": ["lzh"],
    "msi": ["msi"],
    "msoffice": ["msoffice", "msofficex"],
    "ms-office": ["msoffice", "msofficex"],
    "pdf": ["pdf"],
    "png": ["png"],
    "rar": ["rar"],
    "reg": ["registry"],
    "registry": ["registry"],
    "rm": ["rm"],
    "rpm": ["rpm"],
    "tar": ["tar"],
    "torrent": ["torrent"],
    "bittorrent": ["torrent"],
    "zip": ["zip"],
    # encrypted variants -> base type (+ caller flags: AV handles encryption)
    "encrypted-rar": ["rar"],
    "encrypted-zip": ["zip"],
    "encrypted-office2007": ["msofficex"],
    "encrypted-doc": ["msoffice"],
    "encrypted-pdf": ["pdf"],
}

# PAN file-blocking rule action -> FortiOS file-filter rule action
# (verified enum: log-only, block, warning).
ACTION = {
    "block": "block",
    "alert": "log-only",
    "continue": "warning",
}

# PAN types that mean "everything" or have no faithful FortiOS file-type;
# flagged by the caller rather than guessed.
CATCH_ALL = {"any"}


def to_forti(pan_type: str) -> list[str]:
    """FortiOS file-filter file-type(s) for a PAN file-type, or [] if none."""
    return PAN_TO_FORTI.get((pan_type or "").strip().lower(), [])
