"""FortiGuard application-signature database (opt-in, per-signature App-ID).

Every FortiGate carries the full FortiGuard application-control signature DB
of its exact build, queryable over REST (`GET /api/v2/cmdb/application/name`).
This module fetches that table from the user's OWN device at runtime, caches it
under ~/.fwforge/appdb/, and lets the Palo Alto converter map PAN App-IDs to
specific FortiOS application signatures (per-application control) instead of
only FortiGuard categories.

Clean-room note: the signature DB is FortiGuard device data fetched at runtime
from gear the user operates (exactly like the CLI schema in schema.py). It is
cached locally and NEVER shipped with fwforge. fwforge's own contribution is
the PAN-name -> FortiOS-name mapping logic in parsers/pan_appid.py, not the DB.
"""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.request
from pathlib import Path

APPDB_DIR = Path.home() / ".fwforge" / "appdb"


def fetch(host: str, token: str, port: int = 443, timeout: int = 90) -> dict:
    """Fetch the FortiGuard application signature table from a live FortiGate.
    Read-only (a single GET). Raises urllib/ValueError on failure."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        f"https://{host}:{port}/api/v2/cmdb/application/name"
        "?format=name|id|category|popularity",
        headers={"Authorization": f"Bearer {token}"})
    raw = urllib.request.urlopen(req, context=ctx, timeout=timeout).read()
    data = json.loads(raw.decode("utf-8", "replace"))
    if data.get("http_status") not in (200, None):
        raise ValueError("application endpoint returned "
                         f"http_status {data.get('http_status')}")
    apps = []
    for e in data.get("results", []):
        name = e.get("name")
        if not name or e.get("id") in (None, ""):
            continue
        apps.append({"name": name, "id": int(e["id"]),
                     "category": e.get("category", 0),
                     "popularity": e.get("popularity", 0)})
    if not apps:
        raise ValueError("application endpoint returned no signatures")
    return {
        "version": str(data.get("version", "")).lstrip("v"),
        "build": data.get("build", 0),
        "serial": data.get("serial", ""),
        "host": host,
        "fetched": time.strftime("%Y-%m-%d %H:%M"),
        "count": len(apps),
        "apps": apps,
    }


def cache_path(appdb: dict) -> Path:
    return APPDB_DIR / (f"fortiguard-apps-{appdb['version'] or 'unknown'}"
                        f"-b{appdb['build']}.json")


def save(appdb: dict) -> Path:
    APPDB_DIR.mkdir(parents=True, exist_ok=True)
    p = cache_path(appdb)
    p.write_text(json.dumps(appdb), encoding="utf-8")
    return p


def load(path: str | Path) -> dict:
    appdb = json.loads(Path(path).read_text(encoding="utf-8"))
    if "apps" not in appdb:
        raise ValueError(f"{path} is not a fwforge app-db cache")
    return appdb


def list_cached() -> list[dict]:
    out = []
    if not APPDB_DIR.is_dir():
        return out
    for p in sorted(APPDB_DIR.glob("fortiguard-apps-*.json")):
        try:
            a = json.loads(p.read_text(encoding="utf-8"))
            out.append({"path": str(p), "name": p.name,
                        "version": a.get("version", "?"),
                        "build": a.get("build", "?"),
                        "host": a.get("host", "?"),
                        "fetched": a.get("fetched", "?"),
                        "count": a.get("count", len(a.get("apps", [])))})
        except (OSError, ValueError):
            continue
    return out


def newest() -> dict | None:
    """The most recently fetched cached app DB, or None if none exist."""
    cached = list_cached()
    if not cached:
        return None
    newest_path = max(cached, key=lambda c: c.get("fetched", ""))["path"]
    return load(newest_path)


def resolve(ref: str, token: str = "") -> tuple[dict, bool]:
    """A reference is either a path to a cached file or a host to fetch live.
    Returns (appdb, fetched_live)."""
    p = Path(ref)
    if p.is_file():
        return load(p), False
    if re.match(r"^[\w.:\-]+$", ref):
        if not token:
            raise ValueError("fetching an app DB from a host needs --token")
        host, _, port = ref.partition(":")
        appdb = fetch(host, token, int(port) if port else 443)
        return appdb, True
    raise ValueError(f"app-db reference '{ref}' is neither a cache file "
                     "nor a hostname")


def _canon(name: str) -> str:
    """Collapse a PAN or FortiOS app name to a comparable key: lowercase,
    alphanumerics only (so 'Microsoft.Teams', 'ms_teams', 'MS-Teams' all
    reduce the same way for matching)."""
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def build_index(appdb: dict | None) -> dict:
    """canon(name) -> {'id', 'name', 'category'} for signature lookup. On a
    canon collision keep the most 'base' signature (shortest name, then most
    popular) so 'Facebook' wins over a longer variant with the same key."""
    index: dict = {}
    if not appdb:
        return index
    for e in sorted(appdb.get("apps", []),
                    key=lambda x: (len(x["name"]), -x.get("popularity", 0))):
        index.setdefault(_canon(e["name"]),
                         {"id": e["id"], "name": e["name"],
                          "category": e.get("category", 0)})
    return index
