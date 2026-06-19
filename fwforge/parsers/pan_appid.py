"""Palo Alto App-ID -> FortiOS application-control category mapping.

App data is loaded from fwforge/data/pan_apps.json at module import. The
bundled baseline covers 200+ common enterprise PAN App-IDs. Extend it:

  fwforge applipedia import <pan-export.xml>   # imports from a live PAN device

User overrides live at ~/.fwforge/pan_apps.json (merged on top of bundled
data at import time; user entries win on name collision). Schema per entry:

  "web-browsing": {
    "ports": [{"proto": "tcp", "ports": "80"}],
    "category": "general-internet",
    "subcategory": "internet-utility",
    "risk": 4,
    "transport": false,
    "builtin_services": ["HTTP"],
    "fortiguard_category": "Web.Client",
    "sig_aliases": ["HTTP.BROWSER"]
  }

The category crosswalk (pan_cat_xwalk.json) maps PAN category|subcategory
keys to FortiGuard categories, providing a reasonable mapping for any app
imported from a PAN device even if it has no direct fortiguard_category.

Public API (signatures unchanged from v0.54.x):
    default_ports(app)          -> list[tuple[str,str]] | None
    builtin_services(app)       -> list[str] | None
    map_apps(apps)              -> (cats, ids, transport, unmapped)
    map_to_sigs(apps, index)    -> (sig_ids, sig_names, matched, unmatched, transport)
"""
from __future__ import annotations

import json
import pathlib

# ---------------------------------------------------------------------------
# FortiOS application-control category name -> FortiGuard category id.
# FortiOS-side data — stays here, not in the PAN app JSON.
# Verified against a live FortiOS 8.0 FortiGuard application DB
# (cmdb/application/name) on 2026-06-11.
# ---------------------------------------------------------------------------
CATEGORY_ID: dict[str, int] = {
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

# ---------------------------------------------------------------------------
# Load app database
# ---------------------------------------------------------------------------
_PKG_DATA = pathlib.Path(__file__).parent.parent / "data"
_BUNDLED = _PKG_DATA / "pan_apps.json"
_XWALK_FILE = _PKG_DATA / "pan_cat_xwalk.json"
_USER_FILE = pathlib.Path("~/.fwforge/pan_apps.json").expanduser()


def _load_db() -> dict[str, dict]:
    db: dict[str, dict] = {}
    if _BUNDLED.exists():
        raw = json.loads(_BUNDLED.read_text(encoding="utf-8")).get("apps", {})
        db.update({k: v for k, v in raw.items() if not k.startswith("_")})
    if _USER_FILE.exists():
        user = json.loads(_USER_FILE.read_text(encoding="utf-8")).get("apps", {})
        db.update({k: v for k, v in user.items() if not k.startswith("_")})
    return db


def _load_xwalk() -> dict[str, str]:
    if _XWALK_FILE.exists():
        return {k: v for k, v in
                json.loads(_XWALK_FILE.read_text(encoding="utf-8")).items()
                if not k.startswith("_")}
    return {}


_DB: dict[str, dict] = _load_db()
_XWALK: dict[str, str] = _load_xwalk()


def db_counts() -> tuple[int, int]:
    """Return (bundled_count, user_override_count) for the GUI status tile.

    Reads the JSON files directly so the counts are accurate even if the
    user modified the override file after the module was imported.
    """
    bundled_n = 0
    user_n = 0
    if _BUNDLED.exists():
        try:
            apps = json.loads(_BUNDLED.read_text(encoding="utf-8")).get("apps", {})
            bundled_n = sum(1 for k in apps if not k.startswith("_"))
        except Exception:
            pass
    if _USER_FILE.exists():
        try:
            apps = json.loads(_USER_FILE.read_text(encoding="utf-8")).get("apps", {})
            user_n = sum(1 for k in apps if not k.startswith("_"))
        except Exception:
            pass
    return bundled_n, user_n

# ---------------------------------------------------------------------------
# Backward-compat module-level dicts (derived from _DB). They are MUTATED IN
# PLACE by _rebuild_tables() — never reassigned — so code that imported them
# by reference keeps working, and reload() can refresh them in a running
# process (no restart needed after the GUI merges new App-IDs).
# ---------------------------------------------------------------------------
TRANSPORT: set[str] = set()
APP_TO_CAT: dict[str, str] = {}
DEFAULT_PORTS: dict[str, list[tuple[str, str]]] = {}
APP_TO_BUILTIN: dict[str, list[str]] = {}
PAN_SIG_ALIAS: dict[str, list[str]] = {}


def _rebuild_tables() -> None:
    """Rebuild every derived lookup table from _DB, mutating them in place."""
    TRANSPORT.clear()
    TRANSPORT.update(k for k, v in _DB.items() if v.get("transport"))

    APP_TO_CAT.clear()
    APP_TO_CAT.update({
        k: v["fortiguard_category"]
        for k, v in _DB.items()
        if v.get("fortiguard_category") and not v.get("transport")
    })

    DEFAULT_PORTS.clear()
    DEFAULT_PORTS.update({
        k: [(p["proto"], p["ports"]) for p in v.get("ports", []) if p.get("ports") != ""]
        for k, v in _DB.items()
        if v.get("ports") and not all(p.get("ports") == "" for p in v.get("ports", []))
    })
    # icmp entries have empty ports string — keep them as-is (proto=icmp, ports="")
    for _k, _v in _DB.items():
        _ports = _v.get("ports", [])
        if _ports and any(p.get("proto") == "icmp" for p in _ports):
            DEFAULT_PORTS[_k] = [(p["proto"], p["ports"]) for p in _ports]

    APP_TO_BUILTIN.clear()
    APP_TO_BUILTIN.update({
        k: v["builtin_services"]
        for k, v in _DB.items()
        if v.get("builtin_services")
    })

    PAN_SIG_ALIAS.clear()
    PAN_SIG_ALIAS.update({
        k: v["sig_aliases"]
        for k, v in _DB.items()
        if v.get("sig_aliases")
    })


_rebuild_tables()


def reload() -> tuple[int, int]:
    """Re-read the bundled + user App-ID DB and rebuild every in-memory table
    so a freshly-merged ~/.fwforge/pan_apps.json takes effect WITHOUT a process
    restart (e.g. right after the GUI's App-ID gap analyzer writes new entries).
    Mutates the module globals in place so existing imports stay valid.
    Returns the new (bundled_count, user_override_count)."""
    new_db = _load_db()
    _DB.clear()
    _DB.update(new_db)
    new_xwalk = _load_xwalk()
    _XWALK.clear()
    _XWALK.update(new_xwalk)
    _rebuild_tables()
    return db_counts()


# ---------------------------------------------------------------------------
# Name normalization
# ---------------------------------------------------------------------------
def _norm(app: str) -> str:
    a = app.lower()
    for suf in ("-base", "-uploading", "-downloading", "-posting",
                "-chat", "-video", "-audio", "-encrypted", "-unencrypted"):
        if a.endswith(suf):
            a = a[: -len(suf)]
    return a


def _resolve(app: str) -> dict | None:
    """Exact name match, then suffix-stripped match."""
    lo = app.lower()
    return _DB.get(lo) or _DB.get(_norm(lo))


def _fg_category(app: str, entry: dict | None) -> str | None:
    """FortiGuard category: direct mapping first, crosswalk fallback."""
    if entry is None:
        return None
    cat = entry.get("fortiguard_category")
    if cat:
        return cat
    key = f"{entry.get('category') or ''}|{entry.get('subcategory') or ''}"
    return _XWALK.get(key)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def categories_for_pan_filter(pan_categories: list[str],
                               pan_subcategories: list[str] | None = None
                               ) -> list[str]:
    """Resolve PAN application-filter criteria to FortiGuard category names.

    Tries subcategory-specific crosswalk keys first, then the first
    subcategory wildcard match for each PAN category. Returns a deduplicated
    list of FortiGuard category names (may be empty when no match exists).
    """
    found: list[str] = []
    for pan_cat in (pan_categories or []):
        for sub in (pan_subcategories or [""]):
            if sub:
                key = f"{pan_cat}|{sub}"
                fg = _XWALK.get(key)
                if fg and fg not in found:
                    found.append(fg)
            else:
                # Take the first xwalk match for this category
                for xkey, fg in _XWALK.items():
                    if xkey.startswith(f"{pan_cat}|") and fg not in found:
                        found.append(fg)
                        break
    return found


def default_ports(app: str) -> list[tuple[str, str]] | None:
    """Default destination ports for a PAN App-ID, or None when unknown
    / dynamic. Exact name wins over the suffix-stripped form."""
    e = _resolve(app)
    if e is None:
        return None
    ports = e.get("ports") or []
    if not ports:
        return None
    return [(p["proto"], p["ports"]) for p in ports]


def builtin_services(app: str) -> list[str] | None:
    """FortiOS built-in service name(s) for a PAN App-ID, or None when
    the app has no clean native equivalent."""
    e = _resolve(app)
    if not e:
        return None
    svcs = e.get("builtin_services") or []
    return svcs if svcs else None


def map_apps(apps: list[str]) -> tuple[list[str], list[int], list[str],
                                       list[str]]:
    """Return (category-names, category-ids, transport-apps, unmapped-apps)
    for a PAN application list. Uses the crosswalk as a fallback for apps
    with a PAN category but no direct fortiguard_category mapping."""
    cats: list[str] = []
    transport: list[str] = []
    unmapped: list[str] = []
    for app in apps:
        if app in ("any", "application-default"):
            continue
        e = _resolve(app)
        if e and e.get("transport"):
            transport.append(app)
            continue
        cat = _fg_category(app, e)
        if cat and cat not in cats:
            cats.append(cat)
        elif not cat:
            unmapped.append(app)
    ids = [CATEGORY_ID.get(c, 0) for c in cats]
    return cats, ids, transport, unmapped


def map_to_sigs(apps: list[str], index: dict) -> tuple[
        list[int], list[str], list[str], list[str], list[str]]:
    """Map PAN App-IDs to FortiOS application-signature IDs using a FortiGuard
    app index (canon name -> {id,name,category}, from appdb.build_index).
    Returns (sig_ids, sig_names, matched_apps, unmatched_apps, transport_apps).
    Tries the curated alias first, then an exact normalized-name match."""
    from ..appdb import _canon
    sig_ids: list[int] = []
    sig_names: list[str] = []
    matched: list[str] = []
    unmatched: list[str] = []
    transport: list[str] = []
    seen: set[int] = set()
    for app in apps:
        if app in ("any", "application-default"):
            continue
        lo = app.lower()
        n = _norm(lo)
        e = _DB.get(lo) or _DB.get(n)
        if e and e.get("transport"):
            transport.append(app)
            continue
        # sig_aliases from the entry, then normalized-name lookup
        aliases = (e.get("sig_aliases") if e else None) or []
        hits = []
        if aliases:
            hits = [index[_canon(t)] for t in aliases if _canon(t) in index]
        else:
            hit = index.get(_canon(lo)) or index.get(_canon(n))
            if hit:
                hits = [hit]
        if hits:
            matched.append(app)
            for h in hits:
                if h["id"] not in seen:
                    seen.add(h["id"])
                    sig_ids.append(h["id"])
                    sig_names.append(h["name"])
        else:
            unmatched.append(app)
    return sig_ids, sig_names, matched, unmatched, transport
