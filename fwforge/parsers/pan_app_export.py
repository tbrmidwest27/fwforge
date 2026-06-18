"""Parse PAN 'show application all' XML export into the pan_apps.json schema.

Usage:
    fwforge applipedia import <file>

Input is the XML produced by a PAN device:
    admin@fw> show application all | export tftp to <host> from <file>

Or captured from a config XML (the <application> block inside a vsys or
device-group). Both formats are accepted — the parser just looks for all
<entry> elements that have an application structure.

Imported entries are MERGED into ~/.fwforge/pan_apps.json (created if absent).
The user file takes precedence over the bundled baseline at convert time, so
imported data from a live PAN device wins over fwforge's curated defaults.
"""
from __future__ import annotations

import json
import pathlib
import re
import xml.etree.ElementTree as ET

_USER_FILE = pathlib.Path("~/.fwforge/pan_apps.json").expanduser()


def _parse_port_member(member: str) -> dict | None:
    """Convert a PAN port member string to {proto, ports}.

    PAN formats:
        tcp/80          -> {"proto": "tcp",     "ports": "80"}
        tcp/8080-8090   -> {"proto": "tcp",     "ports": "8080-8090"}
        udp/1812 1813   -> {"proto": "udp",     "ports": "1812 1813"}
        tcp/dynamic     -> None  (caller skips dynamic entries)
        icmp            -> {"proto": "icmp",    "ports": ""}
        icmp/8          -> {"proto": "icmp",    "ports": ""}
    """
    m = member.strip().lower()
    if not m:
        return None
    if m in ("icmp", "icmp6") or m.startswith("icmp/") or m.startswith("icmp6/"):
        return {"proto": "icmp", "ports": ""}
    if "/" not in m:
        return None
    proto, ports_str = m.split("/", 1)
    if proto not in ("tcp", "udp", "tcp/udp", "sctp"):
        return None
    if "dynamic" in ports_str:
        return None
    # Normalise: commas -> spaces
    ports_str = re.sub(r",\s*", " ", ports_str).strip()
    return {"proto": proto, "ports": ports_str}


def _parse_entry(entry: ET.Element) -> tuple[str, dict] | None:
    """Parse one <entry name="..."> element into (name, app_dict)."""
    name = entry.get("name", "").lower().strip()
    if not name:
        return None

    # Collect ports from <default><port><member>...</member></port></default>
    ports: list[dict] = []
    default = entry.find("default")
    if default is not None:
        port_el = default.find("port")
        if port_el is not None:
            # Combine members by protocol where possible
            proto_map: dict[str, list[str]] = {}
            for mem in port_el.findall("member"):
                p = _parse_port_member(mem.text or "")
                if p is None:
                    continue
                proto_map.setdefault(p["proto"], [])
                if p["ports"]:
                    proto_map[p["proto"]].append(p["ports"])
            for proto, port_parts in proto_map.items():
                if proto == "icmp":
                    ports.append({"proto": "icmp", "ports": ""})
                else:
                    ports.append({"proto": proto,
                                  "ports": " ".join(p for p in port_parts if p)})

    def _text(tag: str) -> str | None:
        el = entry.find(tag)
        return el.text.strip() if el is not None and el.text else None

    category = _text("category")
    subcategory = _text("subcategory")
    risk_str = _text("risk")
    risk: int | None = int(risk_str) if risk_str and risk_str.isdigit() else None
    technology = _text("technology")

    # Transport heuristic: networking apps whose technology is ip-protocol or
    # infrastructure and whose port count is 0 stay uncategorised by default.
    # We leave fortiguard_category null so the crosswalk takes over.
    app: dict = {
        "ports": ports,
        "category": category,
        "subcategory": subcategory,
        "risk": risk,
        "transport": False,
        "builtin_services": [],
        "fortiguard_category": None,
        "sig_aliases": [],
    }
    if technology:
        app["technology"] = technology
    return name, app


def import_applipedia(path: str | pathlib.Path) -> int:
    """Parse a PAN application XML export and merge into ~/.fwforge/pan_apps.json.

    Returns the number of apps imported (new or updated). Raises on parse errors.
    """
    text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    root = ET.fromstring(text)

    # Accept <response>, <config>, <application>, or bare <entry> roots.
    # Search the entire tree for <entry> elements that look like app entries.
    entries: list[ET.Element] = []
    for el in root.iter("entry"):
        if el.find("category") is not None or el.find("default") is not None:
            entries.append(el)

    if not entries:
        raise ValueError(f"No application entries found in {path!r}")

    imported: dict[str, dict] = {}
    for el in entries:
        result = _parse_entry(el)
        if result is not None:
            name, app = result
            imported[name] = app

    if not imported:
        raise ValueError(f"No parseable app entries in {path!r}")

    # Load existing user file, merge, write back
    existing: dict = {}
    if _USER_FILE.exists():
        existing = json.loads(_USER_FILE.read_text(encoding="utf-8"))

    apps = existing.get("apps", {})
    apps.update(imported)
    existing["apps"] = apps
    existing.setdefault("_meta", {})["source"] = "imported via fwforge applipedia import"

    _USER_FILE.parent.mkdir(parents=True, exist_ok=True)
    _USER_FILE.write_text(
        json.dumps(existing, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return len(imported)
