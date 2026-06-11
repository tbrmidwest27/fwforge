"""Schema-certified output (opt-in).

Every FortiGate exposes the complete CLI schema of its exact firmware
build over REST (`GET /api/v2/cmdb?action=schema`). This module fetches
that schema from the user's OWN device at runtime, caches it under
~/.fwforge/schemas/, and validates emitted FortiOS CLI against it:
every `config` section and every `set` attribute either exists on that
exact build, or gets a finding — before anything touches hardware.

Clean-room note: schemas are device data fetched at runtime from gear
the user operates; they are cached locally and never ship with fwforge.

The cached form is structure-only (section/attribute names and their
nesting) — help text, types, and enum options are stripped, which keeps
the cache small and carries exactly what existence checks need.
"""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.request
from pathlib import Path

from .parsers import fortios_tree
from .parsers.fortios_tree import ConfigNode, EditNode, SetLine

SCHEMA_DIR = Path.home() / ".fwforge" / "schemas"

# findings get noisy on a big config; aggregate per (table, attr) and cap
MAX_FINDINGS = 40


def _strip_children(children: dict) -> dict:
    """Keep only the structure: {attr: {nested attr: {...}}}."""
    out: dict = {}
    if not isinstance(children, dict):
        return out
    for name, node in children.items():
        sub = node.get("children") if isinstance(node, dict) else None
        out[name] = _strip_children(sub) if isinstance(sub, dict) else {}
    return out


def fetch(host: str, token: str, port: int = 443,
          timeout: int = 90) -> dict:
    """Fetch and index the CLI schema from a live FortiGate.
    Read-only (a single GET). Raises urllib/ValueError on failure."""
    # admin certs are self-signed in practice; this is a local tool
    # talking to the user's own device on a private network
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        f"https://{host}:{port}/api/v2/cmdb?action=schema",
        headers={"Authorization": f"Bearer {token}"})
    raw = urllib.request.urlopen(req, context=ctx, timeout=timeout).read()
    # FortiOS schema help strings are not always valid UTF-8
    data = json.loads(raw.decode("utf-8", "replace"))
    if data.get("http_status") not in (200, None):
        raise ValueError(f"schema endpoint returned "
                         f"http_status {data.get('http_status')}")
    tables: dict[str, dict] = {}
    for entry in data.get("results", []):
        path, name = entry.get("path", ""), entry.get("name", "")
        if not name:
            continue
        key = f"{path}/{name}" if path else name
        tables[key] = _strip_children(
            entry.get("schema", {}).get("children", {}))
    if not tables:
        raise ValueError("schema endpoint returned no tables")
    version = str(data.get("version", "")).lstrip("v")
    return {
        "version": version,
        "build": data.get("build", 0),
        "serial": data.get("serial", ""),
        "host": host,
        "fetched": time.strftime("%Y-%m-%d %H:%M"),
        "tables": tables,
    }


def cache_path(schema: dict) -> Path:
    return SCHEMA_DIR / (f"fortios-{schema['version'] or 'unknown'}"
                         f"-b{schema['build']}.json")


def save(schema: dict) -> Path:
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    p = cache_path(schema)
    p.write_text(json.dumps(schema), encoding="utf-8")
    return p


def load(path: str | Path) -> dict:
    schema = json.loads(Path(path).read_text(encoding="utf-8"))
    if "tables" not in schema:
        raise ValueError(f"{path} is not a fwforge schema cache")
    return schema


def list_cached() -> list[dict]:
    out = []
    if not SCHEMA_DIR.is_dir():
        return out
    for p in sorted(SCHEMA_DIR.glob("fortios-*.json")):
        try:
            s = json.loads(p.read_text(encoding="utf-8"))
            out.append({"path": str(p), "name": p.name,
                        "version": s.get("version", "?"),
                        "build": s.get("build", "?"),
                        "host": s.get("host", "?"),
                        "fetched": s.get("fetched", "?"),
                        "tables": len(s.get("tables", {}))})
        except (OSError, ValueError):
            continue
    return out


def resolve(ref: str, token: str = "") -> tuple[dict, bool]:
    """A schema reference is either a path to a cached file or a host to
    fetch from live. Returns (schema, fetched_live)."""
    p = Path(ref)
    if p.is_file():
        return load(p), False
    if re.match(r"^[\w.:\-]+$", ref):
        if not token:
            raise ValueError(
                f"'{ref}' is not a file; fetching live needs an API "
                "token (--schema-token or FWFORGE_API_TOKEN)")
        host, _, port = ref.partition(":")
        schema = fetch(host, token, port=int(port) if port else 443)
        save(schema)
        return schema, True
    raise ValueError(f"schema reference '{ref}' is neither a file nor "
                     "a hostname")


def _table_key(path_tokens: list[str]) -> str:
    """config tokens -> schema key: ['vpn','ipsec','phase1-interface']
    -> 'vpn.ipsec/phase1-interface'."""
    if len(path_tokens) == 1:
        return path_tokens[0]
    return ".".join(path_tokens[:-1]) + "/" + path_tokens[-1]


def _walk(children: dict, node, problems: dict, where: str) -> int:
    """Check one table body against its schema children. Returns the
    number of lines checked."""
    lines = 0
    for child in node.children:
        if isinstance(child, SetLine):
            lines += 1
            if child.attr not in children:
                problems.setdefault(("attr", where, child.attr), 0)
                problems[("attr", where, child.attr)] += 1
        elif isinstance(child, EditNode):
            lines += _walk(children, child, problems, where)
        elif isinstance(child, ConfigNode):
            sub = ".".join(child.path)
            nested = children.get(sub)
            if nested is None:
                problems.setdefault(("table", f"{where} > {sub}", ""), 0)
                problems[("table", f"{where} > {sub}", "")] += 1
            else:
                lines += _walk(nested, child, problems,
                               f"{where} > {sub}")
    return lines


def check(out_text: str, schema: dict, report,
          target: str = "") -> dict:
    """Validate emitted FortiOS CLI against a build schema. Adds
    findings; returns stats."""
    tables = schema["tables"]
    label = f"{schema.get('version', '?')} build{schema.get('build', '?')}"
    if target:
        t_train = ".".join(str(target).split(".")[:2])
        s_train = ".".join(schema.get("version", "").split(".")[:2])
        if s_train and t_train and s_train != t_train:
            report.add(
                "warn", "schema",
                f"schema is from FortiOS {label} but the conversion "
                f"targets {target} — fetch a schema from a {t_train} "
                "device for meaningful certification")

    tree = fortios_tree.parse_config(out_text)
    problems: dict[tuple, int] = {}
    sections = 0
    lines = 0
    # vdom_scopes unwraps config global / config vdom; each scope's
    # children are the top-level sections to check
    for scope_name, scope in fortios_tree.vdom_scopes(tree):
        for child in scope.children:
            if not isinstance(child, ConfigNode):
                continue
            if child.path in (["global"], ["vdom"]):
                continue  # wrapper handled by vdom_scopes
            sections += 1
            key = _table_key(child.path)
            children = tables.get(key)
            if children is None:
                problems.setdefault(
                    ("table", " ".join(child.path), ""), 0)
                problems[("table", " ".join(child.path), "")] += 1
                continue
            lines += _walk(children, child, problems,
                           " ".join(child.path))

    unknown_tables = sum(1 for k in problems if k[0] == "table")
    unknown_attrs = sum(1 for k in problems if k[0] == "attr")
    emitted = 0
    for (kind, where, attr), count in sorted(problems.items()):
        if emitted >= MAX_FINDINGS:
            report.add("warn", "schema",
                       f"... {len(problems) - emitted} further schema "
                       "issue(s) suppressed — see the counts above")
            break
        n = f" (x{count})" if count > 1 else ""
        if kind == "table":
            report.add(
                "error", "schema",
                f"'config {where}' does not exist on FortiOS {label} — "
                f"the whole block is dropped on load{n}")
        else:
            report.add(
                "warn", "schema",
                f"'set {attr}' under config {where} does not exist on "
                f"FortiOS {label} — the line is dropped on load{n}")
        emitted += 1

    if problems:
        summary = (f"schema check vs {label}: {unknown_tables} unknown "
                   f"section(s), {unknown_attrs} unknown attribute(s) "
                   f"across {sections} section(s)")
        report.add("warn", "schema", summary)
    else:
        summary = (f"schema check CLEAN vs {label}: every section and "
                   f"attribute exists on the target ({sections} "
                   f"section(s), {lines} set line(s) checked)")
        report.add("info", "schema", summary)
    report.meta["schema_check"] = summary
    return {"sections": sections, "lines": lines,
            "unknown_tables": unknown_tables,
            "unknown_attrs": unknown_attrs}
