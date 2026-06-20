"""FortiGate platform codes for the #config-version header.

The platform token is the first field of a backup's `#config-version=`
header and must match the restoring device's own code or the FortiGate
rejects the file outright. The token namespace is distinct from BOTH the
product SKU (FG-601F) and the firmware image name (FGT_601F): a
FortiGate 601F writes `FG6H1F`.

Observed naming scheme:
- desktop models keep the FGT prefix and literal model number (FGT60F);
- 3-digit models use an FG prefix; a middle zero is written as `H`
  (601F -> FG6H1F), digits without a zero stay literal (121G -> FG121G);
- thousands collapse to `K` (1500D -> FG1K5D).

Clean-room provenance: entries marked verified=True were read from real
device headers (sources noted inline); the rest are derived from the
scheme above. A derived code is a strong guess, not a guarantee — always
confirm against a backup taken from the actual target device before
restoring. `resolve()` accepts a code, a bare model number ("701G"), an
SKU ("FG-701G"), or a product name ("FortiGate 701G"), case-insensitive.
"""
from __future__ import annotations

import difflib
import re
from typing import NamedTuple

from .transforms.plan import PlanError


class Platform(NamedTuple):
    code: str       # config-version token, e.g. FG6H1F
    model: str      # product label, e.g. FortiGate 601F
    family: str     # dropdown group
    verified: bool  # True = observed in a real header


PLATFORMS: tuple[Platform, ...] = (
    # -- desktop --------------------------------------------------------
    Platform("FGT30G", "FortiGate 30G", "Desktop", False),
    Platform("FGT40F", "FortiGate 40F", "Desktop", False),
    Platform("FGT50G", "FortiGate 50G", "Desktop", False),
    Platform("FGT51G", "FortiGate 51G", "Desktop", False),
    Platform("FGT60E", "FortiGate 60E", "Desktop", False),
    # verified: lab FGSP member header, FortiOS 8.0 build0167 (2026-06-12)
    Platform("FGT60F", "FortiGate 60F", "Desktop", True),
    Platform("FGT61F", "FortiGate 61F", "Desktop", False),
    Platform("FGT70F", "FortiGate 70F", "Desktop", False),
    Platform("FGT71F", "FortiGate 71F", "Desktop", False),
    Platform("FGT70G", "FortiGate 70G", "Desktop", False),
    Platform("FGT71G", "FortiGate 71G", "Desktop", False),
    Platform("FGT80F", "FortiGate 80F", "Desktop", False),
    Platform("FGT81F", "FortiGate 81F", "Desktop", False),
    Platform("FGT80G", "FortiGate 80G", "Desktop", False),
    Platform("FGT81G", "FortiGate 81G", "Desktop", False),
    Platform("FGT90G", "FortiGate 90G", "Desktop", False),
    Platform("FGT91G", "FortiGate 91G", "Desktop", False),
    Platform("FWF40F", "FortiWiFi 40F", "Desktop", False),
    Platform("FWF60F", "FortiWiFi 60F", "Desktop", False),
    Platform("FWF61F", "FortiWiFi 61F", "Desktop", False),
    Platform("FGR60F", "FortiGate Rugged 60F", "Desktop", False),
    Platform("FGR70F", "FortiGate Rugged 70F", "Desktop", False),
    # -- mid-range ------------------------------------------------------
    Platform("FG100E", "FortiGate 100E", "Mid-range", False),
    Platform("FG101E", "FortiGate 101E", "Mid-range", False),
    Platform("FG100F", "FortiGate 100F", "Mid-range", False),
    Platform("FG101F", "FortiGate 101F", "Mid-range", False),
    Platform("FG120G", "FortiGate 120G", "Mid-range", False),
    Platform("FG121G", "FortiGate 121G", "Mid-range", False),
    Platform("FG200E", "FortiGate 200E", "Mid-range", False),
    Platform("FG201E", "FortiGate 201E", "Mid-range", False),
    Platform("FG200F", "FortiGate 200F", "Mid-range", False),
    Platform("FG201F", "FortiGate 201F", "Mid-range", False),
    Platform("FG200G", "FortiGate 200G", "Mid-range", False),
    Platform("FG201G", "FortiGate 201G", "Mid-range", False),
    Platform("FG3H0E", "FortiGate 300E", "Mid-range", False),
    Platform("FG3H1E", "FortiGate 301E", "Mid-range", False),
    Platform("FG4H0E", "FortiGate 400E", "Mid-range", False),
    Platform("FG4H1E", "FortiGate 401E", "Mid-range", False),
    Platform("FG4H0F", "FortiGate 400F", "Mid-range", False),
    Platform("FG4H1F", "FortiGate 401F", "Mid-range", False),
    Platform("FG5H0E", "FortiGate 500E", "Mid-range", False),
    Platform("FG5H1E", "FortiGate 501E", "Mid-range", False),
    Platform("FG6H0E", "FortiGate 600E", "Mid-range", False),
    Platform("FG6H1E", "FortiGate 601E", "Mid-range", False),
    Platform("FG6H0F", "FortiGate 600F", "Mid-range", False),
    # verified: DC-Firewall-601F-A backup header, 8.0 build0167 (2026-06)
    Platform("FG6H1F", "FortiGate 601F", "Mid-range", True),
    # -- high-end -------------------------------------------------------
    Platform("FG7H0G", "FortiGate 700G", "High-end", False),
    # verified: native 701G backup header, 7.4.11 build2878 (2026-06-12)
    Platform("FG7H1G", "FortiGate 701G", "High-end", True),
    Platform("FG9H0G", "FortiGate 900G", "High-end", False),
    Platform("FG9H1G", "FortiGate 901G", "High-end", False),
    Platform("FG1K0F", "FortiGate 1000F", "High-end", False),
    Platform("FG1K1F", "FortiGate 1001F", "High-end", False),
    # x01 siblings use the 4-char tail extension of the K-rule
    # (4801 -> 4K81) — the least-anchored derivations in this table;
    # the * marker / destination-backup flow is the safety net.
    # Lineup ceiling is 4801F by design owner's call (2026-06-12);
    # 6000/7000-series chassis are deliberately not listed.
    Platform("FG1K8F", "FortiGate 1800F", "High-end", False),
    Platform("FG1K81F", "FortiGate 1801F", "High-end", False),
    Platform("FG2K6F", "FortiGate 2600F", "High-end", False),
    Platform("FG3K0F", "FortiGate 3000F", "High-end", False),
    Platform("FG3K1F", "FortiGate 3001F", "High-end", False),
    Platform("FG3K2F", "FortiGate 3200F", "High-end", False),
    Platform("FG3K21F", "FortiGate 3201F", "High-end", False),
    Platform("FG3K5F", "FortiGate 3500F", "High-end", False),
    Platform("FG3K51F", "FortiGate 3501F", "High-end", False),
    Platform("FG3K7F", "FortiGate 3700F", "High-end", False),
    Platform("FG3K71F", "FortiGate 3701F", "High-end", False),
    Platform("FG4K2F", "FortiGate 4200F", "High-end", False),
    Platform("FG4K21F", "FortiGate 4201F", "High-end", False),
    Platform("FG4K4F", "FortiGate 4400F", "High-end", False),
    Platform("FG4K41F", "FortiGate 4401F", "High-end", False),
    Platform("FG4K8F", "FortiGate 4800F", "High-end", False),
    Platform("FG4K81F", "FortiGate 4801F", "High-end", False),
    # -- virtual --------------------------------------------------------
    Platform("FGVM64", "FortiGate VM64", "Virtual", False),
)

# -- FortiOS target versions ------------------------------------------------
# The version "database" backing the target-OS picker. The version field is
# free-text — any exact patch (e.g. "7.4.12") is accepted — so these are just
# the dropdown SUGGESTIONS, newest train first. Keep current as Fortinet ships
# trains; a scheduled job can refresh this from docs.fortinet.com (see the
# fortigate skill). Train-level entries are always valid; the per-train default
# patch is a best-effort hint only (verify against the actual target build).
FORTIOS_TRAINS: tuple[str, ...] = ("8.0", "7.6", "7.4", "7.2", "7.0")

# Latest known GA patch per active train, surfaced as extra datalist hints.
# REFRESH PERIODICALLY — these go stale; the field accepts any unlisted value.
FORTIOS_LATEST_PATCH: dict[str, str] = {
    "8.0": "8.0.1",
    "7.6": "7.6.3",
    "7.4": "7.4.8",
    "7.2": "7.2.11",
}


def version_suggestions() -> tuple[str, ...]:
    """Ordered, de-duplicated version hints for the target-OS datalist:
    each active train followed by its latest known patch."""
    out: list[str] = []
    for train in FORTIOS_TRAINS:
        out.append(train)
        patch = FORTIOS_LATEST_PATCH.get(train)
        if patch and patch not in out:
            out.append(patch)
    return tuple(out)


_FAMILY_ORDER = ("Desktop", "Mid-range", "High-end", "Virtual")

# platform code -> product label, e.g. "FG6H1F" -> "FortiGate 601F"
MODEL_BY_CODE: dict[str, str] = {p.code: p.model for p in PLATFORMS}

GROUPS: tuple[tuple[str, tuple[Platform, ...]], ...] = tuple(
    (fam, tuple(p for p in PLATFORMS if p.family == fam))
    for fam in _FAMILY_ORDER
)

# a plausible custom code: FG/FGT/FWF prefix, then model digits/letters
_CODE_RE = re.compile(r"^(FG|FWF)[0-9A-Z]{2,12}$")

_BY_CODE = {p.code: p for p in PLATFORMS}

# flattened name keys ("701G", "FORTIGATE701G", "FG701G", ...) -> entry.
# Insertion order matters: first writer wins, so FortiGate beats
# FortiWiFi for a bare "60F".
_BY_NAME: dict[str, Platform] = {}
for _p in PLATFORMS:
    _tail = _p.model.split()[-1].upper()
    for _k in (_tail, _p.model.upper().replace(" ", ""), f"FG{_tail}",
               f"FGT{_tail}"):
        _BY_NAME.setdefault(_k, _p)

_VERIFY_NOTE = ("confirm against a backup taken from the actual target "
                "device before restoring")

# -- physical port inventories ----------------------------------------------
# Interface names as FortiOS configures them (lowercase), per platform
# code. Drives portmap target suggestions: a source port that does not
# exist on the target model MUST be remapped or the restore drops it and
# everything referencing it. Only models with a confirmed inventory are
# listed; provenance per entry. USB modem / npu vlinks excluded (not
# front-panel ports).

# ground truth: FortiGate 601F backup, config system interface (2026-06)
_PORTS_600F = ("ha", "mgmt") \
    + tuple(f"port{i}" for i in range(1, 25)) \
    + tuple(f"x{i}" for i in range(1, 9))

# verified against a native 701G backup (34 ports, 2026-06-12);
# matches the FG-700G-Series QuickStart Guide front panel exactly:
# WAN1/2 + LAN1-6 5G RJ45, LAN7-22 SFP 1G, X1-X4 FortiLink SFP+ 10G,
# X5-X8 SFP28 25G, HA 2.5G, MGMT 1G
_PORTS_700G = ("ha", "mgmt", "wan1", "wan2") \
    + tuple(f"lan{i}" for i in range(1, 23)) \
    + tuple(f"x{i}" for i in range(1, 9))

# live `get system interface physical` on a lab FortiGate 60F (2026-06)
_PORTS_60F = ("wan1", "wan2", "dmz", "internal1", "internal2",
              "internal3", "internal4", "internal5", "a", "b")

PORT_INVENTORY: dict[str, tuple[str, ...]] = {
    "FG6H0F": _PORTS_600F,   # 600F: same chassis as 601F
    "FG6H1F": _PORTS_600F,
    "FG7H0G": _PORTS_700G,   # QSG covers FG-700G and FG-701G
    "FG7H1G": _PORTS_700G,
    "FGT60F": _PORTS_60F,
    "FGT61F": _PORTS_60F,    # 61F: 60F chassis + storage
}


def ports_for(code: str) -> tuple[str, ...]:
    """Known physical-port names for a platform code; empty tuple when
    the model's inventory has not been confirmed yet."""
    return PORT_INVENTORY.get(code.strip().upper(), ())


_HEADER_RE = re.compile(
    r"#config-version=([^-\s]+)-(\d+\.\d+\.\d+)-FW")


def header_platform(text: str) -> str:
    """Platform token from a config's #config-version header ('' when
    absent) — identifies the source device, e.g. for faceplate
    rendering."""
    m = _HEADER_RE.match(text.lstrip())
    return m.group(1) if m else ""


# `config system global` settings that identify the physical box rather
# than its security config. When a destination backup is supplied these
# are carried onto the migrated output so the converted file IS the
# destination device's config (keeps its own name), not a renamed clone
# of the source. Identity only — NOT policies/objects (that stays the
# declined merge-into-existing feature). Extend deliberately.
DEVICE_IDENTITY_ATTRS: tuple[str, ...] = ("hostname", "alias")


def device_identity(text: str) -> dict[str, str]:
    """{attr: value} for the DEVICE_IDENTITY_ATTRS present in a config's
    `config system global` (global scope on multi-VDOM)."""
    from .parsers import fortios_tree
    tree = fortios_tree.parse_config(text)
    out: dict[str, str] = {}
    for path, node in fortios_tree.iter_config_nodes(tree):
        if not fortios_tree.path_endswith(path, ("system", "global")):
            continue
        for line in node.children:
            if isinstance(line, fortios_tree.SetLine) \
                    and line.attr in DEVICE_IDENTITY_ATTRS and line.values:
                out[line.attr] = line.values[0].value
        break
    return out


def safe_filename(name: str, fallback: str = "config") -> str:
    """A filesystem-safe stem from a device name/hostname."""
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip()).strip("._-")
    return s or fallback


_SERIES_RE = re.compile(r"^([A-Za-z]+)(\d+)$")


def _series(names: list[str]) -> dict[str, dict[int, str]]:
    """Group <prefix><number> names by prefix: {'port': {1:'port1', ...}}."""
    out: dict[str, dict[int, str]] = {}
    for n in names:
        m = _SERIES_RE.match(n)
        if m:
            out.setdefault(m.group(1).lower(), {})[int(m.group(2))] = n
    return out


def guess_portmap(source_ports: list[str],
                  dest_ports: list[str]) -> dict[str, str]:
    """Best-effort source->dest physical-port guesses, confident only:

    1. exact name match keeps the name (x1->x1, mgmt->mgmt, ha->ha);
    2. the source's largest still-unmatched `<prefix><N>` series maps by
       NUMBER onto the destination's largest still-unused series
       (601F port1->701G lan1 ... port22->lan22).

    Ambiguous ports (a source number with no destination counterpart,
    spare destination ports like wan1/2) are intentionally left out for
    the user to map. Never maps two sources onto one destination."""
    dest_set = set(dest_ports)
    guess: dict[str, str] = {}
    used: set[str] = set()
    for s in source_ports:
        if s in dest_set and s not in used:
            guess[s] = s
            used.add(s)
    src_series = _series([s for s in source_ports if s not in guess])
    dest_series = _series([d for d in dest_ports if d not in used])
    if src_series and dest_series:
        s_prefix = max(src_series, key=lambda k: len(src_series[k]))
        d_prefix = max(dest_series, key=lambda k: len(dest_series[k]))
        for num, sname in sorted(src_series[s_prefix].items()):
            dname = dest_series[d_prefix].get(num)
            if dname and dname not in used:
                guess[sname] = dname
                used.add(dname)
    return guess


# -- faceplate layouts --------------------------------------------------------
# Schematic front-panel specs for the GUI's port-lighting view. These
# are our own schematic drawings (groups of port rectangles) — no
# vendor artwork. Group fields: label, kind (rj45|sfp), rows (FortiGate
# panels stack odd-over-even in column pairs), ports (FortiOS names).
# Models without a spec render a generic strip from their port list.

# verified against the DC-Firewall-601F-A backup: port1-16 GE RJ45,
# port17-24 GE SFP, x1-x4 10G SFP+ (speed 10000full), x5-x8 25G SFP28
# (speed 25000full + FEC). Faceplate shows physical cage type, not the
# installed optic — a 25G cage running a 10G optic is still a 25G port.
_FP_600F = (
    {"label": "MGMT / HA", "kind": "rj45", "rows": 2,
     "ports": ("mgmt", "ha")},
    {"label": "GE RJ45", "kind": "rj45", "rows": 2,
     "ports": tuple(f"port{i}" for i in range(1, 17))},
    {"label": "GE SFP", "kind": "sfp", "rows": 2,
     "ports": tuple(f"port{i}" for i in range(17, 25))},
    {"label": "10G SFP+", "kind": "sfp", "rows": 2,
     "ports": ("x1", "x2", "x3", "x4")},
    {"label": "25G SFP28", "kind": "sfp", "rows": 2,
     "ports": ("x5", "x6", "x7", "x8")},
)

# per the FG-700G-Series QSG front panel (verified vs native backup)
_FP_700G = (
    {"label": "MGMT / HA", "kind": "rj45", "rows": 2,
     "ports": ("mgmt", "ha")},
    {"label": "5G RJ45", "kind": "rj45", "rows": 2,
     "ports": ("wan1", "wan2", "lan1", "lan2", "lan3", "lan4",
               "lan5", "lan6")},
    {"label": "1G SFP", "kind": "sfp", "rows": 2,
     "ports": tuple(f"lan{i}" for i in range(7, 23))},
    {"label": "10G SFP+ FortiLink", "kind": "sfp", "rows": 2,
     "ports": ("x1", "x2", "x3", "x4")},
    {"label": "25G SFP28", "kind": "sfp", "rows": 2,
     "ports": ("x5", "x6", "x7", "x8")},
)

_FP_60F = (
    {"label": "WAN", "kind": "rj45", "rows": 1,
     "ports": ("wan1", "wan2")},
    {"label": "DMZ", "kind": "rj45", "rows": 1, "ports": ("dmz",)},
    {"label": "INTERNAL", "kind": "rj45", "rows": 1,
     "ports": tuple(f"internal{i}" for i in range(1, 6))},
    {"label": "A / B", "kind": "rj45", "rows": 1,
     "ports": ("a", "b")},
)

FACEPLATES: dict[str, tuple] = {
    "FG6H0F": _FP_600F,
    "FG6H1F": _FP_600F,
    "FG7H0G": _FP_700G,
    "FG7H1G": _FP_700G,
    "FGT60F": _FP_60F,
    "FGT61F": _FP_60F,
}


def inventory_from_config(text: str) -> tuple[str, str, tuple[str, ...]]:
    """(platform_code, version, physical_ports) read from a config
    backup taken on the DESTINATION device — a factory-fresh backup is
    ideal. The header supplies the authoritative platform token (no
    derivation, no probing) and `config system interface` the real port
    names. The file is reference metadata only; nothing from it is
    merged into the output."""
    m = _HEADER_RE.match(text.lstrip())
    if not m:
        raise PlanError(
            "the destination file has no #config-version header — "
            "provide a config backup taken from the target device "
            "(System > Configuration > Backup, or "
            "'execute backup config')")
    code, version = m.group(1), m.group(2)
    from .parsers import fortios_tree
    from .transforms.portmap import tree_interface_details
    tree = fortios_tree.parse_config(text)
    ports = tuple(
        d["name"] for d in tree_interface_details(tree)
        if d["type"] == "physical" and "." not in d["name"]
        and d["name"] != "modem")
    if not ports:
        raise PlanError(
            "the destination file has no 'config system interface' "
            "section — it does not look like a FortiGate backup")
    return code, version, ports


def resolve(text: str) -> tuple[str, str]:
    """Map user input to a platform code.

    Accepts a known code ("FG7H1G"), a model number ("701G"/"701g"), an
    SKU ("FG-701G"), a product name ("FortiGate 701G"), or an unknown
    but plausibly-shaped code. Returns (code, note) where note is ""
    for a verified table hit and a verify reminder otherwise. Raises
    PlanError for input that matches nothing.
    """
    flat = text.strip().upper().replace("-", "").replace(" ", "")
    if not flat:
        raise PlanError("empty target platform")

    hit = _BY_CODE.get(flat)
    if hit is None:
        # model-name lookup needs spaces collapsed too ("FORTIGATE 701G")
        hit = _BY_NAME.get(flat)
    if hit is not None:
        if hit.verified:
            return hit.code, ""
        return hit.code, (f"{hit.model}: code derived from the FortiOS "
                          f"naming scheme — {_VERIFY_NOTE}")

    if _CODE_RE.match(flat):
        return flat, f"not in the known-model table — {_VERIFY_NOTE}"

    close = difflib.get_close_matches(
        flat, list(_BY_NAME) + list(_BY_CODE), n=3, cutoff=0.6)
    seen, hints = set(), []
    for c in close:
        p = _BY_NAME.get(c) or _BY_CODE.get(c)
        if p and p.code not in seen:
            seen.add(p.code)
            hints.append(f"{p.model} = {p.code}")
    hint = f" Did you mean: {'; '.join(hints)}?" if hints else ""
    raise PlanError(
        f"'{text}' is not a FortiGate platform code or model. Pick a "
        "model (e.g. '701G') or paste the code from a backup header of "
        f"the target device (e.g. FG7H1G).{hint}")
