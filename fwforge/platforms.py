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
    Platform("FGT40F", "FortiGate 40F", "Desktop", False),
    Platform("FGT60E", "FortiGate 60E", "Desktop", False),
    # verified: lab FGSP member header, FortiOS 8.0 build0167 (2026-06-12)
    Platform("FGT60F", "FortiGate 60F", "Desktop", True),
    Platform("FGT61F", "FortiGate 61F", "Desktop", False),
    Platform("FGT70F", "FortiGate 70F", "Desktop", False),
    Platform("FGT71F", "FortiGate 71F", "Desktop", False),
    Platform("FGT80F", "FortiGate 80F", "Desktop", False),
    Platform("FGT81F", "FortiGate 81F", "Desktop", False),
    Platform("FGT50G", "FortiGate 50G", "Desktop", False),
    Platform("FGT51G", "FortiGate 51G", "Desktop", False),
    Platform("FGT70G", "FortiGate 70G", "Desktop", False),
    Platform("FGT71G", "FortiGate 71G", "Desktop", False),
    Platform("FGT90G", "FortiGate 90G", "Desktop", False),
    Platform("FGT91G", "FortiGate 91G", "Desktop", False),
    Platform("FWF60F", "FortiWiFi 60F", "Desktop", False),
    # -- mid-range ------------------------------------------------------
    Platform("FG100F", "FortiGate 100F", "Mid-range", False),
    Platform("FG101F", "FortiGate 101F", "Mid-range", False),
    Platform("FG120G", "FortiGate 120G", "Mid-range", False),
    Platform("FG121G", "FortiGate 121G", "Mid-range", False),
    Platform("FG200F", "FortiGate 200F", "Mid-range", False),
    Platform("FG201F", "FortiGate 201F", "Mid-range", False),
    Platform("FG200G", "FortiGate 200G", "Mid-range", False),
    Platform("FG201G", "FortiGate 201G", "Mid-range", False),
    Platform("FG4H0F", "FortiGate 400F", "Mid-range", False),
    Platform("FG4H1F", "FortiGate 401F", "Mid-range", False),
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
    # -- virtual --------------------------------------------------------
    Platform("FGVM64", "FortiGate VM64", "Virtual", False),
)

_FAMILY_ORDER = ("Desktop", "Mid-range", "High-end", "Virtual")

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
