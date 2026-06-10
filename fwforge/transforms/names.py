"""Object-name sanitization for FortiOS limits.

FortiOS constraints enforced here:
- address / service / group names: 79 chars
- policy names: 35 chars, unique
- reserved built-in names ('all', 'ALL', 'ALL_ICMP', 'always', 'none')
  must not be claimed by converted objects

Renames are applied consistently to every reference and reported.
"""
from __future__ import annotations

import re

from ..model import FirewallConfig

SAFE = re.compile(r"[^A-Za-z0-9_.-]")
RESERVED = {"all", "ALL", "ALL_ICMP", "always", "none", "ANY", "any"}

OBJ_MAX = 79
POLICY_MAX = 35


def sanitize(name: str, maxlen: int, taken: set[str]) -> str:
    out = SAFE.sub("_", name).strip("_") or "obj"
    if out in RESERVED:
        out = f"{out}_o"
    out = out[:maxlen]
    if out in taken:
        base = out[: maxlen - 4]
        n = 2
        while f"{base}~{n}" in taken:
            n += 1
        out = f"{base}~{n}"
    return out


def apply(cfg: FirewallConfig, report) -> dict[str, str]:
    """Sanitize all object names in-place; returns the rename map."""
    renames: dict[str, str] = {}
    taken: set[str] = set()

    def fix(obj, maxlen: int = OBJ_MAX):
        new = sanitize(obj.name, maxlen, taken)
        if new != obj.name:
            renames[obj.name] = new
            report.add(
                "info", "names",
                f"renamed '{obj.name}' -> '{new}' (FortiOS naming rules)",
                obj.source,
            )
            obj.name = new
        taken.add(obj.name)

    for coll in (cfg.addresses, cfg.addr_groups, cfg.services, cfg.svc_groups,
                 cfg.vips):
        for obj in coll:
            fix(obj)

    # zone names get their own namespace (they collide with nothing above)
    zone_renames: dict[str, str] = {}
    zone_taken: set[str] = set()
    for zone in cfg.zones:
        new = sanitize(zone.name, OBJ_MAX, zone_taken)
        if new != zone.name:
            zone_renames[zone.name] = new
            report.add("info", "names",
                       f"renamed zone '{zone.name}' -> '{new}'", zone.source)
            zone.name = new
        zone_taken.add(zone.name)
    if zone_renames:
        for pol in cfg.policies:
            pol.src_zones = [zone_renames.get(z, z) for z in pol.src_zones]
            pol.dst_zones = [zone_renames.get(z, z) for z in pol.dst_zones]
        for nat in cfg.nats:
            nat.real_ifc = zone_renames.get(nat.real_ifc, nat.real_ifc)
            nat.mapped_ifc = zone_renames.get(nat.mapped_ifc, nat.mapped_ifc)

    taken_policies: set[str] = set()
    for pol in cfg.policies:
        if pol.name:
            new = sanitize(pol.name, POLICY_MAX, taken_policies)
            if new != pol.name:
                renames[pol.name] = new
            pol.name = new
            taken_policies.add(new)

    if renames:
        def remap(names: list[str]):
            for i, n in enumerate(names):
                if n in renames:
                    names[i] = renames[n]

        for grp in cfg.addr_groups:
            remap(grp.members)
        for grp in cfg.svc_groups:
            remap(grp.members)
        for pol in cfg.policies:
            remap(pol.src_addrs)
            remap(pol.dst_addrs)
            remap(pol.services)
        for nat in cfg.nats:
            if nat.real_obj in renames:
                nat.real_obj = renames[nat.real_obj]
    return renames
