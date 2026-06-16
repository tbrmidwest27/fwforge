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
    """Sanitize all object names in-place; returns the rename map.

    FortiOS object namespaces are independent: an address and a service may
    legitimately share a name. Each namespace therefore gets its OWN taken-set
    and rename-map, and a reference is remapped only from the map for the
    namespace it points into. Sharing one map across namespaces silently
    corrupted references -- renaming a service 'web' would rewrite a policy's
    *address* reference 'web' onto the service, or merge two distinct objects.
    """
    addr_renames: dict[str, str] = {}
    svc_renames: dict[str, str] = {}

    def make_fix(taken: set[str], renames: dict[str, str], kind: str):
        def fix(obj, maxlen: int = OBJ_MAX):
            new = sanitize(obj.name, maxlen, taken)
            if new != obj.name:
                renames[obj.name] = new
                report.add(
                    "info", "names",
                    f"renamed {kind} '{obj.name}' -> '{new}' "
                    "(FortiOS naming rules)",
                    obj.source,
                )
                obj.name = new
            taken.add(obj.name)
        return fix

    # Address namespace: firewall address, addrgrp and vip share one namespace.
    addr_taken: set[str] = set()
    fix_addr = make_fix(addr_taken, addr_renames, "address")
    for coll in (cfg.addresses, cfg.addr_groups, cfg.vips):
        for obj in coll:
            fix_addr(obj)

    # Service namespace: service custom + service group share one namespace.
    svc_taken: set[str] = set()
    fix_svc = make_fix(svc_taken, svc_renames, "service")
    for coll in (cfg.services, cfg.svc_groups):
        for obj in coll:
            fix_svc(obj)

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

    # Policy names are their own namespace; nothing references a policy by name,
    # so policy renames are NOT applied to object references. They are still
    # returned so the caller can translate --only/--exclude rule names.
    pol_renames: dict[str, str] = {}
    taken_policies: set[str] = set()
    for pol in cfg.policies:
        if pol.name:
            new = sanitize(pol.name, POLICY_MAX, taken_policies)
            if new != pol.name:
                pol_renames[pol.name] = new
            pol.name = new
            taken_policies.add(new)

    # Remap each reference from the map for the namespace it points into.
    def remap(names: list[str], renames: dict[str, str]):
        for i, n in enumerate(names):
            if n in renames:
                names[i] = renames[n]

    for grp in cfg.addr_groups:
        remap(grp.members, addr_renames)
    for grp in cfg.svc_groups:
        remap(grp.members, svc_renames)
    for pol in cfg.policies:
        remap(pol.src_addrs, addr_renames)
        remap(pol.dst_addrs, addr_renames)
        remap(pol.services, svc_renames)
    for nat in cfg.nats:
        if nat.real_obj in addr_renames:
            nat.real_obj = addr_renames[nat.real_obj]

    return {**addr_renames, **svc_renames, **pol_renames}
