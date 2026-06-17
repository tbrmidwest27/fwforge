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
INTF_MAX = 15  # FortiOS rejects interface names longer than this
PROFILE_MAX = 35  # FortiOS UTM profile / IPS sensor name limit


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


def _emit_name_ok(name: str) -> bool:
    """Whether FortiOS will accept this name on a `config system interface`
    `edit` line: non-empty, <= 15 chars, no whitespace. (FortiOS tolerates
    `/` and `.` in interface names, so a short slashed name is left alone.)"""
    return bool(name) and len(name) <= INTF_MAX and not re.search(r"\s", name)


def sanitize_interfaces(cfg: FirewallConfig, report) -> dict[str, str]:
    """Clamp the interfaces fwforge *creates* (VLAN / aggregate / loopback)
    to FortiOS's 15-char interface-name limit — a hard limit FortiOS rejects
    the `edit` line over (cascading every following `set` to fail).

    A VLAN keeps its full VLAN id (the part that makes it unique) and takes
    its parent's mapped name, truncated to fit: `ethernet1/6.1027` (16) ->
    `port6.1027` when the parent maps to `port6`. References resolve through
    the interface's mapped name (`_intf`), but the few that `apply_ir` already
    rewrote to the old name are remapped here too. Returns {old -> new}.

    Cross-vendor only: a FortiOS source's names are already within limits."""
    created = [i for i in cfg.interfaces
               if i.kind in ("aggregate", "vlan", "loopback")]
    if not created:
        return {}

    # reserve names that stay put (already-valid created ifaces + every
    # physical port) so a rename can't collide with one of them
    taken: set[str] = set()
    todo: list = []
    for i in created:
        (taken.add(i.mapped) if _emit_name_ok(i.mapped) else todo.append(i))
    for i in cfg.interfaces:
        if i.kind == "physical":
            taken.add(i.mapped)

    renames: dict[str, str] = {}
    for i in todo:
        old = i.mapped
        if i.kind == "vlan" and i.vlan_id is not None:
            parent = cfg.interface_by_name(i.parent) if i.parent else None
            head_src = parent.mapped if parent else (i.parent or "vlan")
            suffix = f".{i.vlan_id}"
            head = SAFE.sub("_", head_src)[:max(1, INTF_MAX - len(suffix))]
            head = head.strip("_.-") or "vlan"
            preferred = f"{head}{suffix}"
        else:
            preferred = old
        new = sanitize(preferred, INTF_MAX, taken)
        taken.add(new)
        i.target_name = new
        renames[old] = new
        hint = (" — map its parent port to a short name (e.g. 'port6') for "
                "cleaner VLAN names" if i.kind == "vlan" else "")
        report.add(
            "warn", "interfaces",
            f"interface '{old}' exceeds FortiOS's {INTF_MAX}-char limit; "
            f"renamed to '{new}'{hint}",
            getattr(i, "source", None))

    if renames:
        for zone in cfg.zones:
            zone.members = [renames.get(m, m) for m in zone.members]
        for p1 in cfg.phase1s:
            p1.interface = renames.get(p1.interface, p1.interface)
        for rt in cfg.routes:
            rt.interface = renames.get(rt.interface, rt.interface)
        for vip in cfg.vips:
            vip.ext_intf = renames.get(vip.ext_intf, vip.ext_intf)
        for nat in cfg.nats:
            nat.real_ifc = renames.get(nat.real_ifc, nat.real_ifc)
            nat.mapped_ifc = renames.get(nat.mapped_ifc, nat.mapped_ifc)
    return renames


def sanitize_profiles(cfg: FirewallConfig, report) -> None:
    """Clamp UTM profile + IPS sensor names to FortiOS's 35-char limit (a
    longer `edit` is rejected with -1, cascading the body to -61) and remap
    the policy fields that reference them. Each profile type is its own
    FortiOS namespace, so each gets its own taken-set."""
    specs = [
        (cfg.ips_sensors, "ips_sensor", "IPS sensor"),
        (cfg.app_lists, "app_list", "application list"),
        (cfg.webfilters, "webfilter", "webfilter profile"),
        (cfg.file_filters, "file_filter", "file-filter profile"),
        (cfg.av_profiles, "antivirus", "antivirus profile"),
    ]
    for coll, pol_field, label in specs:
        taken: set[str] = set()
        renames: dict[str, str] = {}
        for obj in coll:
            new = sanitize(obj.name, PROFILE_MAX, taken)
            if new != obj.name:
                renames[obj.name] = new
                report.add("info", "names",
                           f"renamed {label} '{obj.name}' -> '{new}' "
                           f"(FortiOS {PROFILE_MAX}-char limit)",
                           getattr(obj, "source", None))
                obj.name = new
            taken.add(obj.name)
        if renames:
            for pol in cfg.policies:
                cur = getattr(pol, pol_field, "")
                if cur in renames:
                    setattr(pol, pol_field, renames[cur])
