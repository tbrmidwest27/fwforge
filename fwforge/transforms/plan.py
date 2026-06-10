"""Migration plan file: one file describing a whole FortiOS -> FortiOS
model migration — port renames, interfaces to fold into zones, interfaces
to move into SD-WAN.

INI format (stdlib configparser), case-sensitive:

    [portmap]
    port1 = wan1
    port2 = internal1

    [zone lan]
    intrazone = deny
    member = internal1, vlan30

    [sdwan virtual-wan-link]
    member = wan1 gateway=203.0.113.1, wan2 weight=10
    health-check = ping 8.8.8.8

Zone/sdwan member names refer to interfaces *after* the portmap is applied;
source names are translated automatically when they appear.
"""
from __future__ import annotations

import configparser
import re
from dataclasses import dataclass, field


class PlanError(ValueError):
    """A migration plan is invalid or cannot be applied to this config."""


@dataclass
class ZoneSpec:
    name: str
    members: list[str] = field(default_factory=list)
    intrazone: str = "deny"
    vdom: str | None = None  # optional assertion; derived from members


@dataclass
class SdwanMember:
    interface: str
    gateway: str = ""
    cost: str = ""
    weight: str = ""
    priority: str = ""


@dataclass
class SdwanZoneSpec:
    name: str
    members: list[SdwanMember] = field(default_factory=list)
    # (protocol, server) — None = create a default ping check,
    # ("none", "") = explicitly no health check
    health_check: tuple[str, str] | None = None
    vdom: str | None = None  # optional assertion; derived from members


@dataclass
class MigrationPlan:
    portmap: dict[str, str] = field(default_factory=dict)
    zones: list[ZoneSpec] = field(default_factory=list)
    sdwan: list[SdwanZoneSpec] = field(default_factory=list)

    def translate_members(self) -> None:
        """Zone/sdwan members given as *source* names -> target names."""
        for z in self.zones:
            z.members = [self.portmap.get(m, m) for m in z.members]
        for s in self.sdwan:
            for m in s.members:
                m.interface = self.portmap.get(m.interface, m.interface)


_MEMBER_KEYS = {"gateway", "cost", "weight", "priority"}


def _split_members(value: str) -> list[str]:
    return [e.strip() for e in re.split(r"[,\n]+", value) if e.strip()]


def _parse_sdwan_member(entry: str, section: str) -> SdwanMember:
    toks = entry.split()
    member = SdwanMember(interface=toks[0])
    for tok in toks[1:]:
        if "=" not in tok:
            raise PlanError(
                f"[{section}]: bad member attribute '{tok}' "
                f"(expected key=value)")
        key, val = tok.split("=", 1)
        if key not in _MEMBER_KEYS:
            raise PlanError(
                f"[{section}]: unknown member attribute '{key}' "
                f"(allowed: {', '.join(sorted(_MEMBER_KEYS))})")
        setattr(member, key, val)
    return member


def load_plan(path: str) -> MigrationPlan:
    cp = configparser.ConfigParser(interpolation=None)
    cp.optionxform = str  # interface names are case-sensitive
    read = cp.read(path, encoding="utf-8-sig")
    if not read:
        raise PlanError(f"cannot read plan file: {path}")

    plan = MigrationPlan()
    for section in cp.sections():
        parts = section.split(None, 1)
        kind = parts[0]

        if kind == "portmap":
            plan.portmap.update(dict(cp.items(section)))

        elif kind == "zone":
            if len(parts) < 2:
                raise PlanError("[zone] needs a name: [zone lan]")
            spec = ZoneSpec(name=parts[1].strip())
            for key, value in cp.items(section):
                if key in ("member", "members"):
                    spec.members = _split_members(value)
                elif key == "intrazone":
                    if value not in ("allow", "deny"):
                        raise PlanError(
                            f"[{section}]: intrazone must be allow|deny")
                    spec.intrazone = value
                elif key == "vdom":
                    spec.vdom = value.strip()
                else:
                    raise PlanError(f"[{section}]: unknown key '{key}'")
            if not spec.members:
                raise PlanError(f"[{section}]: no members listed")
            plan.zones.append(spec)

        elif kind == "sdwan":
            if len(parts) < 2:
                raise PlanError(
                    "[sdwan] needs a zone name: [sdwan virtual-wan-link]")
            spec = SdwanZoneSpec(name=parts[1].strip())
            for key, value in cp.items(section):
                if key in ("member", "members"):
                    spec.members = [
                        _parse_sdwan_member(e, section)
                        for e in _split_members(value)
                    ]
                elif key in ("health-check", "health_check"):
                    v = value.split()
                    if v == ["none"]:
                        spec.health_check = ("none", "")
                    elif len(v) == 2 and v[0] in ("ping", "http", "dns"):
                        spec.health_check = (v[0], v[1])
                    else:
                        raise PlanError(
                            f"[{section}]: health-check must be "
                            "'none' or '<ping|http|dns> <server>'")
                elif key == "vdom":
                    spec.vdom = value.strip()
                else:
                    raise PlanError(f"[{section}]: unknown key '{key}'")
            if not spec.members:
                raise PlanError(f"[{section}]: no members listed")
            plan.sdwan.append(spec)

        else:
            raise PlanError(
                f"unknown section [{section}] "
                "(expected portmap / zone <name> / sdwan <name>)")

    plan.translate_members()
    return plan


def scaffold(interfaces: list[str], source_name: str) -> str:
    """A starter plan file for a given source config."""
    width = max((len(n) for n in interfaces), default=8)
    lines = [
        f"# fwforge migration plan for {source_name}",
        "# 1. fill in [portmap] with the target model's port names",
        "# 2. optionally uncomment [zone ...] / [sdwan ...] sections",
        "",
        "[portmap]",
    ]
    for n in interfaces:
        lines.append(f"{n.ljust(width)} = {n}")
    lines += [
        "",
        "# [zone lan]",
        "# intrazone = deny",
        "# member = port2, port3",
        "",
        "# [sdwan virtual-wan-link]",
        "# member = wan1 gateway=203.0.113.1, wan2 weight=10",
        "# health-check = ping 8.8.8.8",
        "",
    ]
    return "\n".join(lines)
