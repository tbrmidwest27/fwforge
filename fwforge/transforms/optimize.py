"""Config hygiene analysis.

FortiConverter converts a config 1:1 by default — including objects nothing
references and rules shadowed by earlier rules. v1 reports these instead of
silently porting (or silently dropping) them; auto-clean flags come later.
"""
from __future__ import annotations

from ..model import FirewallConfig


def _referenced_names(cfg: FirewallConfig) -> tuple[set[str], set[str]]:
    addr_refs: set[str] = set()
    svc_refs: set[str] = set()
    for pol in cfg.policies:
        addr_refs.update(pol.src_addrs)
        addr_refs.update(pol.dst_addrs)
        svc_refs.update(pol.services)
    # NAT intents reference address objects too — pruning those would
    # silently widen the emitted SNAT match to 'all'
    for n in cfg.nats:
        if n.real_obj:
            addr_refs.add(n.real_obj)

    # group membership counts as a reference, but only if the group itself
    # is (transitively) referenced
    changed = True
    while changed:
        changed = False
        for grp in cfg.addr_groups:
            if grp.name in addr_refs:
                for m in grp.members:
                    if m not in addr_refs:
                        addr_refs.add(m)
                        changed = True
        for grp in cfg.svc_groups:
            if grp.name in svc_refs:
                for m in grp.members:
                    if m not in svc_refs:
                        svc_refs.add(m)
                        changed = True
    return addr_refs, svc_refs


def analyze(cfg: FirewallConfig, report) -> None:
    # duplicate definitions under different names
    by_value: dict[tuple, list[str]] = {}
    for a in cfg.addresses:
        by_value.setdefault(("addr", a.type, a.value), []).append(a.name)
    for s in cfg.services:
        by_value.setdefault(("svc",) + s.signature(), []).append(s.name)
    for key, names in sorted(by_value.items()):
        if len(names) > 1:
            kind = "address" if key[0] == "addr" else "service"
            report.add(
                "info", "hygiene",
                f"duplicate {kind} definitions (same value, {len(names)} "
                f"names): {', '.join(names)} — candidates to merge",
            )

    # unreferenced objects
    addr_refs, svc_refs = _referenced_names(cfg)
    dead_addrs = [a.name for a in cfg.addresses if a.name not in addr_refs]
    dead_addrs += [g.name for g in cfg.addr_groups if g.name not in addr_refs]
    dead_svcs = [s.name for s in cfg.services if s.name not in svc_refs]
    dead_svcs += [g.name for g in cfg.svc_groups if g.name not in svc_refs]
    if dead_addrs:
        report.add(
            "info", "hygiene",
            f"{len(dead_addrs)} address object(s) referenced by no policy or "
            f"group: {', '.join(sorted(dead_addrs)[:15])}"
            + (" …" if len(dead_addrs) > 15 else ""),
        )
    if dead_svcs:
        report.add(
            "info", "hygiene",
            f"{len(dead_svcs)} service object(s) referenced by no policy or "
            f"group: {', '.join(sorted(dead_svcs)[:15])}"
            + (" …" if len(dead_svcs) > 15 else ""),
        )

    # duplicate / trivially-shadowed policies and any-any-ALL rules
    seen: dict[tuple, str] = {}
    for pol in cfg.policies:
        key = (
            tuple(pol.src_zones), tuple(pol.dst_zones),
            tuple(sorted(pol.src_addrs)), tuple(sorted(pol.dst_addrs)),
            tuple(sorted(pol.services)),
        )
        if key in seen:
            report.add(
                "warn", "hygiene",
                f"policy '{pol.name}' duplicates '{seen[key]}' "
                "(identical match criteria — the later one never matches)",
                pol.source,
            )
        else:
            seen[key] = pol.name
        if (pol.action == "accept" and not pol.disabled
                and pol.src_addrs == ["all"] and pol.dst_addrs == ["all"]
                and pol.services == ["ALL"]):
            report.add(
                "warn", "hygiene",
                f"policy '{pol.name}' is an any/any/ALL accept — "
                "confirm this is intentional",
                pol.source,
            )
