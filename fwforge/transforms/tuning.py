"""Tuning actions — the FortiConverter "Tuning page", but acting not just
reporting.

FortiConverter converts 1:1 by default and offers a shallow opt-in cleanup
(discard unreferenced objects only). optimize.py already *detects* the full
hygiene picture; this module *applies* it, on request, to the cross-vendor
IR before emission:

- prune_unreferenced: drop address/service objects + groups nothing uses
- merge_duplicates: collapse same-value objects to one name, rewrite refs
- filter_policies: rule include/exclude by name
- split_interface_pairs: a policy spanning multiple srcintf/dstintf becomes
  N single-pair policies (FortiConverter's "Interface Pair View Split")

Every action reports what it changed. Order matters and is fixed in apply().
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

from ..model import FirewallConfig
from .optimize import _referenced_names


@dataclass
class TuningOptions:
    prune: bool = False
    merge_dupes: bool = False
    split_pairs: bool = False
    exclude: list[str] = field(default_factory=list)  # policy names to drop
    only: list[str] = field(default_factory=list)     # keep only these
    disable: list[str] = field(default_factory=list)  # policy names -> disabled
    reorder: list[tuple[str, str]] = field(default_factory=list)  # (move, before)

    def any(self) -> bool:
        return bool(self.prune or self.merge_dupes or self.split_pairs
                    or self.exclude or self.only or self.disable
                    or self.reorder)


def merge_duplicates(cfg: FirewallConfig, report) -> int:
    """Collapse addresses/services that share a definition under one name."""
    addr_canon: dict[tuple, str] = {}
    addr_rename: dict[str, str] = {}
    kept_addrs = []
    for a in cfg.addresses:
        key = (a.type, a.value)
        if key in addr_canon:
            addr_rename[a.name] = addr_canon[key]
        else:
            addr_canon[key] = a.name
            kept_addrs.append(a)

    svc_canon: dict[tuple, str] = {}
    svc_rename: dict[str, str] = {}
    kept_svcs = []
    for s in cfg.services:
        key = s.signature()
        if key in svc_canon:
            svc_rename[s.name] = svc_canon[key]
        else:
            svc_canon[key] = s.name
            kept_svcs.append(s)

    if not addr_rename and not svc_rename:
        return 0
    cfg.addresses[:] = kept_addrs
    cfg.services[:] = kept_svcs

    def remap(names, table):
        out, seen = [], set()
        for n in names:
            t = table.get(n, n)
            if t not in seen:
                seen.add(t)
                out.append(t)
        return out

    for grp in cfg.addr_groups:
        grp.members = remap(grp.members, addr_rename)
    for grp in cfg.svc_groups:
        grp.members = remap(grp.members, svc_rename)
    for pol in cfg.policies:
        pol.src_addrs = remap(pol.src_addrs, addr_rename)
        pol.dst_addrs = remap(pol.dst_addrs, addr_rename)
        pol.services = remap(pol.services, svc_rename)
    for nat in cfg.nats:
        nat.real_obj = addr_rename.get(nat.real_obj, nat.real_obj)

    n = len(addr_rename) + len(svc_rename)
    report.add("info", "tuning",
               f"merged {len(addr_rename)} duplicate address object(s) and "
               f"{len(svc_rename)} duplicate service object(s) into their "
               "canonical definitions; references rewritten")
    return n


def filter_policies(cfg: FirewallConfig, exclude: list[str],
                    only: list[str], report) -> int:
    if not exclude and not only:
        return 0
    excl = set(exclude)
    keep_only = set(only)
    # When BOTH flags are supplied, neither is silently dropped: restrict to
    # the --only set first, then remove --exclude names from that set. (Old
    # behaviour let --only win and silently ignored --exclude.)
    both = bool(keep_only and excl)
    if both:
        report.add("warn", "tuning",
                   "both --only and --exclude supplied; applying --only "
                   "first then --exclude (kept = only minus exclude)")
    kept, dropped = [], []
    for pol in cfg.policies:
        name = pol.name or ""
        if keep_only:
            drop = name not in keep_only or name in excl
        else:
            drop = name in excl
        (dropped if drop else kept).append(pol)
    cfg.policies[:] = kept
    if dropped:
        names = ", ".join(p.name for p in dropped[:12])
        report.add("info", "tuning",
                   f"rule filter dropped {len(dropped)} policy(ies): {names}"
                   + (" …" if len(dropped) > 12 else ""))
    if keep_only:
        missing = keep_only - {p.name for p in cfg.policies} - \
            {p.name for p in dropped}
        for m in sorted(missing):
            report.add("warn", "tuning",
                       f"--only named policy '{m}' which does not exist")
    if excl:
        # an --exclude name "exists" only if it was present in the config at
        # all (either dropped here, or — when --only also filtered it out —
        # already gone); flag names that matched no policy whatsoever
        present = {p.name or "" for p in cfg.policies} | \
            {p.name or "" for p in dropped}
        for m in sorted(excl - present):
            report.add("warn", "tuning",
                       f"--exclude named policy '{m}' which does not exist")
    return len(dropped)


def split_interface_pairs(cfg: FirewallConfig, report) -> int:
    """A policy with multiple src/dst interfaces -> one policy per pair."""
    from .names import POLICY_MAX
    new_policies = []
    split = 0
    used = {p.name for p in cfg.policies if p.name}
    for pol in cfg.policies:
        srcs = pol.src_zones or ["any"]
        dsts = pol.dst_zones or ["any"]
        if len(srcs) <= 1 and len(dsts) <= 1:
            new_policies.append(pol)
            continue
        split += 1
        n = 0
        for s in srcs:
            for d in dsts:
                n += 1
                base = pol.name or "policy"
                # this runs after name sanitization, so re-enforce the
                # 35-char policy-name limit (and keep names unique)
                suffix = f"-{n}"
                cand = base[:POLICY_MAX - len(suffix)] + suffix
                k = 0
                while cand in used:
                    k += 1
                    suffix = f"-{n}x{k}"
                    cand = base[:POLICY_MAX - len(suffix)] + suffix
                used.add(cand)
                new_policies.append(replace(
                    pol, name=cand, src_zones=[s], dst_zones=[d]))
    cfg.policies[:] = new_policies
    if split:
        report.add("info", "tuning",
                   f"interface-pair split expanded {split} multi-interface "
                   f"policy(ies) into single srcintf/dstintf pairs")
    return split


def disable_policies(cfg: FirewallConfig, names, report) -> int:
    """Force the named policies to disabled (e.g. dead/shadowed rules the user
    chose to deactivate rather than delete). Only ever SETS disabled — never
    re-enables a rule — so it can't broaden the policy set."""
    want = set(names)
    done = [p.name for p in cfg.policies
            if p.name in want and not p.disabled]
    for p in cfg.policies:
        if p.name in want:
            p.disabled = True
    if done:
        report.add("info", "tuning",
                   f"disabled {len(done)} rule(s) on request: "
                   + ", ".join(done))
    missing = sorted(want - {p.name for p in cfg.policies})
    if missing:
        report.add("info", "tuning",
                   "disable requested for rule(s) not found (no change): "
                   + ", ".join(missing))
    return len(done)


def reorder_policies(cfg: FirewallConfig, pairs, report) -> int:
    """Move each named policy to immediately before another — used to lift a
    shadowed DENY above the ACCEPT that bypasses it. Only reorders existing
    rules (no add/drop/modify), and only when the rule is currently BELOW its
    target (so it's idempotent: a no-op once already fixed)."""
    moved, missing = [], []
    for spec in pairs:
        if len(spec) != 2:
            continue
        move, before = spec
        i_move = next((i for i, p in enumerate(cfg.policies)
                       if p.name == move), None)
        i_before = next((i for i, p in enumerate(cfg.policies)
                         if p.name == before), None)
        if i_move is None or i_before is None:
            missing.append(f"'{move}' before '{before}'")
            continue
        if i_move <= i_before:
            continue  # already at/above the target (idempotent)
        pol = cfg.policies.pop(i_move)
        i_before = next(i for i, p in enumerate(cfg.policies)
                        if p.name == before)
        cfg.policies.insert(i_before, pol)
        moved.append(f"'{move}' above '{before}'")
    if moved:
        report.add("info", "tuning",
                   f"reordered {len(moved)} rule(s) to fix order: "
                   + "; ".join(moved))
    if missing:
        report.add("info", "tuning",
                   "reorder requested but rule(s) not found (no change): "
                   + "; ".join(missing))
    return len(moved)


def apply(cfg: FirewallConfig, opts: TuningOptions, report) -> dict:
    stats = {"merged": 0, "pruned": 0, "filtered": 0, "split": 0,
             "disabled": 0, "reordered": 0}
    if opts.merge_dupes:
        stats["merged"] = merge_duplicates(cfg, report)
    if opts.exclude or opts.only:
        stats["filtered"] = filter_policies(cfg, opts.exclude, opts.only,
                                            report)
    # split BEFORE disable/reorder: the Optimize tab scrapes its rule names
    # from the previous run's findings, which are post-split (e.g. 'Rule-1'),
    # so the policy list must already be split when we match those names
    if opts.split_pairs:
        stats["split"] = split_interface_pairs(cfg, report)
    if opts.disable:
        stats["disabled"] = disable_policies(cfg, opts.disable, report)
    if opts.reorder:
        stats["reordered"] = reorder_policies(cfg, opts.reorder, report)
    if opts.prune:
        stats["pruned"] = _prune(cfg, report)
    return stats


def _prune(cfg: FirewallConfig, report) -> int:
    """Iteratively drop unreferenced objects until the set is stable."""
    total = 0
    while True:
        addr_refs, svc_refs = _referenced_names(cfg)
        before = (len(cfg.addresses) + len(cfg.addr_groups)
                  + len(cfg.services) + len(cfg.svc_groups))
        cfg.addresses[:] = [a for a in cfg.addresses if a.name in addr_refs]
        cfg.addr_groups[:] = [g for g in cfg.addr_groups
                              if g.name in addr_refs]
        cfg.services[:] = [s for s in cfg.services if s.name in svc_refs]
        cfg.svc_groups[:] = [g for g in cfg.svc_groups if g.name in svc_refs]
        after = (len(cfg.addresses) + len(cfg.addr_groups)
                 + len(cfg.services) + len(cfg.svc_groups))
        total += before - after
        if before == after:
            break
    if total:
        report.add("info", "tuning",
                   f"pruned {total} unreferenced object(s) "
                   "(addresses/services/groups used by no policy)")
    return total
