"""Engine entrypoints shared by the CLI and the web UI.

Both front ends call these two functions; neither carries conversion
logic of its own. PlanError propagates to the caller.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import __version__
from .emit import fortios as fortios_emit
from .model import FirewallConfig
from .parsers import CROSS_PARSERS, fortios_tree
from .report import Report
from .transforms import hwswitch
from .transforms import names as names_tf
from .transforms import optimize, portmap, sdwan, sslvpn, tree_refs
from .transforms import versiondelta, vdommode, zones
from .transforms import routes as routes_tf
from .transforms import tuning as tuning_tf
from .transforms.plan import MigrationPlan
from .transforms.tuning import TuningOptions


@dataclass
class ConversionResult:
    mode: str  # "cross" | "migrate"
    vendor: str
    out_text: str = ""
    report: Report | None = None
    cfg: FirewallConfig | None = None  # cross-vendor IR (post-transform)
    unmapped: list[str] = field(default_factory=list)
    sample_portmap: str | None = None
    normalized_source: str = ""  # migrate: source reformatted for diffing
    section_count: int = 0  # migrate
    exit_code: int = 0


def _cross_one(cfg: FirewallConfig, mapping, target, tuning, nat_mode,
               report) -> tuple[str, list[str]]:
    """Transforms + emit for one IR config; returns (text, unmapped)."""
    from dataclasses import replace as _dc_replace
    unmapped = portmap.apply_ir(cfg, mapping, report)
    renames = names_tf.apply(cfg, report)
    routes_tf.infer_dst_zones(cfg, report)
    if tuning and tuning.any():
        # exclude/only are given as SOURCE rule names; sanitization has
        # already renamed the policies, so translate the filters too
        local = _dc_replace(
            tuning,
            exclude=[renames.get(n, n) for n in tuning.exclude],
            only=[renames.get(n, n) for n in tuning.only])
        stats = tuning_tf.apply(cfg, local, report)
        report.meta["tuning"] = ", ".join(
            f"{k}:{v}" for k, v in stats.items() if v)
    optimize.analyze(cfg, report)
    out_text = fortios_emit.emit(cfg, report, target=target,
                                 nat_mode=nat_mode)
    return out_text, unmapped


def run_cross(text: str, vendor: str, src_name: str,
              mapping: dict[str, str], target: str = "7.4",
              tuning: TuningOptions | None = None,
              nat_mode: str = "policy",
              parser_opts: dict | None = None) -> ConversionResult:
    report = Report()
    report.meta = {
        "tool": f"fwforge {__version__}",
        "source": src_name,
        "mode": "cross-vendor",
        "target": f"FortiOS {target}",
    }
    if parser_opts:
        cfg: FirewallConfig = CROSS_PARSERS[vendor](text, src_name,
                                                    **parser_opts)
    else:
        cfg = CROSS_PARSERS[vendor](text, src_name)
    report.absorb_parser_findings(cfg)
    report.meta["source_vendor"] = cfg.vendor
    report.meta["source_hostname"] = cfg.hostname
    if nat_mode == "central":
        report.meta["nat_mode"] = "central NAT"

    vsys_cfgs = cfg.meta.pop("vsys_cfgs", None)
    if vsys_cfgs:
        return _run_cross_multi(vsys_cfgs, cfg, vendor, mapping, target,
                                tuning, nat_mode, report)

    out_text, unmapped = _cross_one(cfg, mapping, target, tuning,
                                    nat_mode, report)
    result = ConversionResult(
        mode="cross", vendor=vendor, out_text=out_text, report=report,
        cfg=cfg, unmapped=unmapped)
    if unmapped:
        result.sample_portmap = portmap.sample_map(unmapped)
    result.exit_code = 1 if report.count("error") else 0
    return result


def _vdom_names(vsys_cfgs, report) -> list[tuple[str, FirewallConfig]]:
    """Clamp scope names to valid FortiOS VDOM names (11 chars,
    letters/digits/_/-), uniquified."""
    import re
    out = []
    used: set[str] = set()
    for vname, vcfg in vsys_cfgs:
        nm = re.sub(r"[^A-Za-z0-9_-]", "-", vname)[:11] or "vd"
        base, k = nm, 2
        while nm in used:
            sfx = str(k)
            nm = base[:11 - len(sfx)] + sfx
            k += 1
        used.add(nm)
        if nm != vname:
            report.add("warn", "vsys",
                       f"scope '{vname}' becomes VDOM '{nm}' (FortiOS "
                       "VDOM names: 11 chars, letters/digits/_/-)")
        out.append((nm, vcfg))
    return out


def _run_cross_multi(vsys_cfgs, primary: FirewallConfig, vendor, mapping,
                     target, tuning, nat_mode,
                     report) -> ConversionResult:
    """Multi-vsys source -> one script with a VDOM block per vsys."""
    bodies: list[tuple[str, str]] = []
    all_unmapped: set[str] = set()
    vsys_cfgs = _vdom_names(vsys_cfgs, report)
    for vname, vcfg in vsys_cfgs:
        if vcfg is not primary:
            report.absorb_parser_findings(vcfg)
        text, unmapped = _cross_one(vcfg, mapping, target, tuning,
                                    nat_mode, report)
        # drop ONLY the emitter's leading #-comment header; a `#` inside a
        # later `set comment` value must survive (don't filter by line)
        lines = text.splitlines()
        h = 0
        while h < len(lines) and lines[h].startswith("#"):
            h += 1
        body = "\n".join(lines[h:]).strip("\n")
        bodies.append((vname, body))
        all_unmapped.update(unmapped)

    names = [v for v, _ in bodies]
    out: list[str] = [
        f"# fwforge converted config - source vendor: {primary.vendor}",
        f"# source hostname: {primary.hostname or '(unknown)'}"
        f" | target: FortiOS {target}",
        f"# multi-vsys source: one VDOM per vsys ({', '.join(names)})",
        "# review the companion report before applying",
        "",
        "# enable multi-VDOM on the target first:",
        "#   config system global / set vdom-mode multi-vdom / end",
        "",
        "config vdom",
    ]
    for v in names:
        out += [f"edit {v}", "next"]
    out += ["end", ""]
    for v, body in bodies:
        out += ["config vdom", f"edit {v}", body, "end", ""]
    report.add(
        "info", "vsys",
        f"{len(names)} vsys converted into VDOM blocks: "
        f"{', '.join(names)}. Interfaces are device-level — assign each "
        "to its VDOM (set vdom) per the interface mapping before "
        "pasting the VDOM blocks")
    report.meta["vsys_vdoms"] = ", ".join(names)

    result = ConversionResult(
        mode="cross", vendor=vendor, out_text="\n".join(out) + "\n",
        report=report, cfg=primary, unmapped=sorted(all_unmapped))
    if all_unmapped:
        result.sample_portmap = portmap.sample_map(sorted(all_unmapped))
    result.exit_code = 1 if report.count("error") else 0
    return result


def _apply_device_identity(tree, identity: dict) -> list[str]:
    """Carry a destination box's identity (hostname, alias, ...) onto the
    migrated config's `config system global`, replacing the source's
    values. Returns human-readable descriptions of what changed."""
    applied: list[str] = []
    for path, node in fortios_tree.iter_config_nodes(tree):
        if not fortios_tree.path_endswith(path, ("system", "global")):
            continue
        for attr, val in identity.items():
            existing = next(
                (ln for ln in node.children
                 if isinstance(ln, fortios_tree.SetLine)
                 and ln.attr == attr), None)
            if existing is not None:
                old = existing.values[0].value if existing.values else ""
                if old != val:
                    existing.values = [fortios_tree.Token(val, True)]
                    applied.append(f"{attr} '{old}' -> '{val}'")
            else:
                node.children.insert(
                    0, fortios_tree.SetLine(
                        attr, [fortios_tree.Token(val, True)]))
                applied.append(f"{attr} set '{val}'")
        return applied
    return applied


def run_migrate(text: str, src_name: str, plan: MigrationPlan,
                target: str | None = None, source_os: str | None = None,
                target_platform: str | None = None,
                want_normalized: bool = False, vdom_mode: str = "keep",
                vdom_name: str = "root", vdom_scope_only: bool = False,
                hw_switch: str = "keep", sslvpn_to_ipsec: bool = False,
                sslvpn_psk: str = "CHANGEME-SET-A-REAL-PSK",
                target_device: tuple | None = None,
                target_identity: dict | None = None
                ) -> ConversionResult:
    """FortiOS -> FortiOS lossless tree migration. Raises PlanError."""
    report = Report()
    report.meta = {
        "tool": f"fwforge {__version__}",
        "source": src_name,
        "mode": "fortios-migrate (lossless tree)",
    }
    tree = fortios_tree.parse_config(text, src_name)
    for w in tree.warnings:
        report.add("warn", "parse", w)

    # VDOM-mode conversion runs first so every downstream transform and the
    # version scan see the target structure
    if vdom_mode in ("multi", "single"):
        vstats = vdommode.apply(tree, vdom_mode, report, vdom_name,
                                vdom_scope_only)
        if vstats.get("converted"):
            report.meta["vdom_mode"] = (
                f"-> {'multi' if vdom_mode == 'multi' else 'single'}-VDOM"
                + (f" (VDOM '{vstats.get('vdom_name', vdom_name)}')"
                   if vdom_mode == 'multi' else ""))

    if plan.vdommap:
        rstats = vdommode.rename_vdoms(tree, plan.vdommap, report)
        if rstats["edits"]:
            report.meta["vdoms_renamed"] = ", ".join(
                f"{s}->{d}" for s, d in plan.vdommap.items() if s != d)

    if hw_switch == "convert":
        hstats = hwswitch.convert(tree, report)
        if hstats["converted"]:
            report.meta["hw_switch_converted"] = hstats["converted"]

    if sslvpn_to_ipsec:
        sstats = sslvpn.convert(tree, report, psk=sslvpn_psk)
        if sstats["tunnels"]:
            report.meta["sslvpn_tunnels"] = sstats["tunnels"]

    if target_platform:
        for child in tree.children:
            if isinstance(child, fortios_tree.CommentLine) \
                    and child.text.startswith("#config-version="):
                old = child.text[len("#config-version="):].split("-", 1)
                child.text = (f"#config-version={target_platform}"
                              + (f"-{old[1]}" if len(old) > 1 else ""))
                if target_device and target_device[0] == target_platform:
                    report.add(
                        "info", "platform",
                        f"config-version platform rewritten {old[0]} -> "
                        f"{target_platform} (read from the destination "
                        "backup — authoritative)")
                else:
                    report.add(
                        "warn", "platform",
                        f"config-version platform rewritten {old[0]} -> "
                        f"{target_platform}. VERIFY this platform code "
                        "against a backup taken from the actual target "
                        "device before restoring — a mismatch makes the "
                        "FortiGate reject the file.")
                break

    if tree_refs.is_multi_vdom(tree):
        scopes = [n for n, _ in fortios_tree.vdom_scopes(tree)]
        report.meta["vdoms"] = ", ".join(s for s in scopes if s != "global")
        report.add("info", "vdom",
                   f"multi-VDOM config; scopes: {', '.join(scopes)}")

    # FortiOS version-jump artifact scan
    hdr_ver = versiondelta.source_version_from_header(tree)
    src_ver = (versiondelta.parse_version(source_os) if source_os
               else hdr_ver)
    # a train-only override of the header's own train keeps the header's
    # patch — the GUI pre-fills '7.6' while the header knows '7.6.6'
    if (src_ver is not None and len(src_ver) < 3 and hdr_ver
            and hdr_ver[:2] == src_ver):
        src_ver = hdr_ver
    if target is None:
        # FGT->FGT default: target the source's own version — plain
        # re-platforming must not run a version delta unless asked
        tgt_ver = src_ver
        target = versiondelta.vlabel(src_ver) if src_ver else ""
    else:
        tgt_ver = versiondelta.parse_version(target)
    if src_ver is None:
        report.add("info", "upgrade",
                   "source FortiOS version not detected in the config "
                   "header — upgrade-artifact scan skipped (pass "
                   "--source-os X.Y)")
    elif tgt_ver is None:
        report.add("info", "upgrade",
                   f"target version '{target}' not understood — "
                   "upgrade-artifact scan skipped")
    else:
        vstats = versiondelta.scan(tree, src_ver, tgt_ver, report)
        # cross-train moves label by train; within-train moves show the
        # patch detail that makes them a move at all
        if src_ver[:2] == tgt_ver[:2] and vstats["direction"] != "none":
            label = (f"{versiondelta.vlabel(src_ver)} -> "
                     f"{versiondelta.vlabel(tgt_ver)}")
        else:
            label = (f"{src_ver[0]}.{src_ver[1]} -> "
                     f"{tgt_ver[0]}.{tgt_ver[1]}")
        report.meta["fortios_versions"] = label
        if vstats["direction"] == "up":
            report.meta["upgrade_artifacts"] = vstats["artifacts"]
            report.meta["upgrade_auto_fixed"] = vstats["auto_fixed"]
        elif vstats["direction"] == "down":
            report.meta["downgrade_artifacts"] = vstats["artifacts"]
            report.meta["downgrade_auto_fixed"] = vstats["auto_fixed"]

    result = ConversionResult(mode="migrate", vendor="fortios",
                              report=report)

    if target_device:
        # (code, version, physical ports) read from a backup of the
        # actual destination box — validate that every physical source
        # interface ends up with a name that exists there
        t_code, t_ver, t_ports = target_device
        report.meta["target_device"] = (
            f"{t_code} (FortiOS {t_ver}, {len(t_ports)} physical ports)")
        src_phys = [
            d["name"] for d in portmap.tree_interface_details(tree)
            if d["type"] == "physical" and "." not in d["name"]
            and d["name"] != "modem"]
        missing = sorted(
            {plan.portmap.get(n, n) for n in src_phys} - set(t_ports))
        if missing:
            report.add(
                "warn", "portmap",
                f"{len(missing)} interface name(s) in the output do "
                f"not exist on the destination ({t_code}): "
                f"{', '.join(missing)} — the restore drops them and "
                "everything referencing them; map each to one of the "
                "destination's ports")
        report.add(
            "info", "portmap",
            f"destination ports ({t_code}): {', '.join(t_ports)}")

    if target_identity:
        applied = _apply_device_identity(tree, target_identity)
        if applied:
            report.meta["identity_from_destination"] = "; ".join(applied)
            report.add(
                "info", "identity",
                "carried device identity from the destination backup so "
                f"the output is the destination's config: {'; '.join(applied)}")

    if plan.portmap:
        stats = portmap.apply_tree(tree, plan.portmap)
        report.meta["interface_renames"] = stats["edits"]
        report.meta["reference_rewrites"] = stats["values"]
        for attr, n in sorted(stats["by_attr"].items()):
            report.add("info", "portmap",
                       f"rewrote {n} reference(s) in 'set {attr}'")
        portmap.leftover_scan(tree, plan.portmap, report)
    elif not (plan.zones or plan.sdwan):
        result.sample_portmap = portmap.sample_map(
            portmap.tree_interface_names(tree))
        report.add(
            "warn", "portmap",
            "no --map/--plan given: config normalized but interfaces "
            "unchanged; a sample portmap file was written",
        )

    if plan.zones or plan.sdwan:
        moved: set[str] = set()
        moved_sdwan: set[str] = set()
        if plan.zones:
            zstats = zones.apply_zones(tree, plan.zones, report)
            report.meta["zones_created"] = zstats["zones"]
            if zstats.get("addresses_rebound"):
                report.meta["addresses_rebound"] = \
                    zstats["addresses_rebound"]
            moved |= set(zstats["mapping"])
        if plan.sdwan:
            sstats = sdwan.apply_sdwan(tree, plan.sdwan, report)
            report.meta["sdwan_members_added"] = sstats["members_added"]
            report.meta["default_routes_converted"] = \
                sstats["routes_converted"]
            moved_sdwan = set(sstats["mapping"])
        merged = tree_refs.dedup_policies(tree, report)
        if merged:
            report.meta["policies_merged"] = merged
        tree_refs.flag_conflicting_policies(tree, report)
        if plan.zones:
            tree_refs.audit_leftovers(
                tree, moved,
                tree_refs.BASE_ALLOWED | tree_refs.ZONE_EXTRA_ALLOWED,
                report, "zones")
        if plan.sdwan:
            tree_refs.audit_leftovers(
                tree, moved_sdwan,
                tree_refs.BASE_ALLOWED | tree_refs.SDWAN_EXTRA_ALLOWED,
                report, "sdwan")

    result.out_text = fortios_tree.serialize(tree)
    result.section_count = len(fortios_tree.section_inventory(tree))
    if want_normalized:
        result.normalized_source = fortios_tree.serialize(
            fortios_tree.parse_config(text))
    result.exit_code = 1 if report.count("error") else 0
    return result
