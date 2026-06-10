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
from .transforms import names as names_tf
from .transforms import optimize, portmap, sdwan, tree_refs, versiondelta, zones
from .transforms import routes as routes_tf
from .transforms.plan import MigrationPlan


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


def run_cross(text: str, vendor: str, src_name: str,
              mapping: dict[str, str], target: str = "7.4"
              ) -> ConversionResult:
    report = Report()
    report.meta = {
        "tool": f"fwforge {__version__}",
        "source": src_name,
        "mode": "cross-vendor",
        "target": f"FortiOS {target}",
    }
    cfg: FirewallConfig = CROSS_PARSERS[vendor](text, src_name)
    report.absorb_parser_findings(cfg)
    report.meta["source_vendor"] = cfg.vendor
    report.meta["source_hostname"] = cfg.hostname

    unmapped = portmap.apply_ir(cfg, mapping, report)
    names_tf.apply(cfg, report)
    routes_tf.infer_dst_zones(cfg, report)
    optimize.analyze(cfg, report)
    out_text = fortios_emit.emit(cfg, report, target=target)

    result = ConversionResult(
        mode="cross", vendor=vendor, out_text=out_text, report=report,
        cfg=cfg, unmapped=unmapped)
    if unmapped:
        result.sample_portmap = portmap.sample_map(unmapped)
    result.exit_code = 1 if report.count("error") else 0
    return result


def run_migrate(text: str, src_name: str, plan: MigrationPlan,
                target: str = "7.4", source_os: str | None = None,
                target_platform: str | None = None,
                want_normalized: bool = False) -> ConversionResult:
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

    if target_platform:
        for child in tree.children:
            if isinstance(child, fortios_tree.CommentLine) \
                    and child.text.startswith("#config-version="):
                old = child.text[len("#config-version="):].split("-", 1)
                child.text = (f"#config-version={target_platform}"
                              + (f"-{old[1]}" if len(old) > 1 else ""))
                report.add(
                    "warn", "platform",
                    f"config-version platform rewritten {old[0]} -> "
                    f"{target_platform}. VERIFY this platform code against "
                    "a backup taken from the actual target device before "
                    "restoring — a mismatch makes the FortiGate reject the "
                    "file.")
                break

    if tree_refs.is_multi_vdom(tree):
        scopes = [n for n, _ in fortios_tree.vdom_scopes(tree)]
        report.meta["vdoms"] = ", ".join(s for s in scopes if s != "global")
        report.add("info", "vdom",
                   f"multi-VDOM config; scopes: {', '.join(scopes)}")

    # FortiOS version-jump artifact scan
    src_ver = (versiondelta.parse_version(source_os) if source_os
               else versiondelta.source_version_from_header(tree))
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
    elif tgt_ver < src_ver:
        report.add("warn", "upgrade",
                   f"target FortiOS {target} is OLDER than the source "
                   f"({src_ver[0]}.{src_ver[1]}) — downgrades are not "
                   "analyzed; new-syntax artifacts may be rejected")
    else:
        vstats = versiondelta.scan(tree, src_ver, tgt_ver, report)
        report.meta["fortios_versions"] = (
            f"{src_ver[0]}.{src_ver[1]} -> {tgt_ver[0]}.{tgt_ver[1]}")
        if tgt_ver > src_ver:
            report.meta["upgrade_artifacts"] = vstats["artifacts"]
            report.meta["upgrade_auto_fixed"] = vstats["auto_fixed"]

    result = ConversionResult(mode="migrate", vendor="fortios",
                              report=report)

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
