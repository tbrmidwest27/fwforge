"""fwforge command line.

    fwforge detect  <config>
    fwforge inspect <config>
    fwforge convert <config> [-o outdir] [--vendor auto] [--fortios 7.4]
                              [--map portmap] [--mode auto|cross|migrate]

convert writes:
    <name>.fos.conf      paste-able FortiOS CLI script
    <name>.report.md     human conversion report
    <name>.report.json   machine-readable report (full provenance)
    <name>.portmap       sample interface map (when names are unmapped)

Exit codes: 0 clean, 1 finished with errors in the report, 2 fatal.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .emit import fortios as fortios_emit
from .model import FirewallConfig
from .parsers import CROSS_PARSERS, detect_vendor
from .parsers import fortios_tree
from .report import Report
from .transforms import names as names_tf
from .transforms import optimize, portmap, sdwan, tree_refs, zones
from .transforms import routes as routes_tf
from .transforms.plan import MigrationPlan, PlanError, load_plan, scaffold


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def cmd_detect(args) -> int:
    vendor, conf = detect_vendor(_read(args.config))
    print(f"{vendor} (confidence {conf:.0%})")
    return 0 if vendor != "unknown" else 1


def cmd_inspect(args) -> int:
    text = _read(args.config)
    vendor, _ = detect_vendor(text)
    if vendor == "fortios":
        tree = fortios_tree.parse_config(text, args.config)
        print("fortios config - top-level sections:")
        for section, n in fortios_tree.section_inventory(tree).items():
            print(f"  {section:<40} {n}")
        ifaces = portmap.tree_interface_names(tree)
        print(f"\ninterfaces ({len(ifaces)}): {', '.join(ifaces)}")
        for w in tree.warnings:
            print(f"  parse warning: {w}")
        return 0
    if vendor in CROSS_PARSERS:
        cfg = CROSS_PARSERS[vendor](text, args.config)
        rep = Report()
        rep.absorb_parser_findings(cfg)
        for k, v in rep.summary_counts(cfg).items():
            print(f"  {k:<16} {v}")
        return 0
    print("unknown source vendor", file=sys.stderr)
    return 2


def _convert_cross(text: str, src_path: str, args, outdir: Path,
                   vendor: str) -> int:
    report = Report()
    report.meta = {
        "tool": f"fwforge {__version__}",
        "source": src_path,
        "mode": "cross-vendor",
        "target": f"FortiOS {args.fortios}",
    }
    cfg: FirewallConfig = CROSS_PARSERS[vendor](text, src_path)
    report.absorb_parser_findings(cfg)
    report.meta["source_vendor"] = cfg.vendor
    report.meta["source_hostname"] = cfg.hostname

    mapping = portmap.load_map(args.map) if args.map else {}
    unmapped = portmap.apply_ir(cfg, mapping, report)
    names_tf.apply(cfg, report)
    routes_tf.infer_dst_zones(cfg, report)
    optimize.analyze(cfg, report)
    out_text = fortios_emit.emit(cfg, report, target=args.fortios)

    base = outdir / (Path(src_path).stem)
    (base.with_suffix(".fos.conf")).write_text(out_text, encoding="utf-8")
    (base.with_suffix(".report.md")).write_text(
        report.to_markdown(cfg, text), encoding="utf-8")
    (base.with_suffix(".report.json")).write_text(
        report.to_json(cfg), encoding="utf-8")
    if unmapped:
        (base.with_suffix(".portmap")).write_text(
            portmap.sample_map(unmapped), encoding="utf-8")

    errors, warns = report.count("error"), report.count("warn")
    print(f"wrote {base.with_suffix('.fos.conf')}")
    print(f"policies: {len(cfg.policies)}  addresses: {len(cfg.addresses)}  "
          f"services: {len(cfg.services)}  vips: {len(cfg.vips)}")
    print(f"report: {errors} errors, {warns} warnings, "
          f"{len(cfg.unparsed)} unconverted lines "
          f"-> {base.with_suffix('.report.md')}")
    if unmapped:
        print(f"ACTION: fill in {base.with_suffix('.portmap')} and re-run "
              f"with --map")
    return 1 if errors else 0


def _load_migration_plan(args) -> MigrationPlan:
    plan = load_plan(args.plan) if args.plan else MigrationPlan()
    if args.map:
        plan.portmap.update(portmap.load_map(args.map))
        plan.translate_members()
    return plan


def _convert_migrate(text: str, src_path: str, args, outdir: Path) -> int:
    report = Report()
    report.meta = {
        "tool": f"fwforge {__version__}",
        "source": src_path,
        "mode": "fortios-migrate (lossless tree)",
    }
    tree = fortios_tree.parse_config(text, src_path)
    for w in tree.warnings:
        report.add("warn", "parse", w)

    try:
        plan = _load_migration_plan(args)
    except PlanError as e:
        print(f"plan error: {e}", file=sys.stderr)
        return 2

    if getattr(args, "target_platform", None):
        for child in tree.children:
            if isinstance(child, fortios_tree.CommentLine) \
                    and child.text.startswith("#config-version="):
                old = child.text[len("#config-version="):].split("-", 1)
                child.text = (f"#config-version={args.target_platform}"
                              + (f"-{old[1]}" if len(old) > 1 else ""))
                report.add(
                    "warn", "platform",
                    f"config-version platform rewritten {old[0]} -> "
                    f"{args.target_platform}. VERIFY this platform code "
                    "against a backup taken from the actual target device "
                    "before restoring — a mismatch makes the FortiGate "
                    "reject the file.")
                break

    if plan.portmap:
        stats = portmap.apply_tree(tree, plan.portmap)
        report.meta["interface_renames"] = stats["edits"]
        report.meta["reference_rewrites"] = stats["values"]
        for attr, n in sorted(stats["by_attr"].items()):
            report.add("info", "portmap", f"rewrote {n} reference(s) in "
                                          f"'set {attr}'")
        portmap.leftover_scan(tree, plan.portmap, report)
    elif not (plan.zones or plan.sdwan):
        sample = portmap.sample_map(portmap.tree_interface_names(tree))
        (outdir / (Path(src_path).stem + ".portmap")).write_text(
            sample, encoding="utf-8")
        report.add(
            "warn", "portmap",
            "no --map/--plan given: config normalized but interfaces "
            "unchanged; a sample portmap file was written",
        )

    if tree_refs.is_multi_vdom(tree):
        scopes = [n for n, _ in fortios_tree.vdom_scopes(tree)]
        report.meta["vdoms"] = ", ".join(s for s in scopes if s != "global")
        report.add("info", "vdom",
                   f"multi-VDOM config; scopes: {', '.join(scopes)}")

    if plan.zones or plan.sdwan:
        moved: set[str] = set()
        try:
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
        except PlanError as e:
            print(f"plan error: {e}", file=sys.stderr)
            return 2
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

    out_text = fortios_tree.serialize(tree)
    base = outdir / (Path(src_path).stem)
    (base.with_suffix(".fos.conf")).write_text(out_text, encoding="utf-8")
    (base.with_suffix(".report.md")).write_text(
        report.to_markdown(), encoding="utf-8")
    (base.with_suffix(".report.json")).write_text(
        report.to_json(), encoding="utf-8")

    inv = fortios_tree.section_inventory(tree)
    print(f"wrote {base.with_suffix('.fos.conf')} "
          f"({len(inv)} sections preserved)")
    if plan.portmap:
        print(f"interface renames: {report.meta.get('interface_renames', 0)} "
              f"edits, {report.meta.get('reference_rewrites', 0)} "
              "references rewritten")
    for key in ("zones_created", "sdwan_members_added",
                "default_routes_converted", "policies_merged"):
        if key in report.meta:
            print(f"{key.replace('_', ' ')}: {report.meta[key]}")
    errors, warns = report.count("error"), report.count("warn")
    print(f"report: {errors} errors, {warns} warnings "
          f"-> {base.with_suffix('.report.md')}")
    return 1 if errors else 0


def cmd_plan(args) -> int:
    text = _read(args.config)
    vendor, _ = detect_vendor(text)
    if vendor != "fortios":
        print("'fwforge plan' needs a FortiOS source config",
              file=sys.stderr)
        return 2
    tree = fortios_tree.parse_config(text, args.config)
    interfaces = portmap.tree_interface_names(tree)
    out = Path(args.out) if args.out else Path(args.config).with_suffix(".plan")
    out.write_text(scaffold(interfaces, Path(args.config).name),
                   encoding="utf-8")
    print(f"wrote {out} ({len(interfaces)} interfaces) - edit it, then run "
          f"convert --plan {out}")
    return 0


def cmd_convert(args) -> int:
    text = _read(args.config)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    vendor = args.vendor
    if vendor == "auto":
        vendor, conf = detect_vendor(text)
        if vendor == "unknown":
            print("could not detect source vendor — use --vendor",
                  file=sys.stderr)
            return 2
        print(f"detected source: {vendor} ({conf:.0%})")

    mode = args.mode
    if mode == "auto":
        mode = "migrate" if vendor == "fortios" else "cross"

    if mode == "migrate":
        if vendor != "fortios":
            print("--mode migrate requires a FortiOS source", file=sys.stderr)
            return 2
        return _convert_migrate(text, args.config, args, outdir)
    if vendor in CROSS_PARSERS:
        return _convert_cross(text, args.config, args, outdir, vendor)
    print(f"no cross-vendor parser for '{vendor}' yet", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="fwforge",
        description="Open firewall config converter -> FortiOS",
    )
    ap.add_argument("--version", action="version",
                    version=f"fwforge {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("detect", help="identify the source vendor")
    p.add_argument("config")
    p.set_defaults(fn=cmd_detect)

    p = sub.add_parser("inspect", help="parse and summarize a config")
    p.add_argument("config")
    p.set_defaults(fn=cmd_inspect)

    p = sub.add_parser("convert", help="convert a config to FortiOS CLI")
    p.add_argument("config")
    p.add_argument("-o", "--outdir", default="out")
    p.add_argument("--vendor", default="auto",
                   choices=["auto", "cisco-asa", "paloalto", "fortios"])
    p.add_argument("--fortios", default="7.4",
                   help="target FortiOS version (default 7.4)")
    p.add_argument("--map", help="interface map file (source = target)")
    p.add_argument("--plan",
                   help="migration plan file ([portmap] / [zone x] / "
                        "[sdwan x] sections); see 'fwforge plan'")
    p.add_argument("--target-platform",
                   help="rewrite the #config-version platform code for the "
                        "target model (e.g. FG7H1G) so the device accepts "
                        "the restore")
    p.add_argument("--mode", default="auto",
                   choices=["auto", "cross", "migrate"])
    p.set_defaults(fn=cmd_convert)

    p = sub.add_parser(
        "plan", help="generate a starter migration plan from a config")
    p.add_argument("config")
    p.add_argument("-o", "--out", help="output file (default <config>.plan)")
    p.set_defaults(fn=cmd_plan)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
