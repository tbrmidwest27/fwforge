"""fwforge command line.

    fwforge detect  <config>
    fwforge inspect <config>
    fwforge convert <config> [-o outdir] [--vendor auto] [--fortios 7.4]
                              [--map portmap] [--plan planfile]
                              [--mode auto|cross|migrate]
                              [--source-os X.Y] [--target-platform FG7H1G]
    fwforge plan    <config>  [-o file]
    fwforge gui     [--host 127.0.0.1] [--port 4848] [--no-browser]

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

from . import __version__, pipeline
from .emit import package
from .parsers import CROSS_PARSERS, detect_vendor
from .parsers import fortios_tree
from .report import Report
from .transforms import portmap
from .transforms.plan import MigrationPlan, PlanError, load_plan, scaffold
from .transforms.tuning import TuningOptions


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


def _load_migration_plan(args) -> MigrationPlan:
    plan = load_plan(args.plan) if args.plan else MigrationPlan()
    if args.map:
        plan.portmap.update(portmap.load_map(args.map))
        plan.translate_members()
    return plan


def _tuning_from_args(args) -> TuningOptions:
    return TuningOptions(
        prune=getattr(args, "prune", False),
        merge_dupes=getattr(args, "merge_dupes", False),
        split_pairs=getattr(args, "split_interface_pairs", False),
        exclude=[s for s in (getattr(args, "exclude", "") or "").split(",")
                 if s.strip()],
        only=[s for s in (getattr(args, "only", "") or "").split(",")
              if s.strip()],
    )


def _convert_cross(text: str, src_path: str, args, outdir: Path,
                   vendor: str) -> int:
    mapping = portmap.load_map(args.map) if args.map else {}
    result = pipeline.run_cross(text, vendor, src_path, mapping,
                                target=args.fortios,
                                tuning=_tuning_from_args(args))
    report, cfg = result.report, result.cfg

    stem = Path(src_path).stem
    base = outdir / stem
    pkg = package.write_split(outdir, stem, result.out_text, report)
    (base.with_suffix(".report.md")).write_text(
        report.to_markdown(cfg, text), encoding="utf-8")
    (base.with_suffix(".report.json")).write_text(
        report.to_json(cfg), encoding="utf-8")
    if result.sample_portmap:
        (base.with_suffix(".portmap")).write_text(
            result.sample_portmap, encoding="utf-8")

    errors, warns = report.count("error"), report.count("warn")
    print(f"wrote {pkg['config_all']} "
          f"(+ {pkg['branch_count']} branch files in {pkg['branch_dir']})")
    print(f"policies: {len(cfg.policies)}  addresses: {len(cfg.addresses)}  "
          f"services: {len(cfg.services)}  vips: {len(cfg.vips)}")
    print(f"report: {errors} errors, {warns} warnings, "
          f"{len(cfg.unparsed)} unconverted lines "
          f"-> {base.with_suffix('.report.md')}")
    if result.unmapped:
        print(f"ACTION: fill in {base.with_suffix('.portmap')} and re-run "
              f"with --map")
    return result.exit_code


def _convert_migrate(text: str, src_path: str, args, outdir: Path) -> int:
    try:
        plan = _load_migration_plan(args)
        result = pipeline.run_migrate(
            text, src_path, plan, target=args.fortios,
            source_os=getattr(args, "source_os", None),
            target_platform=getattr(args, "target_platform", None),
            vdom_mode=getattr(args, "vdom_mode", "keep"),
            vdom_name=getattr(args, "vdom_name", "root"),
            vdom_scope_only=getattr(args, "vdom_scope_only", False),
            hw_switch=getattr(args, "hw_switch", "keep"),
            sslvpn_to_ipsec=getattr(args, "sslvpn_to_ipsec", False),
            sslvpn_psk=getattr(args, "sslvpn_psk", None)
            or "CHANGEME-SET-A-REAL-PSK")
    except PlanError as e:
        print(f"plan error: {e}", file=sys.stderr)
        return 2
    report = result.report

    stem = Path(src_path).stem
    base = outdir / stem
    pkg = package.write_full(outdir, stem, result.out_text, report)
    (base.with_suffix(".report.md")).write_text(
        report.to_markdown(), encoding="utf-8")
    (base.with_suffix(".report.json")).write_text(
        report.to_json(), encoding="utf-8")
    if result.sample_portmap:
        (outdir / (stem + ".portmap")).write_text(
            result.sample_portmap, encoding="utf-8")

    print(f"wrote {pkg['main']} "
          f"(full restorable config, {result.section_count} sections)")
    if plan.portmap:
        print(f"interface renames: {report.meta.get('interface_renames', 0)} "
              f"edits, {report.meta.get('reference_rewrites', 0)} "
              "references rewritten")
    for key in ("vdom_mode", "hw_switch_converted", "sslvpn_tunnels",
                "zones_created", "sdwan_members_added",
                "default_routes_converted", "policies_merged",
                "fortios_versions", "upgrade_artifacts",
                "upgrade_auto_fixed"):
        if key in report.meta:
            print(f"{key.replace('_', ' ')}: {report.meta[key]}")
    errors, warns = report.count("error"), report.count("warn")
    print(f"report: {errors} errors, {warns} warnings "
          f"-> {base.with_suffix('.report.md')}")
    return result.exit_code


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
        if _tuning_from_args(args).any():
            print("note: tuning options apply to cross-vendor conversions "
                  "only (not FortiOS migration) — ignored", file=sys.stderr)
        return _convert_migrate(text, args.config, args, outdir)
    if vendor in CROSS_PARSERS:
        return _convert_cross(text, args.config, args, outdir, vendor)
    print(f"no cross-vendor parser for '{vendor}' yet", file=sys.stderr)
    return 2


def cmd_gui(args) -> int:
    try:
        from .webui.app import create_app
    except ImportError:
        print("Flask is required for the GUI — install it with:\n"
              "    python -m pip install flask", file=sys.stderr)
        return 2
    app = create_app()
    url = f"http://{args.host}:{args.port}/"
    if not args.no_browser:
        import threading
        import webbrowser
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    print(f"fwforge GUI on {url} (Ctrl+C to stop)")
    app.run(host=args.host, port=args.port, debug=False)
    return 0


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
    p.add_argument("--source-os",
                   help="source FortiOS version override (normally read "
                        "from the #config-version header)")
    p.add_argument("--map", help="interface map file (source = target)")
    p.add_argument("--plan",
                   help="migration plan file ([portmap] / [zone x] / "
                        "[sdwan x] sections); see 'fwforge plan'")
    p.add_argument("--target-platform",
                   help="rewrite the #config-version platform code for the "
                        "target model (e.g. FG7H1G) so the device accepts "
                        "the restore")
    p.add_argument("--vdom-mode", default="keep",
                   choices=["keep", "multi", "single"],
                   help="convert VDOM mode: 'multi' wraps a flat config "
                        "into config global + config vdom; 'single' "
                        "flattens a one-VDOM config (FortiOS migration)")
    p.add_argument("--vdom-name", default="root",
                   help="VDOM name to wrap into with --vdom-mode multi "
                        "(default root)")
    p.add_argument("--vdom-scope-only", action="store_true",
                   help="with --vdom-mode multi, drop global-scope sections "
                        "so the output loads into an existing VDOM without "
                        "overwriting the box's global config")
    p.add_argument("--hw-switch", default="keep",
                   choices=["keep", "convert"],
                   help="'convert' rewrites hardware-switch interfaces as "
                        "software switches (for targets without the same "
                        "switch fabric)")
    p.add_argument("--sslvpn-to-ipsec", action="store_true",
                   help="convert SSL-VPN tunnel mode into an IKEv2 dial-up "
                        "IPsec scaffold (SSL-VPN tunnel mode is gone in "
                        "FortiOS 7.6+)")
    p.add_argument("--sslvpn-psk",
                   help="PSK for the generated IPsec dial-up tunnel "
                        "(default: a CHANGEME placeholder)")
    p.add_argument("--mode", default="auto",
                   choices=["auto", "cross", "migrate"])
    tune = p.add_argument_group("tuning (cross-vendor conversions)")
    tune.add_argument("--prune", action="store_true",
                      help="drop address/service objects nothing references")
    tune.add_argument("--merge-dupes", action="store_true",
                      help="collapse duplicate objects to one name")
    tune.add_argument("--split-interface-pairs", action="store_true",
                      help="split multi-interface policies into single "
                           "srcintf/dstintf pairs")
    tune.add_argument("--exclude", default="",
                      help="comma-separated policy names to drop")
    tune.add_argument("--only", default="",
                      help="comma-separated policy names to keep (drop rest)")
    p.set_defaults(fn=cmd_convert)

    p = sub.add_parser(
        "plan", help="generate a starter migration plan from a config")
    p.add_argument("config")
    p.add_argument("-o", "--out", help="output file (default <config>.plan)")
    p.set_defaults(fn=cmd_plan)

    p = sub.add_parser("gui", help="run the local web UI")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=4848)
    p.add_argument("--no-browser", action="store_true")
    p.set_defaults(fn=cmd_gui)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
