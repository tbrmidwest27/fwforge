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
import os
import sys
from pathlib import Path

from . import __version__, pipeline
from . import schema as schema_mod
from .emit import fortimanager, package
from .parsers import CROSS_PARSERS, detect_vendor
from .parsers import fortios_tree
from .parsers.paloalto import PanoramaChoiceNeeded
from .report import Report
from .transforms import portmap
from .transforms.plan import MigrationPlan, PlanError, load_plan, scaffold
from .transforms.tuning import TuningOptions


def _read(path: str) -> str:
    # utf-8-sig: tolerate the BOM Windows editors prepend — it would
    # otherwise break the line-anchored vendor-detection patterns
    return Path(path).read_text(encoding="utf-8-sig", errors="replace")


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
    # translate members once, over the fully merged map — translating in
    # load_plan AND after the --map merge double-applies chained renames
    plan = load_plan(args.plan, translate=False) if args.plan \
        else MigrationPlan()
    if args.map:
        plan.portmap.update(portmap.load_map(args.map))
    plan.translate_members()
    if getattr(args, "vdom_map", None):
        for pair in args.vdom_map.split(","):
            if "=" in pair:
                s, d = pair.split("=", 1)
                plan.vdommap[s.strip()] = d.strip()
    return plan


def _schema_check(args, out_text: str, report) -> None:
    """Opt-in: validate the emitted CLI against a target-build schema."""
    ref = getattr(args, "schema_check", None)
    if not ref:
        return
    try:
        schema, fetched = schema_mod.resolve(
            ref, getattr(args, "schema_token", ""))
        if fetched:
            print(f"schema fetched from {ref} "
                  f"(FortiOS {schema['version']} build{schema['build']}) "
                  f"-> cached at {schema_mod.cache_path(schema)}")
        schema_mod.check(out_text, schema, report,
                         target=getattr(args, "fortios", ""))
    except Exception as e:
        report.add("error", "schema",
                   f"schema check failed ({e}) — output written "
                   "unvalidated")


def cmd_schema(args) -> int:
    if args.list or not args.host:
        cached = schema_mod.list_cached()
        if not cached:
            print("no cached schemas — fetch one with: "
                  "fwforge schema <host> --token <api-key>")
            return 0
        for s in cached:
            print(f"{s['name']}: FortiOS {s['version']} "
                  f"build{s['build']}, {s['tables']} tables, fetched "
                  f"{s['fetched']} from {s['host']}")
        return 0
    if not args.token:
        print("an API token is required (--token or FWFORGE_API_TOKEN)",
              file=sys.stderr)
        return 2
    try:
        schema, _ = schema_mod.resolve(args.host, args.token)
    except Exception as e:
        print(f"schema fetch failed: {e}", file=sys.stderr)
        return 2
    print(f"fetched FortiOS {schema['version']} build{schema['build']} "
          f"({len(schema['tables'])} tables) -> "
          f"{schema_mod.cache_path(schema)}")
    return 0


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
    parser_opts: dict = {}
    if vendor == "paloalto":
        for attr, key in (("pa_vsys", "vsys"),
                          ("pa_device_group", "device_group"),
                          ("pa_template", "template")):
            v = getattr(args, attr, None)
            if v:
                parser_opts[key] = v
    try:
        result = pipeline.run_cross(
            text, vendor, src_path, mapping,
            target=args.fortios,
            tuning=_tuning_from_args(args),
            nat_mode=getattr(args, "nat_mode", "policy"),
            parser_opts=parser_opts or None)
    except PanoramaChoiceNeeded as e:
        print("this is a Panorama export — pick a device-group with "
              "--pa-device-group:", file=sys.stderr)
        for dg in e.device_groups:
            print(f"  --pa-device-group {dg}", file=sys.stderr)
        if e.templates:
            print("optionally add network config from a template:",
                  file=sys.stderr)
            for t in e.templates:
                print(f"  --pa-template {t}", file=sys.stderr)
        return 2
    report, cfg = result.report, result.cfg
    _schema_check(args, result.out_text, report)

    # NOTE: outdir/(stem + ext), never base.with_suffix(ext) — with_suffix
    # truncates dotted stems ('fw.example.com-backup' -> 'fw.example')
    stem = Path(src_path).stem
    fmg_path = None
    if getattr(args, "fmg", None):
        adom, _, fmg_pkg = args.fmg.partition("/")
        try:
            bundle = fortimanager.build_bundle(
                cfg, report, adom=adom.strip() or "root",
                package=fmg_pkg.strip() or f"{stem}-converted",
                nat_mode=getattr(args, "nat_mode", "policy"))
            fmg_path = outdir / (stem + ".fmg.json")
            fmg_path.write_text(fortimanager.render(bundle),
                                encoding="utf-8")
        except Exception as e:  # a bundle failure must not sink the run
            report.add("error", "fortimanager",
                       f"FortiManager bundle failed ({e}) — CLI script and "
                       "reports written without it")
    pkg = package.write_split(outdir, stem, result.out_text, report)
    report_md = outdir / (stem + ".report.md")
    report_md.write_text(report.to_markdown(cfg, text), encoding="utf-8")
    (outdir / (stem + ".report.json")).write_text(
        report.to_json(cfg), encoding="utf-8")
    (outdir / (stem + ".report.html")).write_text(
        report.to_html(cfg, text), encoding="utf-8")
    portmap_path = outdir / (stem + ".portmap")
    if result.sample_portmap:
        portmap_path.write_text(result.sample_portmap, encoding="utf-8")

    errors, warns = report.count("error"), report.count("warn")
    print(f"wrote {pkg['config_all']} "
          f"(+ {pkg['branch_count']} branch files in {pkg['branch_dir']})")
    if fmg_path:
        print(f"wrote {fmg_path} (FortiManager JSON-RPC import bundle)")
    print(f"policies: {len(cfg.policies)}  addresses: {len(cfg.addresses)}  "
          f"services: {len(cfg.services)}  vips: {len(cfg.vips)}")
    print(f"report: {errors} errors, {warns} warnings, "
          f"{len(cfg.unparsed)} unconverted lines "
          f"-> {report_md}")
    if result.unmapped:
        print(f"ACTION: fill in {portmap_path} and re-run with --map")
    # the schema check may add error findings after the pipeline set
    # its exit code
    return max(result.exit_code, 1 if report.count("error") else 0)


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
    _schema_check(args, result.out_text, report)

    stem = Path(src_path).stem
    try:
        clobber = (outdir / f"{stem}.conf").resolve() \
            == Path(src_path).resolve()
    except OSError:
        clobber = False
    if clobber:
        stem += "-converted"
        print(f"note: output would overwrite the input file - writing "
              f"{stem}.* instead")
    pkg = package.write_full(outdir, stem, result.out_text, report)
    (outdir / (stem + ".report.md")).write_text(
        report.to_markdown(), encoding="utf-8")
    (outdir / (stem + ".report.json")).write_text(
        report.to_json(), encoding="utf-8")
    (outdir / (stem + ".report.html")).write_text(
        report.to_html(), encoding="utf-8")
    if result.sample_portmap:
        (outdir / (stem + ".portmap")).write_text(
            result.sample_portmap, encoding="utf-8")

    print(f"wrote {pkg['main']} "
          f"(full restorable config, {result.section_count} sections)")
    if plan.portmap:
        print(f"interface renames: {report.meta.get('interface_renames', 0)} "
              f"edits, {report.meta.get('reference_rewrites', 0)} "
              "references rewritten")
    for key in ("vdom_mode", "vdoms_renamed", "hw_switch_converted",
                "sslvpn_tunnels", "zones_created", "sdwan_members_added",
                "default_routes_converted", "policies_merged",
                "fortios_versions", "upgrade_artifacts",
                "upgrade_auto_fixed", "downgrade_artifacts",
                "downgrade_auto_fixed"):
        if key in report.meta:
            print(f"{key.replace('_', ' ')}: {report.meta[key]}")
    errors, warns = report.count("error"), report.count("warn")
    print(f"report: {errors} errors, {warns} warnings "
          f"-> {outdir / (stem + '.report.md')}")
    return max(result.exit_code, 1 if errors else 0)


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
                   choices=["auto", "cisco-asa", "paloalto", "pfsense",
                            "fortios"])
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
    p.add_argument("--vdom-map", metavar="SRC=DST[,SRC=DST...]",
                   help="rename VDOMs during a multi-VDOM migration "
                        "(FortiConverter's VDOM Mapping)")
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
    p.add_argument("--nat-mode", default="policy",
                   choices=["policy", "central"],
                   help="cross-vendor NAT emission: 'policy' = per-policy "
                        "nat enable + VIPs (default); 'central' = "
                        "central-nat enable + central-snat-map rules, "
                        "VIPs as central DNAT")
    p.add_argument("--fmg", metavar="ADOM[/PACKAGE]",
                   help="also write a FortiManager JSON-RPC import bundle "
                        "(<name>.fmg.json) creating the objects + a policy "
                        "package in that ADOM (cross-vendor conversions)")
    p.add_argument("--pa-vsys",
                   help="Palo Alto multi-vsys: convert only this vsys "
                        "(default: every vsys becomes a VDOM block)")
    p.add_argument("--pa-device-group",
                   help="Panorama export: which device-group to convert")
    p.add_argument("--pa-template",
                   help="Panorama export: template supplying network "
                        "config (interfaces/zones) for the device-group")
    p.add_argument("--schema-check", metavar="HOST|FILE",
                   help="validate the output against the exact CLI schema "
                        "of a target build: a live FortiGate host[:port] "
                        "(read-only; fetched schema is cached under "
                        "~/.fwforge/schemas/) or a cached schema file")
    p.add_argument("--schema-token",
                   default=os.environ.get("FWFORGE_API_TOKEN", ""),
                   help="REST API token for --schema-check live fetch "
                        "(default: FWFORGE_API_TOKEN env var)")
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

    p = sub.add_parser(
        "schema",
        help="fetch / list target-build CLI schemas for --schema-check")
    p.add_argument("host", nargs="?",
                   help="FortiGate host[:port] to fetch from (read-only); "
                        "omit with --list")
    p.add_argument("--token",
                   default=os.environ.get("FWFORGE_API_TOKEN", ""),
                   help="REST API token (default: FWFORGE_API_TOKEN env)")
    p.add_argument("--list", action="store_true",
                   help="list cached schemas")
    p.set_defaults(fn=cmd_schema)

    p = sub.add_parser("gui", help="run the local web UI")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=4848)
    p.add_argument("--no-browser", action="store_true")
    p.set_defaults(fn=cmd_gui)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
