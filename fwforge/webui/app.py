"""fwforge local web UI — a thin Flask layer over fwforge.pipeline.

No conversion logic lives here: routes collect input, call the same
pipeline the CLI uses, and render the Report. Jobs live on disk under
~/.fwforge/gui-jobs/<id>/ (job.json + artifacts) and survive restarts.
"""
from __future__ import annotations

import difflib
import json
import re
import shutil
import time
import uuid
import zipfile
from pathlib import Path

from flask import (Flask, abort, redirect, render_template, request,
                   send_file, url_for)

from .. import __version__, pipeline
from .. import schema as schema_mod
from ..emit import fortimanager, package
from ..parsers import CROSS_PARSERS, detect_vendor, fortios_tree
from ..parsers.paloalto import PanoramaChoiceNeeded
from ..transforms import portmap, tree_refs, zones
from ..transforms import plan as plan_mod
from ..transforms.plan import (MigrationPlan, PlanError, SdwanMember,
                               SdwanZoneSpec, ZoneSpec)
from ..transforms import versiondelta
from ..transforms.tuning import TuningOptions

JOBS: dict[str, dict] = {}
JOBS_DIR = Path.home() / ".fwforge" / "gui-jobs"
FORTIOS_TARGETS = ["7.0", "7.2", "7.4", "7.6", "8.0"]
DIFF_RENDER_CAP = 600
PREVIEW_CAP = 500
POLICY_CAP = 800

VENDOR_LABELS = {"cisco-asa": "Cisco ASA", "paloalto": "Palo Alto",
                 "pfsense": "pfSense", "fortios": "FortiOS"}


def _save_job(jid: str) -> None:
    try:
        (JOBS_DIR / jid / "job.json").write_text(
            json.dumps(JOBS[jid], default=str), encoding="utf-8")
    except OSError:
        pass


def _load_jobs() -> None:
    JOBS.clear()
    if not JOBS_DIR.is_dir():
        return
    for jfile in JOBS_DIR.glob("*/job.json"):
        try:
            JOBS[jfile.parent.name] = json.loads(
                jfile.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue


def _analyze(text: str, name: str) -> dict:
    vendor, conf = detect_vendor(text)
    meta = {
        "name": name,
        "vendor": vendor,
        "vendor_label": VENDOR_LABELS.get(vendor, vendor),
        "confidence": f"{conf:.0%}",
        "created": time.strftime("%Y-%m-%d %H:%M"),
        "interfaces": [],
        "vdoms": {},
        "scopes": [],
        "multi_vdom": False,
        "source_os": "",
        "hostname": "",
        "inventory": {},
        "counts": {},
        "policies": [],
        "policies_truncated": 0,
        "iface_details": [],
        "lines": len(text.splitlines()),
    }
    if vendor == "fortios":
        tree = fortios_tree.parse_config(text, name)
        meta["interfaces"] = portmap.tree_interface_names(tree)
        meta["vdoms"] = tree_refs.interface_vdoms(tree)
        meta["multi_vdom"] = tree_refs.is_multi_vdom(tree)
        meta["scopes"] = [n for n, _ in fortios_tree.vdom_scopes(tree)
                          if n is not None]
        src = versiondelta.source_version_from_header(tree)
        if src:
            meta["source_os"] = versiondelta.vlabel(src)  # full x.y.z
        meta["inventory"] = fortios_tree.section_inventory(tree)
        # per-interface facts for the zone / SD-WAN member pickers
        zoned = zones.existing_zone_members(tree)
        in_sdwan = zones.existing_sdwan_members(tree)
        refs = tree_refs.interface_policy_refs(tree)
        details = portmap.tree_interface_details(tree)
        for d in details:
            d["vdom"] = d["vdom"] or meta["vdoms"].get(d["name"], "root")
            d["zone"] = zoned.get(d["name"], "")
            d["sdwan"] = d["name"] in in_sdwan
            d["policy_refs"] = refs.get(d["name"], 0)
        meta["iface_details"] = details
    elif vendor in CROSS_PARSERS:
        try:
            cfg = CROSS_PARSERS[vendor](text, name)
        except PanoramaChoiceNeeded as e:
            meta["panorama"] = {"device_groups": e.device_groups,
                                "templates": e.templates,
                                "needs_choice": True}
            return meta
        pano = cfg.meta.get("panorama")
        if pano:
            meta["panorama"] = {**pano, "needs_choice": False}
        scopes = cfg.meta.get("vsys_cfgs") or [(None, cfg)]
        if len(scopes) > 1:
            meta["vsys"] = [n for n, _ in scopes]
        seen_if: list[str] = []
        counts = {"interfaces": 0, "zones": 0, "addresses": 0,
                  "services": 0, "policies": 0, "nat rules / vips": 0,
                  "routes": 0}
        pols = []
        truncated = 0
        for vname, vcfg in scopes:
            for i in vcfg.interfaces:
                if i.name not in seen_if:
                    seen_if.append(i.name)
            counts["zones"] += len(vcfg.zones)
            counts["addresses"] += len(vcfg.addresses)
            counts["services"] += len(vcfg.services)
            counts["policies"] += len(vcfg.policies)
            counts["nat rules / vips"] += len(vcfg.nats) + len(vcfg.vips)
            counts["routes"] += len(vcfg.routes)
            for p in vcfg.policies:
                if len(pols) >= POLICY_CAP:
                    truncated += 1
                    continue
                entry = {
                    "name": p.name,
                    "src": " ".join(p.src_zones) or "any",
                    "dst": " ".join(p.dst_zones) or "any",
                    "srcaddr": " ".join(p.src_addrs[:3]),
                    "dstaddr": " ".join(p.dst_addrs[:3]),
                    "service": " ".join(p.services[:3]),
                    "action": p.action,
                    "disabled": p.disabled,
                }
                if vname is not None:
                    entry["vsys"] = vname
                pols.append(entry)
        counts["interfaces"] = len(seen_if)
        meta["interfaces"] = seen_if
        meta["hostname"] = cfg.hostname
        meta["counts"] = counts
        meta["policies"] = pols
        meta["policies_truncated"] = truncated
    return meta


def _grouped_findings(report) -> dict:
    out = {"error": [], "warn": [], "info": []}
    for f in report.findings:
        out.setdefault(f.level, []).append(
            {"area": f.area, "message": f.message, "loc": f.loc})
    return out


def _diff_lines(a: str, b: str) -> tuple[list[dict], int, str]:
    diff = list(difflib.unified_diff(
        a.splitlines(), b.splitlines(),
        "source (normalized)", "converted", n=3, lineterm=""))
    changed = sum(1 for l in diff
                  if l[:1] in "+-" and l[:3] not in ("+++", "---"))
    rendered = []
    for line in diff[:DIFF_RENDER_CAP]:
        if line.startswith("@@"):
            cls = "d-hunk"
        elif line.startswith("+"):
            cls = "d-add"
        elif line.startswith("-"):
            cls = "d-del"
        else:
            cls = "d-ctx"
        rendered.append({"cls": cls, "text": line})
    return rendered, changed, "\n".join(diff) + ("\n" if diff else "")


def _parse_hc(text: str):
    t = text.strip()
    if not t:
        return None
    parts = t.split()
    if parts == ["none"]:
        return ("none", "")
    if len(parts) == 2 and parts[0] in ("ping", "http", "dns"):
        return (parts[0], parts[1])
    raise PlanError(
        "health-check must be 'none' or '<ping|http|dns> <server>'")


def _form_indexes(form, prefix: str) -> list[int]:
    """Row indexes present in the form (gap-tolerant: rows can be removed
    from the middle of the builder)."""
    pat = re.compile(re.escape(prefix) + r"_(\d+)$")
    return sorted({int(m.group(1))
                   for k in form.keys() for m in [pat.match(k)] if m})


def _plan_from_form(form) -> MigrationPlan:
    plan = MigrationPlan()
    for src, dst in zip(form.getlist("map_src"), form.getlist("map_dst")):
        src, dst = src.strip(), dst.strip()
        if src and dst:
            plan.portmap[src] = dst
    for src, dst in zip(form.getlist("vmap_src"), form.getlist("vmap_dst")):
        src, dst = src.strip(), dst.strip()
        if src and dst and src != dst:
            plan.vdommap[src] = dst
    for i in _form_indexes(form, "zone_name"):
        name = form.get(f"zone_name_{i}", "").strip()
        members = [m for m in form.getlist(f"zone_members_{i}") if m]
        if name and members:
            plan.zones.append(ZoneSpec(
                name=name, members=members,
                intrazone=form.get(f"zone_intrazone_{i}", "deny"),
                vdom=form.get(f"zone_vdom_{i}", "").strip() or None))
        elif name or members:
            raise PlanError(f"zone '{name or '?'}': needs both a name and "
                            "members")
    for i in _form_indexes(form, "sdwan_name"):
        name = form.get(f"sdwan_name_{i}", "").strip()
        picked = [m for m in form.getlist(f"sdwan_member_{i}") if m]
        member_text = form.get(f"sdwan_members_{i}", "").strip()
        if name == "virtual-wan-link" and not picked and not member_text:
            continue  # an added-but-untouched row (the name is pre-filled)
        if name and (picked or member_text):
            spec = SdwanZoneSpec(name=name)
            if picked:
                # checkbox picker: per-member gateway/weight inputs
                for ifc in picked:
                    spec.members.append(SdwanMember(
                        interface=ifc,
                        gateway=form.get(f"sdwan_gw_{i}_{ifc}", "").strip(),
                        weight=form.get(f"sdwan_weight_{i}_{ifc}",
                                        "").strip()))
            else:
                # legacy plan-file syntax (kept for scripted POSTs)
                spec.members = [
                    plan_mod._parse_sdwan_member(e, f"sdwan {name}")
                    for e in plan_mod._split_members(member_text)]
            spec.health_check = _parse_hc(form.get(f"sdwan_hc_{i}", ""))
            spec.rule_mode = form.get(f"sdwan_rule_{i}", "auto")
            spec.vdom = form.get(f"sdwan_vdom_{i}", "").strip() or None
            plan.sdwan.append(spec)
        elif name or picked or member_text:
            raise PlanError(f"SD-WAN zone '{name or '?'}': needs both a "
                            "zone name and members")
    plan.translate_members()
    return plan


def _tuning_from_form(form, meta) -> TuningOptions:
    exclude = [s.strip() for s in form.get("t_exclude", "").split(",")
               if s.strip()]
    # policy-selection checkboxes: anything not kept is excluded
    if form.get("pol_present"):
        kept = set(form.getlist("pol_keep"))
        for p in meta.get("policies", []):
            if p["name"] and p["name"] not in kept \
                    and p["name"] not in exclude:
                exclude.append(p["name"])
    return TuningOptions(
        prune=bool(form.get("t_prune")),
        merge_dupes=bool(form.get("t_merge")),
        split_pairs=bool(form.get("t_split")),
        exclude=exclude,
    )


def create_app() -> Flask:
    app = Flask(__name__)
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    _load_jobs()

    @app.context_processor
    def inject():
        return {"version": __version__}

    @app.get("/")
    def index():
        jobs = sorted(JOBS.items(), key=lambda kv: kv[1].get("created", ""),
                      reverse=True)
        return render_template("index.html", jobs=jobs,
                               error=request.args.get("error", ""))

    @app.post("/load")
    def load():
        text = ""
        name = ""
        upload = request.files.get("config")
        if upload and upload.filename:
            # utf-8-sig: strip the BOM Windows editors prepend (it breaks
            # the line-anchored vendor detection)
            text = upload.read().decode("utf-8-sig", "replace")
            name = upload.filename
        elif request.form.get("path", "").strip():
            p = Path(request.form["path"].strip())
            if not p.is_file():
                return redirect(url_for("index",
                                        error=f"file not found: {p}"))
            text = p.read_text(encoding="utf-8-sig", errors="replace")
            name = p.name
        if not text.strip():
            return redirect(url_for("index", error="no config provided"))

        meta = _analyze(text, name)
        if meta["vendor"] == "unknown":
            return redirect(url_for(
                "index",
                error="could not detect the vendor of that config"))
        jid = uuid.uuid4().hex[:12]
        jdir = JOBS_DIR / jid
        jdir.mkdir(parents=True, exist_ok=True)
        # underscore prefix: an upload named e.g. 'source.conf' must not
        # collide with the converted output written into the same dir
        (jdir / "_source.conf").write_text(text, encoding="utf-8")
        JOBS[jid] = meta
        _save_job(jid)
        return redirect(url_for("job", jid=jid))

    def _job(jid: str) -> dict:
        if jid not in JOBS:
            abort(404)
        return JOBS[jid]

    @app.get("/job/<jid>")
    def job(jid):
        meta = _job(jid)
        # jobs analyzed before the informed pickers existed have no
        # iface_details in job.json — re-analyze them from the stored
        # source once, keeping their identity and any conversion result
        if meta.get("vendor") == "fortios" \
                and not meta.get("iface_details"):
            src = _source_path(JOBS_DIR / jid)
            if src.is_file():
                fresh = _analyze(
                    src.read_text(encoding="utf-8", errors="replace"),
                    meta.get("name", src.name))
                fresh["created"] = meta.get("created", fresh["created"])
                if "result" in meta:
                    fresh["result"] = meta["result"]
                JOBS[jid] = meta = fresh
                _save_job(jid)
        src_train = ".".join(meta["source_os"].split(".")[:2])
        default_target = (src_train if src_train in FORTIOS_TARGETS
                          else "7.4")
        det = {d["name"]: d for d in meta.get("iface_details", [])}
        return render_template(
            "plan.html", jid=jid, meta=meta, targets=FORTIOS_TARGETS,
            default_target=default_target, det=det,
            schemas=schema_mod.list_cached(),
            error=request.args.get("error", ""))

    @app.post("/job/<jid>/delete")
    def delete(jid):
        _job(jid)
        shutil.rmtree(JOBS_DIR / jid, ignore_errors=True)
        JOBS.pop(jid, None)
        return redirect(url_for("index"))

    def _source_path(jdir: Path) -> Path:
        p = jdir / "_source.conf"
        if p.is_file():
            return p
        return jdir / "source.conf"  # jobs saved before the rename

    @app.post("/job/<jid>/convert")
    def convert(jid):
        meta = _job(jid)
        jdir = JOBS_DIR / jid
        text = _source_path(jdir).read_text(encoding="utf-8")
        target = request.form.get("fortios", "7.4")

        try:
            if meta["vendor"] == "fortios":
                plan = _plan_from_form(request.form)
                result = pipeline.run_migrate(
                    text, meta["name"], plan, target=target,
                    source_os=request.form.get("source_os", "").strip()
                    or None,
                    target_platform=request.form.get(
                        "target_platform", "").strip() or None,
                    vdom_mode=request.form.get("vdom_mode", "keep"),
                    vdom_name=request.form.get("vdom_name", "root").strip()
                    or "root",
                    vdom_scope_only=bool(request.form.get("vdom_scope_only")),
                    hw_switch=("convert" if request.form.get("hw_switch")
                               else "keep"),
                    sslvpn_to_ipsec=bool(request.form.get("sslvpn_to_ipsec")),
                    sslvpn_psk=request.form.get("sslvpn_psk", "").strip()
                    or "CHANGEME-SET-A-REAL-PSK",
                    want_normalized=True)
            else:
                mapping = {}
                for src, dst in zip(request.form.getlist("map_src"),
                                    request.form.getlist("map_dst")):
                    if src.strip() and dst.strip():
                        mapping[src.strip()] = dst.strip()
                parser_opts = {
                    k: v for k, v in {
                        "device_group":
                            request.form.get("pa_dg", "").strip(),
                        "template":
                            request.form.get("pa_template", "").strip(),
                    }.items() if v}
                result = pipeline.run_cross(
                    text, meta["vendor"], meta["name"], mapping,
                    target=target,
                    tuning=_tuning_from_form(request.form, meta),
                    nat_mode=request.form.get("nat_mode", "policy"),
                    parser_opts=parser_opts or None)
        except PlanError as e:
            return redirect(url_for("job", jid=jid, error=str(e)))
        except PanoramaChoiceNeeded as e:
            return redirect(url_for(
                "job", jid=jid,
                error="pick a device-group (Panorama export): "
                      + ", ".join(e.device_groups)))

        report = result.report
        if request.form.get("schema_enable"):
            try:
                ref = request.form.get("schema_cached", "").strip() \
                    or request.form.get("schema_host", "").strip()
                if not ref:
                    raise ValueError(
                        "pick a cached schema or enter a live host")
                # the token is used for this one fetch and never stored
                schema, _ = schema_mod.resolve(
                    ref, request.form.get("schema_token", "").strip())
                schema_mod.check(result.out_text, schema, report,
                                 target=target)
            except Exception as e:
                report.add("error", "schema",
                           f"schema check failed ({e}) — output written "
                           "unvalidated")
        stem = Path(meta["name"]).stem or "config"
        if stem.lower() in ("_source", "source", "report", "diff",
                            "bundle"):
            stem += "-converted"  # keep clear of the job's own artifacts
        fmg_written = False
        (jdir / f"{stem}.fmg.json").unlink(missing_ok=True)  # stale run
        if result.mode == "cross" and request.form.get("fmg_enable"):
            try:
                bundle = fortimanager.build_bundle(
                    result.cfg, report,
                    adom=request.form.get("fmg_adom", "").strip() or "root",
                    package=request.form.get("fmg_pkg", "").strip()
                    or f"{stem}-converted",
                    nat_mode=request.form.get("nat_mode", "policy"))
                (jdir / f"{stem}.fmg.json").write_text(
                    fortimanager.render(bundle), encoding="utf-8")
                fmg_written = True
            except Exception as e:  # must not sink the whole conversion
                report.add("error", "fortimanager",
                           f"FortiManager bundle failed ({e}) — output and "
                           "reports written without it")
        if result.mode == "migrate":
            pkg = package.write_full(jdir, stem, result.out_text, report)
        else:
            pkg = package.write_split(jdir, stem, result.out_text, report)
        if result.mode == "cross":
            (jdir / "report.md").write_text(
                report.to_markdown(result.cfg, text), encoding="utf-8")
            (jdir / "report.json").write_text(
                report.to_json(result.cfg), encoding="utf-8")
            (jdir / "report.html").write_text(
                report.to_html(result.cfg, text), encoding="utf-8")
        else:
            (jdir / "report.md").write_text(report.to_markdown(),
                                            encoding="utf-8")
            (jdir / "report.json").write_text(report.to_json(),
                                              encoding="utf-8")
            (jdir / "report.html").write_text(report.to_html(),
                                              encoding="utf-8")

        diff_render, diff_changed, diff_full = [], 0, ""
        if result.normalized_source:
            diff_render, diff_changed, diff_full = _diff_lines(
                result.normalized_source, result.out_text)
            (jdir / "diff.patch").write_text(diff_full, encoding="utf-8")

        meta["result"] = {
            "mode": result.mode,
            "when": time.strftime("%Y-%m-%d %H:%M"),
            "target": target,
            "exit": result.exit_code,
            "stem": stem,
            "split": pkg["split"],
            "fmg": fmg_written,
            "main_name": pkg["main_name"],
            "branch_count": pkg["branch_count"],
            "counts": {
                "errors": report.count("error"),
                "warnings": report.count("warn"),
                "notes": report.count("info"),
            },
            "meta": {k: v for k, v in report.meta.items()
                     if k not in ("tool", "source", "mode")},
            "findings": _grouped_findings(report),
            "unmapped": result.unmapped,
            "sample_portmap": result.sample_portmap or "",
            "unparsed": len(result.cfg.unparsed) if result.cfg else 0,
            "sections": result.section_count,
            "diff": diff_render,
            "diff_changed": diff_changed,
            "diff_total": len(diff_full.splitlines()),
            "out_size": len(result.out_text.splitlines()),
        }
        _save_job(jid)
        return redirect(url_for("job_result", jid=jid))

    @app.get("/job/<jid>/result")
    def job_result(jid):
        meta = _job(jid)
        if "result" not in meta:
            return redirect(url_for("job", jid=jid))
        r = meta["result"]
        # files available for the Output tab (main + branch scripts)
        files = [r["main_name"]]
        if r.get("split"):
            bdir = JOBS_DIR / jid / f"{r['stem']}.branches"
            if bdir.is_dir():
                files += [f"{r['stem']}.branches/{p.name}"
                          for p in sorted(bdir.glob("*.txt"))]
        sel = request.args.get("file", "")
        if sel not in files:
            sel = files[0]
        fpath = JOBS_DIR / jid / sel
        preview: list[str] = []
        if fpath.is_file():
            preview = fpath.read_text(
                encoding="utf-8", errors="replace").splitlines()
        shown = preview[:PREVIEW_CAP]
        return render_template(
            "result.html", jid=jid, meta=meta, r=r,
            preview=shown, preview_total=len(preview),
            files=files, sel=sel,
            active_tab="output" if request.args.get("file") else "summary")

    @app.get("/job/<jid>/dl/<which>")
    def download(jid, which):
        meta = _job(jid)
        stem = Path(meta["name"]).stem or "config"
        main_name = meta.get("result", {}).get("main_name",
                                                f"{stem}.config-all.txt")
        files = {
            "conf": (main_name, "text/plain", main_name),
            "report.md": ("report.md", "text/markdown", f"{stem}.report.md"),
            "report.json": ("report.json", "application/json",
                            f"{stem}.report.json"),
            "report.html": ("report.html", "text/html",
                            f"{stem}.report.html"),
            "diff": ("diff.patch", "text/plain", f"{stem}.diff.patch"),
            "fmg": (f"{stem}.fmg.json", "application/json",
                    f"{stem}.fmg.json"),
        }
        if which not in files:
            abort(404)
        fname, mime, dlname = files[which]
        fpath = JOBS_DIR / jid / fname
        if not fpath.is_file():
            abort(404)
        return send_file(fpath, mimetype=mime, as_attachment=True,
                         download_name=dlname)

    @app.get("/job/<jid>/bundle.zip")
    def bundle(jid):
        meta = _job(jid)
        stem = Path(meta["name"]).stem or "config"
        jdir = JOBS_DIR / jid
        zpath = jdir / "bundle.zip"
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            for p in sorted(jdir.rglob("*")):
                if p.is_file() and p.name not in ("bundle.zip",
                                                  "_source.conf",
                                                  "source.conf",
                                                  "job.json"):
                    z.write(p, p.relative_to(jdir))
        return send_file(zpath, mimetype="application/zip",
                         as_attachment=True,
                         download_name=f"{stem}.fwforge.zip")

    return app
