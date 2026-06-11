"""fwforge local web UI — a thin Flask layer over fwforge.pipeline.

No conversion logic lives here: routes collect input, call the same
pipeline the CLI uses, and render the Report. Jobs live on disk under
~/.fwforge/gui-jobs/<id>/ (job.json + artifacts) and survive restarts.
"""
from __future__ import annotations

import difflib
import json
import shutil
import time
import uuid
import zipfile
from pathlib import Path

from flask import (Flask, abort, redirect, render_template, request,
                   send_file, url_for)

from .. import __version__, pipeline
from ..emit import package
from ..parsers import CROSS_PARSERS, detect_vendor, fortios_tree
from ..transforms import portmap, tree_refs
from ..transforms import plan as plan_mod
from ..transforms.plan import (MigrationPlan, PlanError, SdwanZoneSpec,
                               ZoneSpec)
from ..transforms import versiondelta
from ..transforms.tuning import TuningOptions

JOBS: dict[str, dict] = {}
JOBS_DIR = Path.home() / ".fwforge" / "gui-jobs"
FORTIOS_TARGETS = ["7.0", "7.2", "7.4", "7.6", "8.0"]
DIFF_RENDER_CAP = 600
PREVIEW_CAP = 500
POLICY_CAP = 800

VENDOR_LABELS = {"cisco-asa": "Cisco ASA", "paloalto": "Palo Alto",
                 "fortios": "FortiOS"}


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
            meta["source_os"] = f"{src[0]}.{src[1]}"
        meta["inventory"] = fortios_tree.section_inventory(tree)
    elif vendor in CROSS_PARSERS:
        cfg = CROSS_PARSERS[vendor](text, name)
        meta["interfaces"] = [i.name for i in cfg.interfaces]
        meta["hostname"] = cfg.hostname
        meta["counts"] = {
            "interfaces": len(cfg.interfaces),
            "zones": len(cfg.zones),
            "addresses": len(cfg.addresses),
            "services": len(cfg.services),
            "policies": len(cfg.policies),
            "nat rules / vips": len(cfg.nats) + len(cfg.vips),
            "routes": len(cfg.routes),
        }
        pols = []
        for p in cfg.policies[:POLICY_CAP]:
            pols.append({
                "name": p.name,
                "src": " ".join(p.src_zones) or "any",
                "dst": " ".join(p.dst_zones) or "any",
                "srcaddr": " ".join(p.src_addrs[:3]),
                "dstaddr": " ".join(p.dst_addrs[:3]),
                "service": " ".join(p.services[:3]),
                "action": p.action,
                "disabled": p.disabled,
            })
        meta["policies"] = pols
        meta["policies_truncated"] = max(0, len(cfg.policies) - POLICY_CAP)
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
    i = 0
    while f"zone_name_{i}" in form:
        name = form.get(f"zone_name_{i}", "").strip()
        members = [m for m in form.getlist(f"zone_members_{i}") if m]
        if name and members:
            plan.zones.append(ZoneSpec(
                name=name, members=members,
                intrazone=form.get(f"zone_intrazone_{i}", "deny"),
                vdom=form.get(f"zone_vdom_{i}", "").strip() or None))
        elif name or members:
            raise PlanError(f"zone row {i + 1}: needs both a name and "
                            "members")
        i += 1
    i = 0
    while f"sdwan_name_{i}" in form:
        name = form.get(f"sdwan_name_{i}", "").strip()
        member_text = form.get(f"sdwan_members_{i}", "").strip()
        if name and member_text:
            spec = SdwanZoneSpec(name=name)
            spec.members = [
                plan_mod._parse_sdwan_member(e, f"sdwan {name}")
                for e in plan_mod._split_members(member_text)]
            spec.health_check = _parse_hc(form.get(f"sdwan_hc_{i}", ""))
            spec.rule_mode = form.get(f"sdwan_rule_{i}", "auto")
            spec.vdom = form.get(f"sdwan_vdom_{i}", "").strip() or None
            plan.sdwan.append(spec)
        elif name or member_text:
            raise PlanError(f"SD-WAN row {i + 1}: needs both a zone name "
                            "and members")
        i += 1
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
            text = upload.read().decode("utf-8", "replace")
            name = upload.filename
        elif request.form.get("path", "").strip():
            p = Path(request.form["path"].strip())
            if not p.is_file():
                return redirect(url_for("index",
                                        error=f"file not found: {p}"))
            text = p.read_text(encoding="utf-8", errors="replace")
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
        (jdir / "source.conf").write_text(text, encoding="utf-8")
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
        default_target = (meta["source_os"]
                          if meta["source_os"] in FORTIOS_TARGETS else "7.4")
        return render_template(
            "plan.html", jid=jid, meta=meta, targets=FORTIOS_TARGETS,
            default_target=default_target,
            error=request.args.get("error", ""))

    @app.post("/job/<jid>/delete")
    def delete(jid):
        _job(jid)
        shutil.rmtree(JOBS_DIR / jid, ignore_errors=True)
        JOBS.pop(jid, None)
        return redirect(url_for("index"))

    @app.post("/job/<jid>/convert")
    def convert(jid):
        meta = _job(jid)
        jdir = JOBS_DIR / jid
        text = (jdir / "source.conf").read_text(encoding="utf-8")
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
                result = pipeline.run_cross(
                    text, meta["vendor"], meta["name"], mapping,
                    target=target,
                    tuning=_tuning_from_form(request.form, meta))
        except PlanError as e:
            return redirect(url_for("job", jid=jid, error=str(e)))

        report = result.report
        stem = Path(meta["name"]).stem or "config"
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
                                                  "source.conf",
                                                  "job.json"):
                    z.write(p, p.relative_to(jdir))
        return send_file(zpath, mimetype="application/zip",
                         as_attachment=True,
                         download_name=f"{stem}.fwforge.zip")

    return app
