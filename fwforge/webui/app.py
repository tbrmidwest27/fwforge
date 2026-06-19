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
from urllib.parse import urlsplit

from werkzeug.datastructures import MultiDict

from flask import (Flask, abort, redirect, render_template, request,
                   send_file, url_for)

from .. import __version__, pipeline, platforms
from .. import appdb as appdb_mod
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
# version-picker suggestions (trains + latest known patch per train); the
# field itself is free-text so any exact build is accepted. Sourced from the
# platforms "database" so a single place stays current.
FORTIOS_TARGETS = list(platforms.version_suggestions())
DIFF_RENDER_CAP = 600
PREVIEW_CAP = 500
POLICY_CAP = 800

VENDOR_LABELS = {"cisco-asa": "Cisco ASA", "paloalto": "Palo Alto",
                 "pfsense": "pfSense", "juniper-srx": "Juniper SRX",
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


def _analyze(text: str, name: str, forced_vendor: str = "") -> dict:
    detected, conf = detect_vendor(text)
    # When the user picked a source vendor up front (a landing-page tile ->
    # /new/<vendor>), that choice is authoritative: we parse as that vendor
    # even when content detection is unsure. Detection still runs as a sanity
    # check so we can warn on a strong disagreement (vendor_mismatch below).
    vendor = forced_vendor or detected
    meta = {
        "name": name,
        "vendor": vendor,
        "vendor_label": VENDOR_LABELS.get(vendor, vendor),
        "detected_vendor": detected,
        "detected_label": VENDOR_LABELS.get(detected, detected),
        "forced_vendor": bool(forced_vendor),
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
    # the user forced a vendor but content detection points elsewhere — the
    # wizard surfaces this so a misclick can't silently mis-convert
    if forced_vendor and detected not in ("unknown", forced_vendor):
        meta["vendor_mismatch"] = VENDOR_LABELS.get(detected, detected)
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
        meta["source_platform"] = platforms.header_platform(text)
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
        det_by_name: dict[str, dict] = {}
        counts = {"interfaces": 0, "zones": 0, "addresses": 0,
                  "services": 0, "policies": 0, "nat rules / vips": 0,
                  "routes": 0}
        pols = []
        truncated = 0
        for vname, vcfg in scopes:
            for i in vcfg.interfaces:
                if i.name not in seen_if:
                    seen_if.append(i.name)
                if i.name not in det_by_name:
                    # physical + aggregate-member both map to a target
                    # PHYSICAL port (so they get the port dropdown); the
                    # real kind drives the membership badge
                    det_by_name[i.name] = {
                        "name": i.name, "ip": i.ip or "", "alias": "",
                        "descr": i.description or "",
                        "type": ("physical" if i.kind in
                                 ("physical", "aggregate-member")
                                 else i.kind),
                        "vlanid": str(i.vlan_id) if i.vlan_id else "",
                        "parent": i.parent or "", "role": "", "status": "",
                        "vdom": "root", "zone": "", "sdwan": False,
                        "policy_refs": 0, "kind": i.kind,
                        "lacp": i.lacp_mode or ""}
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
        meta["iface_details"] = list(det_by_name.values())
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


def _converted_counts(cfg) -> dict:
    """Per-VDOM-summed counts of what the conversion produced — for the
    result-page outcome tiles. Mirrors the plan-page tally (uses the same
    vsys_cfgs scopes), but read off the FINAL converted config."""
    out = {"policies": 0, "addresses": 0, "services": 0, "nat_vips": 0}
    if cfg is None:
        return out
    for _name, vc in (cfg.meta.get("vsys_cfgs") or [(None, cfg)]):
        out["policies"] += len(vc.policies)
        out["addresses"] += len(vc.addresses)
        out["services"] += len(vc.services)
        out["nat_vips"] += len(vc.nats) + len(vc.vips)
    return out


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


def _authoring_from_form(form):
    """Parse the interface-authoring panel into the run_cross 'authoring'
    payload: target LAG definitions + per-VLAN parent choices. Returns
    None when nothing was authored (preserves the base mapping behaviour)."""
    aggregates = []
    for i in range(64):
        name = form.get(f"agg_name_{i}")
        if name and name.strip():
            aggregates.append({
                "name": name.strip(),
                "lacp": form.get(f"agg_lacp_{i}", "active"),
                "members": [m.strip() for m in
                            form.get(f"agg_members_{i}", "").split(",")
                            if m.strip()],
            })
    vlan_parents = {}
    for src, parent in zip(form.getlist("vparent_src"),
                           form.getlist("vparent_dst")):
        if src.strip() and parent.strip():
            vlan_parents[src.strip()] = parent.strip()
    if not aggregates and not vlan_parents:
        return None
    return {"aggregates": aggregates, "vlan_parents": vlan_parents}


def _mapping_from_form(form):
    """Source-interface -> target-port map from the wizard grid. Blank
    targets and the GUI "do not map" choice (sentinel '__none__') are left
    out, so those interfaces stay unmapped — they keep their source name and
    a physical port isn't emitted, while its target port frees up for a LAG."""
    mapping = {}
    for src, dst in zip(form.getlist("map_src"), form.getlist("map_dst")):
        src, dst = src.strip(), dst.strip()
        if src and dst and dst != "__none__":
            mapping[src] = dst
    return mapping


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
    # actionable-finding fixes: disable dead rules / reorder a bypassed deny
    # (carried as repeatable form fields so they replay through /rerun)
    reorder = [tuple(s.split("|||", 1)) for s in form.getlist("reorder_policy")
               if "|||" in s]
    return TuningOptions(
        prune=bool(form.get("t_prune")),
        merge_dupes=bool(form.get("t_merge")),
        split_pairs=bool(form.get("t_split")),
        exclude=exclude,
        disable=form.getlist("disable_policy"),
        reorder=reorder,
    )


def create_app() -> Flask:
    app = Flask(__name__)
    # cap uploads: /load reads whole config files into memory, so an unbounded
    # body is a trivial memory-exhaustion DoS. 25 MiB is far above any real
    # firewall backup; Flask returns 413 for anything larger.
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    _load_jobs()

    @app.context_processor
    def _inject_globals():
        from ..parsers.pan_appid import db_counts
        try:
            bundled, user = db_counts()
        except Exception:
            bundled, user = 0, 0
        return {"app_db_bundled": bundled, "app_db_user": user}

    # local tool bound to 127.0.0.1: reject cross-origin state-changing
    # requests so a web page the user happens to have open cannot silently
    # drive /load (which can read an arbitrary local file path), /convert, or
    # /delete. Same-origin form posts from our own templates carry a matching
    # Origin/Referer and pass; scripted local use (no Origin AND no Referer,
    # e.g. curl) is allowed.
    @app.before_request
    def _csrf_guard():
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None
        origin = request.headers.get("Origin")
        if origin:
            src_host = urlsplit(origin).netloc
        else:
            referer = request.headers.get("Referer")
            if not referer:
                return None
            src_host = urlsplit(referer).netloc
        if src_host != request.host:
            abort(403)
        return None

    @app.context_processor
    def inject():
        return {"version": __version__}

    @app.get("/")
    def index():
        jobs = sorted(JOBS.items(), key=lambda kv: kv[1].get("created", ""),
                      reverse=True)
        return render_template("index.html", jobs=jobs,
                               error=request.args.get("error", ""))

    @app.get("/new/<vendor>")
    def new(vendor):
        """Per-vendor upload page reached by clicking a source tile on the
        landing page. The chosen vendor is carried as a hidden field into
        /load, where it becomes the authoritative source vendor."""
        if vendor not in VENDOR_LABELS:
            abort(404)
        return render_template("new.html", vendor=vendor,
                               vendor_label=VENDOR_LABELS[vendor],
                               targets=FORTIOS_TARGETS,
                               platform_groups=platforms.GROUPS,
                               error=request.args.get("error", ""))

    @app.post("/detect")
    def detect_head():
        """Live vendor sniff for the upload page: the browser posts the first
        chunk of the chosen file and gets back the detected vendor, so the
        first page confirms the format before you commit to the wizard. Reuses
        the real detect_vendor so the preview can't drift from the parsers."""
        head = request.form.get("head", "")
        if not head.strip():
            return {"vendor": "", "label": "", "confidence": ""}
        vendor, conf = detect_vendor(head)
        if vendor == "unknown":
            return {"vendor": "unknown", "label": "", "confidence": ""}
        return {"vendor": vendor,
                "label": VENDOR_LABELS.get(vendor, vendor),
                "confidence": f"{conf:.0%}"}

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

        # a source tile (/new/<vendor>) posts its vendor as authoritative;
        # an unknown key is ignored so the form falls back to auto-detection
        forced = request.form.get("vendor", "").strip()
        if forced not in VENDOR_LABELS:
            forced = ""
        try:
            meta = _analyze(text, name, forced_vendor=forced)
        except Exception as e:  # forced a vendor onto a config of another kind
            if forced:
                return redirect(url_for(
                    "new", vendor=forced,
                    error=f"couldn't parse that file as "
                          f"{VENDOR_LABELS[forced]}: {e}"))
            return redirect(url_for("index", error=f"parse failed: {e}"))
        if not forced and meta["vendor"] == "unknown":
            return redirect(url_for(
                "index",
                error="could not detect the vendor of that config"))
        jid = uuid.uuid4().hex[:12]
        jdir = JOBS_DIR / jid
        jdir.mkdir(parents=True, exist_ok=True)
        # underscore prefix: an upload named e.g. 'source.conf' must not
        # collide with the converted output written into the same dir
        (jdir / "_source.conf").write_text(text, encoding="utf-8")

        # target FortiGate declared up front on the New-conversion screen
        # (optional): the model preselects the wizard's mapping/faceplate and
        # the OS version prefills the target-version field. A destination
        # backup (below) is authoritative and overrides both.
        tplat = request.form.get("target_platform", "").strip()
        if tplat == "__custom__":
            tplat = request.form.get("target_platform_custom", "").strip()
        if tplat:
            try:
                tplat, _ = platforms.resolve(tplat)
            except PlanError as e:
                shutil.rmtree(jdir, ignore_errors=True)
                return redirect(url_for("new", vendor=forced or meta["vendor"],
                                        error=f"target model: {e}"))
            meta["target_platform"] = tplat
        tos = request.form.get("target_os", "").strip()
        if tos:
            meta["target_os"] = tos

        # optional destination reference backup: authoritative platform
        # code + real port inventory for the migration (reference only,
        # never merged into the output)
        ttext, tname = "", ""
        tup = request.files.get("target_config")
        if tup and tup.filename:
            ttext = tup.read().decode("utf-8-sig", "replace")
            tname = tup.filename
        elif request.form.get("target_path", "").strip():
            tp = Path(request.form["target_path"].strip())
            if not tp.is_file():
                shutil.rmtree(jdir, ignore_errors=True)
                return redirect(url_for(
                    "index", error=f"destination file not found: {tp}"))
            ttext = tp.read_text(encoding="utf-8-sig", errors="replace")
            tname = tp.name
        if ttext.strip():
            try:
                code, ver, ports = platforms.inventory_from_config(ttext)
            except PlanError as e:
                shutil.rmtree(jdir, ignore_errors=True)
                return redirect(url_for(
                    "index", error=f"destination config: {e}"))
            meta["target_code"] = code
            meta["target_version"] = ver
            meta["target_ports"] = list(ports)
            meta["target_name"] = tname
            ident = platforms.device_identity(ttext)
            meta["target_identity"] = ident
            meta["target_hostname"] = ident.get("hostname", "")
            (jdir / "_target.conf").write_text(ttext, encoding="utf-8")

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
        # jobs analyzed before the informed pickers / faceplates existed
        # lack iface_details or source_platform — re-analyze them from
        # the stored source once, keeping identity and any result
        if meta.get("vendor") == "fortios" \
                and (not meta.get("iface_details")
                     or "source_platform" not in meta):
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
        if meta.get("target_version"):
            # a destination backup pins the target version
            src_train = ".".join(meta["target_version"].split(".")[:2])
        # the OS version declared up front on the New-conversion screen wins;
        # else default to the source train when we know it, else 7.4
        default_target = (meta.get("target_os")
                          or (src_train if src_train in FORTIOS_TARGETS
                              else "7.4"))
        det = {d["name"]: d for d in meta.get("iface_details", [])}
        # positional port-guess maps (601F port1 -> 701G lan1, etc.) so
        # the target dropdowns default to a sensible mapping. Computed
        # for the uploaded destination backup and for each model in the
        # table; the JS picks the one matching the chosen destination.
        src_phys = [d["name"] for d in meta.get("iface_details", [])
                    if d.get("type") == "physical"
                    and "." not in d["name"] and d["name"] != "modem"]
        guess_backup = (platforms.guess_portmap(src_phys,
                                                meta["target_ports"])
                        if meta.get("target_ports") else {})
        guess_by_model = {code: platforms.guess_portmap(src_phys,
                                                        list(ports))
                          for code, ports in
                          platforms.PORT_INVENTORY.items()}
        return render_template(
            "plan.html", jid=jid, meta=meta, targets=FORTIOS_TARGETS,
            default_target=default_target, det=det,
            platform_groups=platforms.GROUPS,
            target_platform_known=(meta.get("target_platform")
                                   in platforms.MODEL_BY_CODE),
            port_inventory=platforms.PORT_INVENTORY,
            faceplates=platforms.FACEPLATES,
            platform_models=platforms.MODEL_BY_CODE,
            guess_backup=guess_backup, guess_by_model=guess_by_model,
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
        # remember the exact submitted settings so the result page can re-run
        # this conversion in place (e.g. after the App-ID gap analyzer adds
        # apps) without walking back through the wizard
        meta["last_form"] = request.form.to_dict(flat=False)
        _save_job(jid)
        jdir = JOBS_DIR / jid
        text = _source_path(jdir).read_text(encoding="utf-8")
        # blank = same as source (migrate) / 7.4 (cross, set below)
        target = request.form.get("fortios", "").strip() or None

        try:
            if meta["vendor"] == "fortios":
                plan = _plan_from_form(request.form)
                tplat = request.form.get("target_platform", "").strip()
                if tplat == "__custom__":
                    tplat = request.form.get("target_platform_custom",
                                             "").strip()
                if tplat:
                    tplat, _ = platforms.resolve(tplat)
                tdev = tident = None
                if meta.get("target_ports"):
                    tdev = (meta.get("target_code", ""),
                            meta.get("target_version", ""),
                            tuple(meta["target_ports"]))
                    tident = meta.get("target_identity") or None
                    # the destination backup's own code is authoritative
                    tplat = tplat or meta.get("target_code") or None
                result = pipeline.run_migrate(
                    text, meta["name"], plan, target=target,
                    source_os=request.form.get("source_os", "").strip()
                    or None,
                    target_platform=tplat or None,
                    vdom_mode=request.form.get("vdom_mode", "keep"),
                    vdom_name=request.form.get("vdom_name", "root").strip()
                    or "root",
                    vdom_scope_only=bool(request.form.get("vdom_scope_only")),
                    hw_switch=("convert" if request.form.get("hw_switch")
                               else "keep"),
                    sslvpn_to_ipsec=bool(request.form.get("sslvpn_to_ipsec")),
                    sslvpn_psk=request.form.get("sslvpn_psk", "").strip()
                    or "CHANGEME-SET-A-REAL-PSK",
                    target_device=tdev, target_identity=tident,
                    want_normalized=True)
            else:
                mapping = _mapping_from_form(request.form)
                vdom_mode = request.form.get("vdom_mode", "keep")
                # 'flat' on a multi-vsys source converts ONE vsys (the picker);
                # in multi-VDOM mode the hidden picker is ignored so every vsys
                # becomes its own VDOM
                pa_vsys = (request.form.get("pa_vsys", "").strip()
                           if vdom_mode == "keep" else "")
                parser_opts = {
                    k: v for k, v in {
                        "device_group":
                            request.form.get("pa_dg", "").strip(),
                        "template":
                            request.form.get("pa_template", "").strip(),
                        "vsys": pa_vsys,
                    }.items() if v}
                result = pipeline.run_cross(
                    text, meta["vendor"], meta["name"], mapping,
                    target=target or "7.4",
                    tuning=_tuning_from_form(request.form, meta),
                    nat_mode=request.form.get("nat_mode", "policy"),
                    parser_opts=parser_opts or None,
                    authoring=_authoring_from_form(request.form),
                    # wrap a single-context source into one named VDOM when the
                    # cross-vendor VDOM toggle asks for it (multi-vsys is always
                    # one-VDOM-per-vsys regardless)
                    vdom_mode=vdom_mode,
                    vdom_name=request.form.get("vdom_name", "root").strip()
                    or "root",
                    vdom_scope_only=bool(request.form.get("vdom_scope_only")),
                    # per-application App-ID when a FortiGuard app DB has been
                    # cached (fwforge app-db <host>); else category-level
                    app_db=appdb_mod.newest())
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
        # name outputs after the destination device when its backup is
        # present — the converted file IS that box's config
        if meta.get("target_hostname"):
            stem = platforms.safe_filename(meta["target_hostname"])
        else:
            stem = Path(meta["name"]).stem or "config"
            if stem.lower() in ("_source", "source", "report", "diff",
                                "bundle"):
                stem += "-converted"  # keep clear of the job's artifacts
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
            # what actually converted (per-VDOM summed) — surfaced as result
            # tiles so the outcome, not just errors/warnings, is front and center
            "converted": _converted_counts(result.cfg),
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

    @app.post("/job/<jid>/rerun")
    def rerun(jid):
        """Re-run the conversion with the exact settings of the last run —
        used by the result page after the App-ID gap analyzer adds apps."""
        meta = _job(jid)
        saved = meta.get("last_form")
        if not saved:
            return redirect(url_for(
                "job", jid=jid,
                error="run the conversion once before re-running"))
        # rebuild the submitted form, preserving multi-valued fields
        # (pol_keep, interface maps, members), then replay it through
        # convert() — which reads only request.form — in a fresh context
        form = MultiDict()
        for key, vals in saved.items():
            for v in (vals if isinstance(vals, list) else [vals]):
                form.add(key, v)
        with app.test_request_context(method="POST", data=form):
            return convert(jid)

    @app.post("/job/<jid>/apply_fix")
    def apply_fix(jid):
        """Apply an actionable Optimize-tab fix — disable dead rules, or
        reorder a bypassed DENY above the ACCEPT — on top of the last run's
        settings, then re-convert. The fix fields are merged into last_form so
        they persist (and accumulate) across further re-runs."""
        meta = _job(jid)
        saved = meta.get("last_form")
        if not saved:
            return redirect(url_for(
                "job", jid=jid,
                error="run the conversion once before applying a fix"))
        form = MultiDict()
        for k, vals in saved.items():
            for v in (vals if isinstance(vals, list) else [vals]):
                form.add(k, v)
        for field_name in ("disable_policy", "reorder_policy"):
            have = set(form.getlist(field_name))
            for v in request.form.getlist(field_name):
                if v and v not in have:
                    form.add(field_name, v)
                    have.add(v)
        with app.test_request_context(method="POST", data=form):
            return convert(jid)

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
        stem = (meta.get("result", {}).get("stem")
                or Path(meta["name"]).stem or "config")
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
        stem = (meta.get("result", {}).get("stem")
                or Path(meta["name"]).stem or "config")
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

    @app.post("/job/<jid>/ai")
    def ai_feature(jid):
        from .ai_advisor import (conversion_summary, explain_finding,
                                 research_app_gaps, merge_to_user_db)
        meta = _job(jid)
        r = meta.get("result", {})
        if not r:
            return {"ok": False, "error": "No conversion result yet"}, 400
        body = request.get_json(force=True, silent=True) or {}
        feature = body.get("feature", "")
        vendor = VENDOR_LABELS.get(meta.get("vendor", ""), meta.get("vendor", ""))
        target = r.get("target", "7.4")
        try:
            if feature == "summary":
                return {"ok": True, "text": conversion_summary(vendor, target, r)}

            elif feature == "explain":
                area = body.get("area", "")
                message = body.get("message", "")
                if not message:
                    return {"ok": False, "error": "message required"}, 400
                return {"ok": True, "text": explain_finding(
                    area, message, vendor, target)}

            elif feature == "gaps":
                findings = r.get("findings", {})
                all_f = (findings.get("warn") or []) + (findings.get("info") or [])
                entries, raw = research_app_gaps(all_f, vendor)
                if entries:
                    count, path = merge_to_user_db(entries)
                    # hot-reload the App-ID tables so the new entries take
                    # effect for the next conversion without restarting fwforge
                    from ..parsers import pan_appid
                    _, user_total = pan_appid.reload()
                    return {"ok": True, "count": count,
                            "apps": list(entries.keys()),
                            "path": path, "raw": raw,
                            "reloaded": True, "app_db_user": user_total}
                return {"ok": True, "count": 0, "apps": [], "raw": raw,
                        "text": raw or "No unmapped App-IDs found in findings."}

            else:
                return {"ok": False, "error": f"Unknown feature: {feature!r}"}, 400

        except RuntimeError as e:
            return {"ok": False, "error": str(e)}, 503
        except Exception as e:
            return {"ok": False,
                    "error": f"{type(e).__name__}: {e}"}, 500

    return app
