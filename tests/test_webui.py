from pathlib import Path

import pytest

flask = pytest.importorskip("flask")

from fwforge.webui import app as webui_app  # noqa: E402

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(webui_app, "JOBS_DIR", tmp_path / "jobs")
    monkeypatch.setattr(webui_app, "JOBS", {})
    app = webui_app.create_app()
    app.testing = True
    return app.test_client()


def _load(client, fixture):
    resp = client.post("/load", data={"path": str(FIX / fixture)},
                       follow_redirects=False)
    assert resp.status_code == 302
    jid = resp.headers["Location"].rstrip("/").split("/")[-1]
    return jid


def test_index(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"New conversion" in resp.data
    assert b"Cisco ASA" in resp.data  # vendor tiles


def test_load_and_wizard_page(client):
    jid = _load(client, "fortios_refactor.conf")
    page = client.get(f"/job/{jid}").data.decode()
    assert "Conversion wizard" in page
    assert "port1" in page and "vlan30" in page
    assert "Interface Mapping" in page
    assert "SD-WAN" in page          # restructure step for fortios
    assert "Policy Selection" not in page  # cross-vendor step only

    # home now lists the project with a draft status
    home = client.get("/").data.decode()
    assert "fortios_refactor.conf" in home
    assert "draft" in home


def test_migrate_convert_with_zone(client):
    jid = _load(client, "fortios_refactor.conf")
    form = {
        "fortios": "7.6",
        "source_os": "7.6",
        "target_platform": "",
        "map_src": ["port1", "port2", "port3", "port4", "vlan30"],
        "map_dst": ["port1", "port2", "port3", "port4", "vlan30"],
        "zone_name_0": "lan",
        "zone_intrazone_0": "deny",
        "zone_members_0": ["port2", "vlan30"],
        "zone_vdom_0": "",
    }
    resp = client.post(f"/job/{jid}/convert", data=form,
                       follow_redirects=True)
    page = resp.data.decode()
    assert "converted" in page
    assert "zones created" in page.replace("_", " ")
    assert "same-zone" in page          # findings tab content
    assert "pane-output" in page        # output preview tab
    assert "pane-changes" in page       # diff tab (migrate)
    assert 'edit &#34;lan&#34;' in page or 'edit "lan"' in page

    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert 'edit "lan"' in conf
    assert 'set srcintf "lan"' in conf


def test_iface_details_in_analysis(client):
    jid = _load(client, "fortios_refactor.conf")
    det = {d["name"]: d for d in webui_app.JOBS[jid]["iface_details"]}
    assert det["port2"]["ip"] == "10.10.0.1/16"
    assert det["port2"]["role"] == "lan"
    assert det["port2"]["policy_refs"] == 3      # srcintf in policies 1-3
    assert det["vlan30"]["type"] == "vlan"
    assert det["vlan30"]["vlanid"] == "30"
    assert det["vlan30"]["parent"] == "port2"
    assert det["port1"]["zone"] == "legacy-zone"  # disabled in the picker
    assert det["port3"]["type"] == "physical"
    # the wizard page ships the details to the member-picker JS
    page = client.get(f"/job/{jid}").data.decode()
    assert "legacy-zone" in page
    assert "10.10.0.1/16" in page
    assert "alias / description" in page          # mapping hint columns


def test_sdwan_from_checkbox_picker(client):
    jid = _load(client, "fortios_refactor.conf")
    form = {
        "fortios": "7.6",
        "source_os": "7.6",
        "map_src": ["port1", "port2", "port3", "port4", "vlan30"],
        "map_dst": ["port1", "port2", "port3", "port4", "vlan30"],
        "sdwan_name_0": "virtual-wan-link",
        "sdwan_member_0": ["port3", "port4"],     # checkbox picker
        "sdwan_gw_0_port3": "",                   # blank = harvest route
        "sdwan_weight_0_port3": "",
        "sdwan_gw_0_port4": "198.51.100.1",
        "sdwan_weight_0_port4": "10",
        "sdwan_hc_0": "ping 8.8.8.8",
        "sdwan_rule_0": "auto",
        "sdwan_vdom_0": "",
    }
    resp = client.post(f"/job/{jid}/convert", data=form,
                       follow_redirects=True)
    assert "converted" in resp.data.decode()
    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert "config system sdwan" in conf
    assert "set gateway 203.0.113.1" in conf      # harvested for port3
    assert "set gateway 198.51.100.1" in conf
    assert "set weight 10" in conf


def test_sdwan_legacy_text_syntax_still_accepted(client):
    jid = _load(client, "fortios_refactor.conf")
    form = {
        "fortios": "7.6",
        "map_src": ["port3"], "map_dst": ["port3"],
        "sdwan_name_0": "virtual-wan-link",
        "sdwan_members_0": "port3 gateway=203.0.113.1, port4 weight=10",
        "sdwan_hc_0": "", "sdwan_rule_0": "auto", "sdwan_vdom_0": "",
    }
    client.post(f"/job/{jid}/convert", data=form, follow_redirects=True)
    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert "config system sdwan" in conf
    assert "set weight 10" in conf


def test_cross_wizard_has_policy_selection(client):
    jid = _load(client, "asa_sample.cfg")
    page = client.get(f"/job/{jid}").data.decode()
    assert "Cisco ASA" in page
    assert "Policy Selection" in page
    assert "OUTSIDE-IN-1" in page       # parsed rules listed
    assert "SD-WAN" not in page         # fortios-only step


def test_policy_selection_excludes(client):
    jid = _load(client, "asa_sample.cfg")
    keep = ["OUTSIDE-IN-1", "OUTSIDE-IN-2", "INSIDE-OUT-1", "INSIDE-OUT-2",
            "INSIDE-OUT-3", "INSIDE-OUT-4", "INSIDE-OUT-5", "DMZ-IN-1"]
    form = {"fortios": "7.4",
            "pol_present": "1",
            "pol_keep": keep,           # OUTSIDE-IN-3 unticked
            "map_src": ["outside", "inside", "dmz"],
            "map_dst": ["wan1", "internal1", "dmz"]}
    resp = client.post(f"/job/{jid}/convert", data=form,
                       follow_redirects=True)
    page = resp.data.decode()
    assert "rule filter dropped 1" in page
    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert 'set name "OUTSIDE-IN-3"' not in conf
    assert 'set name "OUTSIDE-IN-1"' in conf


def test_cross_convert_reports_unmapped(client):
    jid = _load(client, "asa_sample.cfg")
    form = {"fortios": "7.4",
            "map_src": ["outside", "inside", "dmz"],
            "map_dst": ["wan1", "internal1", ""]}  # dmz left unmapped
    resp = client.post(f"/job/{jid}/convert", data=form,
                       follow_redirects=True)
    page = resp.data.decode()
    assert "not mapped" in page
    assert "dmz" in page
    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert 'set srcintf "wan1"' in conf


def test_plan_error_round_trips(client):
    jid = _load(client, "fortios_refactor.conf")
    form = {
        "fortios": "7.6",
        "map_src": ["port1"], "map_dst": ["port1"],
        "zone_name_0": "bad", "zone_intrazone_0": "deny",
        "zone_members_0": ["port1"],  # port1 is already in legacy-zone
        "zone_vdom_0": "",
    }
    resp = client.post(f"/job/{jid}/convert", data=form,
                       follow_redirects=True)
    page = resp.data.decode()
    assert "plan error" in page
    assert "legacy-zone" in page


def test_upgrade_artifacts_shown(client):
    jid = _load(client, "fortios_74_legacy.conf")
    form = {"fortios": "8.0", "source_os": "7.4",
            "map_src": ["port1", "port2"], "map_dst": ["port1", "port2"]}
    resp = client.post(f"/job/{jid}/convert", data=form,
                       follow_redirects=True)
    page = resp.data.decode()
    assert "SSL-VPN" in page
    assert "7.4 -&gt; 8.0" in page or "7.4 -> 8.0" in page


def test_vdom_mapping_step(client):
    jid = _load(client, "fortios_multivdom.conf")
    page = client.get(f"/job/{jid}").data.decode()
    assert "VDOM Mapping" in page
    assert 'name="vmap_src" value="FGSP"' in page

    form = {"fortios": "8.0",
            "map_src": ["port1"], "map_dst": ["port1"],
            "vmap_src": ["root", "FGSP"],
            "vmap_dst": ["root", "EDGE"]}
    client.post(f"/job/{jid}/convert", data=form, follow_redirects=True)
    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert 'edit "EDGE"' in conf
    assert "FGSP" not in conf


def test_output_tab_branch_selector(client):
    jid = _load(client, "asa_sample.cfg")
    client.post(f"/job/{jid}/convert",
                data={"fortios": "7.4",
                      "map_src": ["outside"], "map_dst": ["wan1"]},
                follow_redirects=True)
    page = client.get(f"/job/{jid}/result").data.decode()
    assert ".branches/" in page  # selector lists branch files
    branch = "asa_sample.branches/01-firewall-address.txt"
    page2 = client.get(f"/job/{jid}/result?file={branch}").data.decode()
    assert "config firewall address" in page2
    assert 'ACTIVE = "output"' in page2  # lands on the Output tab
    # html audit report downloadable
    rep = client.get(f"/job/{jid}/dl/report.html")
    assert rep.status_code == 200
    assert b"fwforge conversion report" in rep.data


def test_fmg_bundle_from_gui(client):
    jid = _load(client, "asa_sample.cfg")
    resp = client.post(
        f"/job/{jid}/convert",
        data={"fortios": "7.4", "fmg_enable": "1", "fmg_adom": "lab",
              "fmg_pkg": "",
              "map_src": ["outside"], "map_dst": ["wan1"]},
        follow_redirects=True)
    page = resp.data.decode()
    assert "FortiManager bundle (.json)" in page
    dl = client.get(f"/job/{jid}/dl/fmg")
    assert dl.status_code == 200
    import json as _json
    bundle = _json.loads(dl.data)
    assert bundle["fortimanager"]["adom"] == "lab"
    assert any("/pm/pkg/adom/lab" in r["params"][0]["url"]
               for r in bundle["requests"])


def test_jobs_persist_across_restart(client, tmp_path, monkeypatch):
    jid = _load(client, "fortios_sample.conf")
    # simulate a fresh server start against the same jobs dir
    monkeypatch.setattr(webui_app, "JOBS", {})
    app2 = webui_app.create_app()
    app2.testing = True
    c2 = app2.test_client()
    home = c2.get("/").data.decode()
    assert "fortios_sample.conf" in home
    page = c2.get(f"/job/{jid}").data.decode()
    assert "Interface Mapping" in page


def test_delete_job(client):
    jid = _load(client, "fortios_sample.conf")
    assert (webui_app.JOBS_DIR / jid / "_source.conf").is_file()
    resp = client.post(f"/job/{jid}/delete", follow_redirects=True)
    assert resp.status_code == 200
    assert "fortios_sample.conf" not in resp.data.decode()
    assert not (webui_app.JOBS_DIR / jid).exists()
    assert client.get(f"/job/{jid}").status_code == 404


def test_upload_named_source_conf_does_not_clobber(client):
    import io
    text = (FIX / "fortios_sample.conf").read_bytes()
    resp = client.post("/load", data={
        "config": (io.BytesIO(text), "source.conf")},
        content_type="multipart/form-data", follow_redirects=False)
    jid = resp.headers["Location"].rstrip("/").split("/")[-1]
    client.post(f"/job/{jid}/convert",
                data={"fortios": "7.4", "map_src": ["port1"],
                      "map_dst": ["port1"]},
                follow_redirects=True)
    # the saved source survives the conversion untouched
    saved = (webui_app.JOBS_DIR / jid / "_source.conf").read_text(
        encoding="utf-8")
    assert "fwforge conversion" not in saved
    # and the converted output is a separate, downloadable artifact
    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert "fwforge conversion" in conf
    # re-running converts the ORIGINAL, not the previous output
    client.post(f"/job/{jid}/convert",
                data={"fortios": "7.4", "map_src": ["port1"],
                      "map_dst": ["port1"]},
                follow_redirects=True)
    conf2 = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert conf2.count("fwforge conversion") == 1


def test_untouched_sdwan_row_does_not_block_convert(client):
    jid = _load(client, "fortios_refactor.conf")
    form = {
        "fortios": "7.6",
        "map_src": ["port1"], "map_dst": ["port1"],
        # an added-but-untouched SD-WAN card posts the pre-filled name
        "sdwan_name_0": "virtual-wan-link",
        "sdwan_members_0": "", "sdwan_hc_0": "",
        "sdwan_rule_0": "auto", "sdwan_vdom_0": "",
    }
    resp = client.post(f"/job/{jid}/convert", data=form,
                       follow_redirects=True)
    page = resp.data.decode()
    assert "plan error" not in page
    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert "config system sdwan" not in conf


def test_old_job_without_iface_details_heals_on_open(client):
    import json as _json
    jid = _load(client, "fortios_refactor.conf")
    jdir = webui_app.JOBS_DIR / jid
    # turn it into a pre-v0.21 job: no iface_details, old source name
    meta = _json.loads((jdir / "job.json").read_text(encoding="utf-8"))
    meta.pop("iface_details", None)
    (jdir / "job.json").write_text(_json.dumps(meta), encoding="utf-8")
    (jdir / "_source.conf").rename(jdir / "source.conf")
    webui_app.JOBS[jid].pop("iface_details", None)

    page = client.get(f"/job/{jid}").data.decode()
    assert "10.10.0.1/16" in page                 # details re-derived
    det = {d["name"]: d for d in webui_app.JOBS[jid]["iface_details"]}
    assert det["port1"]["zone"] == "legacy-zone"
    # and the healed meta is persisted for the next restart
    saved = _json.loads((jdir / "job.json").read_text(encoding="utf-8"))
    assert saved["iface_details"]
