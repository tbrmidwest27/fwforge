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


def test_target_platform_resolved_from_model_number(client):
    # the real-world case: '701g' typed/posted instead of FG7H1G
    jid = _load(client, "fortios_refactor.conf")
    form = {
        "fortios": "7.6",
        "source_os": "7.6",
        "target_platform": "701g",
        "map_src": ["port1", "port2", "port3", "port4", "vlan30"],
        "map_dst": ["port1", "port2", "port3", "port4", "vlan30"],
    }
    client.post(f"/job/{jid}/convert", data=form, follow_redirects=True)
    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert conf.startswith("#config-version=FG7H1G-")

    # custom-code path: the dropdown posts __custom__ + the text field
    form["target_platform"] = "__custom__"
    form["target_platform_custom"] = "fg1k8f"
    client.post(f"/job/{jid}/convert", data=form, follow_redirects=True)
    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert conf.startswith("#config-version=FG1K8F-")

    # garbage is rejected back to the wizard with the hint, not converted
    form["target_platform"] = "purple"
    page = client.post(f"/job/{jid}/convert", data=form,
                       follow_redirects=True).data.decode()
    assert "not a FortiGate platform code" in page

    # the wizard page itself ships the dropdown
    page = client.get(f"/job/{jid}").data.decode()
    assert 'name="target_platform"' in page
    assert "FG7H1G" in page and "FortiGate 701G" in page


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
    # the SD-WAN/zone Restructure STEP is fortios-only (the JS helpers may
    # still mention SD-WAN; check the step itself isn't rendered)
    assert 'data-title="Restructure"' not in page


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


def test_bom_prefixed_config_detected(client, tmp_path):
    # PowerShell 5.1 Out-File utf8 prepends a BOM; detection must survive
    src = tmp_path / "bom.conf"
    src.write_bytes(b"\xef\xbb\xbf" + (FIX / "fortios_sample.conf").read_bytes())
    resp = client.post("/load", data={"path": str(src)},
                       follow_redirects=False)
    assert resp.status_code == 302
    jid = resp.headers["Location"].rstrip("/").split("/")[-1]
    assert webui_app.JOBS[jid]["vendor"] == "fortios"


def test_port_inventory_shipped_to_wizard(client):
    jid = _load(client, "fortios_refactor.conf")
    page = client.get(f"/job/{jid}").data.decode()
    assert 'id="tp-ports"' in page          # datalist for map_dst inputs
    assert '"FG7H1G"' in page and "lan22" in page  # inventory JSON inline


def test_destination_backup_drives_migration(client):
    import io
    src = (FIX / "fortios_refactor.conf").read_bytes()
    tgt = b"""#config-version=FG7H1G-8.0.0-FW-build0167-260420:opmode=0:vdom=0:user=admin
config system interface
    edit "mgmt"
        set type physical
    next
    edit "wan1"
        set type physical
    next
    edit "lan1"
        set type physical
    next
end
"""
    resp = client.post("/load", data={
        "config": (io.BytesIO(src), "src.conf"),
        "target_config": (io.BytesIO(tgt), "factory-701g.conf"),
    }, content_type="multipart/form-data", follow_redirects=False)
    assert resp.status_code == 302
    jid = resp.headers["Location"].rstrip("/").split("/")[-1]

    # wizard shows the destination as authoritative (no dropdown)
    page = client.get(f"/job/{jid}").data.decode()
    assert "FG7H1G" in page and "factory-701g.conf" in page
    assert 'id="tp-select"' not in page
    assert "TARGET_PORTS" in page and "wan1" in page

    form = {
        "fortios": "",            # blank: pinned by the destination
        "source_os": "7.6",
        "map_src": ["port1", "port2", "port3", "port4", "vlan30"],
        "map_dst": ["wan1", "lan1", "port3", "port4", "vlan30"],
    }
    resp = client.post(f"/job/{jid}/convert", data=form,
                       follow_redirects=True)
    page = resp.data.decode()
    # unmapped physical ports flagged against the real inventory
    assert "do not exist on the destination" in page
    assert "port3" in page and "port4" in page

    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert conf.startswith("#config-version=FG7H1G-")
    assert 'edit "wan1"' in conf  # portmap applied


def test_faceplates_shipped_to_wizard(client):
    jid = _load(client, "fortios_refactor.conf")
    page = client.get(f"/job/{jid}").data.decode()
    assert 'id="fp-src"' in page and 'id="fp-dst"' in page
    assert "FACEPLATES" in page and "5G RJ45" in page  # 700G spec inline
    # the fixture header platform is captured for the source panel
    assert webui_app.JOBS[jid]["source_platform"] == "FGT601F"
    # a FortiOS source is not "foreign" — keeps the FortiGate styling
    assert "const SOURCE_FOREIGN = false" in page


def test_cross_vendor_source_faceplate_labeled_by_vendor(client):
    # regression: a Palo Alto source panel must identify as its own
    # vendor, not silently default to "FortiGate" — there is no FortiGate
    # platform code for a non-FortiOS source, so the wordmark fell back to
    # the hardcoded "FortiGate" and the panel read as the wrong device.
    jid = _load(client, "pa_sample.xml")
    page = client.get(f"/job/{jid}").data.decode()
    assert 'id="fp-src"' in page                       # source panel renders
    assert 'const SOURCE_LABEL = "Palo Alto"' in page  # drives the wordmark
    assert "const SOURCE_FOREIGN = true" in page        # drops Forti styling
    # the source has no FortiGate platform code — exactly the condition
    # that made the old fallback mislabel it
    assert not webui_app.JOBS[jid].get("source_platform")


def test_cross_vendor_vdom_toggle_wraps_output(client):
    # a single-context cross-vendor source offers the VDOM-mode toggle;
    # choosing 'multi' wraps the whole conversion into one named VDOM
    jid = _load(client, "pa_sample.xml")
    page = client.get(f"/job/{jid}").data.decode()
    assert 'name="vdom_mode"' in page          # toggle present for cross-vendor
    assert 'name="vdom_name"' in page
    assert "one VDOM per vsys" not in page      # single-vsys -> not the note

    form = {
        "fortios": "7.4",
        "map_src": ["ethernet1/1", "ethernet1/2", "ethernet1/2.30"],
        "map_dst": ["wan1", "internal1", "vlan30"],
        "vdom_mode": "multi",
        "vdom_name": "CUST1",
    }
    client.post(f"/job/{jid}/convert", data=form, follow_redirects=True)
    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert "config global" in conf
    assert 'edit "CUST1"' in conf
    # per-VDOM sections wrapped inside the VDOM
    assert conf.index("config firewall policy") > conf.index("config global")


MULTIVSYS_MIN = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip>
      <entry name="10.0.0.1/24"/></ip></layer3></entry>
    <entry name="ethernet1/2"><layer3><ip>
      <entry name="10.1.0.1/24"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys>
    <entry name="vsys1"><import><network><interface>
      <member>ethernet1/1</member></interface></network></import>
      <zone><entry name="z1"><network><layer3>
        <member>ethernet1/1</member></layer3></network></entry></zone>
      <rulebase><security><rules><entry name="v1-allow">
        <from><member>z1</member></from><to><member>z1</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>allow</action></entry></rules></security></rulebase>
    </entry>
    <entry name="vsys2"><import><network><interface>
      <member>ethernet1/2</member></interface></network></import>
      <zone><entry name="z2"><network><layer3>
        <member>ethernet1/2</member></layer3></network></entry></zone>
      <rulebase><security><rules><entry name="v2-allow">
        <from><member>z2</member></from><to><member>z2</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>allow</action></entry></rules></security></rulebase>
    </entry>
  </vsys>
</entry></devices></config>"""


def test_multivsys_flat_recommends_multivdom_and_picks_one_vsys(client):
    import io
    resp = client.post("/load", data={
        "config": (io.BytesIO(MULTIVSYS_MIN.encode()), "mv.xml")},
        content_type="multipart/form-data", follow_redirects=False)
    jid = resp.headers["Location"].rstrip("/").split("/")[-1]

    # multi-vsys detected: toggle defaults to multi-VDOM (recommended), ships
    # the per-vsys picker and the flatten-is-dangerous recommendation
    page = client.get(f"/job/{jid}").data.decode()
    assert 'name="vdom_mode"' in page
    assert "recommended" in page
    assert 'name="pa_vsys"' in page
    assert "overlapping IPs" in page              # the recommendation banner

    # choosing flat + one vsys converts ONLY that vsys, flat (no VDOMs)
    form = {
        "fortios": "7.4",
        "map_src": ["ethernet1/1", "ethernet1/2"],
        "map_dst": ["wan1", "internal1"],
        "vdom_mode": "keep",
        "pa_vsys": "vsys1",
    }
    client.post(f"/job/{jid}/convert", data=form, follow_redirects=True)
    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert "config vdom" not in conf              # flat
    assert 'set name "v1-allow"' in conf          # the picked vsys
    assert 'set name "v2-allow"' not in conf      # the other vsys excluded


def test_multivsys_multivdom_ignores_stale_vsys_pick(client):
    # the picker is hidden in multi-VDOM mode but still posts its value; the
    # backend must ignore it so every vsys still becomes its own VDOM
    import io
    resp = client.post("/load", data={
        "config": (io.BytesIO(MULTIVSYS_MIN.encode()), "mv.xml")},
        content_type="multipart/form-data", follow_redirects=False)
    jid = resp.headers["Location"].rstrip("/").split("/")[-1]
    form = {
        "fortios": "7.4",
        "map_src": ["ethernet1/1", "ethernet1/2"],
        "map_dst": ["wan1", "internal1"],
        "vdom_mode": "multi",
        "pa_vsys": "vsys1",          # stale value from the hidden picker
    }
    client.post(f"/job/{jid}/convert", data=form, follow_redirects=True)
    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert "config vdom" in conf
    assert 'set name "v1-allow"' in conf
    assert 'set name "v2-allow"' in conf          # NOT restricted to vsys1


def test_authoring_from_form_parsing():
    from werkzeug.datastructures import MultiDict
    form = MultiDict([
        ("agg_name_0", "bond0"), ("agg_lacp_0", "passive"),
        ("agg_members_0", "x5,x6,x7"),
        ("vparent_src", "ae1.1"), ("vparent_dst", "bond0"),
        ("vparent_src", "v2"), ("vparent_dst", "x1")])
    a = webui_app._authoring_from_form(form)
    assert a["aggregates"] == [
        {"name": "bond0", "lacp": "passive", "members": ["x5", "x6", "x7"]}]
    assert a["vlan_parents"] == {"ae1.1": "bond0", "v2": "x1"}
    assert webui_app._authoring_from_form(MultiDict()) is None


def test_mapping_from_form_skips_do_not_map():
    from werkzeug.datastructures import MultiDict
    form = MultiDict([
        ("map_src", "ethernet1/1"), ("map_dst", "lan1"),
        ("map_src", "ethernet1/2"), ("map_dst", "__none__"),  # "do not map"
        ("map_src", "ethernet1/3"), ("map_dst", ""),          # blank
        ("map_src", "tunnel.1"), ("map_dst", "tunnel.1")])
    m = webui_app._mapping_from_form(form)
    # the skipped + blank interfaces are left out; the rest map through
    assert m == {"ethernet1/1": "lan1", "tunnel.1": "tunnel.1"}


def test_membership_column_live_wiring(client):
    # the membership column is tagged per-interface and enriched live by
    # JS so an aggregate shows its mapped member ports and every nested
    # VLAN shows the parent LAG + ports it rides, tracking dropdown edits
    jid = _load(client, "pa_sample.xml")
    page = client.get(f"/job/{jid}").data.decode()
    assert "<th>members</th>" in page             # FortiOS-style members col
    assert "data-mem=" in page                    # members cells tagged
    assert "function buildTree" in page           # FortiOS-style tree grouping
    assert "function refreshMembership" in page  # live updater shipped
    assert ".memports" in page                   # member-port styling
    # the live authoring panel + per-VLAN parent control + serialization
    assert 'id="agg-panel"' in page
    assert "function addAgg" in page and "function serializeAggs" in page
    assert 'name="vparent_src"' in page and 'class="vparent"' in page
    # physical rows carry the in-place physical<->aggregate type toggle, and
    # VLAN parents now inherit their parent's mapped target by default
    assert 'class="iftype"' in page and "function ifTypeChanged" in page
    assert "function safeIfName" in page
    assert "vlanParent(d)" in page                # refreshNestOptions default
    # a physical port can be left unmapped ("do not map") which frees it to
    # be bonded into a LAG
    assert "— do not map —" in page and 'SKIP_PORT = "__none__"' in page


def test_aggregate_ports_multiselect(client):
    # aggregate member ports can be added several at once via a multi-select
    # listbox + an "add" button (not just one port per dropdown change)
    jid = _load(client, "pa_sample.xml")
    page = client.get(f"/job/{jid}").data.decode()
    assert "function addPortPicker" in page
    assert "function aggAddSelected" in page
    assert 'class="addport" multiple' in page    # multi-select listbox emitted


def test_destination_identity_and_filename(client):
    import io
    src = (FIX / "fortios_refactor.conf").read_bytes()
    tgt = b"""#config-version=FG7H1G-8.0.0-FW-build0167-260420:opmode=0:vdom=0:user=admin
config system global
    set hostname "edge-fw-01"
    set alias "FortiGate-701G"
end
config system interface
    edit "mgmt"
        set type physical
    next
    edit "wan1"
        set type physical
    next
    edit "lan1"
        set type physical
    next
end
"""
    resp = client.post("/load", data={
        "config": (io.BytesIO(src), "src.conf"),
        "target_config": (io.BytesIO(tgt), "edge-fw-01_backup.conf"),
    }, content_type="multipart/form-data", follow_redirects=False)
    jid = resp.headers["Location"].rstrip("/").split("/")[-1]
    assert webui_app.JOBS[jid]["target_hostname"] == "edge-fw-01"

    form = {
        "fortios": "", "source_os": "7.6",
        "map_src": ["port1", "port2", "port3", "port4", "vlan30"],
        "map_dst": ["wan1", "lan1", "mgmt", "lan1", "vlan30"],
    }
    client.post(f"/job/{jid}/convert", data=form, follow_redirects=True)
    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    # destination identity carried onto the output, source name gone
    assert 'set hostname "edge-fw-01"' in conf
    assert "refactor-src" not in conf
    # output is named for the destination device
    assert webui_app.JOBS[jid]["result"]["stem"] == "edge-fw-01"
    assert webui_app.JOBS[jid]["result"]["main_name"] == "edge-fw-01.conf"


def test_mapping_grid_shows_zone_membership(client):
    # a pre-zoned source: the fixture's port1 is in "legacy-zone" — the
    # mapping grid should surface that so you see the zone structure
    jid = _load(client, "fortios_refactor.conf")
    page = client.get(f"/job/{jid}").data.decode()
    assert "<th>type</th>" in page                # membership now the type col
    assert "b-zone" in page
    assert "zone: legacy-zone" in page


def test_physical_ports_are_target_dropdowns(client):
    # physical source ports become <select> dropdowns of destination
    # ports; VLANs keep a free-text input (their names carry over)
    jid = _load(client, "fortios_refactor.conf")
    page = client.get(f"/job/{jid}").data.decode()
    assert '<select name="map_dst"' in page
    assert 'data-src="port1"' in page        # physical -> dropdown
    assert 'data-src="vlan30"' not in page    # vlan -> text input
    assert "populateSelects" in page          # dropdown-fill JS shipped


def test_port_guess_prefills_dropdowns(client):
    import io, json, re
    src = (FIX / "fortios_refactor.conf").read_bytes()
    tgt = b"""#config-version=FG7H1G-8.0.0-FW-build0167-260420:opmode=0:vdom=0:user=admin
config system interface
    edit "mgmt"
        set type physical
    next
    edit "lan1"
        set type physical
    next
    edit "lan2"
        set type physical
    next
    edit "lan3"
        set type physical
    next
    edit "lan4"
        set type physical
    next
end
"""
    resp = client.post("/load", data={
        "config": (io.BytesIO(src), "src.conf"),
        "target_config": (io.BytesIO(tgt), "dst.conf"),
    }, content_type="multipart/form-data", follow_redirects=False)
    jid = resp.headers["Location"].rstrip("/").split("/")[-1]
    page = client.get(f"/job/{jid}").data.decode()
    assert "GUESS_BACKUP" in page
    m = re.search(r'const GUESS_BACKUP = (\{[^}]*\});', page)
    gb = json.loads(m.group(1))
    # the fixture's port1..port4 guess onto the destination's lan1..lan4
    assert gb.get("port1") == "lan1"
    assert gb.get("port4") == "lan4"


def test_cross_origin_post_rejected(client):
    # CSRF: a state-changing POST from another origin must be refused; a
    # same-origin POST (matching the test client's host) still works.
    resp = client.post("/load",
                       data={"path": str(FIX / "fortios_refactor.conf")},
                       headers={"Origin": "http://evil.example"},
                       follow_redirects=False)
    assert resp.status_code == 403
    resp = client.post("/load",
                       data={"path": str(FIX / "fortios_refactor.conf")},
                       headers={"Origin": "http://localhost"},
                       follow_redirects=False)
    assert resp.status_code == 302   # same-origin allowed


def test_esc_escapes_single_quote(client):
    # DOM-XSS guard: the client-side esc() must escape the single quote, since
    # interface/port names (read verbatim from an uploaded config) are
    # interpolated into single-quoted inline handlers. Assert the fix ships in
    # the template (runtime behavior needs a JS engine, out of scope here).
    jid = _load(client, "fortios_refactor.conf")
    page = client.get(f"/job/{jid}").data.decode()
    assert "/'/g" in page and "&#39;" in page


def test_upload_size_capped(client):
    # unbounded uploads are a memory-exhaustion DoS; a cap must be set
    assert webui_app.create_app().config["MAX_CONTENT_LENGTH"] == 25 * 1024 * 1024


def test_detect_endpoint_recognizes_and_handles_unknown(client):
    pan_head = ('<?xml version="1.0"?>\n'
                '<config urldb="paloaltonetworks"><devices>'
                '<entry name="localhost.localdomain"><vsys/>'
                '</entry></devices></config>')
    j = client.post("/detect", data={"head": pan_head}).get_json()
    assert j["vendor"] == "paloalto"
    assert j["label"] == "Palo Alto"
    assert j["confidence"]
    # gibberish -> unknown, no crash, no label
    j2 = client.post("/detect",
                     data={"head": "lorem ipsum not a config at all"}).get_json()
    assert j2["vendor"] in ("unknown", "")
    assert not j2["label"]
    # empty -> empty
    j3 = client.post("/detect", data={"head": "  "}).get_json()
    assert j3["vendor"] == ""


def test_index_ships_live_detection(client):
    page = client.get("/").data.decode()
    assert 'id="cfg-file"' in page        # the file input the readout hooks
    assert 'id="cfg-detect"' in page      # the live readout element
    assert "/detect" in page              # the fetch target
    assert "FileReader" in page           # reads the head client-side
