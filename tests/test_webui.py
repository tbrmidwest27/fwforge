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
    assert (webui_app.JOBS_DIR / jid / "source.conf").is_file()
    resp = client.post(f"/job/{jid}/delete", follow_redirects=True)
    assert resp.status_code == 200
    assert "fortios_sample.conf" not in resp.data.decode()
    assert not (webui_app.JOBS_DIR / jid).exists()
    assert client.get(f"/job/{jid}").status_code == 404
