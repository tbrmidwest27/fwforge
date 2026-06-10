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
    assert b"Load a firewall config" in resp.data


def test_load_and_plan_page(client):
    jid = _load(client, "fortios_refactor.conf")
    page = client.get(f"/job/{jid}").data.decode()
    assert "fortios" in page
    assert "port1" in page and "vlan30" in page
    assert "Interface mapping" in page
    assert "SD-WAN" in page  # restructure builders shown for fortios


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
    # policy 3 (port2 -> vlan30) became same-zone and is flagged
    assert "same-zone" in page
    # diff shows the new zone
    assert 'edit &#34;lan&#34;' in page or 'edit "lan"' in page

    conf = client.get(f"/job/{jid}/dl/conf").data.decode()
    assert 'edit "lan"' in conf
    assert 'set srcintf "lan"' in conf


def test_cross_convert_reports_unmapped(client):
    jid = _load(client, "asa_sample.cfg")
    page = client.get(f"/job/{jid}").data.decode()
    assert "cisco-asa" in page
    assert "SD-WAN" not in page  # builders are fortios-only

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
