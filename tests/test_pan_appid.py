from pathlib import Path

from fwforge import cli
from fwforge.parsers import pan_appid, paloalto

FIX = Path(__file__).parent / "fixtures"

APPCFG = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip>
      <entry name="10.0.0.1/24"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1">
    <zone><entry name="trust"><network><layer3>
      <member>ethernet1/1</member></layer3></network></entry></zone>
    <rulebase><security><rules>
      <entry name="App Rule">
        <from><member>trust</member></from>
        <to><member>trust</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application>
          <member>web-browsing</member>
          <member>facebook-base</member>
          <member>youtube-base</member>
          <member>ssl</member>
          <member>custom-internal-app</member>
        </application>
        <service><member>any</member></service>
        <action>allow</action>
      </entry>
      <entry name="Web Only">
        <from><member>trust</member></from>
        <to><member>trust</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>web-browsing</member></application>
        <service><member>any</member></service>
        <action>allow</action>
      </entry>
    </rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_map_apps():
    cats, ids, transport, unmapped = pan_appid.map_apps(
        ["web-browsing", "facebook-base", "ssl", "custom-app", "any"])
    assert cats == ["Web.Client", "Social.Media"]
    assert ids == [25, 23]
    assert transport == ["ssl"]
    assert unmapped == ["custom-app"]


def test_category_ids_known():
    # every mapped category resolves to an id
    for cat in set(pan_appid.APP_TO_CAT.values()):
        assert cat in pan_appid.CATEGORY_ID


def test_applist_built_and_deduped():
    cfg = paloalto.parse(APPCFG, "app.xml")
    app_rule = next(p for p in cfg.policies if p.name == "App Rule")
    web_rule = next(p for p in cfg.policies if p.name == "Web Only")
    assert app_rule.app_list == "pan-appctrl-1"
    # categories: web-browsing, facebook, youtube -> 3 cats
    al = next(a for a in cfg.app_lists if a.name == "pan-appctrl-1")
    assert al.categories == [25, 23, 5]  # Web.Client, Social.Media, Video
    # the web-only rule maps to a DIFFERENT set -> its own profile
    assert web_rule.app_list == "pan-appctrl-2"
    assert len(cfg.app_lists) == 2

    msgs = [m for _, _, m, _ in cfg.meta["findings"]]
    assert any("transport app(s) ignored: ssl" in m for m in msgs)
    assert any("UNMAPPED (add manually): custom-internal-app" in m
               for m in msgs)


def test_applist_dedup_same_set(tmp_path):
    # two rules with the same app set share one profile
    cfg = paloalto.parse(
        APPCFG.replace("<member>web-browsing</member></application>",
                       "<member>web-browsing</member>"
                       "<member>facebook-base</member>"
                       "<member>youtube-base</member>"
                       "<member>ssl</member>"
                       "<member>custom-internal-app</member></application>"),
        "x.xml")
    assert len({p.app_list for p in cfg.policies}) == 1
    assert len(cfg.app_lists) == 1


def test_e2e_emits_application_list(tmp_path):
    (tmp_path / "app.xml").write_text(APPCFG, encoding="utf-8")
    rc = cli.main(["convert", str(tmp_path / "app.xml"), "-o", str(tmp_path),
                   "--map", str(_write_map(tmp_path))])
    assert rc == 0
    conf = (tmp_path / "app.config-all.txt").read_text(encoding="utf-8")
    assert "config application list" in conf
    assert 'edit "pan-appctrl-1"' in conf
    assert "set category 25 23 5" in conf
    assert "set other-application-action block" in conf
    blocks = conf.split("    edit ")
    apppol = next(b for b in blocks if 'set name "App_Rule"' in b)
    assert 'set application-list "pan-appctrl-1"' in apppol
    assert "set utm-status enable" in apppol


def _write_map(tmp_path):
    m = tmp_path / "ports.map"
    m.write_text("ethernet1/1 = port1\n", encoding="utf-8")
    return m


def test_pa_sample_still_maps(tmp_path):
    # the original sample's 'Out Web' rule (web-browsing, ssl) now also
    # gets an application-list, and existing behavior is intact
    cfg = paloalto.parse((FIX / "pa_sample.xml").read_text(encoding="utf-8"),
                         "pa_sample.xml")
    out = next(p for p in cfg.policies if p.name == "Out Web")
    assert out.app_list == "pan-appctrl-1"
    al = cfg.app_lists[0]
    assert al.categories == [25]  # web-browsing -> Web.Client; ssl ignored
    assert "PAN apps: web-browsing, ssl" in out.comment  # comment preserved


APPDEF = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip>
      <entry name="10.0.0.1/24"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1">
    <zone><entry name="trust"><network><layer3>
      <member>ethernet1/1</member></layer3></network></entry></zone>
    <application>
      <entry name="erp-app"><default><port>
        <member>tcp/8443</member><member>tcp/9000-9010</member>
      </port></default></entry>
      <entry name="dyn-app"><default><port>
        <member>tcp/dynamic</member></port></default></entry>
    </application>
    <application-group>
      <entry name="biz-apps"><members>
        <member>erp-app</member><member>ssh</member></members></entry>
    </application-group>
    <rulebase><security><rules>
      <entry name="Tight"><from><member>trust</member></from>
        <to><member>trust</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>biz-apps</member><member>dns</member></application>
        <service><member>application-default</member></service>
        <action>allow</action></entry>
      <entry name="Loose"><from><member>trust</member></from>
        <to><member>trust</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>dyn-app</member></application>
        <service><member>application-default</member></service>
        <action>allow</action></entry>
    </rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_default_ports_lookup():
    assert pan_appid.default_ports("dns") == [("tcp/udp", "53")]
    assert pan_appid.default_ports("facebook-base") == [("tcp", "80 443")]
    assert pan_appid.default_ports("bittorrent") is None   # dynamic
    assert pan_appid.default_ports("ssl") == [("tcp", "443")]


def test_application_default_tightened():
    cfg = paloalto.parse(APPDEF, "appdef.xml")
    tight = next(p for p in cfg.policies if p.name == "Tight")
    # custom erp-app (file ports) + ssh + dns resolved -> real services
    assert "ALL" not in tight.services
    names = " ".join(tight.services)
    assert "8443" in names and "22" in names
    svc = next(s for s in cfg.services if "8443" in s.name)
    assert svc.protocol == "tcp"
    assert "9000-9010" in svc.dst_ports
    dns_svc = next(s for s in cfg.services if s.name in tight.services
                   and s.protocol == "tcp/udp")
    assert dns_svc.dst_ports == "53"
    msgs = [m for _, _, m, _ in cfg.meta["findings"]]
    assert any("tightened to" in m for m in msgs)


def test_application_default_dynamic_falls_back():
    cfg = paloalto.parse(APPDEF, "appdef.xml")
    loose = next(p for p in cfg.policies if p.name == "Loose")
    assert loose.services == ["ALL"]      # dyn-app has dynamic ports
    msgs = [m for _, _, m, _ in cfg.meta["findings"]]
    assert any("no default-port data" in m and "dyn-app" in m
               for m in msgs)
