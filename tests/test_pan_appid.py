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
    # ssh/dns map to FortiOS built-in services; the custom erp-app keeps
    # a synthesized appdef service. All collapse into one port group.
    assert "ALL" not in tight.services
    assert len(tight.services) == 1
    grp = next(g for g in cfg.svc_groups if g.name == tight.services[0])
    assert "SSH" in grp.members and "DNS" in grp.members
    erp = next(s for s in cfg.services if s.name in grp.members
               and s.protocol == "tcp")
    assert "8443" in erp.dst_ports and "9000-9010" in erp.dst_ports
    msgs = [m for _, _, m, _ in cfg.meta["findings"]]
    assert any("port-based service" in m for m in msgs)


def test_application_default_dynamic_falls_back():
    cfg = paloalto.parse(APPDEF, "appdef.xml")
    loose = next(p for p in cfg.policies if p.name == "Loose")
    assert loose.services == ["ALL"]      # dyn-app has dynamic ports
    msgs = [m for _, _, m, _ in cfg.meta["findings"]]
    assert any("no default-port data" in m and "dyn-app" in m
               for m in msgs)


def test_enterprise_app_mappings():
    # ports for the Microsoft/enterprise apps (incl. _norm suffix forms)
    assert pan_appid.default_ports("msrpc") == [("tcp", "135")]
    assert pan_appid.default_ports("msrpc-base") == [("tcp", "135")]
    assert pan_appid.default_ports("ms-ds-smbv2") == [("tcp", "139 445")]
    assert pan_appid.default_ports("mssql-db-encrypted") == [("tcp", "1433")]
    assert pan_appid.default_ports("active-directory-base") is not None
    assert pan_appid.default_ports("windows-remote-management") == \
        [("tcp", "5985 5986")]
    # categories
    cats, ids, transport, unmapped = pan_appid.map_apps(
        ["msrpc", "ms-ds-smbv2", "mssql-db-encrypted",
         "active-directory-base", "okta", "windows-remote-management",
         "snmp-trap", "webdav"])
    assert unmapped == []
    for c in ("Network.Service", "Storage.Backup", "Business",
              "Cloud.IT", "Remote.Access", "Web.Client"):
        assert c in cats


APPGRP = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip>
      <entry name="10.0.0.1/24"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1">
    <zone><entry name="trust"><network><layer3>
      <member>ethernet1/1</member></layer3></network></entry></zone>
    <application-group>
      <entry name="jabil_serv_mysql_smb_app"><members>
        <member>mysql</member><member>ms-ds-smbv2</member>
        <member>msrpc</member></members></entry>
    </application-group>
    <rulebase><security><rules>
      <entry name="GrpRule">
        <from><member>trust</member></from><to><member>trust</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>jabil_serv_mysql_smb_app</member></application>
        <service><member>application-default</member></service>
        <action>allow</action>
      </entry>
    </rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_appgroup_expanded_for_appcontrol_and_ports():
    # a rule referencing a CUSTOM app-group expands to its member apps:
    # it must get an app-control profile (not "no category") and the
    # application-default service tightens to the members' real ports
    cfg = paloalto.parse(APPGRP, "grp.xml")
    rule = next(p for p in cfg.policies if p.name == "GrpRule")
    assert rule.app_list and rule.app_list.startswith("pan-appctrl-")
    al = next(a for a in cfg.app_lists if a.name == rule.app_list)
    # mysql->Business, ms-ds-smbv2->Storage.Backup, msrpc->Network.Service
    assert set(al.cat_names) == {"Business", "Storage.Backup",
                                 "Network.Service"}
    # the group name did NOT survive as an unmapped App-ID
    msgs = [m for _, _, m, _ in cfg.meta["findings"]]
    assert not any("jabil_serv_mysql_smb_app" in m
                   and "no FortiOS app-control" in m for m in msgs)
    # application-default tightened to FortiGate services — no "kept as ALL"
    assert not any("GrpRule" in m and "kept as ALL" in m for m in msgs)
    grp = next(g for g in cfg.svc_groups if g.name == rule.services[0])
    # mysql -> built-in MYSQL, ms-ds-smbv2 -> built-in SMB, msrpc -> a
    # custom appdef service (tcp 135, no FortiOS built-in for MS-RPC)
    assert "MYSQL" in grp.members and "SMB" in grp.members
    rpc = next(s for s in cfg.services if s.name in grp.members
               and s.protocol == "tcp")
    assert "135" in rpc.dst_ports


ANYAPPS = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip>
      <entry name="10.0.0.1/24"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1">
    <zone><entry name="trust"><network><layer3>
      <member>ethernet1/1</member></layer3></network></entry></zone>
    <rulebase><security><rules>
      <entry name="AnyRule">
        <from><member>trust</member></from><to><member>trust</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>ssh</member><member>dns</member>
          <member>snmp</member></application>
        <service><member>any</member></service>
        <action>allow</action>
      </entry>
    </rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_service_any_apps_become_port_group():
    # the chosen behavior: service=any + App-IDs -> port-based policy
    # (a port group here, since ssh/dns/snmp span protocols), with the
    # app-control profile kept on top
    cfg = paloalto.parse(ANYAPPS, "any.xml")
    rule = next(p for p in cfg.policies if p.name == "AnyRule")
    assert "ALL" not in rule.services
    assert len(rule.services) == 1 and rule.services[0].startswith("appsvc-grp-")
    grp = next(g for g in cfg.svc_groups if g.name == rule.services[0])
    # ssh/dns/snmp -> FortiOS built-in service names (no custom objects)
    assert set(grp.members) == {"SSH", "DNS", "SNMP"}
    assert rule.app_list                      # app-control kept (both)
    msgs = [m for _, _, m, _ in cfg.meta["findings"]]
    assert any("service=any" in m and "port-based service" in m
               for m in msgs)
