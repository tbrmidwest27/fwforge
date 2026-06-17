from pathlib import Path

import pytest

from fwforge import cli, pipeline
from fwforge.parsers import fortios_tree as ft
from fwforge.parsers import paloalto
from fwforge.parsers.paloalto import PanoramaChoiceNeeded
from fwforge.transforms import tree_refs

FIX = Path(__file__).parent / "fixtures"

MULTIVSYS = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network>
    <interface><ethernet>
      <entry name="ethernet1/1"><layer3><ip>
        <entry name="203.0.113.2/29"/></ip></layer3></entry>
      <entry name="ethernet1/2"><layer3><ip>
        <entry name="10.1.0.1/24"/></ip></layer3></entry>
      <entry name="ethernet1/3"><layer3><ip>
        <entry name="198.51.100.2/29"/></ip></layer3></entry>
      <entry name="ethernet1/4"><layer3><ip>
        <entry name="10.2.0.1/24"/></ip></layer3></entry>
    </ethernet></interface>
    <virtual-router>
      <entry name="vr1">
        <interface><member>ethernet1/1</member>
          <member>ethernet1/2</member></interface>
        <routing-table><ip><static-route>
          <entry name="d1"><destination>0.0.0.0/0</destination>
            <nexthop><ip-address>203.0.113.1</ip-address></nexthop>
            <interface>ethernet1/1</interface></entry>
        </static-route></ip></routing-table>
      </entry>
      <entry name="vr2">
        <interface><member>ethernet1/3</member>
          <member>ethernet1/4</member></interface>
        <routing-table><ip><static-route>
          <entry name="d2"><destination>0.0.0.0/0</destination>
            <nexthop><ip-address>198.51.100.1</ip-address></nexthop>
            <interface>ethernet1/3</interface></entry>
        </static-route></ip></routing-table>
      </entry>
    </virtual-router>
  </network>
  <vsys>
    <entry name="vsys1">
      <import><network>
        <interface><member>ethernet1/1</member>
          <member>ethernet1/2</member></interface>
        <virtual-router><member>vr1</member></virtual-router>
      </network></import>
      <zone>
        <entry name="v1-out"><network><layer3>
          <member>ethernet1/1</member></layer3></network></entry>
        <entry name="v1-in"><network><layer3>
          <member>ethernet1/2</member></layer3></network></entry>
      </zone>
      <address><entry name="V1NET">
        <ip-netmask>10.1.0.0/24</ip-netmask></entry></address>
      <rulebase><security><rules>
        <entry name="v1-allow"><from><member>v1-in</member></from>
          <to><member>v1-out</member></to>
          <source><member>V1NET</member></source>
          <destination><member>any</member></destination>
          <application><member>any</member></application>
          <service><member>any</member></service>
          <action>allow</action></entry>
      </rules></security></rulebase>
    </entry>
    <entry name="vsys2">
      <import><network>
        <interface><member>ethernet1/3</member>
          <member>ethernet1/4</member></interface>
        <virtual-router><member>vr2</member></virtual-router>
      </network></import>
      <zone>
        <entry name="v2-out"><network><layer3>
          <member>ethernet1/3</member></layer3></network></entry>
      </zone>
      <rulebase><security><rules>
        <entry name="v2-allow"><from><member>any</member></from>
          <to><member>v2-out</member></to>
          <source><member>any</member></source>
          <destination><member>any</member></destination>
          <application><member>any</member></application>
          <service><member>any</member></service>
          <action>allow</action></entry>
      </rules></security></rulebase>
    </entry>
  </vsys>
</entry></devices></config>"""


# multi-vsys with VLAN subinterfaces — the emitter *creates* logical
# interfaces (VLANs/aggregates/loopbacks) but not physical ports, so this is
# what exercises the device-global interface hoist (MULTIVSYS above is all
# physical and emits no `config system interface`).
MULTIVSYS_VLAN = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3>
      <ip><entry name="172.31.0.1/24"/></ip>
      <units>
        <entry name="ethernet1/1.30"><tag>30</tag>
          <ip><entry name="10.30.0.1/24"/></ip></entry>
        <entry name="ethernet1/1.40"><tag>40</tag>
          <ip><entry name="10.40.0.1/24"/></ip></entry>
      </units></layer3></entry>
  </ethernet></interface></network>
  <vsys>
    <entry name="vsys1"><import><network><interface>
      <member>ethernet1/1.30</member></interface></network></import>
      <zone><entry name="z1"><network><layer3>
        <member>ethernet1/1.30</member></layer3></network></entry></zone>
      <rulebase><security><rules>
        <entry name="r1"><from><member>z1</member></from>
          <to><member>z1</member></to>
          <source><member>any</member></source>
          <destination><member>any</member></destination>
          <application><member>any</member></application>
          <service><member>any</member></service>
          <action>allow</action></entry>
      </rules></security></rulebase>
    </entry>
    <entry name="vsys2"><import><network><interface>
      <member>ethernet1/1.40</member></interface></network></import>
      <zone><entry name="z2"><network><layer3>
        <member>ethernet1/1.40</member></layer3></network></entry></zone>
      <rulebase><security><rules>
        <entry name="r2"><from><member>z2</member></from>
          <to><member>z2</member></to>
          <source><member>any</member></source>
          <destination><member>any</member></destination>
          <application><member>any</member></application>
          <service><member>any</member></service>
          <action>allow</action></entry>
      </rules></security></rulebase>
    </entry>
  </vsys>
</entry></devices></config>"""


def test_multivsys_parses_per_vsys():
    cfg = paloalto.parse(MULTIVSYS, "mv.xml")
    scopes = cfg.meta["vsys_cfgs"]
    assert [n for n, _ in scopes] == ["vsys1", "vsys2"]
    v1, v2 = scopes[0][1], scopes[1][1]
    # interfaces split by import
    assert {i.name for i in v1.interfaces} == {"ethernet1/1",
                                               "ethernet1/2"}
    assert {i.name for i in v2.interfaces} == {"ethernet1/3",
                                               "ethernet1/4"}
    # routes follow the imported virtual-router
    assert [r.gateway for r in v1.routes] == ["203.0.113.1"]
    assert [r.gateway for r in v2.routes] == ["198.51.100.1"]
    # rules stay in their vsys
    assert [p.name for p in v1.policies] == ["v1-allow"]
    assert [p.name for p in v2.policies] == ["v2-allow"]
    # sibling findings carry the vsys tag
    msgs2 = [m for _, _, m, _ in v2.meta["findings"]]
    assert all("[vsys vsys2]" in m for m in msgs2 if m)


def test_multivsys_pipeline_emits_vdom_blocks():
    result = pipeline.run_cross(MULTIVSYS, "paloalto", "mv.xml", {})
    out = result.out_text
    assert "config vdom" in out
    # group the output by the VDOM block each line belongs to
    segs: dict[str, list[str]] = {}
    cur = None
    prev = ""
    for line in out.splitlines():
        if prev == "config vdom" and line.startswith("edit "):
            cur = line.split()[1]
        if cur:
            segs.setdefault(cur, []).append(line)
        prev = line
    s1 = "\n".join(segs.get("vsys1", []))
    s2 = "\n".join(segs.get("vsys2", []))
    assert 'set name "v1-allow"' in s1
    assert 'set name "v1-allow"' not in s2
    assert 'set name "v2-allow"' in s2
    assert 'set name "v2-allow"' not in s1
    assert "vsys_vdoms" in result.report.meta


SINGLE_VSYS = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip>
      <entry name="10.0.0.1/24"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1">
    <zone>
      <entry name="trust"><network><layer3>
        <member>ethernet1/1</member></layer3></network></entry>
      <entry name="untrust"><network><layer3>
        <member>ethernet1/1</member></layer3></network></entry>
    </zone>
    <rulebase><security><rules>
      <entry name="allow1"><from><member>trust</member></from>
        <to><member>untrust</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>allow</action></entry>
    </rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_cross_single_vsys_flat_by_default():
    out = pipeline.run_cross(SINGLE_VSYS, "paloalto", "s.xml", {}).out_text
    # default keeps today's behaviour: flat, no VDOM wrapping
    assert "config vdom" not in out
    assert "config global" not in out
    assert "config firewall policy" in out


def test_cross_single_vsys_wraps_into_named_vdom():
    result = pipeline.run_cross(SINGLE_VSYS, "paloalto", "s.xml", {},
                                vdom_mode="multi", vdom_name="CUST1")
    out = result.out_text
    assert "config global" in out
    assert 'edit "CUST1"' in out
    # per-VDOM sections moved inside the VDOM (after config global); the
    # cross emitter has no interface section, so global ends up empty
    assert out.index("config system zone") > out.index("config global")
    assert out.index("config firewall policy") > out.index("config global")
    # the can't-set-vdom-mode-for-you caveat is surfaced
    assert any(f.area == "vdom-mode" and "Enable multi-VDOM" in f.message
               for f in result.report.findings)
    assert result.report.meta.get("vdom_mode") == "-> multi-VDOM (VDOM 'CUST1')"


def test_cross_multivsys_single_mode_warns_and_stays_multi():
    # a multi-vsys source can't collapse to one flat config; asking for
    # 'single' warns but still emits one VDOM per vsys
    result = pipeline.run_cross(MULTIVSYS, "paloalto", "mv.xml", {},
                                vdom_mode="single")
    assert "config vdom" in result.out_text
    assert 'set name "v1-allow"' in result.out_text
    assert 'set name "v2-allow"' in result.out_text
    assert any(f.area == "vdom-mode" and "cannot flatten" in f.message
               for f in result.report.findings)


def test_multivsys_branch_files(tmp_path):
    src = tmp_path / "mv.xml"
    src.write_text(MULTIVSYS, encoding="utf-8")
    rc = cli.main(["convert", str(src), "-o", str(tmp_path / "out")])
    assert rc == 0
    names = [p.name for p in
             sorted((tmp_path / "out" / "mv.branches").glob("*.txt"))]
    assert any("vsys1-firewall-policy" in n for n in names)
    assert any("vsys2-firewall-policy" in n for n in names)
    assert any(n.endswith("-vdom.txt") for n in names)  # creation block
    pol = next(p for p in
               (tmp_path / "out" / "mv.branches").glob("*vsys1-firewall-policy*"))
    text = pol.read_text(encoding="utf-8")
    assert text.startswith("config vdom\nedit vsys1\n")  # paste-safe
    assert text.rstrip().endswith("end")


PANO_PUSHED = MULTIVSYS.replace(
    "</devices></config>",
    "</devices><panorama><vsys><entry name=\"vsys1\">"
    "<pre-rulebase><security><rules>"
    "<entry name=\"pano-pre\"><from><member>any</member></from>"
    "<to><member>any</member></to><source><member>any</member></source>"
    "<destination><member>any</member></destination>"
    "<application><member>any</member></application>"
    "<service><member>any</member></service><action>deny</action></entry>"
    "</rules></security></pre-rulebase>"
    "<post-rulebase><security><rules>"
    "<entry name=\"pano-post\"><from><member>any</member></from>"
    "<to><member>any</member></to><source><member>any</member></source>"
    "<destination><member>any</member></destination>"
    "<application><member>any</member></application>"
    "<service><member>any</member></service><action>deny</action></entry>"
    "</rules></security></post-rulebase>"
    "</entry></vsys></panorama></config>")


def test_panorama_pushed_rule_order():
    cfg = paloalto.parse(PANO_PUSHED, "pp.xml")
    v1 = cfg.meta["vsys_cfgs"][0][1]
    assert [p.name for p in v1.policies] == [
        "pano-pre", "v1-allow", "pano-post"]
    msgs = [m for _, _, m, _ in v1.meta["findings"]]
    assert any("Panorama-pushed rulebases merged" in m for m in msgs)


PANORAMA = """<config version="11.0.0">
<shared>
  <address><entry name="SHARED-NET">
    <ip-netmask>172.16.0.0/16</ip-netmask></entry></address>
  <pre-rulebase><security><rules>
    <entry name="shared-pre"><from><member>any</member></from>
      <to><member>any</member></to>
      <source><member>any</member></source>
      <destination><member>any</member></destination>
      <application><member>any</member></application>
      <service><member>any</member></service>
      <action>deny</action></entry>
  </rules></security></pre-rulebase>
</shared>
<devices><entry name="localhost.localdomain">
  <device-group>
    <entry name="branch-dg">
      <address><entry name="DG-NET">
        <ip-netmask>10.5.0.0/24</ip-netmask></entry></address>
      <pre-rulebase><security><rules>
        <entry name="dg-pre"><from><member>lan</member></from>
          <to><member>wan</member></to>
          <source><member>DG-NET</member></source>
          <destination><member>any</member></destination>
          <application><member>any</member></application>
          <service><member>any</member></service>
          <action>allow</action></entry>
      </rules></security></pre-rulebase>
      <post-rulebase><security><rules>
        <entry name="dg-post"><from><member>any</member></from>
          <to><member>any</member></to>
          <source><member>any</member></source>
          <destination><member>any</member></destination>
          <application><member>any</member></application>
          <service><member>any</member></service>
          <action>deny</action></entry>
      </rules></security></post-rulebase>
    </entry>
    <entry name="dc-dg">
      <pre-rulebase><security><rules>
        <entry name="dc-rule"><from><member>any</member></from>
          <to><member>any</member></to>
          <source><member>any</member></source>
          <destination><member>any</member></destination>
          <application><member>any</member></application>
          <service><member>any</member></service>
          <action>allow</action></entry>
      </rules></security></pre-rulebase>
    </entry>
  </device-group>
  <template>
    <entry name="branch-tmpl"><config><devices>
      <entry name="localhost.localdomain">
        <network><interface><ethernet>
          <entry name="ethernet1/1"><layer3><ip>
            <entry name="198.18.5.2/29"/></ip></layer3></entry>
          <entry name="ethernet1/2"><layer3><ip>
            <entry name="10.5.0.1/24"/></ip></layer3></entry>
        </ethernet></interface></network>
        <vsys><entry name="vsys1"><zone>
          <entry name="wan"><network><layer3>
            <member>ethernet1/1</member></layer3></network></entry>
          <entry name="lan"><network><layer3>
            <member>ethernet1/2</member></layer3></network></entry>
        </zone></entry></vsys>
      </entry>
    </devices></config></entry>
  </template>
</entry></devices></config>"""


def test_panorama_needs_choice_with_multiple_dgs():
    with pytest.raises(PanoramaChoiceNeeded) as ei:
        paloalto.parse(PANORAMA, "pano.xml")
    assert ei.value.device_groups == ["branch-dg", "dc-dg"]
    assert ei.value.templates == ["branch-tmpl"]


def test_panorama_device_group_with_template():
    cfg = paloalto.parse(PANORAMA, "pano.xml",
                         device_group="branch-dg",
                         template="branch-tmpl")
    # rules merge shared-pre + dg pre + dg post
    assert [p.name for p in cfg.policies] == [
        "shared-pre", "dg-pre", "dg-post"]
    # objects: device-group + shared
    assert cfg.address_by_name("DG-NET") is not None
    assert cfg.address_by_name("SHARED-NET") is not None
    # network + zones from the template
    assert cfg.interface_by_name("ethernet1/2") is not None
    assert {z.name for z in cfg.zones} == {"wan", "lan"}
    assert cfg.meta["panorama"]["device_group"] == "branch-dg"


def test_panorama_cli_lists_choices(tmp_path, capsys):
    src = tmp_path / "pano.xml"
    src.write_text(PANORAMA, encoding="utf-8")
    rc = cli.main(["convert", str(src), "-o", str(tmp_path / "out")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--pa-device-group branch-dg" in err
    assert "--pa-template branch-tmpl" in err
    # and the explicit choice converts
    rc2 = cli.main(["convert", str(src), "-o", str(tmp_path / "out"),
                    "--pa-device-group", "branch-dg",
                    "--pa-template", "branch-tmpl"])
    assert rc2 == 0
    conf = (tmp_path / "out" / "pano.config-all.txt").read_text(
        encoding="utf-8")
    assert 'set name "dg-pre"' in conf
    assert 'set srcintf "lan"' in conf  # template zone carried through


PANO_POST_ORDER = """<config version="11.0.0">
<shared>
  <post-rulebase><security><rules>
    <entry name="shared-post"><from><member>any</member></from>
      <to><member>any</member></to><source><member>any</member></source>
      <destination><member>any</member></destination>
      <application><member>any</member></application>
      <service><member>any</member></service><action>deny</action></entry>
  </rules></security></post-rulebase>
</shared>
<devices><entry name="localhost.localdomain">
  <device-group><entry name="dg1">
    <post-rulebase><security><rules>
      <entry name="dg-post"><from><member>any</member></from>
        <to><member>any</member></to><source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>allow</action></entry>
    </rules></security></post-rulebase>
  </entry></device-group>
</entry></devices></config>"""


def test_panorama_post_rulebase_order():
    # PAN evaluation order: device-group post BEFORE shared post
    cfg = paloalto.parse(PANO_POST_ORDER, "p.xml", device_group="dg1")
    names = [p.name for p in cfg.policies]
    assert names.index("dg-post") < names.index("shared-post")


def test_application_default_keeps_named_service():
    xml = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip>
      <entry name="10.0.0.1/24"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1">
    <zone><entry name="t"><network><layer3>
      <member>ethernet1/1</member></layer3></network></entry></zone>
    <service><entry name="custom-8888"><protocol><tcp>
      <port>8888</port></tcp></protocol></entry></service>
    <rulebase><security><rules>
      <entry name="Mixed"><from><member>t</member></from>
        <to><member>t</member></to><source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>dns</member></application>
        <service><member>application-default</member>
          <member>custom-8888</member></service>
        <action>allow</action></entry>
    </rules></security></rulebase>
  </entry></vsys>
</entry></devices></config>"""
    cfg = paloalto.parse(xml, "m.xml")
    p = cfg.policies[0]
    # dns -> FortiOS built-in DNS service AND the explicit custom-8888
    # named service are both present
    assert "custom-8888" in p.services
    assert "DNS" in p.services


def test_base_interface_not_duplicated_across_vsys():
    xml = """<config version="11.0.0"><devices>
<entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3>
      <ip><entry name="172.31.0.1/24"/></ip>
      <units>
        <entry name="ethernet1/1.30"><tag>30</tag>
          <ip><entry name="10.30.0.1/24"/></ip></entry>
        <entry name="ethernet1/1.40"><tag>40</tag>
          <ip><entry name="10.40.0.1/24"/></ip></entry>
      </units></layer3></entry>
  </ethernet></interface></network>
  <vsys>
    <entry name="vsys1"><import><network><interface>
      <member>ethernet1/1.30</member></interface></network></import>
      <zone><entry name="z1"><network><layer3>
        <member>ethernet1/1.30</member></layer3></network></entry></zone>
    </entry>
    <entry name="vsys2"><import><network><interface>
      <member>ethernet1/1.40</member></interface></network></import>
      <zone><entry name="z2"><network><layer3>
        <member>ethernet1/1.40</member></layer3></network></entry></zone>
    </entry>
  </vsys>
</entry></devices></config>"""
    cfg = paloalto.parse(xml, "dup.xml")
    scopes = dict(cfg.meta["vsys_cfgs"])
    v1 = {i.name for i in scopes["vsys1"].interfaces}
    v2 = {i.name for i in scopes["vsys2"].interfaces}
    # each vsys gets only its own subinterface, NOT the shared base
    assert v1 == {"ethernet1/1.30"}
    assert v2 == {"ethernet1/1.40"}


# --- multi-VDOM scope-split guardrails (Feature A) ---------------------
# A multi-vsys conversion must emit a *valid* multi-VDOM config: interfaces
# are device-global (config global, tagged `set vdom <vsys>`), firewall /
# router / zone are per-VDOM, and one VDOM is the management VDOM.

def _multivdom_scopes(out_text):
    """Re-parse a cross-vendor multi-VDOM script and return (tree, {scope:
    node}) — the same view the FortiOS loader/migrator sees."""
    tree = ft.parse_config(out_text, "out")
    return tree, dict(ft.vdom_scopes(tree))


def test_multivsys_output_is_valid_multi_vdom():
    out = pipeline.run_cross(MULTIVSYS_VLAN, "paloalto", "mv.xml", {}).out_text
    tree, scopes = _multivdom_scopes(out)
    assert not tree.warnings                       # balanced config/edit/end
    assert tree_refs.is_multi_vdom(tree)
    assert set(scopes) == {"global", "vsys1", "vsys2"}


def test_multivsys_interfaces_hoisted_to_global_with_set_vdom():
    # the confirmed bug: created logical interfaces emitted `set vdom "root"`
    # buried inside the `edit <vsys>` wrapper. They must instead live in
    # config global, each tagged with the VDOM that owns it.
    out = pipeline.run_cross(MULTIVSYS_VLAN, "paloalto", "mv.xml", {}).out_text
    tree, scopes = _multivdom_scopes(out)
    # defined once, in the global scope
    assert ft.find_config_under(scopes["global"], "system", "interface")
    # NEVER inside a VDOM body (that would not load)
    for vd in ("vsys1", "vsys2"):
        assert ft.find_config_under(scopes[vd], "system", "interface") is None
    # owned by the right VDOM — not the bug's hardcoded 'root'
    assert tree_refs.interface_vdoms(tree) == {
        "ethernet1/1.30": "vsys1", "ethernet1/1.40": "vsys2"}
    assert 'set vdom "root"' not in out


def test_multivsys_designates_management_vdom():
    # FortiOS needs exactly one management VDOM; a PAN multi-vsys source has
    # no 'root', so the first vsys is designated (in the global scope).
    result = pipeline.run_cross(MULTIVSYS_VLAN, "paloalto", "mv.xml", {})
    out = result.out_text
    assert result.report.meta.get("management_vdom") == "vsys1"
    _, scopes = _multivdom_scopes(out)
    assert 'set management-vdom "vsys1"' in ft.serialize(scopes["global"])
    assert "set vdom-mode multi-vdom" in ft.serialize(scopes["global"])
    # not leaked into a VDOM body
    assert "management-vdom" not in ft.serialize(scopes["vsys1"])


def test_multivsys_routes_collapse_into_their_vdom():
    # each vsys' virtual-router collapses into ITS VDOM's routing table —
    # routes never cross VDOMs and never land in the global scope.
    out = pipeline.run_cross(MULTIVSYS, "paloalto", "mv.xml", {}).out_text
    tree, scopes = _multivdom_scopes(out)
    v1, v2 = ft.serialize(scopes["vsys1"]), ft.serialize(scopes["vsys2"])
    assert "config router static" in v1 and "203.0.113.1" in v1
    assert "config router static" in v2 and "198.51.100.1" in v2
    assert "198.51.100.1" not in v1 and "203.0.113.1" not in v2
    assert ft.find_config_under(scopes["global"], "router", "static") is None
