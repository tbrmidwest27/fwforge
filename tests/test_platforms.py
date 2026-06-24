import pytest

from fwforge import platforms
from fwforge.transforms.plan import PlanError


def test_known_code_passthrough():
    code, note = platforms.resolve("FG9H1G")
    assert code == "FG9H1G"
    assert "confirm" in note  # derived entry carries a verify reminder


def test_verified_entry_has_no_note():
    assert platforms.resolve("FGT60F") == ("FGT60F", "")
    assert platforms.resolve("601F") == ("FG6H1F", "")
    # verified 2026-06-12 against a native 701G backup
    assert platforms.resolve("701G") == ("FG7H1G", "")


def test_bare_model_number_lowercase():
    # the real-world regression: '701g' typed into the platform field
    code, note = platforms.resolve("701g")
    assert code == "FG7H1G"


def test_product_name_and_sku():
    assert platforms.resolve("FortiGate 701G")[0] == "FG7H1G"
    assert platforms.resolve("FG-701G")[0] == "FG7H1G"
    assert platforms.resolve("fg-601f")[0] == "FG6H1F"


def test_bare_model_prefers_fortigate_over_fortiwifi():
    assert platforms.resolve("60F")[0] == "FGT60F"
    assert platforms.resolve("FortiWiFi 60F")[0] == "FWF60F"


def test_unknown_but_plausible_code_accepted():
    code, note = platforms.resolve("fg9k9f")
    assert code == "FG9K9F"
    assert "not in the known-model table" in note


def test_garbage_rejected():
    with pytest.raises(PlanError):
        platforms.resolve("purple")
    with pytest.raises(PlanError):
        platforms.resolve("  ")


def test_close_match_hint():
    with pytest.raises(PlanError) as e:
        platforms.resolve("601")
    assert "FG6H1F" in str(e.value)


def test_groups_cover_all_platforms():
    grouped = [p for _, items in platforms.GROUPS for p in items]
    assert sorted(grouped) == sorted(platforms.PLATFORMS)
    assert all(items for _, items in platforms.GROUPS)


def test_port_inventory():
    p701g = platforms.ports_for("FG7H1G")
    assert "wan1" in p701g and "lan22" in p701g and "x8" in p701g
    assert "mgmt" in p701g and "ha" in p701g
    assert "port1" not in p701g  # 700G series has no portN names
    p601f = platforms.ports_for("fg6h1f")  # case-insensitive
    assert "port24" in p601f and "x8" in p601f
    assert "lan1" not in p601f
    assert platforms.ports_for("FGT60F") == platforms.ports_for("FGT61F")
    assert platforms.ports_for("FG100F") == ()  # unconfirmed model


TARGET_CONF = """#config-version=FG7H1G-8.0.0-FW-build0167-260420:opmode=0:vdom=0:user=admin
config system interface
    edit "mgmt"
        set vdom "root"
        set type physical
    next
    edit "wan1"
        set vdom "root"
        set type physical
    next
    edit "lan1"
        set vdom "root"
        set type physical
    next
    edit "x1"
        set vdom "root"
        set type physical
    next
    edit "modem"
        set vdom "root"
    next
    edit "vlan10"
        set vdom "root"
        set interface "lan1"
        set vlanid 10
    next
    edit "ssl.root"
        set vdom "root"
        set type tunnel
    next
end
"""


def test_inventory_from_config():
    code, ver, ports = platforms.inventory_from_config(TARGET_CONF)
    assert code == "FG7H1G"
    assert ver == "8.0.0"
    # physical only: no modem, no vlan, no tunnel
    assert set(ports) == {"mgmt", "wan1", "lan1", "x1"}


def test_inventory_requires_header_and_interfaces():
    with pytest.raises(PlanError):
        platforms.inventory_from_config("config system interface\nend\n")
    with pytest.raises(PlanError):
        platforms.inventory_from_config(
            "#config-version=FG7H1G-8.0.0-FW-build0167-1:x\nconfig x\nend\n")


def test_expanded_lineup_resolves():
    # spot-check the lineup expansion: E-series H-substitution,
    # rugged/WiFi prefixes, thousands K-pattern
    assert platforms.resolve("300E")[0] == "FG3H0E"
    assert platforms.resolve("FortiGate Rugged 60F")[0] == "FGR60F"
    assert platforms.resolve("FortiWiFi 61F")[0] == "FWF61F"
    assert platforms.resolve("1800F")[0] == "FG1K8F"
    assert platforms.resolve("3001F")[0] == "FG3K1F"
    # bare "60F" still prefers the plain FortiGate over WiFi/Rugged
    assert platforms.resolve("60F")[0] == "FGT60F"


def test_lineup_ceiling_is_4801f():
    assert platforms.resolve("4801F")[0] == "FG4K81F"
    assert platforms.resolve("1801F")[0] == "FG1K81F"
    # nothing above the 4801F ceiling, no chassis series
    assert not any("6000" in p.model or "7000" in p.model
                   or "7081" in p.model for p in platforms.PLATFORMS)


def test_faceplates_match_port_inventory():
    # every faceplate must cover exactly its model's port inventory —
    # the GUI lights ports by name, so drift = dark/phantom ports
    for code, spec in platforms.FACEPLATES.items():
        fp_ports = {p for g in spec for p in g["ports"]}
        assert fp_ports == set(platforms.PORT_INVENTORY[code]), code


def test_header_platform():
    assert platforms.header_platform(
        "#config-version=FG7H1G-7.4.11-FW-build2878-1:x\n") == "FG7H1G"
    assert platforms.header_platform("config system global\nend\n") == ""


def test_601f_faceplate_has_distinct_25g_bank():
    # x5-x8 are 25G SFP28 (verified: speed 25000full in the 601F backup),
    # x1-x4 are 10G SFP+ — they must be separate, correctly-labeled banks
    spec = platforms.FACEPLATES["FG6H1F"]
    by_label = {g["label"]: tuple(g["ports"]) for g in spec}
    assert by_label["10G SFP+"] == ("x1", "x2", "x3", "x4")
    assert by_label["25G SFP28"] == ("x5", "x6", "x7", "x8")


def test_device_identity_and_safe_filename():
    cfg = """#config-version=FG7H1G-7.4.11-FW-build2878-1:x
config system global
    set hostname "701G-TOP"
    set alias "FortiGate-701G"
    set admin-sport 8443
end
"""
    ident = platforms.device_identity(cfg)
    assert ident == {"hostname": "701G-TOP", "alias": "FortiGate-701G"}
    # filename sanitation
    assert platforms.safe_filename("701G-TOP") == "701G-TOP"
    assert platforms.safe_filename("DC Firewall/A:1") == "DC_Firewall_A_1"
    assert platforms.safe_filename("") == "config"


def test_guess_portmap_601f_to_701g():
    src = ["mgmt", "ha"] + [f"port{i}" for i in range(1, 25)] \
        + [f"x{i}" for i in range(1, 9)]
    dst = list(platforms.ports_for("FG7H1G"))   # mgmt,ha,wan1-2,lan1-22,x1-8
    g = platforms.guess_portmap(src, dst)
    # exact names keep themselves
    assert g["mgmt"] == "mgmt" and g["ha"] == "ha"
    assert g["x1"] == "x1" and g["x8"] == "x8"
    # the user's example: port1 -> lan1, positionally through lan22
    assert g["port1"] == "lan1"
    assert g["port22"] == "lan22"
    # ambiguous ports left for the user (no lan23/24; wan1/2 spare)
    assert "port23" not in g and "port24" not in g
    # never double-maps a destination
    assert len(set(g.values())) == len(g.values())


def test_guess_portmap_no_dest_is_empty():
    assert platforms.guess_portmap(["port1", "port2"], []) == {}


# -- version-DB drift check -------------------------------------------------

def test_ver_key_orders_patches_numerically():
    # the whole reason for a numeric key: "7.4.12" < "7.4.8" as STRINGS
    assert platforms._ver_key("7.4.12") > platforms._ver_key("7.4.8")
    assert platforms._ver_key("8.0") > platforms._ver_key("7.6.99")


def test_drift_none_when_db_is_current():
    # feed back exactly what the DB already holds -> no drift
    observed = dict(platforms.FORTIOS_LATEST_PATCH)
    drift = platforms.version_db_drift(observed)
    assert not drift.has_drift
    assert drift.new_trains == ()
    assert drift.patch_updates == ()


def test_drift_detects_newer_patch():
    current = platforms.FORTIOS_LATEST_PATCH["7.4"]
    observed = dict(platforms.FORTIOS_LATEST_PATCH)
    observed["7.4"] = "7.4.99"  # a future patch newer than whatever is seeded
    drift = platforms.version_db_drift(observed)
    assert drift.has_drift
    assert ("7.4", current, "7.4.99") in drift.patch_updates


def test_drift_ignores_older_or_equal_patch():
    observed = dict(platforms.FORTIOS_LATEST_PATCH)
    observed["7.4"] = "7.4.3"   # a downgrade must never be proposed
    drift = platforms.version_db_drift(observed)
    assert all(u[0] != "7.4" for u in drift.patch_updates)
    assert not drift.has_drift


def test_drift_detects_new_train():
    observed = dict(platforms.FORTIOS_LATEST_PATCH)
    observed["8.2"] = "8.2.0"
    drift = platforms.version_db_drift(observed)
    assert drift.has_drift
    assert "8.2" in drift.new_trains
    # the new train also shows up as a patch addition (current was missing)
    assert ("8.2", "", "8.2.0") in drift.patch_updates


def test_drift_new_trains_sorted_newest_first():
    observed = dict(platforms.FORTIOS_LATEST_PATCH)
    observed["8.2"] = "8.2.1"
    observed["9.0"] = "9.0.0"
    drift = platforms.version_db_drift(observed)
    assert drift.new_trains == ("9.0", "8.2")


def test_drift_retired_train_is_informational_not_actionable():
    # a DB train that drops out of the observed set is a retirement candidate
    observed = dict(platforms.FORTIOS_LATEST_PATCH)
    observed.pop("7.2", None)
    drift = platforms.version_db_drift(observed)
    assert "7.2" in drift.retired_trains
    # retirement alone does not trigger a refresh PR
    assert not drift.has_drift


def test_drift_patch_addition_for_hintless_train(monkeypatch):
    # a DB train that currently has NO latest-patch hint gains one
    monkeypatch.delitem(platforms.FORTIOS_LATEST_PATCH, "7.0", raising=False)
    observed = dict(platforms.FORTIOS_LATEST_PATCH)
    observed["7.0"] = "7.0.18"
    drift = platforms.version_db_drift(observed)
    assert ("7.0", "", "7.0.18") in drift.patch_updates
    assert drift.has_drift


def test_render_version_db_roundtrips_and_sorts():
    src = platforms.render_version_db(
        ("7.4", "8.0", "7.6"),
        {"8.0": "8.0.2", "7.6": "7.6.7", "7.4": "7.4.12"})
    # newest train first, in both the tuple and the dict
    assert 'FORTIOS_TRAINS: tuple[str, ...] = ("8.0", "7.6", "7.4")' in src
    assert src.index('"8.0": "8.0.2"') < src.index('"7.6": "7.6.7"')
    assert src.index('"7.6": "7.6.7"') < src.index('"7.4": "7.4.12"')
    # executing the rendered block reproduces usable Python objects
    ns: dict = {}
    exec(src, ns)
    assert ns["FORTIOS_TRAINS"] == ("8.0", "7.6", "7.4")
    assert ns["FORTIOS_LATEST_PATCH"]["7.4"] == "7.4.12"


def test_render_version_db_omits_trains_without_a_patch():
    src = platforms.render_version_db(("8.0", "7.0"), {"8.0": "8.0.2"})
    assert '"8.0": "8.0.2"' in src
    assert '"7.0"' in src.split("FORTIOS_LATEST_PATCH")[0]  # in the trains line
    assert '"7.0":' not in src  # but not in the patch dict


def test_render_version_db_single_train_stays_a_tuple():
    # the 1-element trap: ("8.0") is a str, ("8.0",) is a tuple
    src = platforms.render_version_db(("8.0",), {"8.0": "8.0.0"})
    ns: dict = {}
    exec(src, ns)
    assert ns["FORTIOS_TRAINS"] == ("8.0",)
    assert isinstance(ns["FORTIOS_TRAINS"], tuple)


def test_render_version_db_current_db_roundtrips_exactly():
    # rendering the live DB reproduces a block that rebuilds it identically
    src = platforms.render_version_db(
        platforms.FORTIOS_TRAINS, platforms.FORTIOS_LATEST_PATCH)
    ns: dict = {}
    exec(src, ns)
    assert ns["FORTIOS_TRAINS"] == platforms.FORTIOS_TRAINS
    assert ns["FORTIOS_LATEST_PATCH"] == platforms.FORTIOS_LATEST_PATCH


def test_render_version_db_rejects_injection_tokens():
    # a scraped token with a quote/newline must never reach emitted Python
    with pytest.raises(ValueError):
        platforms.render_version_db(('8.0"\nimport os',), {})
    with pytest.raises(ValueError):
        platforms.render_version_db(("8.0",), {"8.0": '8.0.0"; evil'})


def test_drift_surfaces_malformed_tokens_without_flagging():
    observed = dict(platforms.FORTIOS_LATEST_PATCH)
    observed["bogus train"] = "not.a.version"   # garbled scrape entry
    drift = platforms.version_db_drift(observed)
    assert "bogus train=not.a.version" in drift.malformed
    assert "bogus train" not in drift.new_trains   # filtered, not a new train
    assert not drift.has_drift                      # malformed alone ≠ drift


def test_drift_rejects_train_only_value_as_patch():
    # a bare train string ("8.0") in the patch slot is not a GA patch
    observed = dict(platforms.FORTIOS_LATEST_PATCH)
    observed["8.0"] = "8.0"   # X.Y, not X.Y.Z
    drift = platforms.version_db_drift(observed)
    assert "8.0=8.0" in drift.malformed
    assert all(u[0] != "8.0" for u in drift.patch_updates)
