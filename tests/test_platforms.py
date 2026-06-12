import pytest

from fwforge import platforms
from fwforge.transforms.plan import PlanError


def test_known_code_passthrough():
    code, note = platforms.resolve("FG7H1G")
    assert code == "FG7H1G"
    assert "confirm" in note  # derived entry carries a verify reminder


def test_verified_entry_has_no_note():
    assert platforms.resolve("FGT60F") == ("FGT60F", "")
    assert platforms.resolve("601F") == ("FG6H1F", "")


def test_bare_model_number_lowercase():
    # the real-world regression: '701g' typed into the platform field
    code, note = platforms.resolve("701g")
    assert code == "FG7H1G"
    assert "701G" in note


def test_product_name_and_sku():
    assert platforms.resolve("FortiGate 701G")[0] == "FG7H1G"
    assert platforms.resolve("FG-701G")[0] == "FG7H1G"
    assert platforms.resolve("fg-601f")[0] == "FG6H1F"


def test_bare_model_prefers_fortigate_over_fortiwifi():
    assert platforms.resolve("60F")[0] == "FGT60F"
    assert platforms.resolve("FortiWiFi 60F")[0] == "FWF60F"


def test_unknown_but_plausible_code_accepted():
    code, note = platforms.resolve("fg1k8f")
    assert code == "FG1K8F"
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
