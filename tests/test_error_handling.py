import pytest

from fwforge import cli
from fwforge.transforms.plan import PlanError, load_plan


def test_malformed_plan_raises_planerror(tmp_path):
    # configparser-level errors (duplicate section within one file, missing
    # header, bad line) must surface as PlanError -> clean CLI exit, not a raw
    # configparser.Error traceback.
    dup = tmp_path / "dup.plan"
    dup.write_text("[portmap]\nport1 = wan1\n[portmap]\nport2 = wan2\n",
                   encoding="utf-8")
    with pytest.raises(PlanError):
        load_plan(str(dup))

    noheader = tmp_path / "noheader.plan"
    noheader.write_text("port1 = wan1\n", encoding="utf-8")  # no [section]
    with pytest.raises(PlanError):
        load_plan(str(noheader))


def test_cli_missing_input_exits_2():
    # a missing/unreadable input file is a fatal precondition -> exit 2, not an
    # uncaught traceback (which exits 1 and is indistinguishable from
    # "converted with errors"). Per the documented exit-code contract.
    rc = cli.main(["detect", "definitely-not-a-real-file.cfg"])
    assert rc == 2
