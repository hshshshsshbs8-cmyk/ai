import json
from pathlib import Path

from aet_dss.cli import main
from aet_dss.state import Ledger
from aet_dss.tools import GuardError, default_registry
from aet_dss.trajectory import read_jsonl


def test_full_disposable_sandbox(tmp_path: Path):
    assert main(["seed", "--sandbox", str(tmp_path)]) == 0
    assert main(["run", "--sandbox", str(tmp_path), "--path", "nested/output.txt", "--content", "a/path is content"]) == 0
    assert main(["audit", "--sandbox", str(tmp_path)]) == 0
    assert main(["report", "--sandbox", str(tmp_path)]) == 0
    rows = read_jsonl(tmp_path / ".aet-dss/trajectories.jsonl")
    assert len(rows) == 1 and rows[0]["verification"]["state_diff_valid"] is True
    assert Ledger(tmp_path / ".aet-dss/ledger.jsonl").verify()[0]


def test_tleg_blocks_escape_unregistered_and_pii(tmp_path: Path):
    registry = default_registry(tmp_path)
    for name, args in (("unknown", {}), ("file.write", {"path": "../escape", "content": "x"})):
        try:
            registry.invoke(name, args)
        except GuardError:
            pass
        else:
            raise AssertionError("unsafe action was permitted")
    assert main(["seed", "--sandbox", str(tmp_path)]) == 0
    assert main(["run", "--sandbox", str(tmp_path), "--content", "contact jane@example.com"]) == 2
    assert not (tmp_path / "output.txt").exists()


def test_audit_detects_ledger_and_reference_tampering(tmp_path: Path):
    main(["seed", "--sandbox", str(tmp_path)])
    main(["run", "--sandbox", str(tmp_path)])
    trajectory = tmp_path / ".aet-dss/trajectories.jsonl"
    row = json.loads(trajectory.read_text())
    row["audit_ref"] = "f" * 64
    trajectory.write_text(json.dumps(row) + "\n")
    assert main(["audit", "--sandbox", str(tmp_path)]) == 1
    ledger = tmp_path / ".aet-dss/ledger.jsonl"
    ledger.write_text(ledger.read_text().replace('"kind":"seed"', '"kind":"altered"'))
    assert Ledger(ledger).verify()[0] is False
