import json
from pathlib import Path
from aet_dss.cli import main
from aet_dss.state import Ledger
from aet_dss.trajectory import read_jsonl
from aet_dss.tools import default_registry, GuardError

def test_full_disposable_sandbox(tmp_path: Path, capsys):
    main(["seed", "--sandbox", str(tmp_path)])
    main(["run", "--sandbox", str(tmp_path), "--path", "output.txt", "--content", "hello"])
    main(["audit", "--sandbox", str(tmp_path)])
    main(["report", "--sandbox", str(tmp_path)])
    rows = read_jsonl(tmp_path / ".aet-dss/trajectories.jsonl")
    assert len(rows) == 1 and rows[0]["verification"]["state_diff_valid"] is True
    assert Ledger(tmp_path / ".aet-dss/ledger.jsonl").verify()[0]

def test_tleg_blocks_escape_and_unregistered(tmp_path: Path):
    registry = default_registry(tmp_path)
    for name, args in (("unknown", {}), ("file.write", {"path": "../escape", "content": "x"})):
        try: registry.invoke(name, args)
        except GuardError: pass
        else: raise AssertionError("unsafe action was permitted")
