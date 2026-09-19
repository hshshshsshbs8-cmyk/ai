"""JSONL trajectory records."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from .state import canonical

def record(path: Path, *, run_id: str, event: dict[str, Any], manifest: dict[str, Any], audit_hash: str) -> dict:
    row = {"schema_version": "aet-dss/v1", "run_id": run_id, "tool": event["tool"], "arguments": event["args"],
           "reversibility": {"reversible": event["reversible"], "pre_action_statement": event["pre_action"]},
           "state_diff": event["diff"], "verification": {"state_diff_valid": event["declared_effects_verified"]},
           "audit_ref": audit_hash, "mscp_manifest": manifest, "tleg_events": [event]}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as out: out.write(canonical(row) + "\n")
    return row

def read_jsonl(path: Path) -> list[dict]: return [json.loads(x) for x in path.read_text().splitlines() if x]
