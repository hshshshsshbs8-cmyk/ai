"""Command-line interface for disposable, auditable AET-DSS runs."""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

from .dataset import sensitive_reason, validate_batch
from .mscp import Segment, pack
from .state import Ledger
from .tools import GuardError, default_registry
from .trajectory import read_jsonl, record


def workspace(value: str) -> Path:
    root = Path(value).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not root.is_dir():
        raise ValueError("sandbox is not a directory")
    return root


def cmd_seed(args: argparse.Namespace) -> int:
    root = workspace(args.sandbox)
    metadata = root / ".aet-dss"
    metadata.mkdir(mode=0o700, exist_ok=True)
    (root / "README.sandbox.txt").write_text("Disposable AET-DSS sandbox. Do not use with production data.\n", encoding="utf-8")
    ledger = Ledger(metadata / "ledger.jsonl")
    ledger.append("seed", {"sandbox": str(root)})
    print(json.dumps({"sandbox": str(root), "ledger": str(ledger.path)}))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    root = workspace(args.sandbox)
    unsafe = sensitive_reason(args.content)
    ledger = Ledger(root / ".aet-dss" / "ledger.jsonl")
    if unsafe:
        ledger.append("guard_block", {"tool": "file.write", "reason": unsafe})
        raise GuardError(unsafe)
    registry = default_registry(root)
    try:
        event = registry.invoke("file.write", {"path": args.path, "content": args.content}, args.statement)
    except GuardError as error:
        ledger.append("guard_block", {"tool": "file.write", "reason": str(error)})
        raise
    audit = ledger.append("tool", event)
    manifest = pack([Segment("request", args.content, 1)], args.context_budget)
    row = record(root / ".aet-dss" / "trajectories.jsonl", run_id=str(uuid.uuid4()), event=event, manifest=manifest, audit_hash=audit["hash"])
    print(json.dumps({"run_id": row["run_id"], "trajectory": str(root / ".aet-dss" / "trajectories.jsonl"), "audit_hash": audit["hash"]}))
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    root = workspace(args.sandbox)
    ledger = Ledger(root / ".aet-dss" / "ledger.jsonl")
    valid, message = ledger.verify()
    entries = list(ledger.entries()) if valid else []
    hashes = {entry["hash"] for entry in entries}
    trajectory_path = root / ".aet-dss" / "trajectories.jsonl"
    try:
        rows = read_jsonl(trajectory_path) if trajectory_path.exists() else []
    except (OSError, json.JSONDecodeError) as error:
        valid, message = False, f"invalid trajectories: {error}"
        rows = []
    if valid and any(row.get("audit_ref") not in hashes for row in rows):
        valid, message = False, "trajectory has an unknown audit reference"
    print(json.dumps({"valid": valid, "message": message, "ledger_entries": len(entries), "trajectories": len(rows)}))
    return 0 if valid else 1


def cmd_report(args: argparse.Namespace) -> int:
    root = workspace(args.sandbox)
    path = root / ".aet-dss" / "trajectories.jsonl"
    try:
        rows = read_jsonl(path) if path.exists() else []
    except (OSError, json.JSONDecodeError) as error:
        print(json.dumps({"records": 0, "dataset_accepted": False, "reason": f"invalid JSONL: {error}"}))
        return 1
    accepted, reason = validate_batch(rows)
    print(json.dumps({"records": len(rows), "dataset_accepted": accepted, "reason": reason}))
    return 0 if accepted else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aet-dss")
    subcommands = parser.add_subparsers(required=True)
    def add_sandbox(command: argparse.ArgumentParser) -> None: command.add_argument("--sandbox", required=True)
    seed = subcommands.add_parser("seed"); add_sandbox(seed); seed.set_defaults(func=cmd_seed)
    run = subcommands.add_parser("run"); add_sandbox(run); run.add_argument("--path", default="output.txt"); run.add_argument("--content", default="seeded trajectory"); run.add_argument("--statement"); run.add_argument("--context-budget", type=int, default=256); run.set_defaults(func=cmd_run)
    audit = subcommands.add_parser("audit"); add_sandbox(audit); audit.set_defaults(func=cmd_audit)
    report = subcommands.add_parser("report"); add_sandbox(report); report.set_defaults(func=cmd_report)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (GuardError, ValueError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
