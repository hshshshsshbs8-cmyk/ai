from __future__ import annotations
import argparse, json, uuid
from pathlib import Path
from .state import Ledger
from .tools import default_registry, GuardError
from .mscp import Segment, pack
from .trajectory import record, read_jsonl
from .dataset import validate_batch

def workspace(value: str) -> Path:
    root = Path(value).resolve(); root.mkdir(parents=True, exist_ok=True); return root

def cmd_seed(args):
    root = workspace(args.sandbox); (root / ".aet-dss").mkdir(exist_ok=True)
    (root / "README.sandbox.txt").write_text("Disposable AET-DSS sandbox. Do not use with production data.\n")
    ledger = Ledger(root / ".aet-dss" / "ledger.jsonl"); ledger.append("seed", {"sandbox": str(root)})
    print(json.dumps({"sandbox": str(root), "ledger": str(ledger.path)}))
def cmd_run(args):
    root = workspace(args.sandbox); registry = default_registry(root); ledger = Ledger(root / ".aet-dss" / "ledger.jsonl")
    try: event = registry.invoke("file.write", {"path": args.path, "content": args.content}, args.statement)
    except GuardError as error: ledger.append("guard_block", {"reason": str(error)}); raise SystemExit(f"blocked: {error}")
    audit = ledger.append("tool", event); manifest = pack([Segment("request", args.content, 1)], args.context_budget)
    row = record(root / ".aet-dss" / "trajectories.jsonl", run_id=str(uuid.uuid4()), event=event, manifest=manifest, audit_hash=audit["hash"])
    print(json.dumps({"trajectory": row, "audit_hash": audit["hash"]}))
def cmd_audit(args):
    ok, message = Ledger(workspace(args.sandbox) / ".aet-dss" / "ledger.jsonl").verify(); print(message); return 0 if ok else 1
def cmd_report(args):
    root = workspace(args.sandbox); path = root / ".aet-dss" / "trajectories.jsonl"; rows = read_jsonl(path) if path.exists() else []
    accepted, reason = validate_batch(rows); print(json.dumps({"records": len(rows), "dataset_accepted": accepted, "reason": reason}))
def main(argv=None):
    parser = argparse.ArgumentParser(prog="aet-dss"); sub = parser.add_subparsers(required=True)
    def sandbox(p): p.add_argument("--sandbox", required=True)
    p = sub.add_parser("seed"); sandbox(p); p.set_defaults(func=cmd_seed)
    p = sub.add_parser("run"); sandbox(p); p.add_argument("--path", default="output.txt"); p.add_argument("--content", default="seeded trajectory"); p.add_argument("--statement"); p.add_argument("--context-budget", type=int, default=256); p.set_defaults(func=cmd_run)
    p = sub.add_parser("audit"); sandbox(p); p.set_defaults(func=cmd_audit)
    p = sub.add_parser("report"); sandbox(p); p.set_defaults(func=cmd_report)
    args = parser.parse_args(argv); return args.func(args) or 0
if __name__ == "__main__": raise SystemExit(main())
