"""Canonical snapshots and an append-only hash-chained ledger."""
from __future__ import annotations
import hashlib, json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def snapshot(root: Path) -> dict[str, dict[str, Any]]:
    root = root.resolve(); files = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()):
        rel = path.relative_to(root).as_posix(); data = path.read_bytes()
        files[rel] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    return files

def diff(before: dict, after: dict) -> dict[str, list[str]]:
    return {"created": sorted(set(after)-set(before)), "deleted": sorted(set(before)-set(after)),
            "modified": sorted(k for k in set(before)&set(after) if before[k] != after[k])}

@dataclass
class Ledger:
    path: Path
    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        previous = "0" * 64
        if self.path.exists() and self.path.stat().st_size:
            previous = json.loads(self.path.read_text().splitlines()[-1])["hash"]
        entry = {"kind": kind, "payload": payload, "previous_hash": previous}
        entry["hash"] = digest(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as out: out.write(canonical(entry) + "\n")
        return entry
    def verify(self) -> tuple[bool, str]:
        previous = "0" * 64
        if not self.path.exists(): return True, "empty ledger"
        for number, line in enumerate(self.path.read_text().splitlines(), 1):
            entry = json.loads(line); claimed = entry.pop("hash", None)
            if entry.get("previous_hash") != previous or claimed != digest(entry): return False, f"invalid entry {number}"
            previous = claimed
        return True, f"{number if self.path.stat().st_size else 0} entries verified"
