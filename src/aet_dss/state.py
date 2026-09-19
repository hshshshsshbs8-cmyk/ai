"""Canonical snapshots and a durable append-only hash-chained ledger."""
from __future__ import annotations

import hashlib
import json
import os
import fcntl
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


def canonical(value: Any) -> str:
    """Return the sole serialization used for integrity hashes and JSONL."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def snapshot(root: Path, *, exclude: tuple[str, ...] = (".aet-dss",)) -> dict[str, dict[str, Any]]:
    """Produce a deterministic, regular-file-only snapshot of a sandbox."""
    root = root.resolve()
    files: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] in exclude:
            continue
        data = path.read_bytes()
        files[relative.as_posix()] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    return files


def diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, list[str]]:
    return {
        "created": sorted(set(after) - set(before)),
        "deleted": sorted(set(before) - set(after)),
        "modified": sorted(name for name in set(before) & set(after) if before[name] != after[name]),
    }


@dataclass(frozen=True)
class Ledger:
    path: Path

    def entries(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as source:
            for number, line in enumerate(source, 1):
                if not line.strip():
                    raise ValueError(f"blank ledger line {number}")
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f"invalid JSON at ledger line {number}") from error

    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Append one durable record while holding an inter-process advisory lock."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a+", encoding="utf-8") as output:
            fcntl.flock(output.fileno(), fcntl.LOCK_EX)
            try:
                output.seek(0)
                previous = "0" * 64
                for number, line in enumerate(output, 1):
                    try:
                        prior = json.loads(line)
                    except json.JSONDecodeError as error:
                        raise ValueError(f"refusing to append to invalid ledger line {number}") from error
                    claimed = prior.pop("hash", None)
                    if prior.get("previous_hash") != previous or claimed != digest(prior):
                        raise ValueError(f"refusing to append to invalid ledger entry {number}")
                    previous = claimed
                entry = {"kind": kind, "payload": payload, "previous_hash": previous}
                entry["hash"] = digest(entry)
                output.seek(0, os.SEEK_END)
                output.write(canonical(entry) + "\n")
                output.flush()
                os.fsync(output.fileno())
                return entry
            finally:
                fcntl.flock(output.fileno(), fcntl.LOCK_UN)

    def verify(self) -> tuple[bool, str]:
        previous = "0" * 64
        count = 0
        try:
            for count, entry in enumerate(self.entries(), 1):
                claimed = entry.pop("hash", None)
                if not isinstance(claimed, str) or entry.get("previous_hash") != previous or claimed != digest(entry):
                    return False, f"invalid entry {count}"
                previous = claimed
        except (OSError, ValueError) as error:
            return False, str(error)
        return True, f"{count} entries verified"
