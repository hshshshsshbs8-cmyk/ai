"""Dataset admission filters for PII, canaries, and record distributions."""
from __future__ import annotations

import json
import re
from collections import Counter

PII = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b|\b(?:\d[ -]?){13,16}\b")
CANARY = re.compile(r"(?:canary|do not train|secret[_ -]?token)", re.I)


def sensitive_reason(value: str) -> str | None:
    if PII.search(value):
        return "PII detected"
    if CANARY.search(value):
        return "canary detected"
    return None


def validate_batch(rows: list[dict]) -> tuple[bool, str]:
    if not rows:
        return False, "empty batch"
    tool_counts: Counter[str] = Counter()
    for row in rows:
        if not isinstance(row, dict) or row.get("schema_version") != "aet-dss/v1":
            return False, "invalid trajectory schema"
        reason = sensitive_reason(json.dumps(row, sort_keys=True))
        if reason:
            return False, reason
        if not row.get("verification", {}).get("state_diff_valid"):
            return False, "unverified trajectory"
        tool_counts[str(row.get("tool", "unknown"))] += 1
    # A batch with multiple records cannot be entirely one operation type; this catches accidental duplication.
    if len(rows) > 1 and len(tool_counts) == 1:
        return False, "insufficient tool distribution"
    return True, "accepted"
