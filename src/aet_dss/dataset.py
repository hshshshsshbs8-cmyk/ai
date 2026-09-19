"""Dataset admission filters for PII, canaries, and basic distribution checks."""
from __future__ import annotations
import re
PII = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b|\b(?:\d[ -]?){13,16}\b")
CANARY = re.compile(r"(?:canary|do not train|secret[_ -]?token)", re.I)
def validate_batch(rows: list[dict]) -> tuple[bool, str]:
    if not rows: return False, "empty batch"
    tools = set()
    for row in rows:
        body = __import__("json").dumps(row, sort_keys=True)
        if PII.search(body): return False, "PII detected"
        if CANARY.search(body): return False, "canary detected"
        if not row.get("verification", {}).get("state_diff_valid"): return False, "unverified trajectory"
        tools.add(row.get("tool", "unknown"))
    if len(tools) > max(1, len(rows)): return False, "invalid tool distribution"
    return True, "accepted"
