"""Deterministic MSCP context packing with recorded eviction/compression."""
from __future__ import annotations
from dataclasses import dataclass
from .state import digest
@dataclass
class Segment:
    id: str; text: str; priority: int = 0

def pack(segments: list[Segment], budget: int) -> dict:
    kept, evicted, used = [], [], 0
    for segment in sorted(segments, key=lambda s: (-s.priority, s.id)):
        text = segment.text
        if used + len(text) <= budget: kept.append({"id": segment.id, "text": text}); used += len(text)
        else:
            compressed = text[:max(0, min(64, budget-used))]
            if compressed: kept.append({"id": segment.id, "text": compressed, "compressed": True}); used += len(compressed)
            evicted.append({"id": segment.id, "reason": "budget", "original_bytes": len(text)})
    manifest = {"budget": budget, "used": used, "segments": kept, "evictions": evicted}
    manifest["manifest_hash"] = digest(manifest); return manifest
