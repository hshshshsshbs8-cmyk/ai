"""Sandbox registry, schemas, declared effects, and validation guards."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from .state import diff

@dataclass(frozen=True)
class ToolSchema:
    name: str; required: tuple[str, ...] = (); reversible: bool = True
    effects: tuple[str, ...] = (); blast_radius: int = 10

@dataclass
class Tool:
    schema: ToolSchema; handler: Callable[[dict[str, Any], Path], Any]

class GuardError(ValueError): pass

def contained(root: Path, raw: str) -> Path:
    root = root.resolve(); target = (root / raw).resolve()
    if target != root and root not in target.parents: raise GuardError("path escapes sandbox")
    return target

class ToolRegistry:
    def __init__(self, root: Path): self.root, self.tools, self.events = root.resolve(), {}, []
    def register(self, tool: Tool) -> None: self.tools[tool.schema.name] = tool
    def invoke(self, name: str, args: dict[str, Any], pre_statement: str | None = None) -> dict[str, Any]:
        if name not in self.tools: raise GuardError("unregistered tool")
        tool = self.tools[name]; missing = set(tool.schema.required)-set(args)
        if missing: raise GuardError("missing arguments: " + ", ".join(sorted(missing)))
        if not tool.schema.reversible and not pre_statement: raise GuardError("irreversible operation requires pre-action statement")
        for value in args.values():
            if isinstance(value, str) and ("/" in value or value.startswith(".")): contained(self.root, value)
        before = __import__("aet_dss.state", fromlist=["snapshot"]).snapshot(self.root)
        result = tool.handler(args, self.root)
        after = __import__("aet_dss.state", fromlist=["snapshot"]).snapshot(self.root); changes = diff(before, after)
        count = sum(map(len, changes.values()))
        if count > tool.schema.blast_radius: raise GuardError("blast-radius limit exceeded")
        actual = set(changes["created"] + changes["deleted"] + changes["modified"])
        declared = {effect.format(**args) for effect in tool.schema.effects}
        verified = not declared or actual.issubset(declared)
        event = {"tool": name, "args": args, "reversible": tool.schema.reversible, "pre_action": pre_statement,
                 "diff": changes, "declared_effects_verified": verified, "guard": "allowed"}
        self.events.append(event)
        if not verified: raise GuardError("undeclared effect")
        return {"result": result, **event}

def default_registry(root: Path) -> ToolRegistry:
    registry = ToolRegistry(root)
    def write(args, sandbox):
        path = contained(sandbox, args["path"]); path.parent.mkdir(parents=True, exist_ok=True); path.write_text(args["content"], encoding="utf-8"); return {"path": args["path"]}
    registry.register(Tool(ToolSchema("file.write", ("path", "content"), True, ("{path}",)), write))
    # Other categories are registered as deny-by-default sandbox interfaces; no host capability is exposed.
    for category in ("application", "audio", "network", "process", "memory"):
        registry.register(Tool(ToolSchema(f"{category}.noop"), lambda args, root: {"sandboxed": True}))
    return registry
