"""Schema-validated tools constrained to a disposable filesystem sandbox."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .state import diff, snapshot


class GuardError(ValueError):
    """Raised when TLEG blocks a requested operation."""


@dataclass(frozen=True)
class ToolSchema:
    name: str
    required: tuple[str, ...] = ()
    path_fields: tuple[str, ...] = ()
    reversible: bool = True
    effects: tuple[str, ...] = ()
    blast_radius: int = 10


@dataclass(frozen=True)
class Tool:
    schema: ToolSchema
    handler: Callable[[dict[str, Any], Path], Any]


def contained(root: Path, raw: str) -> Path:
    """Resolve a relative path and reject absolute paths and sandbox escapes."""
    if not isinstance(raw, str) or not raw or Path(raw).is_absolute():
        raise GuardError("path must be a non-empty relative sandbox path")
    root = root.resolve()
    target = (root / raw).resolve()
    if root not in target.parents:
        raise GuardError("path escapes sandbox")
    return target


class ToolRegistry:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.tools: dict[str, Tool] = {}
        self.events: list[dict[str, Any]] = []

    def register(self, tool: Tool) -> None:
        if tool.schema.name in self.tools:
            raise ValueError(f"duplicate tool: {tool.schema.name}")
        self.tools[tool.schema.name] = tool

    def invoke(self, name: str, args: dict[str, Any], pre_statement: str | None = None) -> dict[str, Any]:
        if name not in self.tools:
            raise GuardError("unregistered tool")
        if not isinstance(args, dict):
            raise GuardError("arguments must be an object")
        tool = self.tools[name]
        missing = set(tool.schema.required) - set(args)
        unexpected = set(args) - set(tool.schema.required)
        if missing or unexpected:
            details = [f"missing: {', '.join(sorted(missing))}"] if missing else []
            details += [f"unexpected: {', '.join(sorted(unexpected))}"] if unexpected else []
            raise GuardError("invalid arguments (" + "; ".join(details) + ")")
        if not tool.schema.reversible and not (pre_statement and pre_statement.strip()):
            raise GuardError("irreversible operation requires pre-action statement")
        for field in tool.schema.path_fields:
            contained(self.root, args[field])
        declared = {effect.format(**args) for effect in tool.schema.effects}
        if len(declared) > tool.schema.blast_radius:
            raise GuardError("declared effects exceed blast-radius limit")
        before = snapshot(self.root)
        result = tool.handler(args, self.root)
        changes = diff(before, snapshot(self.root))
        actual = set().union(*changes.values())
        verified = actual.issubset(declared) and len(actual) <= tool.schema.blast_radius
        event = {
            "tool": name, "args": args, "reversible": tool.schema.reversible,
            "pre_action": pre_statement, "diff": changes,
            "declared_effects": sorted(declared), "declared_effects_verified": verified,
            "guard": "allowed" if verified else "blocked_after_execution",
        }
        self.events.append(event)
        if not verified:
            raise GuardError("undeclared effect or blast-radius limit exceeded")
        return {"result": result, **event}


def default_registry(root: Path) -> ToolRegistry:
    registry = ToolRegistry(root)

    def write(args: dict[str, Any], sandbox: Path) -> dict[str, str]:
        path = contained(sandbox, args["path"])
        if not isinstance(args["content"], str):
            raise GuardError("content must be a string")
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_text(args["content"], encoding="utf-8")
        temporary.replace(path)
        return {"path": args["path"]}

    registry.register(Tool(ToolSchema("file.write", ("path", "content"), ("path",), True, ("{path}",)), write))
    # Capability names are intentionally absent: application/audio/network/process/memory execution is not implemented.
    return registry
