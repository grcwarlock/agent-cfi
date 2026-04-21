"""MCP tool-schema hash-pinning: detect silent schema mutations ("rug-pull").

Workflow:
    1. On main, serialize every MCP tool schema canonically and SHA256 it.
       Commit the resulting `{server: {tool: sha256_hex}}` as pin file.
    2. On a PR, re-hash the current live schemas and diff against the pin.
       Any missing, added, or changed tool emits an ``mcp_schema_mismatch``
       finding.

Input shape for both ``pin_schemas`` and ``check_schemas`` is
``{server_name: {tool_name: schema_dict}}``. The schema_dict is whatever the
MCP server reports for that tool (typically a JSON Schema) — we don't care
about its structure, only its canonical bytes.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

MCPKind = Literal["mcp_schema_mismatch"]


@dataclass(frozen=True, slots=True)
class MCPSchemaFinding:
    """One MCP tool whose current schema hash doesn't match the pin."""
    kind: MCPKind
    server: str
    tool: str
    baseline_hash: str
    current_hash: str
    message: str


def hash_schema(schema: dict) -> str:
    """Return the SHA256 hex of a schema's canonical JSON encoding.

    Canonical form is ``json.dumps`` with sorted keys and no whitespace, so
    semantically identical schemas produce identical hashes regardless of
    serialization quirks (key ordering, stray whitespace).
    """
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def pin_schemas(schemas: dict[str, dict[str, dict]]) -> dict[str, dict[str, str]]:
    """Hash every tool schema. Returns ``{server: {tool: sha256_hex}}``."""
    return {
        server: {tool: hash_schema(schema) for tool, schema in tools.items()}
        for server, tools in schemas.items()
    }


def check_schemas(
    pinned: dict[str, dict[str, str]],
    current: dict[str, dict[str, dict]],
) -> list[MCPSchemaFinding]:
    """Diff current schemas against pinned hashes.

    Emits one ``MCPSchemaFinding`` per mismatch:
      - ``changed``: tool exists in both but hash differs
      - ``added``: tool present in current, absent from pin
      - ``removed``: tool present in pin, absent from current
    """
    findings: list[MCPSchemaFinding] = []
    current_hashes = pin_schemas(current)

    servers = set(pinned) | set(current_hashes)
    for server in sorted(servers):
        pinned_tools = pinned.get(server, {})
        current_tools = current_hashes.get(server, {})
        tool_names = set(pinned_tools) | set(current_tools)
        for tool in sorted(tool_names):
            bh = pinned_tools.get(tool)
            ch = current_tools.get(tool)
            if bh is not None and ch is not None:
                if bh != ch:
                    findings.append(MCPSchemaFinding(
                        kind="mcp_schema_mismatch",
                        server=server,
                        tool=tool,
                        baseline_hash=bh,
                        current_hash=ch,
                        message=(
                            f"MCP schema changed for {server}.{tool}: "
                            f"hash {bh[:12]}... -> {ch[:12]}... "
                            "(tool schema mutated since pin)."
                        ),
                    ))
            elif ch is not None:
                findings.append(MCPSchemaFinding(
                    kind="mcp_schema_mismatch",
                    server=server,
                    tool=tool,
                    baseline_hash="",
                    current_hash=ch,
                    message=(
                        f"MCP tool {server}.{tool} added since pin "
                        f"(current hash {ch[:12]}..., no baseline)."
                    ),
                ))
            else:
                findings.append(MCPSchemaFinding(
                    kind="mcp_schema_mismatch",
                    server=server,
                    tool=tool,
                    baseline_hash=bh or "",
                    current_hash="",
                    message=(
                        f"MCP tool {server}.{tool} removed since pin "
                        f"(baseline hash {(bh or '')[:12]}..., not present in current)."
                    ),
                ))
    return findings


def save_pins(pins: dict[str, dict[str, str]], path: str | Path) -> None:
    """Write pin file as pretty JSON. Creates parent dirs like save_graph."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2, sort_keys=True)
        f.write("\n")


def load_pins(path: str | Path) -> dict[str, dict[str, str]]:
    """Load a pin file written by ``save_pins``."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_current_schemas(path: str | Path) -> dict[str, dict[str, dict]]:
    """Load a user-supplied JSON file of live schemas.

    Same structure as ``pin_schemas`` input: ``{server: {tool: schema_dict}}``.
    """
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
