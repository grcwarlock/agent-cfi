"""SARIF 2.1.0 emitter for GitHub Code Scanning ingestion."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Union

from . import __version__
from .graph import EdgeFinding
from .mcp import MCPSchemaFinding
from .taint import TaintFinding

Finding = Union[EdgeFinding, TaintFinding, MCPSchemaFinding]

_VERSION = __version__
_TOOL_URI = "https://github.com/grcwarlock/agent-cfi"
_HELP_URI = f"{_TOOL_URI}#what-it-catches"

_RULES: dict[str, dict] = {
    "new_edge": {
        "id": "agent-cfi/new-edge",
        "name": "NewToolCallEdge",
        "shortDescription": {"text": "New tool-call edge not in baseline graph."},
        "fullDescription": {
            "text": (
                "The agent made a tool-call transition absent from the baseline graph "
                "learned from main. May indicate prompt-injection-induced control flow "
                "deviation."
            )
        },
        "helpUri": _HELP_URI,
        "defaultConfiguration": {"level": "error"},
    },
    "edge_drift": {
        "id": "agent-cfi/edge-drift",
        "name": "EdgeProbabilityDrift",
        "shortDescription": {"text": "Tool-call edge probability drifted beyond threshold."},
        "fullDescription": {
            "text": (
                "A known edge exists but its transition probability changed beyond the "
                "configured threshold. Review whether the agent's decision logic was altered."
            )
        },
        "helpUri": _HELP_URI,
        "defaultConfiguration": {"level": "warning"},
    },
    "removed_edge": {
        "id": "agent-cfi/removed-edge",
        "name": "RemovedToolCallEdge",
        "shortDescription": {"text": "Baseline edge absent in current traces."},
        "fullDescription": {"text": "An edge present in baseline did not appear in current traces."},
        "helpUri": _HELP_URI,
        "defaultConfiguration": {"level": "note"},
    },
    "taint_violation": {
        "id": "agent-cfi/taint-violation",
        "name": "TaintedSinkArgument",
        "shortDescription": {"text": "Tainted source reaches sensitive sink argument."},
        "fullDescription": {
            "text": (
                "An untrusted data source flowed into a sensitive tool's argument "
                "(shell, http_post, fs_write, etc.). Likely data exfiltration or "
                "command injection vector."
            )
        },
        "helpUri": _HELP_URI,
        "defaultConfiguration": {"level": "error"},
    },
    "mcp_schema_mismatch": {
        "id": "agent-cfi/mcp-schema-mismatch",
        "name": "MCPSchemaMismatch",
        "shortDescription": {"text": "MCP tool schema changed since pin (rug-pull)."},
        "fullDescription": {
            "text": (
                "An MCP tool's schema hash no longer matches the pinned baseline, "
                "or a tool was added/removed since the pin. Silent schema mutations "
                "(MCP rug-pull) can alter the agent's tool surface without a "
                "visible code change."
            )
        },
        "helpUri": _HELP_URI,
        "defaultConfiguration": {"level": "error"},
    },
}


def _result(f: Finding, baseline_path: str) -> dict:
    meta = _RULES[f.kind]
    out = {
        "ruleId": meta["id"],
        "level": meta["defaultConfiguration"]["level"],
        "message": {"text": f.message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": baseline_path},
                "region": {"startLine": 1},
            }
        }],
    }
    if isinstance(f, TaintFinding):
        out["properties"] = {
            "run_id": f.run_id, "step": f.step, "tool": f.tool,
            "arg": f.arg, "source": f.source,
        }
        out["partialFingerprints"] = {
            "primary": f"taint:{f.tool}:{f.arg}:{f.source}",
        }
    elif isinstance(f, MCPSchemaFinding):
        out["properties"] = {
            "server": f.server, "tool": f.tool,
            "baseline_hash": f.baseline_hash,
            "current_hash": f.current_hash,
        }
        out["partialFingerprints"] = {
            "primary": f"mcp:{f.server}:{f.tool}",
        }
    else:
        out["properties"] = {
            "src": f.src, "dst": f.dst,
            "baseline_prob": f.baseline_prob,
            "current_prob": f.current_prob,
            "delta": f.delta,
        }
        out["partialFingerprints"] = {
            "primary": f"{f.kind}:{f.src}->{f.dst}",
        }
    return out


def write_sarif(
    findings: Iterable[Finding],
    path: str | Path,
    *,
    baseline_path: str = ".agent-cfi/baseline.json",
) -> None:
    findings_list = list(findings)
    # Always publish the full rule catalog so suppressions / baselines persist
    # across runs even when a given kind has zero results this time.
    rules = [dict(r) for r in _RULES.values()]

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "agent-cfi",
                    "version": _VERSION,
                    "informationUri": _TOOL_URI,
                    "rules": rules,
                }
            },
            "results": [_result(f, baseline_path) for f in findings_list],
        }],
    }
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
        f.write("\n")
