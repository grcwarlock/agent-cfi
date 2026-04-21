"""Taint analysis on trace events.

Each trace event can declare, per argument, a list of source labels describing
where that argument's data came from. Examples:
    user_input
    retrieved
    tool_output:web_fetch
    literal

A finding is emitted when a tainted source appears in the arg_sources of a
sensitive tool (shell_exec, http_post, fs_write, db_query, email_send, ...).

Source labels support a trailing '*' wildcard in the config:
    tool_output:*   matches any tool_output:<name>
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal

from .graph import TraceEvent


@dataclass(frozen=True, slots=True)
class TaintFinding:
    kind: Literal["taint_violation"]
    run_id: str
    step: int
    tool: str
    arg: str
    source: str
    message: str


def check_taint(
    events: Iterable[TraceEvent],
    sensitive_tools: Iterable[str],
    tainted_sources: Iterable[str],
) -> list[TaintFinding]:
    sensitive = set(sensitive_tools)
    exact: set[str] = set()
    prefixes: list[str] = []
    for p in tainted_sources:
        if p.endswith("*"):
            prefixes.append(p[:-1])
        else:
            exact.add(p)

    findings: list[TaintFinding] = []
    for e in events:
        if e.tool not in sensitive:
            continue
        for arg, sources in (e.arg_sources or {}).items():
            for s in sources or []:
                if s in exact or any(s.startswith(pref) for pref in prefixes):
                    findings.append(TaintFinding(
                        kind="taint_violation",
                        run_id=e.run_id,
                        step=e.step,
                        tool=e.tool,
                        arg=arg,
                        source=s,
                        message=(
                            f"Tainted source '{s}' reaches sensitive sink "
                            f"{e.tool}.{arg} (run {e.run_id}, step {e.step})."
                        ),
                    ))
    return findings
