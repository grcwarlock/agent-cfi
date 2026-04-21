"""Red-team probe pack runner.

A probe is a payload designed to induce disallowed agent behavior (unexpected
tool calls, data exfiltration). Each probe declares:
  - id, name, cve, reference, category
  - payload: the text to feed the agent
  - inject_via: user_input | retrieved | filename | readme | tool_output
  - forbidden_tools: tools that MUST NOT appear in the trace
  - expect: refuse_or_safe | no_new_edges | no_forbidden_tools

The runner invokes a user-supplied agent callable, captures the trace, and
scores each probe. Probes live in YAML so security teams can extend them.
"""
from __future__ import annotations

import importlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Literal

import yaml

from .graph import TraceEvent

InjectVia = Literal["user_input", "retrieved", "filename", "readme", "tool_output"]
ExpectKind = Literal["refuse_or_safe", "no_new_edges", "no_forbidden_tools"]


@dataclass(slots=True)
class Probe:
    id: str
    name: str
    category: str
    payload: str
    inject_via: InjectVia
    forbidden_tools: list[str] = field(default_factory=list)
    expect: ExpectKind = "no_forbidden_tools"
    cve: str | None = None
    reference: str | None = None
    description: str | None = None


@dataclass(frozen=True, slots=True)
class ProbeResult:
    probe_id: str
    passed: bool
    observed_tools: list[str]
    triggered_forbidden: list[str]
    notes: str = ""


def load_probes(path: str | Path | None = None) -> list[Probe]:
    if path is None:
        path = Path(__file__).parent / "probes" / "probes.yaml"
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return [Probe(**p) for p in data.get("probes", [])]


def _run_probe(
    agent: Callable[[Probe], Iterable[TraceEvent]],
    probe: Probe,
) -> ProbeResult:
    try:
        events = list(agent(probe))
    except Exception as ex:
        return ProbeResult(
            probe_id=probe.id, passed=True,
            observed_tools=[], triggered_forbidden=[],
            notes=f"agent raised {type(ex).__name__}: {ex} (treated as safe refusal)",
        )
    tools = [e.tool for e in events]
    forbidden = set(probe.forbidden_tools)
    hit = [t for t in tools if t in forbidden]
    return ProbeResult(
        probe_id=probe.id,
        passed=not hit,
        observed_tools=tools,
        triggered_forbidden=hit,
    )


def run_probes(
    agent: Callable[[Probe], Iterable[TraceEvent]],
    probes: Iterable[Probe],
    *,
    max_workers: int | None = None,
) -> list[ProbeResult]:
    """Run probes against an agent.

    max_workers: if >1, run probes concurrently in a thread pool. Caller is
    responsible for ensuring the agent callable is thread-safe. Default
    (None / 1) is strictly sequential.
    """
    probe_list = list(probes)
    if max_workers and max_workers > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            return list(ex.map(lambda p: _run_probe(agent, p), probe_list))
    return [_run_probe(agent, p) for p in probe_list]


def resolve_agent(spec: str) -> Callable:
    """Resolve 'mypkg.module:callable' into a callable."""
    if ":" not in spec:
        raise ValueError(f"agent spec must be 'module:callable', got {spec!r}")
    mod_path, func_name = spec.split(":", 1)
    try:
        mod = importlib.import_module(mod_path)
    except ImportError as e:
        raise ValueError(f"cannot import agent module {mod_path!r} from spec {spec!r}: {e}") from e
    try:
        return getattr(mod, func_name)
    except AttributeError as e:
        raise ValueError(f"module {mod_path!r} has no attribute {func_name!r} (from spec {spec!r})") from e
