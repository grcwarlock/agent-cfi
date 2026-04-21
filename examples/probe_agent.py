"""Reference probe-agent implementations for `agent-cfi probe --agent`.

A probe agent is any callable with the signature::

    (probe: Probe) -> Iterable[TraceEvent]

It receives one probe at a time, does whatever it needs (call a real LLM
and its tools, or just simulate), and returns a trace of the tool calls
the probe induced. `agent-cfi probe` compares the returned tool names to
the probe's `forbidden_tools` list and scores PASS or FAIL.

Use these as templates — the real thing wraps your actual agent.

Invoke via::

    agent-cfi probe --agent examples.probe_agent:safe_agent
    agent-cfi probe --agent examples.probe_agent:unsafe_agent
"""
from __future__ import annotations

from typing import Iterable

from agent_cfi import Probe, TraceEvent
from agent_cfi.graph import END, START


def safe_agent(probe: Probe) -> Iterable[TraceEvent]:
    """A well-guarded agent. Refuses every injection — never calls a tool.

    Every probe in the pack expects `no_forbidden_tools`; a trace with no
    tool calls trivially satisfies that, so every probe scores PASS.
    """
    yield TraceEvent(run_id=probe.id, step=0, tool=START)
    yield TraceEvent(run_id=probe.id, step=1, tool=END)


def unsafe_agent(probe: Probe) -> Iterable[TraceEvent]:
    """A naive agent that invokes the first forbidden tool for each probe.

    Useful for verifying the probe runner actually fails when it should.
    Every probe scores FAIL.
    """
    yield TraceEvent(run_id=probe.id, step=0, tool=START)
    if probe.forbidden_tools:
        # Attribute the tainted call to the probe's injection channel so a
        # downstream taint check can see it.
        yield TraceEvent(
            run_id=probe.id,
            step=1,
            tool=probe.forbidden_tools[0],
            arg_sources={"payload": [probe.inject_via]},
        )
        yield TraceEvent(run_id=probe.id, step=2, tool=END)
    else:
        yield TraceEvent(run_id=probe.id, step=1, tool=END)
