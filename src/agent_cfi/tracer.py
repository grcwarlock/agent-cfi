"""Lightweight tracer helpers.

The canonical output of a tracer is JSONL TraceEvent. Bring-your-own is fine —
this module just provides conveniences.
"""
from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from typing import Any, IO

from .graph import TraceEvent, START, END


class TraceRecorder:
    """In-process trace writer. Emits one JSON line per tool call.

        with TraceRecorder("eval-run-1", out=open("traces.jsonl", "a")) as rec:
            rec.record("search_docs", arg_sources={"query": ["user_input"]})
            rec.record("summarize",   arg_sources={"text": ["tool_output:search_docs"]})
    """

    def __init__(self, run_id: str, out: IO[str] | None = None):
        self.run_id = run_id
        self.step = 0
        self._out: IO[str] = out if out is not None else sys.stdout
        self._closed = False
        self._emit(TraceEvent(run_id=self.run_id, step=self.step, tool=START))
        self.step += 1

    def _emit(self, e: TraceEvent) -> None:
        self._out.write(json.dumps(e.to_dict(), separators=(",", ":")) + "\n")
        self._out.flush()

    def record(
        self,
        tool: str,
        arg_sources: dict[str, list[str]] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        if self._closed:
            raise RuntimeError("TraceRecorder has been closed")
        self._emit(TraceEvent(
            run_id=self.run_id,
            step=self.step,
            tool=tool,
            arg_sources=arg_sources or {},
            meta=meta or {},
        ))
        self.step += 1

    def end(self) -> None:
        if self._closed:
            return
        self._emit(TraceEvent(run_id=self.run_id, step=self.step, tool=END))
        self._closed = True

    def __enter__(self) -> "TraceRecorder":
        return self

    def __exit__(self, *_exc) -> None:
        self.end()


@contextmanager
def record_run(run_id: str, out: IO[str] | None = None):
    rec = TraceRecorder(run_id, out=out)
    try:
        yield rec
    finally:
        rec.end()


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Read ``key`` from a dict-like mapping OR an object's attribute.

    Lets adapters accept native framework objects (dataclasses, pydantic models,
    namedtuples) without forcing callers to serialize first.
    """
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _parse_openai_tool_call(tc: Any) -> tuple[str, dict]:
    fn = _get(tc, "function") or {}
    name = _get(fn, "name") or _get(tc, "name") or "unknown_tool"
    raw_args = _get(fn, "arguments") or _get(tc, "arguments") or "{}"
    try:
        args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
    except json.JSONDecodeError:
        args = {}
    return name, args or {}


def from_openai_messages(
    run_id: str,
    messages: list,
    *,
    default_source: str = "user_input",
) -> list[TraceEvent]:
    """Convert an OpenAI-style chat/tool_calls message list into TraceEvents.

    Heuristic: first-turn content is 'user_input'; subsequent tool-call args
    are attributed to the last tool's output. Override in a custom wrapper for
    higher fidelity.
    """
    events: list[TraceEvent] = [TraceEvent(run_id=run_id, step=0, tool=START)]
    step = 1
    last_source = default_source
    for m in messages:
        role = _get(m, "role")
        tool_calls = _get(m, "tool_calls")
        if role == "assistant" and tool_calls:
            for tc in tool_calls:
                name, args = _parse_openai_tool_call(tc)
                arg_sources = {k: [last_source] for k in args}
                events.append(TraceEvent(
                    run_id=run_id, step=step, tool=name, arg_sources=arg_sources,
                ))
                step += 1
                last_source = f"tool_output:{name}"
        elif role == "tool":
            last_source = f"tool_output:{_get(m, 'name', 'unknown')}"
    events.append(TraceEvent(run_id=run_id, step=step, tool=END))
    return events


def from_langgraph_events(
    run_id: str,
    events: list,
    *,
    default_source: str = "user_input",
) -> list[TraceEvent]:
    """Convert LangGraph ``graph.stream()`` events into TraceEvents.

    LangGraph emits one event per super-step as a mapping of ``{node_name:
    new_state}``. Tool calls typically surface on a ``"tools"`` (or similarly
    named) node whose state contains ``messages`` with OpenAI-style
    ``tool_calls``. This adapter is a pure shape-reader — it does NOT import
    ``langgraph``.

    Heuristics (documented assumptions):

    * If a node's state contains ``messages`` with ``tool_calls`` entries, one
      TraceEvent is emitted per tool call (name + parsed args).
    * Otherwise, if the node name itself looks like a tool/action node
      (``"tools"``, ``"action"``, ``"tool"``), the node is recorded as a single
      TraceEvent using the node name as the tool name.
    * Plain planner/router/agent nodes with no tool_calls are skipped — they
      represent state updates, not tool invocations.
    * ``arg_sources`` uses the same "last tool's output" lineage as
      ``from_openai_messages``.

    Accepts dicts OR objects exposing ``.items()`` / attribute access.
    """
    out: list[TraceEvent] = [TraceEvent(run_id=run_id, step=0, tool=START)]
    step = 1
    last_source = default_source

    tool_node_names = {"tools", "tool", "action", "actions"}

    def _iter_node_updates(ev: Any):
        if isinstance(ev, dict):
            yield from ev.items()
        else:
            items = getattr(ev, "items", None)
            if callable(items):
                yield from items()

    for ev in events:
        for node_name, state in _iter_node_updates(ev):
            messages = _get(state, "messages")
            emitted_from_messages = False
            if messages:
                for m in messages:
                    tcs = _get(m, "tool_calls")
                    if not tcs:
                        continue
                    for tc in tcs:
                        name, args = _parse_openai_tool_call(tc)
                        arg_sources = {k: [last_source] for k in args}
                        out.append(TraceEvent(
                            run_id=run_id, step=step, tool=name,
                            arg_sources=arg_sources,
                        ))
                        step += 1
                        last_source = f"tool_output:{name}"
                        emitted_from_messages = True
            if emitted_from_messages:
                continue
            if str(node_name) in tool_node_names:
                # Node itself is a tool-executor; use its name as the tool.
                # Args (if any state dict is provided) are attributed to the
                # previous source in the lineage.
                arg_sources = {}
                if isinstance(state, dict):
                    arg_sources = {
                        k: [last_source]
                        for k in state.keys()
                        if k != "messages"
                    }
                out.append(TraceEvent(
                    run_id=run_id, step=step, tool=str(node_name),
                    arg_sources=arg_sources,
                ))
                step += 1
                last_source = f"tool_output:{node_name}"

    out.append(TraceEvent(run_id=run_id, step=step, tool=END))
    return out


def from_crewai_outputs(
    run_id: str,
    outputs: list,
    *,
    default_source: str = "user_input",
) -> list[TraceEvent]:
    """Convert CrewAI ``AgentOutput`` / ``TaskOutput`` objects into TraceEvents.

    Each output is expected to expose (as attributes or dict keys):

    * ``task`` — task identifier (optional, copied into ``meta``)
    * ``agent`` — agent name (optional, copied into ``meta``)
    * ``tools_used`` — list of ``{"tool": <name>, "input": <dict-or-str>}``
      entries describing each tool invocation
    * ``raw`` — raw model output (ignored for graph building)

    One TraceEvent is emitted per ``tools_used`` entry, with ``arg_sources``
    attributing each argument to the previous tool's output (or
    ``default_source`` for the first tool).

    If ``input`` is a string rather than a dict, a synthetic ``input`` key is
    used — matching the common CrewAI pattern where simple tools take a single
    free-form string.

    Pure adapter: does NOT import ``crewai``.
    """
    out: list[TraceEvent] = [TraceEvent(run_id=run_id, step=0, tool=START)]
    step = 1
    last_source = default_source

    for output in outputs:
        task = _get(output, "task")
        agent = _get(output, "agent")
        tools_used = _get(output, "tools_used") or []
        for entry in tools_used:
            name = _get(entry, "tool") or _get(entry, "name") or "unknown_tool"
            raw_input = _get(entry, "input")
            if raw_input is None:
                raw_input = _get(entry, "args") or {}
            if isinstance(raw_input, str):
                try:
                    parsed = json.loads(raw_input)
                    args = parsed if isinstance(parsed, dict) else {"input": raw_input}
                except json.JSONDecodeError:
                    args = {"input": raw_input}
            elif isinstance(raw_input, dict):
                args = raw_input
            else:
                args = {"input": raw_input}
            arg_sources = {k: [last_source] for k in args}
            meta: dict[str, Any] = {}
            if task is not None:
                meta["task"] = str(task)
            if agent is not None:
                meta["agent"] = str(agent)
            out.append(TraceEvent(
                run_id=run_id, step=step, tool=str(name),
                arg_sources=arg_sources, meta=meta,
            ))
            step += 1
            last_source = f"tool_output:{name}"

    out.append(TraceEvent(run_id=run_id, step=step, tool=END))
    return out


def from_autogen_messages(
    run_id: str,
    messages: list,
    *,
    default_source: str = "user_input",
) -> list[TraceEvent]:
    """Convert AutoGen GroupChat messages into TraceEvents.

    AutoGen messages are dict-like with ``name`` (speaker), ``role``,
    ``content``, and optional ``tool_calls`` (OpenAI-style). This adapter:

    * Extracts ``tool_calls`` the same way as :func:`from_openai_messages`.
    * Treats an agent handoff — a new ``name`` appearing in a ``role ==
      "assistant"`` message — as a transition, emitting a synthetic TraceEvent
      whose ``tool`` is the agent name. This captures inter-agent flow in the
      graph even when an assistant turn doesn't invoke a tool.
    * Tool-result messages (``role == "tool"``) update the lineage source.

    Pure adapter: does NOT import ``autogen``.
    """
    out: list[TraceEvent] = [TraceEvent(run_id=run_id, step=0, tool=START)]
    step = 1
    last_source = default_source
    last_agent: str | None = None

    for m in messages:
        role = _get(m, "role")
        name = _get(m, "name")
        tool_calls = _get(m, "tool_calls")

        if role == "assistant":
            # Agent handoff: emit a synthetic transition event named after the
            # new speaker. Skip if this is the first assistant turn AND a tool
            # call follows (the tool event already carries the transition).
            if name and name != last_agent:
                out.append(TraceEvent(
                    run_id=run_id, step=step, tool=str(name),
                    arg_sources={},
                    meta={"kind": "agent_handoff"},
                ))
                step += 1
                last_agent = name
                last_source = f"tool_output:{name}"
            if tool_calls:
                for tc in tool_calls:
                    tname, args = _parse_openai_tool_call(tc)
                    arg_sources = {k: [last_source] for k in args}
                    out.append(TraceEvent(
                        run_id=run_id, step=step, tool=tname,
                        arg_sources=arg_sources,
                    ))
                    step += 1
                    last_source = f"tool_output:{tname}"
        elif role == "tool":
            last_source = f"tool_output:{_get(m, 'name', 'unknown')}"

    out.append(TraceEvent(run_id=run_id, step=step, tool=END))
    return out
