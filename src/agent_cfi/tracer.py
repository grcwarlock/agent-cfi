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


def _parse_openai_tool_call(tc: dict) -> tuple[str, dict]:
    fn = tc.get("function") or {}
    name = fn.get("name") or tc.get("name") or "unknown_tool"
    raw_args = fn.get("arguments") or tc.get("arguments") or "{}"
    try:
        args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
    except json.JSONDecodeError:
        args = {}
    return name, args or {}


def from_openai_messages(
    run_id: str,
    messages: list[dict],
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
        if m.get("role") == "assistant" and m.get("tool_calls"):
            for tc in m["tool_calls"]:
                name, args = _parse_openai_tool_call(tc)
                arg_sources = {k: [last_source] for k in args}
                events.append(TraceEvent(
                    run_id=run_id, step=step, tool=name, arg_sources=arg_sources,
                ))
                step += 1
                last_source = f"tool_output:{name}"
        elif m.get("role") == "tool":
            last_source = f"tool_output:{m.get('name', 'unknown')}"
    events.append(TraceEvent(run_id=run_id, step=step, tool=END))
    return events
