"""Tests for framework-adapter tracer helpers.

These adapters are pure shape-readers — no langgraph/crewai/autogen imports —
so tests feed minimal synthetic event/message sequences shaped like each
framework's documented public output.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_cfi import (
    END,
    START,
    from_autogen_messages,
    from_crewai_outputs,
    from_langgraph_events,
)


def _tools(events):
    return [e.tool for e in events]


# ---------------------------------------------------------------------------
# from_langgraph_events
# ---------------------------------------------------------------------------


def test_from_langgraph_events_two_step_lineage():
    # Minimal two-step LangGraph stream: a planner emits a tool_call for
    # search_docs, then the tools node hands off to summarize.
    events = [
        {
            "agent": {
                "messages": [
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "search_docs",
                                    "arguments": '{"query": "openai"}',
                                }
                            }
                        ],
                    }
                ]
            }
        },
        {
            "agent": {
                "messages": [
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "summarize",
                                    "arguments": '{"text": "..."}',
                                }
                            }
                        ],
                    }
                ]
            }
        },
    ]

    out = from_langgraph_events("r1", events)

    assert out[0].tool == START
    assert out[-1].tool == END
    assert _tools(out) == [START, "search_docs", "summarize", END]
    # First tool's only arg traces to user_input; second tool's arg traces to
    # the previous tool's output.
    assert out[1].arg_sources == {"query": ["user_input"]}
    assert out[2].arg_sources == {"text": ["tool_output:search_docs"]}


def test_from_langgraph_events_tool_node_name_fallback():
    # When the event key is itself a tool-executor node and there are no
    # tool_calls in messages, the node name is used as the tool.
    events = [
        {"planner": {"messages": [{"role": "assistant", "content": "thinking"}]}},
        {"tools": {"query": "openai"}},
    ]
    out = from_langgraph_events("r-node", events)
    assert _tools(out) == [START, "tools", END]
    assert out[1].arg_sources == {"query": ["user_input"]}


# ---------------------------------------------------------------------------
# from_crewai_outputs
# ---------------------------------------------------------------------------


@dataclass
class _FakeAgentOutput:
    """Stand-in for crewai.AgentOutput to confirm attribute access works."""
    task: str
    agent: str
    tools_used: list = field(default_factory=list)
    raw: str = ""


def test_from_crewai_outputs_lineage_dict_form():
    outputs = [
        {
            "task": "answer-question",
            "agent": "researcher",
            "tools_used": [
                {"tool": "search_docs", "input": {"query": "openai"}},
                {"tool": "summarize", "input": {"text": "from search"}},
            ],
            "raw": "final answer",
        }
    ]

    out = from_crewai_outputs("r2", outputs)

    assert out[0].tool == START
    assert out[-1].tool == END
    assert _tools(out) == [START, "search_docs", "summarize", END]
    assert out[1].arg_sources == {"query": ["user_input"]}
    assert out[2].arg_sources == {"text": ["tool_output:search_docs"]}
    # meta captures task/agent
    assert out[1].meta["task"] == "answer-question"
    assert out[1].meta["agent"] == "researcher"


def test_from_crewai_outputs_object_attrs_and_string_input():
    outputs = [
        _FakeAgentOutput(
            task="t",
            agent="a",
            tools_used=[
                {"tool": "search_docs", "input": "just a string"},
                {"tool": "summarize", "input": {"text": "x"}},
            ],
        )
    ]

    out = from_crewai_outputs("r2b", outputs)
    assert _tools(out) == [START, "search_docs", "summarize", END]
    # String input gets wrapped under "input"; arg_sources must still exist.
    assert out[1].arg_sources == {"input": ["user_input"]}
    assert out[2].arg_sources == {"text": ["tool_output:search_docs"]}


# ---------------------------------------------------------------------------
# from_autogen_messages
# ---------------------------------------------------------------------------


def test_from_autogen_messages_groupchat_lineage():
    # GroupChat-style: user turn -> researcher assistant (tool_call) ->
    # tool result -> writer assistant (agent handoff + tool_call).
    messages = [
        {"role": "user", "name": "user", "content": "find and summarize"},
        {
            "role": "assistant",
            "name": "researcher",
            "content": None,
            "tool_calls": [
                {"function": {"name": "search_docs", "arguments": '{"query": "x"}'}}
            ],
        },
        {"role": "tool", "name": "search_docs", "content": "result-text"},
        {
            "role": "assistant",
            "name": "writer",
            "content": None,
            "tool_calls": [
                {"function": {"name": "summarize", "arguments": '{"text": "y"}'}}
            ],
        },
    ]

    out = from_autogen_messages("r3", messages)

    assert out[0].tool == START
    assert out[-1].tool == END
    tools = _tools(out)
    # Expected: start, researcher handoff, search_docs, writer handoff,
    # summarize, end.
    assert tools == [
        START,
        "researcher",
        "search_docs",
        "writer",
        "summarize",
        END,
    ]
    # search_docs's arg is attributed to the researcher handoff source.
    assert out[2].arg_sources == {"query": ["tool_output:researcher"]}
    # summarize's arg is attributed to the writer handoff source (the most
    # recent lineage update).
    assert out[4].arg_sources == {"text": ["tool_output:writer"]}
    # Handoff events carry a kind marker.
    assert out[1].meta.get("kind") == "agent_handoff"
    assert out[3].meta.get("kind") == "agent_handoff"
