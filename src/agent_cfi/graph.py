"""Tool-call graph: build from traces, save/load, diff two graphs.

A trace is a JSONL file, one event per line. Each event:
    {
      "run_id":      "<opaque id, events with same id are one agent run>",
      "step":        <int, monotonic within run>,
      "tool":        "<tool name; __start__ and __end__ are synthetic terminals>",
      "arg_sources": {"<arg_name>": ["<source_label>", ...]},
      "meta":        { ...optional }
    }
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Literal

import networkx as nx

START = "__start__"
END = "__end__"


@dataclass(slots=True)
class TraceEvent:
    run_id: str
    step: int
    tool: str
    arg_sources: dict[str, list[str]] = field(default_factory=dict)
    meta: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "TraceEvent":
        return cls(
            run_id=str(d["run_id"]),
            step=int(d["step"]),
            tool=str(d["tool"]),
            arg_sources=dict(d.get("arg_sources") or {}),
            meta=dict(d.get("meta") or {}),
        )

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "step": self.step,
            "tool": self.tool,
            "arg_sources": self.arg_sources,
            "meta": self.meta,
        }


def load_traces(path: str | Path) -> list[TraceEvent]:
    events: list[TraceEvent] = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                events.append(TraceEvent.from_dict(json.loads(line)))
            except (KeyError, ValueError, json.JSONDecodeError) as e:
                raise ValueError(f"{path}:{i}: malformed trace event: {e}") from e
    return events


def build_graph(events: Iterable[TraceEvent]) -> nx.DiGraph:
    """Build a weighted directed graph of tool transitions.

    Node attrs: count (int)
    Edge attrs: count (int), prob (float, normalized out of source node)
    """
    g: nx.DiGraph = nx.DiGraph()

    runs: dict[str, list[TraceEvent]] = {}
    for e in events:
        runs.setdefault(e.run_id, []).append(e)

    for run_events in runs.values():
        run_events.sort(key=lambda e: e.step)
        for i, e in enumerate(run_events):
            if e.tool in g:
                g.nodes[e.tool]["count"] += 1
            else:
                g.add_node(e.tool, count=1)
            if i > 0:
                prev = run_events[i - 1].tool
                ed = g.get_edge_data(prev, e.tool)
                if ed is None:
                    g.add_edge(prev, e.tool, count=1)
                else:
                    ed["count"] += 1

    for u in g.nodes:
        out = list(g.out_edges(u, data=True))
        total = sum(d["count"] for _, _, d in out) or 1
        for _, v, d in out:
            d["prob"] = d["count"] / total

    return g


def graph_to_dict(g: nx.DiGraph) -> dict:
    return {
        "nodes": [{"tool": n, "count": g.nodes[n].get("count", 0)} for n in sorted(g.nodes)],
        "edges": [
            {
                "from": u,
                "to": v,
                "count": g.edges[u, v].get("count", 0),
                "prob": round(float(g.edges[u, v].get("prob", 0.0)), 6),
            }
            for u, v in sorted(g.edges)
        ],
    }


def graph_from_dict(d: dict) -> nx.DiGraph:
    g: nx.DiGraph = nx.DiGraph()
    for n in d.get("nodes", []):
        attrs = {k: v for k, v in n.items() if k != "tool"}
        g.add_node(n["tool"], **attrs)
    for e in d.get("edges", []):
        attrs = {k: v for k, v in e.items() if k not in ("from", "to")}
        g.add_edge(e["from"], e["to"], **attrs)
    return g


def save_graph(g: nx.DiGraph, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(graph_to_dict(g), f, indent=2, sort_keys=True)
        f.write("\n")


def load_graph(path: str | Path) -> nx.DiGraph:
    with open(path, "r", encoding="utf-8") as f:
        return graph_from_dict(json.load(f))


EdgeKind = Literal["new_edge", "removed_edge", "edge_drift"]


@dataclass(frozen=True, slots=True)
class EdgeFinding:
    kind: EdgeKind
    src: str
    dst: str
    baseline_prob: float
    current_prob: float
    delta: float
    message: str


def _edge_finding(
    kind: EdgeKind,
    edge: tuple[str, str],
    bp: float,
    cp: float,
    message: str,
) -> EdgeFinding:
    return EdgeFinding(
        kind=kind,
        src=edge[0], dst=edge[1],
        baseline_prob=bp, current_prob=cp, delta=cp - bp,
        message=message,
    )


def diff_graphs(
    baseline: nx.DiGraph,
    current: nx.DiGraph,
    *,
    drift_threshold: float = 0.30,
    allow_new: set[tuple[str, str]] | None = None,
) -> list[EdgeFinding]:
    allow_new = allow_new or set()
    findings: list[EdgeFinding] = []

    base_edges = {(u, v): d for u, v, d in baseline.edges(data=True)}
    cur_edges = {(u, v): d for u, v, d in current.edges(data=True)}

    for edge, d in cur_edges.items():
        cp = float(d.get("prob", 0.0))
        if edge not in base_edges:
            if edge in allow_new:
                continue
            findings.append(_edge_finding(
                "new_edge", edge, 0.0, cp,
                f"New tool-call edge {edge[0]} -> {edge[1]} (p={cp:.2f}) "
                "not present in baseline graph.",
            ))
        else:
            bp = float(base_edges[edge].get("prob", 0.0))
            if abs(cp - bp) >= drift_threshold:
                findings.append(_edge_finding(
                    "edge_drift", edge, bp, cp,
                    f"Edge probability drift on {edge[0]} -> {edge[1]}: "
                    f"{bp:.2f} -> {cp:.2f} (delta {cp - bp:+.2f}).",
                ))

    for edge, d in base_edges.items():
        if edge not in cur_edges:
            bp = float(d.get("prob", 0.0))
            findings.append(_edge_finding(
                "removed_edge", edge, bp, 0.0,
                f"Baseline edge {edge[0]} -> {edge[1]} absent in current traces.",
            ))

    return findings


def parse_edge_spec(spec: str) -> tuple[str, str]:
    """Parse 'a->b' into ('a', 'b')."""
    if "->" not in spec:
        raise ValueError(f"expected 'src->dst', got {spec!r}")
    src, dst = spec.split("->", 1)
    return src.strip(), dst.strip()
