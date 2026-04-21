from pathlib import Path
import tempfile

from agent_cfi.graph import (
    TraceEvent, build_graph, diff_graphs, load_graph, load_traces,
    save_graph, parse_edge_spec,
)


def _ev(run_id, step, tool, **sources):
    return TraceEvent(run_id=run_id, step=step, tool=tool,
                      arg_sources={k: list(v) for k, v in sources.items()})


def test_build_graph_transitions_and_probs():
    events = [
        _ev("r1", 0, "__start__"),
        _ev("r1", 1, "a"),
        _ev("r1", 2, "b"),
        _ev("r1", 3, "__end__"),
        _ev("r2", 0, "__start__"),
        _ev("r2", 1, "a"),
        _ev("r2", 2, "c"),
        _ev("r2", 3, "__end__"),
    ]
    g = build_graph(events)
    # a has two outgoing edges: a->b and a->c, each prob 0.5
    assert g.has_edge("a", "b") and g.has_edge("a", "c")
    assert abs(g.edges["a", "b"]["prob"] - 0.5) < 1e-9
    assert abs(g.edges["a", "c"]["prob"] - 0.5) < 1e-9
    # __start__ -> a prob is 1.0
    assert abs(g.edges["__start__", "a"]["prob"] - 1.0) < 1e-9


def test_diff_detects_new_edge_and_drift():
    base_events = [
        _ev("r1", 0, "__start__"), _ev("r1", 1, "a"), _ev("r1", 2, "b"), _ev("r1", 3, "__end__"),
        _ev("r2", 0, "__start__"), _ev("r2", 1, "a"), _ev("r2", 2, "b"), _ev("r2", 3, "__end__"),
        _ev("r3", 0, "__start__"), _ev("r3", 1, "a"), _ev("r3", 2, "b"), _ev("r3", 3, "__end__"),
    ]
    cur_events = [
        _ev("r1", 0, "__start__"), _ev("r1", 1, "a"), _ev("r1", 2, "shell_exec"), _ev("r1", 3, "__end__"),
    ]
    base = build_graph(base_events)
    cur = build_graph(cur_events)
    findings = diff_graphs(base, cur, drift_threshold=0.3)
    kinds = [f.kind for f in findings]
    assert "new_edge" in kinds
    # a->b is absent in current; counts as removed_edge
    assert "removed_edge" in kinds


def test_allow_new_edges_suppresses_new_edge():
    base_events = [
        _ev("r1", 0, "__start__"), _ev("r1", 1, "a"), _ev("r1", 2, "b"), _ev("r1", 3, "__end__"),
    ]
    cur_events = [
        _ev("r1", 0, "__start__"), _ev("r1", 1, "a"), _ev("r1", 2, "b"),
        _ev("r1", 3, "c"), _ev("r1", 4, "__end__"),
    ]
    base = build_graph(base_events)
    cur = build_graph(cur_events)
    findings = diff_graphs(base, cur, allow_new={("b", "c")})
    assert not any(f.kind == "new_edge" and (f.src, f.dst) == ("b", "c") for f in findings)


def test_round_trip_save_load(tmp_path: Path):
    events = [
        _ev("r1", 0, "__start__"),
        _ev("r1", 1, "a"),
        _ev("r1", 2, "__end__"),
    ]
    g = build_graph(events)
    p = tmp_path / "baseline.json"
    save_graph(g, p)
    g2 = load_graph(p)
    assert set(g.nodes) == set(g2.nodes)
    assert set(g.edges) == set(g2.edges)


def test_load_traces_skips_blank_and_comments(tmp_path: Path):
    f = tmp_path / "t.jsonl"
    f.write_text(
        '# comment line\n'
        '\n'
        '{"run_id":"r1","step":0,"tool":"__start__"}\n'
        '{"run_id":"r1","step":1,"tool":"a"}\n'
    )
    evs = load_traces(f)
    assert [e.tool for e in evs] == ["__start__", "a"]


def test_parse_edge_spec():
    assert parse_edge_spec("a -> b") == ("a", "b")
    assert parse_edge_spec("planner->search_docs") == ("planner", "search_docs")
