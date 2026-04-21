from __future__ import annotations

from agent_cfi.graph import TraceEvent, build_graph, render_dot


def _ev(run_id: str, step: int, tool: str) -> TraceEvent:
    return TraceEvent(run_id=run_id, step=step, tool=tool)


# Shared colors kept in sync with graph._COLOR_* constants.
RED = "#d73a49"
GREY = "#959da5"
AMBER = "#b08800"


def _linear_graph(tools: list[str], *, run_id: str = "r1"):
    events = [_ev(run_id, i, t) for i, t in enumerate(tools)]
    return build_graph(events)


def test_single_graph_render_contains_core_elements():
    g = _linear_graph(["__start__", "a", "b", "__end__"])
    dot = render_dot(g)

    assert "digraph agent_cfi" in dot
    assert '"a" [label="a\\ncount=1"];' in dot
    assert '"b" [label="b\\ncount=1"];' in dot
    assert '"a" -> "b"' in dot
    assert '"__start__" -> "a"' in dot
    # no coloring when no baseline
    assert RED not in dot
    assert GREY not in dot
    assert AMBER not in dot


def test_diff_identical_graphs_has_no_colored_edges():
    g = _linear_graph(["__start__", "a", "b", "__end__"])
    base = _linear_graph(["__start__", "a", "b", "__end__"])
    dot = render_dot(g, baseline=base)

    # The legend itself references the colors, so strip it before asserting.
    head, _, _legend = dot.partition("subgraph cluster_legend")
    assert RED not in head
    assert GREY not in head
    assert AMBER not in head


def test_diff_new_edge_is_red():
    # Baseline never had a->c; current does.
    base = build_graph([
        _ev("r1", 0, "__start__"), _ev("r1", 1, "a"),
        _ev("r1", 2, "b"), _ev("r1", 3, "__end__"),
    ])
    cur = build_graph([
        _ev("r1", 0, "__start__"), _ev("r1", 1, "a"),
        _ev("r1", 2, "c"), _ev("r1", 3, "__end__"),
    ])
    dot = render_dot(cur, baseline=base)

    # a -> c appears and is colored red.
    red_line = next(
        (ln for ln in dot.splitlines()
         if '"a" -> "c"' in ln and RED in ln),
        None,
    )
    assert red_line is not None, dot
    assert "penwidth=2" in red_line


def test_diff_removed_edge_is_grey_dashed():
    base = build_graph([
        _ev("r1", 0, "__start__"), _ev("r1", 1, "a"),
        _ev("r1", 2, "b"), _ev("r1", 3, "__end__"),
    ])
    cur = build_graph([
        _ev("r1", 0, "__start__"), _ev("r1", 1, "a"),
        _ev("r1", 2, "c"), _ev("r1", 3, "__end__"),
    ])
    dot = render_dot(cur, baseline=base)

    grey_line = next(
        (ln for ln in dot.splitlines()
         if '"a" -> "b"' in ln and GREY in ln),
        None,
    )
    assert grey_line is not None, dot
    assert "style=dashed" in grey_line


def test_diff_drift_is_amber_with_arrow_label():
    # Baseline: a -> b is 1/3, a -> c is 2/3.
    base = build_graph([
        _ev("r1", 0, "__start__"), _ev("r1", 1, "a"), _ev("r1", 2, "b"), _ev("r1", 3, "__end__"),
        _ev("r2", 0, "__start__"), _ev("r2", 1, "a"), _ev("r2", 2, "c"), _ev("r2", 3, "__end__"),
        _ev("r3", 0, "__start__"), _ev("r3", 1, "a"), _ev("r3", 2, "c"), _ev("r3", 3, "__end__"),
    ])
    # Current: a -> b is 1.0 (big drift from 0.33 -> 1.0).
    cur = build_graph([
        _ev("r1", 0, "__start__"), _ev("r1", 1, "a"), _ev("r1", 2, "b"), _ev("r1", 3, "__end__"),
        _ev("r2", 0, "__start__"), _ev("r2", 1, "a"), _ev("r2", 2, "b"), _ev("r2", 3, "__end__"),
    ])
    dot = render_dot(cur, baseline=base, drift_threshold=0.30)

    drift_line = next(
        (ln for ln in dot.splitlines()
         if '"a" -> "b"' in ln and AMBER in ln),
        None,
    )
    assert drift_line is not None, dot
    # Label is "p=BASELINE→CURRENT".
    assert "p=0.33→1.00" in drift_line
