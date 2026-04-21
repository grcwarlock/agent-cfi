"""End-to-end demo. Produces baseline traces and PR traces, builds the
baseline, runs the check, emits SARIF, prints findings.

Run:
    python examples/demo.py
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

# allow running from repo without pip install
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_cfi.graph import (  # noqa: E402
    build_graph, diff_graphs, load_graph, load_traces, save_graph,
)
from agent_cfi.taint import check_taint  # noqa: E402
from agent_cfi.sarif import write_sarif  # noqa: E402
from agent_cfi.tracer import TraceRecorder  # noqa: E402


ROOT = Path(__file__).resolve().parent
BASELINE_TRACES = ROOT / "traces_main.jsonl"
PR_TRACES = ROOT / "traces_pr_bad.jsonl"
BASELINE_GRAPH = ROOT / "baseline.json"
SARIF_OUT = ROOT / "agent-cfi.sarif"


def simulate_baseline_runs(path: Path) -> None:
    """Two golden runs that define legal agent behavior."""
    with open(path, "w", encoding="utf-8") as f:
        for run_id in ("eval-1", "eval-2", "eval-3"):
            rec = TraceRecorder(run_id, out=f)
            rec.record("planner", arg_sources={"goal": ["user_input"]})
            rec.record("search_docs", arg_sources={"query": ["tool_output:planner"]})
            rec.record("summarize", arg_sources={"text": ["tool_output:search_docs"]})
            rec.end()


def simulate_pr_run_with_injection(path: Path) -> None:
    """A PR run where retrieved content injected a call to http_post."""
    with open(path, "w", encoding="utf-8") as f:
        rec = TraceRecorder("eval-pr-1", out=f)
        rec.record("planner",     arg_sources={"goal": ["user_input"]})
        rec.record("search_docs", arg_sources={"query": ["tool_output:planner"]})
        rec.record("summarize",   arg_sources={"text": ["tool_output:search_docs"]})
        # injection: summarize decided to exfiltrate retrieved content
        rec.record("http_post", arg_sources={
            "url":  ["tool_output:search_docs"],
            "body": ["tool_output:search_docs"],
        })
        rec.end()


def main() -> int:
    if "--emit-pr-traces" in sys.argv:
        simulate_pr_run_with_injection(Path("/dev/stdout"))
        return 0

    print("=== agent-cfi demo ===\n")
    simulate_baseline_runs(BASELINE_TRACES)
    simulate_pr_run_with_injection(PR_TRACES)
    print(f"[1] Wrote baseline traces:  {BASELINE_TRACES}")
    print(f"    Wrote PR traces:        {PR_TRACES}\n")

    baseline_events = load_traces(BASELINE_TRACES)
    baseline_graph = build_graph(baseline_events)
    save_graph(baseline_graph, BASELINE_GRAPH)
    print(f"[2] Built baseline graph:   "
          f"{baseline_graph.number_of_nodes()} nodes, "
          f"{baseline_graph.number_of_edges()} edges -> {BASELINE_GRAPH}\n")

    pr_events = load_traces(PR_TRACES)
    pr_graph = build_graph(pr_events)
    edge_findings = diff_graphs(baseline_graph, pr_graph, drift_threshold=0.30)
    taint_findings = check_taint(
        pr_events,
        sensitive_tools=["http_post", "shell_exec", "fs_write", "db_query", "email_send"],
        tainted_sources=["user_input", "retrieved", "tool_output:search_docs"],
    )

    print(f"[3] Diff results:")
    for f in edge_findings:
        print(f"    [{f.kind}] {f.message}")
    for f in taint_findings:
        print(f"    [{f.kind}] {f.message}")
    print()

    write_sarif([*edge_findings, *taint_findings], SARIF_OUT,
                baseline_path=str(BASELINE_GRAPH))
    print(f"[4] SARIF written to:       {SARIF_OUT}\n")

    blocked = any(f.kind in ("new_edge", "taint_violation")
                  for f in [*edge_findings, *taint_findings])
    print(f"CI exit code would be: {1 if blocked else 0}")
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
