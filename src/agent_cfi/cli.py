"""Command-line entrypoint."""
from __future__ import annotations

import argparse
import sys

import yaml

from .graph import (
    build_graph,
    diff_graphs,
    load_graph,
    load_traces,
    parse_edge_spec,
    save_graph,
)
from .probes import load_probes, resolve_agent, run_probes
from .sarif import write_sarif
from .taint import check_taint

DEFAULT_CONFIG: dict = {
    "sensitive_tools": [
        "shell_exec", "http_post", "fs_write", "db_query", "email_send",
    ],
    "tainted_sources": ["user_input", "retrieved", "tool_output:web_fetch"],
    "edge_probability_threshold": 0.30,
    "allow_new_edges": [],
    "fail_on": ["new_edge", "taint_violation"],
    "warn_on": ["edge_drift", "removed_edge"],
}


def _load_config(path: str | None) -> dict:
    user: dict = {}
    if path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                user = yaml.safe_load(f) or {}
        except FileNotFoundError:
            pass
    # Drop None values so `key: null` in YAML falls back to DEFAULT_CONFIG
    # instead of shadowing it with None and breaking downstream set()/float().
    user = {k: v for k, v in user.items() if v is not None}
    return {**DEFAULT_CONFIG, **user}


def cmd_record(args: argparse.Namespace) -> int:
    events = load_traces(args.traces)
    g = build_graph(events)
    save_graph(g, args.out)
    runs = len({e.run_id for e in events})
    print(
        f"agent-cfi: wrote baseline {args.out}\n"
        f"  runs={runs}  events={len(events)}  "
        f"nodes={g.number_of_nodes()}  edges={g.number_of_edges()}"
    )
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    cfg = _load_config(args.config)
    if args.fail_on:
        fail_on = {s.strip() for s in args.fail_on.split(",") if s.strip()}
    else:
        fail_on = set(cfg["fail_on"])

    baseline = load_graph(args.baseline)
    current_events = load_traces(args.current)
    current = build_graph(current_events)

    allow_new = {parse_edge_spec(s) for s in cfg.get("allow_new_edges", [])}

    edge_findings = diff_graphs(
        baseline, current,
        drift_threshold=float(cfg["edge_probability_threshold"]),
        allow_new=allow_new,
    )
    taint_findings = check_taint(
        current_events,
        cfg["sensitive_tools"],
        cfg["tainted_sources"],
    )
    all_findings = [*edge_findings, *taint_findings]
    errs = [f for f in all_findings if f.kind in fail_on]

    print(f"agent-cfi: {len(edge_findings)} graph finding(s), "
          f"{len(taint_findings)} taint finding(s).")
    if not all_findings:
        print("  no drift, no tainted sinks. baseline holds.")
    for f in all_findings:
        tag = "FAIL" if f.kind in fail_on else "warn"
        print(f"  [{tag}] {f.kind}: {f.message}")

    if args.sarif:
        write_sarif(all_findings, args.sarif, baseline_path=args.baseline)
        print(f"  SARIF written to {args.sarif}")

    if errs:
        print(f"\nagent-cfi: FAIL ({len(errs)} blocking finding(s)).")
        return 1
    print("\nagent-cfi: OK")
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    probes = load_probes(args.probes)
    agent = resolve_agent(args.agent)
    results = run_probes(agent, probes, max_workers=args.jobs)
    failed = [r for r in results if not r.passed]
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        extra = f"  forbidden_triggered={r.triggered_forbidden}" if r.triggered_forbidden else ""
        note = f"  note={r.notes}" if r.notes else ""
        print(f"  [{status}] {r.probe_id}  tools={r.observed_tools}{extra}{note}")
    print(f"\n{len(results)} probe(s), {len(failed)} failed.")
    return 1 if failed else 0


def cmd_visualize(args: argparse.Namespace) -> int:
    g = load_graph(args.graph)
    print("digraph agent_cfi {")
    print('  rankdir=LR;')
    print('  node [shape=box,fontname="Helvetica"];')
    for n in sorted(g.nodes):
        print(f'  "{n}" [label="{n}\\ncount={g.nodes[n].get("count", 0)}"];')
    for u, v, d in g.edges(data=True):
        p = float(d.get("prob", 0.0))
        print(f'  "{u}" -> "{v}" [label="p={p:.2f}"];')
    print("}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-cfi",
        description="Control Flow Integrity for AI agents.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("record", help="Build baseline graph from traces.")
    pr.add_argument("--traces", required=True, help="Path to JSONL traces.")
    pr.add_argument("--out", default=".agent-cfi/baseline.json")
    pr.set_defaults(func=cmd_record)

    pc = sub.add_parser("check", help="Diff PR traces against a baseline.")
    pc.add_argument("--baseline", required=True)
    pc.add_argument("--current", required=True)
    pc.add_argument("--config", default=".agent-cfi/config.yaml")
    pc.add_argument("--sarif", default=None)
    pc.add_argument("--fail-on", default=None,
                    help="Comma-separated kinds to fail on (overrides config).")
    pc.set_defaults(func=cmd_check)

    pp = sub.add_parser("probe", help="Run probe pack against an agent.")
    pp.add_argument("--probes", default=None)
    pp.add_argument("--agent", required=True,
                    help="module:callable taking a Probe, returning Iterable[TraceEvent].")
    pp.add_argument("--jobs", type=int, default=None,
                    help="Run probes concurrently in N threads (agent must be thread-safe).")
    pp.set_defaults(func=cmd_probe)

    pv = sub.add_parser("visualize", help="Print graph in DOT format.")
    pv.add_argument("--graph", required=True)
    pv.set_defaults(func=cmd_visualize)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
