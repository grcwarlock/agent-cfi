"""agent-cfi: Control Flow Integrity for AI agents.

Diff the tool-call graph between main and a PR. Fail on new edges,
probability drift, or tainted sources reaching sensitive sinks.
"""
from .graph import (
    TraceEvent,
    EdgeFinding,
    START,
    END,
    build_graph,
    load_traces,
    save_graph,
    load_graph,
    diff_graphs,
)
from .taint import TaintFinding, check_taint
from .tracer import TraceRecorder
from .probes import Probe, ProbeResult, load_probes, run_probes

__version__ = "0.1.0"

__all__ = [
    "TraceEvent",
    "TraceRecorder",
    "EdgeFinding",
    "TaintFinding",
    "Probe",
    "ProbeResult",
    "START",
    "END",
    "build_graph",
    "load_traces",
    "save_graph",
    "load_graph",
    "diff_graphs",
    "check_taint",
    "load_probes",
    "run_probes",
]
