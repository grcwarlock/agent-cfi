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
from .tracer import (
    TraceRecorder,
    from_openai_messages,
    from_langgraph_events,
    from_crewai_outputs,
    from_autogen_messages,
)
from .probes import Probe, ProbeResult, load_probes, run_probes
from .fuzz import paraphrase, fuzz_probes
from .mcp import (
    MCPSchemaFinding,
    hash_schema,
    pin_schemas,
    check_schemas,
    save_pins,
    load_pins,
)

__version__ = "0.2.1"

__all__ = [
    "TraceEvent",
    "TraceRecorder",
    "EdgeFinding",
    "TaintFinding",
    "MCPSchemaFinding",
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
    "paraphrase",
    "fuzz_probes",
    "from_openai_messages",
    "from_langgraph_events",
    "from_crewai_outputs",
    "from_autogen_messages",
    "hash_schema",
    "pin_schemas",
    "check_schemas",
    "save_pins",
    "load_pins",
]
