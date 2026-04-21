from agent_cfi.graph import TraceEvent
from agent_cfi.taint import check_taint


def _ev(run_id, step, tool, **sources):
    return TraceEvent(run_id=run_id, step=step, tool=tool,
                      arg_sources={k: list(v) for k, v in sources.items()})


def test_taint_flags_direct_user_input_to_sensitive_sink():
    events = [_ev("r1", 5, "http_post", body=["user_input"])]
    findings = check_taint(events, {"http_post"}, {"user_input"})
    assert len(findings) == 1
    assert findings[0].tool == "http_post"
    assert findings[0].source == "user_input"


def test_taint_wildcard_matches_tool_output_prefix():
    events = [_ev("r1", 3, "http_post", body=["tool_output:search_docs"])]
    findings = check_taint(events, {"http_post"}, {"tool_output:*"})
    assert len(findings) == 1
    assert findings[0].source == "tool_output:search_docs"


def test_taint_ignores_non_sensitive_tool():
    events = [_ev("r1", 2, "summarize", text=["user_input"])]
    findings = check_taint(events, {"http_post"}, {"user_input"})
    assert findings == []


def test_taint_ignores_literal_source():
    events = [_ev("r1", 2, "http_post", url=["literal"])]
    findings = check_taint(events, {"http_post"}, {"user_input", "retrieved"})
    assert findings == []


def test_taint_multiple_sources_on_one_arg():
    events = [_ev("r1", 2, "fs_write", path=["literal"], contents=["user_input", "retrieved"])]
    findings = check_taint(events, {"fs_write"}, {"user_input", "retrieved"})
    # both user_input AND retrieved on `contents` should each be flagged
    assert len(findings) == 2
    assert {f.source for f in findings} == {"user_input", "retrieved"}
