import json
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]


def _run(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "agent_cfi", *args],
        cwd=REPO, capture_output=True, text=True,
    )


def _write_traces(path: Path, lines: list[dict]) -> None:
    with open(path, "w") as f:
        for ln in lines:
            f.write(json.dumps(ln) + "\n")


def test_record_and_check_clean(tmp_path: Path):
    base = [
        {"run_id": "r1", "step": 0, "tool": "__start__"},
        {"run_id": "r1", "step": 1, "tool": "a"},
        {"run_id": "r1", "step": 2, "tool": "b"},
        {"run_id": "r1", "step": 3, "tool": "__end__"},
    ]
    t_base = tmp_path / "base.jsonl"
    t_cur = tmp_path / "cur.jsonl"
    graph = tmp_path / "baseline.json"

    _write_traces(t_base, base)
    _write_traces(t_cur, base)

    r = _run("record", "--traces", str(t_base), "--out", str(graph))
    assert r.returncode == 0, r.stderr
    assert graph.exists()

    r = _run(
        "check",
        "--baseline", str(graph),
        "--current", str(t_cur),
        "--config", str(REPO / "examples" / "config.yaml"),
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_check_fails_on_new_edge(tmp_path: Path):
    base = [
        {"run_id": "r1", "step": 0, "tool": "__start__"},
        {"run_id": "r1", "step": 1, "tool": "planner"},
        {"run_id": "r1", "step": 2, "tool": "summarize"},
        {"run_id": "r1", "step": 3, "tool": "__end__"},
    ]
    pr = [
        {"run_id": "r1", "step": 0, "tool": "__start__"},
        {"run_id": "r1", "step": 1, "tool": "planner"},
        {"run_id": "r1", "step": 2, "tool": "summarize"},
        {"run_id": "r1", "step": 3, "tool": "http_post",
         "arg_sources": {"body": ["tool_output:summarize"]}},
        {"run_id": "r1", "step": 4, "tool": "__end__"},
    ]
    t_base = tmp_path / "base.jsonl"
    t_cur = tmp_path / "cur.jsonl"
    graph = tmp_path / "baseline.json"
    sarif = tmp_path / "out.sarif"

    _write_traces(t_base, base)
    _write_traces(t_cur, pr)

    _run("record", "--traces", str(t_base), "--out", str(graph))
    r = _run(
        "check",
        "--baseline", str(graph),
        "--current", str(t_cur),
        "--config", str(REPO / "examples" / "config.yaml"),
        "--sarif", str(sarif),
    )
    assert r.returncode == 1, r.stdout
    assert "new_edge" in r.stdout
    sarif_data = json.loads(sarif.read_text())
    rule_ids = {res["ruleId"] for res in sarif_data["runs"][0]["results"]}
    assert "agent-cfi/new-edge" in rule_ids
