# agent-cfi

**Control Flow Integrity for AI agents.**

Your eval suite tells you if your agent works. `agent-cfi` tells you if your agent is still the same agent after this PR.

---

## The idea

Classic CFI protects compiled binaries from ROP attacks by verifying that every indirect call lands on a target the compiler said was legal. If an attacker smashes the stack and redirects execution, the CFG check catches it.

Prompt injection is the ROP of AI agents. An attacker smuggles instructions through a document, an issue comment, or a tool response, and coerces your agent into calling tools it shouldn't — shell when it should only be reading, `http.post` with exfiltrated data, `fs.write` to a sensitive path. Runtime guardrails see each call in isolation. Eval suites see pass/fail. Nothing gates on the **shape** of the agent's tool-call graph.

`agent-cfi` does.

1. Run your agent's eval suite on `main`. Capture every tool call as a trace.
2. Build a Markov graph of observed tool transitions. Commit it as `.agent-cfi/baseline.json`.
3. On every PR, re-run evals and diff the graph. New edges, shifted probabilities, or tainted sources reaching sensitive sinks → CI fails.
4. Ship with a red-team probe pack derived from 2025–2026 CVEs (CamoLeak, EchoLeak, InversePrompt, Rules-File Backdoor, CurXecute). Green probes mean your guardrails held.

That's it. Under 1k lines of Python, one GitHub Action, one YAML probe file.

## Why this is novel

Runtime firewalls (Lakera, LLM-Guard, NeMo Guardrails) see a single call and ask "is this one bad?" Red-team frameworks (Garak, PyRIT, Promptfoo) ask "did my agent fail this scenario?" Neither models the agent's **allowed behavior as a graph** and gates drift in CI.

Academic work exists — AgentSpec (arXiv 2503.18666), probabilistic runtime enforcement (arXiv 2508.00500) — but no OSS tool ships CFI-as-a-CI-gate. This is the gap.

## Install

```bash
pip install git+https://github.com/grcwarlock/agent-cfi@v0.1.0
```

Not yet on PyPI.

Dependencies: `networkx`, `pyyaml`. That's it.

## Quickstart

### 1. Capture traces

Record tool-use from your agent. `agent-cfi` reads a simple JSONL format, one event per line:

```jsonl
{"run_id": "r1", "step": 0, "tool": "__start__", "arg_sources": {}}
{"run_id": "r1", "step": 1, "tool": "search_docs", "arg_sources": {"query": ["user_input"]}}
{"run_id": "r1", "step": 2, "tool": "summarize", "arg_sources": {"text": ["tool_output:search_docs"]}}
{"run_id": "r1", "step": 3, "tool": "__end__", "arg_sources": {}}
```

`agent_cfi.tracer` ships `TraceRecorder` for emitting events directly, plus framework-adapter helpers that convert native event/message sequences into `list[TraceEvent]`:

- `from_openai_messages` — OpenAI chat/tool_calls message list
- `from_langgraph_events` — LangGraph `graph.stream()` state-update events
- `from_crewai_outputs` — CrewAI `AgentOutput` / `TaskOutput` objects
- `from_autogen_messages` — AutoGen GroupChat message sequences

Adapters are pure shape-readers (no framework imports), accept dicts or native objects, and bookend with `__start__` / `__end__`. Bring-your-own for other frameworks — the format is stable and trivial.

### 2. Build the baseline from `main`

```bash
agent-cfi record --traces traces.jsonl --out .agent-cfi/baseline.json
```

Commit `.agent-cfi/baseline.json`. That's your CFG.

### 3. Gate PRs

```bash
agent-cfi check \
  --baseline .agent-cfi/baseline.json \
  --current pr-traces.jsonl \
  --config .agent-cfi/config.yaml \
  --sarif agent-cfi.sarif
```

Exit code 1 on violations. SARIF output uploads cleanly to GitHub Code Scanning.

### 4. Run the probe pack

```bash
agent-cfi probe --agent mypkg.agent:run
# run probes concurrently (agent must be thread-safe):
agent-cfi probe --agent mypkg.agent:run --jobs 8
```

`--agent` takes a `module:callable` that accepts a `Probe` and returns an iterable of `TraceEvent`. Injection payloads are derived from real 2025–2026 CVEs; each probe asserts the agent either refuses or stays inside the allowed graph.

### 5. Fuzz the probe pack (optional)

Agents that pass probes via exact-string regex matches are cheating. `agent-cfi fuzz-probes` expands the pack with rule-based paraphrases — synonyms, reordering, benign prefixes/suffixes, punctuation mangling, optional Unicode lookalikes — so you can check the guardrail generalizes. Offline only; no LLM calls, no network.

```bash
agent-cfi fuzz-probes --out probes-fuzzed.yaml --count 5
agent-cfi probe --agent mypkg.agent:run --probes probes-fuzzed.yaml
```

Use `--seed INT` for deterministic output and `--unicode` to include Cyrillic/Greek homoglyph substitutions.

## GitHub Action

```yaml
# .github/workflows/agent-cfi.yml
- uses: grcwarlock/agent-cfi@v0.1.0
  with:
    traces: pr-traces.jsonl
    baseline: .agent-cfi/baseline.json
    config: .agent-cfi/config.yaml
    upload-sarif: true
```

See [`action.yml`](action.yml).

## What it catches

| Attack | How `agent-cfi` detects it |
|---|---|
| Indirect prompt injection → unexpected tool call | New edge in graph (`summarize → shell_exec`) |
| Exfiltration via `http.post` after reading secrets | Tainted source (`tool_output:fs_read`) reaches sink arg (`http_post.body`) |
| Agent hijacked into loop (e.g., billing drain) | Edge probability drift beyond threshold |
| Rules-file backdoor changing tool preference | Baseline edges drop off; new edges appear |
| MCP tool "rug-pull" (schema silently mutates between main and PR) | Pinned SHA256 per tool schema on main, re-hashed on PR; `mcp_schema_mismatch` finding on any added, removed, or changed tool |

## What it does NOT do

- It doesn't run at inference time. Use `LLM-Guard`, `Lakera`, or `NeMo Guardrails` for that.
- It doesn't detect jailbreaks that produce text-only output. Use `Garak` / `PyRIT`.
- It doesn't scan model weights. Use `ModelScan`.
- It sits where those tools don't: **in CI, gating agent-behavior drift on every PR.**

## Config

```yaml
# .agent-cfi/config.yaml
sensitive_tools:
  - shell_exec
  - http_post
  - fs_write
  - db_query
  - email_send
tainted_sources:
  - user_input
  - retrieved
  - tool_output:web_fetch
  - tool_output:search_docs
edge_probability_threshold: 0.30   # fail if any edge's p shifts by more
allow_new_edges: []                # whitelist, e.g. ["search_docs->summarize"]
fail_on: [new_edge, taint_violation]
warn_on: [edge_drift, removed_edge]
```

## How the graph is built

Every trace run contributes a sequence of tool calls. We add edges `prev → curr` weighted by count, then normalize per-source-node to get transition probabilities. `__start__` and `__end__` are synthetic terminals.

```
__start__ --1.0--> planner
planner  --0.8--> search_docs
planner  --0.2--> fs_read
search_docs --1.0--> summarize
summarize --1.0--> __end__
```

A PR that introduces `summarize → shell_exec` is an unambiguous new edge. A PR that shifts `planner → fs_read` from 0.2 to 0.9 is behavioral drift. Both fail the gate (configurable).

Inspect a baseline with `agent-cfi visualize` — it emits Graphviz DOT, pipe through `dot -Tsvg` for a rendered graph. Two modes:

```bash
# Single graph: just the current topology with counts and probs.
agent-cfi visualize --graph .agent-cfi/baseline.json | dot -Tsvg > graph.svg

# Diff overlay: colorize edges vs a baseline.
#   red          = new edge (present in current, absent in baseline)
#   grey dashed  = removed edge (in baseline, gone in current)
#   amber        = edge_drift, label shows "p=baseline→current"
agent-cfi visualize --graph pr.json --baseline main.json | dot -Tsvg > diff.svg
```

`--drift-threshold` (default `0.30`) controls how much a probability must shift before an edge is classified as drift.

## Taint rules

Each trace event declares, per argument, a list of source labels (e.g. `user_input`, `retrieved`, `tool_output:web_fetch`). If any source listed under a sensitive tool's argument matches a `tainted_sources` pattern from the config, we emit a finding:

```
  [FAIL] taint_violation: Tainted source 'tool_output:search_docs' reaches sensitive sink http_post.body (run eval-pr-1, step 4).
```

Patterns support a trailing `*` wildcard (e.g. `tool_output:*` matches any `tool_output:<name>`). The tracer just needs you to tag `arg_sources` when you emit each event.

## Philosophy

`agent-cfi` is deliberately small. One primitive — **the agent's tool-call graph is a policy artifact** — applied at one place — **the CI gate**. No models, no network calls, no embeddings. Runs in a few seconds on a laptop.

If you need runtime enforcement, write a guardrail. If you need behavioral regression testing in CI, you need this.

## License

MIT. See [LICENSE](LICENSE).

## References

The research that motivated this repo:

- Pillar Security — [Rules File Backdoor in Copilot & Cursor](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- Legit Security — [CamoLeak / CVE-2025-59145](https://www.legitsecurity.com/blog/camoleak-critical-github-copilot-vulnerability-leaks-private-source-code)
- Trail of Bits — [Prompt Injection Engineering for Copilot](https://blog.trailofbits.com/2025/08/06/prompt-injection-engineering-for-attackers-exploiting-github-copilot/)
- Aikido — [PromptPwnd: GitHub Actions AI Agents](https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents)
- arXiv 2503.18666 — AgentSpec: Customizable Runtime Enforcement
- arXiv 2508.00500 — Proactive Runtime Enforcement via Probabilistic Model Checking
- arXiv 2506.23260 — From Prompt Injections to Protocol Exploits
- OWASP — [Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
