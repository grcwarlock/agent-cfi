# Changelog

All notable changes to `agent-cfi` are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/), and versions follow
[SemVer](https://semver.org/).

## [0.2.1] - 2026-04-21

### Added
- `agent-cfi --version` flag.
- GitHub Action now exposes `mcp-pins`, `mcp-current`, and `python-version`
  inputs so Marketplace consumers can enable MCP schema pinning in CI.
- `examples/probe_agent.py` — reference `safe_agent` / `unsafe_agent`
  implementations showing the `Probe -> Iterable[TraceEvent]` contract.
- Unit-test CI workflow (`.github/workflows/test.yml`) running pytest on
  Python 3.10 / 3.11 / 3.12 for every push and PR.
- `CHANGELOG.md`.

### Changed
- SARIF tool version now tracks `agent_cfi.__version__` instead of being
  hard-coded, so package and SARIF output can't drift apart.

## [0.2.0] - 2026-04-21

All five roadmap items shipped in a single release.

### Added
- **MCP schema hash-pinning.** New `agent-cfi mcp-pin` subcommand, `mcp.py`
  module, `mcp_schema_mismatch` finding kind with its own SARIF rule, and
  `--mcp-pins`/`--mcp-current` on `agent-cfi check`. Detects silent
  rug-pulls between `main` and a PR (added/removed/changed tools).
- **Diff-overlay graph visualization.** `agent-cfi visualize --baseline`
  colorizes edges: new=red, removed=grey dashed, drift=amber with
  `p=baseline→current` label. Pure `render_dot()` helper extracted for
  testability.
- **Native framework tracer adapters.** `from_langgraph_events`,
  `from_crewai_outputs`, and `from_autogen_messages`. Pure shape-readers —
  zero framework imports. Accept dicts or native objects.
- **Offline paraphrase fuzzer.** New `agent-cfi fuzz-probes` subcommand and
  `fuzz.py` module. Rule-based variants (synonyms, prefixes/suffixes,
  whitespace/punctuation mangling, sentence reorder, optional Unicode
  homoglyphs). Deterministic under `--seed`. No LLM calls, no network.
- **Probe pack v2.** Six CVE-derived probes covering MCP tool-response
  poisoning, MCP cross-server handoff, MCP runtime rug-pull, Camo-proxy
  SVG attribute exfil, link-unfurl preview exfil, and markdown data-URI
  trackers. Pack grew from 12 to 18 probes.

### Changed
- 43 tests now pass (up from 13).
- Finding dataclasses are now `frozen=True, slots=True` value objects.

## [0.1.0] - 2026-04-21

Initial release. Core CFI loop: `record` → commit baseline →
`check` diffs PR traces → fails CI on new edges, drift, or tainted
sources reaching sensitive sinks. SARIF output for GitHub Code Scanning.
Composite GitHub Action. Red-team probe pack derived from 2025–2026
CVEs.
