# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool (SIH26164)

Person 3 platform layer: CLI, GUI, SQLite store, exports/reports, CI gate,
and benchmark harness. **Mock-first**: detection, risk, graph, migration,
and PQC intelligence are deterministic placeholders until Person 1 (core
intelligence) and Person 2 (discovery/scanning) integrate. Mock behavior is
labeled `mock` in code, CLI output, GUI badges, and tests.

## Prerequisites

- Python 3.10+
- `pip install -e .` (runtime dep: `jsonschema`; tests need `pytest`)
- No network, no credentials, no external services required.

## Validate

```bash
python -m pytest -q
```

Must report all tests passing (currently 450+). Nothing else is required
to verify the platform.

## One-command local demo

```bash
python -m ecdat.cli demo
```

Seeds a fresh temp workspace (two mock targets) through the real scan
pipeline and serves the dashboard at `http://127.0.0.1:8734`
(loopback only; `--port 0` for an ephemeral port, `--db PATH` to reuse
a database). Press Ctrl-C to stop. Useful variants:

```bash
python -m ecdat.cli demo --port 0   # avoid port clashes
python -m ecdat.cli gui             # dashboard on your own DB (no seeding)
```

## Demo workflow (dashboard cards)

1. **Target** — pick a seeded demo target (or type any path).
2. **Scan-plan preview + monitor** — read-only plan, simulated progress.
3. **Inventory/findings** — click rows for finding detail (Card 6).
4. **Risk dashboard** — mock severity-weight scoring (labeled).
5. **Asset inventory + groupings** — flat CBOM-derived assets (Card 7).
6. **Knowledge graph** — `MOCK DATASET` badge; not scan data (Card 8).
7. **Migration planner** — severity triage only, `MOCK / PLACEHOLDER` (Card 9).
8. **Reports** — view/download HTML, PDF, CSV, JSON, SARIF (Card 10).

## CLI commands

`scan`, `scan-binary`, `scan-container`, `scan-cloud` (all mock fixtures),
`list`, `show`, `risk`, `recommend`, `export` (json/csv/cbom-json/cbom-xml/sarif),
`report` (markdown/console/html/pdf), `ci` (mock-first gate with
`--fail-on`, `--json`, `--summary`, `--sarif`), `gui`, `demo`.
`python -m ecdat.benchmark run|cases|suite-run|baselines` runs the benchmark harness
(`suite-run --baseline NAME` evaluates one registered baseline).

## Generated artifacts

Reports: Markdown, console, HTML, PDF (stdlib-only). Exports: JSON, CSV,
CBOM JSON/XML, SARIF 2.1.0. Benchmark: JSON results, HTML/CSV/SVG/PDF
artifacts. GUI Card 10 serves HTML/PDF/CSV/JSON/SARIF downloads.

## Mock-first limitations (current)

- Scanners return deterministic fixtures; nothing is really analyzed.
- Risk = severity-weight sum; recommendations = static map + fallback.
- Graph is hand-authored and scan-independent; migration tracks no state.
- Benchmark accuracy metrics run over synthetic labels only.
- Proof: `grep -ri mock ecdat/ | wc -l` labels them everywhere.

## P1/P2 integration points (blocked on owners)

| Need | Owner | Seam (ready) |
|---|---|---|
| Real detection / Core API | Person 1 | `CoreClient` protocol (`ecdat/core/client.py`); `RealCoreClient` raises until agreed |
| CIR graph data | Person 1 | `GraphProvider` protocol (`ecdat/gui/graph.py`) |
| Risk / PQC engines | Person 1 | `risk_from_findings`, `recommend_cmd` map, `MigrationProvider` |
| Discovery/evidence inputs | Person 2 | Mock routing in `MockCoreClient`; specialized scan commands |
| Real benchmark labels/baselines | Person 1/2 | `PredictionProvider`, ground-truth model, accuracy gate |

Contracts P1/P2 must satisfy are pinned in `tests/contract/`.

## Troubleshooting

- Port busy: `demo --port 0`. Non-loopback `--host`: refused by design.
- Stale DB confusion: `demo` uses a fresh temp dir each run (path printed).
- `pytest` failures: run `python -m pytest -q`; GUI tests bind 127.0.0.1
  ephemeral ports only.
