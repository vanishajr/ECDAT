# ECDAT Person 3 — Release Readiness (SIH26164)

Freeze state: branch `person3-platform`, HEAD `cf936ac`, `python -m pytest -q` →
**497 passing**. Task 35 integration audit: **PASS** (no known P3 bugs).
This document describes what exists. It claims no real detection,
accuracy, PQC intelligence, or superiority.

## 1. P3 scope

Person 3 owns the platform layer: CLI, localhost GUI dashboard, SQLite
store, exports/reports, CI gate, benchmark harness (engine, ground truth,
reports/charts/PDF, baseline-adapter framework), consumer contracts for
P1/P2, and deterministic mock/simulation fixtures. Everything
intelligent-looking is a labeled placeholder until Person 1 (core
intelligence) and Person 2 (discovery/scanning) integrate through the
pinned contracts (`tests/contract/`).

## 2. Current architecture

```
Target → CoreClient (mock today) → canonical v1 JSON → validate()
  → SQLite (insert_scan + insert_findings_for_scan)
  → read-back via get_scan_doc (single source of truth)
  → risk/recommend (mock) → exports/reports/CI/GUI
GUI: GuiService (use cases) → server.py (loopback HTTP + static page)
Benchmarks: seeded suite → PredictionProvider → evaluate_cases
  → execution metadata → report → HTML/CSV/SVG/PDF
Baselines: registry → availability probe → normalized predictions
  → same evaluate_cases engine → same report shape
```

## 3. CLI capabilities

`scan`, `scan-binary`, `scan-container`, `scan-cloud` (mock fixtures,
`--mock` default), `list`, `show`, `risk`, `recommend`, `export`
(json/csv/cbom-json/cbom-xml/sarif), `report`
(markdown/console/html/pdf; pdf needs `--output`), `ci`
(`--fail-on/--json/--summary/--sarif`; exit 0 pass, 1 on gated failure
or unknown scan), `gui` (existing DB, no seeding), `demo` (fresh temp
workspace, two mock targets). `python -m ecdat.benchmark
list|run|cases|suite-run|baselines`; `suite-run` accepts
`--baseline NAME`, `--group`, `--json/--output/--html/--csv/--charts/--pdf`.

## 4. GUI capabilities

Loopback-only dashboard (`http://127.0.0.1:8734`, `--port 0` for an
ephemeral port; non-loopback hosts refused). Cards 1–10: target →
scan-plan preview + simulated monitor → inventory/findings + finding
detail (WHAT/WHERE/WHY/EVIDENCE) → risk dashboard → asset inventory +
groupings → knowledge graph → migration planner → reports/downloads.
A lightweight workflow rail links Scan → Discovery → Risk → Graph →
Migration → Report without blocking free navigation; severity/rule
filters are preserved across cross-links; empty states are actionable
and mock-labeled.

## 5. SQLite/storage

Fresh temp DB per benchmark/demo run unless `--db PATH` is given.
`insert_scan` + `insert_findings_for_scan`; duplicate fixture `scan_id`
re-insertion raises `sqlite3.IntegrityError` and is handled by reuse —
the store never corrupts on repeat runs. All reads go through
`get_scan_doc()` + `validate()`.

## 6. Export formats

JSON, CSV, CBOM JSON, CBOM XML, SARIF 2.1.0, Markdown, console, HTML,
stdlib-only PDF. Cross-format count consistency + determinism are
gated by `test_export_conformance.py`.

## 7. Risk/recommendation placeholder behavior

`risk_from_findings`: severity weights critical=10, high=5, medium=3,
low=1, info=0 (unknown severities score 0 but stay in the breakdown);
levels none(0)/low(1–4)/medium(5–9)/high(10–19)/critical(20+), labeled
`MOCK SCORING MODEL`. `recommend_for_findings`: static text for 7 known
rule IDs, severity fallback otherwise, deduped by `rule_id`, sorted.

## 8. Graph behavior

Hand-authored deterministic mock dataset (`MOCK DATASET` badge),
scan-independent, served via `GraphProvider` → `to_frontend_graph()`
(closed node/relation vocabularies, validated layout; malformed graphs
raise `ValueError` and never render). UI supports pan/zoom/fit,
keyboard selection, trace paths, type/risky filtering, rule-level
`Show in inventory` links, and honest scope notes (topology ≠ scan).

## 9. Migration planner behavior

Strict recombination of existing recommendations + affected files +
mock-graph rule links, labeled `MOCK / PLACEHOLDER`. Item status is
always `not started (mock — v1 tracks no migration state)`; ordering
is severity triage (heaviest first), explicitly NOT a migration
sequence. No timelines, effort, owners, phases, or PQC targets exist.

## 10. CI behavior

`ci <target>`: mock scan → validate → store → risk gate. `--fail-on
LEVEL` trips exit 1 when the mock level meets the threshold; `--json`,
`--summary`, `--sarif` outputs supported. 26 tests in `test_ci.py`.

## 11. Benchmark architecture

Seeded synthetic suite (`ecdat-seed-suite` v1) → `PredictionProvider`
→ `evaluate_cases` (single metric engine) → `run_suite` (timing +
resources via stdlib) → `logical_result` (volatile fields stripped for
byte-identical reproducibility) → `build_report` (micro-averaged
groups, unavailable-metrics preserved) → HTML/CSV/SVG/PDF renderers.

## 12. Baseline adapter framework

Registry of 7 families (grep/ripgrep, CBOMkit/Sonar-style, cdxgen,
Syft/Trivy, strings/objdump, LIEF-only, YARA-only). Availability via
`shutil.which` only — tools are never executed, downloaded, or
contacted; versions never probed. Run states: EVALUATED / FAILED /
UNAVAILABLE / NOT_APPLICABLE; unavailable tools attempt zero cases and
produce no metrics. `MockBaselineAdapter` test doubles (TEST/MOCK
labeled) prove the pipeline deterministically.

## 13. Mock/simulation infrastructure

`MockCoreClient` routing (empty/multi/minimal fixtures),
`MockGraphProvider`, `MockMigrationProvider`, `MockPredictionProvider`,
`MockBaselineAdapter`, plus realistic P1/P2-shaped fixtures under
`tests/fixtures/p1p2/` (TEST DATA ONLY — never presented as detected
intelligence). Session activity feed is tab-local and never persisted
as history.

## 14. Current test count

**497 passing** (`python -m pytest -q`), including contract suites for
core/graph/risk/migration, export conformance, GUI + workflow cohesion,
P1/P2 simulation, and baseline adapters.

## 15. End-to-end verification performed (Task 35)

CLI battery (all scan variants, list/show/risk/recommend, all export
and report formats, CI pass + gated-fail exit codes), live GUI walk
(plan → scan → inventory → detail → risk → graph selection/trace →
migration → reports; 6/6 workflow steps; no `undefined`/`null`/`NaN`;
no page overflow at 1440/800; zero console messages), loopback refusal
of `0.0.0.0`, duplicate-scan guard, benchmark CLI + determinism
(byte-identical logical JSON), honest unavailable-baseline reporting,
and a clean `git status` before/after (tests modify no tracked files).

## 16. Security/local-first guarantees

Loopback-only GUI (`LOOPBACK_HOSTS` enforced, tested); no network
calls, downloads, subprocess invocations, secrets, or hard-coded paths
in `ecdat/` (audited); stdlib-only runtime (`jsonschema` is the sole
runtime dependency); no external fonts/CDN; PII redaction honestly
reports `applied: false` with reason (v1 defines no PII markers).

## 17. Explicit limitations

No real detection, accuracy, risk/PQC engines, CIR data,
discovery/evidence inputs, real benchmark labels, migration state,
PQC targets/timelines/effort, cache behavior, duplicate suppression
on real streams, PNG chart rendering, or `[project.scripts]`
entrypoint. Benchmark metrics run over synthetic labels only.

## 18. P1/P2 integration dependencies

Real Core API + detection (P1), CIR graph data (P1), risk/PQC engines
(P1), discovery/evidence inputs (P2), real benchmark labels/baselines
(P1/P2). Exact field-level requirements are pinned in
`docs/P1_P2_INTEGRATION_CONTRACT.md` and enforced by
`tests/contract/`.
