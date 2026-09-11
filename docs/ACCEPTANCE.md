# ECDAT Person 3 — Final Acceptance Checklist (SIH26164)

Branch: `person3-platform`. Validation: `python -m pytest -q` → **462 passing**.
All mock behavior is labeled in code, CLI, GUI, and tests. Nothing here
claims real detection, accuracy, PQC intelligence, or superiority.

Status key: **PASS** = P3-complete · **PARTIAL** = usable, known gap ·
**BLOCKED** = needs P1/P2. Mock-labeled items are PASS as platform.

## 1. P3-complete functionality (PASS)

| Requirement | Evidence / test |
|---|---|
| CLI scan/list/show + binary/container/cloud variants | `ecdat/cli.py`, `test_cli.py`, `test_scan_specialized.py` |
| risk / recommend (mock-labeled) | `risk_cmd.py`, `recommend_cmd.py`, `test_risk_recommend.py` |
| report md/console/html/pdf + export json/csv/cbom/sarif | `report_cmd.py`, `export_cmd.py`, `test_reports.py`, `test_exports.py` |
| Cross-format count consistency + determinism | `test_export_conformance.py` |
| CI gate (`--fail-on/--json/--summary/--sarif`) | `ci_cmd.py`, `test_ci.py` (26) |
| GUI cards 1–10 incl. Reports downloads | `server.py`, `service.py`, `test_gui*.py` |
| SQLite store, canonical validation | `store/`, `core/`, `test_store.py`, `test_validate.py` |
| Benchmark pipeline + HTML/CSV/SVG/PDF artifacts | `benchmark/`, `test_benchmark*.py` |
| Consumer contracts (client/graph/risk/migration) | `tests/contract/` |
| Demo + README | `demo_cmd.py`, `README.md`, `test_demo.py` |
| SIH readiness: loopback-only, no net deps, no secrets, no hard-coded paths | audit 2026-09-11; `LOOPBACK_HOSTS` enforced |

## 2. Mock/demo functionality (PASS as platform, mock-labeled)

| Item | Label location |
|---|---|
| Fixture scanners (no real analysis) | command docstrings, `--mock` default |
| Severity-weight risk, static-map recommendations | `MOCK SCORING MODEL`, CLI/GUI text |
| Hand-authored knowledge graph | `MOCK DATASET` badge (Card 8) |
| Migration triage, no state | `MOCK / PLACEHOLDER` badge (Card 9) |
| Synthetic benchmark labels/metrics | `synthetic=true`, unavailable-None semantics |

## 3. P1/P2-blocked functionality (BLOCKED)

| Need | Owner | Seam ready |
|---|---|---|
| Real detection / Core API (`RealCoreClient` raises) | P1 | `CoreClient` protocol |
| CIR graph data | P1 | `GraphProvider` protocol |
| Real risk / PQC engines | P1 | `risk_from_findings`, recommend map, `MigrationProvider` |
| Discovery/evidence inputs | P2 | `MockCoreClient` routing, scan commands |
| Real benchmark labels, baselines, param/wrapper scoring | P1/P2 | `PredictionProvider`, ground-truth model |

## 4. Intentionally deferred

Duplicate-suppression cases (needs real streams), cache speedup (no cache),
baseline adapters (no chosen tool), PNG chart rendering (no imaging dep),
`[project.scripts]` entrypoint (invocation is `python -m ecdat.cli`).
