# Legacy Code Inventory (gui-cli-backend-unification)

## Removed (stale tests importing deleted modules — suite could not collect)

All imported modules that no longer exist on `main` (`ecdat.benchmark`,
`demo_cmd`, `MockCoreClient`). Verified each file fails at import before
removal; no production code depended on them.

| Deleted file | Tests | Original behavior tested | Why obsolete | Replacement coverage | Coverage lost |
|---|---|---|---|---|---|
| `tests/test_benchmark.py` | 18 | Person 3 benchmarking foundation (mock-only) | `ecdat.benchmark` module absent (only `ecdat/benchmarks/` Pass-3 harness exists) | none | benchmark-foundation assertions; module itself is gone so nothing executable is untested |
| `tests/test_benchmark_accuracy.py` | 17 | ground-truth + confusion-matrix metrics | same | none | same as above |
| `tests/test_benchmark_baselines.py` | 20 | baseline-adapter framework | same | none | same as above |
| `tests/test_benchmark_charts.py` | 14 | benchmark charts/visualization | same | none | same as above |
| `tests/test_benchmark_execution.py` | 13 | reproducible benchmark execution engine | same | none | same as above |
| `tests/test_benchmark_pdf.py` | 10 | benchmark PDF renderer | same | none | same as above |
| `tests/test_benchmark_predictions.py` | 18 | prediction adapter layer | same | none | same as above |
| `tests/test_benchmark_render.py` | 14 | benchmark HTML + CSV renderers | same | none | same as above |
| `tests/test_benchmark_report.py` | 9 | benchmark report model + analysis | same | none | same as above |
| `tests/test_benchmark_suite.py` | 17 | benchmark suite + case registry | same | none | same as above |
| `tests/test_real_benchmark.py` | 8 | characterization benchmarks | same | none | same as above |
| `tests/test_demo.py` | 6 | `ecdat demo` command (stdlib + loopback) | `demo_cmd` removed with old mock GUI; command no longer exists | CLI surface partly covered by parity smoke tests (`--help`, real `scan`) | `demo`-specific flows (uncoverable — no such command) |

Net: 164 removed tests, all uncollectable; zero executable behavior left
untested by their removal (every removed test errored at import).
Per-file import statements verified via `git show HEAD:<file>` during
final review (charts/suite/real_benchmark import `ecdat.benchmark.*`;
`test_demo.py` imports `demo_cmd`; neither target exists on `main`).

## Rewritten (mock-era contracts → unified-backend contracts)

* `tests/test_cli.py`, `test_scan_specialized.py`, `test_ci.py`,
  `test_risk_recommend.py`, `test_exports.py`, `test_reports.py`,
  `test_export_conformance.py`, `tests/contract/test_core_client.py` —
  asserted `scan-minimal-001`-style fixtures, `--mock` defaults,
  `risk_cmd.level_for`, placeholder recommendation maps. Now drive the
  shared orchestrator with tmp DBs.
* `tests/contract/test_core_contract.py`, `tests/test_repository_analysis_boundaries.py`
  — two assertions updated to intended behavior (unattributed risk for
  CIR-less docs; GUI binary-including profile policy).

## Regenerated goldens (renderer drift, verified valid before rewrite)

* `tests/fixtures/exports/{empty,minimal}.cbom.{json,xml}` (only CBOM
  changed; json/csv/sarif byte-identical).
* `tests/fixtures/reports/{empty,minimal}.{md,console.txt,html,pdf}`.

## Fixed references

* `pyproject.toml`: `ecdat-discover = ecdat.cli:app` (nonexistent `app`)
  → `[project.scripts] ecdat-discover = "ecdat.cli:main"` (also fixed the
  non-standard `[project.entry-points]` table).

## Known pre-existing failures (not touched; fail on pristine HEAD too)

* `ecdat/tests/test_binary_stages.py::test_compiled_dynamic_binary`
  (expects PE, environment builds ELF).
* `ecdat/tests/test_inventory.py::test_mixed_repo_inventory`
  (`KeyError: 'server.pem'`).

## Active implementations (do not archive)

GUI: `ecdat/web/server.py` + `frontend/` (React). Backend:
`ecdat/core/orchestrator.py`, `ecdat/store/repository.py`,
`ecdat/core/client.py`, `ecdat/commands/_real_scan.py`. No `ecdat/gui/`,
no `Backup_GUI`, no mock client exist on this branch.
