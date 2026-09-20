# GUI–CLI Architecture Audit (gui-cli-backend-unification, base: origin/main @ 3aa2af4)

All claims verified against the worktree at
`/tmp/opencode/unification/gui-cli-backend-unification`. No `person3-platform`
code was merged; it served only as CLI-behavior reference.

## 1. Current GUI entry point

* UI: `frontend/src/main.tsx` → `frontend/src/App.tsx` (React + Vite; dev via
  `cd frontend && npm run dev`, API proxied `/api` → `127.0.0.1:8734`).
* API: `ecdat/web/server.py` — stdlib `ThreadingHTTPServer`, loopback-only
  (`LOOPBACK_HOSTS`), session-scoped inputs under `<tempdir>/ecdat-web-*`.
* Launcher: `python -m ecdat.cli gui` → `ecdat/commands/gui_cmd.py:run()` →
  `ecdat.web.server.make_server(host, port, db_path)`.

## 2. GUI request flow

`POST /api/scan-jobs` (create job: input_id, scanners, profile, context,
risk_z, cloud_config) → background `_run_job(job_id)` (`web/server.py:309`)
→ `ScanRequest(...)` (`web/server.py:371`, `caller="gui"`) →
`get_orchestrator().scan(request, progress=...)` → `result.as_tuple()` →
`ScanRepository(db_path).save_scan(canonical, cir, plan, diagnostics)` →
job marked completed with `scan_id` (+ `persisted` flag). Progress polled via
`GET /api/scan-jobs`; results served from in-memory `STATE.results`.

## 3. GUI API endpoints (scan-related)

`POST /api/uploads`, `POST /api/inputs/inspect`, `POST /api/demos/select`,
`POST /api/scan-plan`, `POST /api/scan-jobs`, `GET /api/scan-jobs`,
`POST /api/github/public` (public URL → codeload tarball → session input),
`/api/github/{oauth/start,callback,session,repos,repos/select,logout}`,
`/api/scanner-capabilities`, `/api/health`, `/api/demos`.

## 4. Exact function that starts a scan

`ecdat.web.server._run_job(job_id)` (line 309); orchestration call at line 371:
`result = get_orchestrator().scan(request, progress=_on_progress)`.

## 5. GUI request object

`ecdat.core.orchestrator.ScanRequest`: `target` (local path or
`aws:<profile>:services=...` label), `scanners`, `permissions`
(`ScanPermissions`: container/cloud/runtime/pull/build), `profile`
(`quick|standard|deep`, default `standard`), `region`, `risk_z` (default 10.0),
`context` (`ScanContext`: environment/owner/exposure/business_criticality/
data_lifetime_years/migration_years), `cloud_aws_{access_key_id,
secret_access_key,session_token,profile}` (new in 3aa2af4),
`caller="gui"`, `display_name`, `max_archive_depth`.

## 6. Backend orchestration path

`ScanOrchestrator.scan()` (`core/orchestrator.py:813`) — the single production
pipeline: plan → `DiscoveryEngine` (P2 detectors) → CIR → P3 normalize →
P1 `enrich_cir` (risk + recommendations) → `to_canonical` → validate →
`ScanResult` (`as_tuple()` → `(cir, canonical)` + `.plan` + `.diagnostics`).

## 7. Discovery engines used

`ecdat/scanners/discovery.py:DiscoveryEngine` — families source (0.2.0),
dependency (0.2.0), binary (`binary-v0.2.0`), config, certificate, container,
cloud (credential-aware since 3aa2af4), runtime. Default local set from
`adapters/scanner_policy.py`.

## 8. Context/profile handling

GUI: `ScanContext(**job["context"])` + `risk_z=float(job.get("risk_z",10.0))`
(`web/server.py:331-350`); profile from job (default `standard`).
CLI: `context_from_args(args)` + `risk_z_from_args(args)` + `--profile`
(`orchestrator.py:261,320`; wired in `_real_scan.py:55-66`). Equivalent.

## 9. Persistence behavior

GUI: `ScanRepository(db_path).save_scan(...)` with `db_path =
$ECDAT_DB or ~/.ecdat/ecdat.db` (`web/server.py:181-187`) — same default file
as the CLI ("GUI and CLI histories unify"); v3 schema (`scans` + `cir_json`,
`scan_meta` plan/diagnostics).
CLI: `sstore.insert_scan + fstore.insert_findings_for_scan +
repository.save_meta` into `--db` (default same file). Same tables/rows.

## 10. Risk-analysis path

P1 `core/risk.py` via `api.enrich_cir` → wire risks in CIR; displayed via
`adapters/risk_view.summarize_wire_risks` on both sides. No separate scorer.

## 11. Recommendation path

P1 `core/recommend.py` via `enrich_cir` → wire recommendations; CLI
`recommend_cmd` and GUI both project them (migration envelope via
`adapters/migration_adapter.py`). No placeholder maps on this branch.

## 12. Result object

`ScanResult`: validated CIR + canonical dicts, `.plan.as_dict()`,
`.diagnostics` (elapsed, tool_versions, scanner_status, artifact counts).

## 13. Current CLI request flow

`ecdat/cli.py:build_parser()` → `commands/*_cmd.run(args)` →
`_real_scan.run_real_and_store(args, target, scanners?, caller)` →
`RealCoreClient(...).scan_result(str(target))` → `ScanRequest(...)` →
`get_orchestrator().scan()` → persist → print `scan_id`, exit codes
0/1/2(/3 legacy). All scan surfaces (`scan`, `scan-binary`,
`scan-container`, `scan-cloud`, `ci`) funnel through this one helper.

## 14. Current CLI scanning path

Identical orchestrator pipeline (see §6). `RealCoreClient` (`core/client.py`)
is a thin facade: builds `ScanRequest` from constructor args, delegates to
`get_orchestrator()`. No `MockCoreClient` exists anywhere under `ecdat/`
(verified by grep).

## 15. Differences between GUI and CLI (gaps to close)

1. **Cloud credentials (3aa2af4):** GUI collects `aws_access_key_id /
   aws_secret_access_key / aws_session_token / profile_name` and sets
   `ScanRequest.cloud_aws_*`; CLI has no such flags and `_real_scan.py`
   never forwards them → CLI cloud scans cannot use explicit credentials.
2. **Broken console script:** `pyproject.toml:50`
   `ecdat-discover = ecdat.cli:app`, but `ecdat/cli.py` defines only `main()`
   (no `app`) → installed entry point fails at import.
3. **Stale tests:** `tests/test_cli.py`, `test_scan_specialized.py`,
   `test_ci.py`, `test_risk_recommend.py`, `test_exports.py`,
   `test_reports.py`, `test_export_conformance.py`,
   `tests/contract/test_core_client.py` (+1 each in `test_core_contract.py`,
   `test_repository_analysis_boundaries.py`) assert the removed mock-era CLI
   (`scan-minimal-001`, `risk_cmd.level_for`, `--mock`); 13 more files
   (`test_benchmark*.py`, `test_real_benchmark.py`, `test_demo.py`) fail at
   collection importing deleted modules (`ecdat.benchmark`, `demo_cmd`,
   `MockCoreClient`).
4. `scan-cloud --profile` means AWS profile while every other command's
   `--profile` means scan depth (pre-existing; documented, not refactored).

## 16. Legacy/duplicated pipelines discovered

None active. No `ecdat/gui/`, no `Backup_GUI`, no mock client on this branch.
Stale items are tests + the console-script reference only (§15.3, §15.2).

## 17. Recommended integration point (adopted)

`ScanRequest` + `get_orchestrator().scan()` + `ScanRepository` — already shared.
CLI work = thin adapter parity: forward cloud creds (gap 1), keep everything
else. No new pipeline, no new adapter module (`_real_scan.py` already is it).

## 18. Files that must not be modified

`ecdat/core/orchestrator.py` (pipeline owner — CLI only passes fields),
`ecdat/scanners/*` (P2 detectors), `ecdat/core/{risk,recommend,graph,fusion,
registry,cir_models}.py` + schemas (P1), `ecdat/web/server.py` scan path
(GUI backend — read-only reference), `frontend/*`, `main` branch itself.

## 19. Risks and unresolved questions

* Credential flags put secrets on process command lines (visible in `ps`);
  mitigated by documenting env-var alternative in help text; orchestrator
  already redacts creds from reports/CIR (per 3aa2af4 message — verify in test).
* `scan-cloud --profile` collision: additive `--aws-profile` flag sidesteps it.
* Full-suite baseline: 118 failed / 219 passed (all stale-mock assertions);
  13 collection errors (deleted modules). Target: green after test rewrite.
