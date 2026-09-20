# GUI–CLI Integration Complete

## 1. Final architecture diagram

```text
GUI request (web/server.py, caller="gui") ─┐
                                           ├──> ScanOrchestrator.scan(ScanRequest)
CLI request (_real_scan.py, caller="cli-*") ┘         ↓
                                              DiscoveryEngine → normalize →
                                              enrich_cir (P1 risk+recs) →
                                              to_canonical → validate
                                                        ↓
                                              ScanResult → ScanRepository
                                              (scans + findings + scan_meta)
```

## 2. Final call flow

`ecdat.cli` parser → `commands/*_cmd.run` → `run_real_and_store` →
`RealCoreClient.scan_result` → `ScanRequest` → `get_orchestrator().scan()` →
persist → print `scan_id`. GUI: `POST /api/scan-jobs` → `_run_job` → same
`ScanRequest` (with cloud creds + display label) → same orchestrator → same
`ScanRepository` (same default DB file). Read paths (`list/show/risk/
recommend/export/report`) serve stored rows on both sides.

## 3. Files changed

* `ecdat/cli.py` — `scan-cloud` gains `--aws-access-key-id`,
  `--aws-secret-access-key`, `--aws-session-token`, `--aws-profile`.
* `ecdat/commands/_real_scan.py` — forwards creds (flag > env fallback);
  `scan-cloud` keeps scan-depth `standard` despite AWS `--profile`.
* `ecdat/core/client.py` — `RealCoreClient` accepts/forwards `cloud_aws_*`.
* `pyproject.toml` — fixed `ecdat-discover` entry point.
* 8 test files rewritten to the unified contract; 2 assertions corrected to
  intended behavior; 18 golden files regenerated (verified).

## 4. Files created

* `ecdat/acquisition.py` — shared GitHub acquisition (stdlib-only).
* `docs/GUI_CLI_ARCHITECTURE_AUDIT.md`, `docs/GUI_CLI_BACKEND_CONTRACT.md`,
  `docs/LEGACY_CODE_INVENTORY.md`, this file.
* `tests/test_gui_cli_parity.py` (15 tests) and
  `tests/test_repo_acquisition.py` (20 tests: URL validation, stubbed
  download/extract/flatten incl. exact file-set, CLI `--repo` end-to-end,
  public + cloud request-equivalence, AWS redaction).

## 5. Files removed / archived

13 stale test files removed (import deleted modules; see legacy inventory).
Nothing archived; no `archive/` needed (no dead GUI copies on this branch).

## 6. Tests executed

* `pytest tests/` → **336 passed** (baseline: 118 failed + 13 collection errors).
* `pytest ecdat/tests/` → 264 passed, 1 skipped, 2 pre-existing env failures
  (PE-vs-ELF, `server.pem` KeyError — fail on pristine HEAD too).

## 7. Test results

All green except the 2 pre-existing environment failures, which are out of
scope and documented.

## 8. Parity-test methodology

Spy on `ScanOrchestrator.scan` to prove both surfaces invoke it; capture and
compare normalized `ScanRequest` fields; run both callers on one fixture and
compare findings/assets/operations/risks/recommendations byte-for-byte
(deterministic IDs match); profiles quick/standard/deep via plan records.

### Verification tiers (GitHub URL workflow)

* Code-level: GUI `_github_public` and CLI `--repo` both call
  `ecdat.acquisition` (single implementation; import-verified).
* Offline deterministic tests (`tests/test_repo_acquisition.py`, 20 tests):
  URL accept/reject matrix, stubbed-tarball download → byte-exact extracted
  file set, flatten behavior, failure cleanup, oversize rejection, CLI
  `--repo` end-to-end on stubbed tarball, request-field equivalence
  (public + cloud shapes), AWS redaction.
* Manual verification still necessary (requires network, unsuitable for the
  automated suite — not yet performed in this task):
  `python -m ecdat.cli scan --repo https://github.com/openssl/openssl --db
  /tmp/manual.db` then compare scan ID/findings against a GUI scan of the
  same URL. The OpenSSL comparison stage is the planned venue.

### Live verification (performed 2026-09-20, real network)

`scan --repo https://github.com/mpdavis/python-jose` (CLI, exit 0) →
`scan:651ca10921080e2f`, 86 findings; same tree through the GUI backend path
(`ScanRequest`, `caller="gui"`) → **identical scan ID, byte-identical
findings list and stats** (H84/I2; RSA-1024×59, ECDSA×18). Risk high 6.31
(P1 engine), SARIF export verified. An earlier attempt with a nonexistent
repo (`mozilla/python-jose`) failed cleanly (exit 1, actionable stderr, no
traceback) — acquisition errors stay loud.

## 9. Ignored fields and reasons

`caller` (provenance only, never analysis), `display_name` (GUI label; CLI
prints raw target), timestamps (none compared — IDs compared instead),
HTTP/CLI presentation wrappers.

## 10. Remaining known issues

* Secrets on CLI command lines are visible in `ps` (help advises env vars;
  orchestrator redacts creds from reports/CIR).
* `scan-cloud --profile` (AWS) vs global `--profile` (depth) collision —
  sidestepped with `--aws-profile`, documented.
* 2 pre-existing `ecdat/tests` env failures (see §6).

## 11. Follow-up fix: path-independent finding identity (OpenSSL parity)

OpenSSL GUI-vs-CLI comparison exposed path-dependent representative
selection: tied same-file hits were tie-broken by absolute-path-derived
operation IDs (`reconstruct_cir` survivor sort). Fixed in
`ecdat/core/operations.py` without changing ID formats, stored locations,
grouping semantics, or risk math: group keys, survivor tie-breaks
(relative path → line → function → canonical), regenerated op/asset IDs,
and graph file-node IDs now derive from repository-relative paths
(`_stable_file`/`_stable_sort_key`/`_scan_root`); non-relativizable inputs
(cloud labels, image refs) keep prior behavior. Verified: two-root
regression tests (`tests/test_path_independence.py`), CLI-A ≡ CLI-B ≡ GUI
on OpenSSL (0 finding differences after root normalization; CBOM/SARIF/
risks/recs equal; severity and 6.26 risk identical).

## 11. OpenSSL comparison

**Not performed.** No benchmarks run, no external ground-truth validation.
