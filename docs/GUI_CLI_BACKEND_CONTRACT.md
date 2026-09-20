# GUI–CLI Shared Backend Contract

Both interfaces invoke the same backend. There is exactly one production
pipeline; this document maps GUI and CLI arguments onto it.

## Entry point

`ecdat.core.orchestrator.get_orchestrator().scan(request) -> ScanResult`

* GUI caller: `ecdat/web/server.py:_run_job` (`caller="gui"`).
* CLI caller: `ecdat/commands/_real_scan.py:run_real_and_store` via
  `ecdat/core/client.py:RealCoreClient.scan_result` (`caller="cli-scan…"`, `ci`).

## Input mapping

Repository acquisition is shared production code (`ecdat/acquisition.py`,
used by `web/server.py:_github_public` and CLI `--repo`): validate public
URL → codeload HEAD tarball (≤250 MB) → zip-slip-safe extract → flatten
single top-level dir → `repository/` target. Session dirs stay under the
web temp root for the GUI; the CLI keeps `ecdat-repo-<label>-*/` under the
system temp dir and prints its location (caller deletes when done).

| Contract field | GUI source | CLI source |
|---|---|---|
| `target` | session input path, or `aws:<profile>:services=…` label | positional path / image / `aws:…` label, or `--repo URL` (acquired tree) |
| `scanners` | job scanner list (default local set) | `--scanners` CSV (default local set); specialized commands pin `["binary"]`, `["container"]`, `["cloud"]` |
| `permissions.*` | opt-in toggles + cloud config | `--allow-container/cloud/runtime/pull/build` |
| `profile` | job profile (`quick/standard/deep`, default `standard`) | `--profile` (same choices/default; `scan-cloud` stays `standard`) |
| `region` | job region | `--region` |
| `risk_z` | job `risk_z` (default 10.0) | `--risk-z` (default 10.0) |
| `context` | job context dict → `ScanContext` | `--environment/--owner/--exposure/--business-criticality/--data-lifetime/--migration-years` |
| `cloud_aws_access_key_id` | cloud_config `aws_access_key_id` | `--aws-access-key-id` (unification addition) |
| `cloud_aws_secret_access_key` | cloud_config `aws_secret_access_key` | `--aws-secret-access-key` |
| `cloud_aws_session_token` | cloud_config `aws_session_token` | `--aws-session-token` |
| `cloud_aws_profile` | cloud_config `profile_name`/profile | `--aws-profile` (avoids `--profile` collision on `scan-cloud`) |
| `caller` | `"gui"` | `"cli-scan"`, `"cli-scan-binary"`, … (provenance only) |
| `display_name` | input label | repo label for `--repo`, else unset |

`scan --repo URL` is the CLI equivalent of pasting a URL into the
dashboard (same validator, downloader, extractor, scanner set, profile,
and orchestrator). `scan-cloud` accepts the same credential fields as the
GUI cloud form (`--aws-access-key-id/--aws-secret-access-key/
--aws-session-token/--aws-profile`, or `AWS_ACCESS_KEY_ID` etc. from the
environment when flags are absent). Secrets are never logged, persisted,
or embedded in CIR/canonical/reports (covered by redaction tests); note
that command-line flags remain visible in process listings and shell
history, so the environment-variable form is recommended.

## Processing (identical for both)

Plan → `DiscoveryEngine` (explicit scanner allowlist; availability probed,
unavailable families warn loudly) → CIR → deterministic ID/RFC3339/stats
normalize → CIR-validate → `enrich_cir` (P1 risk + recommendations) →
`to_canonical` → canonical-validate. No mock fallback on any path.

## Output (identical for both)

* `ScanResult.as_tuple()` → `(cir_dict, canonical_doc)`; `.plan.as_dict()`,
  `.diagnostics` (elapsed, tool_versions, scanner_status, artifact counts).
* Persistence: `scans` row (canonical + CIR sidecar, same scan ID),
  `findings` rows, `scan_meta` (plan + diagnostics). GUI and CLI default to
  the same file (`~/.ecdat/ecdat.db`); any `--db`/`$ECDAT_DB` path works.
* CLI presentation only: prints `scan_id`; `--output`/`--cir-out` sidecars;
  exit codes 0 ok / 1 backend error / 2 bad target / 3 validation.

## Compatibility notes

* Additive CLI flags only; exit codes, DB schema, and request defaults
  unchanged. Secrets are never persisted (orchestrator redaction) — CLI help
  advises env-var sourcing for shell-history hygiene.
* `scan-cloud --profile` keeps its AWS-profile meaning (pre-existing).
