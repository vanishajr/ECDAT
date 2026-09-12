# P1/P2 → P3 Integration Contract (SIH26164)

Source of truth: the code and `tests/contract/`. This document
summarizes; it does not extend. Anything not listed here is not
accepted — `additionalProperties: false` and closed vocabularies are
enforced, and malformed payloads are rejected, never repaired.

## A. CoreClient (Person 1)

* Implement `scan(target: Path) -> dict` behind the `CoreClient`
  protocol (`ecdat/core/client.py`); `get_client("real")` must return
  it. `RealCoreClient.scan()` currently raises `NotImplementedError`.
* The returned dict MUST validate against
  `ecdat/core/canonical_v1.json` (`schema_version: "1.0"`).
* Scan fields: `scan_id` (non-empty string, deterministic per target
  run), `target`, `started_at`/`finished_at` (date-time),
  `tool_versions` (string map), `stats` (`files_scanned`,
  `findings_count`), `findings` (array).
* Finding fields: required `rule_id`, `title`, `severity`, `file`,
  `line` (int ≥ 0); optional `snippet` (string), `confidence`
  (0–1), `metadata` (object, free-form, P1-reserved). Severity MUST be
  one of `info|low|medium|high|critical`. No other keys anywhere.
* Error behavior: raise before returning anything invalid. P3
  validates on receipt; invalid docs are never stored, never rendered,
  and surface as existing 400/404/validation errors.

## B. GraphProvider (Person 1 CIR)

* Implement `get_graph() -> dict` behind the `GraphProvider` protocol
  (`ecdat/gui/graph.py`); return `to_frontend_graph()`-shaped output
  (P3 passes conforming envelopes through unchanged and adds no mock
  flags to provider data).
* Nodes: `id`, `type` (one of Endpoint, Service, Container, Library,
  CryptoOperation, CryptoAsset, CertificateKey, CloudResource),
  `label`, `risk`, `confidence`, `metadata` (object); optional
  `rule_id` — the ONLY sanctioned finding linkage, rule-level, never
  per-finding.
* Edges: `id`, `source`, `target` (both must exist), `type` (one of
  uses, provides, implements, configures, protects, exposes, runs_in,
  depends_on), `detail`.
* `trace_paths`: `id`, `label`, `node_ids` (all must exist), `note`.
* Unknown types, dangling endpoints, or broken traces raise
  `ValueError` and are never rendered. Layout is deterministic
  (type column, then id); coordinates are assigned by P3.

## C. MigrationProvider (Person 1 migration intelligence)

* Implement `get_plan(scan_id, target, findings) -> dict` behind the
  `MigrationProvider` protocol (`ecdat/gui/migration.py`).
* P3 renders exactly these item fields: `rule_id`, `severity`,
  `title`, `action`, `refs`, `count`, `affected_files`,
  `graph_node_ids`, `status`. Envelope: `plan_version`, `scan_id`,
  `target`, `item_count`, `items`, plus label/note/source strings.
* The canonical P3 finding carries NO owner/effort/priority/timeline/
  phase/confidence/sequencing/PQC-target fields, and P3's own output
  forbids `timeline, effort, priority, confidence, phase, pqc_target,
  migration_sequence, migration_state, sequencing, owner`
  (enforced by `tests/contract/test_migration_contract.py`).
* Current boundary: items are severity triage with status `not
  started (mock — v1 tracks no migration state)` — NOT a sequence.
  Extending the envelope needs all-3 agreement first.

## D. PredictionProvider (Person 1/2 detectors and baselines)

* Implement `predict(case: SuiteCase) -> Prediction(keys, ok, error,
  detail)` (`ecdat/benchmark/predictions.py`).
* Keys reuse finding-key identity semantics (`RULE@file:line`); no
  second key system. Return explicitly produced sets only — never
  copy ground truth.
* `ok=False` or raised exceptions become `failed` entries: no counts,
  excluded from totals. Baseline adapters may raise
  `NotApplicableError` for unsupported case types → `not_applicable`
  entries, likewise unscored. Metrics come solely from
  `ground_truth.evaluate_cases`; providers never compute
  precision/recall/F1.

## E. Integration expectations

* Deterministic IDs: stable `scan_id` per target run; finding identity
  is positional (canonical list order) plus `RULE@file:line` keys in
  benchmarks.
* Severities: exactly `info|low|medium|high|critical` everywhere
  (risk, inventory filters, graph rings, migration triage).
* Rule IDs: shared vocabulary strings (`RSA-1024`, `MD5-USAGE`, …);
  unknown IDs take documented fallbacks, never errors.
* Cross-view references: `rule_id` (inventory ↔ risk ↔ graph nodes ↔
  migration) and `graph_node_ids` (migration → graph). Graph topology
  is provider data, not scan data — rule overlap is advisory.
* Empty/partial: zero-findings docs are valid (risk 0/none, empty
  triage, reports still render); missing optional finding fields
  render as explicit `not provided` labels, never `undefined`/`null`/`NaN`.

## F. What P1/P2 MUST NOT assume

* P3 does not perform real detection.
* P3 does not infer cryptographic truth from regex alone.
* P3 does not fabricate risk/PQC results.
* P3 does not require an LLM.
* P3 does not expose a non-loopback GUI.
* P3 does not silently accept malformed canonical payloads.
* P3 does not execute, download, or probe external tools.
* Absent tools/data are reported UNAVAILABLE, never scored as zero.
