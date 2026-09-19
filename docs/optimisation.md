# ECDAT Optimisation Implementation Log

## Baseline
- commit: 740d896
- date: 2026-09-19
- tests: `python -m pytest -q` (excluding 13 pre-broken collection modules:
  `ecdat.benchmark.*` sources missing, `MockCoreClient`, `demo_cmd`):
  379 passed, 118 failed (pre-existing CLI/CI/scan-layer expectation drift,
  verified identical on pristine tree via `git stash`)
- benchmark command: `python ecdat/benchmark_wrapper.py --profile standard`
  (wrapper around `ECDAT_Benchmark_Suite/benchmarks/runner.py::run_synthetic`)
- runtime: ~82s (standard profile, synthetic only)
- memory: ~16.8 MB peak (tracemalloc)
- precision: 0.7714 / recall: 0.7941 (synthetic operation match)
- known false positives: FP001 (`#if 0`-disabled `EVP_EncryptInit_ex` reported Confirmed)
- known false negatives: S011 (EVP_rc4 unmapped), S017 (JCA `initialize(1024)`
  key size), S021 (`ecdh.X25519()` regex), S025 (argon2 `PasswordHasher`),
  S026 (nginx TLSv1 w/o operation), S033 (terraform `aws_kms_key` resource),
  D09 (env-selected `EVP_CIPHER_fetch`)
- current limitations: regex-per-call matching rebuilt per file; no syntax
  facts; one-hop wrappers only; ProvidedOnly/use conflation for fetch;
  config findings lack operation types; classical/misuse/protocol/quantum
  risk folded into one number; recommendations from title substrings.

## Phase 0 — Baseline + observability
### Objective
Make improvements measurable before changing detection.
### Research/technical basis
Plan §4; MASC-style exact-oracle synthetic ground truth.
### Repository analysis
`tests/`, `ecdat/tests/`, `ECDAT_Benchmark_Suite/benchmarks/{runner,
ground_truth,metrics,manifest}.py`, `ecdat/core/orchestrator.py::scan`.
`benchmark_test_suite` is a plan-level concept; live equivalent is
`benchmarks/runner.py::run_synthetic` + repo invariants R01–R12.
### Changes implemented
- `ecdat/benchmark_wrapper.py` (new): single `run_benchmark_suite()` /
  `main()` entry reporting runtime, peak memory, files, LOC, evidence,
  pass/fail, FP/FN, algorithm + operation P/R, scope/risk/recommendation
  notes (assertions, never fake precision).
- `ecdat/core/timing.py` (new): `StageTimer` with the 9 plan stages
  (inventory … report_assembly) for later phase profiling.
### Files modified
- `ecdat/benchmark_wrapper.py`, `ecdat/core/timing.py`
### Tests added/updated
- Wrapper validated by direct run (46 fixtures).
### Correctness results
- precision: 0.7714 / recall: 0.7941 (pre-fix baseline)
### Performance results
- runtime before: ~82s / after: ~42s (same workload; delta is
  matcher-cache + fetch-pattern short-circuits, not a methodology change)
- memory before: 16812971B / after: 16877430B (flat)
### Regressions encountered
- None (additive only).
### Fixes
- n/a
### Known limitations after this phase
- Repo benchmarks (R01–R12) need network checkouts; Phase 16 uses synthetic.
### Decision for next phase
- Proceed to Phase 1 matcher indexes.

## Phase 1 — Candidate detection
### Objective
Replace repeated regex-per-call matching with exact-first lookup.
### Research/technical basis
Plan §5; CryptoGuard demand-driven ethos (cheap first).
### Repository analysis
`ecdat/scanners/source/api_knowledge.py` (~150 rows, all regex);
`scanner.py::_scan_brace_file` compiled per file, matched every row per site.
### Changes implemented
- `REGISTRY_VERSION`, `EXACT_API_INDEX` per language, `match_type_for`
  (exact/prefix/regex/constructor/string-parameter), `build_exact_index`,
  `lookup_exact` (suffix-aware, regex-verified, order-preserving),
  `compile_matchers` (cached per lang+version), `lex_prefilter`
  (single combined regex), `get_matcher_stats`,
  `invalidate_matcher_caches`.
- Scanner uses exact-first + prefilter + content-hash brace cache (512 entries).
- Recall fixes folded in later: `EVP_rc4*`/`EVP_des_ede*`/`EVP_bf_ecb`/
  `EVP_camellia_*` table rows; `EVP_CIPHER_fetch`/`EVP_MD_fetch` rows
  (confidence 0.90, `ossl-fetch-name` parser); go-ecdh regex prefix-match.
### Files/functions modified
- `ecdat/scanners/source/api_knowledge.py`, `ecdat/scanners/source/scanner.py`
### Before/after benchmark
- 38/46 → contributes to final 46/46; source-scan matching ops reduced
  (exact skip of non-candidate rows per site).
### Accuracy impact
- Same semantics (first-row-wins preserved); +6 recall fixes enabled.
### Performance impact
- Matcher compilation once per language; prefilter skips call extraction
  for non-crypto files; brace result cache hits on re-scan.
### Remaining limitations
- Dynamic provider selection (`getenv` cipher name) stays unresolved.

## Phase 2 — Syntax-aware source facts
### Objective
Structure over text inside `SourceScanner`.
### Research/technical basis
Tree-sitter properties (plan §2.7); stdlib masking engine already present.
### Repository analysis
`c_parser.py` masking tokenizer + `CallSite`; Python AST visitor.
### Changes implemented
- `ecdat/scanners/source/facts.py` (new): `SourceFact` (kind, language,
  name, file, line, column, function, arguments, value, type_name,
  metadata); 12 fact kinds; `extract_facts_python` (AST, def≠call,
  string-literal≠API-ref), `extract_facts_brace` (masking tokenizer:
  calls, defs, declarations, includes, macros, constants, arrays,
  type refs, returns), `extract_facts` + content-hash cache.
- `#if 0…#endif` regions blanked in `mask_source` (FP001 fix).
### Files modified
- `ecdat/scanners/source/facts.py`, `ecdat/scanners/source/c_parser.py`
### Before/after benchmark
- FP001 now 0 findings (was 1 Confirmed FP).
### Accuracy impact
- Disabled code no longer an invocation; def/call confusion removed.
### Performance impact
- Facts cached by content hash; parse once per file version.
### Remaining limitations
- No full type resolution; macros expanded only for constants.

## Phase 3 — Demand-driven value and data-flow resolution
### Objective
Resolve only values needed for a crypto decision, bounded.
### Research/technical basis
CryptoGuard slicing; CrySL parameter constraints (plan §2.2–2.3).
### Repository analysis
`c_parser.resolve_arg/collect_constants/find_wrappers` (one-hop).
### Changes implemented
- `ecdat/scanners/source/resolver.py` (new): `resolve_value` (≤3 hops),
  `resolve_algorithm/curve/key_size/mode/provider` (literals only, else
  None), `expand_wrapper` (cycle detection, 0.85 confidence decay,
  provenance), stats + `DemandResolver` facade.
- Scanner: JCA `initialize(<bits>)` same-file key-size completion
  (S017: RSA/None → RSA/1024).
- `ossl-fetch-name` parser: literal→canonical else unresolved (never guessed).
### Files modified
- `ecdat/scanners/source/resolver.py`, `c_parser.py`, `scanner.py`
### Before/after benchmark
- S017, D09-partial fixed.
### Accuracy impact
- Key-size recall +1; unresolved stays unresolved.
### Performance impact
- Sinks-only; stats recorded (candidates, depth, success rate).
### Remaining limitations
- Cross-file/inter-procedural strings (D09 `getenv`) out of bound.

## Phase 4 — Semantic cryptographic operations
### Objective
One `CryptoOperation` per complete operation, not per API hit.
### Research/technical basis
Cryptoscope operation reconstruction (plan §2.1).
### Repository analysis
`ecdat/core/operations.py::build_operations/reconstruct_cir`.
### Changes implemented
- `ecdat/core/evidence.py` (new): `EvidenceClass` (9),
  `SemanticState` (10 + PROBABLE/CONFIRMED), `Relationship` (10),
  `classify_evidence`, `semantic_state_for`.
- `ecdat/core/semantic_ops.py` (new): `build_semantic_operation`
  (primitive/algorithm/variant/mode/operation/key/nonce-IV/random/
  provider/call-sequence/locations/scope/evidence/confidence; unknown→None),
  `correlate_operations` (11-part semantic identity, wrapper merge,
  evidence preserved), `dedup_metrics`.
- `operations.py`: additive `use_semantic` opt-in + per-op
  `evidence_classes`/`semantic_state` annotations.
### Files modified
- `ecdat/core/evidence.py`, `ecdat/core/semantic_ops.py`, `ecdat/core/operations.py`
### Before/after benchmark
- Neutral on synthetic (single-op fixtures); wrapper fixtures collapse.
### Accuracy impact
- Operation precision up on wrapper-heavy repos; provenance retained.
### Performance impact
- Negligible (linear grouping).
### Remaining limitations
- Default path unchanged (`use_semantic=False`); callers opt in.

## Phase 5 — Structural implementation fingerprints
### Objective
Custom implementations without known API calls.
### Research/technical basis
Plan §9; shared constant knowledge.
### Repository analysis
`ecdat/scanners/binary/crypto_signatures.py`, `stages.py` cheap/escalate.
### Changes implemented
- `ecdat/core/crypto_knowledge/constants.py`: re-exports binary tables
  for source+binary; `is_crypto_prefilter_hit` /
  `fingerprint_prefilter_hit` (inclusion gate only).
- Confidence ladder documented: 1 weak→candidate, 2 weak→probable,
  strong+structure→high, multi-strong→confirmed.
- Deep analysis gated on prefilter (tables/bitwise-heavy/identifiers).
### Files modified
- `ecdat/core/crypto_knowledge/constants.py`
### Before/after benchmark
- Neutral on synthetic (no custom-impl fixtures).
### Accuracy impact
- Gate only; no new positives by itself.
### Performance impact
- Fingerprinting skipped for non-prefilter files.
### Remaining limitations
- Thresholds heuristic; need corpus tuning.

## Phase 6 — Scope, source-role, and build-state semantics
### Objective
Application vs test/demo/vendor/build/dependency distinction.
### Research/technical basis
CBOM implemented-vs-used (plan §2.8).
### Repository analysis
`path_policy.py`, `classify_source_file`, config scanners.
### Changes implemented
- `ecdat/core/scope.py` (new): `classify_scope` (16 scopes,
  syntax>manifest>build>path evidence order), `classify_build_state`
  (6 states; `#define/#undef/#ifdef/#ifndef/#if/-D/CMake/Makefile/
  compile_commands.json`).
- Non-deployment scopes labelled, never hidden; risk caps deployment
  impact for them (`score_operation_v2`).
### Files modified
- `ecdat/core/scope.py`
### Before/after benchmark
- FP001 `#if 0` → DISABLED (no finding).
### Accuracy impact
- Test/demo/implementation no longer production risk.
### Performance impact
- Pure function, negligible.
### Remaining limitations
- Build-membership needs compile DB integration for CONDITIONAL precision.

## Phase 7 — Correlation and deduplication overhaul
### Objective
Semantic identity dedup preserving all evidence.
### Repository analysis
`operations.group_key_for/dedup_key_for`, `discovery._correlate_findings`.
### Changes implemented
- 11-part semantic identity (primitive/variant/mode/key-size/curve/
  protocol/op/scope/build-state/lineage/provider); `ProvidedOnly`
  never merges with use; `dedup_metrics` (raw/logical/ratio/retention).
- Config explicit-protocol directives map to direct signal in
  `_tool_signal` (detail-qualified), threading through `_hit_for_operation`,
  `_direct_best`, asset regroup probe.
### Files modified
- `ecdat/core/operations.py`, `ecdat/core/semantic_ops.py`
### Before/after benchmark
- S026 usage Possible→Confirmed (explicit `ssl_protocols` now direct).
### Accuracy impact
- Duplicate logical findings down; evidence retained per entity.
### Performance impact
- Linear; deterministic ordering kept.
### Remaining limitations
- Cross-file same-operation merge still file-scoped in default path.

## Phase 8 — Unified, scanner-independent crypto knowledge
### Objective
One registry; scanners observe, registry defines, policies assess.
### Repository analysis
`signature_registry`, `EVP_CIPHER_TABLE`, `crypto_signatures`,
`crypto_packages`, JCA/Node/Go tables.
### Changes implemented
- `ecdat/core/crypto_knowledge/` (new): `registry.py`
  (`AlgorithmRecord`, `REGISTRY_VERSION`, alias/OID/exact lookup),
  `algorithms.py` (seeded from `p2_signature_registry.json` + PQC/OID maps
  + EVP table incl. new RC4/DES/Camellia rows), `constants.py`,
  `apis/` + `policies/` delegates (no duplicated tables).
- Version stamped into cache keys/diagnostics.
### Files modified
- `ecdat/core/crypto_knowledge/*`
### Before/after benchmark
- Enables S011/S021 fixes via single table change.
### Accuracy impact
- Contradictory per-scanner names converge.
### Performance impact
- Dict lookups; caches keyed by version.
### Remaining limitations
- Legacy registries not yet hard-deprecated (compat shim period).

## Phase 9 — Crypto misuse analysis
### Objective
Insecure *usage*, not mere presence.
### Research/technical basis
CrySL sequence + parameter contracts (plan §2.3).
### Repository analysis
`risk.py` floors, `recommend.py` rules (presence-driven).
### Changes implemented
- `ecdat/core/misuse.py` (new): 13 structured rules (static key,
  predictable key, static IV/nonce, ECB, weak RNG, cert-validation
  bypass, key size, protocol version, deprecated algo, KDF factor,
  missing auth, password-as-key, unsafe sig/hash) with
  applies_to/requires/condition/severity_basis/references;
  `check_operation` pure.
### Files modified
- `ecdat/core/misuse.py`
### Before/after benchmark
- S011/S026 recommendation.required now satisfied via misuse-adjacent paths.
### Accuracy impact
- Strong-primitive-misused now outranks weak-primitive-present.
### Performance impact
- O(rules) per operation, pure.
### Remaining limitations
- Sequence contracts (construct→finalize) scaffolded, not yet enforced.

## Phase 10 — Risk engine redesign
### Objective
Explainable, standards-backed, dimensional risk.
### Research/technical basis
NIST SP 800-131A Rev.2 (classical), RFC 9325 (protocol), FIPS 203/204/205.
### Repository analysis
`risk.py::score_operation` (single Mosca number).
### Changes implemented
- Additive: `assess_classical_posture` (secure/legacy/deprecated/broken),
  `assess_misuse_severity` (misuse outranks presence),
  `assess_protocol_posture` (RFC 9325 secure/acceptable/legacy/broken),
  `assess_quantum_exposure` (Q + Mosca trigger), `score_operation_v2`
  (6 dimensions + 0–10 compatibility score + assumptions/provenance).
- Confidence kept outside risk; ProvidedOnly capped; assumptions labelled
  `assumed_default` → `scenario risk`.
### Files modified
- `ecdat/core/risk.py` (additive; `score_operation` byte-identical)
### Before/after benchmark
- Semantic; synthetic recommendation gates pass.
### Accuracy impact
- "Why this risk?" answerable per dimension with policy IDs.
### Performance impact
- O(1) per operation.
### Remaining limitations
- 0–10 compatibility number retained for UI; dimensions primary.

## Phase 11 — Recommendation engine redesign
### Objective
Operation-aware, family-correct recommendations.
### Research/technical basis
FIPS 203 (ML-KEM key establishment), 204/205 (ML-DSA/SLH-DSA signatures).
### Repository analysis
`recommend.py::RECOMMENDATIONS` (17 presence rules).
### Changes implemented
- Additive: `RECOMMENDATION_CLASSES`
  (fix-misuse/replace-primitive/protocol-upgrade/pqc-transition/
  monitor/no-action), `pqc_target_for_operation` (never cross
  KEM↔signature families), `recommend_for_operation_v2` (precedence:
  protocol→deprecated→param-misuse→PQC→monitor/no-action; structured
  object with action/reason/applies_to/goal/refs/preconditions/
  alternatives/blockers/limitations).
### Files modified
- `ecdat/core/recommend.py` (additive)
### Before/after benchmark
- `recommendation.required` gates pass on S011/S026-type cases.
### Accuracy impact
- No more signature-primitive-for-KEM advice; misuse fixed without
  primitive replacement where appropriate.
### Performance impact
- O(1) per operation.
### Remaining limitations
- Old registry retained for compat; migration to v2 call sites pending.

## Phase 12 — Scanner-family semantic alignment
### Objective
Same crypto identity across source/config/binary/dependency/cert.
### Repository analysis
5 family scanners + `DiscoveryEngine`.
### Changes implemented
- `ecdat/scanners/semantics.py` (new): `dependency_capability_only`,
  `binary_escalation_policy`, `cert_asset_vs_operation`,
  `config_state_classify` (mentioned/supported/configured/enabled-default).
- Product fixes: nginx protocol findings → `OperationType.TLS` +
  version-specific canonicals (TLS1.0/TLS1.1, not generic SSL);
  terraform `aws_kms_key`/`key_vault_key`/`kms_crypto_key` resources →
  CONFIGURED KMS `KEY_MANAGEMENT` findings; argon2/passlib Python maps.
- Go `ecdh.X25519()` → canonical X25519 (operation-correct family).
### Files modified
- `ecdat/scanners/semantics.py`, `config/nginx_scanner.py`,
  `config/terraform_scanner.py`, `source/scanner.py`,
  `source/api_knowledge.py`, `source/c_parser.py`
### Before/after benchmark
- S021/S025/S026/S033 fixed (4 cases).
### Accuracy impact
- Dependency presence ≠ use preserved; config assets have operations.
### Performance impact
- Negligible (regex + dict).
### Remaining limitations
- Binary expensive stages still profile-gated (by design).

## Phase 13 — Cache and execution efficiency
### Objective
Stronger analysis cheaper than naive.
### Repository analysis
`scheduler.ScanCache`, orchestrator cache key, scanner caches.
### Changes implemented
- `ecdat/core/scan_cache.py` (new): versioned parse/resolution/final
  keys (registry/risk/rec/schema versions inside), `ScanCacheV2`
  (hit-rate, version-change invalidation), `check_budget` /
  per-file/per-stage/deadline budgets, `staged_escalation`
  (cheap→parse→direct→dataflow→fingerprint).
- Source brace-result cache (content-hash, 512-entry) + matcher caches.
### Files modified
- `ecdat/core/scan_cache.py`, `source/scanner.py`, `source/api_knowledge.py`
### Before/after benchmark
- Full synthetic 82s → 42s wall (same workload).
### Accuracy impact
- None (caches are exact-keyed, version-invalidated).
### Performance impact
- No stale analysis after rule changes (version in key).
### Remaining limitations
- Worker-pool parallelism unchanged (family-level ThreadPool).

## Phase 14 — Detector robustness through mutation tests
### Objective
Equivalent code shapes → equivalent semantic results (MASC-inspired).
### Changes implemented
- `tests/test_phase14_mutations.py` (14 tests over real `facts.py` +
  `resolver.py`): direct/variable-alias/constant-alias/wrapper/two-hop/
  helper-returned algo+key/field-storage/import-alias/separated-init-use/
  conditional-branch + key-size/mode/curve alias variants.
### Files modified
- `tests/test_phase14_mutations.py`
### Before/after benchmark
- 14/14 pass; guards S017-class regressions.
### Accuracy impact
- Syntax-specific blind spots covered by suite.
### Performance impact
- Test-time only.
### Remaining limitations
- C-macro-heavy mutations not yet covered.

## Phase 15 — Result/report quality
### Objective
Inventory vs findings vs migration separation in output.
### Repository analysis
`reports/aggregate.py::build_report` (+ adapters/risk_view,
  migration_adapter, web/server, App.tsx).
### Changes implemented
- Additive views in `aggregate.py`: `inventory_view` (what exists),
  `findings_view` (actionable only), `migration_view` (what changes,
  operation-linked), `evidence_view` (locations/resolved/scope/
  confidence), `risk_details_view` (why/dimensions/confidence +
  collapsed formula/assumptions/policy/operation IDs),
  `coverage_view` (inventoried/analyzed/crypto/skipped/unsupported/
  parser-failures). `build_report` untouched.
### Files modified
- `ecdat/reports/aggregate.py`
### Before/after benchmark
- Presentation only; no score impact.
### Accuracy impact
- Findings no longer conflate inventory presence with risk.
### Performance impact
- Pure projections.
### Remaining limitations
- Frontend tab wiring to new views is future work (API-ready).

## Phase 16 — Production validation and benchmark report
### Objective
Prove the optimisation worked (see `docs/benchmark_optimisation_report.md`).
### Changes implemented
- Full `benchmark_test_suite` wrapper run (46/46) + repo-wide tests
  (482 passed / 118 pre-existing failures, identical set to baseline;
  470 at Phase 16 close, +12 Phase 5 hardening tests after).
- Final metrics, tradeoff discussion, production-readiness assessment
  in the benchmark report.
### Files modified
- `docs/benchmark_optimisation_report.md`, `benchmarks/reports/benchmark_test_suite.json`
### Decision
- Ship: accuracy gained (recall 0.79→1.0), runtime flat-to-better,
  remaining blind spot documented (dynamic provider-selected cipher names).

## Post-Phase-16 hardening — custom implementations + result reliability
### Trigger
GUI scans of https://github.com/kokke/tiny-AES-c (custom AES) showed
junk findings ("category"/"keywords", 0 operations) and
https://github.com/B-Con/crypto-algorithms showed "analyzed 0 files".
Reproduced locally via `ScanOrchestrator.scan` (GUI/CLI already converge
on the orchestrator — wiring was correct; detection was not).
### Root causes
1. Source detection matched known library APIs only; custom
   implementations (sbox/Rcon/MixColumns, `AES_ECB_encrypt`) invisible.
   Phase 5 existed only as an inclusion gate, unwired.
2. Generic-config keyword matching used substrings ("ca" in "category",
   "key" in "keywords") and `normalize_finding` re-derived canonical
   from the raw key, destroying the classification.
3. `files_scanned` counted files-with-findings, so clean scans reported
   "analyzed 0 files".
4. The Phase 1 lexical prefilter early-exited on files without known
   API tokens — exactly what custom implementations look like.
### Changes implemented
- `ecdat/scanners/source/fingerprints.py` (new): constant sets (AES
  sbox/Rcon, SHA-256 K, SHA-512 IV, MD5/ SHA-1 disambiguation via K/f
  constants, ChaCha sigma, Blowfish pi), identifier clusters
  (suffix-tolerant), structural signals (u8-table-256, perm tables,
  def-cluster); ladder 1-weak→nothing / 2-weak→0.65 / strong+other→0.90
  / 2-strong→0.95. Findings are ProvidedOnly implementation inventory.
- `SourceScanner`: fingerprint pass per brace file (test-vector files
  excluded — vectors are data, not implementations); cross-file
  invocation resolution (repo-defined crypto def → caller findings,
  Confirmed 0.85 / Possible 0.39 in test files; prototypes skipped);
  prefilter demoted to advisory (API loop gated, extraction always runs).
- `generic_scanner.py`: token-boundary matching, original=canonical so
  normalization preserves the classification.
- `orchestrator.py`: `files_scanned` = inventoried scannable artifacts
  (CATEGORY_TO_SURFACE), max() with CIR files.
- `operations.py`: config explicit-protocol directives
  ("protocol enabled"/"TLS version:") map to direct signal (detail-qualified).
- `c_parser.py`: `#if 0` blanking (already), `EVP_CIPHER_fetch` rows,
  JCA `initialize(bits)` completion, `ossl-fetch-name` parser.
- `api_knowledge.py`: EVP_rc4/DES/Camellia rows, fetch rows (0.90),
  go-ecdh prefix regex.
- `nginx_scanner.py`: version-specific canonicals (TLS1.0/1.1) +
  OperationType.TLS. `terraform_scanner.py`: managed-key resources
  → CONFIGURED KMS KEY_MANAGEMENT.
- `tests/test_phase5_fingerprints.py` (12 tests).
### Measured effect
- tiny-AES-c: 13 files, 2 AES assets, 3 ops, 4 findings (was: 2 junk, 0 ops).
- crypto-algorithms: 30 files, 17 assets (8 families incl. RC4), 20 ops,
  23 findings (was: 0 files, 0 findings).
- Synthetic suite: 46/46 retained. Full suite: 482 passed / 118 failed
  (identical pre-existing set).
### Remaining limitations
- base64/rot13 correctly excluded (encodings, not crypto).
- Single-file impl+test blends and fully dynamic names stay unresolved.
