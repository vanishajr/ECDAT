# ECDAT — Complete Implementation & Architecture Report

> Generated 2026-09-23 from a repo-wide scan of `D:\Coding\Websites\ECDAT`.
> Backend: Python ≥3.10 (`ecdat/`, 176 files, ~40k LOC). Frontend: React + Vite
> (`frontend/src`, 23 TS/TSX files). Tests: 25 files under `tests/`.
> Single production pipeline — no mock mode. Every interface (CLI, GUI, CI)
> funnels through `ScanOrchestrator.scan()`.

---

## 1. What ECDAT is

**ECDAT = Cryptographic Discovery, Inventory, Analysis, Migration-Readiness
Platform.** It discovers crypto assets across 8 surfaces (source, dependency,
binary, container, config, certificate, runtime, cloud/AWS), normalizes them
into **CIR** (Cryptographic Inventory Representation, `ecdat/core/cir.schema.json`),
validates, scores quantum/classical risk (Mosca-style), recommends PQC
migrations, builds an asset/operation graph, persists to SQLite, and serves
reports/exports through CLI + local web GUI.

Key invariants (see root `README.md`):

- One pipeline: `GUI → ecdat/web/server.py → ScanRequest → ScanOrchestrator.scan()`,
  `CLI → ecdat/commands/_real_scan.py → RealCoreClient → ScanRequest → ScanOrchestrator.scan()`.
- Single-pass real analysis: `DiscoveryEngine` scans once → CIR v0.1 validation →
  fusion/operations/graph/risk/recommendations → canonical v1 + CIR sidecar →
  SQLite (`scans` + `scan_meta`) → CLI/GUI/reports/exports/CI.
- Failures are loud errors, never silent mock fallbacks.
- Deterministic `scan:<32hex>`-style IDs for identical inputs; RFC3339 timestamps;
  asset-only findings preserved; unavailable tools reported, never zero-filled.

---

## 2. Repository map

```
ecdat/
  cli.py                    argparse dispatch (build_parser:58, main:178)
  acquisition.py            GitHub URL → local scan input (shared GUI+CLI)
  core/                     models, CIR, orchestrator, validation, risk, fusion,
                            graph, recommend, inventory, scheduler, ops, misuse,
                            evidence, scope, cache, timing, api, client, registry
  scanners/                 base.py, discovery.py, path_policy.py, semantics.py
    source/                 Python AST, C parser, facts+resolver, api_knowledge
                            (~400 API patterns), fingerprints, semgrep (optional)
    dependency/             manifest parsers (requirements, package.json, cargo,
                            go.mod, pom.xml, SBOM, syft/cdxgen, …)
    binary/                 stages (magic, entropy, constants, OIDs, symbols),
                            strings, lief, yara, crypto_signatures
    container/              docker-save/OCI/rootfs, syft, daemon, trivy, dockerfile
    config/                 nginx, apache, openssl, envoy, k8s, terraform,
                            dockerfile, generic (+service_context)
    certificate/            pem, der, jwk, pkcs12, jks (keytool), ssh
    runtime/                tls (live handshake), ssh (ssh-keyscan)
    cloud/                  aws (kms, acm, elb/alb via boto3); azure/gcp = stubs []
  store/                    db.py (SQLite WAL, SCHEMA v3), scans.py, findings.py,
                            repository.py (+scan_meta plan/diagnostics)
  reports/                  aggregate.py (build_report:747), console, markdown,
                            html, pdf (stdlib canvas)
  exports/                  cbom.py (CycloneDX 1.6), sarif.py (2.1.0), csv_gen.py
  adapters/                 pipeline.py (run_real_scan:54), normalize.py,
                            scanner_policy.py, graph_adapter.py, risk_view.py,
                            migration_adapter.py
  commands/                 scan, scan_binary, scan_container, scan_cloud, ci,
                            list, show, risk, recommend, export, report, gui,
                            _real_scan.py (single persist path:30)
  web/server.py             loopback ThreadingHTTPServer (do_GET:472, do_POST:589)
  benchmark/, benchmarks/, benchmark_wrapper.py   eval harness
frontend/src/
  App.tsx (~2500 lines, tab SPA, no router), main.tsx, styles.css
  graph/CryptoGraph.tsx (821 lines) + graphTypes/Model/Views/SecurityMap/
    Layout/Labels/Focus/Edges/Components + __tests__ (8 files)
tests/ + tests/contract/ + tests/fixtures/  (canonical, exports, reports, p1p2)
benchmarks/ (46-fixture wrapper) + ECDAT_Benchmark_Suite/ (full harness:
  runner, repo_runner, metrics, ground_truth, ecdat_adapter, manifest.yaml,
  synthetic S001-S035/D01-D10/FP001 + repo invariants R01-R12)
docs/ (roadmaps, audits, optimisation log, this report)
```

---

## 3. The single production pipeline (12 stages)

Owner: `ecdat/core/orchestrator.py:837 ScanOrchestrator.scan()`.

```
normalize → plan → inventory → triage → cache-check → availability →
discovery → normalize_cir → validate_cir → enrich → validate_canonical → persist
```

| # | Stage | Code | What happens |
|---|-------|------|--------------|
| 1 | normalize | `orchestrator.py:859`, `scanner_policy.resolve_scanners`, helpers `_is_cloud_label:76`, `_is_image_reference:82`, `_is_runtime_endpoint:105`, `_target_requires_existing_path:133` | Resolve scanner list; refuse image-ref pull without `allow_pull`; refuse missing local path |
| 2 | plan | `orchestrator.py:908`, `scheduler.py:211 InputRegistry.normalize`, `scheduler.py:240 AdaptiveScheduler.route/triage` | `ScanJob{job_id,kind,label,content_hash}`; kind ∈ repo/file/binary/container_tar/rootfs/endpoint/cloud; route → `{stages, escalate}`; profile `quick\|standard\|deep` → `PROFILE_EFFORT` (`orchestrator.py:192`) controls escalation/expensive backends |
| 3 | inventory | `orchestrator.py:918`, `inventory.py:466 inventory_target()` | Magic-bytes first, extension second (`classify_bytes:117`); safe zip/tar expand (`safe_extract_archive:332`, zip-slip guard, `MAX_ARCHIVE_DEPTH=5`, `MAX_EXPANDED_BYTES=512MB`); emits `ArtifactRecord:214`; `CATEGORY_TO_SURFACE:58` |
| 4 | triage | `orchestrator.py:925`, `_surfaces_for:532`, `_permissions_required_for:548` | Artifacts → surfaces; compute opt-in permissions needed |
| 5 | cache-check | `orchestrator.py:933`, `_cache_key_for:565`, `scan_cache.py:108 final_scan_cache_key`, `scheduler.py:90 content_hash_for (blake2s-16)` | Key = input + scanner versions + registry + risk/rec + config + schema; hit returns stored `ScanResult` with `cache_hit=True` (~5–15 ms, see benchmarks doc) |
| 6 | availability | `orchestrator.py:965`, `DiscoveryEngine.availability()` | Report unavailable optional backends (semgrep, syft, trivy, docker, keytool, ssh) — never zero-fill |
| 7 | discovery | `orchestrator.py:1012`, `scanners/discovery.py:332 scan_and_emit_cir`, `:142 scan` | Run selected scanners (artifacts routed to source scanner; `escalation_allowed`/`expensive_backends` forwarded; cloud label → services/region; container pull/build flags); correlate + merge findings (`_correlate_findings:211`, `_merge_findings:288`) |
| 8 | normalize_cir | `orchestrator.py:1064`, `adapters/normalize.normalize_cir` | Normalize CIR, attach scan context, derive files list, synthesize asset-only findings |
| 9 | validate_cir | `orchestrator.py:1079`, `cir_validate.py:26 validate_cir` | `Draft202012Validator(cir.schema.json)` |
| 10 | enrich | `orchestrator.py:1091`, `_apply_scan_context:601`, `api.enrich_cir` (`api.py:539` → `risk()` + `recommend()` + graph) | `risk.score_cir (risk.py:663)`, `recommend.recommend_cir (recommend.py:434)`, `graph.build_graph (graph.py:179)` |
| 11 | validate_canonical | `orchestrator.py:1133`, `validate.py:40 validate` | `jsonschema.validate(canonical_v1.json)`, `SCHEMA_VERSION=1.0` |
| 12 | persist | `commands/_real_scan.py:30 run_real_and_store` → `store/persist.store_scan_result` (idempotent: unseen ID inserts, known ID reuses the stored row unless `--replace`, genuine write errors stay loud) + `--output/--cir-out` | Stores canonical + CIR sidecar + plan/diagnostics; honors `--output/--cir-out`; `--repo URL` acquired first via `acquisition.acquire_github_repository` |

Supporting entry points: `adapters/pipeline.py:54 run_real_scan`,
`core/client.py:25 RealCoreClient.scan:80 / scan_result / scan_with_cir`,
`orchestrator.py:1280 plan_scan`, `:1285 run_scan`, `:1272 get_orchestrator`,
`ScanResult.as_tuple:479`. Permissions: `ScanPermissions:203`
(allow_container/cloud/runtime/pull/build); context: `ScanContext:230`
(environment, owner, exposure, business_criticality, X=data-lifetime,
Y=migration-years, Z=risk_z default 10) + `cache_seed:257`.

---

## 4. Data models

### 4.1 CIR (`core/cir_models.py`, schema `core/cir.schema.json`)

Enums: `UsageState:16` (Confirmed/Probable/Possible/ProvidedOnly/FalsePositiveSuppressed),
`OperationType:24` (Encrypt/Decrypt/Sign/Verify/KeyExchange/Hash/KDF/TLS/Storage/KeyManagement),
`Exposure:37`, `GraphNodeKind:45`, `GraphRelationship:55`.

Models: `EvidenceSignal:65` (+regex redaction `redact_snippet:73` — base64/PEM/
password/api-key/ssh), `Location:92`, `Implementation:100`, `Context:107`,
`RiskInputs:114`, `CryptoAsset:121` (`ast:[0-9a-f]{16}`),
`CryptoOperation:139` (`op:[0-9a-f]{16}`), `GraphNode:152`, `GraphEdge:159`,
`Graph:166`, `Stats:171`, `CIRDocument:178` (`update_stats:194`).

**Deterministic IDs** (same shape in 6 places — `cir_models.py:202/223`,
`api.py:57/64`, `scanners/discovery.py:49`, `operations.py:596`,
`scheduler.py:85`, `scan_cache.py:62`, `inventory.py:108`):

```python
# cir_models.py:202
seed = "canonical|key_size|mode|curve|protocol|file|line"
asset_id = "ast:" + sha256(seed)[:16]
# cir_models.py:223
seed = "opType|asset_id|function|file|line"
op_id = "op:" + sha256(seed)[:16]
```

### 4.2 Canonical v1 (`core/models.py:14 Finding`, `:53 Scan`; schema `core/canonical_v1.json`)

Frozen dataclass view with `from_dict/to_dict`. Findings carry
`rule_id, severity, file, line, title, confidence, snippet, metadata{cir_op_id,
cir_asset_id, canonical_name, usage_state, risk_class, risk_score, asset_only,
library}`.

### 4.3 Plan & diagnostics

Persisted in `scan_meta(scan_id, plan_json, diagnostics_json)` (schema mig v3).
Plan: `{job_id, kind, label, content_hash, profile, permissions, scanners,
stages, escalate, artifacts_total, artifact_counts, surfaces, effort}`.
Diagnostics: `{elapsed_sec, cache_hit, cache_key, scanner_status, tool_versions,
registry_version, binary_stages/tools, escalation, surfaces, unavailable, …}`.

---

## 5. Core algorithms (exact formulas)

### 5.1 Fusion — `core/fusion.py:104 weighted_fusion`

```text
raw = 0.5 + 0.25*direct_usage + 0.10*param + 0.08*binary + 0.07*agreement
      - 0.35*dependency_penalty
confidence = clamp(raw * reliability_mean, 0, 1)   # :138, :156
```

- Inputs: `evidence[{detector, signal_type, confidence}]`, flags
  `param_resolved, binary_support, config_runtime_agreement, dependency_only`.
- `reliability_mean` from `DETECTOR_RELIABILITY:27`: source 0.92, runtime 0.92,
  sslyze 0.92, semgrep 0.9, tree-sitter 0.88, config/certificate/secret/gitleaks
  0.85, lief 0.85, binary/capa 0.8, cloud/yara-x 0.75, default 0.7,
  strings/syft/container 0.6, dependency/dockerfile/bom 0.5.
- Direct iff `signal_type ∈ DIRECT_SIGNAL_TYPES:54` + substring direct/call/dataflow (`_is_direct:94`).
- `decide_usage:176`: test/checksum → FalsePositiveSuppressed; dependency_only →
  ProvidedOnly; ≥0.85 (+direct) → Confirmed; ≥0.65 → Probable; else Possible.
- `deduplicate:219`: exact `dedup_key`, keep max-confidence (tie smallest id).
- `redact_snippet:289`: `key=/secret=/PEM PRIVATE → [REDACTED]` (`_KEY_RE:276` etc.).

### 5.2 Operations collapse — `core/operations.py:316 build_operations`

Raw hits `[{canonical, evidence, location, implementation, context}]` → sorted
`CryptoOperation` dicts + dedup_key/id/confidence/usage_state/semantic_state.
Key fns: `group_key_for:246`, `dedup_key_for:273`
(`canonical|op|file|line|ProvidedOnly-suffix`), `_tool_signal:602`
(source:api-call→(source,call), binary-lief→(lief,binary-import), … via
`_TOOL_SIGNALS:31`), `_direct_best:643`, `_test_suppressed:662`,
`_merge_evidence:688`. Caps ProvidedOnly ≤ 0.35 (`_PROVIDED_ONLY_CAP:72`).
Sibling `core/semantic_ops.py:125 build_semantic_operation`,
`:281 semantic_identity_key`, `:329 _merge_semantic_ops`,
`:372 correlate_operations`, primitive inference `_infer_primitive:74`;
`operations.py:549 build_semantic_operations`, `:460 _correlate_semantic`, `:820 reconstruct_cir`.

### 5.3 Risk (Mosca-style) — `core/risk.py:495 score_operation, :663 score_cir, :684 to_cir_risk`

```text
score = clamp(0.35*Q + 0.20*E + 0.15*B + 0.15*C + 0.15*mosca_boost)  # 3 decimals
mosca_trigger(X, Y, Z) = (X + Y > Z)                                  # :216
wire score = round(score * 10, 2)  # 0..1 → 0..10
Classes: ≥0.8 Critical, ≥0.6 High, ≥0.4 Medium, ≥0.2 Low, else Informational
ProvidedOnly caps ≤ 0.39 (score = min(score, 0.39) :578); Suppressed → 0.0
```

Per-operation inputs (merged asset + risk_inputs + data_classification/notes):
`Q=QUANTUM_VULN:65` (RSA/DSA/DH/ECDH/ECDSA/X25519/Ed25519=1.0, HYBRID=0.35,
ML-KEM/ML-DSA/SLH-DSA=0.0, AES=0.15/0.30 if <256, MD5=0.60, SHA-1=0.50, DES=0.70,
RC4=0.70, AES-ECB=0.45, TLS-OLD=0.60, TLS12=0.30, TLS13=0.10, UNKNOWN=0.50;
`quantum_vuln:221`), `E=EXPOSURE_W:120` (internet-facing > cloud > third-party >
internal > offline), `B=CRIT_W:128`, `C=USAGE_CONFIDENCE:135` averaged with fused
confidence (`_confidence:403`), `mosca_boost ∈ {0,1}` from `_mosca_inputs:412`
(X=data-lifetime, Y=migration-years, Z default 10). Helpers `_risk_inputs:326`,
`_exposure_weight:338`, `_criticality_weight:362`, `_usage_state:393`,
`_class_for:483`, `_merge_asset_view:640`. V2 split: `assess_classical_posture:757`,
`assess_misuse_severity:817`, `assess_protocol_posture:848`,
`assess_quantum_exposure:879` (`0.7*q+0.3*trigger:901`, deployment `(E+B)/2:923`),
`score_operation_v2:948`. API: `api.py:510 risk(cir,Z)`, `:539 enrich_cir`,
`:589 _severity_for`, `:637 _rule_id_for`.

### 5.4 Recommendations — `core/recommend.py:343 recommend_for_operation, :434 recommend_cir, :480 to_cir_recommendation`

Registry `RECOMMENDATIONS:76` (RSA-ENC→ML-KEM-768 hybrid, RSA-SIG→ML-DSA-65,
DH/ECDH→hybrid X25519+ML-KEM, …; refs FIPS 203/204/205, NCCoE, OQS). Choice is
always registry-driven; risk only sets priority.

```text
replacement_score = .35*risk_reduction + .20*standards + .15*compat
                  + .10*latency + .10*effort + .10*cost          # :10, :323
sort = PRIORITY_ORDER(Critical0…Informational4) :42, then score desc, then op_id  # :461
```

Helpers `_priority_for:332`, `_asset_ids_of:404`, `_pqc_target_for:466`,
`pqc_target_for_operation:581`, `recommend_for_operation_v2:617`.

Planning layer — `adapters/migration_adapter.py:98 build_real_items`
(per-operation items: contract fields + verbatim P1 detail) plus additive
aids: `estimate_days` (rough person-day range from P1 S/M/L × file fan-out
capped ×3 + blockers + hybrid widening, cap 40d; `estimate_basis` states the
inputs), `app_group_for` (code-boundary bucket: top-two path segments),
`to_real_plan:192` envelope with `summarize_app_groups` (priority-ordered
triage grouping, never a sequence). Forbidden keys (timeline, sequencing,
state, owner) still absent; P1 scoring untouched.

### 5.5 Misuse — `core/misuse.py:489 check_operation, :479 check_rule, MISUSE_RULES:34`

12 data-rules via `_rule:19`: STATIC_KEY, PREDICTABLE_KEY, STATIC_IV_NONCE,
ECB_MODE, WEAK_RNG, CERT_VALIDATION_DISABLED, SMALL_KEY, DEPRECATED_ALGO,
WEAK_KDF, MISSING_AUTH, PASSWORD_AS_KEY, UNSAFE_SIG_HASH — each `_check_*:230–441`
does substring/regex on `op+params+blob` (`_text_blob:196`), severity High/Medium.

### 5.6 Evidence / graph / scope / scheduler / cache

- `evidence.py:188 classify_evidence(tool→EvidenceClass:26)` — ordered needle match
  (`_INVOCATION_NEEDLES:73`, `_BINARY_NEEDLES:93`); unknown → REFERENCE.
  `:294 semantic_state_for(usage+classes→SemanticState:40)`.
- `graph.py:179 build_graph(ops,assets,contexts)` → `{nodes,edges}`;
  `to_cir_graph:447`; `GraphIndex:554` (neighbors:607, risky_nodes:612,
  internet_facing:632, blast_radius:658, trace:688); `wire_system_links:768`.
  Node types `NODE_TYPES:67`, relations `RELATIONS:72`; linear passes, slug IDs `_slug:110`.
- `scope.py:261 classify_scope(path,language,build)`, `:350 classify_build_state` —
  path-part heuristics (`_path_hint:174`).
- `scheduler.py:211 InputRegistry.normalize→ScanJob:185`, `:240 AdaptiveScheduler`
  (triage→surface ∈ SURFACES:42, route→{stages,escalate}, should_escalate:335),
  `:366 ScanCache`, `:409 scan_paths_parallel`, `:113 infer_kind`,
  `:90 content_hash_for=blake2s16`.
- `scan_cache.py:83 parse_cache_key`, `:95 resolution_cache_key`,
  `:108 final_scan_cache_key(input+scanner_vers+registry+risk+rec+config+schema)`,
  `:141 ScanCacheV2{get:183,set:196,hit_rate:170}`, `:242 check_budget`,
  `:252 staged_escalation(cheap→parse→direct→dataflow→fingerprint)`.
- `crypto_knowledge/registry.py:44 CryptoKnowledgeRegistry{register:54,lookup:67,
  canonicalize:81}`, `algorithms.py:70 seed_algorithms`, `constants.py:73
  is_crypto_prefilter_hit`, `:84 fingerprint_prefilter_hit`, `policies/__init__.py:21 is_weak`.
- `inventory.py:117 classify_bytes` (magic+ext), `:279 _record_for`,
  `:332 safe_extract_archive`, `:466 inventory_target`.
- `timing.py:30 StageTimer{start:34,stop:37,section:51}`.

---

## 6. Scanners (all 8 families)

Dispatcher: `scanners/discovery.py:58 DiscoveryEngine{get_available_scanners:92,
scan:142, scan_and_emit_cir:332, _correlate_findings:211, _merge_findings:288}`,
`create_discovery_engine:455`. Path filter `scanners/path_policy.py:30
is_ignored_path`, `:36 iter_project_files`. Semantics `scanners/semantics.py:82
dependency_capability_only`, `:137 binary_escalation_policy`,
`:188 cert_asset_vs_operation`, `:228 config_state_classify`.
Base: `scanners/base.py:31 ScannerFinding`, `:114 Scanner`,
`:149 create_evidence_signal`, `:154 normalize_finding` (via signature_registry).

### 6.1 Source — `scanners/source/scanner.py:182 SourceScanner`

- **Python AST** `scanner.py:1006 CryptoASTVisitor{visit_Call:1040}`
  + `PYTHON_CRYPTO_PATTERNS` exact-match (`hashlib.`, `hmac.`, `Crypto.`, `cryptography.`).
  PyCryptodome constructors (`AES.new(key, AES.MODE_ECB)`, incl. fully-
  qualified form) resolve modes from dotted constants/bare names/aliases/
  `mode=` keywords (`_constructor_mode`, `_MODED_CIPHERS`; canonical embeds
  the mode: `AES-ECB`), with module-level constant collection in
  `_collect_imports` (R2 fix for the ECB false negative). Binding aliases
  (`AESGCM = rust_openssl.aead.AESGCM`) and cipher/mode class definitions
  yield ProvidedOnly capabilities via exact allowlists (R3/P4;
  `visit_Assign`, `visit_ClassDef`).
- **Facts + resolver**: `facts.py:260 extract_facts_python` (AST `_PythonFactVisitor:125`),
  `:271 extract_facts_brace` (regex call-split); `resolver.py:151 resolve_value`
  (assignment index, constant propagation), `:294 resolve_algorithm`, `:306
  resolve_curve`, `:328 resolve_key_size`, `:355 resolve_mode` (+ dotted-
  constant `_dotted_mode` and alias-to-dotted fallback, R2), `:398 expand_wrapper`
  (repo-defined wrappers → custom invocations).
- **C parser**: `c_parser.py:66 mask_source` (strip comments/strings, blank `#if 0`),
  `:282 extract_calls` (`_CALL_RE:54`) with brace-depth function spans
  (`_function_spans`: stack-based, any-depth defs incl. class methods,
  K&R close fix, Go receivers, throws/returns; R3/P1),
  `:357 collect_constants` (+ Java string constants `collect_java_string_consts`,
  R3/P1), `:405 _first_string` (never returns call-expressions; R3/P1),
  `:491 resolve_entry` (+ `ossl-pkey-type`, `ossl-cipher-encflag`,
  `ossl-digest-arg` parsers; jca-name `or canonical` fallback; R3/P2–P3),
  `:685 _name_to_canonical`, Java enum resolution (`resolve_java_enum_string`
  incl. enum-family fallback; R3/P1).
- **API knowledge**: `api_knowledge.py:101 API_PATTERNS[~400 rows]`
  (`{call,re,langs,canonical,cipher_arg,op}` incl. OpenSSL EVP table
  `_evp_ctor_rows:506`), compiled regex `compile_matchers:762`, exact index
  `build_exact_index:723`, lex prefilter `lex_prefilter:843`. R3 additions:
  JCA `BCrypt.hashpw/checkpw`, `SecureRandom`, `SecretKeySpec` (P1); OpenSSL
  DigestSign/Verify×Init/Final×one-shot, FinalXOF, PKEY_new_raw, CipherInit
  (P2); use_certificate/PrivateKey→X.509, X509_digest→digest-arg, tmp_dh→DH,
  curves→ECDH, echstore→TLS (P3).
- **Java wrapper attribution** (R3/P1, all in `scanner.py`): delegate table
  (`_stash_delegates`: factory wrappers with forwarded-param indexes),
  cross-file post-pass (`_resolve_cross_file_wrappers`: qualified/
  capitalized calls only, def-line skips), cipher field flows
  (`_field_flow_findings`: factory assignment + init direction + doFinal
  terminal; instance doFinal anchored to same-function findings), same-file
  wrapper hardening (declaration skips, overload-arity matching).
- **Fingerprints** (custom impl detection): `fingerprints.py:234 analyze_file` —
  hex-int tables `_hex_ints:131`, array blocks `_array_blocks:141`, 256-u8 S-box
  `_has_256_u8_table:176`, strong constants `_strong_constants:187` (AES S-box /
  SHA-256 K / MD5 s-table / ChaCha sigma), def-cluster `_def_cluster:342`.
- **Semgrep (optional)**: `semgrep_scanner.py:387 SemgrepScanner{scan:432,
  _ensure_rules:465, _parse_results:473}` (subprocess `semgrep --json`).
- Output: `ScannerFinding(canonical, confidence ~0.9, evidence tool=source:api-call/signal=call)`
  plus `source:wrapper-call` (Probable, one-hop attributions).

### 6.2 Dependency — `scanners/dependency/scanner.py:40 DependencyScanner`

Manifest parsing + exact package-name lookup in `crypto_packages.py:142
CRYPTO_PACKAGES` / `capabilities_for` (+`SYFT_CRYPTO_PACKAGES`). No crypto regex.
Parsers: requirements:180, pyproject:225, poetry.lock:273, package.json:312,
js lockfiles:354 (package-lock:368, yarn:406, pnpm:445), cargo.lock:525,
go.mod:564, pom.xml:607, gradle:651, gemfile:690, composer:730, cmake:826,
conan:873, vcpkg:916, meson:937, autotools:956, SBOM cyclonedx_json:1038 /
cyclonedx_xml:1072 / spdx_json:1104, external syft:1158 / cdxgen:1208, python
imports:1242. Always `dependency_only=True, ProvidedOnly, exposure=internal`.
`Cargo.toml` manifests parsed by `_scan_cargo_toml` ([dependencies],
[dev/build], `[target.*]`, `[workspace.dependencies]`; version/git/path
specs) against 18 Rust-crate knowledge entries (`ring`, `aes-gcm`,
`ed25519-dalek`, `sha2`, …) added to `CRYPTO_PACKAGES`/`SYFT_CRYPTO_PACKAGES`
(R2 fix; previously a missing-method error degraded the surface).

### 6.3 Binary — `scanners/binary/scanner.py:19 BinaryScanner` (cheap-always, expensive-gated)

Stages `binary/stages.py:135 detect_format(magic ELF/MZ/Mach-O)`, `:152
file_entropy` (Shannon, 256 KB sample), `:172 match_constants
(CRYPTO_CONSTANTS:341 — AES S-box, SHA-256 K, ChaCha sigma)`, `:184 match_oids
(CRYPTO_OIDS:361 DER+dotted)`, `:202 match_symbol_strings (CRYPTO_SYMBOLS)`,
`:237 analyze_cheap→CheapSignals:48`, `:328 decide_escalation
(constants/OIDs→capa/floss)`, `:384 run_capa`, `:451 run_floss`,
`expensive_tool_status:221`. Sub-scanners: `strings_scanner.py:13
({_extract_strings:107 ASCII runs min4, _match_crypto_string:131})`,
`lief_scanner.py:12`, `yara_scanner.py:472` (subprocess yara/yara-x),
`crypto_signatures.py:419 is_plausible_crypto_string` (word-boundary guard),
`re_strings:13`.

### 6.4 Container — `scanners/container/scanner.py:181 ContainerScanner`,
`docker_scanner.py:14`, `syft_scanner.py:14`

No crypto regex; delegates to backends + layer untar + Dockerfile/Compose parse.
`scan:312` routes image-ref vs docker-save.tar (`_scan_docker_save:461`) vs OCI
layout (`_scan_oci_layout:520`) vs rootfs (`_scan_rootfs:600`); per-layer
`_scan_layer_bytes:579`, sqlite layer cache `_get_cached_layer:215`. Backends
`_scan_with_syft:712` (syft scan -o json → `_parse_syft_output:75` +
`_map_syft_type:134`), `_scan_with_daemon:722` (docker inspect → env/labels/ports),
`_scan_with_trivy_fs:732`. `DockerScanner._scan_dockerfile:398 /
_scan_docker_compose:428` (FROM/COPY/EXPOSE + cert detect `_analyze_cert_content:358`).

### 6.5 Config — `scanners/config/scanner.py:18 ConfigScanner` (fan-out)

Per-service regex+parser sub-scanners, all
`can_scan_file+scan+_scan_file+_analyze_ciphers/_parse_cipher/_is_insecure_cipher`:
nginx (`ssl_ciphers:18`, `ssl_protocols:19`, `_analyze_protocols:205`
SSLv2/3/TLS1.0→TLS-OLD), apache (`SSLProtocol:17`, `SSLCipherSuite:18`), openssl
(`Min/MaxProtocol:17-18`, `CipherSuites/Ciphers/Options`, `_parse_tls13_cipher:231`),
envoy (JSON/YAML `TlsParameters:110`), kubernetes (Secret/Ingress/Workload
`_scan_secret:79`), terraform (`resource":17`, tls versions, `ssl_policy`,
`cipher_suites[]`, tfstate `_scan_tfstate:113`), dockerfile (FROM/COPY/EXPOSE,
`_CERT_COPY_RE:54`), generic (JSON/YAML/TOML walk `_scan_dict:163`,
keyword-boundary `_token:209`, `_guess_canonical:214`). Post:
`service_context.py:211 attach_service_context` (listen/server_name/VirtualHost/ARN/KMS regex).

### 6.6 Certificate — `scanners/certificate/scanner.py:15 CertificateScanner` (fan-out)

`cryptography`-lib parsing (not regex); key-type→canonical, size/curve, sig-algo
normalize. `pem_scanner.py:23` (cert:89, csr:155, private:207, public:256;
`_map_signature_algorithm:325`, `_identify_private/public_key:368/388`),
`der_scanner.py:22`, `jwk_scanner.py:12` (`_parse_jwk:59`, `_identify_jwk:100`
kty/crv→Ed25519/X25519/ECDSA/RSA), `pkcs12_scanner.py:11` (+openssl fallback
`_parse_openssl_output:135`), `jks_scanner.py:11` (keytool → `_parse_keytool_output:75`),
`ssh_scanner.py:12` (`_parse_ssh_key_type:114`). `cert_metadata.py:30
sha256_fingerprint_hex`, `:40 openssh_fingerprint`, `:49 public_jwk_view`.

### 6.7 Runtime — `scanners/runtime/scanner.py:25 RuntimeScanner`,
`tls_scanner.py:29 TLSScanner`, `ssh_scanner.py:13 SSHScanner` (opt-in only)

Live probes (host:port; `_parse_target:62`). TLS: `ssl.create_default_context
(verify=CERT_NONE):80` + `socket.create_connection:84` +
`cipher()/version()/getpeercert():87` → `TLSResult:16`; `_create_findings:150`
(negotiated cipher `_parse_cipher:241` CHACHA20/AES-GCM/ECDHE_RSA/DHE_RSA +
`_is_insecure_cipher:283`; cert `_map_signature_algorithm:288`,
`_get_key_size:304`, `_get_curve:323`). SSH: `ssh-keyscan -T:65` → `_parse_ssh_keyscan:85`
→ `_parse_ssh_key_type:161`. Availability via `shutil.which` (`external_tool_status:11`).

### 6.8 Cloud — `scanners/cloud/scanner.py:12 CloudScanner`,
`aws_scanner.py:11 AWSScanner`, `azure_scanner.py:9`, `gcp_scanner.py:9`

SDK inventory (no regex); **only AWS implemented**, Azure/GCP stubs return `[]`.
AWS via `boto3.Session:29` (explicit keys/profile or env; never logged):
`_scan_kms:99` (list_keys+describe_key → `_map_kms_key_spec:275`,
`_get_kms_key_size:293`), `_scan_acm:143`, `_scan_elb:182`, `_scan_alb:223`.
Label `aws:profile:services=kms,acm,elb` (`_parse_cloud_services:121`). Opt-in only.

---

## 7. Store, exports, reports

- **Store** — SQLite WAL (`store/db.py:69 connect`, `:92 init_schema`, `:110
  open_db`, `SCHEMA_VERSION=3`). DDL `:30`: `scans(id,target,started_at,
  finished_at,raw_json,cir_json,created_at)`,
  `findings(id,scan_id,rule_id,severity,file,line,title,confidence)` +
  `idx_findings_scan_severity`, `scan_meta(scan_id,plan_json,diagnostics_json)`
  (mig v2:+cir_json, v3:+scan_meta). CRUD `scans.py:30 insert_scan`, `:56 get_scan`,
  `:62 get_scan_doc`, `:70 get_scan_cir`, `:84 list_scans`, `:94 delete_scan`;
  `findings.py:22 insert_finding`, `:45 insert_findings_for_scan`, `:69
  list_findings`, `:85 count_findings`; `repository.py:67 ScanRepository{save_scan:94,
  get_payload:122, list_scans:139}` (+`replace=True` GUI overwrite);
  idempotent CLI/CI writes via `persist.py:store_scan_result`
  (reuse-on-duplicate, `--replace` overwrite).
- **Exports** (pure canonical→string): `exports/cbom.py:80 to_cbom_json`, `:91
  to_cbom_xml` (CycloneDX 1.6, 1 component+vuln per finding, `_bom_ref:20`);
  `exports/sarif.py:25 to_sarif` (SARIF 2.1.0, `LEVELS:9`
  critical/high→error, medium→warning, low/info→note); `exports/csv_gen.py:21 to_csv`.
- **Reports**: `reports/aggregate.py:747 build_report(doc,real_risk,recs,cir,
  coverage,plan)` → `{executive_summary:714, operations_summary:167,
  crypto_inventory:394, finding_groups:322, affected_components:507,
  coverage_summary:548, migration_groups:613, methodology:687}` + views
  (`inventory_view:915`, `findings_view:985`, `migration_view:1036`,
  `evidence_view:1086`, `risk_details_view:1118`, `coverage_view:1145`,
  `coverage_payload:116`; `_unified_severity:74`, `_scrub_snippet:99` 500ch).
  Renderers `console.py:23`, `markdown.py:17`, `html.py:63`, `pdf.py:702`
  (`ReportBuilder:218`, stdlib `Canvas:90`).

---

## 8. CLI — full command reference

Dispatcher `cli.py:58 build_parser` (`prog=ecdat`, subparsers required).
Shared: `_context_options:17` (`--environment/--owner/--exposure/
--business-criticality/--criticality/--data-lifetime/--migration-years/--risk-z=10`),
`_common_scan_options:38` (`--db ~/.ecdat/ecdat.db, --output, --scanners,
--allow-container/cloud/runtime, --cir-out, --replace,
--profile{quick,standard,deep}=standard`),
`DEFAULT_DB:12`, `SEVERITIES:13`, `PROFILES:14`.
Re-scanning identical input reuses the stored row (exit 0, same ID);
`--replace` overwrites it. `ci` additionally accepts `--replace`.

| Command | Args | Handler |
|---|---|---|
| `scan [path]` | `path?`, `--repo URL` | `commands/scan_cmd.py:13` → `_real_scan:30` |
| `scan-binary <binary>` | `binary` + common | `commands/scan_binary_cmd.py:13` |
| `scan-container <image_or_path>` | `image_or_path` + common + `--allow-pull/--allow-build` | `commands/scan_container_cmd.py:12` |
| `scan-cloud aws` | `provider{aws}`, `--profile`(AWS profile, not depth), `--services=kms,acm,elb`, `--region`, `--aws-access-key-id/--aws-secret-access-key/--aws-session-token/--aws-profile` | `commands/scan_cloud_cmd.py:19`, `build_target_label:12` |
| `list` | `--db --limit=100 --json` | `commands/list_cmd.py:19` |
| `show <scan_id>` | `--db --json` | `commands/show_cmd.py:21` |
| `risk <scan_id>` | `--db --json` | `commands/risk_cmd.py:22` |
| `recommend <scan_id>` | `--db --json --severity` | `commands/recommend_cmd.py:15` |
| `export <scan_id>` | `--format{json,csv,cbom-json,cbom-xml,sarif}=json --output --db` | `commands/export_cmd.py:46` |
| `report <scan_id>` | `--format{markdown,console,html,pdf}=markdown --output --db` | `commands/report_cmd.py:43` |
| `gui` | `--host=127.0.0.1 --port=8734 --db` (loopback-only) | `commands/gui_cmd.py:15` → `web/server.py:966 make_server/main` |
| `ci <target>` | `target --fail-on --summary --json --sarif --scanners --allow-*/--cir-out/--region + context + profile` | `commands/ci_cmd.py:128` (`evaluate:33`, rank `:26`, posture `:48`) |

CI examples are in root `README.md:70-95` (local dir, `--repo` GitHub, binary,
container tar/image-ref, cloud, scanner subset, opt-ins, `ci --fail-on high` gate).

---

## 9. GUI (React) + web API

**Frontend** (`frontend/src`, single SPA, no router; tabs
`[Overview, Findings, Crypto Inventory, Crypto Graph, Migration, Coverage]`
`App.tsx:88-95`):

| UI step | Component | API call |
|---|---|---|
| Hero/nav | `App:616-653` | — |
| Step 1 upload (drag/drop, browse, ZIP/TAR, allowlist `.py/.js/.c/.pem/.exe`) | `App:659-749`, `InputSummary:1354-1377`, `upload():396-436` | `POST /api/uploads` (headers X-File-Name/Relative-Path/Input-Id, octet-stream) → `server.py:623 _upload()` |
| Inspect | `App:424-428` | `POST /api/inputs/inspect{input_id}` → `server.py:644 _inspect_input()` (archive expand, host:port detect, `inventory_target`) |
| Demo | `App:709-748`, `useDemo():480-497` | `GET /api/demos`, `POST /api/demos/select` |
| Step 2 GitHub (OAuth + public URL + private list/search) | `App:751-880`, `GithubProjectStatus:1379-1432` | `POST /api/github/public{url}`, `POST /api/github/repos/select`, `GET /api/github/repos/session/oauth/*`, `POST /api/github/logout` → `server.py:677-963` (+ `acquisition.py`) |
| Config (auto `source,dependency,binary,config,certificate` + opt-in container/runtime/cloud; manual override `App:500-506`; profile fixed `standard` `:509`) | `App:883-1015`, `AUTO_LOCAL:100-106`, `layers:78-87`, `scanBody():499-534` | `POST /api/scan-plan` (preview, `server.py:695`), `POST /api/scan-jobs{input_id,profile,scanners,allowPull/Build,cloudConfig,context,risk_z}` → `server.py:743 _start_job()` → `ScanOrchestrator.scan()` in thread `_run_job:310-436` |
| Progress | `App:1026-1044`, poll 700 ms `App:551-561` | `GET /api/jobs/:id` → `server.py:499` |
| Results (Overview cards Risk/Findings/Assets/Operations; GroupedFindings; Inventory; CryptoGraph ReactFlow+ELK; Migration; Coverage; downloads pdf/json/cir) | `App:563-585,1091-1143`, `CryptoGraph.tsx`, `graphViews/SecurityMap/Layout/Labels/Focus/Edges` | `GET /api/results/:scan_id`, `GET /api/results/:id/report/:format` → `server.py:517 _result_payload:265-307` (+ `/report/:fmt _report:558`) |
| Cloud modal (AWS only; Azure/GCP “coming soon”) | `CloudConfigModal:1167-1352` | `body.cloudConfig:515-532` |
| Misc | `api(url,init)` helper `App:108-125` (`fetch /api+url, credentials:include`) | `GET /api/health:486`, `/api/scanner-capabilities:489`, `/api/demos:492`, `/api/scans:508`, `DELETE /api/inputs/:id:615` |

**Backend** (`web/server.py`): loopback `ThreadingHTTPServer`; safe zip/tar
extract `_safe_extract_zip:87/_safe_extract_tar:102` (20k members, 250 MB);
session workspaces cleaned on exit; `_result_payload:265` =
`adapt_cir_graph + summarize_wire_risks + build_real_items +
aggregate.build_report` → persisted via `ScanRepository.save_scan:423`.

**Dashboard workflow** (user journey): Repository input (GitHub URL / upload /
demo) → scan plan + monitor (read-only plan, staged progress) →
inventory/findings (row → detail: usage state, evidence, confidence, redacted
snippets) → risk dashboard (Mosca posture over wire risks) → asset inventory
(CBOM assets) → knowledge graph (CIR projection) → migration planner (P1
recommendations + rough estimate ranges and code-boundary triage groups;
no persistent migration state) → reports (HTML/PDF/CSV/JSON/
SARIF/CBOM/CIR downloads).

---

## 10. Acquisition, security, contracts

- **Acquisition** `acquisition.py:134 acquire_github_repository(url,parent)`:
  `is_github_url:45`/`parse_github_url:50` (`GITHUB_URL_PATTERN:40`),
  `download_github_tarball:96` (codeload tar.gz/HEAD, 1 MB chunks,
  `MAX_DOWNLOAD_BYTES=250MB:37`), `extract_archive:121` +
  `_safe_extract_{zip,tar}:66/80` (PurePosixPath traversal guard
  `_safe_relative:59`, `MAX_ARCHIVE_MEMBERS=20000:38`), flatten single top-level.
- **Security**: secrets from env only; never logged/stored/reported; zip-slip/
  tar-slip guards; runtime/cloud opt-in; loopback-only GUI (`--host` non-loopback
  refused by design); ephemeral `--port 0`; shared `--db` for CLI+GUI.
- **Contracts**: pinned in `tests/contract/` (`test_core_client:52-93`,
  `test_core_contract:70-106`) and `docs/P1_P2_INTEGRATION_CONTRACT.md`.
  Honest limits: P1 Mosca + recommendations (+ rough planning ranges) only;
  no persistent migration state,
  owners/timelines/sequencing, full Azure/GCP, guaranteed Docker, external baselines,
  full runtime probing, prod auth/remote deploy.
- **Troubleshooting** (root README): port busy → `gui --port 0`; stale DB → same
  `--db`; pytest → `python -m pytest -q` (GUI binds 127.0.0.1 ephemeral only);
  missing real-scan deps named in error; setuptools `referenceDocs` exclusion fix.

---

## 11. File reference index (primary sources)

- Pipeline: `ecdat/core/orchestrator.py:837`, `ecdat/scanners/discovery.py:332`,
  `ecdat/adapters/pipeline.py:54`, `ecdat/core/client.py:25`,
  `ecdat/commands/_real_scan.py:30`
- Models: `ecdat/core/cir_models.py`, `ecdat/core/models.py`,
  `ecdat/core/cir.schema.json`, `ecdat/core/canonical_v1.json`,
  `ecdat/core/cir_validate.py:26`, `ecdat/core/validate.py:40`
- Analysis: `ecdat/core/fusion.py:104`, `ecdat/core/operations.py:316`,
  `ecdat/core/risk.py:495`, `ecdat/core/recommend.py:343`, `ecdat/core/misuse.py:489`,
  `ecdat/core/evidence.py:188`, `ecdat/core/graph.py:179`, `ecdat/core/api.py:539`
- Infra: `ecdat/core/inventory.py:466`, `ecdat/core/scheduler.py:211`,
  `ecdat/core/scan_cache.py:108`, `ecdat/core/scope.py:261`
- Interfaces: `ecdat/cli.py:58`, `ecdat/web/server.py:472/589`,
  `frontend/src/App.tsx`, `ecdat/acquisition.py:134`
