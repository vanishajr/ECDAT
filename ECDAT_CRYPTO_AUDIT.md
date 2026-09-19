# ECDAT Crypto Detection / Correlation / Risk — Current-System Audit

> Read-only audit. No code modified. Purpose: give a second engineer exact file/function ground truth to plan precision/recall/semantic/risk improvements.
> Repo root: `D:\Coding\Websites\ECDAT`. Package is `ecdat/` (there is no `ecdatt/` package).

---

## A. REAL CURRENT PIPELINE (exact file → function flow)

### A.1 Entry points

```
frontend/src/App.tsx:upload():368
  → POST /api/uploads (X-Input-Id/X-File-Name/X-Relative-Path)
  → POST /api/inputs/inspect (App.tsx:396)
frontend/src/App.tsx:connectPublicRepo():420 / selectRepository():310
  → POST /api/github/public | POST /api/github/repos/select
frontend/src/App.tsx:scanBody():445, previewPlan():474, analyse():492
  → POST /api/scan-plan, POST /api/scan-jobs
  → poll GET /api/jobs/:id (509), GET /api/results/:id (521)
  → GET /api/results/:id/report/:fmt (download():554)
ecdat/cli.py:build_parser():58, main():164
  → scan→commands/scan_cmd.py:run():13
  → scan-binary/container/cloud, ci→commands/ci_cmd.py:run():128,
    gui→commands/gui_cmd.py:run():15, report/export/risk/recommend/show/list
ecdat/commands/scan_cmd.py:run():13 → commands/_real_scan.py:run_real_and_store():30
  → core/client.py:RealCoreClient(scanners/allow_*/profile/risk_z/context/caller)
  → client.scan_result(target):69/150 → result.as_tuple()
  → store/db.py:open_db() + store/scans.py:insert_scan()
    + store/findings.py:insert_findings_for_scan()
    + store/repository.py:save_meta():33
ecdat/commands/ci_cmd.py:run():128 → core/client.py:RealCoreClient:34/136 (caller=ci)
  → scan_result():150 → sstore/fstore/save_meta:159 → build_result():87
  + evaluate():33 + _posture():48 + _limitations_from():55
ecdat/core/client.py:RealCoreClient.__init__():34, scan_result():69,
  scan_with_cir():102, scan():66
  → core/orchestrator.py:get_orchestrator():1213 → ScanOrchestrator.scan():813
```

### A.2 Web API (`ecdat/web/server.py`, stdlib `BaseHTTPRequestHandler`)

- `Handler._upload():567` — stream `Content-Length` → `STATE.inputs/<id>/`.
- `Handler._inspect_input():588` — `core/inventory.py:safe_extract_archive():332` then `_inspect():139` → `inventory_target():466` + `scanners/path_policy.py:iter_project_files():34` + `_architecture():124`.
- `Handler._scan_plan():605` — `_profile_scanners():227` → `ScanRequest` → `get_orchestrator().plan().as_dict():629`.
- `Handler._start_job():631` — `_profile_scanners:639` + `orchestrator.context_from_args():261` + `risk_z_from_args():320` → `STATE.jobs` → `Thread(target=_run_job):661`.
- `Handler._run_job():310` — `STATE.input_for`, `_ScanContext`, `ScanRequest(caller=gui):353` → `get_orchestrator().scan(request, progress=_on_progress):371` → `result.as_tuple()` → `_result_payload(cir,canonical,plan,diagnostics):373` → `store/repository.py:ScanRepository.save_scan(replace=True):378`.
- `Handler.do_GET():425` — `/api/health:439`, `/api/scanner-capabilities:442`, `/api/jobs/:446`, `/api/scans:454` (`ScanRepository.list_scans:139`), `/api/results/:id:463` (memory else `get_payload():122` → `_result_payload:478`), `/api/results/:id/report/:fmt:493` → `_report():504`.
- `Handler._result_payload():265` — `adapters/graph_adapter.py:adapt_cir_graph():55` + `adapters/risk_view.py:summarize_wire_risks():31` + `adapters/migration_adapter.py:build_real_items():98` + `reports/aggregate.py:coverage_payload():116` + `commands/ci_cmd.py:_limitations_from():55` + `reports/aggregate.py:build_report():747`.
- `Handler._report():504` — `reports/markdown.py:to_markdown()`, `reports/html.py:to_html()`, `reports/pdf.py:to_pdf_bytes()`, canonical→json, cir→json, `exports/csv_gen.py:to_csv()`, `exports/sarif.py:to_sarif():25`, `exports/cbom.py:to_cbom_json/xml()`.

### A.3 Scan-plan / scanner selection

- `web/server.py:_profile_scanners():227` — explicit `requested` else `DEFAULT_SCANNERS` for quick/standard/deep; validated vs `DEFAULT_SCANNERS:19` + `OPT_IN_SCANNERS:37`.
- `adapters/scanner_policy.py:resolve_scanners():46` — `scanners!=None` → strict allowlist (unknown→`ValueError`); `None` → `DEFAULT_SCANNERS + allow_container/cloud/runtime`.
- `core/orchestrator.py:ScanPermissions:198`, `ScanRequest:338` (`normalized_profile:358`, `scanner_list:361`, `display_target:373`, `archive_depth:378`), `PROFILE_EFFORT:155` (quick: no-escalation/depth2, standard: escalation+depth3, deep: depth5), `SURFACE_OWNER:177`.
- `ScanOrchestrator.plan():731` — `InputRegistry.normalize:877` → `AdaptiveScheduler.route:878` → `_inventory_for_request():493` → `_surfaces_for():520` (`AdaptiveScheduler.triage_artifact:289`) → `_permissions_required_for():536` → `DiscoveryEngine(enabled).availability():772` → `ScanCache.get(_cache_key_for:553):780` → `ScanPlan:406/as_dict:439`.
- `frontend/src/App.tsx:AUTO_LOCAL:92` mirrors `DEFAULT_SCANNERS` (`source,dependency,binary,config,certificate`).

### A.4 Orchestrated scan (`core/orchestrator.py:ScanOrchestrator.scan():813`)

1. `cleaned=request.cleaned_target():824`, `normalize_profile:827`, `resolve_scanners:837`, `_target_requires_existing_path:846`, pull-gate `allow_pull:854` + `container_backend_status:865`.
2. `scheduler.py:InputRegistry.normalize():214` → `AdaptiveScheduler.route():309` → emit `normalize:835, plan:884, inventory:893, triage:901`.
3. `_inventory_for_request:894` → `inventory.py:inventory_target:466` (`classify_bytes:117`, `_record_for:279`, `safe_extract_archive:332`) + `_surfaces_for:896` + `_permissions_required_for:897`.
4. `_cache_key_for:909` → `scheduler.py:ScanCache.get():379` → hit return `915`.
5. `scanners/discovery.py:DiscoveryEngine(enabled_scanners):58` → `availability():98` gate `942` → emit `availability:942, discovery:976`.
6. `scan_kwargs:979` → `DiscoveryEngine.scan_and_emit_cir(cleaned,...):1008` → emit `normalize_cir:1018, validate_cir:1033, enrich:1045, validate_canonical:1074, complete:1185`.
7. `cir_doc.model_dump:1020` → `adapters/normalize.py:normalize_cir():93` → `core/cir_validate.py:validate_cir():27` → `_apply_scan_context:1053/589` → `core/api.py:enrich_cir():539` + `to_canonical():650` → fixups `1061` (`files_from_cir:78`, `synthesize_asset_only_findings:128`) → `core/validate.py:validate()` → re-`validate_cir(enriched):1089`.
8. `ScanPlan:1094` + `diagnostics:1156` (`engine.last_status():1129`, `_escalation_for:1132→628`, `binary_stage_report():1136`) → `ScanCache.set:1197` → `ScanResult:1187/as_tuple:479`.

### A.5 Discovery / per-family scan

- `scanners/discovery.py:DiscoveryEngine.scan():139` — ThreadPool per family (sort `195`), `is_available+scan` → `_last_status:114`, `normalize_finding (base.py)` → `_correlate_findings:208` (`(file,canonical)` + ≤5-line merge) → `_merge_findings:276` / `_get_scanner_name:267`.
- `scan_and_emit_cir():320` → `scan:327` → `_emit_cir:346` (`ScannerFinding.to_asset:48` / `to_operation:86` via `cir_models.new_asset_id:202` / `new_operation_id:223`, `_add_asset_to_graph:389`, `_add_operation_to_graph:411`, `_get_tool_versions:429`) → `core/operations.py:reconstruct_cir():543` (`_hit_for_operation:443` + `build_operations:207` + `fusion.weighted_fusion/decide_usage:104/176` + asset regroup + `core/graph.py:wire_system_links():768`).
- Families: `source/scanner.py:SourceScanner.scan():192`, `dependency/scanner.py:55`, `binary/scanner.py:45`, `config/scanner.py:40`, `certificate/scanner.py:35`, `container/scanner.py:312`, `cloud/scanner.py:40`, `runtime/scanner.py:41`. Base: `scanners/base.py:Scanner:119`, `ScannerRegistry:126`, `ScannerFinding:27`; `scanners/path_policy.py:iter_project_files:34`.

### A.6 Enrich → canonical → views

- `core/api.py:enrich_cir:539` → `risk(cir,Z):510` → `core/risk.py:score_cir:658` → `score_operation:490` → `recommend(cir,risks):519` → `core/recommend.py:recommend_cir:431` → `recommend_for_operation:340`; `to_canonical:650` (`_severity_for:589`, `_human_title:605`, `_rule_id_for:637`).
- `adapters/risk_view.py:summarize_wire_risks:31` (verbatim top wire risk), `adapters/migration_adapter.py:build_real_items:98`, `adapters/graph_adapter.py:adapt_cir_graph:55`, `reports/aggregate.py:build_report:747` (`_finding_groups:322`, `_crypto_inventory:394`, `_migration_groups:613`, `_coverage_summary:548`, `coverage_payload:116`, `_methodology:687`, `display_path:42`).
- Persist: `store/repository.py:save_scan:94/get_payload:122/list_scans:139/save_meta:33`; `store/scans.py:insert_scan:28`, `store/findings.py:insert_findings_for_scan`, `store/db.py:open_db`.

### A.7 Designed-but-unused / legacy / dead (no prod caller)

- `core/api.py:scan():458, scan_paths():498` — `adapters/pipeline.py:5` notes `api.scan is never called`; orchestrator calls only `enrich_cir/to_canonical`.
- `core/api.py:get_openapi():743`, standalone `risk():510`/`recommend():519` — only used inside `enrich_cir`.
- `adapters/pipeline.py:run_real_scan():54` — only test caller `tests/test_repository_analysis_boundaries.py:5`.
- `adapters/scanner_policy.py:PROJECT_SCANNERS:29, cached_availability():80` — unused in prod.
- `core/scheduler.py:ScanPlan:203, scan_paths_parallel():409` — orchestrator has own `ScanPlan:406`; no prod caller for parallel helper. `ScanCache:366, InputRegistry:211, AdaptiveScheduler:240` are live.
- `core/graph.py:build_graph/to_cir_graph` — dead in real path; real graph is `DiscoveryEngine._emit_cir + operations.reconstruct_cir + wire_system_links`.
- `core/fusion.py:deduplicate():219` — no prod caller (fusion via `weighted_fusion/decide_usage` through `operations.py`).
- `scanners/source/python_ast.py:PythonASTScanner:87` — dead duplicate; wired class is `source/scanner.py:SourceScanner:177`.
- `scanners/discovery.py:create_discovery_engine():443, get_available_scanners:92, get_enabled_scanners:95`, `scanners/base.py:ScannerRegistry:126` — registered but never read (hardcoded `factories:71`).
- `AdaptiveScheduler.route():309` stage names are advisory labels; execution fans out by family; `escalated` hardcoded `0` (`orchestrator._escalation_for:628`).

---

## B. DETECTION CAPABILITY MATRIX

| Capability | Implemented? | Location | Quality / notes |
|---|---|---|---|
| C/H API-call regex | Yes | `scanners/source/api_knowledge.py:77-206,472-497`, `scanners/source/c_parser.py:222-260`, `scanners/source/scanner.py:370-522` | Only path for C. ~OSS-EVP/SSL + sodium rows. `rx.search(site.name+"(")`; first-row-wins. No AST/symbols |
| Python AST import/call | Yes (py only) | `scanners/source/scanner.py:678-1030 CryptoASTVisitor`, `python_ast.py:149-262` | Imports→ProvidedOnly/Possible; calls matched by name |
| Semgrep rules | Partial (opt-in, usually unavailable) | `scanners/source/semgrep_scanner.py:14-384,407-463`, merged `source/scanner.py:614-647` | No tiny-AES rule; `is_available()==False` → no-op |
| `#define`/`const` one-hop constant prop | Yes (candidate-only) | `scanners/source/c_parser.py:297-333,431-590` | Only consumed by known-API `cipher_arg/parser` rows; dead data otherwise |
| Wrapper (same-file one-hop) | Yes | `c_parser.py:414-428`, `source/scanner.py:470-522` | `conf=0.70`, `CONFIRMED→PROBABLE`; chains not followed; needs seed API hit |
| Imports / `#include` resolution | No (C) | — | Python `_collect_imports:688-701` has no C equivalent |
| Function-def as evidence | No | `source/scanner.py:524-545 _looks_like_declaration` filters prototypes; `Location.function` attribution only | `DSA_generate_key` def ≠ finding by itself |
| Type info / dataflow / call graph | No | `c_parser.py:1-13` “No whole-program analysis” | No def-use across files, no taint |
| Call-graph / interprocedural | No | — | `find_wrappers` explicitly one-hop |
| Macro expansion / `#ifdef` / `-D` / build-graph | No | `source/scanner.py:417-418` skips `#` lines; `inventory.py:179-182` build files→dependency only | `AES128 1` vs commented `AES192` indistinguishable |
| CMake/Makefile/Meson/Bazel semantic parse | No (manifest names only) | `scanners/dependency/scanner.py:826-1002` | `find_package/target_link_libraries` → single ProvidedOnly capability |
| Test/scope path heuristic | Partial | `c_parser.py:35-37,394-411`, `operations.py:353-393`, `path_policy.py:10-27` | Dir-name lists; misses `*_test.go`, `testdata/`, vendored `lib/` |
| Custom-impl structural fingerprint (source) | No | — | S-box/Rcon bytes survive masking but never inspected |
| Binary constants (S-box/SHA/ChaCha) | Partial (binary only) | `scanners/binary/crypto_signatures.py:341-358`, `stages.py:172-199` | `637c777b→AES` etc.; requires compiled artifact |
| YARA strings | Yes (binary, strings-only) | `scanners/binary/yara_scanner.py:12-469` | `nocase` literals, conf 0.5–0.75; no CFG/disasm |
| Dependency package-name match | Yes | `scanners/dependency/crypto_packages.py:28-139` | `tiny-aes ∉ CRYPTO_PACKAGES`; vendored file → nothing |
| Config TLS strings | Yes | `scanners/config/*_scanner.py` | Cipher-string regexes only |
| Cert OID/curve/key-size parse | Yes | `scanners/certificate/*.py` | Real parse via `cryptography` lib, then `normalize_algorithm` |
| Generic-API context tracing (EVP cipher_arg) | Partial | `c_parser.py:458-469 resolve_entry` | Unresolved → `canonical=OpenSSL conf≤0.70`; `EVP_PKEY_*` hardcoded (see §I) |
| Constant propagation / interprocedural for EVP | No | — | One const-hop + positional literal only |
| Risk scoring | Yes (downstream) | `core/risk.py:490-700`, `adapters/risk_view.py:31` | Mosca-style 0..1→0..10; ProvidedOnly capped 0.39 |
| Migration rules | Yes (substring rules) | `core/recommend.py:73-290,340-490` | Order-dependent `has()` cascade; ignores `operation_type`/`library` |

Why tiny-AES-c is missed: source path requires `CallSite.name` to match a row in `api_knowledge.py` C langs. There are zero rows for `AES_init_ctx|AES_ECB_encrypt|AES_CBC_*|AES_CTR_*|KeyExpansion|SubBytes|ShiftRows|MixColumns|sbox|Rcon|TinyAES`. Extracted calls exist but `finding is None`; wrapper seed set empty; S-box/Rcon numeric arrays ignored; semgrep has no rule and is unavailable; dependency/config/binary paths have no signal → fusion never invoked.

---

## C. EVIDENCE / CIR MODEL

### C.1 Current schema (`core/cir.schema.json:1-295`, `core/cir_models.py:16-235`)

```json
CryptoAsset{asset_id, canonical, original, key_size?, mode?, curve?, protocol?,
 library?, usage_state:[Confirmed,Probable,Possible,ProvidedOnly,FalsePositiveSuppressed],
 confidence:0-1, evidence:EvidenceSignal[], location:Location{file?,line?,column?,function?,uri?},
 implementation:Implementation{library,version?,provider?,api?},
 context:Context{exposure,environment?,data_classification?,notes?},
 risk_inputs:RiskInputs{usage_state,exposure?,sensitive_data?,external_dependency?}}
CryptoOperation{operation_id, operation_type:[Encrypt,Decrypt,Sign,Verify,KeyExchange,Hash,KDF,TLS,Storage,KeyManagement],
 asset_id, confidence, evidence, function?, +location/implementation/context/risk_inputs}
EvidenceSignal{tool, detail, confidence?, snippet? (redacted)}
Graph{Node{id,kind:[asset,operation,file,service,host,library,key]}, Edge{from,to,relationship:[uses,calls,contains,derives,protects,depends_on,terminates]}}
```

Legacy pre-CIR `core/models.py:13-88 Finding{rule_id,title,severity,file,line,snippet,confidence,metadata}`.

Covered as first-class: primitive/canonical ✓, original ✓, mode ✓, key_size ✓, curve/protocol ✓, operation ✓, API (`implementation.api`) ✓, evidence ✓, location ✓, usage_state ✓, confidence ✓, asset linkage ✓, dependency (→ProvidedOnly) ✓.
Missing as first-class:

- `scope` — only `service=` smuggled in `context.notes` (`operations.py:396-400`) + graph `svc-` bit.
  Intended scopes (production/application, library-impl, test, demo/example, doc, generated, build/config, dependency, binary, cert/key, unknown) have no enum.
- `evidence-type` taxonomy REFERENCE / DECLARED/SUPPORTED / IMPLEMENTED / REGISTERED/ENABLED / INVOKED / PROBABLE / CONFIRMED — collapsed early to `tool:` prefix + confidence + usage_state.
- `impl-vs-invoke` — only `tool: source:api-call vs dependency:syft` + `Implementation.provider/api`; version almost always `unknown`.
- `build state` (supported/default/enabled/disabled/conditional) — no field; only `is_test_fixture/is_checksum_only` flags + `packed/stripped` in stage report.
- `configured vs supported` — no distinction.

### C.2 Where information is lost / collapsed too early

- `scanners/base.py:49-58 to_asset()` — `asset_id=new_asset_id(canonical|key_size|mode|curve|protocol|file|line)` (`cir_models.py:202-220`); distinct snippets/confidences with same tuple merge in `discovery.py:363-372`.
- `discovery.py:276-318 _merge_findings` — keeps winner location/impl/context/function, concatenates evidence, `max(conf)`; loser file/line/API dropped pre-CIR.
- `core/operations.py:168-204 group_key_for` 9-tuple drops `library/version/provider/api/line/column/uri/snippet/confidence/tool`; `:228-330 build_operations` fuses to one op (confidence formula, ProvidedOnly cap 0.35); single redacted snippet.
- `operations.py:706-801 reconstruct_cir` asset regroup `(canonical,key_size,mode,curve,protocol,file)` collapses line/function/service/endpoint; new `ast:sha256(...)`; graph rebuilt minimal + `wire_system_links`.
- `adapters/normalize.py:93-120` overwrites scan_id/target/timestamps/stats; `EvidenceSignal.redact_snippet` replaces PEM/key with `[REDACTED]`.

---

## D. ROOT CAUSES (ranked)

1. **Source detection is library-API-call allowlist only** (`api_knowledge.py` + `c_parser.extract_calls` + `rx.search(name+"(")`). No structural/constant/AST fingerprint → 100% FN on self-contained impls (tiny-AES-c). Architectural.
2. **No usage-state / evidence-type ontology.** Single `usage_state` enum + confidence formula (`fusion.py:104-216`) cannot represent REFERENCE/DECLARED/IMPLEMENTED/REGISTERED/INVOKED/CONFIRMED. Forces `def==usage`, `registration==usage` collapses downstream.
3. **Generic-API resolution is hardcoded, not dataflow.** `EVP_PKEY_derive→ECDH` (`api_knowledge.py:117-120,141-144`), `EVP_PKEY_(encrypt|decrypt|sign|verify)→RSA` (`:121-124`), `EC_KEY→ECDSA` (`:113-116`). No context-creation/assignment/param tracing → systematic wrong-algorithm FPs.
4. **No scope model.** Dir-name heuristics (`TEST_DIR_NAMES`, `IMPL_DIR_NAMES`, `_is_test_path`, `path_policy.IGNORED`) + `test_best<0.8` gate (`operations.py:385-393`) leak test/demo/doc/cert evidence into prod findings and risk.
5. **No build/config semantics.** No `#ifdef`/`-D`/CMake-option/Meson-option/Bazel-select evaluation; `find_package(OpenSSL)` → capability regardless of linkage; every `Min/MaxProtocol=` → `CONFIRMED` (`openssl_scanner.py:86-128`). Supported≠enabled≠default conflated.
6. **Correlation keys drop semantics.** 9-tuple + `|provided-only` suffix + `(file,canonical)+5-line` pre-pass (`discovery.py:208-265`, `operations.py:168-204`) merge impl/header/wrapper/callsite/test/doc by proximity, not role. Causes OpenSSL/Node duplicates + overlaps.
7. **Migration `_rule_key` is order-dependent substring cascade** (`recommend.py:239-290`) ignoring `operation_type`/`library`/`location`. Causes `SHA256withRSA→RSA-SIG`, `TLS+CBC→TLS-OLD`, `DSA→RSA-SIG`, `OPENSSL→REVIEW` (UI misread as `OpenSSL→TLS1.3` when grouped by library node).
8. **Risk scores unscoped evidence.** `score_operation` scores all non-suppressed states (`ProvidedOnly` capped 0.39 Low, else full Mosca `0.35Q+0.20E+0.15B+0.15C+0.15mosca_boost` with inferred defaults X=5/Y=3/Z=10, E=internal, B=medium). Test/impl-only with strong direct conf (≥0.8) stays Confirmed → deployment-style severity.
9. **Split-brain registries.** P1 `signature_registry.json` (aliases/OIDs/libraries/weak/pqc_map) vs P2 `p2_signature_registry.json` (algorithms/category) + `api_knowledge.py` EVP table + `CRYPTO_SYMBOLS/STRINGS/CONSTANTS` + `CRYPTO_PACKAGES`. `risk.py` has own `QUANTUM_VULN` table; `weak`/`recommendation_rules` unimported. No single canonical knowledge API.
10. **Scheduler/plan labels unconnected.** `route().stages`, `escalated=0`, write-only `_file_cache`, in-mem `ScanCache` (tool-change blind), no retries/deadlines. Improved detectors must respect: ~2k LOC/s source, 60s wall, regex×rows×callsites hotspot, `mask_source` O(n), archive re-feed, `reconstruct_cir` O(groups×evidence).

---

## E. tiny-AES-c FAILURE TRACE (aes.c / aes.h / test.c, no external calls)

1. Inventoried as `source` (`inventory.py:193-194`, `scheduler.py:275-276`), opened (`source/scanner.py:218-224`). If under `test|tests|examples` → `test-vector`; if under `crypto/` → `implementation` (`c_parser.py:394-411`).
2. `aes.h` → `header-capability` (`c_parser.py:409-410`); prototypes filtered by `_looks_like_declaration` (`scanner.py:524-545`); best case `PROBABLE ≤0.80`.
3. `mask_source` preserves `sbox[256]={0x63,0x7c,...}`, `Rcon[11]`, `AES128/ECB/CBC/CTR defines` as code, but no inspector reads numeric literals except `collect_constants:297-312` (only `#define`/scalar, consumed only for known-API args).
4. `extract_calls` emits `AES_init_ctx`, `AES_ECB_encrypt`, `AES_CBC_*`, `AES_CTR_*`, `KeyExpansion`, `AddRoundKey` CallSites — loop `scanner.py:415-446` tests each vs `patterns_for("c")` (`EVP_*|SSL_*|sodium*`). Zero match → zero findings; `find_wrappers` seed empty → local wrappers also zero.
5. `#define AES128 1 / ECB 1 / CBC 1 / CTR 1` captured in `consts` but `resolve_entry` has no row → dead data. No `aes.h↔aes.c` include link.
6. S-box prefixes known only in `binary/crypto_signatures.py:342-345`; source has no equivalent. Semgrep has no tiny-AES rule + usually unavailable. Dependency (`tiny-aes ∉ CRYPTO_PACKAGES`), config, binary see nothing → `fusion`/`operations` never run; `normalize_algorithm` passthrough never reached.
7. Net: `0 crypto operations`, only generic category/keyword capabilities. Fix requires new `langs=("c","cpp")` rows and/or source-side static-table heuristic — not a config tweak (per `api_knowledge.py:1-7` registry-driven rule).

AES / AES-128 / ECB / CBC / CTR unrepresented because: no API row → no finding → no asset → no operation → no inventory → no risk/migration. Mode defines (`ECB/CBC/CTR 1`) never become `mode`; key-size defines never become `key_size`.

---

## F. OPENSSL FALSE-POSITIVE TRACE

Pipeline per example: raw evidence → normalized → usage → finding → risk → migration.

- `EVP_PKEY_decrypt(...)` — raw: `ossl-evp-pkey-encrypt` regex hit → normalized `canonical=RSA op=ENCRYPT conf=0.80` (`api_knowledge.py:121-124`) → usage `Probable/Confirmed` by confidence → finding `RSA` → risk full Mosca (Q=1.0) → migration `RSA-ENC→ML-KEM-768`. Wrong when keytype is EC/X25519 or op is sign/verify: regex conflates all five ops to RSA/ENCRYPT. Correct stage to fix: `api_knowledge.py:121-124` + `c_parser.resolve_entry` (needs keytype/param tracing).
- `EVP_PKEY_derive(...)` — raw: `ossl-evp-pkey-derive` + `ossl-ecdh` both `canonical=ECDH` (`:117-120,141-144`) → finding `ECDH` → risk Q=1.0 → migration `ECDH→X25519+ML-KEM`. Wrong for DH/X25519/RSA-KEM (generic KDF op). Fix stage: same registry rows.
- `DSA_generate_key(...)` definition — raw: `ossl-* DSA_*` call-site extracted with `function=DSA_generate_key` attribution; def itself not evidence, but call inside def body counted as direct usage → `Confirmed` → finding → risk → migration `DSA→RSA-SIG→ML-DSA` (`recommend.py:281` legacy mirror). Fix stage: `operations.build_operations` group key includes `function` but does not demote def-body to IMPLEMENTED.
- `EVP_add_cipher(EVP_aes_128_ecb())` — raw: `_evp_ctor_rows` + `ossl-evp-enc-init` (`cipher_arg:1` → `EVP_CIPHER_TABLE` → `AES-128-ECB`) with subsumption dedupe (`scanner.py:451-468`) → asset `AES-128-ECB` + op `ENCRYPT` → risk Q includes ECB floor 0.45 → migration `AES-ECB→AES-256-GCM`. Registration (capability advertisement) counted as active use; correct would be REGISTERED/ENABLED, not INVOKED/CONFIRMED.
- Test cert/key files (`test/*.pem`, `*_test.c`) — raw: `certificate/pem_scanner.py:104-110 CONFIRMED 0.9` asset + `to_operation()` when `operation_type` set; source test calls with conf ≥0.8 bypass `_test_suppressed` (`operations.py:385-393`) → findings `Possible/Confirmed` → risk full → migration per cert canonical (often `RSA-SIG` default). Fix stage: scope model + `cert==operation` split + `synthesize_asset_only_findings` policy.
- `EVP_rc4()` — missing from `EVP_CIPHER_TABLE` (`api_knowledge.py:38-64`) → falls to `canonical=OpenSSL Probable` (S011 post-mortem `benchmarks/reports/analysis.md:23`); RC4 missed, OpenSSL capability polluted.
- `OpenSSL → TLS 1.3` — pure `OpenSSL` canonical (`api.py:208 conf=0.40→ProvidedOnly`) has no `_rule_key` branch → `REVIEW`. TLS text appears only when op carries TLS token (`TLS-OLD→TLS1.3`). UI grouping by `library:openssl` graph node makes protocol advice look like library advice. Cross-family examples: `SHA256withRSA→RSA-SIG`, `TLS1.2+CBC→TLS-OLD`, `DSA→RSA-SIG`, `PBKDF2` unconditional.

---

## G. TEST / EVALUATION COVERAGE GAPS

Exact files:

- Source/wrapper/const: `ecdat/tests/test_source_semantics.py` (phase-4 P/R, wrapper `:155`, strings-vs-calls `:179`), `test_scanners.py:73,78,152`, fixtures `source/c_openssl_evp.c:12,18`, `c_wrappers_const.c:3-6`, `c_noise.c:3`, `ground_truth.json`.
- Duplicates: `ecdat/tests/test_correlation.py` (11 proximity cases), `test_fusion_operations.py:51-76` (12→2), `test_edge_cases.py:45`, `tests/test_benchmark_accuracy.py:46`.
- Strings/comments/test-only: `test_source_semantics.py:179`, fixtures `false_positives.py`, `syntax_error.py`, `S003_strings_only`, `FP001_adversarial_names/main.c:12`, `test_fusion_operations.py:110`.
- Flags/config: `test_config_edge_cases.py:63,75`, `test_phase5_artifacts.py:22` (CMakeLists), `test_runtime_cloud_paths.py`, `test_runtime_mocked.py:19,55,72`.
- Secrets/vectors, assets/ops: `test_core.py:45`, `test_edge_cases.py:259`, `test_integration.py:115`, `test_phase5_artifacts.py:290`; `test_fusion_operations.py` + `adapters/normalize.py`.
- Migration: `tests/test_risk_recommend.py:170`, `ecdat/tests/test_risk_context.py:147`, `tests/contract/test_core_contract.py`, `test_export_conformance.py`, `test_exports.py:240`.
- Full inventory: `ecdat/tests/` (22 files incl. `test_binary_stages.py:144,190-193`, `test_inventory.py`, `test_orchestrator.py:152`, `test_container_*.py`, `test_certificate_edge_cases.py`) + `tests/` (22 files incl. `test_benchmark*.py ×10`, `test_cli.py:129`, `test_scan_specialized.py:111,190,284`, `test_repository_analysis_boundaries.py`, `test_real_benchmark.py:71-84`).

Major missing:

- No `EVP_PKEY_decrypt/derive` ambiguity test; no `EVP_rc4` unknown-cipher test; no cross-file wrapper negative; no `#ifdef/-D/disabled-cipher` test; no supported-vs-enabled config test; no scheduler timeout/retry/cancellation test; no cache-invalidation-on-tool-change test; no perf regression gate (only `BENCHMARK_RESULTS_PASS3.md` analysis).

---

## H. PERFORMANCE CONSTRAINTS (do not optimize yet)

- Stages with progress: `normalize(5)→plan(10)→inventory(18)→triage(24)→availability(30)→discovery(40)→normalize_cir(60)→validate(68)→enrich(78)→validate_canonical(90)→complete(100)` (`orchestrator.py:835-1186`); `elapsed_sec` in `diagnostics:1180` + `aggregate.py:161,609,709`.
- Concurrency: ThreadPool per-family + per-target; no multiprocessing; deterministic resort (`discovery.py:148-206`); `scheduler.py:409-424` (max8), `api.py:498-507` (max4).
- Hotspots: source regex × rows × callsites (`compiled=[(row,re)]` per file `scanner.py:406`); `mask_source` O(n) char loop; chunked `blake2s` + archive re-feed; `reconstruct_cir` O(groups×evidence) + graph wire.
- Caches: `SourceScanner._file_cache` write-only never read (`scanner.py:181,252,394`); `ScanCache` hit ~1.09× in-mem only; `cached_availability` lru unused.
- Measured (`BENCHMARK_RESULTS_PASS3.md`, Win11/py3.13, 60s/1GB cap): source ~100k LOC 41.2s/166MB (~2.0k LOC/s, max 116k LOC/475f 57.6s/197MB); binary 1000×10KB 57.8s/194MB (17.3 f/s); dependency 4000f 52.6s/208MB (76 f/s); config 10k f 59.5s/222MB (168 f/s); cert 20k 58.3s/118MB (343 f/s); container BLOCKED (no Docker); full 150k LOC/300f 51.3s/248MB. Harness `ecdat/benchmarks/harness.py:36-83`. Improved detectors must stay within 60s wall, ~200–250MB, per-file 2MB cap, archive depth/files/bytes/ratio caps (`inventory.py:46`), subprocess timeouts (capa/floss 300s, semgrep 5/300s, jks 30s).

---

## I. CHANGE SURFACE (likely files/functions — no implementation proposed)

- Knowledge: `ecdat/core/signature_registry.json` + `ecdat/core/registry.py`, `ecdat/core/p2_signature_registry.json` + `ecdat/core/signature_registry.py`, `ecdat/scanners/source/api_knowledge.py:patterns_for/_evp_ctor_rows/EVP_CIPHER_TABLE/CURVE_ALIASES`, `ecdat/scanners/binary/crypto_signatures.py:CRYPTO_SYMBOLS/STRINGS/LIBRARIES/CONSTANTS/OIDS`, `ecdat/scanners/binary/yara_scanner.py:YARA_RULES`, `ecdat/scanners/dependency/crypto_packages.py`, `ecdat/scanners/config/*_scanner.py`, `ecdat/core/api.py:_PATTERNS`.
- Source engine: `ecdat/scanners/source/scanner.py:_scan_brace_file/_build_finding/find_wrappers/_merge_semgrep/_looks_like_declaration/CryptoASTVisitor`, `ecdat/scanners/source/c_parser.py:mask_source/extract_calls/collect_constants/resolve_entry/resolve_arg/classify_source_file/find_wrappers`, `ecdat/scanners/source/semgrep_scanner.py:SEMGREP_RULES`, `ecdat/scanners/source/python_ast.py`.
- CIR/evidence: `ecdat/core/cir.schema.json`, `ecdat/core/cir_models.py:new_asset_id/new_operation_id/EvidenceSignal/Location/Implementation/Context/RiskInputs`, `ecdat/core/models.py`, `ecdat/scanners/base.py:to_asset/to_operation/normalize_finding`, `ecdat/scanners/discovery.py:_correlate_findings/_merge_findings/_emit_cir`.
- Fusion/correlation: `ecdat/core/operations.py:group_key_for/dedup_key_for/build_operations/_hit_for_operation/_test_suppressed/_is_test_path/reconstruct_cir`, `ecdat/core/fusion.py:weighted_fusion/decide_usage/DETECTOR_RELIABILITY/DIRECT_SIGNAL_TYPES`, `ecdat/core/graph.py:wire_system_links`, `ecdat/adapters/normalize.py:normalize_cir/synthesize_asset_only_findings`.
- Scope/build: `ecdat/scanners/path_policy.py`, `ecdat/core/inventory.py:classify_bytes/CATEGORY_TO_SURFACE/safe_extract_archive`, `ecdat/core/scheduler.py:triage/triage_artifact`, `ecdat/scanners/dependency/scanner.py`, `ecdat/scanners/config/scanner.py`.
- Risk: `ecdat/core/risk.py:score_operation/score_cir/quantum_vuln/_usage_state/_exposure_weight/_criticality_weight/_mosca_inputs/_class_for/to_cir_risk`, `ecdat/adapters/risk_view.py:summarize_wire_risks`, `ecdat/core/api.py:enrich_cir/to_canonical/_severity_for/_rule_id_for/_human_title`.
- Migration: `ecdat/core/recommend.py:_rule_key/recommend_for_operation/recommend_cir/to_cir_recommendation/RECOMMENDATIONS/_BLOCKERS`, `ecdat/adapters/migration_adapter.py:build_real_items/to_real_plan`, `ecdat/reports/aggregate.py:_finding_groups/_crypto_inventory/_migration_groups/_dedupe_migration/build_report`.
- Scheduling: `ecdat/core/orchestrator.py:ScanOrchestrator.scan/plan/_inventory_for_request/_escalation_for`, `ecdat/core/scheduler.py:AdaptiveScheduler/InputRegistry/ScanCache`, `ecdat/adapters/scanner_policy.py:resolve_scanners`, `ecdat/web/server.py:_profile_scanners`, `ecdat/scanners/discovery.py:DiscoveryEngine`.

---

## J. IMPORTANT CODE SNIPPETS

```python
# source/scanner.py:427 — C detection gate (name must match allowlist row)
if not rx.search(site.name + "("): continue
# ... resolve_entry + _build_finding(tool="source:api-call") else no finding
```

```python
# c_parser.py:1-13 — no whole-program analysis by design
"""stdlib masking tokenizer + balanced-paren ... No whole-program analysis"""
```

```python
# api_knowledge.py:117-124 — generic-API hardcode (FP source)
{"id":"ossl-evp-pkey-derive","re":r"\bEVP_PKEY_derive(_init|_set_peer)?\b","canonical":"ECDH"},
{"id":"ossl-evp-pkey-encrypt","re":r"\bEVP_PKEY_(encrypt|decrypt|sign|verify|verify_recover)\b","canonical":"RSA","op":"ENCRYPT"},
```

```python
# c_parser.py:466-469 — unresolved cipher fallback
canonical="OpenSSL", conf<=0.70, detail="cipher unresolved"
```

```python
# fusion.py:104-115,176-216 — confidence + usage decision
raw=0.5+0.25*direct+0.10*param+0.08*binary+0.07*agreement-0.35*dependency_penalty
if is_test_fixture or is_checksum_only: return FalsePositiveSuppressed
if dependency_only: return ProvidedOnly
if conf>=0.85 and has_direct: return Confirmed
if conf>=0.65: return Probable
return Possible
```

```python
# operations.py:385-393 — test suppression needs weak evidence
return _is_test_path(path) and _direct_best(evidence)<0.8
```

```python
# operations.py:168-195 — correlation key (drops library/api/line/snippet)
(op|canonical|key_size|mode|curve|file|function|service|endpoint)[+|provided-only]
```

```python
# risk.py:545,570-574 — score + ProvidedOnly cap
score=clamp(.35*Q+.20*E+.15*B+.15*C+.15*mosca_boost)
if ProvidedOnly and (score>0.39 or klass not in (Low,Informational)): score=min(score,0.39)
```

```python
# recommend.py:239-290 — order-dependent substring cascade (ignores operation_type/library)
if RSA in text: return RSA-SIG if SIGN|VERIFY|CERT|X.509 in text else RSA-ENC
if X.509/CERT: return ECDSA if ECDSA|EC- else RSA-SIG
if TLS and (CBC|RC4|DES): return TLS-OLD
if TLS: return CLASSICAL-OK
```

```python
# crypto_signatures.py:341-358 — only structural fingerprints (binary-only)
CRYPTO_CONSTANTS={"637c777bf26b6f":"AES","52096ad53036a5":"AES","6a09e667bb67ae":"SHA-256",...}
```

```python
# api.py:589-602 — severity from usage+risk
if ProvidedOnly/Suppressed: return info
if Possible: return low
if Probable: return medium
if Confirmed and risk_class==Critical: return critical else high
```
