# ECDAT — Cryptographic Discovery, Inventory, Analysis & Migration-Readiness Platform
### Complete Technical Whitepaper (Notion-ready, SIH 2026 Appendix)

> Copy-paste this entire file into Notion. All headings, tables and code blocks are Notion-compatible. Source: repo `D:\Coding\Websites\ECDAT`, verified from code + `ARCHITECTURE.md` + `BENCHMARKS.md` + `ECDAT_CRYPTO_AUDIT.md`.
> One-line pitch: **ECDAT finds every crypto use across 8 surfaces, fuses evidence into verified operations, scores quantum risk (Mosca), and plans PQC migration — one deterministic pipeline for CLI + GUI + CI.**

---

## 1. Executive Summary

**Problem:** Quantum computers break RSA / DSA / DH / ECDH / ECDSA / Ed25519. Enterprises don't know where crypto lives — scattered in source, deps, binaries, containers, configs, certs, runtime TLS, cloud KMS. Classical misuse (ECB, MD5, SHA-1, static keys, weak RNG) compounds it. NIST PQC standards (FIPS 203 ML-KEM, 204 ML-DSA, 205 SLH-DSA, 2024) require migration, but there is no inventory to plan from.

**Solution — ECDAT:** Single production pipeline:

```
GUI → ecdat/web/server.py → ScanRequest → ScanOrchestrator.scan()
CLI → ecdat/commands/_real_scan.py → RealCoreClient → ScanRequest → ScanOrchestrator.scan()
```

Single-pass real analysis: `DiscoveryEngine` scans once → CIR v0.1 validation → fusion / operations / graph / risk / recommendations → canonical v1 + CIR sidecar → SQLite (`scans` + `scan_meta`) → CLI / GUI / reports / exports / CI. No mock mode. Failures are loud, never silent.

**Key results (measured 2026-09-23, Win11 / Py3.13.3):**

- Committed synthetic suite: **46/46 pass, algo P 0.8718 / R 1.0 / F1 0.9315, 0 FN**
- Real-repo eval (5 repos, 81 annotated ops): **P 100% / R 97.5% / F1 98.8%, 0 FP**
- Unit suite: **390 passed, 0 failed in ~30s**
- Cold scan 1-4 files: 584–1614 ms; cache hit 5–15 ms (~50-100x); GUI payload 11.5 ms
- 8 scanner families, CIR + CBOM + SARIF + HTML/PDF/CSV/JSON exports, SQLite persistence, React dashboard, full CLI + CI gate

**Honest limits:** P1 Mosca + recommendations only; no persistent migration state, no owners/timelines/sequencing, Azure/GCP stubs, no guaranteed Docker, single annotator eval, modest detector quality on un-reviewed regions. See §30-31.

---

## 2. Complete Architecture

**Repo map:**

```
ecdat/
  cli.py, acquisition.py
  core/ — models, CIR, orchestrator, validation, risk, fusion, graph, recommend, inventory, scheduler, ops, misuse, evidence, scope, cache, timing, api, client, registry
  scanners/ — base, discovery, path_policy, semantics
    source/ — Python AST, C parser, facts+resolver, api_knowledge (~400 rows), fingerprints, semgrep (optional)
    dependency/ — requirements, package.json, cargo, go.mod, pom.xml, SBOM, syft/cdxgen
    binary/ — stages, strings, lief, yara, crypto_signatures
    container/ — docker-save/OCI/rootfs, syft, daemon, trivy, dockerfile
    config/ — nginx, apache, openssl, envoy, k8s, terraform, dockerfile, generic
    certificate/ — pem, der, jwk, pkcs12, jks, ssh
    runtime/ — tls (live handshake), ssh
    cloud/ — aws (kms, acm, elb/alb); azure/gcp = stubs returning []
  store/ — db.py (SQLite WAL SCHEMA v3), scans.py, findings.py, repository.py
  reports/ — aggregate.py, console, markdown, html, pdf (stdlib canvas)
  exports/ — cbom.py (CycloneDX 1.6), sarif.py (2.1.0), csv_gen.py
  adapters/ — pipeline, normalize, scanner_policy, graph_adapter, risk_view, migration_adapter
  commands/ — scan, scan_binary, scan_container, scan_cloud, ci, list, show, risk, recommend, export, report, gui, _real_scan.py
  web/server.py — loopback ThreadingHTTPServer
  benchmark/, benchmarks/, benchmark_wrapper.py
frontend/src/ — App.tsx (~2500 lines, tab SPA), CryptoGraph.tsx (821 lines) + graph/* + __tests__
tests/ + tests/contract/ + tests/fixtures/ + ecdat/tests/ (22+22 files)
benchmarks/ (46-fixture) + ECDAT_Benchmark_Suite/ (runner, repo_runner, metrics, ground_truth, manifest.yaml, S001-S035/D01-D10/FP001 + R01-R12)
```

**12-stage orchestrated scan (`ecdat/core/orchestrator.py:813 ScanOrchestrator.scan()`):**

| # | Stage | Code | Action |
|---|---|---|---|
| 1 | normalize | `:824`, `scanner_policy.resolve_scanners` | Resolve scanners; refuse pull without allow_pull; refuse missing path |
| 2 | plan | `InputRegistry.normalize`, `AdaptiveScheduler.route` | ScanJob kind ∈ repo/file/binary/container_tar/rootfs/endpoint/cloud; PROFILE_EFFORT quick/standard/deep |
| 3 | inventory | `inventory.py:466 inventory_target()` | Magic-first classify, safe zip/tar expand (MAX_DEPTH 5, 512 MB), ArtifactRecord |
| 4 | triage | `_surfaces_for:520`, `_permissions_required_for:536` | Artifacts → surfaces; opt-in perms |
| 5 | cache-check | `_cache_key_for:553`, `ScanCache.get` | Key = input + scanner vers + registry + risk/rec + config + schema |
| 6 | availability | `DiscoveryEngine.availability():98` | Report missing semgrep/syft/trivy/docker/keytool/ssh — never zero-fill |
| 7 | discovery | `DiscoveryEngine.scan_and_emit_cir:1008` | ThreadPool per family, correlate + merge |
| 8 | normalize_cir | `adapters/normalize.normalize_cir:93` | Attach scan context, derive files, synthesize asset-only |
| 9 | validate_cir | `cir_validate.py:27 validate_cir` | Draft202012Validator(cir.schema.json) |
| 10 | enrich | `api.enrich_cir:539` → risk + recommend + graph | score_cir + recommend_cir + build_graph |
| 11 | validate_canonical | `validate.py:40` | jsonschema canonical_v1.json SCHEMA 1.0 |
| 12 | persist | `_real_scan.py:30` → `store/persist.store_scan_result` | Idempotent; --replace overwrites; --output/--cir-out |

Progress events: normalize(5)→plan(10)→inventory(18)→triage(24)→availability(30)→discovery(40)→normalize_cir(60)→validate(68)→enrich(78)→validate_canonical(90)→complete(100). `elapsed_sec` in diagnostics.

---

## 3. Discovery Engine

File: `ecdat/scanners/discovery.py:58 DiscoveryEngine`

- `__init__(enabled_scanners)`, `availability():98`, `scan():139`, `scan_and_emit_cir():320`, `_emit_cir():346`, `_correlate_findings():208`, `_merge_findings():276`
- ThreadPool per family (sorted `:195`), `is_available + scan` → `_last_status:114`
- `normalize_finding (base.py)` → correlate `(file,canonical) + ≤5-line merge` → merge (winner location/impl/context/function, concat evidence, max conf)
- `_emit_cir`: `ScannerFinding.to_asset:48 / to_operation:86` via `cir_models.new_asset_id:202 / new_operation_id:223`, `_add_asset_to_graph:389`, `_add_operation_to_graph:411`, `_get_tool_versions:429`
- Then `core/operations.py:reconstruct_cir():543` (`_hit_for_operation:443` + `build_operations:207` + `fusion.weighted_fusion/decide_usage:104/176` + asset regroup + `core/graph.py:wire_system_links():768`)
- `factories:71` hardcoded; `ScannerRegistry` registered but never read; `create_discovery_engine():443`, `get_available_scanners:92` unused in prod
- Path filter: `scanners/path_policy.py:iter_project_files:34`, `is_ignored_path`
- Scan-plan selection: `web/server.py:_profile_scanners():227` (DEFAULT_SCANNERS else explicit), `adapters/scanner_policy.py:resolve_scanners():46` (strict allowlist), `ScanPermissions:198`, `ScanRequest:338`, `PROFILE_EFFORT:155` (quick depth2 no-escalation, standard depth3 escalation, deep depth5), `SURFACE_OWNER:177`

---

## 4. Each Scanner Individually (8 families)

| Family | File | Default? | Signal strength |
|---|---|---|---|
| source | `scanners/source/scanner.py:192` | Yes | Direct API calls 0.9 Confirmed |
| dependency | `scanners/dependency/scanner.py:55` | Yes | ProvidedOnly 0.075 asset-only |
| binary | `scanners/binary/scanner.py:45` | Yes | strings 0.35 < symbols 0.5 < constants/OID 0.6 < capa 0.75 < LIEF 0.55-0.9 |
| config | `scanners/config/scanner.py:40` | Yes | Regex + parser, service-scoped |
| certificate | `scanners/certificate/scanner.py:35` | Yes | Real parse via `cryptography` lib, 0.9 Confirmed |
| container | `scanners/container/scanner.py:312` | Opt-in pull/build | Delegates to backends + inner scans |
| cloud | `scanners/cloud/scanner.py:40` | Opt-in | AWS only; Azure/GCP [] |
| runtime | `scanners/runtime/scanner.py:41` | Opt-in | Live TLS/SSH probes 0.92 |

---

## 5. Scanner Implementation Details

### 5.1 Source — `scanners/source/scanner.py:182 SourceScanner`

- **Python AST** `CryptoASTVisitor:678-1030`, `visit_Call:1040` + `PYTHON_CRYPTO_PATTERNS` exact-match (`hashlib.`, `hmac.`, `Crypto.`, `cryptography.`). PyCryptodome `AES.new(key, AES.MODE_ECB)` resolves modes from dotted/bare/alias/`mode=` keywords (`_constructor_mode`, `_MODED_CIPHERS`; canonical embeds mode `AES-ECB`). Module constant collection in `_collect_imports` (R2 ECB fix). Binding aliases + cipher/mode class defs → ProvidedOnly via allowlists (R3/P4).
- **Facts + resolver:** `facts.py:260 extract_facts_python` (AST `_PythonFactVisitor:125`), `:271 extract_facts_brace`; `resolver.py:151 resolve_value` (assignment index, const prop), `:294 resolve_algorithm`, `:306 resolve_curve`, `:328 resolve_key_size`, `:355 resolve_mode` (+ dotted `_dotted_mode`), `:398 expand_wrapper` (repo wrappers → invocations).
- **C parser** `c_parser.py`: `mask_source:66` (strip comments/strings, blank `#if 0`), `extract_calls:282` (`_CALL_RE:54`) with brace-depth spans (`_function_spans`, K&R fix, Go receivers), `collect_constants:357` (+ Java strings), `_first_string` (never call-expr; R3/P1), `resolve_entry:491` (+ ossl-pkey-type, cipher-encflag, digest-arg, JCA `or canonical` fallback; R3/P2-P3), `_name_to_canonical:685`, Java enum resolution.
- **API knowledge** `api_knowledge.py:101 API_PATTERNS[~400 rows]` `{call,re,langs,canonical,cipher_arg,op}` incl. OpenSSL EVP `_evp_ctor_rows:506`, `EVP_CIPHER_TABLE`, `CURVE_ALIASES`; `compile_matchers:762`, `build_exact_index:723`, `lex_prefilter:843`. R3: JCA BCrypt/SecureRandom/SecretKeySpec (P1); DigestSign/Verify×Init/Final×one-shot, FinalXOF, PKEY_new_raw, CipherInit (P2); use_certificate/PrivateKey→X.509, X509_digest, tmp_dh→DH, curves→ECDH, echstore→TLS (P3).
- **Java wrapper attribution (R3/P1):** delegate table (`_stash_delegates`), cross-file post-pass (qualified/capitalized only, def-line skips), cipher field flows (factory + init + doFinal terminal), same-file hardening (declaration skips, overload-arity).
- **Fingerprints** `fingerprints.py:234 analyze_file` — hex-int tables, array blocks, 256-u8 S-box `_has_256_u8_table:176`, strong constants `_strong_constants:187` (AES S-box / SHA-256 K / MD5 / ChaCha sigma), def-cluster.
- **Semgrep (optional)** `semgrep_scanner.py:387` (`scan:432`, subprocess `--json`). Usually unavailable → no-op. Merged `source/scanner.py:614-647`.
- Output: `ScannerFinding(canonical, ~0.9, tool=source:api-call/signal=call)` + `source:wrapper-call` (Probable 0.70, one-hop).

### 5.2 Dependency — `scanners/dependency/scanner.py:40`

Manifest parsing + exact package lookup in `crypto_packages.py:142 CRYPTO_PACKAGES / capabilities_for` (+ `SYFT_CRYPTO_PACKAGES`). No crypto regex. Parsers: requirements:180, pyproject:225, poetry.lock:273, package.json:312, package-lock:368, yarn:406, pnpm:445, cargo.lock:525, go.mod:564, pom.xml:607, gradle:651, gemfile:690, composer:730, cmake:826, conan:873, vcpkg:916, meson:937, autotools:956, SBOM cyclonedx_json:1038/xml:1072/spdx_json:1104, syft:1158/cdxgen:1208, python imports:1242, `_scan_cargo_toml` ([dependencies]/dev/build/target/workspace; 18 Rust crates ring/aes-gcm/ed25519-dalek/sha2; R2 fix). Always `dependency_only=True, ProvidedOnly, exposure=internal`.

### 5.3 Binary — `scanners/binary/scanner.py:19` (cheap-always, expensive-gated)

Stages `binary/stages.py`: `detect_format:135` (ELF/MZ/Mach-O), `file_entropy:152` (Shannon 256KB), `match_constants:172` (CRYPTO_CONSTANTS:341 AES S-box/SHA-256 K/ChaCha sigma `637c777b→AES`), `match_oids:184` (CRYPTO_OIDS:361 DER+dotted), `match_symbol_strings:202` (CRYPTO_SYMBOLS), `analyze_cheap:237→CheapSignals:48`, `decide_escalation:328` (constants/OIDs→capa/floss), `run_capa:384`, `run_floss:451`, `expensive_tool_status:221`. Sub-scanners: `strings_scanner.py:13` (ASCII min4, `_match_crypto_string:131`), `lief_scanner.py:12`, `yara_scanner.py:472` (yara/yara-x subprocess, nocase 0.5-0.75), `is_plausible_crypto_string` guard (drops `Destination`, PE TLS structs; hello-world PE 57→0 FP).

### 5.4 Container — `scanners/container/scanner.py:181`

No crypto regex; delegates + layer untar + Dockerfile/Compose parse. `scan:312` routes image-ref vs docker-save.tar (`_scan_docker_save:461`) vs OCI (`_scan_oci_layout:520`) vs rootfs (`_scan_rootfs:600`); `_scan_layer_bytes:579`, sqlite layer cache `_get_cached_layer:215` (per-layer sha256, never first-only). Backends `_scan_with_syft:712`, `_scan_with_daemon:722`, `_scan_with_trivy_fs:732`. `DockerScanner._scan_dockerfile:398 / _scan_docker_compose:428`. Inner findings use `image:<ref>/layer:<digest>/<rel>` URIs + `image=/layer=/service=` notes.

### 5.5 Config — `scanners/config/scanner.py:18` (fan-out)

Per-service `can_scan_file+scan+_scan_file+_analyze_ciphers/_parse_cipher/_is_insecure_cipher`: nginx (`ssl_ciphers:18`, `ssl_protocols:19`, SSLv2/3/TLS1.0→TLS-OLD), apache, openssl (`Min/MaxProtocol:17-18`, CipherSuites/Ciphers/Options, `_parse_tls13_cipher:231`), envoy (TlsParameters:110), k8s (Secret/Ingress/Workload), terraform (resource, tls versions, ssl_policy, cipher_suites, tfstate:113), dockerfile (FROM/COPY/EXPOSE, `_CERT_COPY_RE:54`), generic (JSON/YAML/TOML walk, keyword-boundary `_token:209`, `_guess_canonical:214`), dockerfile_scanner (FROM/RUN/COPY, always ProvidedOnly). Post: `service_context.py:211 attach_service_context` (listen/server_name/VirtualHost/ARN/KMS).

### 5.6 Certificate — `scanners/certificate/scanner.py:15` (fan-out)

`cryptography`-lib parsing (not regex). pem:23 (cert:89/csr:155/private:207/public:256; `_map_signature_algorithm:325`), der:22, jwk:12 (`_parse_jwk:59`, kty/crv→Ed25519/X25519/ECDSA/RSA), pkcs12:11 (+openssl fallback), jks:11 (keytool), ssh:12. `cert_metadata.py:30 sha256_fingerprint_hex`, `:40 openssh_fingerprint`, `:49 public_jwk_view` (JWK private leak fixed; fingerprints for config↔cert linkage).

### 5.7 Runtime — `scanners/runtime/scanner.py:25` (opt-in only)

`_parse_target:62` host:port. TLS `tls_scanner.py:29`: `ssl.create_default_context(verify=CERT_NONE):80` + `socket.create_connection:84` + `cipher()/version()/getpeercert():87` → `TLSResult:16`; `_create_findings:150` (negotiated `_parse_cipher:241` CHACHA20/AES-GCM/ECDHE_RSA/DHE_RSA + `_is_insecure_cipher:283`; cert sig/key/curve), leaf SHA256 fingerprint + `probed_at` + tool/version notes. SSH `ssh_scanner.py:13`: `ssh-keyscan -T:65` → parse → host-key fingerprints, INTERNET_FACING.

### 5.8 Cloud — `scanners/cloud/scanner.py:12` (opt-in, AWS only)

SDK inventory (no regex). `aws_scanner.py:11` via `boto3.Session:29` (keys/profile/env, never logged): `_scan_kms:99` (list+describe → `_map_kms_key_spec:275`, `_get_kms_key_size:293`), `_scan_acm:143`, `_scan_elb:182`, `_scan_alb:223` (+ service=/listener=/cert_ref=/ssl_policy= linkage). Label `aws:profile:services=kms,acm,elb` (`_parse_cloud_services:121`). Azure/GCP stubs `is_available False`, `scan []` — no fabricated findings.

---

## 6. CIR Schema (Cryptographic Inventory Representation)

Files: `ecdat/core/cir.schema.json:1-295`, `ecdat/core/cir_models.py:16-235`

```json
CryptoAsset{asset_id ast:hex16, canonical, original, key_size?, mode?, curve?, protocol?, library?, usage_state:[Confirmed,Probable,Possible,ProvidedOnly,FalsePositiveSuppressed], confidence:0-1, evidence:EvidenceSignal[], location:Location{file?,line?,column?,function?,uri?}, implementation:Implementation{library,version?,provider?,api?}, context:Context{exposure,environment?,data_classification?,notes?}, risk_inputs:RiskInputs{usage_state,exposure?,sensitive_data?,external_dependency?}}
CryptoOperation{operation_id op:hex16, operation_type:[Encrypt,Decrypt,Sign,Verify,KeyExchange,Hash,KDF,TLS,Storage,KeyManagement], asset_id, confidence, evidence, function?, +location/implementation/context/risk_inputs}
EvidenceSignal{tool, detail, confidence?, snippet? (redacted)}
Graph{Node{id,kind:[asset,operation,file,service,host,library,key]}, Edge{from,to,relationship:[uses,calls,contains,derives,protects,depends_on,terminates]}}
Stats, CIRDocument{scan_id, target, timestamps, stats}
```

Legacy pre-CIR `core/models.py:13-88 Finding{rule_id,title,severity,file,line,snippet,confidence,metadata}`.

Deterministic IDs (6 places — cir_models:202/223, api:57/64, discovery:49, operations:596, scheduler:85, scan_cache:62, inventory:108):

```python
asset_id = "ast:" + sha256("canonical|key_size|mode|curve|protocol|file|line")[:16]
op_id = "op:" + sha256("opType|asset_id|function|file|line")[:16]
```

First-class: primitive/canonical, original, mode, key_size, curve/protocol, operation, API (`implementation.api`), evidence, location, usage_state, confidence, asset linkage, dependency→ProvidedOnly. Missing as first-class: `scope` (smuggled in `context.notes service=` + graph svc- bit), evidence-type taxonomy (collapsed to `tool:` prefix), impl-vs-invoke (only tool prefix + provider/api), build state (only is_test_fixture/is_checksum_only + packed/stripped), configured-vs-supported.

---

## 7. Normalization

`ecdat/adapters/normalize.py:93 normalize_cir()`

- Overwrites scan_id/target/timestamps/stats; `EvidenceSignal.redact_snippet` replaces PEM/key with `[REDACTED]`
- `files_from_cir:78`, `synthesize_asset_only_findings:128` (dependency ProvidedOnly preserved as asset-only, capped)
- `core/cir_validate.py:27 validate_cir()` (Draft202012Validator), `core/validate.py:40 validate()` (canonical_v1.json SCHEMA 1.0)
- `core/api.py:208 normalize_algorithm` passthrough; `_apply_scan_context:589` merges ScanContext (environment/owner/exposure/criticality/X/Y/Z)
- Early collapse points: `base.py:49-58 to_asset()` (same tuple merges), `discovery.py:276-318 _merge_findings` (winner keeps location, loser file/line/API dropped pre-CIR), `operations.py:706-801 reconstruct_cir` regroup `(canonical,key_size,mode,curve,protocol,file)` collapses line/function/service (new ast: IDs, graph rebuilt minimal + wire_system_links)

---

## 8. Evidence Fusion

`ecdat/core/fusion.py:104 weighted_fusion`, `ecdat/core/operations.py:316 build_operations`, `:549 build_semantic_operations`, `semantic_ops.py:125`

```
raw = 0.5 + 0.25*direct_usage + 0.10*param + 0.08*binary + 0.07*agreement - 0.35*dependency_penalty
confidence = clamp(raw * reliability_mean, 0, 1)
```

- Inputs: `evidence[{detector, signal_type, confidence}]`, flags param_resolved / binary_support / config_runtime_agreement / dependency_only
- Direct iff `signal_type ∈ DIRECT_SIGNAL_TYPES` + substring direct/call/dataflow (`_is_direct:94`)
- `deduplicate:219` exact dedup_key, keep max-conf (tie smallest id); `redact_snippet:289`
- Operations collapse: raw hits → sorted CryptoOperation dicts + dedup_key/id/confidence/usage_state/semantic_state. Keys `group_key_for:246`, `dedup_key_for:273` (`canonical|op|file|line|ProvidedOnly-suffix`), `_tool_signal:602` (source:api-call→(source,call), binary-lief→(lief,binary-import)…), `_direct_best:643`, `_test_suppressed:662`, `_merge_evidence:688`. ProvidedOnly cap 0.35 (`_PROVIDED_ONLY_CAP:72`). 12 mentions → 2 ops measured (one per function, 6-signal provenance each).

---

## 9. Confidence Model

- `reliability_mean` from `DETECTOR_RELIABILITY:27`: source 0.92, runtime 0.92, sslyze 0.92, semgrep 0.9, tree-sitter 0.88, config/certificate/secret/gitleaks 0.85, lief 0.85, binary/capa 0.8, cloud/yara-x 0.75, default 0.7, strings/syft/container 0.6, dependency/dockerfile/bom 0.5
- Direct observation is a floor (never fused below observed direct conf; dep/test caps dominate) — `operations.py` Phase 8 fix
- Micro: `weighted_fusion` 0.0116 ms (p95 0.0166), `new_asset_id` 0.0053 ms, `build_operations` 20 hits 1.14 ms (~0.057/hit)
- Bands: ≥0.85+direct Confirmed; ≥0.65 Probable; else Possible; ProvidedOnly ≤0.35; Suppressed 0. See §10.

---

## 10. Usage-State Classification

`fusion.py:176 decide_usage()`:

```python
if is_test_fixture or is_checksum_only: return FalsePositiveSuppressed
if dependency_only: return ProvidedOnly
if conf>=0.85 and has_direct: return Confirmed
if conf>=0.65: return Probable
return Possible
```

- Suppression requires test-path AND weak direct evidence (<0.8) — `operations.py:385-393 _test_suppressed`, `_is_test_path`. Strong direct call in `test.py` stays Confirmed.
- ProvidedOnly never merges with use (`reconstruct_cir`).
- `evidence.py:188 classify_evidence(tool→EvidenceClass:26)` ordered needle match (`_INVOCATION_NEEDLES:73`, `_BINARY_NEEDLES:93`); unknown → REFERENCE. `:294 semantic_state_for(usage+classes→SemanticState:40)`.
- `scope.py:261 classify_scope(path,language,build)`, `:350 classify_build_state` — path-part heuristics (`_path_hint:174`).
- Severity mapping `api.py:589-602`: ProvidedOnly/Suppressed→info; Possible→low; Probable→medium; Confirmed+Critical→critical else high.

---

## 11. Crypto Operation Reconstruction

`operations.py:316 build_operations`, `:460 _correlate_semantic`, `:549 build_semantic_operations`, `:820 reconstruct_cir`, `semantic_ops.py:125 build_semantic_operation`, `:281 semantic_identity_key`, `:329 _merge_semantic_ops`, `:372 correlate_operations`, `_infer_primitive:74`

- Adapts CIR ops+assets to raw-hit dicts (detector/signal/location/parameters/confidence/usage/context per evidence via tool→(detector,signal) taxonomy; param/binary/agreement/dependency/test flags), collapses with `build_operations` (ProvidedOnly never merges), rewrites ops (merged provenance, fused conf, adjudicated usage on floored score, stable semantic IDs), regroups assets by (canonical,params,file), preserves asset-only, rebuilds graph, returns validated CIRDocument.
- Group key 9-tuple drops library/version/provider/api/line/column/uri/snippet/confidence/tool — deliberate file-scoped grouping (no cross-file merges; Phase 9 graph work covers cross-surface).
- Config+runtime agreement: config claim also observed live gets agreement bonus.
- Fusion failures degrade to raw CIR with warning, never failed scan.

---

## 12. Crypto Graph

`ecdat/core/graph.py:179 build_graph(ops,assets,contexts)` → `{nodes,edges}`; `to_cir_graph:447`; `GraphIndex:554` (neighbors:607, risky_nodes:612, internet_facing:632, blast_radius:658, trace:688); `wire_system_links:768`. Node types `NODE_TYPES:67`, relations `RELATIONS:72`; linear passes, slug IDs `_slug:110`.

- Kinds: asset, operation, file, service, host, library, key. Relationships: uses, calls, contains, derives, protects, depends_on, terminates.
- Frontend `CryptoGraph.tsx` (821 lines) ReactFlow+ELK: Model/Views/SecurityMap/Layout/Labels/Focus/Edges/Components + 8 test files. Backend `adapters/graph_adapter.py:55 adapt_cir_graph()`.
- Micro: 20 ops/10 assets 0.88 ms (~0.044/op). Graph edges always resolve (asserted).
- Join keys enabling edges: `service=/listener=/endpoint=/cert_ref=/key_ref=/kms_ref=/image=/layer=` (config/service_context, container URIs, AWS linkage, cert fingerprints).

---

## 13. Misuse Engine (12 rules)

`ecdat/core/misuse.py:489 check_operation`, `:479 check_rule`, `MISUSE_RULES:34` via `_rule:19`. Each `_check_*:230-441` does substring/regex on `op+params+blob` (`_text_blob:196`). 0.0933 ms/op.

| Rule | Title | Severity |
|---|---|---|
| STATIC_KEY | Static/hardcoded key | High |
| PREDICTABLE_KEY | Predictable key source (time/pid/user/counter) | High |
| STATIC_IV_NONCE | Static/reused IV/nonce (CBC/CTR/GCM/ChaCha) | High |
| ECB_MODE | ECB for multi-block/structured plaintext | High |
| WEAK_RNG | rand()/random/Math.random for secrets | High |
| CERT_VALIDATION_DISABLED | Trust-all / verify off | High |
| SMALL_KEY | e.g. RSA <2048, EC <224 | Medium/High |
| DEPRECATED_ALGO | MD5/SHA-1/DES/RC4/3DES | Medium/High |
| WEAK_KDF | Few iterations / unsalted | Medium |
| MISSING_AUTH | Encrypt without MAC/AEAD | Medium |
| PASSWORD_AS_KEY | Password directly as key | High |
| UNSAFE_SIG_HASH | e.g. SHA256withRSA flagged for PQ review / weak hash sig | Medium |

Refs: FIPS 800-38A, 800-131A-r2, RFC 9325, NCCoE PQC.

---

## 14. Risk Engine

`ecdat/core/risk.py:495 score_operation`, `:663 score_cir`, `:684 to_cir_risk`; API `api.py:510 risk(cir,Z)`, `:539 enrich_cir`, `:589 _severity_for`, `:637 _rule_id_for`; view `adapters/risk_view.py:31 summarize_wire_risks` (verbatim top wire risk).

---

## 15. Exact Risk Formula / Rules

```text
score = clamp(0.35*Q + 0.20*E + 0.15*B + 0.15*C + 0.15*mosca_boost)  # 3 decimals
mosca_trigger(X,Y,Z) = (X + Y > Z)
wire score = round(score * 10, 2)   # 0..1 → 0..10
Classes: ≥0.8 Critical, ≥0.6 High, ≥0.4 Medium, ≥0.2 Low, else Informational
ProvidedOnly caps ≤0.39 (score=min(score,0.39) :578); Suppressed → 0.0 Informational
```

- `Q=QUANTUM_VULN:65`: RSA/DSA/DH/ECDH/ECDSA/X25519/X448/Ed25519/Ed448/ELGAMAL=1.0, HYBRID=0.35, ML-KEM/ML-DSA/SLH-DSA/FN-DSA/HQC=0.0, AES=0.15 (0.30 if key<256), CHACHA20 0.10, POLY1305/HMAC/SHA-2/HKDF 0.05, SHA-3/BLAKE 0.03, MD5 0.60, SHA-1 0.50, DES 0.70, 3DES 0.50, RC4 0.70, BLOWFISH 0.35, AES-ECB 0.45, TLS-OLD 0.60, TLS12 0.30, TLS13 0.10, PBKDF2-WEAK 0.30, PBKDF2 0.10, BCRYPT/SCRYPT/ARGON2 0.05, X.509 0.90, UNKNOWN 0.50 (`quantum_vuln:221`)
- Classical-weakness floor folded into Q (`_CLASSICAL_FLOOR`: MD5/SHA-1/DES/3DES/RC4/BLOWFISH/AES-ECB/TLS-OLD/TLS12/PBKDF2-WEAK/X.509) — documented per entry, surfaced in explanation
- `E=EXPOSURE_W:120` (internet-facing > cloud > third-party > internal > offline), `B=CRIT_W:128`, `C=USAGE_CONFIDENCE:135` averaged with fused confidence (`_confidence:403`), `mosca_boost ∈ {0,1}` from `_mosca_inputs:412` (X=data-lifetime, Y=migration-years, Z default 10)
- Helpers `_risk_inputs:326`, `_exposure_weight:338`, `_criticality_weight:362`, `_usage_state:393`, `_class_for:483`, `_merge_asset_view:640`
- V2 split: `assess_classical_posture:757`, `assess_misuse_severity:817`, `assess_protocol_posture:848`, `assess_quantum_exposure:879` (`0.7*q+0.3*trigger:901`, deployment `(E+B)/2:923`), `score_operation_v2:948`
- Micro: `score_operation` 0.1134 ms. Example: AES-ECB Confirmed → Medium 4.39; SHA-256 Confirmed → Low 0.299 wire.

---

## 16. Mosca Implementation

`risk.py:216 mosca_trigger`, `:412 _mosca_inputs`

- Inputs: X=data-lifetime (years, `--data-lifetime`), Y=migration-years (`--migration-years`), Z=risk horizon (`--risk-z` default 10, `ScanContext:230` + `cache_seed:257`)
- Trigger `X+Y>Z` → `mosca_boost=1.0` (+0.15 to score) + explanation string + urgency flag
- `assess_quantum_exposure:879` = `0.7*q+0.3*trigger`, deployment `(E+B)/2`
- P1 Mosca posture powers dashboard risk cards, CI `ci_cmd.py:_posture:48`, migration priority. Deterministic, stdlib-only, O(n).

---

## 17. Recommendation Engine

`ecdat/core/recommend.py:343 recommend_for_operation`, `:434 recommend_cir`, `:480 to_cir_recommendation`; helpers `_priority_for:332`, `_asset_ids_of:404`, `_pqc_target_for:466`, `pqc_target_for_operation:581`, `recommend_for_operation_v2:617`; planning `adapters/migration_adapter.py:98 build_real_items`, `:192 to_real_plan`; views `reports/aggregate.py:_migration_groups:613`

```text
replacement_score = .35*risk_reduction + .20*standards + .15*compat + .10*latency + .10*effort + .10*cost  (:10,:323)
sort = PRIORITY_ORDER(Critical0…Informational4):42, then score desc, then op_id (:461)
```

- Choice always registry-driven; risk only sets priority. LLM may rephrase `reason`, never change target.
- 0.0326 ms/op. Migration items ~1 ms for 3 items (incl. estimate/grouping aids R2).

---

## 18. NIST Rule Mappings

Registry `RECOMMENDATIONS:76` refs: FIPS 203/204/205, NCCoE `migration-to-pqc`, SP 1800-38, OQS liboqs.

| Rule key | Targets | Pattern | Effort |
|---|---|---|---|
| RSA-ENC | ML-KEM-768 (hybrid X25519+ML-KEM) | hybrid-kem | M |
| RSA-SIG | ML-DSA-65 (alt SLH-DSA-128s) | sig-replace | L |
| DH / ECDH | hybrid X25519+ML-KEM-768 (TLS1.3 KEM) | hybrid-kex | M |
| ECDSA / EDDSA | ML-DSA-65 (alt SLH-DSA-128s) | sig-replace | L/M |
| TLS-OLD | TLS 1.3 (AEAD, modern groups, PQ-hybrid-ready) | protocol-upgrade | S |
| AES-ECB | AES-256-GCM | mode-upgrade | S |
| MD5/SHA-1 | SHA-256/384, SHA-3 | hash-upgrade | S |
| DES/RC4/3DES | AES-256-GCM / ChaCha20-Poly1305 | cipher-replace | S |
| PBKDF2-WEAK | Argon2id / scrypt / bcrypt (high iter) | kdf-harden | S |
| X.509/RSA-cert | ML-DSA PKI / hybrid certs | cert-migrate | L |

`_rule_key:239-290` order-dependent substring cascade (ignores operation_type/library — known weakness §31, causes SHA256withRSA→RSA-SIG, TLS+CBC→TLS-OLD; fix surface listed in audit §I).
Planning aids (backend-only): `estimate_days {min,max}` + `estimate_basis` (P1 S/M/L × file fan-out capped ×3 + blockers + hybrid widening, cap 40d), `app_group_for` (top-two path segments), `to_real_plan` envelope with `summarize_app_groups` (triage grouping, never sequence). Forbidden keys (timeline/sequencing/state/owner) absent by contract.

---

## 19. ML-KEM / ML-DSA / SLH-DSA

- Q=0.0 (safe) in `QUANTUM_VULN`; refs `_FIPS203` ML-KEM, `_FIPS204` ML-DSA, `_FIPS205` SLH-DSA
- RSA-ENC → ML-KEM-768 hybrid (X25519+ML-KEM during transition); RSA-SIG/ECDSA/EdDSA → ML-DSA-65 primary, SLH-DSA-128s conservative/hash-based profile (PKI/tooling blocker noted; signature size/verify cost tracked)
- ECDH/DH → hybrid X25519+ML-KEM-768 TLS1.3 KEM; HYBRID residual Q 0.35
- Detection: PQC names in registry + `pqc_map` preferred for `pqc_target` (`to_cir_recommendation`); detectors surface ML-KEM/DSA/SLH-DSA as Q0 Informational (no migration).

---

## 20. CBOM

`ecdat/exports/cbom.py:80 to_cbom_json`, `:91 to_cbom_xml` (CycloneDX 1.6, 1 component+vuln per finding, `_bom_ref:20`)

- Canonical → CBOM components (asset inventory flat view in GUI = CBOM-derived assets)
- Companion: `exports/sarif.py:25 to_sarif` (SARIF 2.1.0, LEVELS:9 critical/high→error, medium→warning, low/info→note), `exports/csv_gen.py:21 to_csv`
- BOM import (Phase 5): CycloneDX JSON/XML + SPDX JSON/tag-value → ProvidedOnly inventory evidence (unknown components silent); syft/cdxgen hooks (binary-gated, bounded timeouts)
- Dashboard serves CBOM/CIR/JSON/SARIF/CSV/HTML/PDF downloads.

---

## 21. Reports / Exports

`reports/aggregate.py:747 build_report(doc,real_risk,recs,cir,coverage,plan)` → `{executive_summary:714, operations_summary:167, crypto_inventory:394, finding_groups:322, affected_components:507, coverage_summary:548, migration_groups:613, methodology:687}` + views (`inventory_view:915`, `findings_view:985`, `migration_view:1036`, `evidence_view:1086`, `risk_details_view:1118`, `coverage_view:1145`, `coverage_payload:116`; `_unified_severity:74`, `_scrub_snippet:99` 500ch). Renderers `console.py:23`, `markdown.py:17`, `html.py:63`, `pdf.py:702` (`ReportBuilder:218`, stdlib Canvas:90). `Handler._report:504` maps fmt→renderer. CLI `report` (markdown/console/html/pdf), `export` (json/csv/cbom-json/cbom-xml/sarif).

---

## 22. SQLite

`store/db.py:69 connect`, `:92 init_schema`, `:110 open_db`, `SCHEMA_VERSION=3`, WAL. DDL `:30`: `scans(id,target,started_at,finished_at,raw_json,cir_json,created_at)`, `findings(id,scan_id,rule_id,severity,file,line,title,confidence)` + `idx_findings_scan_severity`, `scan_meta(scan_id,plan_json,diagnostics_json)` (mig v2:+cir_json, v3:+scan_meta). CRUD `scans.py:30 insert_scan`, `:56 get_scan`, `:62 get_scan_doc`, `:70 get_scan_cir`, `:84 list_scans`, `:94 delete_scan`; `findings.py:22 insert_finding`, `:45 insert_findings_for_scan`, `:69 list_findings`, `:85 count_findings`; `repository.py:67 ScanRepository{save_scan:94, get_payload:122, list_scans:139}` (+replace=True GUI overwrite); idempotent CLI/CI via `persist.py:store_scan_result` (reuse-on-duplicate, --replace overwrite). Default DB `~/.ecdat/ecdat.db`; `--db` shares CLI+GUI. Plan `{job_id,kind,label,content_hash,profile,permissions,scanners,stages,escalate,artifacts_total,counts,surfaces,effort}`; diagnostics `{elapsed_sec,cache_hit,cache_key,scanner_status,tool_versions,registry_version,binary_stages/tools,escalation,surfaces,unavailable}`.

---

## 23. API / Backend

`ecdat/web/server.py` loopback ThreadingHTTPServer (`do_GET:472`, `do_POST:589`).

- `Handler._upload:567` stream Content-Length → `STATE.inputs/<id>/`; `_inspect_input:588` (`inventory.safe_extract_archive:332`, `_inspect:139` → `inventory_target:466` + `path_policy.iter_project_files:34` + `_architecture:124`); `_scan_plan:605` (`_profile_scanners:227` → ScanRequest → `get_orchestrator().plan().as_dict():629`); `_start_job:631` (+ context/risk_z → STATE.jobs → Thread `_run_job:661`); `_run_job:310` (input_for, _ScanContext, ScanRequest caller=gui:353 → `get_orchestrator().scan(progress=_on_progress):371` → `result.as_tuple()` → `_result_payload(cir,canonical,plan,diagnostics):373` → `ScanRepository.save_scan(replace=True):378`)
- GET `/api/health:439`, `/api/scanner-capabilities:442`, `/api/jobs/:446`, `/api/scans:454`, `/api/results/:id:463` (memory else get_payload:122 → _result_payload:478), `/api/results/:id/report/:fmt:493` → `_report:504`
- `_result_payload:265` = `adapt_cir_graph + summarize_wire_risks + build_real_items + coverage_payload + _limitations_from + build_report`
- `_safe_extract_zip:87/_safe_extract_tar:102` (20k members, 250MB); workspaces cleaned on exit; non-loopback --host refused; --port 0 ephemeral.

---

## 24. Frontend

`frontend/src` React+Vite, single SPA no router, tabs [Overview, Findings, Crypto Inventory, Crypto Graph, Migration, Coverage] `App.tsx:88-95`.

| Step | Component | API |
|---|---|---|
| Hero/nav | App:616-653 | — |
| Upload (drag/drop, ZIP/TAR, allowlist .py/.js/.c/.pem/.exe) | App:659-749, InputSummary:1354-1377, upload():396-436 | POST /api/uploads |
| Inspect | App:424-428 | POST /api/inputs/inspect |
| Demo | App:709-748, useDemo():480-497 | GET /api/demos, POST /api/demos/select |
| GitHub (OAuth+public+private) | App:751-880, GithubProjectStatus:1379-1432 | POST /api/github/public, /repos/select, GET .../oauth/* |
| Config (AUTO_LOCAL source,dependency,binary,config,certificate:100-106; opt-in container/runtime/cloud; manual override:500-506; profile standard:509) | App:883-1015, scanBody():499-534 | POST /api/scan-plan, POST /api/scan-jobs |
| Progress (poll 700ms:551-561) | App:1026-1044 | GET /api/jobs/:id |
| Results (Risk/Findings/Assets/Ops cards; GroupedFindings; Inventory; CryptoGraph ReactFlow+ELK; Migration; Coverage; downloads) | App:563-585,1091-1143, CryptoGraph.tsx | GET /api/results/:id, GET .../report/:fmt |
| Cloud modal (AWS only; Azure/GCP coming soon) | CloudConfigModal:1167-1352 | body.cloudConfig:515-532 |
| Helper | api(url,init) App:108-125 | GET /api/health, /scanner-capabilities, /demos, /scans, DELETE /api/inputs/:id |

Dashboard workflow: Repository input (URL/upload/demo) → plan+monitor → inventory/findings (usage, evidence, confidence, redacted snippets) → risk dashboard (Mosca) → asset inventory (CBOM) → knowledge graph (CIR) → migration planner (P1 recs + estimate/grouping; no persistent state) → reports downloads.

---

## 25. CLI

Dispatcher `cli.py:58 build_parser` (prog=ecdat). Shared `_context_options:17` (--environment/--owner/--exposure/--business-criticality/--data-lifetime/--migration-years/--risk-z=10), `_common_scan_options:38` (--db ~/.ecdat/ecdat.db, --output, --scanners, --allow-container/cloud/runtime, --cir-out, --replace, --profile quick/standard/deep=standard). Re-scan reuses stored row (exit 0 same ID); --replace overwrites.

| Command | Handler |
|---|---|
| `scan [path] [--repo URL]` | commands/scan_cmd.py:13 → _real_scan:30 |
| `scan-binary <binary>` | scan_binary_cmd.py:13 |
| `scan-container <image_or_path> [--allow-pull/--allow-build]` | scan_container_cmd.py:12 |
| `scan-cloud aws [--profile AWS][--services kms,acm,elb][--region][--aws-*-key]` | scan_cloud_cmd.py:19, build_target_label:12 |
| `list [--limit=100][--json]` | list_cmd.py:19 |
| `show <scan_id> [--json]` | show_cmd.py:21 |
| `risk <scan_id> [--json]` | risk_cmd.py:22 |
| `recommend <scan_id> [--json][--severity]` | recommend_cmd.py:15 |
| `export <scan_id> [--format json/csv/cbom-json/cbom-xml/sarif]` | export_cmd.py:46 |
| `report <scan_id> [--format markdown/console/html/pdf]` | report_cmd.py:43 |
| `gui [--host=127.0.0.1 --port=8734 --db]` | gui_cmd.py:15 → web/server.py:966 |
| `ci <target> [--fail-on][--summary][--json][--sarif]` | ci_cmd.py:128 (evaluate:33, rank:26, posture:48) |

CI examples in README:70-95 (local dir, --repo, binary, container tar/image-ref, cloud, scanner subset, opt-ins, `ci --fail-on high` gate).

---

## 26. Complete E2E Pipeline (worked example: 2-file repo app.py + requirements.txt)

Total 487–738 ms cold. Plan: kind=repo, scanners=[source,dependency,binary,config,certificate], stages=[semgrep,tree-sitter,gitleaks], artifacts_total=2 (source:1, dependency:1), escalate=False. Output: 2 findings (SHA-256 Confirmed 0.92 risk Low 0.299; `cryptography` ProvidedOnly 0.075 asset-only), 2 assets, 1 op. Post-discovery: summarize_wire_risks 0.02 ms + build_real_items ~1.0 ms + _result_payload 11.53 ms. Discovery+inventory ≈95%+ latency; risk/rec/graph/report ~12 ms; cache hit skips discovery (5–15 ms).

---

## 27. Benchmark Suite

- Harness `ecdat/benchmarks/harness.py:36-83`, `benchmark_wrapper.py`, `benchmark/`; committed suite `benchmarks/reports/benchmark_test_suite.json` (46/46); full harness `ECDAT_Benchmark_Suite/benchmarks/runner.py`, `repo_runner`, `metrics`, `ground_truth`, `ecdat_adapter`, `manifest.yaml`
- Env: Win11/PowerShell5.1, Py3.13.3, `time.perf_counter()`, `tracemalloc`, subprocess wall-clock (startup 1.4–1.7 s). In-process `RealCoreClient(caller="bench").scan_result(target)`. Cache = second-scan in-mem hit. Profiles quick/standard/deep. Repro: `runner.py --mode fast`; `python -m pytest tests/ -q` (venv `.venv-p1/Scripts/python.exe`); `repo_eval/score.py`; `python -m ecdat.cli scan <dir> --db <db>`; `gui --port 0` + `npm run dev`.
- Perf harness `BENCHMARK_RESULTS_PASS3.md` (Win11/py3.13, 60s/1GB cap): source ~100k LOC 41.2s/166MB (~2.0k LOC/s, max 116k LOC/475f 57.6s/197MB); binary 1000×10KB 57.8s/194MB (17.3 f/s); dependency 4000f 52.6s/208MB (76 f/s); config 10k f 59.5s/222MB (168 f/s); cert 20k 58.3s/118MB (343 f/s); container BLOCKED (no Docker); full 150k LOC/300f 51.3s/248MB. Caps: per-file 2MB, archive depth/files/bytes/ratio (`inventory.py:46`), subprocess timeouts (capa/floss 300s, semgrep 5/300s, jks 30s).

---

## 28. Synthetic Oracle (46 fixtures S001-S035/D01-D10/FP001 + R01-R12)

- `profile=standard, scan_runtime_s=42.339, peak_memory_bytes=16877430 (~16.9MB), files_processed=59, source_loc=171, crypto_evidence_count=39`
- `synthetic_pass=46, synthetic_fail=0, false_positives=5, false_negatives=0`
- `algorithm{precision=0.8718, recall=1.0, f1=0.9315}`, `operation{same}`
- Baseline before optimisation (`benchmark_optimisation_report.md`): 38/46, P 0.7714/R 0.7941/F1 0.7826, 8 FN, ~82s → after 46/46, P 0.8718/R 1.0/F1 0.9315, 0 FN, ~42s (−49%), mem flat. Fixed: S011 EVP_rc4 table, S017 JCA initialize(1024), S021 X25519, S025 argon2, S026 nginx TLS, S033 terraform KMS, D09 EVP_CIPHER_fetch, FP001 #if 0. Companion `latest.json` (2026-09-19 fast): 38/46 (superseded).
- Stays byte-identical through recall program P1–P4 (R3); ops TP=34 FP=5 FN=0.

---

## 29. Adversarial Tests

- `FP001_adversarial_names/main.c:12`, `false_positives.py`, `syntax_error.py`, `S003_strings_only`, `test_source_semantics.py:179` (strings-vs-calls), `test_fusion_operations.py:110`, `config_edge_cases.py:63,75`, `edge_cases.py:45,259`, `test_benchmark_accuracy.py:46`, negative controls per cluster + express 0-findings control throughout.
- Guards: `mask_source` (comments/strings never match; suppressed hits counted), `_looks_like_declaration` (prototypes never fire, incl. multi-line), `_first_string` hardening (no call-expr), plausibility guard (57→0 on hello-world PE), overload-arity, delegate qualifier rules, enum-family grounding (fixed RsaRaw AES mislabel), definition/prototype def-line skips in both wrapper passes.

---

## 30. Real-World Repos (5 OSS, pinned SHAs, `repo_eval/` slices/outputs/EVAL-*.yaml/lockfile/score.py→REPORT.json/rescan.py)

- `openssl/openssl@15ed7c1e` (C: apps/enc.c+dgst.c), `pyca/cryptography@f717d797` (ciphers/{aead,algorithms,base,modes}.py), `nginx/nginx@ef0aa96` (ngx_event_openssl.c+nginx.conf), `spring-projects/spring-security@3d23cf3` (9 Java crypto files), `expressjs/express@9a34acf` (JS lib/*.js, negative control)
- GT 81 items (R3): init/update/final of one computation = one item; free/get0_*/plumbing/commented config excluded. Granularity: mutually exclusive branches feeding one var/ctx + fetch+init in one function = ONE item (matches op-group fusion). Match = same file ±15 lines (file-window for pyca), canonical size-insensitive (AES-256-CBC≡AES-CBC); dyn-tier location-only; many-to-many credit. FNs hunted via token sweeps (e.g. 172 APIs / 363 sites in nginx file), each judged by reading source. Precision judges every finding on slice.

---

## 31. Precision / Recall Results

| Repo | GT | Findings | TP | FP | FN | P | R | F1 |
|---|---|---|---|---|---|---|---|---|
| openssl (C EVP CLI) | 18 | 17 | 18 | 0 | 0 | 100% | 100% | 100% |
| pyca (Python defs/aliases) | 8 | 14 | 8 | 0 | 0 | 100% | 100% | 100% |
| nginx (C TLS 6.7k lines) | 24 | 22 | 23 | 0 | 1 | 100% | 95.8% | 97.9% |
| spring (Java JCA/BCrypt/PBKDF2) | 31 | 31 | 30 | 0 | 1 | 100% | 96.8% | 98.4% |
| express (control) | 0 | 0 | 0 | 0 | 0 | — | — | — |
| **Aggregate R3** | **81** | **84** | **79** | **0** | **2** | **100%** | **97.5%** | **98.8%** |
| Aggregate R2 baseline | 72 | 28 | 27 | 1 | 45 | 96.4% | 37.5% | 54.0% |

Honest read: 100% precision (every finding judged); 97.5% recall with 2 FNs as documented design boundaries: N21 (nginx DH fingerprint suppressed — fingerprint pass skips families already covered by direct `tmp_dh` finding; capability surfaced once) + S04 (AesBytes decrypt via enum-method dispatch `alg.createCipher()` — needs interprocedural enum-method knowledge, out of one-hop scope). Limits: single annotator, bounded slices (recall lower bound outside), ±15-line window, one snapshot (SHAs pinned). For claims quote R3, never synthetic 100% alone.

Recall program P1–P4 (fixture-first, gates: full suite + 46-fixture + negatives + re-scored eval):

| Cluster | Mechanism | TP/FP/FN → | P/R/F1 → | Tests |
|---|---|---|---|---|
| Baseline R2 | — | 27/1/45 | 96.4/37.5/54.0 | — |
| P1 Java (21 FN) | K&R/method spans; JCA BCrypt×2/SecureRandom/SecretKeySpec; enum+family; cross-file delegates; field-flow init/doFinal; def-line skips; overload-arity; _first_string harden | 58/2/24 | 96.7/70.7/81.7 | 9 |
| P2 OpenSSL (12 FN) | DigestSign/Verify×Init/Final×one-shot, FinalXOF, PKEY_new_raw+type table, CipherInit+enc-flag, _ex idiom | 67/3/15 | 95.7/81.7/88.2 | 10 |
| P3 TLS/cert (8 FN) | use_certificate/PrivateKey→X.509, X509_digest, tmp_dh→DH, curves→ECDH, echstore→TLS; GT aligned | 75/0/6 | 100/92.6/96.2 | 7 |
| P4 pyca (4 FN) | Binding-alias + class-def ProvidedOnly (exact allowlists) | 79/0/2 | 100/97.5/98.8 | 7 |

GT 72→82→81 (P1 +10 verified-true, P2/P3 op-group merges, +1 dispatch). Precision dip to 82% mid-P1 repaired via definition/prototype skips, arity, qualifier rules, _first_string, `or canonical` fallback, enum-family grounding.

---

## 32. Scanner-Level Results

- Committed `evaluation_results_summary.json` (older 47-fixture per-scanner cut, superseded by §28/31 — include for transparency, do not quote as current): Source P0.49/R0.45/F1 0.47 (28ms); PythonAST P0/R0 (legacy duplicate `python_ast.py` — wired class is `source/scanner.py:SourceScanner:177`); Dependency P1.0/R1.0; Config P0/R1.0 (over-counted FPs by substring); Certificate P0/R1.0 (same counting artefact); overall P0.14/R0.25 — counting method differs from R3 op-level eval; use §31 for product claims.
- Current per-scanner split (real targets): R-source source-only 631ms vs dep-only 481ms; R-core source-only 1355ms vs dep-only 801ms — source parsing dominates (~75–120 ms/file).
- Our 6 synthetic scenarios 6/6 after R2 (ECB FN fixed via constructor-mode resolution + dotted-constant, pinned `test_ecb_mode_fix.py`; Cargo exception fixed via `_scan_cargo_toml` + 18 crates, pinned `test_cargo_toml_fix.py`; TLS PROTOCOL_TLSv1 → TLS1-2 ProvidedOnly coarse mapping still open).

---

## 33. Performance

- Micro (means 50–2000 iters): weighted_fusion 0.0116ms, new_asset_id 0.0053ms, classify_bytes 0.0916ms, classify_evidence 0.0050ms, score_operation 0.1134ms, check_operation 0.0933ms, recommend 0.0326ms, build_operations 20 hits 1.14ms, build_graph 20ops 0.88ms. Analysis math sub-ms; cost is I/O+parsing+startup.
- E2E cold (in-process): S-empty 799ms/0 findings; S-single-aes 737ms/2; S-rsa-tls-misuse 705ms/3 (R2 296ms/4 with ECB fix); S-deps-only 584ms/3; S-config-cert 1442ms/4; S-polyglot 1614ms/3; R-ecdat-source (9py) 1083ms/2; R-ecdat-core (29py) 2234ms/14. Throughput R-core 13 files/s; 1-file overhead-dominated.
- Profiles (tiny repos, fresh tmp): quick ~212–300ms, standard cold 584–1614ms / repeat ~214–340ms, deep ~214–379ms — escalation gates matter only on binaries/containers.
- CLI wall-clock (subprocess): scan 2.2–2.5s, list/show/risk/recommend/export/report 1.4–1.9s (startup-dominated; in-process 3–4× faster). GUI backend 11.5ms total.

---

## 34. Caching

- `core/scheduler.py:366 ScanCache`, `core/scan_cache.py:83 parse_cache_key`, `:95 resolution_cache_key`, `:108 final_scan_cache_key(input+scanner_vers+registry+risk+rec+config+schema)`, `:141 ScanCacheV2{get:183,set:196,hit_rate:170}`, `:242 check_budget`, `:252 staged_escalation(cheap→parse→direct→dataflow→fingerprint)`
- Key = content hash (blake2s-16 `content_hash_for:90`, `inventory.py:108`) + registry + scanner set + profile + caller + risk/rec + schema. Hit returns stored ScanResult `cache_hit=True` (~5–15ms, 50–100× speedup). `SourceScanner._file_cache` write-only never read; `cached_availability` lru unused; tool-binary changes blind (known limit); `ScanCache` in-mem only (`hit ~1.09×`); container per-layer sha256 cache (mutation-tested, retarget-fixed).
- Hotspots: source regex×rows×callsites (compiled per file `:406`), `mask_source` O(n), chunked blake2s + archive re-feed, `reconstruct_cir` O(groups×evidence) + graph wire. Concurrency ThreadPool per-family + per-target (max8 scheduler:409, max4 api:498); deterministic resort; no multiprocessing.

---

## 35. Deterministic Tests

- `python -m pytest tests/ -q`: **390 passed, 0 failed in ~30s** (R3; was 327/9 in 41.69s). +54 tests since R2: ECB (9), Cargo (3), persistence reuse/replace (4), migration aids (7), P1 Java (9), P2 sign/verify (10), P3 TLS/cert (7), P4 pyca (7). Gates per cluster: full suite + 46-fixture + negatives + re-scored eval (366→376→383→390 all green).
- 9 fixed failures diagnosed (none hidden): test_path_independence×2 (helper replaced root after json.dumps — Windows backslash doubling; product IDs already identical; fixed strip pre-serialization), test_repo_acquisition×1 (str(path) vs POSIX; .as_posix()), reports goldens×6 (missing encoding=utf-8 cp1252 mojibake of ·; PDFs stale after 34aabe9 redesign, regenerated after verifying deterministic output).
- Contracts pinned `tests/contract/` + `docs/P1_P2_INTEGRATION_CONTRACT.md`. Deterministic `scan:<32hex>` IDs for identical inputs; RFC3339 timestamps; asset-only preserved; unavailable tools reported.

---

## 36. Known Failures (with traces)

- **tiny-AES-c miss (architectural):** source path requires CallSite.name ∈ `api_knowledge.py` C rows. Zero rows for AES_init_ctx/ECB/CBC/CTR/KeyExpansion/SubBytes/sbox/Rcon/TinyAES → zero findings; wrapper seeds empty; S-box bytes survive masking but never inspected (source has no equivalent of `binary/crypto_signatures.py:342-345`); semgrep no rule + unavailable; dep/config/binary silent → fusion never invoked. Needs new langs=(c,cpp) rows and/or source static-table heuristic. Trace: inventoried as source → aes.h header-capability (PROBABLE≤0.80, prototypes filtered) → mask preserves sbox/Rcon/defines but `collect_constants:297-312` only consumed for known-API args → extract_calls emit but `rx.search(name+"(")` gate `scanner.py:427` drops all → 0 ops.
- **OpenSSL FPs (hardcoded generic-API):** `EVP_PKEY_decrypt→RSA/ENCRYPT 0.80` (`api_knowledge:121-124`) wrong for EC/X25519/sign/verify; `EVP_PKEY_derive→ECDH` wrong for DH/X25519/RSA-KEM; `DSA_generate_key` def-body call counted as Confirmed use (needs IMPLEMENTED demotion); `EVP_add_cipher(EVP_aes_128_ecb())` registration counted as INVOKED (needs REGISTERED/ENABLED); test certs bypass `_test_suppressed` when conf≥0.8; `EVP_rc4` missing from `EVP_CIPHER_TABLE:38-64` → `OpenSSL Probable` fallback (S011 fixed); `OpenSSL→TLS1.3` is UI grouping by library node (pure OpenSSL→REVIEW; TLS text only when op carries TLS token).
- **Cargo.toml crash (fixed R2):** `DependencyScanner has no attribute _scan_cargo_toml` → real parser + 18 crates.
- **ECB FN (fixed R2):** `AES.new(…, AES.MODE_ECB)` → nothing → constructor-mode + dotted-constant resolution.
- **CI UNIQUE error (fixed R2):** re-scan → `UNIQUE constraint failed: scans.id` exit 1 → idempotent `persist.py` (reuse exit 0 same ID; --replace overwrite).

---

## 37. Weaknesses (ranked, audit §D)

1. Library-API-allowlist only → 100% FN on self-contained impls (tiny-AES-c). Architectural.
2. No usage/evidence ontology (REFERENCE/DECLARED/IMPLEMENTED/REGISTERED/INVOKED/CONFIRMED collapsed to tool prefix + conf + usage_state). Forces def==usage, registration==usage.
3. Generic-API hardcoded not dataflow (EVP_PKEY_*→RSA, derive→ECDH, EC_KEY→ECDSA). Systematic wrong-algorithm FPs.
4. No scope model (dir-name heuristics + test_best<0.8 gate leak test/demo/doc/cert into prod + risk).
5. No build/config semantics (#ifdef/-D/CMake-option/Meson/Bazel-select; find_package→capability regardless; every Min/MaxProtocol→CONFIRMED; supported≠enabled≠default conflated).
6. Correlation keys drop semantics (9-tuple + |provided-only + (file,canonical)+5-line pre-pass merge impl/header/wrapper/callsite/test/doc by proximity — OpenSSL/Node duplicates).
7. Migration _rule_key order-dependent substring cascade ignoring operation_type/library (SHA256withRSA→RSA-SIG, TLS+CBC→TLS-OLD, DSA→RSA-SIG, OPENSSL→REVIEW misread as OpenSSL→TLS1.3).
8. Risk scores unscoped evidence (all non-suppressed scored full Mosca with inferred X=5/Y=3/Z=10, E=internal, B=medium; test/impl-only with conf≥0.8 stays Confirmed → deployment severity).
9. Split-brain registries (P1 signature_registry.json vs P2 p2_signature_registry.json + api_knowledge EVP table + CRYPTO_SYMBOLS/STRINGS/CONSTANTS + CRYPTO_PACKAGES; risk own QUANTUM_VULN; weak/recommendation_rules unimported).
10. Scheduler/plan labels unconnected (route stages advisory; escalated hardcoded 0; write-only _file_cache; in-mem tool-blind ScanCache; no retries/deadlines; ~2k LOC/s, 60s wall, regex×rows×callsites hotspot, mask O(n), archive re-feed, reconstruct O(groups×evidence)).

---

## 38. Current Status

- P1 Mosca risk + recommendation engine (+ rough estimate ranges + code-boundary triage groups); deterministic IDs; RFC3339; asset-only preserved; unavailable tools reported, never zero-filled.
- Product intentionally incomplete: persistent migration state, owners/effort/timelines/sequencing, full Azure/GCP, guaranteed Docker, external baselines, full runtime probing, prod auth/remote deploy — out of scope or versioned-contract extensions.
- 390/0 tests, 46/46 fixtures, R3 P100/R97.5/F1 98.8 (81 ops). Measured detector quality on committed fixtures is modest — do not claim fixed P/R targets until independently reproduced on corrected ground truth (README honest limits).

---

## 39. Future Work

- Source: tiny-AES-style structural fingerprints in source (S-box/Rcon/hex-table heuristics), C `#include` resolution, one-hop→bounded multi-hop wrappers, cross-file tracking, `#ifdef/-D`/CMake-option evaluation, supported-vs-enabled-vs-default distinction, EVP keytype/param dataflow tracing (fix PKEY hardcode), JCA split-config linking (`initialize(2048)`).
- Model: full scope enum (production/library-impl/test/demo/doc/generated/build/dependency/binary/cert/unknown), evidence-type taxonomy (REFERENCE/DECLARED/IMPLEMENTED/REGISTERED/ENABLED/INVOKED/PROBABLE/CONFIRMED), impl-vs-invoke split, build-state field, configured-vs-supported.
- Correlation: semantic keys (retain library/api/line/snippet/tool), role-aware merge (impl/header/wrapper/callsite/test/doc), cross-file/cross-surface corroboration beyond co-located evidence.
- Risk/rec: scoped scoring (test/impl-only demotion), `_rule_key` operation_type/library-aware, single canonical knowledge API unifying registries.
- Platform: persistent migration state + mutation API/UI, waves/milestones view, full Azure/GCP, Docker-guaranteed CI, external baselines, expanded runtime probing, prod auth/remote deploy, perf regression gate, scheduler timeouts/retries/cancellation, cache invalidation on tool change, multiprocessing.
- Eval: multi-annotator, wider slices/snapshots, ±window sensitivity, independent reproduction.

---

## 40. Research Journey (Phases 1–13 + R2/R3)

Phase 1 One Orchestrator (convergence, ScanRequest/Plan/Result, 17 tests, 158 pass) → Phase 2 InputRegistry + Inventory (magic-first, safe_extract, blake2s-16, 9 tests, 177 pass) → Phase 3 Routing/Profiles/Cache/Permissions (PROFILE_EFFORT, auto local coverage, plan preview, cache hit, 10 tests) → Phase 4 Source Semantics C-first (~100-row api_knowledge, c_parser mask/calls/consts/wrappers, 8 tests, 30/30 P/R 1.0, 185 pass) → Phase 5 Deps/Config/Certs/Dockerfiles/BOM (CRYPTO_PACKAGES truth, service_context join keys, DockerfileScanner, cert_metadata fingerprints, JWK leak fix, 12 tests, 197 pass) → Phase 6 Binary Stages (CheapSignals, decide_escalation, plausibility 57→0, 16 tests, 213 pass) → Phase 7 Containers/Runtime/Cloud (unified dispatcher, per-layer cache, TLS fingerprints, Azure/GCP stub removal, AWS linkage, 17 tests, 230 pass) → Phase 8 Fusion/Reconstruction (DETECTOR_RELIABILITY calibration, reconstruct_cir, floor, 12→2 ops, 9 tests, 239 pass) → Phase 9 Graph/System reconstruction (build_graph, wire_system_links) → Phase 10 Risk/Recommend (Mosca, registry) → Phase 11 Store/Contracts → Phase 12 GUI/CLI convergence → Phase 13 Eval/Benchmarks. R2 fixes (ECB, Cargo, suite green 357/0, idempotent persist, R2 eval P96.4/R37.5) → R3 recall P1–P4 (Java/OpenSSL/TLS/pyca, 390/0, P100/R97.5/F1 98.8). Full log `docs/Implemented.md` + `ARCHITECTURE.md` + `BENCHMARKS.md` + `ECDAT_CRYPTO_AUDIT.md`.

---

## 41. References

- NIST FIPS 203 ML-KEM — https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204 ML-DSA — https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 205 SLH-DSA — https://csrc.nist.gov/pubs/fips/205/final
- NCCoE Migration to PQC — https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc
- SP 1800-38 Practice Guide — https://www.nccoe.nist.gov/publications/practice-guide/migration-post-quantum-cryptography-nist-sp-1800-38-practice-guide
- OQS liboqs — https://openquantumsafe.org/liboqs/
- FIPS SP 800-38A (modes) — https://csrc.nist.gov/pubs/sp/800/38/a/final
- SP 800-131A-r2 (key management) — https://csrc.nist.gov/pubs/sp/800/131/a/r2/final
- RFC 9325 (TLS recommendations) — https://www.rfc-editor.org/rfc/rfc9325.html
- Mosca (X+Y>Z) — quantum threat timeline model (risk.py:216)
- CycloneDX 1.6 CBOM — exports/cbom.py; SARIF 2.1.0 — exports/sarif.py
- CIR schema — ecdat/core/cir.schema.json; Canonical v1 — ecdat/core/canonical_v1.json
- SIH26164 Solution Architecture PDF — docs/SIH26164_ECDAT_Solution_Architecture.pdf (19pp)
- Roadmap — docs/ECDAT_CODEX_IMPLEMENTATION_ROADMAP.md; Contracts — docs/P1_P2_INTEGRATION_CONTRACT.md + tests/contract/
- Audits — ECDAT_CRYPTO_AUDIT.md, docs/ARCHITECTURE.md, docs/BENCHMARKS.md, docs/benchmark_optimisation_report.md, docs/GUI_CLI_ARCHITECTURE_AUDIT.md

---

*End of whitepaper. For SIH PPT: use §1 as slide 1–2, §2+§26 as architecture slide, §15–16 as risk slide, §31 as results slide, §36–38 as limitations/honesty slide.*
