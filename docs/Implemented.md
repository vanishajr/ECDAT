# Implemented — Phase 1: One Production `ScanOrchestrator`

> Phase 1 output record for the ECDAT architecture-convergence plan.
> Roadmap: `docs/ECDAT_CODEX_IMPLEMENTATION_ROADMAP.md` (Phase 1, plus §§0–2, 11.1, 14).
> Architecture: `docs/SIH26164_ECDAT_Solution_Architecture.pdf` (19 pages — read via `pypdf`;
> used for the orchestrator shape: Input registry → Adaptive scheduler → cheap-first staged
> scanners → CIR → graph → Mosca-style risk → deterministic PQC recommender → canonical result,
> with CLI/GUI calling the same core engine and the §11 data-model expectations for
> ScanRun/plan/permissions).

## Files changed (only these — other working-tree M/D entries were pre-existing, left untouched)

**New**

- `ecdat/core/orchestrator.py` — the single production pipeline owner: `RealScanError`,
  `ScanProfile` (`quick`/`standard`/`deep` + `normalize_profile`), `ScanPermissions`
  (allow_container/cloud/runtime + reserved allow_pull/build), `ScanRequest`,
  `ScanProgressEvent` (+ `ProgressCallback`), `ScanPlan`, `ScanResult`, `ScanOrchestrator`
  (`plan()`, `scan()`, `scan_with_cir()`), `get_orchestrator()`/`plan_scan()`/`run_scan()`,
  plus the target-kind helpers as single source of truth. `scan()` reuses `InputRegistry`,
  `AdaptiveScheduler.route()`, `scanner_policy`, `DiscoveryEngine` (execution utility only),
  `normalize_cir`, CIR + canonical validation, `api.enrich_cir`/`to_canonical`. Emits structured
  stages: normalize → plan → availability → discovery → normalize_cir → validate_cir →
  enrich → validate_canonical → complete.
- `ecdat/tests/test_orchestrator.py` — 17 regression tests proving convergence (see below).

**Rewired (thin wrappers, same behavior/signatures)**

- `ecdat/adapters/pipeline.py` — now delegates to `ScanOrchestrator`; re-exports `RealScanError`
  + target helpers (no second implementation). Adds optional `profile`/`caller`/`progress` kwargs.
- `ecdat/core/client.py` — `RealCoreClient` now builds a `ScanRequest` and delegates to the
  orchestrator; adds `profile`/`caller` (defaults `standard`/`client`).
- `ecdat/commands/_real_scan.py` — forwards `--profile`/`caller` into the client.
- `ecdat/commands/scan_cmd.py`, `scan_binary_cmd.py`, `scan_container_cmd.py`,
  `scan_cloud_cmd.py` — pass `caller=` hint (`cli-scan`, `cli-scan-binary`,
  `cli-scan-container`, `cli-scan-cloud`) with their existing scanner hints; same pipeline.
- `ecdat/commands/ci_cmd.py` — passes `region`/`profile`/`caller="ci"` through the same
  client→orchestrator path (gating logic untouched).
- `ecdat/web/server.py` — `_run_job` now calls `get_orchestrator().scan()` with a progress
  callback driving job `progress`/`stage`; `_start_job` stores `profile`. `run_real_scan`
  import removed (no GUI bypass).
- `ecdat/cli.py` — adds `--profile {quick,standard,deep}` (default `standard`) to `scan`,
  `scan-binary`, `scan-container`, and `ci` (+ `--region` for `ci`). `scan-cloud` keeps
  `--profile` as the AWS profile (collision avoided via `include_profile=False`; depth stays
  `standard`).

## Expected behaviour after Phase 1

```text
CLI ──→ RealCoreClient ──→ ScanOrchestrator ──→ shared stages
CI ───→ RealCoreClient ──→ ScanOrchestrator ──→ shared stages
GUI ──→ ScanOrchestrator ────────────────────→ shared stages
pipeline.run_real_scan() ──→ ScanOrchestrator (compat wrapper)
```

- Same target + scanners through any surface yields the same deterministic `scan_id`
  (verified: `scan` and `ci` on one file both returned `scan:99e5…`).
- `plan(request)` previews job/kind/scanners/stages/profile/permissions without scanning
  (GUI preview hook for Phase 3/12).
- Progress events are structured (`stage`, 0–100, message, detail) though still coarse —
  stage detail deepens in later phases.
- `DiscoveryEngine`, `InputRegistry`, `AdaptiveScheduler`, `ScanCache` are real runtime
  components of every scan; no alternate production pipeline remains.
- No behavior change to detection, validation, risk, or report content — pure orchestration
  migration.

## Tests / builds run (venv `.venv-p1`)

- `python -m ecdat.cli --help` — PASS.
- `ecdat/tests` full suite — **158 passed** (141 pre-existing + 17 new `test_orchestrator.py`),
  0 failures.
- CLI smoke — `scan --profile standard/deep`, `scan-binary`, `ci --profile quick`, `list` —
  all PASS; invalid `--profile bogus` rejected cleanly by argparse.
- `frontend`: `npm run build` (`tsc --noEmit && vite build`) — PASS (1869 modules, built in ~13s).
- `py_compile` on all touched files — PASS. Ruff unavailable in venv (not installed) — skipped.
- Stale `tests/test_real_integration.py + test_scan_specialized.py` — 36 failed / 30 passed,
  **identical to pre-change baseline** (they expect removed mock mode/`--real` flag/
  `ecdat.gui.server`; untouched per rule 11.1/§12, not deleted).

## Newly working capability

- One importable production entry point: `ScanOrchestrator.plan()` / `.scan()` with typed
  request/plan/result contracts.
- Proven GUI/CLI/CI convergence (monkeypatch tests: each surface triggers exactly one
  `ScanOrchestrator.scan`).
- Scan-depth `profile` plumbed end-to-end (recorded in plan/diagnostics; effort tiers deferred
  to Phase 3 as the roadmap requires).

## Known limitations / intentionally deferred (per roadmap)

- `quick`/`standard`/`deep` do not yet change analysis effort (Phase 3 task).
- `plan()` uses `AdaptiveScheduler.route()` job-level stages, not per-file inventory/triage/cache
  accounting (Phase 2/3).
- `ScanCache` is instantiated/shared but generic content-hash caching semantics activate in
  Phase 3.
- GUI still uses in-memory results (shared `ScanRepository` persistence is Phase 11); scanner
  checkboxes remain (UX overhaul is Phase 12).
- `scan-cloud` has no depth flag (AWS `--profile` collision); cloud depth stays `standard`.

## Phase 1 acceptance

- `CLI → GUI → CI ⇒ ScanOrchestrator ⇒ shared analysis stages` — MET (17/17 new tests + smoke).
- No active production surface has an independent scan implementation — MET (`run_real_scan`
  is a wrapper; server bypass removed).
- `python -m ecdat.cli --help` functional + frontend build passing — MET.
- No existing functionality removed; historical stale tests preserved — MET.

**Next phase (Phase 2) can safely start.**

---

# Phase 2 — InputRegistry, Full Inventory and Safe Recursive Artifact Discovery

> Roadmap: `docs/ECDAT_CODEX_IMPLEMENTATION_ROADMAP.md` (Phase 2, §§2, 11.1).
> Architecture: `docs/SIH26164_ECDAT_Solution_Architecture.pdf` (§6 stage 0 —
> "walk files … compute content hashes … creates a cache key for incremental
> and repeated scans"; Input registry — "normalizes repo, image, binary,
> directory, URL and cloud targets into scan jobs … hash every target").

## Files changed (Phase 2)

**New**

- `ecdat/core/inventory.py` — stdlib-only (`zipfile`, `tarfile`, `hashlib`,
  `mimetypes`) inventory engine: `ArtifactRecord` (relative path, absolute
  internal path, size, blake2s-16 content hash, extension, MIME, magic,
  executable format, language, category, archive/container metadata,
  candidate routes, cache state, skip reason), `classify_bytes()`
  (content/magic first — ELF/MZ/Mach-O, zip/gzip/tar magic, PEM markers,
  JKS magic — extension only as hint), `inventory_target()` (recursive walk
  reusing `scanners.path_policy.iter_project_files`, nested archives expanded
  and re-fed, duplicate-content suppression, deterministic sorted output),
  `safe_extract_archive()` (traversal/link/ratio/count/byte limits; every
  violation skipped with a recorded reason, never extracted unsafely),
  `summarize_inventory()` roll-up. No existing inventory existed, so a new
  module was justified; existing traversal/pruning was reused, not duplicated.

**Extended**

- `ecdat/core/scheduler.py` — additive `AdaptiveScheduler.triage_artifact()`
  bridge: an `ArtifactRecord`'s magic-based category wins when it maps to a
  real surface, otherwise falls back to `triage(path)` (path behavior
  untouched).
- `ecdat/core/orchestrator.py` — `ScanRequest` gains `display_name`
  (user-facing identity; canonical `target` and deterministic scan IDs
  unchanged) and `max_archive_depth`; `ScanPlan` gains `display_target`,
  `artifacts_total`, `artifact_counts`, `surfaces`, `skipped`, `warnings`.
  `plan()` and `scan()` run the real inventory (progress stages `inventory`
  → `triage`) and triage every record centrally; inventory errors degrade to
  the Phase 1 job-level route with a warning, never a failure.
- `ecdat/web/server.py` — `_inspect()` now returns the real inventory
  roll-up (`artifact_counts`, `surfaces`, `archives`, `skipped`,
  `inventory_truncated`, `display_name`) alongside all legacy keys;
  `_inspect_input()` single-archive extraction uses the hardened
  `safe_extract_archive` (one implementation). Upload and GitHub flows
  untouched.

## Expected behaviour after Phase 2

- Any local input is understood before analysis: an OpenSSL-style checkout
  (`evp_demo.c` + `requirements.txt` + `nginx.conf`, no scanner flags) plans
  as 3 artifacts across `source`/`dependency`/`config` surfaces automatically.
- Nested archives are discovered recursively (zip → tar → file, depth
  tracked with parent chains); traversal attacks, symlinks/hardlinks,
  oversized/ratio-violating members are skipped with explicit reasons.
- Content beats extension: extensionless ELF → `binary`, `.txt` holding a
  PEM block → `cert`, `.txt` holding ELF magic → `binary`.
- `/api/inputs/inspect` answers what the input *contains* (categories,
  surfaces, archives, skip reasons); `name`/`display_target` stay the
  user-supplied label, never a temp upload path.

## Tests (Phase 2)

- `ecdat/tests/test_inventory.py` — 9 tests: magic-over-extension,
  mixed-repo categories + nested depth-2 re-feed, traversal safety (nothing
  written outside), determinism, symlink skipping, ratio-limit skip,
  unsupported-format (7z) recorded, single-file/missing targets, summary
  shape. Three failures during development exposed real bugs (test-fixture
  duplicate content, symlink pre-filter hiding link reports, silent
  unsupported formats) — all fixed in the implementation, not the tests.

## Phase 2 acceptance

- Nested archives safely discoverable — MET (depth-tracked re-feed + limits).
- Binaries/certs/configs inside a mixed repo classified automatically — MET.
- Inventory deterministic — MET (sorted traversal/output, hashed content).
- Target hashing works — MET (blake2s-16 per artifact + job content hash).
- Temp upload paths not the primary user-facing identity — MET
  (`display_name`/`display_target` from input label).

---

# Phase 3 — Real Routing, Profiles, Cache, Permissions and Scan Planning

> Roadmap: `docs/ECDAT_CODEX_IMPLEMENTATION_ROADMAP.md` (Phase 3).
> Architecture: same PDF (Adaptive scheduler — "file triage, tool routing,
> cache, parallel workers, cheap-to-expensive escalation"; "cache by
> image/layer digest"; scan-plan preview — "shows detectors that will run,
> expected depth, … cache hits").

## Files changed (Phase 3)

**Extended**

- `ecdat/core/orchestrator.py`
  - `PROFILE_EFFORT` / `SURFACE_OWNER` tables: depth changes effort, never
    existence. quick = no escalation, archive depth 2, no expensive
    backends; standard = escalation recorded, depth 3, capa/FLOSS-selective
    expected; deep = escalation recorded, depth 5, capa/FLOSS/Ghidra-optional
    expected. Quick/Standard/Deep plans are observably different.
  - `ScanPlan` gains `effort`, `escalation_allowed`, `permissions_required`,
    `cache_hit`. `plan()` reports detected surfaces, scanners/tools,
    unavailable tools, escalation-capable stages, cache state, skip reasons,
    and permissions required (detected-but-unselected surfaces named
    explicitly, e.g. "`binary`: N artifact(s) detected but `binary` scanner
    not selected").
  - Generic `ScanCache` activated: key = content hash + registry version +
    scanner set + profile + caller; repeat scans return the stored result
    (cache-hit diagnostics refreshed honestly). Tool-binary changes do not
    invalidate the key — recorded below as a known limitation, not hidden.
  - `should_escalate()` now has a real production caller: every
    reconstructed operation with binary-surface evidence below confidence
    0.65 becomes a recorded escalation candidate
    (`diagnostics.escalation`). Expensive backends land in Phase 6, so
    `escalated` stays 0 with an explicit note.
  - `diagnostics` gains `scanner_status` (structured success/unavailable/
    failed per scanner), `permissions_required`, inventory summary,
    `cache_hit`/`cache_key`, `registry_version`, `display_target`.
- `ecdat/scanners/discovery.py` — additive `last_status()` + per-scanner
  outcome tracking (`success`/`unavailable`/`failed: …`/`not-run`) in both
  parallel and serial paths; findings behavior unchanged (unavailable
  scanners previously yielded `[]` via exception swallowing — same outcome,
  now honestly labeled).
- `ecdat/web/server.py`
  - `_profile_scanners()`: local/static coverage (source, dependencies,
    **binaries**, configs, certs/keys) is automatic for every profile —
    normal users no longer gate discovery with checkboxes. Explicit lists
    remain as the Advanced/debug override.
  - New `POST /api/scan-plan` preview endpoint (input → real `ScanPlan`,
    no scanning). `_run_job` forwards the input label as `display_name`.
  - `/api/scanner-capabilities` default list corrected to the auto-enabled
    local set.

## Expected behaviour after Phase 3

- Measured on a demo repo (`evp_demo.c` + `requirements.txt` + `nginx.conf`):
  quick/standard/deep plans report identical artifacts (3) and surfaces
  (`config`, `dependency`, `source`) but different effort
  (escalation False/True/True; archive depth 2/3/5); a repeat scan returns
  `cache_hit: True` with the same scan ID; `scanner_status` shows all five
  local families `success`.
- Binary analysis runs by default in GUI scans (previously omitted unless
  explicitly ticked); external actions (container pull/build, runtime
  probing, cloud APIs) remain permission-gated and are named in
  `permissions_required` when relevant artifacts go unscanned for lack of
  them.
- Scan-plan preview is available before any scan runs; live progress now
  flows through `normalize → plan → inventory → triage → availability →
  discovery → … → complete`.

## Tests (Phase 3)

- `ecdat/tests/test_scan_planning.py` — 10 tests: content-first triage
  bridge, plan inventory/surfaces, profile differences, display-name
  identity, permission-gap notes, cache miss→hit→profile-miss, diagnostics
  status/escalation shape, GUI auto-discovery defaults, inspect payload,
  plan-preview shape. One failure exposed a real bug (cache hits returned
  stale `cache_hit: False`) — fixed via `dataclasses.replace` on hits.

## Verification (Phases 2+3)

- `python -m ecdat.cli --help` — PASS.
- `ecdat/tests` full suite — **177 passed** (158 Phase 1 + 9 inventory +
  10 planning), 0 failures.
- CLI smoke (`scan --profile standard`, deterministic ID) — PASS.
- Stale `tests/test_real_integration.py + test_scan_specialized.py` —
  36 failed / 30 passed, **identical to the pre-change baseline**
  (mock-mode expectations; preserved, not deleted).
- `frontend` `npm run build` — PASS.
- Container layer cache (`ContainerScanner._layer_cache`): preserved as
  the layer-level cache; generic `ScanCache` follows the same
  content-hash-keyed philosophy. Full unification deferred to Phase 7 with
  the container inner-scanning work.

## Known limitations / deferred

- Tool-binary upgrades (LIEF/YARA/etc.) do not invalidate the generic cache
  key (versions observable only post-scan); registry/scanner/profile/caller
  changes invalidate exactly.
- `should_escalate` candidates are recorded, not executed (Phase 6).
- `scan-cloud` keeps `--profile` as the AWS profile (scan depth standard).
- Frontend still shows scanner checkboxes (UX overhaul is Phase 12);
  backend already ignores them for local coverage.

## Phase 3 acceptance

- `should_escalate()` has real production callers — MET.
- Quick/Standard/Deep produce observably different plans — MET.
- Binary auto-enabled; external actions permission-gated — MET.
- Scan-plan data visible to callers (`plan()`, `POST /api/scan-plan`) — MET.
- Repeat scans demonstrate cache hits — MET (measured same-ID hit).
- Scanner failures structured (success/unavailable/failed/skipped-reasons)
  — MET.

**Next phase (Phase 4) can safely start.**

---

# Phase 4 — Multi-Language Source Semantic Engine (C/C++ First)

> Roadmap: `docs/ECDAT_CODEX_IMPLEMENTATION_ROADMAP.md` (Phase 4, §§2, 11.1).
> Architecture: `docs/SIH26164_ECDAT_Solution_Architecture.pdf` (§3.1 source
> scanner — "CBOMkit/Sonar + Semgrep + Tree-sitter … AST/dataflow only on
> crypto candidate slices"; §4 "Registry-driven additions instead of code
> changes"; §5 evidence-signal table — direct source API calls carry high
> confidence; §6 stages 2–3 — cheap pattern rules, candidate-only dataflow).

## Starting state (verified before editing)

- `SourceScanner` was Python-only (`.py` via AST + regex fallback);
  C/C++/Java/JS/Go/C#/Rust files were never opened.
- `SemgrepScanner` existed with multi-language rules but was never called
  by any production path (`is_available()` False here — no binary).
- No tree-sitter bindings installed; Semgrep binary absent (Windows host).

## Files changed (Phase 4)

**New**

- `ecdat/scanners/source/api_knowledge.py` — registry-driven API tables
  (~100 rows, `patterns_for(lang)`): OpenSSL EVP high-level
  (`EVP_EncryptInit_ex`, `EVP_DecryptInit_ex`, `EVP_DigestSignInit`,
  `EVP_DigestVerifyInit`, `EVP_PKEY_*`, `RSA/EC/DH/DSA`, `HMAC`,
  `RAND_bytes`, `PKCS5_PBKDF2_HMAC`, low-level `AES/DES/RC4/SHA/MD5`
  primitives), OpenSSL TLS (`SSL_CTX_*`, method/min-version/cipher-list),
  all `EVP_*` cipher/digest constructors generated from
  `EVP_CIPHER_TABLE` (canonical + key + mode), libsodium, JCA/JCE +
  BouncyCastle, Node `crypto`, WebCrypto, Go `crypto/*`, .NET, RustCrypto
  crates. New libraries/APIs = new rows, not new code.
- `ecdat/scanners/source/c_parser.py` — the "Tree-sitter **or equivalent**"
  fast-syntax engine (stdlib only): offset-preserving comment/string
  masking with suppressed-keyword counting, balanced-paren call extraction,
  brace-depth function spans incl. multi-line definitions and pointer
  return types, file-local `#define`/`const`/assignment collection,
  one-hop `resolve_arg`, per-row semantic resolvers (EVP cipher args, JCA
  transformations like `AES/GCM/NoPadding`, Node/WebCrypto names, key-size
  ints, curve aliases incl. `prime256v1`→P-256, TLS methods/version consts),
  `find_wrappers` (one-hop, same file, no chains), `classify_source_file`
  (use / test-vector / implementation / header-capability),
  multi-line-prototype-aware `statement_text`. No whole-program analysis.
- `ecdat/tests/fixtures/source/c_openssl_evp.c`,
  `c_wrappers_const.c`, `c_noise.c`, `jca_crypto.java`, `node_crypto.js`,
  `go_crypto.go`, `dotnet_crypto.cs`, `rust_crypto.rs` — seeded fixtures.
- `ecdat/tests/test_source_semantics.py` — 8 tests (below).

**Extended**

- `ecdat/scanners/source/scanner.py` (`0.1.0` → `0.2.0`) — suffix→language
  routing (Python AST path byte-identical), `_scan_brace_file` semantic
  pass, `_looks_like_declaration` (single- and multi-line prototype
  filtering that never confuses `EVP_…int…` names for return types),
  ctor-argument subsumption (a constructor passed to a resolved Init is
  one finding, not two), wrapper findings inheriting resolved semantics at
  Probable/`source:wrapper-call`, `_merge_semgrep` (opportunistic merge
  with dedupe, retagged `source:semgrep`; absence only recorded in
  `last_stats`), `last_stats()` traceability, optional `artifacts` kwarg.
  Python findings, canonicals, confidences, and `source:ast` tags unchanged.
- `ecdat/tests/fixtures/source/ground_truth.json` — 8 new entries
  (`"suite": "phase4"`, 30 expectations + noise negatives); existing 17
  entries untouched.
- `ecdat/core/orchestrator.py` — `scan()` forwards inventory source
  artifacts (`artifacts` kwarg; scanners without support ignore it, empty
  inventory falls back). All other scanners already accept `**kwargs`.

## Expected behaviour after Phase 4

- C/C++ files are opened and semantically analyzed: `EVP_EncryptInit_ex`
  through `const EVP_CIPHER *c = EVP_aes_256_gcm()` resolves to
  AES-256-GCM/Encrypt/Confirmed; `#define`-indirection and wrapper calls
  resolve one hop; `RSA_generate_key_ex(rsa, 2048…)` yields key size 2048;
  `SSL_CTX_set_min_proto_version(…, TLS1_2_VERSION)` yields TLS1.2.
- Java/JS/Go/C#/Rust get registry-driven API coverage with parameter
  extraction (`Cipher.getInstance("AES/GCM/NoPadding")` → AES/GCM,
  `createECDH('prime256v1')` → ECDH/P-256, `rsa.GenerateKey(…, 2048)`).
- Comments/strings/docs never match (masked; suppressed hits counted);
  prototypes/declarations never match (incl. multi-line); headers,
  test trees, and OpenSSL-`crypto/` implementation files are classified:
  use → Confirmed, test-vector → Possible, implementation → ProvidedOnly
  (via the codebase's own provides-flag, so fusion can never upgrade it),
  headers → Probable.
- An OpenSSL-shaped tree scans to use=Confirmed (AES-256-GCM),
  impl=ProvidedOnly, test=Possible, header=silent — never "OpenSSL uses
  every algorithm it implements".
- Signal taxonomy: `source:api-call` (direct, ≥0.8) > `source:wrapper-call`
  (0.7) > test/unsupported (≤0.6/0.39); Python `source:ast` unchanged.

## Measured results (no estimates)

- Seeded ground truth (`test_ground_truth_precision_recall_by_language`):
  **recall 30/30 = 1.000, precision 30/30 = 1.000** —
  c 13/13 + 2/2, java 3/3, js 3/3, go 4/4, csharp 3/3, rust 2/2, noise 0
  findings with suppressed hits counted. (Fixture-scale by construction;
  real repos will score lower — that is Phase 13's job to measure.)
- End-to-end mixed C+Python repo through the real pipeline: 2 artifacts →
  11 assets / 11 operations, 8 distinct algorithms, usage
  `{Confirmed: 10, Probable: 1}` — mentions collapse toward operations,
  no explosion; repeat scan `cache_hit: True`; CLI returns the identical
  deterministic scan ID as the direct orchestrator call.

## Verification (Phase 4)

- `ecdat/tests`: **185 passed** (177 + 8 new), 0 failures.
- `python -m ecdat.cli --help` + `scan` smoke — PASS.
- Stale `tests/` suite 36F/30P — identical to baseline (preserved).
- Frontend `npm run build` — PASS.
- Test failures during development caught 5 real bugs (fixes in code, not
  tests): declaration filter matching `EVP_…int…` names, pointer
  declarators breaking constant collection, masked literals starving
  JCA/Node parsers (now read from original lines), paren-less row matching,
  multi-line prototypes.

## Known limitations / deferred

- Wrappers resolve same-file, one hop, no chains or cross-file tracking.
- `KeyPairGenerator.initialize(2048)`-style split configuration is not
  linked (RSA key size unresolved there); complex dataflow stays out by
  design (roadmap task 9).
- Capability-only `#include`s yield no finding (covered by dependency
  evidence instead of per-file ProvidedOnly noise).
- Semgrep/tree-sitter backends activate automatically when installed;
  graceful degradation is recorded in `last_stats`.
- Real-OpenSSL-checkout benchmarking belongs to Phase 13.

## Phase 4 acceptance

- C/C++ files actually opened/analyzed — MET.
- Semgrep wired into production (opportunistic) + masking fast-syntax
  engine as the Tree-sitter-equivalent — MET.
- Direct API evidence outranks strings/comments (which never match) — MET.
- Seeded precision/recall by language/algorithm — MET (1.000/1.000).
- OpenSSL subset materially informative + impl/use/test separated — MET.

**Next phase (Phase 5) can safely start.**

---

# Phase 5 — Dependencies, Configs, Certificates/Keys, Dockerfiles, BOM Import

> Roadmap: `docs/ECDAT_CODEX_IMPLEMENTATION_ROADMAP.md` (Phase 5, §§2, 11.1).
> Architecture: `docs/SIH26164_ECDAT_Solution_Architecture.pdf` (§2 scan
> surfaces — libraries/dependencies, config files, certificates/keys,
> SBOM/CBOM import; §5 CIR evidence/CIR-object notes; §6 stages 4–7 —
> dependency scan, container pass; "never store raw secrets; store
> fingerprint, type, key size, path and risk").

## Starting state (verified before editing)

- Dependency scanner covered common manifests (requirements, pyproject,
  npm, cargo, go, maven, gradle, gem, composer) but no native C/C++
  ecosystems (CMake/Conan/vcpkg/Meson/Autotools/pkg-config); package
  table inlined in the scanner module.
- `container/syft_scanner.py` imported a non-existent
  `dependency.crypto_packages` module (latent ImportError; nothing
  imported it yet).
- Config scanners (nginx/apache/envoy/openssl/k8s/terraform/generic)
  emitted flat findings with no service/listener/cert-ref join keys;
  generic scanner could not see `.env` files (suffix gate).
- Dockerfile parsing existed only in the opt-in container family — a
  repo-only scan never surfaced Dockerfile evidence.
- PEM/DER/JKS/PKCS12/JWK/SSH parsing existed with metadata extraction,
  but no fingerprints; **JWK snippets embedded private key material**
  (`d`/`k` in `json.dumps(key)`).
- No BOM import (exports only); inventory already knew most manifest
  basenames but not `*.pc`/BOM/SPDX names.

## Files changed (Phase 5)

**New**

- `ecdat/scanners/dependency/crypto_packages.py` — single source of truth:
  `CRYPTO_PACKAGES` flat table (moved verbatim + native libs: wolfSSL,
  mbedTLS, libsodium, Crypto++, Botan, GnuTLS, NSS, BouncyCastle, Tink),
  `CRYPTO_CAPABILITIES` (library → provided algorithms), ecosystem-nested
  `SYFT_CRYPTO_PACKAGES` (same dicts, no copies), `capabilities_for()`.
- `ecdat/scanners/config/service_context.py` — `k=v` join-key convention
  (`service/listener/endpoint/cert_ref/key_ref/kms_ref` in
  `Context.notes`, no schema change): per-file derivation (nginx
  server_name/listen, Apache vhost/ServerName, k8s names/secretNames/
  ingress hosts, Terraform resource labels, Envoy listeners, openssl.cnf
  sections, `.env` bindings, URLs/ARNs) + `refs_from_detail` + additive
  `attach_service_context()` post-pass (per-finding scope).
- `ecdat/scanners/config/dockerfile_scanner.py` — `DockerfileScanner`
  (config family, default scans): FROM base images, RUN/ADD crypto
  installs (continuation-aware), COPY cert/config refs, EXPOSE/ENTRYPOINT
  folded into notes. Every finding ProvidedOnly + `dependency_only`
  ("container definition, not deployed image") — a Dockerfile can never
  become confirmed deployment use.
- `ecdat/scanners/certificate/cert_metadata.py` — secret-safe helpers:
  SHA256 colon-hex and OpenSSH fingerprints, public-only JWK view,
  cert/public-key fingerprint notes (all never-raise, never secrets).
- `ecdat/tests/test_phase5_artifacts.py` — 12 tests (below).

**Extended**

- `dependency/scanner.py` (`0.1.0` → `0.2.0`) — imports the shared table
  (inline copy deleted); native dispatch (CMake/CMake-package/link-refs,
  conan txt/py, vcpkg, Meson, Autotools, pkg-config) all ProvidedOnly +
  `dependency_only` with versions where trivial; capability post-pass
  (one finding per dep — `provides=` notes, no per-algorithm explosion);
  CycloneDX JSON/XML + SPDX JSON/tag-value import as ProvidedOnly
  inventory evidence (unknown components silent); optional Syft/cdxgen
  hooks (binary-gated, bounded timeouts, `last_stats()` recorded, never
  fatal); dir patterns extended.
- `container/syft_scanner.py` — broken import now resolves (nested table).
- `config/scanner.py` — registers `DockerfileScanner`; runs the service
  post-pass over file and directory scans.
- `config/terraform_scanner.py` — KMS/key-id reference extraction
  (roadmap task; `key_id`/`kms_key_arn` → KMS findings).
- `config/generic_scanner.py` — `.env` files visible (`Path(".env").suffix
  == ""` gate fixed).
- `certificate/{jwk,ssh,pem,der}_scanner.py` — JWK private-material leak
  fixed (public view + fingerprint); SHA256 fingerprints in PEM/DER cert
  and SSH public-key notes.
- `core/inventory.py` — `*.pc`, BOM (`bom/cyclonedx/cdx`), SPDX names →
  dependency category.

## Expected behaviour after Phase 5

- `CMakeLists.txt` (`find_package(OpenSSL)`, `target_link_libraries(…
  ssl crypto sodium)`), `conanfile.txt` (`openssl/3.1.2`), `vcpkg.json`,
  `meson.build`, `configure.ac`, `*.pc` all yield ProvidedOnly findings
  with versions and `provides=RSA,…` notes; `openssl` dep stays ONE
  finding (measured: requirements with one dep → exactly 1 finding).
- Syft/cdxgen run only when installed; otherwise `last_stats()` says
  `unavailable` and local scans are unaffected (measured here).
- A default repo scan surfaces Dockerfile evidence (base image, crypto
  installs, baked-in cert/config refs, exposed ports) — always
  ProvidedOnly, never Confirmed.
- Config findings carry `service=/listener=/cert_ref=/key_ref=/kms_ref=`
  join keys (nginx/apache/terraform/k8s/envoy/openssl/generic/`.env`);
  per-file scoping verified by regression test (a real cross-file leak
  found during development and fixed).
- Cert/key output is metadata-only: real 2048-bit key + self-signed cert
  scan contains zero private bytes (asserted), fingerprints present for
  config↔cert linkage (`cert_ref` path basenames match on-disk certs).
- Imported BOMs enter as ProvidedOnly inventory evidence with versions;
  non-BOM JSON and unknown components stay silent.

## Measured results

- New suite: **12/12 pass**. Full `ecdat/tests`: **197 passed**
  (185 + 12), 0 failures.
- End-to-end mixed repo (CMakeLists + Dockerfile + nginx.conf + real
  cert, default scan): 4 artifacts across `cert/config/container/
  dependency` → 6 assets / 2 ops, usage `{ProvidedOnly: 3, Confirmed: 1,
  Probable: 2}`, capability notes present, all five families `success`.
- CLI smoke PASS (deterministic ID); stale `tests/` 36F/30P identical to
  baseline; frontend build PASS; temp probe dirs removed.

## Verification notes

- Failing tests caught 4 real defects, fixed in code: service-notes
  leaking across same-file findings, `.env` invisibility, missing KMS
  extraction, k8s filename gating in test fixture (Ingress needs a
  k8s-keyword filename — pre-existing behavior, fixture renamed).
- Pre-existing Python behavior untouched (byte-identical Python path
  discipline from Phase 4 held for all existing suites).

## Known limitations / deferred

- Syft/cdxgen exercise only where binaries exist (absent here); OS-layer
  and image-inner scanning stay in Phase 7 with container unification.
- KMS findings use canonical `KMS` (new vocabulary entry; risk mapping
  resolves it in Phase 10).
- Deep cert↔config↔service edge reconstruction is Phase 9; Phase 5
  provides the join keys (`fingerprint=`, `cert_ref=`, `service=`).
- Gitleaks/TruffleHog not installed here; the redaction contract (public
  metadata + fingerprints only) is implemented and asserted in the
  first-party scanners.

## Phase 5 acceptance

- Native C/C++ dependency context improves — MET (6 manifest kinds).
- Cert/key output secret-safe — MET (asserted, incl. JWK leak fix).
- Dockerfile evidence visible in repo-only scan — MET.
- Dependency presence ≠ confirmed use — MET (ProvidedOnly + 1:1).
- Config/cert evidence graph-ready — MET (join keys populated).

**Next phase (Phase 6) can safely start.**

---

# Phase 6 — Staged Binary Analysis with Real Escalation

> Roadmap: `docs/ECDAT_CODEX_IMPLEMENTATION_ROADMAP.md` (Phase 6, §§2, 11.1).
> Architecture: `docs/SIH26164_ECDAT_Solution_Architecture.pdf` (§3 binary
> scanner — "LIEF, strings, YARA-X, capa/FLOSS, optional Ghidra" with
> "imports/symbols → strings → constants → behavior → decompiler"; §5
> evidence-signal table — binary import/symbol vs constant vs plain
> string; §6 stage 5–6 — cheap pass first, heavy reversing as escalation).

## Starting state (verified before editing)

- `BinaryScanner` fanned every available sub-scanner flatly over every
  binary: no stages, no escalation, no timing, no counts, no per-binary
  candidate state. On this host only `StringsScanner` runs (no LIEF,
  YARA, capa, FLOSS, or Ghidra installed).
- Plain-substring matching produced **57 false findings on a hello-world
  PE** (PE TLS-directory structs, `Destination`, `ProcessLocksList`,
  `gccmain.c`, `_tls_*` CRT symbols) — the exact FP class the roadmap
  targets.
- Phase 3 orchestrator recorded CIR-level escalation candidates but
  executed nothing ("lands in Phase 6").

## Files changed (Phase 6)

**New**

- `ecdat/scanners/binary/stages.py` — staging engine (stdlib only):
  `CheapSignals` (format/magic, import/symbol/constant/OID evidence,
  linked libs, crypto symbols, stripped tri-state, packed
  yes/suspected/no/unknown via markers + entropy, high-value names,
  per-stage timings), `decide_escalation()` (roadmap taxonomy —
  stripped/packed/ambiguous/weak-confidence/conflicting/high-value/
  static-implementation — plus a REAL `should_escalate()` call whose
  verdict gates execution while reasons stay explainable even when the
  profile forbids escalation), `run_capa()` (behavior rules → 0.75
  findings, crypto-namespace filtered), `run_floss()` (decoded strings
  re-matched → 0.5 findings), `expensive_tool_status()`,
  `match_constants/match_oids/match_symbol_strings/file_entropy/
  detect_format` probes.
- `ecdat/tests/fixtures/binary/src/crypto_app.c`, `hello.c` — real
  fixture sources (EVP AES-256-GCM, SHA-256, RAND_bytes, S-box bytes,
  RSA OID; clean control). Compiled fresh into tmp by tests; no binaries
  committed.
- `ecdat/tests/test_binary_stages.py` — 16 tests (below).

**Extended**

- `ecdat/scanners/binary/crypto_signatures.py` — `CRYPTO_CONSTANTS`
  (verified S-box/SHA/MD5/ChaCha bytes), `CRYPTO_OIDS` (+ dotted forms),
  `PACKER_MARKERS`, `is_plausible_crypto_string()` FP guard (PE-loader
  denylist; letter-boundary/dominance rule for <4-char patterns —
  keeps `tls1.2`, `aes-256-gcm`, `3DES`, `ECDH`, drops `Destination`).
- `ecdat/scanners/binary/{strings,lief}_scanner.py` — plausibility guard
  on the shared noisy path (symbol/import matching untouched).
- `ecdat/scanners/binary/scanner.py` (`0.1.0` → `0.2.0`) — staged
  `scan()`: cheap pass (strings + LIEF/YARA when present + constant/OID/
  symbol-string signatures) for EVERY binary; escalation evaluated per
  binary; capa/FLOSS/Ghidra candidate-only per profile backends
  (`floss-selective` runs only on packing/obfuscation signals);
  inventory `artifacts` routing; `(canonical, uri, tool)` dedupe;
  `last_report()` (per-binary records + counts/rates/timings/tools).
- `ecdat/scanners/discovery.py` — additive `binary_stage_report()`.
- `ecdat/core/orchestrator.py` — forwards `escalation_allowed` +
  `expensive_backends` from profile effort; `diagnostics` gains
  `binary_stages`/`binary_tools`; CIR escalation section gains executed
  counts (`binaries_evaluated/with_findings/candidates/escalated`,
  `expensive_analysis_rate`, `binary_stage_times`).

## Expected behaviour after Phase 6

- Cheap order holds everywhere: strings Possible ≤0.35 < symbol-strings
  0.5 < constants/OIDs 0.6 Probable < capa behavior 0.75 < LIEF
  imports/symbols 0.55–0.9 (asserted).
- Hello-world PE: 57 → **0 findings**; dynamic OpenSSL PE keeps 28 real
  ones (AES/RSA/SHA-256/OpenSSL); stripped keeps strings/constants but
  loses symbol surface (28→11); static link embeds more (const evidence).
- Escalation reasons are explicit per binary (`weak-confidence`,
  `packed:`, `stripped:`, `ambiguous-`, `conflicting-`, `high-value-`,
  `static-implementation:`); expensive backends run only on candidates
  (measured 2-binary dir: 1 escalated, control explicitly `skipped`);
  missing capa/FLOSS/Ghidra read as `unavailable`/`not-configured`
  coverage — scans succeed regardless.
- Quick profile never escalates (`binaries_escalated == 0` with the
  profile reason recorded); standard/deep escalate per taxonomy.
- Binary evidence reaches fused CIR assets; signal metadata (linked lib,
  symbol, mode string, OID, constant, `binary-offset:`/`binary-import:`
  URIs) rides on findings.

## Measured results

- New suite: **16/16 pass, 0 skipped** (real gcc + OpenSSL toolchain
  present: dynamic/static/stripped/control all compiled and asserted).
- Full `ecdat/tests`: **213 passed** (197 + 16), 0 failures.
- End-to-end mixed dir via orchestrator: 2 binaries evaluated,
  1 with findings, 1 candidate, 1 escalated, expensive rate 0.0 (nothing
  installed), cheap 0.301s / expensive-probe 0.024s, 12 CIR assets.
- CLI smoke PASS; stale `tests/` 36F/30P identical to baseline; frontend
  build PASS; temp build dirs removed.

## Verification notes

- Failing probes drove the work honestly: the 57-FP hello-world scan
  forced the plausibility guard (57→13→0 across two iterations, each
  verified against the synthetic `test_binary.bin` expectations, which
  still pass unchanged at 12 findings).
- Constant/OID hex was hand-verified (two transcription errors in S-box/
  OID bytes caught by re-checking known vectors before any test encoded
  them).
- Static linking needed system libs (`-lws2_32 -lcrypt32 …`) — recorded
  in the test builder, not hidden.

## Known limitations / deferred

- No LIEF/YARA/capa/FLOSS/Ghidra on this host: import/symbol,
  YARA-constant, behavior, and decompiler stages are implemented and
  unit-wired but integration-proven only where tools exist; statuses
  prove the wiring (`unavailable`, never silent).
- `stripped` reports `unknown` without LIEF (assumed nothing); packed
  `suspected` is entropy+marker heuristic, `yes` only on markers.
- Ghidra stays record-only even when configured (explicit headless
  setup is Phase 7+ work); deep profile flags it expected.
- Real-OpenSSL-checkout and weak-laptop performance benchmarking belong
  to Phase 13.

## Phase 6 acceptance

- Auto binary analysis without manual selection — MET (inventory-routed,
  default scanners; asserted via orchestrator).
- Expensive analysis on a subset only — MET (measured 1/2, control
  skipped).
- Explainable escalation — MET (taxonomy reasons on every binary).
- Binary evidence in fusion — MET (asserted in CIR assets).
- Strings weaker than symbol/behavior — MET (asserted ordering).

**Next phase (Phase 7) can safely start.**

---

# Phase 7 — Unified Containers, Runtime & Cloud Innovation Paths

> Roadmap: `docs/ECDAT_CODEX_IMPLEMENTATION_ROADMAP.md` (Phase 7, §§2, 11.1).
> Architecture: `docs/SIH26164_ECDAT_Solution_Architecture.pdf` (§2 surfaces
> — container images, runtime endpoints, cloud KMS; §3 container scanner —
> "layer cache, Syft/cdxgen/Trivy, then inner passes", "cache by
> image/layer digest"; runtime — "SSLyze/testssl probes joined with
> config graph"; cloud — "read-only inventory, no secret extraction").

## Starting state (verified before editing)

- Two parallel container implementations: `ContainerScanner`
  (syft/docker-save/tarball/dir) and `DockerScanner` (inspect/trivy/
  layers/dockerfile/compose) with overlapping tarball/dir/image routing.
- `.tar.gz`/`.tgz` unrecognized (only `.tar` routed); tarball extraction
  to fixed `/tmp/ecdat_container_scan` with no traversal protection;
  layer cache keyed by the FIRST layer only; findings persisted via
  fragile `__dict__` round-trip (nested pydantic models break it);
  inner findings had context OVERWRITTEN (capability notes destroyed).
- Environment: docker CLI present but daemon down; no syft/trivy/sslyze —
  the container family was effectively unavailable for everything.
- Runtime TLS/SSH probers real but evidence lacked timestamps,
  tool versions, and cert fingerprints; SSH exposure inconsistent.
- Azure/GCP scanners emitted fabricated 0.1-confidence "stub" findings
  whenever SDKs imported — mock data in production output.
- AWS scanner genuinely deep (KMS/ACM/ELB/ALB) but ELB/ALB→cert links
  unstructured.

## Files changed (Phase 7)

**Containers (one engine)**

- `ecdat/scanners/container/scanner.py` (`0.1.0` → `0.2.0`, rewritten —
  justified: routing/caching/safety were wrong, not merely thin):
  single dispatcher for image refs (pull-gated, backend-gated),
  Docker/OCI/plain tarballs (manifest/oci-layout sniffed, `.tar/.tar.gz/
  .tgz` all recognized), OCI layout dirs (`index.json` → blobs), rootfs
  dirs — all daemon-free via stdlib; Dockerfiles explicitly deferred to
  the config family; inner contents scanned by the SAME five family
  scanners with `image:<ref>/layer:<digest>/<rel>` URIs (posix-stable)
  and APPENDED `image=/layer=/service=` notes; per-layer sha256 cache
  (never first-only) with NORMALIZED model_dump round-trip persistence
  (memory + sqlite); guarded syft-dir and trivy-fs hooks;
  `last_report()` (kind/layers/cache-hits/skipped/tools) and
  `container_backend_status()` (lru-cached probes, no pulls).
  `DockerScanner` kept byte-identical as the daemon backend with an
  ownership docstring (image inspect/trivy where a daemon exists).
- `ecdat/core/orchestrator.py` — pull gate (refs without `allow_pull` →
  loud permission error naming `--allow-pull`) + backend gate (permitted
  but impossible → loud missing-backend error); forwards
  `allow_pull/allow_build` to the family.
- `ecdat/core/client.py`, `commands/_real_scan.py`, `commands/ci_cmd.py`,
  `ecdat/cli.py` (`scan-container`, `ci`: `--allow-pull/--allow-build`),
  `ecdat/web/server.py` (`allowPull/allowBuild` job fields + scan-plan
  preview) — permission model end to end.

**Runtime**

- `runtime/tls_scanner.py` — leaf-cert SHA256 fingerprint (static-link
  join key), `probed_at`, tool/version + endpoint/protocol notes on all
  three findings.
- `runtime/ssh_scanner.py` — same provenance notes, host-key
  fingerprints, consistent INTERNET_FACING exposure.
- `runtime/scanner.py` — `external_tool_status()` (sslyze/testssl
  probes; stdlib documented as the strong path).

**Cloud**

- `cloud/{azure,gcp}_scanner.py` — stub findings deleted (no fabricated
  evidence): `is_available()` False with honest
  `<sdk>-not-implemented` versions, `scan()` []. Also fixed a
  copy-pasted `_check_azure` name in the GCP module.
- `cloud/aws_scanner.py` — ELB/ALB findings gain `service=/listener=/
  cert_ref=/ssl_policy=` linkage notes (ACM join keys).

## Expected behaviour after Phase 7

- `scan-container local.tar/rootfs/` works with zero tools installed;
  image refs refuse loudly without `--allow-pull`, and loudly report
  missing backends with it; Dockerfile-only inputs stay config-owned
  (no double count); pulls/builds never happen implicitly.
- Repeat image scans hit per-layer cache (proven by mutating one layer:
  other stays cached); corrupted/evil archives skip safely; findings
  retarget correctly across cache hits (a dropped-path-segments bug
  caught by tests and fixed).
- Localhost TLS probes record version/cipher/chain-metadata/exposure/
  timestamp/tool/fingerprint; closed ports return [] silently-safe;
  default scans never open sockets; Azure/GCP report honestly narrow;
  AWS KMS/ACM/ELB evidence carries service linkage.

## Measured results

- New suites: **17/17 pass** (`test_container_unified` 8,
  `test_runtime_cloud_paths` 9 — incl. a live localhost TLS handshake
  asserting the exact cert fingerprint).
- Full `ecdat/tests`: **230 passed** (213 + 17), 0 failures.
- E2E: synthetic 2-layer save → layer-tagged config/cert/dependency
  findings, repeat = 2 cache hits; local tar via CLI → stored scan;
  refusals verified on CLI for both gates.
- CLI smoke PASS; stale `tests/` 36F/30P identical to baseline; frontend
  build PASS; temp fixtures removed.

## Verification notes

- Failing tests caught 3 real defects, fixed in code: per-layer (not
  first-layer) cache semantics needed a same-content-mutation test to
  prove; cached-URI retargeting dropped path segments; cloud labels
  matched the image-ref gate (excluded explicitly).
- The `mbedtls` trivy keyword (spaced, dead) was corrected and verified
  by length check.

## Known limitations / deferred

- No daemon/syft/trivy here: image-ref pulls, syft-image, trivy, and
  Ghidra paths are implemented, status-reported, but
  integration-unproven until tooled hosts run Phase 13.
- cdxgen-image support deferred (dependency cdxgen hook covers repos).
- OCI `zstd` layers skip safely (stdlib tarfile limit), recorded.
- Full container↔config↔runtime edge reconstruction is Phase 9; Phase 7
  provides URIs, fingerprints, and `image=/service=/cert_ref=` keys.

## Phase 7 acceptance

- Local container input auto-recognized — MET (tar/tar.gz/rootfs/OCI).
- Inner artifacts use the same scanners — MET (asserted tool prefixes).
- Layer caching correct — MET (repeat + mutation + cross-instance).
- Runtime/cloud opt-in — MET (permission gates, loud errors).
- ≥1 runtime + ≥1 cloud real graph-linkable path — MET (TLS probe with
  fingerprint; AWS KMS/ACM/ELB with linkage notes; stubs removed).

**Next phase (Phase 8) can safely start.**

---

# Phase 8 — Evidence Fusion & Operation Reconstruction

> Roadmap: `docs/ECDAT_CODEX_IMPLEMENTATION_ROADMAP.md` (Phase 8, §§2, 11.1).
> Architecture: `docs/SIH26164_ECDAT_Solution_Architecture.pdf` (§5 CIR —
> operations/assets with evidence, "provided vs actually used"; §6 stages
> 8–9 — evidence merge with duplicate suppression, risk on resolved
> operations; §8 — score resolved systems, "a repo with 80 RSA mentions
> may become 3 actual risk objects").

## Starting state (verified before editing)

- `core/fusion.py` (weighted fusion, usage adjudication, dedup,
  redaction) and `core/operations.py` (`build_operations` collapse)
  existed but were called ONLY by the standalone `core/api.py` pattern
  scanner — never in production. Production built one asset + one
  operation per raw finding via `finding.to_asset()/to_operation()`.
- `DiscoveryEngine._correlate_findings` (5-line proximity) was the de
  facto confidence engine — explicitly pinned by `test_correlation.py`
  ("not silently changed").

## Files changed (Phase 8)

**Extended**

- `ecdat/core/fusion.py` — additive calibration only: registered ECDAT's
  real detector families in `DETECTOR_RELIABILITY` (source 0.92, runtime
  0.92, config/cert 0.85, binary 0.8, strings 0.6, dependency 0.5,
  container 0.6, cloud 0.75, secret 0.85, dockerfile/bom 0.5; original
  eight values byte-identical) so production evidence fuses through the
  table instead of the 0.7 default. Formula and thresholds untouched.
- `ecdat/core/operations.py` —
  - `build_operations`: direct observation is now a floor (never fused
    below observed direct confidence; dependency/test caps still
    dominate). Lib-level, benefits all callers.
  - New `reconstruct_cir(cir)`: adapts CIR operations+assets to raw-hit
    dicts (detector/signal/location/parameters/confidence/usage/context
    per evidence item via a tool→(detector, signal) taxonomy;
    param/binary/agreement/dependency/test flags), collapses with
    `build_operations` (ProvidedOnly never merges with use), rewrites
    operations (merged provenance evidence, fused confidence, usage
    adjudicated on the floored score, stable semantic IDs), regroups
    assets by (canonical, params, file) with fused confidence/usage,
    preserves asset-only evidence, rebuilds graph nodes/edges in the
    same vocabulary, returns a validated `CIRDocument`. Suppression
    requires test-path AND weak direct evidence (<0.8), so a strong
    direct call in a file named `test.py` stays Confirmed.
  - Scan-level static/runtime agreement: config claims for an algorithm
    also observed live get the agreement bonus (contract untouched).
- `ecdat/scanners/discovery.py` — `scan_and_emit_cir` calls
  `reconstruct_cir` for every scan (CLI/GUI/CI/discovery-direct);
  proximity correlation stays as the grouping pre-pass; fusion failures
  degrade to raw CIR with a warning, never a failed scan.
- `ecdat/tests/test_fusion_operations.py` — 9 tests (collapse,
  production-spy, FP rule, asset-only, suppression, ID stability, graph
  integrity, empty scan, floor/bands unit).

## Expected behaviour after Phase 8

- 12 same-function mentions → 2 operations (one per function) with full
  6-signal provenance each; operations fewer and stronger than findings.
- OpenSSL dep + AES-GCM use → `{Confirmed: 1, ProvidedOnly: 1}`,
  algorithms exactly `{AES-256-GCM, OpenSSL}` — provides never leaks
  into use (pre-existing dep `TLS` capability-op stays ProvidedOnly,
  capped 0.075, unchanged semantics).
- Test-tree crypto evidence suppresses (`FalsePositiveSuppressed`);
  strong direct calls never suppress regardless of filename.
- Same-file duplicates share one asset; cross-file assets stay distinct;
  all IDs deterministic across runs; graph edges always resolve.

## Measured results

- New suite **9/9**; full `ecdat/tests` **239 passed** (230 + 9).
- E2E mixed repo: usage `{Confirmed: 1, ProvidedOnly: 1}`, 1 Encrypt op
  at 0.92; localhost-style probes unaffected.
- CLI help + smoke PASS; stale suite 36F/30P = baseline; frontend PASS.

## Verification notes

- Two failing tests drove contract fixes in code: usage/confidence
  disagreement after flooring (adjudicate on floored score), and
  path-only suppression overriding 0.92 direct evidence (suppression now
  needs weak evidence too) — the pinned `test.py`-fixture test passes.
- A stray non-ASCII byte introduced mid-edit was removed; module
  imports cleanly.

## Known limitations / deferred

- Fusion groups are file-scoped (no cross-file merges): cross-surface
  corroboration beyond co-located multi-scanner evidence is Phase 9
  graph work; binary `binary_support` fires within same-file groups.
- Checksum-only auto-detection not implemented (no silent
  `FalsePositiveSuppressed` from keyword guessing); the state exists
  via `decide_usage` for explicit callers.
- LIEF/YARA/capa-deprived hosts fuse on strings/signature evidence at
  honestly lower confidence — coverage status, not silence.

## Phase 8 acceptance

- Production calls the real fusion layer — MET (spy test).
- Production calls the operation builder — MET (same).
- Fewer, stronger operations — MET (12→2 measured).
- Testable usage reasoning — MET (floor/bands + suppression tests).
- Fused CIR — MET (`fusion=` provenance notes on every rebuilt op).

**Next phase (Phase 9) can safely start.**

# Phase 9 — Crypto Knowledge Graph and system reconstruction

> Verified against the Phase 9 requirements in the roadmap. The implementation
> is present in the production CIR path; no Phase 13/14 work was performed.

## Implementation verified

- `ecdat/core/graph.py` is the graph builder and provides stable node/edge IDs,
  deduplication, indexed lookup, neighbourhood/path queries, and system-link
  helpers. It models operations, assets, libraries, services, containers,
  endpoints, keys/certificates, configs, cloud resources, and owners when
  evidence supplies them.
- `ecdat/core/operations.py:reconstruct_cir()` rebuilds the graph after fusion,
  so source/binary/dependency/config/certificate/runtime/container/cloud
  evidence is represented in the same CIR rather than a discovery-only graph.
- `ecdat/adapters/graph_adapter.py` consumes the CIR graph for the GUI and
  preserves folded file locations and edge provenance; it does not rebuild a
  separate minimal graph. `ecdat/tests/test_graph_systems.py` and
  `test_fusion_operations.py` cover stable IDs, resolved edges, and cross-
  surface reconstruction.

## Acceptance status

- Authoritative production graph: MET.
- Stable, deduplicated entities and justified relationships: MET for supplied
  operation context; inferred links retain confidence/provenance.
- Service/container/config/TLS/certificate chain: supported when the relevant
  identifiers and evidence are present; unsupported links are omitted rather
  than invented.

# Phase 10 — System risk and deterministic recommendations

## Implementation verified

- `ecdat/core/risk.py` scores reconstructed operations and emits per-operation
  P1/Mosca-style records; `ecdat/web/server.py` and report aggregation consume
  those records through `ecdat/adapters/risk_view.py`, not a UI severity-count
  score. Legacy/mock risk is not used by the web result payload.
- `ScanContext` and the web risk-context form support environment, owner,
  exposure, business criticality, data lifetime, migration lead time, and the
  configurable QC timeline. Context provenance is retained as observed,
  inferred, user-supplied, or unknown; omitted values are not silently raised
  to enterprise-critical defaults.
- `ecdat/core/recommend.py` and `ecdat/adapters/migration_adapter.py` produce
  deterministic, operation-aware migration records with target, rationale,
  compatibility/blockers, effort/cost information, and standards metadata.
- `ecdat/tests/test_risk_context.py` verifies context handling and explicit
  assumptions; recommendation and integration tests exercise shared output.

## Acceptance status

- Risk/recommendations based on resolved CIR operations: MET.
- Explicit assumptions and user-supplied context: MET.
- Shared CLI/GUI/report risk data: MET through the canonical/CIR result path.

# Phase 11 — Unified persistence, exports and CI behavior

## Implementation verified

- `ecdat/store/repository.py` provides the shared SQLite `ScanRepository` for
  canonical scans, CIR, plan, diagnostics, findings, cache/provenance metadata,
  and scan history. The schema is initialized/migrated by `ecdat/store/db.py`.
- GUI jobs persist completed results through this repository and
  `GET /api/results/<scan_id>` reopens them when the in-memory result is absent;
  `/api/scans` exposes history. CLI/CI use the same orchestrator and storage
  model.
- `ecdat/web/server.py` export routes derive JSON, CIR, CSV, SARIF, CycloneDX
  CBOM JSON/XML, HTML, Markdown, and PDF from the stored result payload. CI
  policy gating remains separate from P1 risk scoring and reports limitations
  and unavailable tools.
- `ecdat/tests/test_persistence.py` and the integration/export tests cover
  round-trip storage, reopen behavior, and export consistency.

## Acceptance status

- Durable GUI/CLI/CI scan model: MET.
- Reopen/history and cache-aware metadata: MET.
- Shared export source and CI gating: MET.

# Phase 12 — GUI scan-plan UX and judge-grade result delivery

## Implementation verified and fixed

- `frontend/src/App.tsx` now presents automatic local discovery by default,
  with Quick/Standard/Deep depth, detected local artifact counts, opt-in
  container/runtime/cloud controls, and manual scanner overrides under
  Advanced. Optional risk context is visibly labelled user-supplied.
- The scan-plan preview calls `POST /api/scan-plan` before execution and shows
  artifact totals, surfaces, planned scanners, permissions, and unavailable
  tools. Live job progress is driven by orchestrator stage events; coverage and
  diagnostics are included in the result payload.
- Result tabs expose analytics, P1 risk, graph, evidence/findings, assets,
  operations, recommendations, and coverage, with exports from the shared
  result model.
- Fixed a half-implemented data contract in `App.tsx`: `/api/inputs/inspect`
  returns `surfaces` as a category-count object and `archives` as archive
  records, but the UI treated them as an array and number. The UI now renders
  counted surfaces and archive-record totals correctly.

## Remaining Phase 12 limitations (not expanded beyond scope)

- Progress is stage-level rather than per-artifact counters for every scanner.
- The graph view is a compact tabular projection rather than a full interactive
  neighbourhood visualization.
- Scan history is API-backed; the frontend does not yet provide a dedicated
  history/reopen picker.

## Validation

- Frontend type/build validation was attempted, but the workspace has no local
  `tsc` executable (`npm run build` stops at `tsc: not found`). Python focused
  tests were also not runnable in the system interpreter because `pydantic` is
  unavailable. No other phases were changed.
# Phase 13 — Benchmark harness and measurable result quality (implemented)

- Added `ecdat/benchmarks/harness.py`, runnable with
  `python -m ecdat.benchmarks.harness --output results/phase13.json`.
- It runs deterministic mixed source/dependency/config fixtures through the
  real orchestrator at quick/standard/deep profiles and records timing, scan
  counts, expected/observed algorithms, precision, recall, cache, and
  escalation metrics.
- It writes versioned JSON and CSV. `--openssl` records a checkout but does
  not falsely claim execution; a pinned OpenSSL adapter remains deferred.

Validation: Python syntax compilation and `git diff --check` passed. Full tests
and frontend build are environment-blocked because `pydantic` and local `tsc`
are unavailable.

# Phase 14 — Final hardening, legacy quarantine and release gate

## Updates

- Audited production entry points: CLI, CI, GUI, and the compatibility
  `pipeline.run_real_scan()` path all delegate to `ScanOrchestrator`.
- Retained historical mock/legacy tests and documentation references rather
  than deleting them; active production reports use P1 risk and deterministic
  recommendations only.
- Preserved the Phase 14 regression coverage in
  `ecdat/tests/test_phase14_hardening.py`, including no-mock production guards,
  orchestrator convergence, structured scanner failure/tool diagnostics, path
  redaction, and CLI registration checks.
- Added `docs/implementation/optional-tools.md`, documenting optional tool
  installation/capability behavior and honest graceful degradation for
  Semgrep, Tree-sitter, LIEF, YARA-X, capa, FLOSS, container/SBOM tooling,
  runtime probes, and cloud SDKs.

## Release-gate status

- Runtime architecture and no-silent-tool-failure checks: implemented and
  covered by the Phase 14 tests.
- Report generation, CLI help, benchmark harness, and syntax checks: covered
  or implemented where dependencies are available.
- Full backend suite, frontend typecheck/build, real OpenSSL acceptance run,
  and Windows/Linux matrix: environment/deployment validation still required;
  this workspace lacks `pydantic` and local `tsc`, and no OpenSSL checkout was
  supplied. These are recorded blockers, not fabricated passes.
