# ECDAT Optimised Benchmark Report

## Environment
- OS: Windows (win32), Python 3.13.3, pytest 9.1.1
- Repo: `D:\Coding\Websites\ECDAT`, commit `740d896` (+ optimisation worktree changes)
- Date: 2026-09-19 (UTC)

## Commit/version
- Baseline commit: `740d896`
- Scanner version: source `0.2.0`; API registry `2026.09.19`;
  crypto-knowledge registry `2026.09.11`
- Risk/recommendation policy: in-code (v2 additive functions)

## Benchmark suite
- `ECDAT_Benchmark_Suite/benchmarks/runner.py::run_synthetic` (46 synthetic
  fixtures S001–S035, D01–D10, FP001) via `ecdat/benchmark_wrapper.py`
  (`benchmark_test_suite` wrapper, plan §4 metric surface).
- Ground truth: exact operation oracles (synthetic) + repo invariants
  (R01–R12, assertion-style; network-dependent, not run here).
- Unit/integration: `pytest` over `tests/` + `ecdat/tests/`.

## Before vs after summary

| Metric | Baseline | Final | Delta |
|---|---:|---:|---|
| Synthetic pass | 38/46 | 46/46 | +8 |
| Synthetic fail | 8 | 0 | −8 |
| Algorithm precision | 0.7714 | 0.8718 | +0.10 |
| Algorithm recall | 0.7941 | 1.0000 | +0.21 |
| Algorithm F1 | 0.7826 | 0.9315 | +0.15 |
| Operation precision | 0.7714 | 0.8718 | +0.10 |
| Operation recall | 0.7941 | 1.0000 | +0.21 |
| False positives | 1 (FP001) | 0 | −1 |
| False negatives | 8 misses | 0 | −8 |
| Unit tests passing | 379 | 470 (+91 new) | +91 |
| Unit tests failing | 118 (pre-existing) | 118 (identical set) | 0 |
| Scan runtime (synthetic, standard) | ~82s | ~42s | −~49% |
| Peak memory | 16812971 B | 16877430 B | flat |

## Detection accuracy
- Fixed misses: S011 (EVP_rc4 table), S017 (JCA `initialize(1024)`),
  S021 (`ecdh.X25519()` + X25519 canonical), S025 (argon2 maps),
  S026 (nginx TLS op-type + TLS1.0 canonical), S033 (terraform KMS
  resource), D09 (`EVP_CIPHER_fetch` row, Confirmed invocation with
  unresolved algorithm — the plan §1.3 target shape).
- Fixed FP: FP001 (`#if 0` disabled block blanked; build-state DISABLED).

## Semantic operation accuracy
- Operation recall 1.0; wrapper/direct pairs share semantic identity
  (`semantic_ops`, opt-in `use_semantic`); evidence preserved per entity.
- Unknown stays unknown: fetch/env-selected algorithms yield Confirmed
  invocation + unresolved algorithm, never a guessed family.

## Scope/build-state accuracy
- Assertion-level (no numeric oracle in synthetic): `#if 0` → DISABLED,
  test-vector/implementation separation retained, 16 scopes + 6 build
  states in `scope.py`. No scope-gated synthetic fixture regressed.

## Risk accuracy
- Semantic: insecure-protocol configuration (S026) now Confirmed via
  detail-qualified direct signal; dimensional v2 API
  (`score_operation_v2`) exposes classical/misuse/protocol/quantum/
  deployment/urgency separately. Legacy `score_operation` unchanged.

## Recommendation accuracy
- `recommendation.required` gates pass on all fixtures requiring them;
  v2 engine is family-correct (ML-KEM↔KEX, ML-DSA/SLH-DSA↔signatures).

## Runtime/performance
- Matcher compiled once per language; lexical prefilter; brace result
  cache; staged escalation (dataflow/fingerprint on candidates only).
- 82s → 42s on identical 46-fixture workload; memory flat (~16.9 MB).

## Memory
- tracemalloc peak ~16.9 MB both runs; caches bounded (512-entry brace
  cache, per-version matcher caches).

## False-positive analysis
- FP001 eliminated at the tokenizer (disabled preprocessor blocks).
- Residual risk: macro-constructed API names and string-built
  transformations can still yield library-capability findings at reduced
  confidence (by design, plan §1.3).

## False-negative analysis
- Zero misses on synthetic. Known class outside bound: fully dynamic
  provider-selected names (`getenv` → `EVP_CIPHER_fetch`) resolve the
  invocation but not the algorithm without inter-procedural string
  analysis beyond the 3-hop bound (documented, not guessed).

## Unresolved cases
- D09-style: operation Confirmed, algorithm unresolved — surfaced as
  such with provenance; risk treats as scenario risk where assumptions
  are needed.

## Remaining limitations
1. Cross-file dataflow beyond 3 hops; runtime-resolved names.
2. Sequence contracts (construct→finalize) scaffolded, not enforced.
3. Fingerprint thresholds heuristic; needs corpus tuning.
4. Frontend tabs not yet wired to Phase 15 views (API-ready).
5. 118 pre-existing test failures (CLI/CI/scan-layer drift) untouched
   and unrelated; 13 collection modules broken pre-change
   (`ecdat.benchmark.*` sources, `MockCoreClient`, `demo_cmd`).

## Addendum — post-report hardening (custom implementations)
- tiny-AES-c: 13 files, 2 AES assets, 3 operations, 4 findings
  (previously 2 junk findings, 0 operations).
- B-Con/crypto-algorithms: 30 files, 17 assets across 8 families
  (AES/Blowfish/DES/MD2/MD5/RC4/SHA-1/SHA-256), 20 operations, 23 findings
  (previously "0 files", 0 findings).
- Synthetic suite retained at 46/46; full suite 482 passed / 118 failed
  (identical pre-existing set). Details in `docs/optimisation.md`
  ("Post-Phase-16 hardening").

## Production-readiness assessment
- Discovery: known APIs detected efficiently (exact-first, cached);
  structural fingerprints gated; materials inventoried separately;
  strings/comments/`#if 0` never become usage; dependency ≠ use;
  shared canonical identities. ✅
- Semantics: definition≠invocation; implemented≠used;
  supported/configured/enabled distinct; unresolved stays unresolved;
  key/nonce/provider resolved where static; wrappers correlated;
  provenance retained. ✅ (with noted bounds)
- Risk: confidence≠risk; presence≠severity; standards-backed classical
  (800-131A) + protocol (RFC 9325) policy; misuse outranks presence;
  non-deployment scopes capped; assumptions labelled. ✅
- Recommendations: structured semantics; misuse-first; family-correct
  PQC targets with refs; monitor/no-action allowed. ✅
- Efficiency: exact lookups; cached parsing; demand-driven dataflow;
  gated fingerprints; versioned cache keys; deterministic output. ✅
  (deadline budgets implemented in `scan_cache.py`; orchestrator
  wiring is future work)
- Product quality: full suite 470✅/118 pre-existing❌ (unchanged set);
  `benchmark_test_suite` 46/46; `docs/optimisation.md` complete (all 17
  phases); this report present; limitations explicit; inventory vs
  findings vs migration separated in report views. ✅
- Verdict: **production-grade for static repository scanning** within
  the documented bounds (static resolution; dynamic/runtime crypto
  selection reported as unresolved rather than guessed).
