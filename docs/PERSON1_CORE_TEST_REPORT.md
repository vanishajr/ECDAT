# Person 1 Core Pipeline Test Report

Date: 2026-09-12  
Scope: Person 1 core intelligence only  
Excluded: Person 2 scanners, Person 3 CLI/GUI integration, database, reports, and end-to-end product workflow

## Executive result

The Person 1 pipeline was exercised using the existing CIR fixtures and synthetic detector-shaped evidence. All custom checks passed: **67 passed, 0 failed**. The focused repository tests also passed: **47 passed, 0 failed**.

The core stages are currently fast on the test environment. The complete fixture pipeline (validate → graph → risk → recommendations) has a median runtime of **7.3291 ms** for the `multi-evidence.json` fixture. These are local microbenchmarks, not production-scale scanner benchmarks; no Person 2 scanner was invoked.

## Test environment

- Python: `3.13`
- Virtual environment: `.venv-p1`
- Dependencies installed in venv: `jsonschema 4.26.0`, `pytest 9.1.1`
- Project editable installation: **blocked** because setuptools discovers both `ecdat` and `referenceDocs` as top-level packages.
- Tests therefore ran with the repository root on Python’s import path, without modifying packaging files.
- Pytest emitted one non-functional warning because the existing `.pytest_cache` directory was not writable.
- Hardware details were not collected, so results should be compared only on the same machine/environment.

## Commands executed

### Focused automated tests

```powershell
.\.venv-p1\Scripts\python.exe -m pytest -q tests/test_benchmark_predictions.py tests/test_benchmark_accuracy.py tests/test_validate.py
```

Result: **47 passed in 0.90s**.

### CIR fixture pipeline

```python
from ecdat.core.cir_validate import load_cir_json, validate_cir
from ecdat.core.graph import graph_index_for_cir
from ecdat.core.risk import score_cir
from ecdat.core.recommend import recommend_cir

cir = load_cir_json("ecdat/core/samples/multi-evidence.json")
validate_cir(cir)
graph = graph_index_for_cir(cir)
risks = score_cir(cir)
recommendations = recommend_cir(cir, risks)
```

### Raw detector evidence to operations

```python
from ecdat.core.operations import build_operations

operations = build_operations(raw_detector_hits)
```

Then use `build_graph`, `score_operation`/`score_cir`, and `recommend_for_operation`/`recommend_cir` for the downstream stages.

## Component coverage

### CIR schema and models

- Loaded and validated all four Person 1 fixtures:
  - `source-only.json`
  - `binary-only.json`
  - `container-only.json`
  - `multi-evidence.json`
- Converted fixtures through `CirDocument.from_dict`.
- Verified required CIR structure and model version preservation.
- No Person 2 scanner output was needed.

Fixture sizes:

| Fixture | Assets | Operations | Graph nodes | Graph edges |
|---|---:|---:|---:|---:|
| `source-only.json` | 5 | 5 | 20 | 25 |
| `binary-only.json` | 4 | 4 | 11 | 17 |
| `container-only.json` | 5 | 5 | 21 | 29 |
| `multi-evidence.json` | 4 | 5 | 21 | 29 |

### Registry, aliases, weak crypto, and PQC

Registry version tested: `2026.09.11`.

Verified aliases and canonical results:

| Input | Result |
|---|---|
| `AES256` | `AES-256-GCM` |
| `AES-256` | `AES-256-GCM` |
| `EVP_aes_256_gcm` | `AES-256-GCM` |
| `SHA1` | `SHA-1` |
| `SHA-1` | `SHA-1` |
| `rsa1024` | `RSA1024` |
| `X25519` | `X25519` |

Also verified:

- RSA 1024 is identified as weak.
- AES-ECB is identified as weak.
- AES-256-GCM is not identified as weak.
- RSA encryption maps to ML-KEM targets.
- ECDSA signing maps to ML-DSA targets.
- RSA OID lookup succeeds for `1.2.840.113549.1.1.1`.
- OpenSSL library capability lookup returns registered capabilities.

### Scheduler and caching

Verified target classification for repository, binary, container tar, endpoint, and cloud labels. Verified surface triage for source, dependency, certificate, container, binary, and skipped documentation files.

The binary route is correctly cheap-first:

```text
lief → yara-x → capa-quick
```

Low-confidence binary evidence triggers escalation. Content-hash cache hit accounting also passed, including a 100% hit-rate check after storing and retrieving the same key.

### Evidence fusion and operation construction

Scenario: two direct-use AES-ECB signals at the same operation location plus one dependency-only OpenSSL signal.

Verified:

- Two duplicate direct-use signals merge into one operation.
- Dependency-only evidence remains separate from direct-use evidence.
- Direct-use evidence receives `Confirmed` or `Probable` usage state.
- Test fixtures become `FalsePositiveSuppressed`.
- Checksum-only evidence becomes `FalsePositiveSuppressed`.
- Sensitive key/private-key snippets are redacted.
- The public deduplication API removes duplicate operation records deterministically.

### Graph construction and queries

All four fixture graphs built successfully. Graph index queries for risky nodes and service tracing returned valid list results.

Sample graph output from `multi-evidence.json`:

```text
Nodes:
ast:43666eeb8d40ff8f
ast:4b4866f6816f2251
ast:53098eba6e646c72
ast:ed31b807963deab2
ast:ffa252efe9e1e624
lib:cryptography@44.0.0
lib:ecdsa@0.19.0
lib:hashlib
lib:pycryptodome@3.20.0
op:054fce3c54fbd2ef
op:6ade0fc5a7e7b903
op:8943b1f62e707f83
```

Sample edges:

```text
lib:cryptography@44.0.0 --provides--> ast:4b4866f6816f2251
lib:cryptography@44.0.0 --provides--> ast:ffa252efe9e1e624
lib:ecdsa@0.19.0 --provides--> ast:43666eeb8d40ff8f
lib:hashlib --provides--> ast:53098eba6e646c72
lib:pycryptodome@3.20.0 --provides--> ast:ed31b807963deab2
op:054fce3c54fbd2ef --implements--> ast:43666eeb8d40ff8f
op:054fce3c54fbd2ef --depends_on--> lib:ecdsa@0.19.0
op:6ade0fc5a7e7b903 --implements--> ast:4b4866f6816f2251
```

### Risk engine scenarios

| Scenario | Mosca | Score | Class |
|---|---|---:|---|
| Internet-facing RSA-1024 signing, critical data, 15-year lifetime | `15 + 3 > 10` | 0.925 | Critical |
| Confirmed AES-ECB | `5 + 3 <= 10` | 0.408 | Medium |
| Confirmed AES-256-GCM | `5 + 3 <= 10` | 0.302 | Low |
| OpenSSL dependency-only / ProvidedOnly | `5 + 3 <= 10` | 0.390 | Low |

The Mosca trigger itself passed both true and false cases. Risk outputs include assumptions for default lifetime, migration time, exposure, criticality, and quantum timeline values.

### Recommendation mapping

All **17/17** tested policy mappings matched their expected rule and migration guidance:

| Rule | Expected guidance |
|---|---|
| `RSA-ENC` | ML-KEM / hybrid KEM |
| `RSA-SIG` | ML-DSA / SLH-DSA |
| `DH` | ML-KEM hybrid key exchange |
| `ECDH` | ML-KEM hybrid key exchange |
| `ECDSA` | ML-DSA / SLH-DSA |
| `EDDSA` | ML-DSA / SLH-DSA |
| `TLS-OLD` | TLS 1.3 |
| `AES-ECB` | AES-256-GCM / ChaCha20-Poly1305 |
| `CBC-NO-AUTH` | AEAD upgrade |
| `DES-3DES-RC4` | AES-256-GCM / ChaCha20-Poly1305 |
| `MD5-SHA1` | SHA-256 / SHA-384 / SHA-3 |
| `PBKDF2-WEAK` | Argon2id / stronger password policy |
| `AES128-LONG` | AES-256-GCM |
| `PQC-OK` | Verify parameters and implementation maturity |
| `HYBRID-OK` | Verify interoperability and certificate strategy |
| `CLASSICAL-OK` | Keep strong primitive and monitor |
| `REVIEW` | Confirm usage before selecting migration path |

All four CIR fixtures also produced one recommendation per operation.

## Performance benchmarks

Each benchmark reports minimum, median, p95, and maximum per-call wall-clock time. Timings are milliseconds and were measured inside `.venv-p1` using `time.perf_counter()`.

| Operation | Iterations | Min | Median | P95 | Max |
|---|---:|---:|---:|---:|---:|
| CIR validation | 1,000 | 4.5253 | 6.2282 | 10.7487 | 44.6985 |
| Risk scoring for fixture | 1,000 | 0.1744 | 0.1984 | 0.3458 | 0.5845 |
| Recommendations for fixture | 1,000 | 0.0805 | 0.1033 | 0.2134 | 0.3160 |
| Graph construction for fixture | 1,000 | 0.1067 | 0.1227 | 0.2118 | 0.8504 |
| Operations from 30 raw hits | 1,000 | 0.4015 | 0.4708 | 0.8009 | 1.5347 |
| Full fixture pipeline | 500 | 5.1116 | 7.3291 | 11.7238 | 43.1499 |
| Operations from ~1,000 raw hits | 100 | 14.1481 | 18.2850 | 26.6345 | 65.4402 |

The full pipeline benchmark used `multi-evidence.json` and executed validation, graph construction, risk scoring, and recommendations. It did not perform filesystem scanning or call external tools.

## Findings and limitations

1. **Core behavior is functioning:** all requested isolated component checks and scenario mappings passed.
2. **The core stages are lightweight:** graph, risk, and recommendation stages are sub-millisecond at the tested fixture size; validation dominates the normal fixture pipeline.
3. **Packaging issue:** `pip install -e .` fails because setuptools treats `referenceDocs` as a second top-level package. This was not fixed because it is outside the requested Person 1 test scope.
4. **ProvidedOnly classification:** the current risk implementation caps dependency-only results at `Low` with score `0.390`. The architecture reference describes dependency-only evidence as `Informational`; this policy difference should be reviewed before final calibration.
5. **Alias semantics:** the registry intentionally maps broad inputs such as `AES256` and `AES-256` to `AES-256-GCM`, and `rsa1024` to `RSA1024`. This passed the current registry behavior, but the canonical naming policy should confirm whether those broad aliases are sufficiently precise.
6. **No scanner claims:** detection recall, precision, file throughput, container layer speedup, and binary-analysis performance were not measured because Person 2 scanners are not implemented and were intentionally excluded.
7. **No production claims:** these are deterministic unit/microbenchmarks on synthetic fixtures, not SIH accuracy or enterprise-scale performance results.

## Overall assessment

Person 1’s current standalone pipeline is internally coherent and performant for synthetic CIR evidence. Schema/model handling, registry logic, fusion, operation grouping, graph construction, Mosca risk scoring, and deterministic recommendation selection all passed the requested checks. The next meaningful validation step is to feed real Person 2 detector outputs into the existing `build_operations` boundary and repeat the same assertions; no CLI, GUI, or integration wiring is required for that test.
