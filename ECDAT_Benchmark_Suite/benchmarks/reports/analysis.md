# ECDAT fast benchmark failure analysis

Run: `python -m benchmarks.runner --mode fast`  
Result: **38 passed, 8 failed, 1 repository run** (`R12`, Express).  
The run exits 1 because synthetic failures remain. Ground truth and thresholds were not changed.

## Framework integration fixes applied

- Added the documented top-level `benchmarks` import path for the checked-in suite.
- Made repository RSS measurement work on Windows.
- Adapted configured GitHub repository URLs to the current production local-path contract by downloading them into a temporary cache before calling `ScanRequest`/`ScanOrchestrator`.
- Normalized CIR evaluation at the benchmark boundary: operations now join their referenced assets, and risks/recommendations are read from `cir`.

These changes explain the initial reduction from 34 apparent failures to 8 real failures; no scanner, fusion, risk, recommendation, ground-truth, or threshold logic was weakened.

## False positives

- **FP001 — `source` scanner / preprocessor handling.** Code inside `#if 0` was reported as a confirmed AES-256-GCM operation. The finding evidence is `source:api-call` at `FP001_adversarial_names/main.c:12`; fusion preserves it as `Confirmed`. Responsible path: source C/API extraction, specifically inactive-preprocessor exclusion. The false-positive decision is not caused by risk or recommendation.

## False negatives

- **D09 — source scanner + fusion.** `EVP_CIPHER_fetch(0, name, 0)` with an environment-selected cipher produced no operation matching the required confirmed usage. Responsible path: dynamic-cipher handling in the source API scanner, followed by fusion's unresolved-capability classification.
- **S011 — source scanner/API resolution + fusion.** RC4 is detected only as an unresolved `EVP_EncryptInit_ex` capability (`canonical: OpenSSL`, `usage_state: Probable`), so the expected RC4 operation is missed. Responsible path: OpenSSL cipher-argument resolution and fusion usage classification.
- **S017 — source Java scanner.** `KeyPairGenerator.getInstance("RSA"); k.initialize(1024)` yields RSA without the 1024-bit asset parameter, so the exact oracle match is missed. Responsible path: Java source/API extraction and key-size/dataflow propagation.
- **S021 — source Go scanner/API knowledge.** `ecdh.X25519().GenerateKey(nil)` produces no X25519 operation. Responsible path: Go ECDH/X25519 signature rule and parser mapping in the source scanner.
- **S025 — source Python scanner/API knowledge.** `PasswordHasher().hash()` is not recognized as an Argon2 operation. Only the dependency finding survives, so the expected operation is missed. Responsible path: Python AST/API signature coverage; fusion then correctly retains dependency-only evidence.
- **S026 — Nginx config scanner.** `ssl_protocols TLSv1;` is not emitted as the expected `TLS1.0` asset. Responsible path: Nginx protocol normalization in `NginxScanner`; the current branch handles legacy protocol text as generic SSL or omits it from the expected canonical form.
- **S033 — Terraform config scanner.** An `aws_kms_key` resource with rotation enabled produces no KMS finding. Responsible path: Terraform KMS resource/config extraction; the current matcher looks for KMS ID/ARN/key attributes rather than this resource declaration.

## Wrong classification

No independent wrong-classification failure remains after evaluation-boundary normalization. The operation-type values on the remaining failures are consistent with the observed evidence; S011 and S025 are semantic usage/detection failures listed above.

## Wrong usage state

- **D09 — expected `Confirmed`, no operation emitted.** Root cause is the unresolved dynamic source call in the source scanner/fusion path.
- **S011 — expected `Confirmed`, actual `Probable`.** Root cause is unresolved RC4 cipher selection in source API extraction/fusion.
- **S025 — expected `Confirmed`, actual `ProvidedOnly`.** Root cause is missing Python `PasswordHasher` operation detection; the dependency scanner's `ProvidedOnly` state is internally consistent for the evidence it received.

## Wrong risk score

No wrong-risk-score failure is asserted by this fast suite. The benchmark currently evaluates operation matching, forbidden operations, and recommendation presence; it does not compare risk scores against a numeric oracle. Risk attribution therefore remains untestable here, not passing.

## Wrong recommendation

No standalone recommendation-component failure remains. The S026 required recommendation is absent because its upstream TLS1.0 operation is absent; the primary fault is `NginxScanner`, not `recommend.py`.

## Performance regressions

No regression can be established: the suite has no baseline file in this run. The R12 repository run completed in approximately **0.14 s** with measured peak RSS approximately **23.4 MiB**. This is an observation, not a regression verdict.

## Artifacts

- [latest benchmark JSON](latest.json)
- [runner summary](latest.md)
