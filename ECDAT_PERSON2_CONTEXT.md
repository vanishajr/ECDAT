# ECDAT — PERSON 2 AUTHORITATIVE CONTEXT

## Role

Person 2 owns the ECDAT Discovery Engine and all cryptographic detection surfaces.

Person 2 owns:

- source detection
- dependency/library detection
- binary detection
- container detection
- configuration detection
- certificate/key detection
- runtime detection
- cloud/AWS detection
- finding identity/correlation
- detector evidence
- detector → CIR-compatible JSON handoff

Person 1 owns:

- CIR/core intelligence
- evidence fusion
- operation reconstruction
- graph intelligence
- risk
- PQC recommendations

Person 3 owns:

- CLI/GUI
- reports/exports
- final benchmark harness/product views

Integration is through JSON/API/file contracts. Do not introduce hidden coupling.

---

# CURRENT PROJECT STATE

Pass 1 has already been completed.

The current regression baseline is believed to be 61/61 tests passing, but this MUST be verified from the repository. Do not rely on an old prompt claiming 53/53.

Pass 2 is now the active phase.

Pass 2 must first audit the actual Pass 1 implementation before making benchmark conclusions.

There is a known historical evaluator failure involving:

    get_key_sizes

Historical traceback:

    evaluate_pass2.py
    → run_full_evaluation
    → run_source_evaluation
    → scanner.scan
    → _scan_file
    → AST visitor
    → visit_FunctionDef
    → visit_Call
    → _check_name_call
    → _create_finding
    → get_key_sizes

Historical failing line:

    key_sizes = get_key_sizes(canonical_norm)

DO NOT assume this issue still exists. Verify the current repository first.

---

# PASS 2 OBJECTIVE

Evaluate and improve the Discovery Engine based on actual evidence.

The objective is NOT to claim that the architecture exists.

The objective is to determine:

- what actually works;
- what does not work;
- what is detected;
- what is missed;
- what produces false positives;
- whether parameters are resolved;
- whether usage states are correct;
- whether findings correlate correctly;
- whether scanner failures are isolated;
- whether evaluation logic is correct;
- whether performance requirements are met.

No invented metrics.

No unsupported claims.

---

# PASS 1 AUDIT REQUIREMENT

Before Pass 2 evaluation, audit what Pass 1 actually implemented.

Check:

- asset identity/correlation
- usage states
- signature registry
- CIR validation
- evidence security/redaction
- graph integrity
- scanner failure isolation
- source scanner
- dependency scanner
- binary scanner
- container scanner
- config scanner
- certificate/key scanner
- runtime scanner
- AWS scanner
- CLI
- regression tests
- Windows compatibility

For each area determine whether it is:

- IMPLEMENTED
- IMPLEMENTED BUT WEAK
- PARTIALLY IMPLEMENTED
- UNTESTED
- MISSING
- BROKEN
- UNKNOWN

Base the status on actual code and tests.

---

# SOURCE DETECTION

Target:

- 95%+ recall
- <5% false positives

Expected capabilities include:

- RSA
- DSA
- DH/FFDHE
- ECDH
- ECDSA
- X25519/X448
- Ed25519/Ed448
- ElGamal
- AES
- DES
- 3DES
- RC4
- ChaCha variants
- Blowfish
- Twofish
- Camellia
- IDEA
- SM4
- MD5
- SHA families
- BLAKE
- RIPEMD
- HMAC
- CMAC
- GMAC
- Poly1305
- HKDF
- PBKDF2
- bcrypt
- scrypt
- Argon2
- ML-KEM/Kyber
- ML-DSA/Dilithium
- SLH-DSA/SPHINCS+
- FN-DSA/Falcon
- HQC
- hybrid PQC constructions

Detection should use appropriate combinations of:

- Semgrep
- Tree-sitter/AST
- API/call extraction
- constants
- limited dataflow
- signature registry
- dependency/library evidence

Do not turn ECDAT into generic SAST or regex-only detection.

---

# USAGE STATES

The system uses:

- Confirmed
- Probable
- Possible
- ProvidedOnly
- FalsePositiveSuppressed

Dependency capability alone must not be treated as confirmed algorithm usage.

Example:

OpenSSL dependency with no matching usage evidence:

    ProvidedOnly

Direct source API plus resolved parameters:

    Confirmed

Usage-state assignment must be verified in actual implementation and tests.

---

# SIGNATURE REGISTRY

Canonical names, aliases, OIDs, library APIs, weak modes, key sizes, and PQC mappings should be normalized through the signature registry.

Do not duplicate algorithm knowledge unnecessarily across scanners.

---

# DEPENDENCY DETECTION

Expected ecosystems include:

- npm
- pip
- cargo
- Go modules
- Maven
- Gradle
- gem
- composer
- OS packages

Expected tooling/parsers may include:

- Syft
- cdxgen
- package-manager parsers

Map packages to crypto capability.

Dependency capability alone must produce ProvidedOnly unless actual usage evidence exists.

Do not claim support for an ecosystem that returns empty/no-op results without evidence.

---

# BINARY DETECTION

Expected architecture:

Cheap first:

- LIEF
- imports
- symbols
- sections
- libraries
- architecture
- strings
- YARA-X

Escalate only when necessary:

- capa
- FLOSS
- Ghidra

Heavy analysis should not be the default path.

Imports/library presence alone must not automatically prove algorithm usage.

Target:

- 90%+ detection

---

# CONTAINER DETECTION

Containers/images should support:

- Docker/OCI image tar/rootfs
- package detection
- binary detection
- config detection
- inner scanner execution
- image/layer caching

Repeated scans should target:

- 70%+ faster execution through valid caching

Cache correctness matters as much as cache speed.

---

# CONFIGURATION DETECTION

Relevant configurations include:

- nginx
- Apache
- Envoy
- OpenSSL
- YAML
- TOML
- Kubernetes
- Terraform
- Docker Compose

Detect where applicable:

- TLS versions
- cipher suites
- certificate paths
- key paths
- KMS/provider references

Preserve exact path/line evidence where possible.

---

# CERTIFICATE / KEY DETECTION

Expected formats:

- PEM
- DER
- JKS
- PKCS#12/PFX
- SSH
- JWK/JWKS

Extract metadata such as:

- subject
- issuer
- validity
- key algorithm
- key size
- curve
- signature algorithm
- SAN
- fingerprint

Never store raw private keys.

Secrets/key discovery must redact sensitive material.

---

# RUNTIME DETECTION

Expected runtime probing may include:

- HTTPS
- TLS
- STARTTLS
- SSH

Where supported, capture:

- negotiated protocol
- negotiated cipher
- certificate chain
- signature algorithm
- weak protocol configuration

Runtime failures must degrade gracefully.

---

# CLOUD

AWS support includes read-only inspection of:

- KMS
- ACM
- ELB/ALB TLS metadata
- relevant tags/configuration

Never require or expose secrets.

Azure/GCP are optional.

---

# EVALUATION

Existing evaluator:

    ecdat/benchmarks/evaluate_pass2.py

Ground truth:

    ecdat/tests/fixtures/source

Evaluation must correctly measure:

- TP
- FP
- FN
- precision
- recall
- F1
- accuracy
- FPR
- FNR
- specificity
- detection time
- peak memory

Verify evaluator matching/correlation logic before trusting results.

---

# MISUSE CASES

Evaluation should include cases such as:

- AES-ECB
- unauthenticated AES-CBC
- hardcoded keys
- weak key sizes
- MD5 password hashing
- SHA-1 signatures
- RSA-1024
- RSA-2048
- TLS 1.0
- TLS 1.1
- expired certificates
- weak certificate signatures
- dependency-only ProvidedOnly

Also test:

- aliases
- wrappers
- constants
- cross-file usage
- framework APIs
- library imports without actual use

---

# PERFORMANCE

Acceptance criteria include:

- 100k LOC scan under 60 seconds
- peak RAM below 1 GB

These are REAL project acceptance criteria.

Do not claim success without actually measuring them.

Measure where possible:

- total time
- files/sec
- MB/sec
- peak memory
- CPU
- cache hit rate
- expensive analyzer invocation count
- detector time
- raw findings
- merged findings
- duplicate reduction

---

# ARCHITECTURE

The intended staged pipeline is:

0. inventory/hash
1. triage
2. cheap source analysis
3. candidate dataflow
4. dependency scan
5. binary cheap pass
6. binary expensive escalation
7. container cache + inner scans
8. evidence merge
9. risk on resolved operations

ECDAT reconstructs cryptographic systems rather than simply matching keywords.

Do not introduce:

- generic SAST
- regex-only final truth
- LLM-based detection
- LLM-based recommendations
- unsupported accuracy claims
- unsupported performance claims
- raw secret storage

---

# PERSON 2 EXIT CRITERIA

Before declaring Pass 2 complete:

1. Pass 1 audit completed.
2. Foundational Pass 1 issues fixed where necessary.
3. Full regression suite passes.
4. Actual test count recorded.
5. Existing evaluator works correctly.
6. Ground truth integrity verified.
7. TP/FP/FN metrics produced.
8. Source detection evaluated.
9. Dependency detection evaluated.
10. Binary detection evaluated.
11. Container detection evaluated.
12. Config detection evaluated.
13. Certificate/key detection evaluated.
14. Runtime detection evaluated where available.
15. AWS detection audited.
16. Usage states verified.
17. Finding correlation verified.
18. Scanner failure isolation verified.
19. Performance measured.
20. 100k LOC requirement explicitly evaluated.
21. No unsupported claims made.
22. Detector  Person 1 CIR handoff remains contract-compatible.
