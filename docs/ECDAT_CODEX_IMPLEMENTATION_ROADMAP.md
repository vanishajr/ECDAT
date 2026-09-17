# ECDAT Architecture-Convergence Implementation Plan for Codex

> **Purpose:** This file is an execution plan for converting the current ECDAT prototype into the architecture described in `SIH26164_ECDAT_Solution_Architecture(3).pdf`.
>
> **How to use:** Put this file at the repository root. When asked to implement a phase, read this file, inspect the actual repository, implement only that phase plus required compatibility fixes, run the required tests/builds, and report exactly what changed and what remains.
>
> **Primary target:** By the end of all phases, both CLI and React GUI must use the same production scanning core and should achieve **at least 8/10 overall solution readiness/result quality** against the acceptance rubric near the end of this document.
>
> **Do not optimize for appearance over correctness.** The core differentiator is evidence-driven cryptographic discovery, operation/system reconstruction, confidence-aware fusion, quantum risk analysis, and explainable migration guidance.

---

# 0. Product thesis and non-negotiable architecture

ECDAT is **not** a regex scanner and must not behave like a collection of unrelated scanners hidden behind checkboxes.

The target system is:

```text
Input(s)
  ↓
CLI / React GUI / CI
  ↓
Single ScanOrchestrator
  ↓
InputRegistry.normalize()
  ↓
Inventory + recursive artifact discovery
  ↓
AdaptiveScheduler.triage()
  ↓
Scan plan
  ↓
Cheap scanners in parallel
  ↓
Candidate evaluation
  ↓
Selective expensive escalation
  ↓
Evidence normalization + fusion
  ↓
Operation reconstruction
  ↓
CIR
  ↓
Crypto Knowledge Graph / system reconstruction
  ↓
Quantum/classical risk
  ↓
PQC/classical/hybrid recommendations
  ↓
Canonical scan result + persistent storage
  ↓
CLI / GUI / PDF / HTML / JSON / SARIF / CSV / CycloneDX CBOM
```

The scanner must automatically discover all **local/static** scan surfaces available in the supplied input. The user should not need to know whether a repo contains binaries, certificates, configs, manifests, archives, or container artifacts.

External actions remain permission-gated:

- cloud inventory
- runtime network probing
- pulling remote container images
- building container images
- any action requiring credentials or network access

Core architectural rules:

1. **One runtime pipeline** for CLI, GUI and CI.
2. **CIR + crypto graph** are the internal semantic model. Do not introduce LLVM/MLIR.
3. **Inventory and route first.**
4. **Cheap analysis before expensive analysis.**
5. **Escalate only candidates.**
6. **Separate “library provides algorithm” from “application actually uses algorithm.”**
7. **Risk resolved operations/systems, not raw keyword hits.**
8. **Recommendations are deterministic/rule-driven.**
9. **Missing scanners/tools must be visible, never silently interpreted as “nothing found.”**
10. **No mock data or mock scoring in production output.**
11. **Never store raw private keys/secrets.**
12. **Preserve historical tests/docs unless genuinely updating them. Do not delete tests/docs merely to make the new runtime cleaner or to make tests pass.**
13. Dead or historical runtime paths may be quarantined/deprecated, but production code must have one clear path.
14. Every phase must keep `python -m ecdat.cli --help` functional and the frontend production build passing unless the phase explicitly requires a temporary interface migration and fixes it before completion.

---

# 1. Known current implementation state

Before changing code, verify this state against the repository. Treat filenames below as strong hints, not assumptions if the repo has moved.

## Current real GUI path

```text
frontend/src/App.tsx:analyse()
  → POST /api/scan-jobs
  → ecdat/web/server.py:_start_job
  → thread _run_job
  → ecdat/adapters/pipeline.py:run_real_scan()
  → ecdat/scanners/discovery.py:DiscoveryEngine.scan_and_emit_cir()
  → adapters/normalize
  → core/cir_validate
  → core/api.enrich_cir
  → server.py:_result_payload
  → GET /api/results/<scan_id>
```

This currently bypasses `ecdat/core/scheduler.py`.

## Existing but unused architecture components

`ecdat/core/scheduler.py` already contains concepts similar to:

- `InputRegistry`
- `AdaptiveScheduler`
- `ScanCache`
- input-kind inference
- target hashing
- triage
- cheap-first routing
- `should_escalate()`
- parallel path scanning

The problem is not that these ideas do not exist. The problem is that the real GUI/CLI pipeline does not execute through them.

## Current scanner behavior

### Source
Current production `SourceScanner` is effectively Python-centric. C/C++ source such as OpenSSL is not semantically analyzed through the real path. A Semgrep scanner may exist but is not correctly wired into the production source scanner.

### Dependencies
Common manifests are handled, but native C/C++ ecosystems are weak. Missing/weak coverage likely includes:

- CMake
- Conan
- vcpkg
- Meson
- Autotools
- pkg-config linkage/context

### Binary
Binary support exists but is not part of the default GUI scan. Cheap scanners include strings and optionally LIEF/YARA depending on availability.

### Config
Nginx/Apache/Envoy/OpenSSL/Kubernetes/Terraform/generic configuration support exists.

### Certificates/keys
PEM/DER/JKS/PKCS#12/JWK/SSH handling exists and is part of default scanning.

### Containers
There are duplicated/parallel container implementations. Dockerfile-aware logic exists in one implementation but the production discovery path uses another. Container analysis is opt-in, cache behavior is incomplete, and nested/inner artifacts are not yet handled as the architecture requires.

### Archives
Only a very limited top-level/single-file archive extraction case exists. Nested archives and archives mixed into repositories are not centrally discovered and recursively triaged.

### Runtime/cloud
Implementations exist, but are opt-in and not yet tightly linked into system reconstruction.

## Current orchestration behavior

- scanner family selection is essentially a static allow-list
- scanner families run in parallel
- each scanner performs its own filtering
- no central inventory-to-route decision
- no real cheap→expensive escalation
- `should_escalate()` is effectively unused
- generic content cache is not the primary runtime behavior
- container caching exists partially
- no production input registry normalization
- current quick/standard/deep behavior is not meaningfully differentiated
- binary is not part of the default GUI scan
- user-visible scanner checkboxes determine local discovery coverage

## Current fusion / operation / graph behavior

- discovery-layer correlation is mainly proximity/grouping based
- `core/fusion.py` is not the authoritative production fusion path
- `core/operations.py` is not the authoritative production operation reconstruction path
- raw findings can map too directly to operations
- production graph is thinner than the intended `core/graph.py` model
- risk and recommendations run, but on weaker upstream semantics than intended

## Current GUI/result delivery behavior

The current frontend already has a useful visual foundation. The saved UI exposes:

- project upload
- GitHub integration
- quick/standard/deep selector
- manual scanner layer checkboxes
- analysis progress
- result tabs such as:
  - Analytics
  - Risk level
  - Graph
  - Findings
  - Assets
  - Operations
  - Recommendations
- report download
- export formats such as Markdown/JSON/CIR/SARIF/CSV

The saved result page currently shows high-level metrics such as risk level, findings, assets, operations, files scanned, severity counts, recent findings, and exports.

The **presentation shell is ahead of the underlying orchestration/semantics**. Do not rewrite the frontend from scratch without cause. Keep the useful design language, but make it present richer and more defensible data from the new pipeline.

## Current PDF/report problem

The existing exported PDF is a minimal one-page executive summary and can still expose stale/mock concepts such as:

- a legacy/mock risk score
- a separate “real P1” score
- mock migration placeholder text
- repeated temporary absolute file paths
- simple frequency counts without enough evidence/context
- insufficient operation/system explanation

This must be replaced with a judge-grade evidence-driven report backed only by real scan data.

---

# 2. Codex execution protocol for every phase

When the user says **“Implement Phase N”**, follow this process.

## 2.1 Inspect first

Before editing:

1. Read this phase.
2. Inspect the actual files named in the phase.
3. Search for all callers of functions/classes being changed.
4. Identify legacy vs production paths.
5. Run the smallest relevant existing test subset.
6. Do not assume the repository still exactly matches this document.

If actual repository structure differs, preserve the **architectural intent** and adapt the implementation.

## 2.2 Implementation rules

- Prefer extending/refactoring existing good code over parallel duplication.
- Avoid introducing a second implementation of the same abstraction.
- Avoid huge rewrites when an incremental migration can preserve behavior.
- Keep deterministic identifiers wherever the current project relies on them.
- Maintain Windows and Linux path handling.
- Use repo-relative paths in user-facing output when possible.
- Do not silently catch scanner errors and convert them to “0 findings.” Scanner failure must become structured diagnostic state.
- Do not fabricate risk context, scanner availability, tool results, confidence, or recommendations.
- Never persist secrets or private-key material.
- Keep runtime mocks/fixtures out of the production pipeline.
- Preserve historical tests/docs. Update active docs where needed; if historical references are intentionally stale, mark them historical rather than deleting them.

## 2.3 Test/build requirements after every phase

At minimum:

```bash
python -m ecdat.cli --help
```

Run the repo's Python test suite or the relevant subset.

Run frontend checks, using the repository's package manager, equivalent to:

```bash
npm run build
```

or the actual production build command.

Run lint/type checks if configured.

If a phase changes schemas, persistence, APIs, or result payloads, add regression tests for backward-compatible migration or intentionally update all affected consumers in the same phase.

## 2.4 Required phase completion report

After implementing a phase, report:

1. files changed
2. major behavior changes
3. tests/builds run and results
4. newly working capability
5. remaining known limitations
6. any intentionally deferred item
7. whether the next phase can safely start

Do not claim a phase is complete if its acceptance criteria are not met.

Do not automatically start the next phase unless explicitly asked.

---

# Phase 0 — Baseline audit and architecture guardrails

## Objective

Create an accurate baseline before architectural migration so later phases do not accidentally preserve dead paths or break working behavior.

## Inspect

At minimum inspect:

- `ecdat/cli.py`
- `ecdat/adapters/pipeline.py`
- `ecdat/adapters/scanner_policy.py`
- `ecdat/scanners/discovery.py`
- `ecdat/core/scheduler.py`
- `ecdat/core/api.py`
- `ecdat/core/fusion.py`
- `ecdat/core/operations.py`
- `ecdat/core/graph.py`
- `ecdat/core/risk.py`
- `ecdat/core/recommend.py`
- `ecdat/web/server.py`
- `frontend/src/App.tsx`
- storage modules under `ecdat/store/`
- all scanner-family implementations
- report/export modules
- current tests that exercise GUI/API/CLI scanning

## Tasks

1. Trace every production scan entry point:
   - CLI source scan
   - binary scan
   - container scan
   - cloud scan
   - CI scan
   - GUI scan
2. Identify direct `DiscoveryEngine` callers.
3. Identify every caller of:
   - `InputRegistry`
   - `AdaptiveScheduler`
   - `ScanCache`
   - `should_escalate`
   - `core.fusion`
   - `core.operations`
   - `core.graph`
4. Mark modules as:
   - production
   - reusable but currently unused
   - legacy
   - test-only
   - stale/backup
5. Record current tool integrations and availability behavior.
6. Run baseline tests/builds.
7. Add a short baseline document, for example:
   - `docs/implementation/current-runtime-baseline.md`
8. Add architecture-level regression tests where cheap to do so:
   - GUI real scan eventually calls a common pipeline wrapper
   - no mock scoring in current production result objects
   - scanner failure is distinguishable from zero findings

## Do not

Do not perform the full architecture rewrite in Phase 0.

## Acceptance criteria

- real runtime paths are documented
- dead/unused scheduler status is confirmed
- baseline tests/build results are recorded
- no existing functionality is removed
- known mock/legacy production outputs are identified for later removal

---

# Phase 1 — Create one production `ScanOrchestrator`

## Objective

Make one orchestration layer the only supported route for CLI, GUI and CI.

## Target

Create or evolve an abstraction similar to:

```python
ScanRequest
ScanPermissions
ScanProfile
ScanProgressEvent
ScanPlan
ScanResult

class ScanOrchestrator:
    def plan(request) -> ScanPlan: ...
    def scan(request, progress=None) -> ScanResult: ...
```

Exact names may differ if the repository already has suitable models.

## Inspect

- `ecdat/adapters/pipeline.py`
- `ecdat/scanners/discovery.py`
- `ecdat/core/scheduler.py`
- `ecdat/core/api.py`
- all CLI scan commands
- `ecdat/commands/ci_cmd.py`
- `ecdat/web/server.py`

## Tasks

1. Add `ecdat/core/orchestrator.py` or a clearly named equivalent.
2. Move orchestration ownership into this layer.
3. `run_real_scan()` should become a thin compatibility wrapper over the orchestrator.
4. GUI `_run_job` must call the orchestrator.
5. CLI commands must call the orchestrator.
6. CI must call the orchestrator.
7. Specialized commands such as `scan-binary` and `scan-container` may provide target hints/permissions, but must not use a different analysis pipeline.
8. Define structured progress events now, even if only a few stages emit them initially.
9. Preserve CIR/canonical validation already in the working pipeline.
10. Keep `DiscoveryEngine` as an execution utility if useful, but it must no longer own the whole architecture.
11. Add tests proving GUI/CLI/CI reach the same orchestration layer.

## Acceptance criteria

These paths converge:

```text
CLI ─┐
GUI ─┼→ ScanOrchestrator → shared analysis stages
CI  ─┘
```

No active production surface should have an independent scan implementation.

---

# Phase 2 — Activate InputRegistry, full inventory and safe recursive artifact discovery

## Objective

Given any local input, ECDAT should understand what it contains before analysis.

## Required target kinds

At minimum support normalization/classification for:

- repository
- directory
- source file
- generic file
- native binary
- archive
- container image reference
- Docker/OCI tar
- OCI layout
- rootfs
- certificate/key
- runtime endpoint
- cloud target

## Tasks

1. Integrate `InputRegistry.normalize()` into `ScanOrchestrator`.
2. Generate a stable scan job/target ID from normalized target information and content identity.
3. Build an `ArtifactRecord` or equivalent with fields such as:
   - relative path
   - absolute internal path
   - size
   - content hash
   - extension
   - MIME/content type
   - magic bytes / executable format
   - detected language
   - artifact category
   - archive/container metadata
   - candidate scanner routes
   - cache state
4. Prefer content/magic-based classification where possible; extension is a hint, not truth.
5. Recursively inventory directories.
6. Add safe recursive archive handling for:
   - ZIP
   - TAR
   - TAR.GZ/TGZ
   - other already-supported safe formats
7. Archive safety must include:
   - path traversal protection
   - maximum nesting depth
   - maximum expanded byte count
   - maximum file count
   - decompression-ratio limit
   - symlink/hardlink safety
8. Archives found *inside* repositories must be handled, not only an input consisting of exactly one archive.
9. Re-feed safely extracted artifacts into inventory/triage.
10. Upgrade `/api/inputs/inspect` to return real inventory summaries instead of only file counts/extensions.
11. Preserve upload and GitHub flows.
12. Use repo-relative display names instead of temp paths in user-visible scan metadata.

## Expected behavior

Input:

```text
openssl/
```

Inventory should identify, as applicable:

```text
C source
headers
Perl/Python/build scripts
configuration
certificates/test certs
generated or checked-in binaries
manifests/build metadata
archives
Docker/container definitions
```

without the user selecting scanners manually.

## Acceptance criteria

- nested archives are safely discoverable
- binaries/certs/configs inside a mixed repo are classified automatically
- inventory is deterministic
- target hashing works
- temp upload paths are not the primary user-facing identity

---

# Phase 3 — Make AdaptiveScheduler real: routing, profiles, cache, permissions and scan planning

## Objective

Make `AdaptiveScheduler` the production decision-maker rather than dead design code.

## Tasks

1. Route `ArtifactRecord`s centrally through `AdaptiveScheduler.triage()`.
2. Scanner-local `can_scan()` remains a defensive check, not primary discovery.
3. Implement meaningful `quick`, `standard`, `deep` semantics.
4. Remove fundamental local-static coverage from normal-user manual checkboxes.
5. Automatically enable applicable local analysis:
   - source
   - dependencies
   - binaries
   - configuration
   - certificates/keys
   - local container artifacts when directly supplied/detected
6. Keep explicit permissions for:
   - runtime probing
   - cloud APIs
   - remote image pull
   - container build
7. Implement a `ScanPlan` that records:
   - detected surfaces
   - scanners/tools to run
   - unavailable tools
   - expected escalation-capable stages
   - cache hits
   - skip reasons
   - permissions required
8. Expose scan-plan preview through API for GUI use.
9. Make all scanner failures structured:
   - success
   - unavailable
   - skipped by policy
   - skipped as irrelevant
   - failed
10. Activate generic `ScanCache`:
   - cache by content hash + scanner/tool version + relevant config/profile
   - invalidate when tool/rule version changes
11. Preserve/rework container layer cache to use the same cache philosophy.

## Profile semantics

### Quick

Run cheap/high-yield detection only:

- inventory + triage
- fast source pattern/API pass
- manifests
- config/cert parsing
- LIEF metadata/imports where available
- strings
- fast signatures
- no heavy decompilation
- very limited candidate reasoning

### Standard

Quick plus:

- AST/Tree-sitter candidate reasoning
- limited local/cross-file parameter resolution
- stronger signatures
- normal evidence fusion
- normal operation reconstruction
- selective binary behavior analysis when justified

### Deep

Standard plus selective expensive escalation:

- deeper wrapper/dataflow reasoning
- capa/FLOSS for qualifying binaries
- optional Ghidra/decompiler backend for high-value ambiguous cases
- deeper archive/container exploration within safety limits

Depth changes **analysis effort**, not whether ECDAT knows a binary/cert/config exists.

## Acceptance criteria

- `should_escalate()` has real production callers
- Quick/Standard/Deep produce observably different plans
- binary analysis is no longer omitted just because a user did not tick a box
- external actions still require explicit permission
- scan-plan data is visible to callers
- repeat scans demonstrate cache hits

---

# Phase 4 — Build a real multi-language source semantic engine, with C/C++ first

## Objective

Make repo scans useful for real enterprise codebases and specifically make OpenSSL/C projects meaningful.

## Priority order

1. C/C++
2. Python
3. Java
4. JavaScript/TypeScript
5. Go
6. C#
7. Rust

Reuse existing integrations wherever possible.

## Tasks

1. Wire existing Semgrep integration into the production source path.
2. Add/activate Tree-sitter or equivalent fast syntax parsing.
3. Keep Python AST support where it is better than generic parsing.
4. Route only source artifacts detected by inventory.
5. Add/expand registry-driven API knowledge for:
   - OpenSSL EVP
   - lower-level OpenSSL primitives
   - libsodium
   - JCA/JCE
   - BouncyCastle
   - Python `cryptography`
   - Python stdlib crypto/hash APIs
   - Node `crypto`
   - WebCrypto
   - Go `crypto/*`
   - .NET cryptography
   - RustCrypto
   - common TLS APIs
6. Extract semantic details where available:
   - operation type
   - algorithm
   - mode
   - padding
   - key size
   - curve
   - protocol
   - KDF/hash
   - provider/library
   - function/call site
7. Add candidate-only constant/parameter propagation.
8. Add limited wrapper resolution near crypto candidates.
9. Do not implement expensive whole-program analysis by default.
10. Distinguish:
    - implementation of an algorithm/library
    - API capability/provision
    - test vectors
    - actual application use
11. Add source evidence signal types so fusion can treat direct API calls differently from strings/comments/dependencies.
12. Suppress obvious comments/docs/generated/vendor-only noise where safe, but preserve traceability.
13. Add seeded multi-language fixtures with known ground truth.

## OpenSSL-specific acceptance

Scanning an OpenSSL source checkout must no longer produce approximately zero source-semantic results.

The scanner should understand representative calls and constructs such as:

- `EVP_EncryptInit_ex`
- `EVP_DecryptInit_ex`
- `EVP_DigestSignInit`
- `EVP_DigestVerifyInit`
- `EVP_PKEY_*`
- `SSL_CTX_*`
- `EVP_aes_*`
- digest constructors/providers
- TLS version/cipher configuration

At the same time, ECDAT must not claim “OpenSSL uses every algorithm it implements” as application use. Library implementation/capability evidence must be represented separately.

## Acceptance criteria

- C/C++ files are actually opened/analyzed
- Semgrep/Tree-sitter are wired into production
- direct API call evidence has higher semantic quality than regex strings
- seeded tests measure precision/recall by language/algorithm
- OpenSSL scan is materially more informative

---

# Phase 5 — Strengthen dependencies, configs, certificates/keys, Dockerfiles and imported BOMs

## Objective

Complete local static artifact coverage around source analysis.

## Dependency tasks

1. Preserve current common manifest support.
2. Add native project support where practical:
   - `CMakeLists.txt`
   - CMake package/link references
   - Conan
   - vcpkg
   - Meson
   - Autotools/configure metadata where useful
   - pkg-config references
3. Integrate Syft/cdxgen where available without making them hard requirements for basic local scans.
4. Map dependencies to a crypto-capability registry.
5. Dependency-only evidence must start as `ProvidedOnly` or similarly weak usage evidence.

## Config tasks

1. Preserve current Nginx/Apache/Envoy/OpenSSL/Kubernetes/Terraform/generic support.
2. Improve service-specific extraction:
   - TLS versions
   - cipher suites
   - cert/key references
   - KMS/key references
   - endpoints/listeners
   - container/service names
3. Emit graph-linkable context rather than only flat findings.

## Certificate/key tasks

1. Preserve support for:
   - PEM
   - DER
   - JKS
   - PKCS#12/PFX
   - JWK
   - SSH key formats
2. Extract metadata only:
   - fingerprint
   - key type
   - key size
   - curve
   - signature algorithm
   - validity
   - subject/issuer where relevant
   - path/resource
3. Never store raw private-key material.
4. If Gitleaks/TruffleHog are integrated, store only redacted evidence/fingerprint/type/location.
5. Link referenced certificates/keys to config/service/operation where evidence permits.

## Dockerfile/container-definition tasks

1. Make Dockerfile scanning part of local config/container-definition discovery.
2. Parse useful evidence:
   - base image
   - package installation
   - copied cert/config paths
   - exposed ports
   - entrypoint/service hints
3. A Dockerfile alone must **not** be treated as proof of final image contents.

## BOM import

If feasible in this phase, add import/enrichment for:

- CycloneDX JSON/XML
- SPDX

Imported BOM evidence should enter CIR as lower-level inventory/capability evidence and can be enriched by other detectors.

## Acceptance criteria

- native C/C++ dependency context improves
- cert/key output is secret-safe
- Dockerfile evidence is visible in a repo-only scan
- dependency presence does not equal confirmed crypto use
- config/cert evidence can later participate in graph reconstruction

---

# Phase 6 — Staged binary analysis with real escalation

## Objective

Implement the architecture's binary pipeline:

```text
metadata/imports
  ↓
strings
  ↓
signatures/constants
  ↓
behavior
  ↓
deobfuscation/decompiler only when justified
```

## Tasks

1. Make binary scanning automatic for binary artifacts found during inventory.
2. Cheap stage:
   - LIEF for ELF/PE/Mach-O metadata/imports/symbols
   - strings
   - fast YARA/YARA-X rules
3. Add signal metadata:
   - linked crypto library
   - crypto symbol
   - algorithm/mode string
   - OID
   - constants/signatures
   - binary offset
4. Wire `should_escalate()` to binary candidate state.
5. Escalation reasons should be explicit:
   - stripped
   - packed
   - ambiguous crypto evidence
   - weak confidence
   - conflicting evidence
   - high-value target
6. Candidate-only deeper stages:
   - capa
   - FLOSS
7. Optional deep-only backend:
   - Ghidra or equivalent, only if installed/configured
8. Tool availability must be reported.
9. Missing capa/FLOSS/Ghidra must reduce coverage status, not crash the scan.
10. Add binary fixtures:
    - dynamic linked
    - static linked
    - stripped
    - embedded crypto constants
    - non-crypto false-positive controls
11. Record:
    - number of binaries
    - cheap-pass candidates
    - escalated binaries
    - expensive-analysis rate
    - time per stage

## Acceptance criteria

- binary analysis runs without manual user selection when binaries are present
- expensive analysis runs on only a subset
- all escalation decisions are explainable
- binary evidence participates in later fusion
- false positives from plain strings are lower confidence than symbol/behavior evidence

---

# Phase 7 — Unify container scanning and complete runtime/cloud innovation paths

## Objective

Make containers first-class while keeping runtime/cloud safe and opt-in.

## Container tasks

1. Remove production ambiguity between duplicate container scanner implementations.
2. One production container engine must support, as practical:
   - Docker image reference
   - OCI image reference/layout
   - Docker/OCI tar
   - rootfs directory
   - Dockerfile/container definition evidence
3. Recognize `.tar`, `.tar.gz`, `.tgz` correctly when they are actual container archives.
4. Scan inner contents using normal artifact routing:
   - packages/dependencies
   - binaries
   - configs
   - certificates/keys
   - source if present
5. Integrate Syft/cdxgen/Trivy where available.
6. Cache by:
   - image digest
   - individual layer digest
7. Do **not** use only the first layer as a cache key.
8. Persist normalized evidence, not fragile scanner-object `__dict__` state.
9. Link inner evidence to image/layer/service context.

## Remote/build permission model

- Supplied local image/rootfs/tar → analyze automatically.
- Repo with Dockerfile only → analyze Dockerfile automatically.
- Pulling an image → ask/require explicit permission.
- Building a Dockerfile → ask/require explicit permission.

## Runtime tasks

At minimum provide one strong runtime path:

- TLS endpoint probing
- optional SSH probing

Prefer adapter integration with tools such as SSLyze/testssl where available.

Runtime evidence should record:

- endpoint
- protocol/version
- negotiated cipher/group
- certificate chain metadata
- exposure
- timestamp
- tool/version

Then link runtime evidence to matching config/cert/service when possible.

## Cloud tasks

Do not attempt perfect multi-cloud depth at the expense of core quality.

At minimum make one provider, preferably AWS if it is already strongest, genuinely useful for read-only inventory:

- KMS
- ACM
- ELB/TLS-related resources where available
- key specs
- cert metadata
- service linkage

Azure/GCP may remain narrower if necessary, but capability status must be honest.

## Acceptance criteria

- local container input is automatically recognized
- inner artifacts use the same scanners as local repos
- layer caching is correct
- runtime/cloud require explicit opt-in/credentials
- at least one runtime and one cloud path provide real graph-linkable evidence

---

# Phase 8 — Centralize evidence normalization/fusion and reconstruct real crypto operations

## Objective

Stop treating findings as the product. Findings are evidence. The product is resolved crypto operations/assets/systems.

## Tasks

1. Make `core/fusion.py` or its evolved equivalent the authoritative production fusion layer.
2. Retire discovery-only proximity correlation as the main confidence engine.
3. Every evidence signal should carry:
   - detector
   - signal type
   - location
   - algorithm candidate
   - parameters
   - confidence
   - reliability class
   - redacted snippet/details
   - usage implication
   - artifact/service/container context
4. Fusion should account for:
   - direct usage evidence
   - parameter resolution
   - binary corroboration
   - config/runtime agreement
   - dependency-only penalty
   - detector reliability
   - duplicate correlation
5. Implement consistent usage states:
   - `Confirmed`
   - `Probable`
   - `Possible`
   - `ProvidedOnly`
   - `FalsePositiveSuppressed`
6. Keep provenance so a merged result can show every contributing signal.
7. Activate `core/operations.py` or replace it with one authoritative operation builder.
8. Do **not** create one operation per raw finding.
9. Reconstruct semantic operations such as:
   - Encrypt
   - Decrypt
   - Sign
   - Verify
   - KeyExchange
   - Hash
   - KDF
   - TLS
   - Storage/key protection
10. Operation identity should be stable and based on semantic location/implementation/context.
11. Associate assets:
    - algorithm
    - key/cert
    - library/provider
    - protocol
12. Normalize/enrich CIR after reconstruction, then validate.
13. Preserve asset-only evidence where no operation can honestly be reconstructed.
14. Add tests where dozens of raw mentions collapse into a small number of correct operations.

## Critical false-positive rule

A crypto library that **provides** AES/RSA/RC4/etc. must not make the application appear to actively use all those algorithms.

Example progression:

```text
OpenSSL dependency present
  → Provides RSA/AES/etc. = ProvidedOnly

EVP_aes_256_gcm symbol imported
  → AES-GCM = Possible/Probable

direct source API + resolved mode + binary corroboration
  → AES-GCM operation = Confirmed
```

## Acceptance criteria

- production pipeline actually calls the real fusion layer
- production pipeline actually calls the operation builder
- operations are fewer and semantically stronger than raw findings
- usage-state reasoning is testable/explainable
- CIR reflects fused evidence, not only scanner hits

---

# Phase 9 — Build the intended Crypto Knowledge Graph and system reconstruction

## Objective

Connect evidence across surfaces into systems, not isolated rows.

## Required node concepts

As appropriate:

- source location/function
- binary
- dependency/library
- crypto asset
- crypto operation
- certificate/key
- config
- container/image
- service
- endpoint
- cloud resource
- owner/environment/context when supplied

## Required relationship concepts

Use existing schema naming where possible, but support semantics equivalent to:

- `USES`
- `PROVIDES`
- `IMPLEMENTS`
- `CONFIGURES`
- `PROTECTS`
- `EXPOSES`
- `RUNS_IN`
- `CONTAINS`
- `DEPENDS_ON`
- `REFERENCES`

## Tasks

1. Make `core/graph.py` or its evolved equivalent the authoritative graph builder.
2. Deduplicate graph entities before risk scoring.
3. Link source evidence to operations.
4. Link binary evidence to implementation/operations.
5. Link dependency evidence as provides/capability.
6. Link cert/key evidence to operations/services/config where justified.
7. Link containers/layers to binaries/configs/certs/services.
8. Link runtime endpoint evidence to service/config/cert.
9. Link cloud key/cert resources to services when identifiers/config evidence agree.
10. Preserve uncertainty in edges where linkage is inferred rather than observed.
11. Provide stable IDs.
12. Make graph adapters/query functions consume this graph, not the old minimal discovery graph.
13. Add reconstruction tests across source + config + cert + binary/container evidence.

## Acceptance criteria

A result should be able to explain a chain similar to:

```text
service
  RUNS_IN → container
  CONFIGURED_BY → nginx.conf
  USES → TLS operation
  PROTECTS_WITH → certificate
  IMPLEMENTED_BY → libssl/OpenSSL
  EXPOSES → endpoint
```

without inventing links unsupported by evidence.

---

# Phase 10 — Make risk and recommendations operate on real systems with explicit assumptions

## Objective

Make P1 risk and migration output defensible.

## Risk tasks

1. Risk operations/systems after fusion/graph resolution.
2. Do not compute a “risk” independently in UI/CLI from severity counts.
3. Remove legacy/mock risk from production outputs.
4. Preserve inputs such as:
   - quantum vulnerability
   - classical weakness
   - usage confidence
   - exposure
   - data confidentiality lifetime
   - migration/replacement lead time
   - business criticality
   - algorithm/key size/protocol
   - environment
5. Every context value must be tagged:
   - observed
   - inferred
   - user-supplied
   - unknown
6. Unknown values remain unknown. Do not silently insert enterprise-critical defaults that exaggerate risk.
7. Keep CRQC timeline/configurable policy explicit as an assumption rather than a hidden fact.
8. Show risk explanation and contributing factors.

## Recommendation tasks

1. Keep recommendations deterministic and policy/standards-driven.
2. Map operation semantics to migration paths:
   - RSA encryption/KEX → ML-KEM or hybrid
   - RSA/ECDSA/EdDSA signatures → ML-DSA/SLH-DSA/hybrid as appropriate
   - DH/ECDH/X25519 → hybrid ML-KEM migration path where ecosystem permits
   - weak TLS → modern TLS first, then PQ readiness
   - AES-ECB/CBC misuse → AEAD
   - DES/3DES/RC4 → modern AEAD
   - MD5/SHA-1 security use → modern hash
3. Do not blindly call all PQC usage safe.
4. Include:
   - rationale
   - target
   - compatibility
   - blockers
   - effort class
   - expected latency/cost class
   - standards/reference metadata
5. Recommender output must refer to the actual operation/system, not only a generic algorithm string.

## GUI/API context input

Add a mechanism for users to provide optional context:

- environment
- owner/team
- exposure
- business criticality
- data lifetime
- migration estimate

Context must be visibly user-provided.

## Acceptance criteria

- no mock risk appears in runtime/report output
- risk is based on resolved operations/systems
- assumptions are visible
- recommendations are operation-aware
- CLI/GUI/report share the same risk/recommendation data

---

# Phase 11 — Unified persistence, exports and CI behavior

## Objective

Make GUI and CLI use the same durable scan model and make every export derive from it.

## Persistence tasks

Create/evolve a shared repository layer such as `ScanRepository`.

At minimum persist or queryably represent:

- scan run metadata
- scan plan
- tool versions/capabilities
- raw/redacted evidence
- crypto assets
- crypto operations
- graph edges
- risk records
- recommendations
- enriched CIR
- canonical document
- cache/provenance metrics where useful

SQLite is sufficient.

The GUI should not rely only on process memory for completed scan results.

## Tasks

1. Move GUI completed scan data into the same persistence abstraction as CLI.
2. Keep canonical/CIR outputs internally consistent.
3. Add schema migration handling if DB shape changes.
4. Allow scan history/reopen where practical.
5. Make repeated runs cache-aware.
6. Ensure exports derive from persisted canonical/CIR/P1 data, not recomputation with separate logic.

## Export requirements

Support and validate:

- canonical JSON
- CIR JSON if exposed separately
- CSV
- SARIF
- CycloneDX CBOM JSON
- CycloneDX CBOM XML
- HTML report
- PDF report

Where relevant, validate against the target format/schema.

## CI tasks

1. CI uses the same orchestrator.
2. `--fail-on` is policy gating only.
3. CI does not replace P1 risk with a simplistic severity-weight score.
4. SARIF comes from real findings/operations with stable locations.
5. CI output includes scan limitations/tool unavailability when important.

## Acceptance criteria

- same input/profile/permissions produces equivalent core results from CLI and GUI
- completed GUI results survive process-level UI navigation/reload where intended
- exports agree on counts/IDs/risk
- CI gates real production results

---

# Phase 12 — GUI scan-plan UX and judge-grade result delivery

## Objective

Improve not only detection quality but **how results are communicated**.

Do not discard the current visual identity unless necessary. The current React UI already has a coherent design; improve information architecture and data fidelity.

---

## 12A. Replace scanner checkboxes with automatic discovery UX

Current normal-user behavior exposes checkboxes for:

- Source code
- Dependencies
- Binary analysis
- Configuration
- Certificates/keys
- Containers
- Runtime
- Cloud

This makes the user responsible for ECDAT's internal routing.

Replace the default UX with:

```text
Analysis configuration

Depth
[ Quick ] [ Standard ] [ Deep ]

Detected locally
✓ Source code
✓ Dependencies
✓ 14 binaries
✓ 61 configuration files
✓ 9 certificates/keys
✓ 3 archives
✓ Docker/container definition

External discovery
[ ] Pull/analyze referenced container images
[ ] Probe runtime endpoints
[ ] Connect cloud infrastructure

Advanced settings ▸
```

Manual scanner overrides can remain under **Advanced** for debugging/expert usage.

---

## 12B. Add scan-plan preview

Before scanning, show:

- normalized input type
- languages
- artifact counts
- detected binaries
- manifests
- configs
- cert/key artifacts
- archives
- container artifacts/definitions
- scanners planned
- missing optional tools
- expected cache hits
- depth/profile
- external permissions
- expected expensive stages

Do not invent time estimates unless there is data to estimate them reliably.

---

## 12C. Make live progress reflect the real architecture

Replace vague stages with real progress events such as:

```text
Inventory: 18,492 artifacts
Triage: 6,214 relevant artifacts
Source cheap scan: 1,240/3,100
Dependencies: complete
Binary cheap pass: 14/14
Binary escalation: 3/14 candidates
Certificates/config: complete
Evidence fusion
Operation reconstruction
Graph construction
Risk scoring
Recommendations
Persistence/export preparation
Complete
```

Expose scanner errors and unavailable tools in the progress/diagnostics experience.

---

## 12D. Redesign result information architecture

The UI should answer these questions quickly:

1. **What cryptography is actually used?**
2. **Where is it used?**
3. **How certain are we?**
4. **What is only provided by a dependency?**
5. **What is risky and why?**
6. **What should be migrated first?**
7. **What evidence supports each conclusion?**
8. **What did ECDAT fail or skip scanning?**

Recommended result areas:

### Overview

Show:

- target/repository identity
- commit/image digest when available
- scan timestamp
- profile
- files/artifacts scanned
- scanner coverage
- tool limitations
- number of:
  - raw evidence signals
  - unique assets
  - reconstructed operations
  - confirmed/probable/possible/provided-only usage
- overall P1 risk posture
- top actual risky operations/systems
- top migration priorities
- confidence distribution
- cache/escalation summary

Do **not** center the page around raw finding count alone.

### Crypto inventory / Assets

Columns/filters should include:

- canonical algorithm
- family
- mode
- padding
- key size
- curve
- protocol
- library/provider
- usage state
- confidence
- linked operations
- locations
- risk

### Operations

This should become a primary view.

For each operation show:

- operation type
- algorithm/mode
- parameters
- implementation/library/provider
- location/function/service
- usage state
- confidence
- risk
- linked key/cert
- evidence count/types
- linked graph context

Allow drill-down to evidence.

### Findings / Evidence

Make clear that findings are **evidence**, not necessarily unique risks.

Show:

- detector
- signal type
- repo-relative location
- redacted snippet/details
- confidence contribution
- usage implication
- linked operation/asset
- duplicate/fusion relationship
- suppression reason if suppressed

### Graph

Support:

- semantic node types
- relation labels
- filtering
- click-through to operations/assets/evidence
- confidence/observed-vs-inferred distinction where possible
- layouts that remain usable on medium-sized scans

Do not dump thousands of nodes by default. Start from risky systems or filtered neighborhoods.

### Risk

Show:

- P1 score/class
- risk factors
- quantum vs classical weakness
- Mosca-style assumptions
- exposure
- data lifetime
- migration time
- criticality
- usage confidence
- unknown context fields
- provenance for each contextual input

### Recommendations

Show:

- affected operation/system
- current algorithm
- target migration
- priority
- rationale
- compatibility
- blockers
- effort
- latency/cost class
- standards/reference metadata
- status/owner if user supplied

Allow grouping into a migration roadmap.

### Coverage / Diagnostics

Add a dedicated view or panel for:

- scanners/tools available
- scanners run
- scanners skipped
- scanners failed
- unavailable tools
- artifacts by type
- cache hit rate
- escalation rate
- scan duration per stage
- unsupported artifacts

This is essential for judge trust.

### Reports / Exports

Expose only formats that actually work and agree with canonical/CIR data.

---

## 12E. Replace the current minimal/mock PDF with a real report

The current PDF/report style must be retired from production.

The PDF must not contain:

- `[mock scoring]`
- “mock placeholder”
- contradictory legacy and P1 risk totals
- repeated temp absolute paths
- fake migration output
- unexplained giant finding counts as the main result

### Required PDF structure

#### 1. Executive summary

- target
- scan date/profile
- scan coverage
- overall risk posture
- number of real operations/assets
- top 3–5 priority systems/operations
- top migration actions
- important limitations

#### 2. Scan scope and methodology

- input kind
- artifact counts
- scanners/tools used
- unavailable tools
- profile/depth
- cache/escalation summary

#### 3. Cryptographic inventory summary

- algorithms/families
- usage-state distribution
- key/cert/protocol summary
- confirmed vs provided-only distinction

#### 4. High-priority operations/systems

For each:

- operation/system
- location
- usage confidence
- evidence summary
- risk
- rationale

#### 5. Quantum/classical risk analysis

- P1 risk
- risk factor breakdown
- Mosca/assumption fields
- unknown context explicitly shown

#### 6. Migration roadmap

- current
- target
- priority
- rationale
- blockers
- compatibility
- effort/cost/latency class

#### 7. Evidence and traceability

- representative evidence
- detector sources
- confidence/usage state
- repo-relative locations

#### 8. Coverage and limitations

- missing tools
- unsupported artifacts
- failed scanners
- unscanned external surfaces
- assumptions

#### 9. Appendix

- concise detailed table of findings/operations or references to machine-readable exports

### PDF quality rules

- use repo-relative paths
- readable page breaks
- no cut-off tables
- no single-line temp paths dominating pages
- consistent severity/risk terminology
- counts exactly match canonical result
- risk is P1/system risk, not a legacy mock
- no secret material
- generate from the same aggregate used by UI/HTML

---

## 12F. Improve HTML report

HTML report should be:

- self-contained/offline where practical
- derived from same report model as PDF
- searchable/filterable
- include overview, inventory, operations, risk, recommendations, coverage
- use safe redacted evidence
- not depend on the live React dev server

---

## 12G. CLI delivery quality

Human-readable CLI output should default to the most actionable summary:

```text
Scan complete
Target: ...
Profile: standard

Coverage:
  Source ........ OK
  Dependencies .. OK
  Binary ........ 14 scanned, 3 escalated
  Config ........ OK
  Certs/keys .... 9 metadata objects
  Runtime ....... not requested
  Cloud ......... not requested

Crypto usage:
  Confirmed ..... N
  Probable ...... N
  Possible ...... N
  Provided only . N

Risk:
  High (6.3)
  Top risks: ...

Migration:
  1. ...
  2. ...

Limitations:
  capa unavailable
  runtime not requested
```

Detailed output belongs behind flags/JSON/export commands.

## Acceptance criteria

- default GUI no longer requires local scanner checkboxes
- user can preview the real scan plan
- progress reflects real stages
- result views are operation/evidence-centric
- report has no mock output
- PDF/HTML/UI/CLI counts/risk agree
- diagnostic limitations are visible
- result delivery is substantially more useful than the current one-page frequency summary

---

# Phase 13 — Benchmark harness, OpenSSL acceptance suite and measurable result quality

## Objective

Prove that architecture improvements actually improve results.

A large scanner count is not success. Measure precision, recall, reconstruction quality, speed and false positives.

## Build benchmark fixtures

### Source

Seed synthetic and small real fixtures across:

- C/C++
- Python
- Java
- JS/TS
- Go
- C#
- Rust

Include:

- direct crypto calls
- wrappers
- constant indirection
- dead/test code
- comments containing algorithm names
- weak and strong configurations
- ProvidedOnly dependency cases

Metrics:

- precision
- recall
- algorithm classification
- operation-type classification
- parameter extraction rate
- wrapper detection rate

### Binary

Fixtures:

- dynamically linked
- statically linked
- stripped
- crypto constants
- non-crypto lookalikes

Metrics:

- recall
- false positives
- confidence quality
- stage timing
- expensive-analysis rate

### Containers

Fixtures containing:

- OS packages
- application deps
- binary
- config
- cert
- repeated unchanged layer

Metrics:

- inner-artifact coverage
- duplicate suppression
- graph linkage
- layer-cache speedup

### Runtime

Known local TLS endpoints/configs.

Metrics:

- protocol/cipher accuracy
- cert accuracy
- static/runtime agreement

### Graph

Known service fixture where source/config/cert/container refer to the same system.

Metrics:

- correct operations
- correct edges
- duplicate reduction
- incorrect-link rate

### Recommendation

Known scenarios:

- HNDL-sensitive public-key crypto
- internal short-lived data
- weak classical crypto
- secure symmetric crypto
- PQC already present

Metrics:

- correct risk category
- correct migration target class
- no unnecessary PQ migration for safe/non-security artifacts

---

## OpenSSL acceptance suite

Use an OpenSSL checkout or pinned representative subset as a high-value real benchmark.

Required outcomes:

1. C/C++ source is analyzed.
2. API/implementation evidence is discovered.
3. Build/dependency metadata is understood better than before.
4. Checked-in/generated binaries are automatically recognized if present.
5. Cert/config artifacts are discovered.
6. ECDAT distinguishes:
   - implementation/provision
   - tests/examples
   - actual operations/use
7. Result is not “thousands of raw RSA/TLS strings = thousands of independent risks.”
8. Risk and recommendations apply to reconstructed use where possible.
9. Repeat scan demonstrates caching.
10. Standard vs Deep shows sensible escalation differences.

Do not define success as a specific raw finding count.

---

## Baseline comparison targets

When available, compare with:

- grep/ripgrep pattern baseline
- CBOMkit/Sonar-like source baseline
- cdxgen crypto output
- Syft/Trivy package/container inventory
- strings/objdump binary baseline
- LIEF-only
- YARA-only

ECDAT's intended advantage:

- better linked coverage
- lower false positives
- richer operation reconstruction
- stronger evidence traceability
- actionable risk/migration output

## Performance metrics

Record:

- files/sec
- MB/sec where meaningful
- total scan time
- peak RSS
- cache hit rate
- repeat-scan speedup
- number/percentage of artifacts escalated
- time spent in expensive analysis

## Acceptance criteria

- benchmark command/script is reproducible
- fixtures include ground truth
- metrics are saved as JSON/CSV
- OpenSSL benchmark is repeatable
- no improvement claim is made without numbers

---

# Phase 14 — Final hardening, legacy quarantine and release gate

## Objective

Make the architecture unambiguous and remove production confusion without destroying history.

## Tasks

1. Search for alternate/legacy scan paths.
2. Ensure all production entry points call `ScanOrchestrator`.
3. Quarantine or clearly mark:
   - stale GUI implementations
   - backup GUI
   - dead scanner wrappers
   - old non-orchestrated analysis functions
4. Do not delete historical tests/docs solely because they mention fixtures/mocks.
5. Update active docs to describe the real pipeline.
6. Add a runtime test ensuring mock fixtures/scoring are not imported into production modules.
7. Add installation/capability documentation for optional tools:
   - Semgrep
   - Tree-sitter bindings
   - LIEF
   - YARA/YARA-X
   - capa
   - FLOSS
   - Docker/OCI tooling
   - Syft/cdxgen/Trivy
   - SSLyze/testssl
   - cloud SDK dependencies
8. Verify graceful degradation when optional tools are absent.
9. Verify Windows/Linux path behavior.
10. Verify report generation on representative scans.
11. Run full backend tests.
12. Run frontend typecheck/build/tests.
13. Run CLI smoke suite.
14. Run benchmark suite.
15. Record final known limitations.

## Final runtime shape

```text
CLI / GUI / CI
       ↓
ScanOrchestrator
       ↓
InputRegistry
       ↓
Inventory
       ↓
AdaptiveScheduler + ScanCache
       ↓
staged scanner execution
       ↓
Evidence fusion
       ↓
Operation reconstruction
       ↓
CIR validation
       ↓
Knowledge graph
       ↓
Risk + recommendations
       ↓
Persistent ScanRepository
       ↓
Canonical/export/report adapters
```

No production surface should bypass this architecture.

---

# 3. Final CLI behavior requirements

The exposed CLI may keep commands such as:

```text
scan
scan-binary
scan-container
scan-cloud
list
show
risk
recommend
export
report
gui
ci
```

But specialized scan commands are convenience entry points, not separate architectures.

## `scan`

A generic local scan must automatically detect relevant local artifacts.

Example:

```bash
ecdat scan ./repo
```

should discover source, binaries, manifests, configs, certs, archives, Dockerfiles, etc. automatically.

## `scan-binary`

Convenience for explicit binary target/profile tuning. It still uses the common orchestrator.

## `scan-container`

Convenience for image/rootfs/container targets. It still uses the common orchestrator and inner scanners.

## `scan-cloud`

Explicit cloud authorization/target path.

## `risk`

Reads stored real P1 risk. Does not recalculate fake severity weights.

## `recommend`

Reads/recomputes deterministic recommendation policy over stored semantic results as designed. No static mock fallback map.

## `ci`

Runs the same scan core and only applies CI pass/fail policy after real analysis.

---

# 4. Final GUI behavior requirements

A judge/user should be able to:

1. upload a file/folder/archive
2. select/paste a GitHub repository
3. see automatic input inspection
4. see detected artifact types
5. choose Quick/Standard/Deep
6. optionally authorize external runtime/cloud/container pull/build actions
7. preview planned scanners/tools
8. run analysis
9. watch meaningful architecture-stage progress
10. inspect:
    - overview
    - crypto inventory
    - operations
    - evidence/findings
    - graph
    - risk
    - recommendations
    - coverage/diagnostics
11. export:
    - PDF
    - HTML
    - JSON/CIR
    - CSV
    - SARIF
    - CBOM JSON/XML
12. understand limitations/missing tools

The GUI should **not** force the user to manually know that a repo contains binaries or certificates before scanning it.

---

# 5. Result-quality rules

These rules apply across CLI, GUI and reports.

## Never conflate

- dependency capability with actual use
- algorithm implementation with application use
- raw keyword count with operation count
- severity with quantum risk
- unknown context with high-risk defaults
- missing scanner/tool with zero findings
- multiple corroborating signals with multiple independent risks

## Every important conclusion should be traceable

For a risky operation, the user should be able to answer:

- what operation is this?
- what algorithm/mode/key/protocol?
- where is it?
- what library/provider implements it?
- what evidence found it?
- what is the usage state?
- what is confidence and why?
- what system/container/service is it part of?
- why is it risky?
- which risk inputs are observed vs inferred vs unknown?
- what migration is recommended and why?

---

# 6. Minimum final data model expectations

Do not force exact class names, but final semantics should support the equivalent of:

## ScanRun

```text
id
target
target_kind
content/commit/image identity
profile
permissions
timestamps
tool versions
status
scan plan
limitations
cache metrics
```

## EvidenceSignal

```text
id
detector
signal_type
artifact/location
algorithm candidate
parameters
confidence
reliability
usage implication
redacted evidence
metadata
```

## CryptoAsset

```text
id
canonical algorithm/family
mode
padding
key size
curve
protocol
version
provider/library
cert/key metadata
```

## CryptoOperation

```text
id
operation type
asset links
implementation
location
usage state
confidence
evidence links
context
```

## GraphEdge

```text
source
target
relation
confidence/provenance
```

## RiskRecord

```text
operation/system id
class
score
quantum factors
classical factors
Mosca/context inputs
input provenance
explanation
assumptions
```

## Recommendation

```text
operation/system id
target algorithms/pattern
priority
rationale
compatibility
blockers
effort
latency/cost class
references
```

---

# 7. Internal 10-point final readiness rubric

This is not a marketing score. Use it to decide whether ECDAT is genuinely at least **7/10**.

## A. Unified architecture — 1.0

**1.0**
- CLI/GUI/CI all use the orchestrator
- scheduler/input registry are real runtime components
- no alternate production pipeline

**0.5**
- mostly unified but one major surface bypasses it

**0**
- architecture diagram still differs fundamentally from runtime

## B. Automatic inventory/scheduling/cache — 1.0

**1.0**
- local artifact auto-detection
- safe recursive archive discovery
- meaningful profiles
- generic cache
- real escalation

**0.5**
- partial routing/cache or profiles still mostly cosmetic

## C. Source semantic coverage — 1.5

**1.5**
- C/C++ + several major languages
- semantic API extraction
- limited candidate dataflow/wrapper support
- OpenSSL benchmark useful

**1.0**
- C/C++ + Python and reasonable semantic patterns

**0.5**
- mostly Python/regex

## D. Binary + container depth — 1.5

**1.5**
- staged binaries + escalation
- real container inner scanning
- layer cache
- tool diagnostics

**1.0**
- solid basic binary/container scanning

**0.5**
- opt-in/basic only

## E. Fusion + operations + graph — 1.5

**1.5**
- evidence fusion is authoritative
- usage states reliable
- operations reconstructed
- cross-surface graph meaningful

**1.0**
- fusion/ops work but graph/correlation is limited

**0.5**
- mostly flat findings

## F. Risk + recommendation quality — 1.0

**1.0**
- system/operation based
- assumptions/provenance explicit
- deterministic migration guidance
- no mock scoring

**0.5**
- basic real risk/recommendations but thin context

## G. GUI/report/export delivery — 1.5

**1.5**
- automatic scan-plan UX
- evidence/operation-centered results
- useful graph/risk/recommendation views
- judge-grade PDF/HTML
- export consistency

**1.0**
- good UI and real reports, some missing diagnostics/drilldown

**0.5**
- current-style overview/minimal report

## H. Benchmarks/reliability — 1.0

**1.0**
- reproducible ground truth
- OpenSSL acceptance
- precision/recall/performance/cache metrics
- stable builds/tests

**0.5**
- fixtures and some metrics only

## Minimum target

```text
Total >= 7.0 / 10
```

Additionally, the following are **mandatory gates regardless of score**:

- no production mock risk/migration output
- C/C++ source scanning works
- binary auto-discovery works
- GUI and CLI share core engine
- real fusion/usage state exists
- operation reconstruction is called
- reports use real P1 risk/recommendations
- missing tools are disclosed
- frontend production build passes
- CLI help passes

---

# 8. Practical prioritization if time is limited

If SIH time becomes constrained, prioritize in this order:

1. unified orchestrator
2. input inventory + scheduler
3. C/C++/multi-language source semantics
4. automatic binary scanning
5. cert/config/dependency quality
6. evidence fusion + ProvidedOnly separation
7. operation reconstruction
8. graph
9. risk/recommendations
10. container inner scanning + cache
11. result delivery/report quality
12. benchmark/OpenSSL proof
13. runtime/cloud breadth
14. optional Ghidra/deep enterprise extras

Do not sacrifice the first 12 items merely to claim broad cloud support.

---

# 9. End-to-end final acceptance scenarios

## Scenario 1 — C/OpenSSL repository

Input:

```text
./openssl
```

Expected:

- detected as repo/source-mixed
- C/C++ recognized
- manifests/build/config/certs identified
- binaries automatically scanned if present
- source semantic analysis runs
- crypto implementation/capability separated from active use
- operations reconstructed where evidence supports them
- graph/risk/recommendations generated
- report does not explode every algorithm implementation into an independent high-risk application use

## Scenario 2 — Mixed application repo

Contains:

```text
Python/Java/JS source
Dockerfile
PEM cert
nginx config
ELF binary
package manifests
nested archive
```

Expected:

- all local surfaces auto-detected
- no scanner checkboxes required
- archive safely expanded
- binary auto-scanned
- config and cert linked where possible
- dependency-only capabilities remain ProvidedOnly until corroborated

## Scenario 3 — Single binary

Input:

```text
app.exe
```

Expected:

- recognized as PE
- binary pipeline planned automatically
- cheap pass runs
- deep escalation only if criteria match
- report explains scanner availability and confidence

## Scenario 4 — Local container image/tar/rootfs

Expected:

- recognized automatically
- packages + binaries + config + certs analyzed inside
- layer linkage/caching
- repeated scan shows cache reuse

## Scenario 5 — Runtime/cloud

Expected:

- never silently contacts external infrastructure
- explicit opt-in/credentials
- evidence is timestamped and linked to static configuration where possible

## Scenario 6 — GUI vs CLI consistency

Same target, profile and permissions:

```text
GUI result
≈ CLI result
```

Core IDs/counts/risk/recommendations must match aside from presentation.

## Scenario 7 — PDF/report consistency

For one scan:

- overview count == canonical count
- risk == P1 stored risk
- recommendations == stored deterministic recommendations
- relative paths are readable
- no mock fields
- no leaked secrets
- missing tools/limitations listed

---

# 10. Definition of done for the whole plan

ECDAT is considered architecture-converged when:

```text
User gives target
  ↓
ECDAT understands target automatically
  ↓
ECDAT inventories every relevant local artifact
  ↓
ECDAT chooses the correct cheap scanners
  ↓
ECDAT escalates only ambiguous/high-value candidates
  ↓
ECDAT fuses evidence with confidence
  ↓
ECDAT reconstructs actual crypto operations
  ↓
ECDAT connects those operations into systems
  ↓
ECDAT evaluates real quantum/classical risk
  ↓
ECDAT produces deterministic migration guidance
  ↓
CLI and GUI show the same truth
  ↓
Reports/exports communicate that truth clearly
```

The final product should feel like an **Enterprise Cryptographic Discovery and Quantum Risk Analysis Tool**, not “a GUI that runs several scanners.”

# 11. Repository engineering rules for Codex

These rules apply to **every phase**.

The goal is not only to make features work. The repository must remain clean, coherent, maintainable, and architecturally consistent.

---

## 11.1 Modify existing code before creating new code

Before adding any new file, class, function, abstraction, adapter, scanner, utility, or model:

1. Search the repository for existing code that already solves part or all of the problem.
2. Read its callers and dependencies.
3. Determine whether it is:
   - currently used
   - reusable but disconnected
   - legacy
   - duplicated elsewhere
4. Prefer modifying, extending, or wiring existing code into the production path.

### Rule

**Do not create a second implementation when a usable implementation already exists.** aim to make the existing solution as required and more efficient