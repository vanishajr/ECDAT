# ECDAT Functional Optimisation Plan

> **Target:** production-grade cryptographic discovery, semantic analysis, risk classification, recommendation quality, and scan efficiency.
>
> **Execution owner:** Codex
>
> **Architecture constraint:** **DO NOT redesign, replace, or reorganize ECDAT's top-level architecture.** The existing orchestration, scanner-family model, CIR flow, risk stage, recommendation stage, reporting/export flow, and frontend/API structure remain the product architecture. This plan changes the **quality and efficiency of the functionality inside those stages**.
>
> **Primary goals, in order:**
>
> 1. increase cryptographic detection recall;
> 2. increase semantic precision and reduce false positives;
> 3. reconstruct complete cryptographic operations instead of isolated keyword/API hits;
> 4. make risk classification defensible and standards-backed;
> 5. make recommendations operation-aware and technically correct;
> 6. reduce unnecessary compute through staged/demand-driven analysis and caching;
> 7. make the final result reliable enough to ship as a real security product.

---

# 1. Non-negotiable implementation constraints

Codex must treat these as hard requirements.

## 1.1 Preserve the current architecture

Keep the existing broad flow:

```text
Input / repository
    ↓
Inventory / routing
    ↓
Existing scanner families
    ↓
CIR / normalization
    ↓
Correlation / reconstruction
    ↓
Risk
    ↓
Recommendations
    ↓
Reports / exports / GUI
```

Do not create a parallel product pipeline.

Do not move core analysis into the frontend.

Do not bypass CIR.

Do not build a second risk or recommendation path.

Improve the live production path already identified in the audit.

Primary live modules include:

```text
ecdat/core/orchestrator.py
ecdat/core/scheduler.py
ecdat/scanners/discovery.py

ecdat/scanners/source/scanner.py
ecdat/scanners/source/c_parser.py
ecdat/scanners/source/api_knowledge.py

ecdat/scanners/base.py
ecdat/core/cir_models.py
ecdat/core/cir.schema.json

ecdat/core/operations.py
ecdat/core/fusion.py

ecdat/core/api.py
ecdat/core/risk.py
ecdat/core/recommend.py

ecdat/reports/aggregate.py
ecdat/adapters/risk_view.py
ecdat/adapters/migration_adapter.py
ecdat/web/server.py
frontend/src/App.tsx
```

Before modifying any function, search the current branch and verify that it remains live.

---

## 1.2 Optimise for truth, not finding count

The target metric is not:

```text
more findings
```

It is:

```text
more true cryptographic assets and operations found
+
fewer false conclusions
+
better parameter resolution
+
better context
+
lower duplicate rate
+
lower runtime per useful result
```

A scan producing 100 correct semantic findings is better than one producing 10,000 disconnected keyword hits.

---

## 1.3 Unknown must remain unknown

Never force an algorithm, key size, mode, provider, or use-state when the evidence does not resolve it.

Acceptable:

```text
operation: asymmetric decrypt
algorithm: unresolved
confidence: high for operation
```

Not acceptable:

```text
operation: asymmetric decrypt
algorithm: guessed-most-likely-algorithm
```

This rule applies throughout discovery, correlation, risk, and recommendations.

---

## 1.4 Presence is not usage

The system must preserve distinctions among:

```text
reference
declaration
supported capability
implementation
registration
configuration
enabled/default state
invocation
confirmed operation
```

These semantics are critical for reliable risk classification.

---

## 1.5 Confidence is not risk

Maintain separate concepts:

```text
Confidence:
"How sure is ECDAT that this observation is true?"

Risk:
"If true in this context, how serious is it?"
```

Do not lower or inflate security severity merely because detection confidence changes.

---

# 2. Research and standards basis

Codex should use these sources as design references.

The objective is not to copy their architecture; use the techniques relevant to ECDAT's existing stages.

## 2.1 Cryptoscope — reconstruct complete crypto operations

**Paper:** Cryptoscope: Analyzing cryptographic usages in modern software  
https://arxiv.org/abs/2503.19531

Important ideas to apply:

- static parsing of source;
- control/data-flow analysis around cryptographic code;
- do not treat individual crypto-library calls as the final asset;
- reconstruct a complete cryptographic operation;
- associate algorithm, key, nonce, random source, APIs, and related material.

ECDAT application:

```text
isolated API observations
    ↓
related call/parameter reconstruction
    ↓
one semantic CryptoOperation
```

---

## 2.2 CryptoGuard — efficient demand-driven slicing

**Paper:** CryptoGuard: High Precision Detection of Cryptographic Vulnerabilities in Massive-sized Java Projects  
https://arxiv.org/abs/1806.06881

Important ideas:

- use refined program slicing rather than broad whole-program analysis;
- remove irrelevant program elements from slices;
- analyse data required for a crypto security decision;
- prioritise precision and scalability.

ECDAT application:

```text
crypto candidate / sink
    ↓
bounded backward slice
    ↓
resolve only the values needed:
algorithm
key
IV/nonce
mode
provider
configuration
```

Do not perform expensive data-flow over every variable in every source file.

---

## 2.3 CrySL — semantic API contracts

**Paper:** CrySL: Validating Correct Usage of Cryptographic APIs  
https://arxiv.org/abs/1710.00564

Important ideas:

- crypto correctness depends on method-call sequences;
- parameter constraints matter;
- data-flow constraints matter;
- a single API name is insufficient to classify secure/insecure usage.

ECDAT application:

Convert API knowledge from simple name mappings toward contracts that can describe:

```text
anchors
expected call sequence
argument semantics
parameter constraints
operation semantics
security checks
```

---

## 2.4 Classification-driven crypto discovery

**Paper:** Hidden Ciphers and Where to Find Them: Static Discovery and Assessment of Cryptographic Assets in Software  
https://arxiv.org/abs/2608.04857

Important ideas:

- separate discovery from assessment;
- classify Crypto-Material, Crypto-Artifacts, and Crypto-Invocations;
- keep rules scanner-independent;
- produce structured crypto inventory before risk evaluation.

ECDAT application:

Use explicit evidence classes and keep discovery findings separate from security conclusions.

---

## 2.5 Mutation-driven detector evaluation

**Paper:** MASC: A Tool for Mutation-Based Evaluation of Static Crypto-API Misuse Detectors  
https://arxiv.org/abs/2308.02310

Important ideas:

- detector quality must survive equivalent syntactic transformations;
- one misuse should be tested in aliases, wrappers, helper functions, fields, alternate expressions, etc.;
- mutation-based evaluation finds blind spots that ordinary fixture testing misses.

ECDAT application:

Add mutation-like benchmark variants to prevent detection rules from becoming syntax-specific.

---

## 2.6 Version-aware crypto rules

**Paper:** MetaCrySL  
https://arxiv.org/abs/2105.04950

Important idea:

- crypto API validity and security guidance can depend on library/platform/security-standard versions.

ECDAT application:

Version policy/rule data rather than hard-code eternal "good/bad" assumptions.

---

## 2.7 Tree-sitter

**Project documentation:**  
https://tree-sitter.github.io/tree-sitter/

Useful properties:

- fast syntax parsing;
- error-tolerant;
- language-extensible;
- appropriate for source repositories that may not compile locally.

ECDAT application:

Use it behind the existing source scanner to extract syntax facts.

---

## 2.8 CycloneDX CBOM

**Authoritative Guide:**  
https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-CBOM-en.pdf

**CBOM capability page:**  
https://cyclonedx.org/capabilities/cbom/

Important ideas:

- distinguish implemented/provided cryptography from cryptography actually used;
- represent algorithms, protocols, certificates, keys/material, and relationships;
- keep sufficient properties to reason about cryptographic strength and dependencies.

ECDAT application:

CIR should be semantically at least as expressive as the crypto information ECDAT exports.

---

## 2.9 Security/risk standards

### NIST SP 800-131A Rev. 2

Transitioning the Use of Cryptographic Algorithms and Key Lengths  
https://csrc.nist.gov/pubs/sp/800/131/a/r2/final

Use for:

- algorithm/key-size status;
- transition guidance;
- classical cryptographic strength decisions.

### RFC 9325

Recommendations for Secure Use of TLS and DTLS  
https://www.rfc-editor.org/rfc/rfc9325.html

Use for:

- TLS/DTLS-specific risk policy;
- protocol/cipher deployment recommendations.

### NIST post-quantum standards

ML-KEM — FIPS 203  
https://csrc.nist.gov/pubs/fips/203/final

ML-DSA — FIPS 204  
https://csrc.nist.gov/pubs/fips/204/final

SLH-DSA — FIPS 205  
https://csrc.nist.gov/pubs/fips/205/final

Use the correct primitive family for the correct operation.

---

# 3. Desired production detection model

ECDAT's existing scanner families remain.

Within them, move toward a staged approach:

```text
                    INPUT FILE
                        │
                        ▼
             STAGE A — CHEAP TRIAGE
      extension / language / imports / literals
       exact API symbols / manifests / constants
                        │
                        ▼
                candidate evidence
                        │
                        ▼
             STAGE B — SYNTAX FACTS
         AST / Tree-sitter / native parsers
                        │
                        ▼
             STAGE C — DIRECT RESOLUTION
        exact API lookup / literals / constants
                        │
                        ▼
          STAGE D — DEMAND-DRIVEN ANALYSIS
        bounded dataflow / wrapper resolution
                        │
                        ▼
           STAGE E — STRUCTURAL FINGERPRINTS
      custom implementation identification when needed
                        │
                        ▼
             SEMANTIC CRYPTO EVIDENCE
                        │
                        ▼
            CORRELATION / OPERATION BUILD
                        │
                        ▼
                 CRYPTO INVENTORY
                        │
                 actionable subset
                        ▼
             RISK + RECOMMENDATION
```

Expensive analysis should only run when cheaper evidence justifies it.

---

# 4. Phase 0 — Baseline, observability, and quality gates

## Objective

Before changing detection, make improvements measurable.

## Required work

Create or verify a single benchmark runner around the existing:

```text
benchmark_test_suite
```

It must report at least:

```text
scan runtime
peak memory if available
files processed
source LOC processed
crypto evidence count
logical crypto assets
logical operations
duplicate evidence ratio
confirmed/probable/unknown counts
false positives
false negatives
algorithm precision
algorithm recall
operation precision
operation recall
scope classification accuracy
risk classification correctness
recommendation correctness
```

Where a benchmark case has explicit ground truth, calculate exact metrics.

Where only integration expectations exist, report assertions rather than fake precision numbers.

## Add timing instrumentation

Measure:

```text
inventory
source candidate scan
parsing
dataflow/resolution
fingerprinting
correlation
risk
recommendation
report assembly
```

This is essential because later phases must improve accuracy without uncontrolled performance regression.

## Baseline artifact

Before Phase 1, create/update:

```text
docs/optimisation.md
```

with:

```markdown
# ECDAT Optimisation Log

## Baseline
- commit:
- date:
- tests:
- benchmark command:
- runtime:
- memory:
- precision:
- recall:
- known false positives:
- known false negatives:
- current limitations:
```

## Completion gate

Do not proceed until:

```text
all existing tests pass
benchmark_test_suite runs reproducibly
baseline numbers are recorded
```

---

# 5. Phase 1 — Make candidate detection cheaper

## Problem

The current C-family source path can perform repeated regex matching across extracted call sites.

This is wasteful when most crypto APIs have exact symbol names.

## Target

Replace broad regex-per-call matching with:

```text
exact symbol lookup first
pattern matching only when actually required
```

## Implementation

### 5.1 Build per-language API indexes

From current crypto API knowledge produce structures similar to:

```python
EXACT_API_INDEX = {
    "c": {
        "some_crypto_symbol": ApiRule(...),
    },
    "python": {...},
    "java": {...},
}
```

Lookup:

```text
CallSite.name
    ↓
hash/dict lookup
```

### 5.2 Separate exact and pattern rules

Each rule should indicate:

```text
match_type:
  exact
  prefix
  regex
  constructor
  string-parameter
```

Do not compile every rule as a regex if a dictionary lookup is sufficient.

### 5.3 Multi-pattern lexical prefilter

For initial raw source triage, use one compiled multi-pattern mechanism for mostly literal terms.

Possible implementation choices:

```text
Aho-Corasick trie
RegexSet
combined regex automaton
```

Avoid adding a heavy native dependency unless benchmarks justify it.

### 5.4 Compile matcher structures once

Do not rebuild compiled rules per source file.

Compile per:

```text
scanner version
registry version
language
```

and reuse.

## Expected result

```text
same/better recall
same/better precision
fewer matching operations
lower source-scan time
```

## Tests

Add:

```text
exact lookup and regex fallback produce same semantic result
matcher compilation occurs once
ambiguous/pattern APIs still work
```

## optimisation.md requirement

After the phase append:

```markdown
## Phase 1 — Candidate detection
### Changed
### Why
### Files/functions modified
### Before/after benchmark
### Accuracy impact
### Performance impact
### Remaining limitations
```

---

# 6. Phase 2 — Syntax-aware source facts

## Objective

Make the source detector understand code structure rather than treating source mostly as text.

## Architecture constraint

This remains inside:

```text
SourceScanner
```

Do not create a replacement source pipeline.

## Implement a language-neutral fact representation

Recommended new module:

```text
ecdat/scanners/source/facts.py
```

Suggested object:

```python
SourceFact(
    kind,
    language,
    name,
    file,
    line,
    column,
    function,
    arguments,
    value,
    type_name,
    metadata,
)
```

Required fact types:

```text
function_definition
function_declaration
function_call
import
include
assignment
constant
macro
array_constant
string_literal
type_reference
return
```

## Parser implementation

### C/C++

Use Tree-sitter to extract facts.

Do not require successful project compilation.

### Python

Use the existing AST but normalize into the same SourceFact model.

### Other supported languages

Incrementally provide adapters for languages ECDAT currently scans.

Do not block the phase until every language is perfect.

## Preserve fallback

If syntax parsing fails:

```text
existing lexical/API detection remains available
diagnostic records parser failure
confidence reflects weaker evidence
```

## Critical semantic distinction

Codex must explicitly represent:

```text
function_definition != function_call
```

and:

```text
string_literal != executable API reference
```

## Cache parsed facts

Cache by:

```text
file content hash
parser name/version
language adapter version
```

This will later make re-scans much cheaper.

## Completion gate

The scanner must be able to answer:

```text
where is a crypto-like symbol defined?
where is it called?
where is it imported/included?
what arguments were supplied?
```

without relying on raw regex for those structural facts.

---

# 7. Phase 3 — Demand-driven value and data-flow resolution

## Objective

Resolve the information required to identify a cryptographic operation while avoiding expensive whole-program analysis.

Follow the demand-driven slicing principles from CryptoGuard/CrySL.

## Trigger

Only run this phase around:

```text
direct crypto API candidates
crypto configuration calls
cryptographic constructors
unresolved crypto operation candidates
```

## Resolve these values

Where applicable:

```text
algorithm
mode
key size
curve
digest
protocol
provider
key source
nonce/IV source
random source
KDF
iteration/work factor
certificate validation mode
```

## Resolution depth

Start with bounded analysis:

```text
expression
→ local assignment
→ same function
→ same file
→ direct wrapper/caller/callee
→ bounded 1–3 hops
```

Stop on:

```text
dynamic dispatch
unknown external call
cycle
depth limit
unresolvable runtime input
```

Return unresolved state rather than guessing.

## Implement simple def-use

Examples:

```text
constructor -> variable -> crypto init
literal -> variable -> API argument
constant -> wrapper parameter -> crypto call
```

## Wrapper expansion

Extend current wrapper handling to:

```text
bounded graph
cycle detection
confidence decay
provenance preservation
```

A wrapper does not create a separate logical cryptographic operation unless it performs a separate operation.

## Slice refinement

Do not pull every dependency into the slice.

Ignore unrelated:

```text
logging
UI
formatting
error strings
unrelated branches
unrelated local variables
```

where safely identifiable.

## Efficiency requirement

Record:

```text
number of candidate sinks
average slice nodes
max slice depth
resolution success rate
time spent in resolver
```

Use this data to prevent dataflow from becoming the dominant scan cost.

---

# 8. Phase 4 — Reconstruct semantic cryptographic operations

## Objective

The unit presented to risk/recommendation should be a complete cryptographic operation, not an isolated detector hit.

Use the Cryptoscope concept as inspiration.

## Example target

Instead of:

```text
API constructor finding
encryption-init finding
algorithm string finding
random call finding
```

create:

```text
CryptoOperation
  primitive
  algorithm
  variant
  mode
  operation
  key
  nonce/IV
  random source
  provider/library
  call sequence
  locations
  scope
  evidence
  confidence
```

## Evidence types

Add first-class evidence classification if not already completed:

```text
REFERENCE
DECLARATION
IMPLEMENTATION
REGISTRATION
CONFIGURATION
INVOCATION
ASSET
DEPENDENCY
BINARY_SIGNATURE
```

## Semantic state

Represent:

```text
REFERENCED
DECLARED
SUPPORTED
IMPLEMENTED
REGISTERED
ENABLED
CONFIGURED
INVOKED
PROBABLE
CONFIRMED
```

Do not replace provenance with only a final state.

## Relationship model

Use/extend existing graph relationships to express:

```text
implements
provides
uses
configures
registers
invokes
contains
depends_on
derives
protects
```

Align semantics with CBOM concepts where useful.

## Required change

Risk and recommendation stages should primarily consume:

```text
normalized semantic operations/assets
```

not raw detector strings.

---

# 9. Phase 5 — Structural implementation fingerprints

## Objective

Detect cryptographic implementations that do not call a known external crypto API.

## Approach

Use multiple independent signals.

Do not classify an algorithm from one weak constant or identifier.

## Shared fingerprint knowledge

Refactor constants currently useful to binary scanning so source and binary scanners can consume a common knowledge layer.

Suggested location:

```text
ecdat/core/crypto_knowledge/
```

## Fingerprint classes

Prioritise common primitives:

```text
AES
DES / 3DES
RC4
ChaCha20
Poly1305
MD5
SHA-1
SHA-2
SHA-3 / Keccak
HMAC
PBKDF2
HKDF
scrypt
Argon2
RSA
DH
DSA
ECC-related primitives
```

## Signals may include

```text
known constant sequences
array/table sizes
round constants
rotation patterns
block sizes
key-size constants
round counts
characteristic arithmetic
function/data-flow structure
algorithm identifiers
```

## Confidence

Example model:

```text
one weak signal             -> candidate only
two independent weak signals -> probable implementation
strong constant + structure -> high-confidence implementation
multiple strong signals     -> confirmed implementation
```

Exact thresholds must be derived from benchmark results, not intuition only.

## Efficiency

Only run deep structural analysis for files/functions that pass a cheap prefilter such as:

```text
large static numeric tables
bitwise-heavy code
crypto constants
algorithm-like identifiers
round/key/block patterns
```

---

# 10. Phase 6 — Scope, source-role, and build-state semantics

## Objective

Know whether evidence belongs to application code, tests, demos, build metadata, dependencies, generated code, or library implementation.

## Add central scope classification

Recommended:

```text
ecdat/core/scope.py
```

Scopes:

```text
APPLICATION
LIBRARY_IMPLEMENTATION
TEST
FIXTURE
BENCHMARK
DEMO
EXAMPLE
DOCUMENTATION
GENERATED
VENDOR
BUILD
CONFIG
DEPENDENCY
BINARY
CERTIFICATE_ASSET
UNKNOWN
```

## Inputs

Use:

```text
path
filename
language
build membership
manifest information
parsed syntax facts
directory semantics
```

Avoid path-name-only classification where stronger evidence exists.

## Build-state classification

Add:

```text
DEFAULT_ENABLED
ENABLED
DISABLED
CONDITIONAL
SUPPORTED
UNKNOWN
```

Interpret common:

```text
#define
#undef
#ifdef
#ifndef
#if
-D flags
CMake options
Makefile flags
compile_commands.json
```

Then extend to other build systems as needed.

## Risk effect

Non-deployment scopes should not automatically receive production-style risk.

Do not hide the evidence.

Display it as:

```text
implementation
test use
demo use
configuration
asset
```

---

# 11. Phase 7 — Correlation and deduplication overhaul

## Objective

Reduce duplicate logical findings while preserving every useful evidence location.

## Current principle to replace

Do not rely mainly on:

```text
same algorithm + same file + nearby line
```

## New identity

Correlate using semantic identity:

```text
primitive
variant
mode
key size
curve
protocol
operation type
scope
build state
symbol lineage
provider/library
```

## Preserve evidence

One logical entity may contain many observations:

```text
definition
declaration
registration
configuration
test invocation
application invocation
binary evidence
```

Keep them all.

## Metrics

Report:

```text
raw observations
correlated logical assets
logical operations
deduplication ratio
evidence retained
```

A lower logical finding count is acceptable if information is preserved and semantics improve.

---

# 12. Phase 8 — Unified, scanner-independent crypto knowledge

## Objective

Prevent different scanner families and downstream engines from maintaining contradictory crypto knowledge.

## Consolidate conceptually

Current scattered information should be exposed through a common knowledge API.

Suggested organization:

```text
ecdat/core/crypto_knowledge/
  registry.py
  algorithms.*
  aliases.*
  constants.*
  oids.*
  libraries.*
  protocols.*
  apis/
  policies/
  recommendations/
```

The physical file format is up to Codex after inspecting existing registries.

## Canonical algorithm model

Each entry should support where applicable:

```text
canonical name
primitive/family
variant
aliases
OIDs
modes
key sizes
security strengths
protocol associations
known constants
provider/library aliases
deprecated status
standards status
quantum properties
```

## Separation of responsibilities

```text
scanner:
"What did I observe?"

knowledge registry:
"What is this?"

assessment policy:
"Is this acceptable?"

recommendation policy:
"What action is appropriate?"
```

Do not mix these layers.

## Version knowledge

Registry/policies must have their own version.

Include registry/policy version in:

```text
cache keys
scan diagnostics
reports
exports
```

---

# 13. Phase 9 — Crypto misuse analysis

## Objective

Move beyond "algorithm exists" to detecting actual insecure usage.

Use CrySL/CryptoGuard-style parameter and sequence checks.

## High-value misuse rules

Implement progressively:

```text
static/hardcoded cryptographic key
predictable key source
static/reused IV or nonce where unsafe
AEAD nonce reuse
ECB mode where semantically unsafe
weak/insecure RNG
certificate validation disabled/bypassed
insufficient key size
insecure protocol version
deprecated algorithms
low KDF work factor
missing authentication where security semantics require it
password used directly as encryption key
unsafe signature/hash combinations
```

## Rule definition

Prefer structured rules:

```yaml
id: example
applies_to:
  primitive: ...
  operation: ...
requires:
  parameter: ...
condition:
  ...
severity_basis:
  ...
references:
  ...
```

Do not bury all logic in long Python `if` chains.

## Sequence contracts

Support API lifecycle semantics, for example:

```text
construct
configure
initialize
update
finalize
```

The rule engine should be able to check both:

```text
required sequence
invalid parameter combination
```

---

# 14. Phase 10 — Risk engine redesign

## Objective

Make risk results explainable, defensible, and based on the semantic operation.

## Do not delete the current risk stage

Improve its inputs and internal calculation.

## Separate dimensions

Calculate internally:

```text
Classical Security Posture
Misuse Severity
Protocol/Configuration Posture
Quantum Exposure
Deployment Impact
Migration Urgency
```

Keep:

```text
Detection Confidence
```

outside the risk value.

## Classical security

Use standards-based algorithm/key-size status.

Primary source:

NIST SP 800-131A Rev. 2  
https://csrc.nist.gov/pubs/sp/800/131/a/r2/final

Policy records should include:

```text
algorithm/variant
operation
key size
status
effective date
source
```

## Protocol risk

Use protocol-specific rules rather than generic algorithm rules.

For TLS/DTLS:

RFC 9325  
https://www.rfc-editor.org/rfc/rfc9325.html

## Misuse risk

Take precedence when a strong primitive is used incorrectly.

Example logic:

```text
strong algorithm + catastrophic nonce misuse
    -> serious finding

strong algorithm + correct use
    -> no finding merely for presence
```

## Context

Use known context only.

If assumptions are needed, clearly mark:

```text
assumed_default
```

and call the output:

```text
scenario risk
```

rather than presenting the assumption as fact.

## Overall score

A 0–10 number may remain for UI compatibility.

But it must derive from named dimensions whose values are inspectable.

Store enough detail that:

```text
Why this risk?
```

can explain the actual technical reason.

---

# 15. Phase 11 — Recommendation engine redesign

## Objective

Recommendations must follow structured cryptographic semantics.

## Input

Use:

```text
primitive
variant
operation
mode
key size
protocol
misuse
scope
build state
classical posture
quantum posture
policy profile
```

Do not infer recommendation families from raw title/string substring matching.

## Recommendation classes

### Fix misuse without replacing the primitive

Examples:

```text
nonce generation/reuse issue
key-generation issue
certificate validation issue
KDF work factor issue
```

Recommendation should address the misuse directly.

### Replace deprecated/inadequate primitive

Use current standards policy.

### Protocol upgrade

Only when the protocol/configuration rule calls for it.

### Post-quantum transition

Use operation-correct standards:

Key establishment:
- ML-KEM / FIPS 203
  https://csrc.nist.gov/pubs/fips/203/final

Digital signatures:
- ML-DSA / FIPS 204
  https://csrc.nist.gov/pubs/fips/204/final
- SLH-DSA / FIPS 205
  https://csrc.nist.gov/pubs/fips/205/final

Do not recommend signature primitives for key establishment or key-establishment primitives for signature operations.

## Recommendation object

Each recommendation should contain:

```text
action
reason
applies_to
target/security goal
standards reference
preconditions
alternatives
migration blockers
confidence/known limitations
```

## No recommendation when no action is justified

The recommendation engine must be allowed to return:

```text
monitor
no action
insufficient context
```

---

# 16. Phase 12 — Align every scanner family with the same semantics

## Objective

Improve the current specialized scanners without changing scanner architecture.

## Dependency scanner

Dependency presence should indicate:

```text
provided capability / dependency
```

not active operation by itself.

Resolve package:

```text
name
version
provider
known crypto capabilities
```

where reliable.

## Binary scanner

Improve in stages:

```text
imports/symbols
strings
known constants
fragmented constants
structural signatures
```

Do not run expensive deeper analysis globally.

Use escalation only for ambiguous high-value binary candidates.

## Certificate/key scanner

Treat parsed items primarily as:

```text
cryptographic assets/material
```

Extract:

```text
algorithm
key size
curve
signature algorithm
validity
issuer/subject
encryption/protection metadata
```

Only create an operation when actual operation evidence exists.

## Config scanner

Distinguish:

```text
mentioned
supported
configured
enabled/default
```

Use protocol-specific semantics.

## Source scanner

Remain the primary location for:

```text
API use
custom implementation
operation reconstruction
parameter resolution
misuse detection
```

---

# 17. Phase 13 — Cache and execution efficiency

## Objective

Make the stronger analysis cheaper than a naive implementation.

## Parse cache

Cache SourceFacts:

```text
key =
file content hash
+ parser version
+ language adapter version
```

## Resolution cache

Cache expensive bounded-resolution results where safe:

```text
function content/symbol hash
+ resolver version
+ rule registry version
```

## Final scan cache

Include:

```text
input hash
scanner versions
registry version
risk policy version
recommendation policy version
analysis configuration
schema version
```

Do not return stale analysis after rules change.

## Staged escalation

Implement source work approximately as:

```text
cheap triage
    ↓
parse candidate
    ↓
direct resolve
    ↓
only unresolved/complex candidates → dataflow
    ↓
only implementation-like candidates → fingerprints
```

## Concurrency

Retain scanner-family concurrency.

Within source analysis, prefer:

```text
bounded worker pool
deterministic output ordering
shared immutable registries
```

Avoid uncontrolled thread creation.

## Time budgets

Track and enforce:

```text
per-file budget
per-stage budget
overall scan deadline
```

Return partial diagnostics rather than silently hanging.

---

# 18. Phase 14 — Detector robustness through mutation tests

## Objective

Make detection robust to equivalent code shapes.

Inspired by MASC:

https://arxiv.org/abs/2308.02310

For representative crypto operations, create variants:

```text
direct call
variable alias
constant alias
function wrapper
two-hop wrapper
helper-returned algorithm
helper-returned key
field/member storage
import alias
different casing/string construction where relevant
separated initialization and use
conditional branch
```

The semantic result should remain equivalent where the code remains equivalent.

Add these to:

```text
benchmark_test_suite
```

or a suite invoked by it.

Report:

```text
mutation variants total
detected correctly
semantic mismatches
false positives
```

---

# 19. Phase 15 — Result/report quality

## Objective

The GUI/report must expose the improved semantics without overwhelming the user.

## Crypto Inventory

Answer:

```text
What cryptography exists?
```

Show:

```text
primitive/variant
state
scope
provider
operations
evidence count
```

## Findings

Answer:

```text
What is actually insecure or policy-relevant?
```

Only include actionable security/policy findings.

## Migration

Answer:

```text
What should change?
```

Recommendations should reference the specific operation/finding.

## Evidence

Allow expansion to:

```text
source locations
scanner evidence
resolved values
scope/build state
confidence
```

## Risk details

Default view:

```text
why this matters
risk dimensions
confidence
```

Advanced/collapsed:

```text
formula
assumptions
policy IDs
operation IDs
```

## Coverage

Clearly separate:

```text
files inventoried
files analyzed
files containing crypto evidence
files skipped
unsupported files
parser failures
```

---

# 20. Phase 16 — Production validation and benchmark report

## Objective

At the end, prove the optimisation worked.

## Mandatory command/suite

Run the complete:

```text
benchmark_test_suite
```

Do not cherry-pick only passing benchmark cases.

Run all normal unit/integration/export/contract tests as well.

## Final metrics

Compare against the Phase 0 baseline:

```text
algorithm precision
algorithm recall
operation precision
operation recall
misuse precision/recall where ground truth exists
scope accuracy
build-state accuracy
risk classification correctness
recommendation correctness
logical duplicate rate
scan runtime
source throughput
memory usage
cache hit improvement
parser failure rate
unresolved-operation rate
```

## Performance interpretation

The final report must explicitly discuss tradeoffs:

```text
accuracy gained
recall gained
runtime cost
memory cost
remaining blind spots
```

Do not claim "production-ready" only because tests pass.

## Required final benchmark document

Create:

```text
docs/benchmark_optimisation_report.md
```

with:

```markdown
# ECDAT Optimised Benchmark Report

## Environment
## Commit/version
## Benchmark suite
## Before vs after summary

| Metric | Baseline | Final | Delta |
|---|---:|---:|---:|

## Detection accuracy
## Semantic operation accuracy
## Scope/build-state accuracy
## Risk accuracy
## Recommendation accuracy
## Runtime/performance
## Memory
## False-positive analysis
## False-negative analysis
## Unresolved cases
## Remaining limitations
## Production-readiness assessment
```

---

# 21. Mandatory `docs/optimisation.md` workflow

This is required for every phase.

Codex must create:

```text
docs/optimisation.md
```

if it does not exist.

After **each phase**, append/update a section before starting the next phase.

Use this structure:

```markdown
# ECDAT Optimisation Implementation Log

## Phase N — <name>

### Objective
What this phase was intended to improve.

### Research/technical basis
Which techniques/standards informed the change.

### Repository analysis
Live files/functions inspected before implementation.

### Changes implemented
Exact behavior changed.

### Files modified
- ...

### Tests added/updated
- ...

### Correctness results
- precision:
- recall:
- false positives:
- false negatives:
- semantic accuracy:

### Performance results
- runtime before:
- runtime after:
- memory before:
- memory after:

### Regressions encountered
- ...

### Fixes
- ...

### Known limitations after this phase
- ...

### Decision for next phase
- ...
```

This document is not optional.

It must describe **actual implemented behavior**, not restate this plan.

---

# 22. Required quality gates before moving between phases

After each phase:

1. run the relevant unit tests;
2. run repository-wide tests affected by changed contracts;
3. run the semantic/benchmark subset;
4. compare metrics;
5. update `docs/optimisation.md`;
6. inspect false positives and false negatives;
7. do not continue while unexplained regressions remain.

If performance regresses severely:

```text
profile first
optimise second
```

Do not remove semantic correctness simply to regain speed without evidence.

---

# 23. Suggested implementation sequence

Codex should implement in this order:

```text
Phase 0  Baseline + observability

Phase 1  Faster candidate matching

Phase 2  Syntax-aware source facts

Phase 3  Demand-driven resolution

Phase 4  Semantic operation reconstruction

Phase 5  Structural implementation fingerprints

Phase 6  Scope + build-state semantics

Phase 7  Correlation/deduplication

Phase 8  Unified crypto knowledge

Phase 9  Crypto misuse detection

Phase 10 Risk engine

Phase 11 Recommendation engine

Phase 12 Scanner-family semantic alignment

Phase 13 Caching/execution efficiency

Phase 14 Mutation robustness

Phase 15 Result/report quality

Phase 16 Full benchmark + final production report
```

Do not reorder risk/recommendation ahead of semantic detection.

Correct dependency:

```text
better evidence
    ↓
better operation reconstruction
    ↓
better scope/config knowledge
    ↓
better assessment
    ↓
better risk
    ↓
better recommendation
```

---

# 24. Practical Codex instructions

## Before changing each subsystem

Search the repository for:

```text
the class/function named in this guide
all callers
all tests
all serializers/exporters
all schema dependencies
```

Do not rely solely on old line numbers.

## Preserve API compatibility

Where possible:

```text
add optional fields
provide migration/default logic
keep current exports valid
```

Only make a breaking schema change when it is required for correctness, and update all consumers/tests in the same phase.

## Keep rule engines testable

Prefer pure functions such as:

```text
resolve_algorithm(...)
classify_scope(...)
assess_operation(...)
recommend_operation(...)
```

over tightly coupling new logic to HTTP/UI code.

## Determinism

Same:

```text
input
scanner versions
policy versions
configuration
```

must produce the same semantic output.

## Explainability

Every actionable result must be able to answer:

```text
What did ECDAT observe?
Where?
How was it resolved?
What operation does it represent?
What rule says it is risky?
Why is this recommendation appropriate?
```

---

# 25. Production acceptance criteria

The final implementation should satisfy all of the following.

## Discovery

- [ ] known crypto APIs are detected efficiently;
- [ ] direct/custom implementations are detectable through structural evidence;
- [ ] crypto materials and artifacts are inventoried separately from operations;
- [ ] strings/comments/docs do not become executable usage;
- [ ] dependency presence does not automatically become use;
- [ ] source, config, binary, dependency, and certificate evidence share canonical crypto identities.

## Semantics

- [ ] definition and invocation are distinct;
- [ ] implemented and used are distinct;
- [ ] supported/configured/enabled/default are distinct;
- [ ] generic APIs may remain unresolved;
- [ ] key/nonce/provider parameters are resolved where statically practical;
- [ ] wrappers are correlated without duplicate explosion;
- [ ] evidence provenance is retained.

## Risk

- [ ] confidence is separate from risk;
- [ ] presence alone does not create vulnerability severity;
- [ ] algorithm/key-size decisions are standards-backed;
- [ ] misuse rules operate on semantic parameters;
- [ ] protocol risk uses protocol-specific policy;
- [ ] non-deployment scope does not automatically get deployment severity;
- [ ] assumptions are clearly labelled.

## Recommendations

- [ ] recommendations use structured operation semantics;
- [ ] misuse recommendations fix misuse when replacement is unnecessary;
- [ ] transition recommendations use the correct cryptographic function family;
- [ ] references/standards are attached;
- [ ] no recommendation is generated when evidence does not justify one.

## Efficiency

- [ ] exact API lookups avoid unnecessary regex work;
- [ ] parser output is cached;
- [ ] data-flow analysis is demand-driven;
- [ ] structural fingerprinting is gated;
- [ ] cache keys include scanner/policy versions;
- [ ] scan deadlines are enforced;
- [ ] output remains deterministic.

## Product quality

- [ ] complete test suite passes;
- [ ] `benchmark_test_suite` passes;
- [ ] baseline vs final metrics are documented;
- [ ] `docs/optimisation.md` contains every implementation phase;
- [ ] `docs/benchmark_optimisation_report.md` exists;
- [ ] remaining limitations are explicitly documented;
- [ ] report/UI distinguishes inventory, findings, and migration.

---

# 26. First task Codex should execute

Do **Phase 0 only** first.

Before implementing later phases:

1. inspect the live modules listed in this document;
2. locate `benchmark_test_suite` and understand its ground-truth format;
3. run the full current test suite;
4. run the benchmark suite;
5. create `docs/optimisation.md`;
6. write the baseline metrics and current detector behavior;
7. identify the exact functions Phase 1 will modify;
8. proceed to Phase 1 only after the baseline is reproducible.

The optimisation work is complete only after all phases have been implemented or explicitly documented as unnecessary based on measured evidence, followed by the mandatory full benchmark and production-readiness report.

