# ECDAT PERSON 2 — PASS 2 FULL AUTONOMOUS COMPLETION

Read `ECDAT_PERSON2_CONTEXT.md` first. It is the authoritative context for this work.

You are the MAIN REMOTE CODING AGENT responsible for completing Person 2's Pass 2.

Your job is to investigate, fix, test, benchmark, clean, and finish the Discovery Engine to the highest defensible standard.

---

# 0. CRITICAL AGENT ALLOCATION RULE

There are TWO agents available:

1. YOU — the main remote agent using Nemotron.
2. `local-investigator` — the local Qwen3 8B read-only investigator.

The purpose of the local investigator is to save remote context by performing repository reconnaissance locally.

## YOU MUST USE `local-investigator` FOR THE SIX INVESTIGATION TRACKS BELOW

Delegate these six independent investigations to `local-investigator`:

### Investigator 1 — Source Detection
Audit:
- `ecdat/scanners/source/`
- source detection implementation
- source fixtures
- source tests
- detection accuracy
- the known `get_key_sizes` evaluator/scanner failure if still present

### Investigator 2 — Pass 2 Evaluator / Benchmark Infrastructure
Audit:
- `ecdat/benchmarks/evaluate_pass2.py`
- evaluation logic
- ground-truth loading
- TP/FP/FN calculation
- precision/recall/F1 calculation
- summary generation
- evaluator failure paths
- benchmark artifact handling

### Investigator 3 — All Discovery Scanners
Audit the remaining scanner implementations:
- dependency/library
- binary
- container
- config
- certificate/key
- runtime endpoint
- cloud/AWS where applicable

Check actual implementation, tests, fixtures, and obvious detection gaps.

### Investigator 4 — Accuracy / False Positive / False Negative Coverage
Independently inspect the test and fixture corpus and determine:
- what is actually detected
- what is missed
- what creates false positives
- whether tests genuinely exercise the relevant code paths
- where Pass 2 accuracy requirements are currently weak or untested

### Investigator 5 — Integration / Fusion / Handoff
Audit Person 2's integration boundary:
- detector JSON
- core/fusion handoff
- identity/correlation fields
- usage state
- signature normalization
- CIR v0.1 compatibility
- evidence security/redaction
- graph-related detector output
- Person 1 handoff
- Person 3/CLI/export compatibility

### Investigator 6 — Performance / Scalability
Audit the current implementation for:
- large repository behavior
- 100k LOC feasibility
- scanner bottlenecks
- repeated container scanning
- layer-cache behavior
- memory-heavy operations
- obvious scalability problems

Do not merely estimate performance. Identify what must actually be benchmarked.

## LOCAL INVESTIGATOR RULES

For these six investigations, actually delegate to:

`local-investigator`

Do not substitute another agent.

Do not delegate unrelated work merely to create more agents.

The local investigator is READ-ONLY.

It must inspect actual implementation, execution paths, tests, and fixtures.

It must distinguish:

VERIFIED
INFERRED
UNKNOWN

It must not invent evidence.

After receiving the six reports, critically evaluate them yourself and verify important claims before changing code.

If the task/delegation system executes the six investigations sequentially rather than concurrently, continue anyway. Do not abandon the investigations merely because execution is not perfectly parallel.

---

# 1. PERSON 2 SCOPE

You own the Discovery Engine:

- source
- dependency/library
- binary
- container
- config
- certificate/key
- runtime endpoint
- cloud/AWS

Person 1 owns:
- CIR/core intelligence
- fusion
- operation reconstruction
- graph
- risk
- PQC recommendations

Person 3 owns:
- CLI/GUI/reporting
- final benchmark harness
- product views

Respect these boundaries.

Do not redesign unrelated systems.

---

# 2. ONE-TIME PROJECT DIRECTORY CLEANUP

Before Pass 2 investigation, inspect the actual project directory recursively.

This is a PROJECT-FOLDER cleanup, not a Git cleanup.

Remove genuinely obsolete:
- abandoned prototypes
- duplicate implementations
- stale scripts
- temporary files
- debug files
- old logs
- generated junk
- stale benchmark outputs
- temporary profiling artifacts
- abandoned experiments
- duplicate documentation
- obsolete notes
- accidental files
- unused temporary test artifacts

Only remove something when there is strong evidence that it is:

OBSOLETE + UNREFERENCED + NOT REQUIRED.

If uncertain, KEEP IT.

Never delete:
- source code of uncertain purpose
- tests
- ground-truth fixtures
- required benchmarks
- configuration
- integration contracts
- `ECDAT_PERSON2_CONTEXT.md`
- `BUILD_PROMPT.md`
- `.opencode/`
- required project documentation
- user work
- anything needed indirectly by tooling

Do not restructure the repository unnecessarily.

Remove temporary benchmark/profiling artifacts after use unless they are intentional deliverables.

After cleanup, verify that the project still works.

Do not repeatedly revisit cleanup after this pass.

---

# 3. ESTABLISH CURRENT BASELINE

Run the actual current regression suite.

Do not assume the historical 61/61 result is still true.

Record:
- total tests
- passed
- failed
- errors
- skipped
- important failures

Preserve the baseline unless a failure is directly caused by a Pass 2 fix.

---

# 4. INVESTIGATE FIRST

Complete the six `local-investigator` investigations before making substantial changes where practical.

Read their reports carefully.

Do not blindly trust them.

Use direct repository inspection yourself only where necessary to:
- verify critical claims
- understand implementation details needed for a fix
- resolve contradictions
- implement changes
- debug concrete failures

Avoid duplicating broad reconnaissance unnecessarily.

---

# 5. FIX THE EVALUATOR FIRST

Run:

`ecdat/benchmarks/evaluate_pass2.py`

If the evaluator is broken, fix the evaluator/infrastructure first.

Investigate the known historical:

`NameError: name 'get_key_sizes' is not defined`

Do not assume it still exists.

Run the evaluator against the real fixtures and make it produce trustworthy results.

Do not hide scanner failures behind evaluator changes.

---

# 6. DISCOVERY ACCURACY

Evaluate actual detection performance.

Measure:
- TP
- FP
- FN
- precision
- recall
- F1

By scanner where possible.

Required targets:

- source: 95%+ recall and <5% FPs
- binary: 90%+ recall
- config/cert: 95%+ metadata accuracy
- container: 90%+ detection
- fusion duplicates: <3%

If targets are missed, determine whether the cause is:
- scanner implementation
- normalization
- evaluator logic
- fixture/ground truth problem
- integration issue

Fix the actual root cause.

---

# 7. FIX DISCOVERY ENGINE PROBLEMS

Make the smallest correct changes necessary.

Do not perform speculative rewrites.

Do not refactor unrelated code simply because it could be cleaner.

After every meaningful fix:
- run targeted tests
- then run the relevant broader regression tests

---

# 8. CONTAINER PERFORMANCE

Measure repeated container scans and caching behavior.

Verify the actual implementation and measure whether repeated scans benefit from layer caching.

Target:

70%+ faster repeated scans where the acceptance criterion applies.

Report actual measured values.

---

# 9. FAILURE ISOLATION

Verify that one broken scanner/file/input does not unnecessarily destroy the entire discovery run.

Test failure paths where practical.

---

# 10. INTEGRATION

Verify the actual detector → core handoff.

Check:
- JSON structure
- required fields
- asset identity
- correlation
- usage state
- signatures
- evidence
- redaction
- CIR compatibility
- downstream compatibility

Do not introduce hidden coupling between Person 2, Person 1, and Person 3.

---

# 11. MANDATORY 100K LOC PERFORMANCE TEST

This is REQUIRED. Do not skip it.

Create a realistic temporary source repository containing at least approximately 100,000 lines of source code.

The benchmark must exercise the ACTUAL ECDAT discovery pipeline, not a fake isolated parser benchmark.

Measure:

1. total scan wall-clock time
2. peak RAM usage
3. CPU behavior where practical
4. number of files processed
5. findings produced
6. errors/failures

Acceptance target:

**100,000 LOC scan under 60 seconds**

and

**peak RAM below 1 GB**

Run enough repetitions to make the result meaningful, preferably including:
- cold run
- warm run
- repeated run / median

Do NOT count fixture generation time as scan time.

Do NOT claim the requirement is met without an actual measurement.

If it fails:
1. identify the bottleneck
2. make a targeted optimization
3. rerun the benchmark
4. verify regression behavior

Temporary benchmark data must not pollute the permanent project directory.

Clean it up afterward.

---

# 12. REGRESSION DISCIPLINE

After changes:

- run targeted tests
- run scanner tests
- run evaluator
- run full regression suite
- rerun performance benchmarks after relevant changes

Do not declare success from a single passing command.

---

# 13. FINAL EVALUATION

Run the complete Pass 2 evaluation against the real ground truth.

Produce actual numbers.

Do not manufacture or estimate metrics.

Clearly distinguish:
- PASS
- FAIL
- PARTIAL
- UNTESTED
- UNKNOWN

---

# 14. FINAL ACCEPTANCE CHECK

Before declaring Pass 2 complete, verify:

- source detection target
- binary detection target
- config/cert metadata target
- container detection target
- container cache performance
- fusion duplicate target
- operation reconstruction compatibility
- risk/recommendation compatibility
- evaluator correctness
- scanner failure isolation
- integration contract
- CLI/GUI/export compatibility
- regression suite
- benchmark results
- 100k LOC <60 sec
- 100k LOC peak RAM <1 GB
- project directory cleanup

Do not claim an acceptance criterion is met without evidence.

---

# 15. CHANGE SCOPE

Only change files necessary to complete Person 2 Pass 2.

Prefer:
- minimal fixes
- targeted optimizations
- focused tests
- required benchmark/evaluator changes
- required documentation/handoff updates

Do not:
- rewrite working architecture
- redesign unrelated modules
- modify Person 1/3-owned systems unnecessarily
- introduce dependencies without need
- change public interfaces unless required
- perform cosmetic refactors unrelated to Pass 2

Before each substantial change, understand why it is required.

---

# 16. GIT DISCIPLINE

Git is secondary to the actual project work.

Do NOT use destructive commands.

Never:
- reset user changes
- checkout/revert unrelated work
- clean the repository with destructive Git commands
- overwrite pre-existing modifications

Do not delete project files merely because Git considers them untracked.

The project-folder cleanup must be based on actual project evidence, not Git status.

If commits are appropriate, keep them logically grouped and limited to the work performed.

---

# 17. OVERNIGHT AUTONOMOUS EXECUTION

Work continuously through the entire checklist.

Do not stop after the first successful test.

Do not ask for confirmation for routine decisions.

If something fails:
1. investigate
2. fix if within scope
3. test
4. continue

If an acceptance criterion cannot be achieved safely, document exactly why and continue with the remaining work.

Do not fabricate success.

---

# 18. FINAL HANDOFF

At the end, provide a concise final report containing:

## Cleanup
- removed
- kept because uncertain/required
- organized, if any

## Baseline
- initial test result

## Changes
- files changed
- what changed
- why

## Evaluation
- TP
- FP
- FN
- precision
- recall
- F1

## Performance
- 100k LOC size
- scan time
- peak RAM
- cold/warm/repeated results
- container cache result

## Regression
- final test result

## Acceptance Matrix
Every criterion:
- PASS / FAIL / PARTIAL / UNTESTED / UNKNOWN
- supporting evidence

## Person 1 Handoff
State exactly what detector output/contracts are ready for Person 1.

## Person 3 Handoff
State exactly what outputs/interfaces are ready for Person 3.

Do not declare Pass 2 complete until the evidence supports the claim.

# MOST IMPORTANT RULE

**Finish the actual work.**

Use the local Qwen3 8B `local-investigator` specifically for the six reconnaissance tracks defined above to save remote context.

You remain responsible for reasoning, implementation, debugging, testing, benchmarking, verification, and final completion.

Do not stop at analysis.
