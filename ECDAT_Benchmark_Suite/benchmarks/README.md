# ECDAT Benchmark Suite

Permanent accuracy, false-positive, risk/recommendation and performance regression suite for ECDAT.

## Drop-in

Copy the `benchmarks/` directory and `tests/test_benchmark_framework.py` into the repository root.

## Commands

```bash
python -m benchmarks.runner --mode fast
python -m benchmarks.runner --mode nightly
python -m benchmarks.runner --mode full
python -m benchmarks.runner --mode fast --profile quick
python -m benchmarks.runner --mode fast --profile standard
python -m benchmarks.runner --mode fast --profile deep
python -m benchmarks.runner --mode full --baseline benchmarks/reports/baseline.json
```

Pin repository revisions:

```bash
python benchmarks/tools/pin_repos.py
```

The full-repository runner passes GitHub URLs through ECDAT's production input path using
`ecdat.core.orchestrator.ScanRequest` and `get_orchestrator().scan()`.

If the repository's current `ScanRequest` signature differs, modify only:

```text
benchmarks/ecdat_adapter.py
```

Do not bypass ECDAT's InputRegistry / orchestrator / scheduler for end-to-end benchmarks.

## Modes

- `fast`: synthetic exact-oracle + FP + dataflow + selected binaries.
- `nightly`: fast + selected real repositories.
- `full`: all configured repositories, profiles and performance checks.

## Ground truth philosophy

Synthetic and curated slices use exact operation expectations.

Full repositories use invariants, not brittle exact finding counts.

Examples:

- OpenSSL implementation code must not automatically become Confirmed application use.
- docs/comments must not create Confirmed operations.
- test-only legacy algorithms must not inflate production risk.
- Express is a mostly-negative control.
- curl must distinguish supported TLS backends from selected/active deployment use.

## Important

Initial risk expectations are semantic rather than exact numeric score assertions because ECDAT's
risk scale may evolve. Update ground truth only when the product semantics intentionally change.
