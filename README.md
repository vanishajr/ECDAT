# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool (SIH26164)

Integrated product: Person 2 discovery + Person 1 intelligence + Person 3
platform. Two modes share one store/GUI/reports surface:

- **Mock mode (default)**: deterministic fixtures, labeled `mock` in code,
  CLI output, GUI badges, and tests. Offline demos and regression tests.
- **Real mode (`--real`)**: single-pass pipeline — P2 `DiscoveryEngine`
  scans once → CIR v0.1 validation → P1 fusion/operations/graph/risk/
  recommendations → canonical v1 + CIR sidecar → SQLite → CLI/GUI/reports/
  exports/CI. Never silently falls back to mock; failures raise
  `RealScanError`.

Data contracts: CIR v0.1 is the internal intelligence model
(`ecdat/core/cir.schema.json`); canonical v1 is the stable
platform-facing model (`ecdat/core/canonical_v1.json`). Adapters in
`ecdat/adapters/` translate between them.

## Prerequisites

- Python 3.10+
- Mock/demo path: `pip install -e .` (runtime dep: `jsonschema`;
  tests need `pytest`). No network, credentials, or services required.
- Real-scan path: `pip install -e ".[test]"` plus real deps
  (`pydantic>=2.7`, `pyyaml>=6`, `cryptography>=42`,
  `tomli` on Python 3.10). Optional capabilities are probed, never
  required: Semgrep, LIEF, YARA, Docker/Syft, cloud SDKs, runtime sockets.
  Unavailable scanners are reported explicitly, never scored as zero.
- Container/cloud/runtime scanning is opt-in (Docker, credentials, sockets).

## Validate

```bash
python -m pytest -q
```

Must report all tests passing (platform regression + P2 scanner suite +
P1/core tests + contract tests + real integration tests).

## One-command local demo (mock)

```bash
python -m ecdat.cli demo
```

Seeds a fresh temp workspace (two mock targets) and serves the dashboard
at `http://127.0.0.1:8734` (loopback only; `--port 0` for an ephemeral
port, `--db PATH` to reuse a database). Press Ctrl-C to stop.

```bash
python -m ecdat.cli demo --port 0   # avoid port clashes
python -m ecdat.cli gui             # dashboard on your own DB (no seeding)
```

## Real scans (integrated pipeline)

Default real selection is network-free:
`source,dependency,binary,config,certificate`. Opt in explicitly for
`container` (Docker/Syft), `cloud` (ambient credentials), `runtime`
(TLS/SSH sockets).

```bash
# Source tree (real)
python -m ecdat.cli scan ./repo --real --db .ecdat.db
python -m ecdat.cli scan ./repo --real --cir-out cir.json --output canonical.json --db .ecdat.db

# Binary / container tar / rootfs / image ref
python -m ecdat.cli scan-binary ./bin/app --real --db .ecdat.db
python -m ecdat.cli scan-container ./image.tar --real --db .ecdat.db
python -m ecdat.cli scan-container nginx:1.25 --real --allow-container --db .ecdat.db

# Cloud (label target, no local path required)
python -m ecdat.cli scan-cloud aws --profile readonly --services kms,acm,elb --real --db .ecdat.db

# Explicit scanner subset + opt-ins
python -m ecdat.cli scan ./repo --real --scanners source,config,certificate --db .ecdat.db
python -m ecdat.cli scan ./repo --real --allow-container --allow-cloud --allow-runtime --db .ecdat.db

# CI gate on real findings (P1 risk posture, severity policy)
python -m ecdat.cli ci ./repo --real --fail-on high --summary --db .ecdat.db

# GUI over a real database
python -m ecdat.cli gui --db .ecdat.db --port 0
```

Real findings reach inventory, finding detail (usage state, evidence,
confidence, locations, redacted snippets), risk dashboard (P1 Mosca
posture), graph view (CIR projection), migration planner (P1
recommendations), reports/exports (canonical v1), and CI gates.

## Demo workflow (dashboard cards)

1. **Target** — pick a seeded demo target (or type any path).
2. **Scan-plan preview + monitor** — read-only plan; real scans run
   synchronously, progress is staged/estimated.
3. **Inventory/findings** — click rows for finding detail (Card 6).
4. **Risk dashboard** — mock severity-weight scoring in mock mode
   (labeled); P1 risk posture for real scans.
5. **Asset inventory + groupings** — flat CBOM-derived assets (Card 7).
6. **Knowledge graph** — `MOCK DATASET` badge in mock mode; real CIR
   projection for real scans (Card 8).
7. **Migration planner** — severity triage, `MOCK / PLACEHOLDER` in mock
   mode; P1 recommendations for real scans, still no persistent
   migration state (Card 9).
8. **Reports** — view/download HTML, PDF, CSV, JSON, SARIF (Card 10).

## CLI commands

`scan`, `scan-binary`, `scan-container`, `scan-cloud` (each with
`--mock`/`--real`, `--scanners`, `--allow-container/--allow-cloud/--allow-runtime`,
`--cir-out` on real paths), `list`, `show`, `risk`, `recommend`,
`export` (json/csv/cbom-json/cbom-xml/sarif),
`report` (markdown/console/html/pdf),
`ci` (`--fail-on`/`--json`/`--summary`/`--sarif`, plus real flags),
`gui`, `demo`.
`python -m ecdat.benchmark run|cases|suite-run|baselines` runs the benchmark harness
(`suite-run --baseline NAME` evaluates one registered baseline).

## Generated artifacts

Reports: Markdown, console, HTML, PDF (stdlib-only). Exports: JSON, CSV,
CBOM JSON/XML, SARIF 2.1.0. Benchmark: JSON results, HTML/CSV/SVG/PDF
artifacts. GUI Card 10 serves HTML/PDF/CSV/JSON/SARIF downloads.
Real scans also persist the enriched CIR sidecar (`scans.cir_json`,
schema v2) alongside canonical v1; mock/legacy rows store NULL.

## Mock vs real (honest boundaries)

- Mock: deterministic fixtures; severity-weight risk; static-map
  recommendations; hand-authored graph; triage-only migration; synthetic
  benchmark labels. Labeled `mock` everywhere.
- Real: P2 discovery (parallel scanner families, persistent container
  layer cache, content-aware correlation); P1 Mosca risk + 17-rule
  recommendation map; deterministic `scan:<16hex>` IDs; RFC3339
  timestamps; asset-only findings preserved; unavailable tools reported,
  never zero-filled. Measured P2 quality on committed fixtures is
  ~25% recall / ~14% precision — do not claim 95%/90% targets until
  independently reproduced on corrected ground truth.
- Product is intentionally incomplete: persistent migration state,
  owners/effort/timelines/sequencing, full Azure/GCP, guaranteed Docker
  environments, external baseline comparisons, full runtime probing,
  and production auth/remote deployment remain out of scope or
  versioned-contract extensions.

Contracts are pinned in `tests/contract/` and `docs/P1_P2_INTEGRATION_CONTRACT.md`.

## Troubleshooting

- Port busy: `demo --port 0` or `gui --port 0`. Non-loopback `--host`:
  refused by design.
- Stale DB confusion: `demo` uses a fresh temp dir each run (path printed).
- `pytest` failures: run `python -m pytest -q`; GUI tests bind 127.0.0.1
  ephemeral ports only.
- Real scan missing deps: install real-scan group above; the error names
  the missing package.
- `pip install -e .` used to fail (setuptools discovered `referenceDocs`
  as a package); fixed via `[tool.setuptools.packages.find]` include/exclude.
