# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool (SIH26164)

Integrated product: discovery + intelligence + platform. One production
pipeline serves both interfaces:

GUI → `ecdat/web/server.py` → `ScanRequest` → `ScanOrchestrator.scan()`
CLI → `ecdat/commands/_real_scan.py` → `RealCoreClient` → `ScanRequest` →
`ScanOrchestrator.scan()`

There is no mock mode: every scan runs single-pass real analysis —
`DiscoveryEngine` scans once → CIR v0.1 validation → fusion/operations/
graph/risk/recommendations → canonical v1 + CIR sidecar → SQLite
(`scans` + `scan_meta` plan/diagnostics) → CLI/GUI/reports/exports/CI.
Failures are loud errors, never silent mock fallbacks.

Data contracts: CIR v0.1 is the internal intelligence model
(`ecdat/core/cir.schema.json`); canonical v1 is the stable
platform-facing model (`ecdat/core/canonical_v1.json`). Adapters in
`ecdat/adapters/` translate between them.

## Prerequisites

- Python 3.10+
- `pip install -e .` (runtime deps: `pydantic>=2.7`, `pyyaml>=6`,
  `cryptography>=42`, `jsonschema`, `tomli` on Python 3.10; tests need
  `pytest`). No network, credentials, or services required for local scans.
- Optional capabilities are probed, never required: Semgrep, LIEF, YARA,
  Docker/Syft, cloud SDKs, runtime sockets. Unavailable scanners are
  reported explicitly, never scored as zero.
- Container/cloud/runtime scanning is opt-in (Docker, credentials, sockets).

## Validate

```bash
python -m pytest -q
```

Must report all tests passing (platform regression + P2 scanner suite +
P1/core tests + contract tests + real integration tests).

## One-command local dashboard (React API + UI)

```bash
python -m ecdat.cli gui --port 8734
```

Serves the local API at `http://127.0.0.1:8734` (loopback only;
`--port 0` for an ephemeral port, `--db PATH` to share a database with
the CLI). Start the React interface with `cd frontend && npm run dev`.
Press Ctrl-C to stop.

## Real scans (integrated pipeline)

Default real selection is network-free:
`source,dependency,binary,config,certificate`. Opt in explicitly for
`container` (Docker/Syft), `cloud` (ambient credentials), `runtime`
(TLS/SSH sockets).

```bash
# Source tree (production pipeline)
python -m ecdat.cli scan ./repo --db .ecdat.db
python -m ecdat.cli scan ./repo --cir-out cir.json --output canonical.json --db .ecdat.db

# GitHub repository (same downloader + pipeline as the dashboard)
python -m ecdat.cli scan --repo https://github.com/openssl/openssl --db .ecdat.db

# Binary / container tar / rootfs / image ref
python -m ecdat.cli scan-binary ./bin/app --db .ecdat.db
python -m ecdat.cli scan-container ./image.tar --db .ecdat.db
python -m ecdat.cli scan-container nginx:1.25 --allow-container --db .ecdat.db

# Cloud (label target, no local path required)
python -m ecdat.cli scan-cloud aws --profile readonly --services kms,acm,elb --db .ecdat.db

# Explicit scanner subset + opt-ins
python -m ecdat.cli scan ./repo --scanners source,config,certificate --db .ecdat.db
python -m ecdat.cli scan ./repo --allow-container --allow-cloud --allow-runtime --db .ecdat.db

# CI gate on real findings (P1 risk posture, severity policy)
python -m ecdat.cli ci ./repo --fail-on high --summary --db .ecdat.db

# GUI over a real database
python -m ecdat.cli gui --db .ecdat.db --port 0
```

Real findings reach inventory, finding detail (usage state, evidence,
confidence, locations, redacted snippets), risk dashboard (P1 Mosca
posture), graph view (CIR projection), migration planner (P1
recommendations), reports/exports (canonical v1), and CI gates.

## Dashboard workflow

1. **Repository input** — paste a public GitHub URL, upload a file/archive,
   or pick a demo input.
2. **Scan plan + monitor** — read-only plan; scans run through the shared
   orchestrator with staged progress.
3. **Inventory/findings** — click rows for finding detail (usage state,
   evidence, confidence, redacted snippets).
4. **Risk dashboard** — P1 Mosca risk posture over stored wire risks.
5. **Asset inventory** — flat CBOM-derived assets.
6. **Knowledge graph** — real CIR projection.
7. **Migration planner** — P1 recommendations; no persistent migration
   state.
8. **Reports** — view/download HTML, PDF, CSV, JSON, SARIF, CBOM, CIR.

## CLI commands

All scan commands run the shared production backend
(`ScanOrchestrator`); there is no mock mode. `scan [path] [--repo URL]`,
`scan-binary`, `scan-container`, `scan-cloud` (with `--scanners`,
`--allow-container/--allow-cloud/--allow-runtime/--allow-pull/--allow-build`,
`--profile` (scan depth, except `scan-cloud` where `--profile` is the AWS
profile), `--region`, `--cir-out`, context/Mosca options; `scan-cloud`
additionally accepts `--aws-access-key-id/--aws-secret-access-key/
--aws-session-token/--aws-profile`), `list`, `show`, `risk`, `recommend`,
`export` (json/csv/cbom-json/cbom-xml/sarif),
`report` (markdown/console/html/pdf),
`ci` (`--fail-on`/`--json`/`--summary`/`--sarif`, plus scan options),
`gui` (local React API).

## Generated artifacts

Reports: Markdown, console, HTML, PDF. Exports: JSON, CSV,
CBOM JSON/XML, SARIF 2.1.0, CIR JSON. Dashboard serves HTML/PDF/CSV/JSON/
SARIF/CBOM/CIR downloads. Scans persist the enriched CIR sidecar
(`scans.cir_json`, schema v3) alongside canonical v1 plus plan/diagnostics
(`scan_meta`).

## Production boundaries (honest limits)

- P1 Mosca risk + recommendation engine; deterministic `scan:<32hex>` IDs
  for identical inputs; RFC3339 timestamps; asset-only findings preserved;
  unavailable tools reported, never zero-filled. Measured detector quality
  on committed fixtures is modest — do not claim fixed precision/recall
  targets until independently reproduced on corrected ground truth.
- Product is intentionally incomplete: persistent migration state,
  owners/effort/timelines/sequencing, full Azure/GCP, guaranteed Docker
  environments, external baseline comparisons, full runtime probing,
  and production auth/remote deployment remain out of scope or
  versioned-contract extensions.

Contracts are pinned in `tests/contract/` and `docs/P1_P2_INTEGRATION_CONTRACT.md`.

## Troubleshooting

- Port busy: `gui --port 0`. Non-loopback `--host`:
  refused by design.
- Stale DB confusion: point CLI and GUI at the same `--db` file to share
  scan history (both default to `~/.ecdat/ecdat.db`).
- `pytest` failures: run `python -m pytest -q`; GUI tests bind 127.0.0.1
  ephemeral ports only.
- Real scan missing deps: install real-scan group above; the error names
  the missing package.
- `pip install -e .` used to fail (setuptools discovered `referenceDocs`
  as a package); fixed via `[tool.setuptools.packages.find]` include/exclude.
