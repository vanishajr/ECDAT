# ECDAT

**Cryptographic Discovery, Inventory, Analysis & Migration-Readiness Platform.**

Point ECDAT at any codebase, binary, container, or cloud account and it finds every cryptographic asset (algorithms, keys, certificates, TLS configs, KMS usage), scores its quantum/classical risk, and tells you exactly what to migrate first for a post-quantum world. One real analysis pipeline powers a local dashboard, a full CLI, and CI gates — no mock data, no silent fallbacks.

## How it works (30 seconds)

```
Any target ─▶ DiscoveryEngine (single pass, 8 scanners) ─▶ CIR validation
   ─▶ fusion / operations / graph / risk / recommendations
   ─▶ canonical v1 + CIR sidecar ─▶ SQLite ─▶ dashboard · CLI · reports · CI
```

- **CLI** → `ecdat/commands/_real_scan.py` → `RealCoreClient` → `ScanOrchestrator.scan()`
- **Dashboard** → `ecdat/web/server.py` → `ScanRequest` → `ScanOrchestrator.scan()`

Same backend, same results, every time. Finding IDs are deterministic (`scan:<32hex>`) for identical inputs.

## Run it locally in ~5 minutes

Prerequisites: **Python ≥ 3.10**, **Node ≥ 18**. Optional: Docker/`syft` (container scans), AWS credentials (cloud scans) — everything else works without them.

```bash
git clone https://github.com/vanishajr/ECDAT.git
cd ECDAT

# Backend
pip install -e .

# Scan something (SQLite DB is created automatically)
python -m ecdat.cli scan ./ecdat --db .ecdat.db

# Dashboard (terminal 1) — API at http://127.0.0.1:8734
python -m ecdat.cli gui --port 8734 --db .ecdat.db

# Dashboard UI (terminal 2) — opens at http://localhost:5173
cd frontend && npm install && npm run dev
```

Paste a public GitHub URL, upload an archive, or pick a demo input in the UI — then walk through **Inventory → Risk → Knowledge Graph → Migration Planner → Reports**. Press Ctrl-C to stop either server.

> The CLI and dashboard share the `--db` file: scan once in either, inspect in both. Both default to `~/.ecdat/ecdat.db`.

<details>
<summary><strong>CLI command reference (exact commands)</strong></summary>

### Scan targets

```bash
# Local directory / file (most common)
python -m ecdat.cli scan ./repo --db .ecdat.db

# Only specific scanners
python -m ecdat.cli scan ./repo --scanners source,config,certificate --db .ecdat.db

# Public GitHub repo (same downloader the dashboard uses)
python -m ecdat.cli scan --repo https://github.com/openssl/openssl --db .ecdat.db

# Binary, container tar / rootfs / image ref
python -m ecdat.cli scan-binary ./bin/app --db .ecdat.db
python -m ecdat.cli scan-container ./image.tar --db .ecdat.db
python -m ecdat.cli scan-container nginx:1.25 --allow-container --db .ecdat.db

# AWS cloud (opt-in; creds via env vars only, never stored)
python -m ecdat.cli scan-cloud aws --profile readonly --services kms,acm,elb --db .ecdat.db

# Save machine-readable outputs alongside the DB write
python -m ecdat.cli scan ./repo --cir-out cir.json --output canonical.json --db .ecdat.db
```

### Inspect results

```bash
python -m ecdat.cli list --db .ecdat.db            # all stored scans
python -m ecdat.cli show <scan-id> --db .ecdat.db  # findings + evidence
python -m ecdat.cli risk <scan-id> --db .ecdat.db       # Mosca risk posture
python -m ecdat.cli recommend <scan-id> --db .ecdat.db  # PQC migration steps
```

### Reports & exports

```bash
# Reports: markdown | console | html | pdf
python -m ecdat.cli report <scan-id> --format html --output report.html --db .ecdat.db

# Exports: json | csv | cbom-json | cbom-xml | sarif
python -m ecdat.cli export <scan-id> --format sarif --output findings.sarif --db .ecdat.db
```

### CI gate

```bash
# Fails the build when findings meet the severity threshold
python -m ecdat.cli ci ./repo --fail-on high --summary --db .ecdat.db
python -m ecdat.cli ci ./repo --fail-on medium --sarif results.sarif --db .ecdat.db
```

After `pip install -e .`, `ecdat-discover` works as a shorthand for `python -m ecdat.cli`.

</details>

## What it scans (8 surfaces)

| Surface | Examples |
|---|---|
| Source | Python, C/C++, Java, Go, JS/TS — calls, imports, custom crypto |
| Dependencies | requirements.txt, package.json, Cargo.toml, go.mod, pom.xml, SBOMs |
| Binaries | ELF/PE/Mach-O — constants, OIDs, strings, symbols |
| Containers | Docker/OCI layers, rootfs, Dockerfiles |
| Config | nginx, Apache, Kubernetes, Terraform, Envoy, openssl.cnf |
| Certificates | PEM, DER, JKS, PKCS12, SSH keys |
| Runtime | Live TLS handshakes, SSH banners (opt-in only) |
| Cloud | AWS KMS, ACM, ELB/ALB (opt-in only) |

Findings normalize into **CIR** (Cryptographic Inventory Representation, `ecdat/core/cir.schema.json`), then get **Mosca-style risk scores** (quantum + classical) and **concrete PQC migration recommendations** with a knowledge-graph view of how assets connect.

## Why trust the results

- **Measured, not claimed**: 46/46 synthetic benchmark fixtures pass — algorithm precision 0.87, recall 1.0 (`benchmarks/reports/benchmark_test_suite.json`). Full methodology in `docs/BENCHMARKS.md`.
- **690+ automated tests** across `tests/` and `ecdat/tests/`, plus consumer contracts in `tests/contract/`.
- **Honest about limits**: unavailable tools are reported, never zero-filled; runtime/cloud scans are explicit opt-ins; asset-only findings are preserved rather than dropped.

## Project layout

```
ecdat/
├── cli.py            # CLI dispatch (scan, gui, ci, report, export, …)
├── core/             # Orchestrator, CIR models, fusion, graph, risk, recommend
├── scanners/         # source · dependency · binary · container · config ·
│                     # certificate · runtime · cloud
├── store/            # SQLite persistence (scans + scan_meta diagnostics)
├── reports/          # markdown / console / html / pdf
├── exports/          # json / csv / CycloneDX CBOM / SARIF
├── web/              # Loopback-only local API serving the React dashboard
└── commands/         # One persist path shared by CLI, GUI and CI
frontend/src/         # React + Vite dashboard (inventory, risk, graph, planner)
tests/ + ecdat/tests/ # Unit, regression, contract & end-to-end tests
ECDAT_Benchmark_Suite/ # Accuracy harness: 46 synthetic + real-repo invariants
docs/                 # ARCHITECTURE.md · BENCHMARKS.md · solution-architecture PDF
```

## Security & privacy

- Secrets (AWS keys, GitHub tokens) come from environment variables only — see `.env.example`. Never committed, never logged, never embedded in reports.
- The dashboard binds loopback-only by design; archive extraction is zip-slip/tar-slip hardened; runtime and cloud probing require explicit opt-in flags.

## Docs & troubleshooting

- Architecture deep-dive: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · Benchmark methodology: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)
- Port busy? `gui --port 0` picks a free one. Seeing stale results? Make sure CLI and GUI point at the same `--db` file. Test failures? `python -m pytest -q` (GUI tests bind 127.0.0.1 ephemeral ports only).
