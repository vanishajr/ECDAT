# ECDAT

**ECDAT** - Cryptographic Discovery, Inventory, Analysis, and Migration-Readiness Platform.

## Overview

ECDAT is a comprehensive cryptographic scanning and analysis platform that discovers, inventories, and analyzes cryptographic assets across source code, dependencies, binaries, containers, configurations, certificates, runtime endpoints, and cloud environments.
GUI and CLI use the same production analysis pipeline through `ScanOrchestrator`. Repository acquisition, discovery, normalization, risk analysis, recommendations, persistence, and result generation are shared across both interfaces.

## Features

- **Multi-surface scanning**: Source code, dependencies, binaries, containers, configurations, certificates, runtime endpoints, and cloud (AWS)
- **CIR (Cryptographic Inventory Representation)**: Standardized JSON output format for cryptographic findings
- **Risk assessment**: Mosca-style quantum/classical risk scoring with migration recommendations
- **Report generation**: Markdown, HTML, PDF, JSON, CSV, SARIF, and CycloneDX CBOM formats
- **CLI and Web API**: Command-line interface and local web API for integration
- **Deterministic results**: Reproducible asset IDs and scan results

## Installation

```bash
pip install -e .
```

Or install with development dependencies:

```bash
pip install -e .[dev]
```

## Quick Start

### Local Directory Scan

```bash
ecdat-discover scan /path/to/project
```

### Scan with Specific Scanners

```bash
ecdat-discover scan /path/to/project --scanners source,dependency,config
```

### Scan Public GitHub Repository

```bash
ecdat-discover scan --repo <github-repository-url>
```

### Generate Reports

```bash
# List scans
ecdat-discover list

# Generate markdown report
ecdat-discover report <scan_id> --format markdown --output report.md

# Generate PDF report
ecdat-discover report <scan_id> --format pdf --output report.pdf

# Export as SARIF
ecdat-discover export <scan_id> --format sarif --output results.sarif
```

### Container Scanning

```bash
ecdat-discover scan-container nginx:latest --allow-container
```

### Cloud Scanning (AWS)

```bash
ecdat-discover scan-cloud aws --allow-cloud --profile default --services kms,acm
```

### CI Integration

```bash
ecdat-discover ci /path/to/project --fail-on high
```

## Scan Profiles

- `quick`: Fast scan, no escalation
- `standard`: Balanced scan (default)
- `deep`: Deep analysis with escalation candidates

## Requirements

- Python 3.10+
- For binary analysis: lief, yara-x (Linux/macOS only)
- For semantic analysis: semgrep (Linux/macOS only)
- For container scanning: Docker daemon, syft, or trivy
- For cloud scanning: boto3 and AWS credentials

## Architecture

```
ecdat/
├── cli.py              # Command-line interface
├── core/               # Core models, orchestrator, CIR, validation
├── scanners/           # Scanner implementations
│   ├── source/         # Source code scanner (Python, C, Go, JS, Java, etc.)
│   ├── dependency/     # Dependency scanner (requirements.txt, package.json, etc.)
│   ├── binary/         # Binary scanner (ELF, PE, Mach-O)
│   ├── container/      # Container scanner (Docker, OCI, rootfs)
│   ├── config/         # Config scanner (nginx, Apache, Kubernetes, etc.)
│   ├── certificate/    # Certificate/key scanner (PEM, DER, JKS, PKCS12)
│   ├── runtime/        # Runtime scanner (TLS, SSH)
│   └── cloud/          # Cloud scanner (AWS KMS, ACM, ELB/ALB)
├── reports/            # Report generators (markdown, HTML, PDF, etc.)
├── exports/            # Export formats (SARIF, CBOM, CSV)
├── store/              # SQLite persistence layer
├── web/                # Local web API server
├── commands/           # CLI command implementations
└── tests/              # Test suite
```

## Security

- All secrets (AWS keys, GitHub tokens) are read from environment variables only
- No credentials are logged, stored in reports, or exposed in API responses
- Archive extraction is protected against path traversal (zip-slip/tar-slip)
- Runtime probing is opt-in only
- Cloud scanning is opt-in only

## License

MIT
