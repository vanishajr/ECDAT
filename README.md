# ECDAT - Person 2 Discovery Engine

Cryptographic Discovery Engine for the ECDAT (SIH26164) platform. This is the Person 2 (Discovery) component that finds cryptographic assets and emits CIR v0.1 records for handoff to Person 1 (Core Intelligence).

## Architecture

```
DiscoveryEngine
├── SourceScanner          # AST/Tree-sitter + Semgrep for source code
├── DependencyScanner      # Package manifest parsing (npm, pip, cargo, go, maven, etc.)
├── BinaryScanner          # LIEF + strings + YARA for binary analysis
├── ContainerScanner       # Docker + Syft for container images
├── ConfigScanner          # nginx, Apache, Envoy, OpenSSL, Kubernetes, Terraform, generic
├── CertificateScanner     # PEM, DER, JKS, PKCS#12, SSH keys, JWK/JWKS
├── RuntimeScanner         # TLS/SSH probing
└── CloudScanner           # AWS KMS/ACM/ELB (Azure/GCP stubs)
    ↓
Finding Normalization      # Registry-based canonical naming
    ↓
Evidence Correlation       # Cross-scanner asset deduplication
    ↓
CIR Emission              # CIR v0.1 JSON output
    ↓
CIR Validation            # Schema validation
```

## Installation

```bash
# Core dependencies
pip install -e .

# Development dependencies (tests, linting)
pip install -e ".[dev]"

# Benchmark dependencies
pip install -e ".[bench]"

# Optional external tools (recommended for full functionality)
# Semgrep (multi-language source scanning)
pip install semgrep

# LIEF (binary analysis)
pip install lief

# YARA-X (binary pattern matching)
pip install yara-x

# Syft (container SBOM)
# Install from https://github.com/anchore/syft

# Trivy (container vulnerability scanning)
# Install from https://github.com/aquasecurity/trivy

# AWS credentials for cloud scanning
aws configure
```

## Quick Start

```python
from ecdat import create_discovery_engine

# Create engine with all available scanners
engine = create_discovery_engine()

# Scan a directory
cir = engine.scan_and_emit_cir("/path/to/project", target_name="my-project")

# Output CIR JSON
print(cir.model_dump_json(indent=2))

# Or save to file
cir_file = Path("output.cir.json")
cir_file.write_text(cir.model_dump_json(indent=2))
```

## CLI Usage

```bash
# List available scanners
ecdat-discover list-scanners

# Run discovery scan
ecdat-discover discover /path/to/project --output results.cir.json

# Run with specific scanners
ecdat-discover discover /path/to/project --scanners source,dependency,config

# Validate CIR file
ecdat-discover validate results.cir.json
```

## Scanner Details

### Source Scanner
- **Python AST Scanner**: Native Python AST analysis for direct API calls, imports, class instantiation
- **Semgrep Scanner**: Multi-language pattern matching (Python, JS/TS, Go, Java, C/C++, Rust, etc.)
- Detects: AES-GCM/CBC/CTR/CCM, ChaCha20-Poly1305, RSA, DSA, DH, ECDH, ECDSA, Ed25519, Ed448, X25519, X448, MD5, SHA-1/2/3, BLAKE2/3, PBKDF2, HKDF, scrypt, Argon2, TLS/SSL/SSH, PQC (ML-KEM, ML-DSA, SLH-DSA, Falcon)
- Usage states: Confirmed (direct API calls), Probable (strong evidence), Possible (weak evidence), ProvidedOnly (imports only)

### Dependency Scanner
Parses: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt, pyproject.toml, poetry.lock, Cargo.toml, Cargo.lock, go.mod, go.sum, pom.xml, build.gradle, Gemfile, composer.json
Maps packages to crypto capabilities via registry. **Never promotes dependency presence to Confirmed usage** - always ProvidedOnly.

### Binary Scanner
- **LIEF Scanner**: ELF/PE/Mach-O import/symbol/string analysis (when LIEF available)
- **Strings Scanner**: Fallback string extraction (always available)
- **YARA Scanner**: YARA-X pattern matching for crypto constants (when available)
- Usage states: ProvidedOnly (library imports), Probable (symbols), Possible (strings only)

### Container Scanner
- **Docker Scanner**: Image inspection, layer analysis, Dockerfile/Compose parsing
- **Syft Scanner**: SBOM generation for package detection in containers
- Scans: packages, binaries, configs, certificates in container layers

### Config Scanner
- **nginx**: ssl_ciphers, ssl_protocols, ssl_certificate, ssl_certificate_key
- **Apache**: SSLCipherSuite, SSLProtocol, SSLCertificateFile, SSLCertificateKeyFile
- **Envoy**: transport_socket TLS context, cipher_suites, tls_params, certificates
- **OpenSSL**: MinProtocol/MaxProtocol, CipherSuites/Ciphers, Options
- **Kubernetes**: Secrets, Certificates (cert-manager), Ingress TLS
- **Terraform**: aws_acm_certificate, aws_lb_listener, ssl_policy, cipher_suites
- **Generic**: YAML/JSON/TOML/INI key-value scanning for TLS/cert/key references

### Certificate Scanner
- **PEM**: X.509 certificates, CSRs, private/public keys (RSA, ECDSA, Ed25519, Ed448, X25519, X448)
- **DER**: Binary certificate/key parsing
- **JKS**: Java KeyStore via keytool (when available)
- **PKCS#12**: .p12/.pfx via cryptography/OpenSSL
- **SSH**: Public keys (authorized_keys, known_hosts), private keys
- **JWK/JWKS**: JSON Web Key sets
- **Never stores private key material** - only safe metadata (algorithm, key size, curve, validity, etc.)

### Runtime Scanner
- **TLS Scanner**: SSLyze-style handshake probing for negotiated version, cipher, certificate chain
- **SSH Scanner**: ssh-keyscan for host key algorithms
- Optional, graceful failure handling

### Cloud Scanner
- **AWS**: KMS keys (spec, usage, origin), ACM certificates (domain, key algorithm, status), ELB/ALB listeners (TLS config, certificates, SSL policies)
- **Azure/GCP**: Stubs for future implementation
- Read-only, no secret extraction

## CIR v0.1 Handoff

All scanner output maps to the CIR v0.1 schema:

```json
{
  "cir_version": "0.1",
  "scan_id": "scan:abcdef1234567890",
  "target": "my-project",
  "started_at": "2024-01-01T00:00:00Z",
  "finished_at": "2024-01-01T00:01:00Z",
  "tool_versions": {"source": "source-v0.1.0(...)", "dependency": "dependency-v0.1.0"},
  "registry_version": "2026.09.11",
  "assets": [...],
  "operations": [...],
  "graph": {"nodes": [...], "edges": [...]},
  "stats": {"asset_count": 10, "operation_count": 5, "node_count": 20, "edge_count": 15}
}
```

### CryptoAsset Fields
- `asset_id`: Deterministic `ast:<hash>`
- `canonical`: Registry-normalized name (e.g., "AES-256-GCM")
- `original`: Detector spelling (e.g., "AESGCM")
- `key_size`, `mode`, `curve`, `protocol`: When identifiable
- `library`: Source library/package
- `usage_state`: Confirmed | Probable | Possible | ProvidedOnly | FalsePositiveSuppressed
- `confidence`: 0.0 - 1.0
- `evidence`: Array of EvidenceSignal with tool, detail, confidence, snippet (redacted)
- `location`, `implementation`, `context`, `risk_inputs`: Optional context

### CryptoOperation Fields
- `operation_id`: Deterministic `op:<hash>`
- `operation_type`: Encrypt | Decrypt | Sign | Verify | KeyExchange | Hash | KDF | TLS | Storage | KeyManagement
- `asset_id`: References CryptoAsset
- Same evidence/confidence/context as assets

### Graph
- Node kinds: asset, operation, file, service, host, library, key
- Relationships: uses, calls, contains, derives, protects, depends_on, terminates
- Every edge endpoint exists

## Semantic Rules

**CRITICAL**: Installation/import/dependency presence ≠ crypto usage proof

| Evidence | Usage State |
|----------|-------------|
| OpenSSL installed | ProvidedOnly |
| OpenSSL imported | Probable at most |
| Actual AES API call | Confirmed/Probable |
| RSA library import | Probable at most |
| Actual RSA signing | Confirmed |
| Container with OpenSSL | ProvidedOnly |

## Running Tests

```bash
# Unit tests
pytest ecdat/tests/test_core.py -v

# Scanner tests
pytest ecdat/tests/test_scanners.py -v

# Integration tests
pytest ecdat/tests/test_integration.py -v

# All tests with coverage
pytest ecdat/tests/ --cov=ecdat --cov-report=term-missing

# Benchmarks
pytest ecdat/benchmarks/benchmark.py -v --benchmark-only
```

## Benchmarking

```bash
# Run benchmarks
pytest ecdat/benchmarks/benchmark.py -v

# Results include:
# - Time (mean, median, stdev, min, max)
# - Memory usage (mean)
# - Finding counts
# - JSON export for CI/CD
```

Target benchmarks (not guarantees):
- Source: 95% recall, <5% FP
- Binary: 90%+
- Config/Certificate: 95%+
- Container: 90%+
- 100k LOC: <60 seconds, <1 GB RAM

## Security

- **Never** prints, persists, or transmits private keys
- **Never** sends source code to LLMs
- **Never** uses LLMs for detection
- Deterministic, explainable detection only
- Evidence snippets auto-redacted (base64, PEM, passwords, tokens, keys)

## Limitations

- Semgrep/LIEF/YARA-X not available on Windows (fallback to strings/parser)
- JKS scanning requires keytool in PATH
- PKCS#12 scanning requires OpenSSL CLI for fallback
- AWS scanning requires valid credentials
- Runtime scanning is network-dependent
- Azure/GCP cloud scanners are stubs only

## Extending

### Add New Source Language
1. Add Semgrep rules to `SemgrepScanner.SEMGREP_RULES`
2. Or implement new AST scanner subclassing `Scanner`

### Add New Package Manager
1. Add parser to `ecdat/scanners/dependency/parsers.py`
2. Add crypto package mappings to `ecdat/scanners/dependency/crypto_packages.py`

### Add New Config Format
1. Implement scanner subclassing `Scanner`
2. Register in `ConfigScanner._init_scanners()`

### Add New Certificate Format
1. Implement scanner subclassing `Scanner`
2. Register in `CertificateScanner.__init__()`

## License

MIT