# ECDAT Current Runtime Baseline (Phase 0 Artefact)

> Recorded as part of Phase 0 / Phase 1 audit. Updated through Phase 14.
> Describes the actual production runtime shape confirmed by 259 passing
> regression tests as of 2026-09-17.

---

## 1. Production scan entry points (all converge on one orchestrator)

```text
ecdat scan ./path
  → cli.py::build_parser() → scan_cmd.run()
  → commands/_real_scan.py → RealCoreClient.scan()
  → core/client.py → ScanOrchestrator.scan()

ecdat scan-binary ./bin
  → scan_binary_cmd.run() → RealCoreClient (caller="cli-scan-binary")
  → ScanOrchestrator.scan()

ecdat scan-container ./image.tar
  → scan_container_cmd.run() → RealCoreClient (caller="cli-scan-container")
  → ScanOrchestrator.scan()

ecdat scan-cloud aws
  → scan_cloud_cmd.run() → RealCoreClient (caller="cli-scan-cloud")
  → ScanOrchestrator.scan()

ecdat ci ./path
  → ci_cmd.run() → RealCoreClient (caller="ci")
  → ScanOrchestrator.scan() → gating-only result pass

GUI upload → POST /api/scan-jobs
  → web/server.py::_start_job() → thread _run_job()
  → ScanOrchestrator.scan(progress=callback)
```

**No production path bypasses `ScanOrchestrator`.**

---

## 2. Production orchestration pipeline (ScanOrchestrator.scan)

```text
ScanRequest
  → InputRegistry.normalize()       # target kind, hash
  → ArtifactInventory               # recursive walk, magic-based classify
  → AdaptiveScheduler.triage()      # artifact → scanner route
  → ScanCache lookup                # content-hash + profile + scanner version
  → DiscoveryEngine.scan_and_emit_cir()   # staged scanner execution
      → SourceScanner (C/Python/Java/JS/Go/C#/Rust + Semgrep opportunistic)
      → DependencyScanner (+ native C++: CMake/Conan/vcpkg/Meson/pkg-config)
      → BinaryScanner (staged: strings → LIEF/YARA → capa/FLOSS)
      → ConfigScanner (nginx/apache/k8s/terraform/envoy/generic + Dockerfile)
      → CertificateScanner (PEM/DER/PKCS12/JWK/SSH)
      → ContainerScanner (tar/OCI/rootfs; image-ref gated by allow_pull)
      → RuntimeScanner (TLS/SSH; gated by allow_runtime)
      → CloudScanner (AWS KMS/ACM/ELB; gated by credentials)
  → normalize_cir()                  # CIR normalization
  → reconstruct_cir()                # evidence fusion + operation builder
  → wire_system_links()              # crypto knowledge graph
  → cir_validate()                   # CIR schema validation
  → api.enrich_cir()                 # risk scoring + recommendations
  → to_canonical()                   # canonical JSON
  → validate_canonical()             # canonical schema validation
  → ScanResult (canonical, cir, plan, diagnostics)
  → ScanRepository.save_scan()       # durable persistence
```

---

## 3. Module classification

### Production (active pipeline)

| Module | Role |
|--------|------|
| `ecdat/core/orchestrator.py` | Single pipeline owner |
| `ecdat/core/scheduler.py` | InputRegistry + AdaptiveScheduler + ScanCache |
| `ecdat/core/inventory.py` | Artifact inventory + magic classification |
| `ecdat/core/fusion.py` | Evidence normalization + confidence fusion |
| `ecdat/core/operations.py` | Operation reconstruction (reconstruct_cir) |
| `ecdat/core/graph.py` | Crypto knowledge graph builder |
| `ecdat/core/risk.py` | Mosca-style quantum/classical risk engine |
| `ecdat/core/recommend.py` | Deterministic PQC recommendation policy |
| `ecdat/core/api.py` | enrich_cir / to_canonical adapter |
| `ecdat/core/cir_validate.py` | CIR JSON schema validation |
| `ecdat/store/repository.py` | ScanRepository — durable persistence |
| `ecdat/store/db.py` | SQLite schema + migration (v1→v2→v3) |
| `ecdat/adapters/pipeline.py` | Thin compat wrapper over orchestrator |
| `ecdat/adapters/scanner_policy.py` | DEFAULT_SCANNERS / OPT_IN_SCANNERS |
| `ecdat/adapters/graph_adapter.py` | Graph → GUI wire format |
| `ecdat/adapters/risk_view.py` | Risk → GUI wire format |
| `ecdat/scanners/discovery.py` | DiscoveryEngine (execution utility) |
| `ecdat/scanners/source/scanner.py` | Multi-language source scanner |
| `ecdat/scanners/source/api_knowledge.py` | Crypto API registry (~100 rows) |
| `ecdat/scanners/source/c_parser.py` | Fast-syntax C/C++ engine |
| `ecdat/scanners/binary/scanner.py` | Staged binary scanner |
| `ecdat/scanners/binary/stages.py` | CheapSignals + escalation + capa/FLOSS |
| `ecdat/scanners/binary/crypto_signatures.py` | Constants + OIDs + plausibility guard |
| `ecdat/scanners/dependency/scanner.py` | Dependency + native C++ + BOM import |
| `ecdat/scanners/dependency/crypto_packages.py` | Shared package→capability table |
| `ecdat/scanners/config/scanner.py` | Config family (registers Dockerfile) |
| `ecdat/scanners/config/dockerfile_scanner.py` | Dockerfile evidence (config family) |
| `ecdat/scanners/config/service_context.py` | Service/listener/cert join keys |
| `ecdat/scanners/certificate/*.py` | PEM/DER/JKS/PKCS12/JWK/SSH + fingerprints |
| `ecdat/scanners/container/scanner.py` | Unified container engine (v0.2.0) |
| `ecdat/scanners/runtime/tls_scanner.py` | TLS probe + cert fingerprint |
| `ecdat/scanners/runtime/ssh_scanner.py` | SSH probe + host-key fingerprint |
| `ecdat/scanners/cloud/aws_scanner.py` | AWS KMS/ACM/ELB with linkage notes |
| `ecdat/reports/aggregate.py` | Pure report aggregation (shared by all renderers) |
| `ecdat/reports/console.py` | Human-readable CLI summary (Phase 12G) |
| `ecdat/reports/html.py` | Self-contained offline HTML report |
| `ecdat/reports/pdf.py` | Multi-section production PDF |
| `ecdat/reports/markdown.py` | Markdown report |
| `ecdat/exports/cbom.py` | CycloneDX JSON/XML CBOM export |
| `ecdat/exports/sarif.py` | SARIF export with stable locations |
| `ecdat/exports/csv_gen.py` | CSV findings export |
| `ecdat/web/server.py` | GUI HTTP API |
| `frontend/src/App.tsx` | React GUI (Phase 12 UX) |

### Reusable but secondary

| Module | Role |
|--------|------|
| `ecdat/core/models.py` | Finding/Asset/Operation CIR-adjacent models |
| `ecdat/core/client.py` | CLI/CI adapter over orchestrator |
| `ecdat/core/registry.py` | Algorithm normalization registry |
| `ecdat/commands/*.py` | CLI command handlers |

### Legacy / historical (preserved, not deleted)

| Module | Status |
|--------|--------|
| `ecdat/Backup_GUI/` | Historical UI; clearly labeled backup |
| `tests/test_real_integration.py` | 36 failures — expects removed mock mode; preserved per roadmap rule |
| `tests/test_scan_specialized.py` | 30P/36F baseline — same |
| `ecdat/scanners/container/docker_scanner.py` | Daemon-based backend; kept as fallback |

### Stub / not-yet-implemented (honest, non-fabricating)

| Module | Status |
|--------|--------|
| `ecdat/scanners/cloud/azure_scanner.py` | `is_available()` False; `azure-not-implemented` |
| `ecdat/scanners/cloud/gcp_scanner.py` | `is_available()` False; `gcp-not-implemented` |

---

## 4. Current tool availability (this host: Windows 11, Python 3.13)

| Tool | Available | Impact |
|------|-----------|--------|
| `cryptography` | ✅ | Certificate/key parsing |
| `pydantic` | ✅ | CIR/canonical validation |
| `gcc` (MinGW) | ✅ | Binary test fixture compilation |
| `semgrep` | ❌ | Opportunistic source-semantic pass skipped |
| `lief` | ❌ | Import/symbol/section binary evidence absent |
| `yara` | ❌ | YARA rule constant matching absent |
| `capa` | ❌ | Behavior analysis absent (recorded unavailable) |
| `floss` | ❌ | Obfuscated-string decode absent (recorded) |
| `Ghidra` | ❌ | Deep decompiler absent (recorded) |
| Docker daemon | ❌ | Remote image pull/container inner-scan blocked |
| `syft` | ❌ | OS-layer package inventory absent |
| `trivy` | ❌ | Vuln-DB cross-reference absent |
| `sslyze` | ❌ | Enhanced TLS analysis absent |
| `boto3` | ❌ | AWS scanner unavailable (no credentials) |

All absences are reported in `diagnostics.scanner_status`, never silent.

---

## 5. Test baseline (Phase 14 final)

```
ecdat/tests: 259 passed, 0 failures, 1 warning (asyncio_mode)
tests/ (stale): 36 failed / 30 passed — identical to pre-change baseline
                (mock-mode expectations; preserved, not deleted)
frontend: npm run build — PASS
python -m ecdat.cli --help — PASS
```

---

## 6. Mock/legacy production outputs status

All the following were removed or replaced:

- `[mock scoring]` — removed from PDF/report pipeline
- `mock placeholder` text — removed
- Legacy "P1 vs real" dual-risk score — unified to real P1 only  
- Temp absolute paths in PDF — replaced with repo-relative display paths
- Azure/GCP stub findings — deleted (was fabricating 0.1-confidence evidence)
- Proximity correlation as primary confidence engine — superseded by fusion.py
- One-operation-per-raw-finding pattern — replaced by reconstruct_cir()

**No mock risk or migration output appears in the production pipeline.**
