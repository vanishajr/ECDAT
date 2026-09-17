# ECDAT Optional Tool Installation and Capability Guide

> Phase 14 artefact. Describes every optional analysis tool, its impact on
> scan coverage, and how to install/configure it. Core scans always work
> without these tools; their absence is reported in `diagnostics.scanner_status`
> and in the Coverage tab of the GUI — never silently treated as "nothing found."

---

## Core requirement (always needed)

| Package | Purpose |
|---------|---------|
| `cryptography` | Certificate/key parsing — PEM, DER, PKCS#12, SSH, JWK |
| `pydantic` | CIR/canonical schema validation |

Install via:

```bash
pip install -e .          # or: pip install ecdat
```

---

## Optional source-analysis tools

### Semgrep

**Impact**: Adds a third-party semantic rule pass on top of the built-in
registry-driven C/Python/Java/JS/Go/C#/Rust parser. When absent, only
the built-in fast-syntax engine runs.

```bash
pip install semgrep            # or: brew install semgrep
```

ECDAT auto-detects the `semgrep` binary via `shutil.which`; no
configuration needed. When present, results are merged and retagged
`source:semgrep`; conflicts are resolved by confidence. Absence is
recorded in `SourceScanner.last_stats()["semgrep_status"]`.

### Tree-sitter language bindings

**Impact**: Adds AST-level C/C++ analysis for cross-function prototype
resolution. The built-in regex+balanced-paren engine handles most cases;
tree-sitter improves accuracy on complex macro-heavy code.

```bash
pip install tree-sitter tree-sitter-c tree-sitter-cpp
```

Auto-detected by `SourceScanner`; absence recorded in `last_stats`.

---

## Optional binary-analysis tools

### LIEF

**Impact**: Provides ELF/PE/Mach-O metadata, import tables, symbol
tables, and section entropy. Without LIEF, ECDAT relies on strings-based
analysis only. Symbol/import evidence has higher confidence (0.55–0.90)
than plain strings (≤0.35).

```bash
pip install lief
```

Probed per-scan by `LiefScanner.is_available()`.

### YARA / YARA-X

**Impact**: Adds rule-based binary signature matching (crypto constants,
algorithm OIDs, packer markers). Without YARA, constant/OID matching
falls back to the built-in Python byte-scan.

```bash
pip install yara-python          # classic YARA
# or
pip install yara-x               # YARA-X (Rust-based, preferred)
```

Auto-detected by `BinaryScanner`; absence recorded in scanner status.

### capa (Mandiant)

**Impact**: Behavior-level capability analysis for ELF/PE binaries.
Escalated candidate binaries get behavior findings at confidence 0.75.
Without capa, behavior evidence is absent (recorded in `binary_tools` diagnostics).

```bash
pip install flare-capa
# or download standalone: https://github.com/mandiant/capa/releases
```

Only runs on binaries that pass the `should_escalate()` gate in
`standard`/`deep` profiles.

### FLOSS (FLARE Obfuscated String Solver)

**Impact**: Decodes obfuscated strings in packed/obfuscated binaries.
Runs only on binaries with packing/obfuscation signals. Decoded strings
are re-matched at confidence 0.5 (lower than raw symbols). Without FLOSS,
obfuscated-string evidence is absent.

```bash
pip install flare-floss
# or standalone: https://github.com/mandiant/flare-floss/releases
```

### Ghidra (optional deep backend)

**Impact**: Full decompiler analysis for stripped/high-value ambiguous
binaries in `deep` profile. Never runs automatically; requires explicit
configuration via `ECDAT_GHIDRA_PATH`.

```bash
# 1. Install Ghidra: https://ghidra-sre.org/
# 2. Set environment variable:
export ECDAT_GHIDRA_PATH=/path/to/ghidra_11.x/support/analyzeHeadless
```

Status probed from `expensive_tool_status()` in `binary/stages.py`; shown
in `binary_tools` diagnostics.

---

## Optional container tools

### Docker / Moby daemon

**Impact**: Required for pulling remote image references and for
`docker save`-style exports. Local OCI tarballs, rootfs directories,
and OCI layout directories work without Docker.

Permission gate: pulling requires `--allow-pull` (CLI) or `allowPull`
(GUI); building requires `--allow-build`.

### Syft (Anchore)

**Impact**: Package/SBOM extraction from container images and directories.
Adds OS-level package inventory to container inner scanning.

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh
```

Auto-detected by `syft` binary presence. Fallback: ECDAT scans inner
file system directly.

### cdxgen

**Impact**: CBOM/SBOM generation with richer language-level component
detection. Optional supplement to Syft.

```bash
npm install -g @cyclonedx/cdxgen
```

### Trivy (Aqua Security)

**Impact**: Vulnerability database cross-reference for container packages.
When absent, ECDAT provides crypto-focused analysis without CVE data.

```bash
# https://aquasecurity.github.io/trivy/latest/getting-started/installation/
brew install trivy   # macOS
```

---

## Optional runtime tools

### SSLyze

**Impact**: Deeper TLS protocol/cipher analysis and certificate chain
validation beyond ECDAT's stdlib TLS probe. Results have higher
reliability for negotiated-cipher evidence.

```bash
pip install sslyze
```

Auto-detected in `runtime/scanner.py::external_tool_status()`.

### testssl.sh

**Impact**: Comprehensive TLS testing including weak ciphers, BEAST,
POODLE, CRIME/BREACH, heartbleed, etc. Results are parsed and converted
to ECDAT evidence signals.

```bash
# https://testssl.sh/
curl -L -O https://github.com/drwetter/testssl.sh/archive/3.2.tar.gz
```

Set `ECDAT_TESTSSL_PATH` to the `testssl.sh` script path.

---

## Optional cloud SDK dependencies

### AWS (boto3)

**Impact**: KMS key inventory, ACM certificate metadata, ELB/ALB TLS
policy discovery. Without boto3, `aws` provider is unavailable.

```bash
pip install boto3
```

Credentials: standard AWS credential chain (env vars, `~/.aws/credentials`,
IAM role). Always read-only; no write operations performed.

### Azure (azure-mgmt-*)

**Impact**: Key Vault, ACM, TLS inventory. Currently marked
`azure-not-implemented` in `is_available()`; stub returns [] (no
fabricated evidence).

### GCP (google-cloud-*)

**Impact**: KMS, certificate manager. Currently marked
`gcp-not-implemented` in `is_available()`; stub returns [] (no
fabricated evidence).

---

## Tool-availability diagnostics

Every scan records tool availability in `diagnostics.scanner_status` and
`diagnostics.binary_tools`. These are exposed in:

- **CLI**: `ecdat scan --profile deep ./repo` → `Coverage:` section
- **GUI**: Coverage tab (Phase 12)
- **PDF/HTML reports**: §8 Coverage and Limitations section
- **SARIF**: `run.tool.extensions` array

No tool absence is silently converted to zero findings. The Coverage
section always lists tools that were checked.

---

## Checking availability without scanning

```bash
# Check which optional tools are found by the Python environment:
python -c "
import shutil
tools = ['semgrep', 'syft', 'cdxgen', 'trivy', 'sslyze']
for t in tools:
    print(t, shutil.which(t) or 'NOT FOUND')
"

# Check Python optional packages:
python -c "
for pkg in ['lief', 'yara', 'capa', 'floss', 'boto3']:
    try: import importlib; importlib.import_module(pkg); print(pkg, 'OK')
    except ImportError: print(pkg, 'NOT INSTALLED')
"
```

---

## Windows path notes

- ECDAT uses `pathlib.Path` and `shutil.which` throughout — no
  hardcoded POSIX paths.
- `ECDAT_GHIDRA_PATH`, `ECDAT_TESTSSL_PATH` accept Windows paths.
- Binary fixtures compiled with `gcc` (MinGW/MSYS2) are tested on
  Windows in the binary-stages test suite.
- The `.venv-p1` virtual environment was created and verified on
  Windows 11 / Python 3.13.

---

## Linux path notes

All tools above use standard Linux packaging. Container tools (Docker,
Syft, Trivy) are especially well-supported. ECDAT test suite runs on
both platforms; `sys.platform` guards protect platform-specific binary
builds in the test fixtures.
