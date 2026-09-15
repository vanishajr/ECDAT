# Person 2 Scanner → Person 1 CIR Handoff

This document is the scanner-output contract for Person 2. It is intentionally limited to the boundary between discovery/scanning and Person 1’s core intelligence. Do not connect this output to the CLI or GUI yet.

## 1. Authoritative schema

The exact, authoritative schema file is:

```text
ecdat/core/cir.schema.json
```

This file is the source of truth for CIR v0.1. Do not invent a scanner-specific JSON format and do not silently add fields. The schema uses `additionalProperties: false` throughout the record objects. If the schema must change, version the CIR format instead of changing v0.1 in place.

The schema `$id` is:

```text
https://ecdat.local/schemas/cir/v0.1/cir.schema.json
```

The current registry version used by the repository is `2026.09.11`. The schema file itself should be passed alongside this handoff when sharing the contract.

## 2. Required top-level document

Every scanner result that is emitted as CIR must have this envelope:

```json
{
  "cir_version": "0.1",
  "scan_id": "scan:...",
  "target": "...",
  "started_at": "2026-09-12T10:00:00Z",
  "finished_at": "2026-09-12T10:00:01Z",
  "tool_versions": {
    "semgrep": "1.XX.X"
  },
  "registry_version": "2026.09.11",
  "assets": [],
  "operations": [],
  "graph": {
    "nodes": [],
    "edges": []
  },
  "stats": {
    "asset_count": 0,
    "operation_count": 0,
    "node_count": 0,
    "edge_count": 0
  }
}
```

`risks` and `recommendations` are optional downstream fields. Person 2 should normally not produce them; Person 1’s risk and recommendation engines produce those later.

## 3. Exact field rules

### `CryptoAsset`

Required fields:

```text
asset_id, canonical, usage_state, confidence, evidence
```

Optional fields:

```text
original, key_size, mode, curve, protocol, library,
location, implementation, context, risk_inputs
```

Rules:

- `asset_id` must match `^ast:[0-9a-f]{16}$`.
- `canonical` is the normalized algorithm/artefact name, not an arbitrary detector label.
- `original` preserves the scanner’s observed spelling or API name.
- `key_size` is an integer when known; omit it when unknown.
- `usage_state` must be exactly one of `Confirmed`, `Probable`, `Possible`, `ProvidedOnly`, or `FalsePositiveSuppressed`.
- `confidence` must be a number from `0` to `1`.
- `evidence` is an array of redacted `EvidenceSignal` objects.

### `CryptoOperation`

Required fields:

```text
operation_id, operation_type, asset_id, confidence, evidence
```

`operation_type` must be exactly one of:

```text
Encrypt, Decrypt, Sign, Verify, KeyExchange, Hash,
KDF, TLS, Storage, KeyManagement
```

Use one operation for one logical crypto use, not one operation for every repeated string match. Multiple detector signals for the same logical use belong in the same `evidence` array.

### `EvidenceSignal`

Required fields:

```text
tool, detail
```

Optional fields:

```text
confidence, snippet
```

`snippet` must be redacted. Never emit private keys, passwords, tokens, raw key material, credentials, or complete secrets.

### `Location`

Allowed fields:

```text
file, line, column, function, uri
```

For file findings, provide `file` and a one-based `line` when available. For binaries, use `uri` for offsets/symbols, for example `binary-offset:0x4a2f0`. For container artefacts, use a URI containing the image/layer digest and inner path.

### `Implementation`

Required field:

```text
library
```

Optional fields:

```text
version, provider, api
```

### `Context`

Required field:

```text
exposure
```

Allowed exposure values:

```text
internet-facing, internal, offline, cloud, third-party
```

### `RiskInputs`

Required field:

```text
usage_state
```

Optional fields:

```text
exposure, sensitive_data, external_dependency
```

Do not add owner, priority, phase, timeline, migration sequence, or PQC target fields to scanner output.

## 4. Realistic scanner examples

The following examples are records to place in the `assets` and `operations` arrays of the common envelope. They are examples of the required shape, not claims that the scanner must use these exact IDs.

### A. Source-code finding

```json
{
  "asset_id": "ast:1111111111111111",
  "canonical": "AES-256-GCM",
  "original": "AESGCM",
  "key_size": 256,
  "mode": "GCM",
  "library": "cryptography",
  "usage_state": "Confirmed",
  "confidence": 0.96,
  "evidence": [
    {
      "tool": "semgrep",
      "detail": "direct source API call: AESGCM.encrypt at src/payments/crypto.py:64",
      "confidence": 0.96,
      "snippet": "cipher = AESGCM(data_key); ciphertext = cipher.encrypt(nonce, payload, aad)"
    }
  ],
  "location": {
    "file": "src/payments/crypto.py",
    "line": 64,
    "function": "encrypt_payment_payload"
  },
  "implementation": {
    "library": "cryptography",
    "version": "44.0.0",
    "api": "AESGCM.encrypt"
  },
  "context": {
    "exposure": "internet-facing",
    "environment": "production",
    "data_classification": "restricted"
  },
  "risk_inputs": {
    "usage_state": "Confirmed",
    "exposure": "internet-facing",
    "sensitive_data": true,
    "external_dependency": false
  }
}
```

Matching logical operation:

```json
{
  "operation_id": "op:1111111111111111",
  "operation_type": "Encrypt",
  "asset_id": "ast:1111111111111111",
  "confidence": 0.96,
  "evidence": [
    {
      "tool": "semgrep",
      "detail": "direct source API call: AESGCM.encrypt at src/payments/crypto.py:64",
      "confidence": 0.96,
      "snippet": "cipher.encrypt(nonce, payload, aad)"
    }
  ],
  "function": "encrypt_payment_payload",
  "location": {
    "file": "src/payments/crypto.py",
    "line": 64,
    "function": "encrypt_payment_payload"
  },
  "implementation": {
    "library": "cryptography",
    "version": "44.0.0",
    "api": "AESGCM.encrypt"
  },
  "context": {
    "exposure": "internet-facing",
    "environment": "production",
    "data_classification": "restricted"
  },
  "risk_inputs": {
    "usage_state": "Confirmed",
    "exposure": "internet-facing",
    "sensitive_data": true,
    "external_dependency": false
  }
}
```

### B. Binary finding

For a binary, preserve the executable path and offset/symbol in `location` and `EvidenceSignal.detail`.

```json
{
  "asset_id": "ast:2222222222222222",
  "canonical": "RSA",
  "original": "RSA_public_encrypt",
  "key_size": 2048,
  "library": "openssl",
  "usage_state": "Probable",
  "confidence": 0.82,
  "evidence": [
    {
      "tool": "lief",
      "detail": "imported symbol RSA_public_encrypt from libcrypto.so.3",
      "confidence": 0.78,
      "snippet": "ELF import: RSA_public_encrypt"
    },
    {
      "tool": "yara-x",
      "detail": "RSA operation signature matched in payments-worker at offset 0x4a2f0",
      "confidence": 0.72,
      "snippet": "RSA_public_encrypt referenced at binary offset 0x4a2f0"
    }
  ],
  "location": {
    "file": "bin/payments-worker",
    "uri": "binary-offset:0x4a2f0"
  },
  "implementation": {
    "library": "openssl",
    "version": "3.0.13",
    "api": "RSA_public_encrypt"
  },
  "context": {
    "exposure": "internal",
    "environment": "staging",
    "data_classification": "confidential"
  },
  "risk_inputs": {
    "usage_state": "Probable",
    "exposure": "internal",
    "sensitive_data": true,
    "external_dependency": false
  }
}
```

Matching operation type for an observed encryption call is `Encrypt`; if the binary evidence only proves a signing path, use `Sign`. Do not call every imported symbol `Confirmed` without call/use context.

### C. Container finding

Container metadata belongs in `location.uri`, `context.notes`, or both. Keep the image and layer digest so evidence can be traced back to the immutable artefact.

```json
{
  "asset_id": "ast:3333333333333333",
  "canonical": "OpenSSL",
  "original": "openssl-3.0.13",
  "library": "openssl",
  "usage_state": "ProvidedOnly",
  "confidence": 0.60,
  "evidence": [
    {
      "tool": "syft",
      "detail": "package capability found in image layer sha256:9f2c7a1e4b5d",
      "confidence": 0.60,
      "snippet": "openssl 3.0.13 installed at /usr/lib/x86_64-linux-gnu"
    }
  ],
  "location": {
    "file": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
    "uri": "image:sha256:9f2c7a1e4b5d/layer:sha256:layer01"
  },
  "implementation": {
    "library": "openssl",
    "version": "3.0.13"
  },
  "context": {
    "exposure": "cloud",
    "environment": "production",
    "notes": "Package capability only; no matching application-use evidence"
  },
  "risk_inputs": {
    "usage_state": "ProvidedOnly",
    "exposure": "cloud",
    "sensitive_data": false,
    "external_dependency": true
  }
}
```

Dependency/library presence alone must be `ProvidedOnly` unless source, binary, config, runtime, or other evidence demonstrates actual use.

### D. Configuration/certificate finding

Configuration and certificate evidence can refer to the same asset. Use separate evidence signals when the config parser and X.509 parser contribute distinct facts.

```json
{
  "asset_id": "ast:4444444444444444",
  "canonical": "RSA",
  "original": "RSA-2048 X.509 certificate",
  "key_size": 2048,
  "protocol": "TLS1.2",
  "library": "openssl",
  "usage_state": "Confirmed",
  "confidence": 0.93,
  "evidence": [
    {
      "tool": "nginx-config-parser",
      "detail": "certificate configured for server block at /etc/nginx/nginx.conf:18",
      "confidence": 0.90,
      "snippet": "ssl_certificate /etc/tls/payments.crt;"
    },
    {
      "tool": "x509-parser",
      "detail": "certificate payments.crt has RSA-2048 public key and valid SAN pay.example.com",
      "confidence": 0.96,
      "snippet": "subject=CN=pay.example.com; public-key=RSA-2048; fingerprint=sha256:[REDACTED]"
    }
  ],
  "location": {
    "file": "/etc/nginx/nginx.conf",
    "line": 18,
    "uri": "certificate:/etc/tls/payments.crt"
  },
  "implementation": {
    "library": "openssl",
    "version": "3.0.13",
    "api": "TLS certificate configuration"
  },
  "context": {
    "exposure": "internet-facing",
    "environment": "production",
    "data_classification": "restricted"
  },
  "risk_inputs": {
    "usage_state": "Confirmed",
    "exposure": "internet-facing",
    "sensitive_data": true,
    "external_dependency": false
  }
}
```

Matching operation:

```json
{
  "operation_id": "op:4444444444444444",
  "operation_type": "TLS",
  "asset_id": "ast:4444444444444444",
  "confidence": 0.93,
  "evidence": [
    {
      "tool": "nginx-config-parser",
      "detail": "TLS certificate configured at /etc/nginx/nginx.conf:18",
      "confidence": 0.90,
      "snippet": "ssl_certificate /etc/tls/payments.crt;"
    },
    {
      "tool": "x509-parser",
      "detail": "RSA-2048 certificate fingerprint matched configured payments.crt",
      "confidence": 0.96,
      "snippet": "public-key=RSA-2048; fingerprint=sha256:[REDACTED]"
    }
  ],
  "location": {
    "file": "/etc/nginx/nginx.conf",
    "line": 18,
    "uri": "endpoint:https://pay.example.com:443"
  },
  "implementation": {
    "library": "openssl",
    "version": "3.0.13"
  },
  "context": {
    "exposure": "internet-facing",
    "environment": "production",
    "data_classification": "restricted"
  },
  "risk_inputs": {
    "usage_state": "Confirmed",
    "exposure": "internet-facing",
    "sensitive_data": true,
    "external_dependency": false
  }
}
```

### E. Dependency-only finding

This is deliberately not an algorithm-use finding:

```json
{
  "asset_id": "ast:5555555555555555",
  "canonical": "OpenSSL",
  "original": "openssl@3.0.13",
  "library": "openssl",
  "usage_state": "ProvidedOnly",
  "confidence": 0.55,
  "evidence": [
    {
      "tool": "syft",
      "detail": "dependency inventory lists openssl@3.0.13 in requirements.lock",
      "confidence": 0.55,
      "snippet": "openssl==3.0.13"
    }
  ],
  "location": {
    "file": "requirements.lock",
    "line": 27
  },
  "implementation": {
    "library": "openssl",
    "version": "3.0.13"
  },
  "context": {
    "exposure": "internal",
    "environment": "production",
    "notes": "Capability provided by dependency; no confirmed crypto operation"
  },
  "risk_inputs": {
    "usage_state": "ProvidedOnly",
    "exposure": "internal",
    "sensitive_data": false,
    "external_dependency": true
  }
}
```

Do not expand this into one finding for every algorithm supported by OpenSSL. Emit only the library capability unless actual-use evidence exists.

### F. Multiple evidence signals for one crypto asset

Use one shared `asset_id` and one shared logical operation when source, binary, container, certificate, config, runtime, or cloud evidence refers to the same underlying asset/use. Put the signals in the same evidence array:

```json
{
  "asset_id": "ast:6666666666666666",
  "canonical": "RSA",
  "original": "RSA / rsa.encrypt / RSA_public_encrypt",
  "key_size": 2048,
  "library": "cryptography",
  "usage_state": "Confirmed",
  "confidence": 0.96,
  "evidence": [
    {
      "tool": "semgrep",
      "detail": "source call rsa.encrypt at src/payments/payments.py:64",
      "confidence": 0.95,
      "snippet": "rsa.encrypt(card_token, public_key)"
    },
    {
      "tool": "lief",
      "detail": "payments-worker imports RSA_public_encrypt from libcrypto.so.3",
      "confidence": 0.84,
      "snippet": "RSA_public_encrypt @ binary offset 0x12ab"
    },
    {
      "tool": "x509-parser",
      "detail": "payments.crt RSA-2048 public-key fingerprint matches source key",
      "confidence": 0.91,
      "snippet": "RSA-2048 fingerprint=sha256:[REDACTED]"
    }
  ],
  "location": {
    "file": "src/payments/payments.py",
    "line": 64,
    "function": "charge",
    "uri": "binary:payments-worker;certificate:payments.crt"
  },
  "implementation": {
    "library": "cryptography",
    "version": "44.0.0",
    "api": "rsa.encrypt"
  },
  "context": {
    "exposure": "internet-facing",
    "environment": "production",
    "data_classification": "restricted"
  },
  "risk_inputs": {
    "usage_state": "Confirmed",
    "exposure": "internet-facing",
    "sensitive_data": true,
    "external_dependency": false
  }
}
```

Matching operation:

```json
{
  "operation_id": "op:6666666666666666",
  "operation_type": "Encrypt",
  "asset_id": "ast:6666666666666666",
  "confidence": 0.96,
  "evidence": [
    {
      "tool": "semgrep",
      "detail": "source call rsa.encrypt at src/payments/payments.py:64",
      "confidence": 0.95,
      "snippet": "rsa.encrypt(card_token, public_key)"
    },
    {
      "tool": "lief",
      "detail": "payments-worker imports RSA_public_encrypt from libcrypto.so.3",
      "confidence": 0.84,
      "snippet": "RSA_public_encrypt @ binary offset 0x12ab"
    },
    {
      "tool": "x509-parser",
      "detail": "payments.crt key fingerprint matches source key",
      "confidence": 0.91,
      "snippet": "RSA-2048 fingerprint=sha256:[REDACTED]"
    }
  ],
  "function": "charge",
  "location": {
    "file": "src/payments/payments.py",
    "line": 64,
    "function": "charge"
  },
  "implementation": {
    "library": "cryptography",
    "version": "44.0.0",
    "api": "rsa.encrypt"
  },
  "context": {
    "exposure": "internet-facing",
    "environment": "production",
    "data_classification": "restricted"
  },
  "risk_inputs": {
    "usage_state": "Confirmed",
    "exposure": "internet-facing",
    "sensitive_data": true,
    "external_dependency": false
  }
}
```

The important rule is **same asset identity + evidence array**, not three separate RSA assets. If the signals refer to different operations or different keys/certificates, use separate assets or operations and explain the distinction in `detail`.

## 5. Graph records from scanners

The CIR graph uses a separate compact schema from the GUI graph. CIR graph nodes use these `kind` values:

```text
asset, operation, file, service, host, library, key
```

CIR graph edges use these `relationship` values:

```text
uses, calls, contains, derives, protects, depends_on, terminates
```

Example:

```json
{
  "nodes": [
    {"id": "svc:payments-api", "kind": "service", "label": "payments-api"},
    {"id": "op:6666666666666666", "kind": "operation", "ref": "op:6666666666666666", "label": "RSA encryption"},
    {"id": "ast:6666666666666666", "kind": "asset", "ref": "ast:6666666666666666", "label": "RSA"},
    {"id": "lib:cryptography@44.0.0", "kind": "library", "label": "cryptography 44.0.0"}
  ],
  "edges": [
    {"from": "svc:payments-api", "to": "op:6666666666666666", "relationship": "uses"},
    {"from": "op:6666666666666666", "to": "ast:6666666666666666", "relationship": "derives"},
    {"from": "op:6666666666666666", "to": "lib:cryptography@44.0.0", "relationship": "depends_on"}
  ]
}
```

Every graph edge endpoint must have a corresponding node. Do not emit GUI-only node types such as `CryptoAsset` or GUI-only relations such as `provides` in the CIR graph; those are produced by the GUI projection layer.

## 6. Identity, canonicalization, and evidence rules

- Use the shared signature registry in `ecdat/core/signature_registry.json` and report its version in `registry_version`.
- Preserve the observed detector spelling in `original`; put the normalized name in `canonical`.
- Prefer the repository’s deterministic ID helpers:

```python
from ecdat.core.cir_models import new_asset_id, new_operation_id

asset_id = new_asset_id(canonical, key_size, mode, curve, protocol)
operation_id = new_operation_id(operation_type, asset_id, function, location)
```

- Use `Confirmed` only for strong direct-use or corroborated evidence.
- Use `Probable` for strong indirect evidence such as binary symbols/imports with useful context.
- Use `Possible` for weak or ambiguous matches.
- Use `ProvidedOnly` for dependency/library capability without use evidence.
- Use `FalsePositiveSuppressed` for supported test-fixture, dead-code, or checksum-only suppression.
- Do not infer crypto use from a library being installed.
- Do not emit raw secrets or private-key contents, even temporarily in snippets.
- Do not emit Person 1 risk, recommendation, owner, priority, effort, phase, timeline, migration-state, or PQC-target fields in scanner records.
- Empty arrays are valid. A clean scan must still emit a valid envelope with empty `assets`, `operations`, and graph arrays.

## 7. Validation before handoff

Validate every generated document against the exact repository schema before passing it to Person 1:

```powershell
.\.venv-p1\Scripts\python.exe -c "from ecdat.core.cir_validate import load_cir_json; load_cir_json('scan.cir.json'); print('valid CIR')"
```

Or in Python:

```python
from ecdat.core.cir_validate import load_cir_json

document = load_cir_json("scan.cir.json")
```

A schema failure must stop the handoff. Do not repair malformed records downstream.

## 8. Existing repository references

Use these as additional valid examples:

```text
ecdat/core/samples/source-only.json
ecdat/core/samples/binary-only.json
ecdat/core/samples/container-only.json
ecdat/core/samples/multi-evidence.json
```

The most useful multi-surface example is `multi-evidence.json`: it demonstrates one asset with source, binary, and certificate evidence combined under one asset identity.

## 9. Person 2 delivery checklist

- [ ] Emit the exact top-level CIR v0.1 envelope.
- [ ] Validate output against `ecdat/core/cir.schema.json`.
- [ ] Use canonical names from `signature_registry.json`.
- [ ] Preserve observed names in `original`.
- [ ] Populate source, binary, container, config/certificate, dependency, runtime, or cloud evidence using the common `EvidenceSignal` shape.
- [ ] Keep dependency-only findings as `ProvidedOnly`.
- [ ] Merge corroborating evidence for the same asset instead of duplicating assets.
- [ ] Use deterministic `asset_id` and `operation_id` helpers where possible.
- [ ] Redact all secrets and raw key material.
- [ ] Use only the enumerated operation types, usage states, graph kinds, and graph relationships.
- [ ] Leave `risks` and `recommendations` to downstream Person 1 processing unless explicitly agreed otherwise.
