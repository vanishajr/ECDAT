# ECDAT Cryptographic Analysis Report

## 1. Executive Summary

- Project: rsa_small.py
- Status: COMPLETE
- Overall risk: **NONE** (0.0/10, 0 risk records)
- Findings: 1 (operations: 0, assets: 0)
- Files: 1 / 1 with cryptographic evidence

ECDAT analyzed 1 files in rsa_small.py and detected 1 finding. The main risks are RSA-1024. These issues are concentrated in (root) and should be prioritized for migration.

- Confirmed findings: 0
- Declared capabilities (unconfirmed): 1

## 2. Priority Findings

No confirmed findings.

Severity distribution (measured risk class per finding): high=1.

## 3. Cryptographic Inventory (Confirmed Use)

No confirmed cryptographic use.

Unconfirmed finding groups: RSA-1024 x1

## 4. Affected Components

| Module | Findings | Files | Top severity | Algorithms |
| --- | --- | --- | --- | --- |
| (root) | 1 | 1 | [HIGH] high | RSA-1024 |

## 5. Migration Priorities

No migration actions.

## 6. Scan Coverage

Coverage: 1 / 1 files with cryptographic evidence (profile: standard).

- 0 file(s) skipped before analysis; 0 file(s) analyzed with no cryptographic evidence.

## 7. Methodology & Technical Details

P1 quantum/classical risk engine: Mosca-style score per operation (0.35*Q + 0.20*E + 0.15*B + 0.15*C + 0.15*mosca_boost, clamped 0..1, wire scale 0..10); classes Critical >= 8, High >= 6, Medium >= 4, Low >= 2, else Informational. ProvidedOnly caps at Low; suppressed states score 0.0 Informational.

- Risk source: no-risk-record
- Signature registry:
- Profile: standard; elapsed: Nones
- Scan ID: scan-minimal-001
- Target: rsa_small.py
- Started: 2026-09-10T10:00:00Z
- Finished: 2026-09-10T10:00:02Z
- Detector ecdat: 0.1.0

## 8. Detailed Findings

| Severity | Rule | Title | File | Line | Confidence |
| --- | --- | --- | --- | --- | --- |
| [HIGH] high | RSA-1024 | Weak RSA key size (1024-bit) | rsa_small.py | 12 | 0.95 |

