# ECDAT Report: scan-minimal-001

## Executive Summary

- Target: samples/rsa_small.py
- Findings: 1 (files scanned: 1)
- Risk: medium (5) [mock scoring]
- Rules affected: 1

## Scan Information

- Scan ID: scan-minimal-001
- Target: samples/rsa_small.py
- Started: 2026-09-10T10:00:00Z
- Finished: 2026-09-10T10:00:02Z
- Tool ecdat: 0.1.0

## Findings by Severity

| Severity | Count |
| --- | --- |
| high | 1 |

## Findings by Rule

| Rule | Severity | Count | Title |
| --- | --- | --- | --- |
| RSA-1024 | high | 1 | Weak RSA key size (1024-bit) |

## Top Affected Files/Services

| File/Service | Count |
| --- | --- |
| samples/rsa_small.py | 1 |

## Risk Summary (mock)

Score 5 / level medium using the temporary mock scoring model.

## Migration Summary (mock placeholder)

- RSA-1024 [high] x1: Replace 1024-bit RSA keys with 2048-bit+ RSA or PQC KEM (mock).

## Disclaimer

Risk and migration sections are mock/placeholder output pending Person 1's real risk and PQC recommendation engine.
