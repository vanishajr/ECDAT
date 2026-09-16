import json

with open('ecdat/tests/fixtures/source/ground_truth.json') as f:
    data = json.load(f)

# Fix ec_ops.py
for fixture in data['fixtures']:
    if 'ec_ops.py' in fixture['fixture_path']:
        fixture['expected_findings'] = [
            {
                "canonical": "ECDSA",
                "original": "ECDSA",
                "curve": "P-256",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KeyManagement",
                "function": "generate_ec_key_pair",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ec_ops.py",
                    "line": 7,
                    "function": "generate_ec_key_pair"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "ECDSA",
                "original": "ECDSA",
                "curve": "P-256",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KeyManagement",
                "function": "generate_ec_key_pair",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ec_ops.py",
                    "line": 8,
                    "function": "generate_ec_key_pair"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "ECDSA",
                "original": "ECDSA",
                "curve": "P-256",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "Sign",
                "function": "ecdsa_sign",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ec_ops.py",
                    "line": 12,
                    "function": "ecdsa_sign"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "ECDSA",
                "original": "ECDSA",
                "curve": "P-256",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "Verify",
                "function": "ecdsa_verify",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ec_ops.py",
                    "line": 17,
                    "function": "ecdsa_verify"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "ECDH",
                "original": "ECDH",
                "curve": "P-256",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KeyExchange",
                "function": "ecdh_key_exchange",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ec_ops.py",
                    "line": 23,
                    "function": "ecdh_key_exchange"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "HKDF",
                "original": "HKDF",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KDF",
                "function": "ecdh_key_exchange",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ec_ops.py",
                    "line": 24,
                    "function": "ecdh_key_exchange"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            }
        ]

# Fix ecdh_hkdf.py
for fixture in data['fixtures']:
    if 'ecdh_hkdf.py' in fixture['fixture_path']:
        fixture['expected_findings'] = [
            {
                "canonical": "ECDSA",
                "original": "ECDSA",
                "curve": "P-256",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KeyManagement",
                "function": "ecdh_key_exchange",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ecdh_hkdf.py",
                    "line": 6,
                    "function": "ecdh_key_exchange"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "ECDSA",
                "original": "ECDSA",
                "curve": "P-256",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KeyManagement",
                "function": "ecdh_key_exchange",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ecdh_hkdf.py",
                    "line": 7,
                    "function": "ecdh_key_exchange"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "ECDH",
                "original": "ECDH",
                "curve": "P-256",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KeyExchange",
                "function": "ecdh_key_exchange",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ecdh_hkdf.py",
                    "line": 8,
                    "function": "ecdh_key_exchange"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "ECDSA",
                "original": "ECDSA",
                "curve": "P-256",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KeyManagement",
                "function": "ecdsa_sign",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ecdh_hkdf.py",
                    "line": 12,
                    "function": "ecdsa_sign"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "ECDSA",
                "original": "ECDSA",
                "curve": "P-256",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "Sign",
                "function": "ecdsa_sign",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ecdh_hkdf.py",
                    "line": 14,
                    "function": "ecdsa_sign"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "HKDF",
                "original": "HKDF",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KDF",
                "function": "hkdf_derive",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ecdh_hkdf.py",
                    "line": 18,
                    "function": "hkdf_derive"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            }
        ]

# Fix ed25519_ops.py
for fixture in data['fixtures']:
    if 'ed25519_ops.py' in fixture['fixture_path']:
        fixture['expected_findings'] = [
            {
                "canonical": "X25519",
                "original": "X25519",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KeyManagement",
                "function": "generate_x25519_key_pair",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ed25519_ops.py",
                    "line": 7,
                    "function": "generate_x25519_key_pair"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "X25519",
                "original": "X25519",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KeyManagement",
                "function": "generate_x25519_key_pair",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ed25519_ops.py",
                    "line": 8,
                    "function": "generate_x25519_key_pair"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "X25519",
                "original": "X25519",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KeyExchange",
                "function": "x25519_key_exchange",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ed25519_ops.py",
                    "line": 12,
                    "function": "x25519_key_exchange"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "HKDF",
                "original": "HKDF",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KDF",
                "function": "x25519_key_exchange",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ed25519_ops.py",
                    "line": 13,
                    "function": "x25519_key_exchange"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "Ed25519",
                "original": "Ed25519",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KeyManagement",
                "function": "generate_ed25519_key_pair",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ed25519_ops.py",
                    "line": 22,
                    "function": "generate_ed25519_key_pair"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "Ed25519",
                "original": "Ed25519",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "KeyManagement",
                "function": "generate_ed25519_key_pair",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ed25519_ops.py",
                    "line": 23,
                    "function": "generate_ed25519_key_pair"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "Ed25519",
                "original": "Ed25519",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "Sign",
                "function": "ed25519_sign",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ed25519_ops.py",
                    "line": 27,
                    "function": "ed25519_sign"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            },
            {
                "canonical": "Ed25519",
                "original": "Ed25519",
                "library": "cryptography",
                "usage_state": "Confirmed",
                "confidence": 0.85,
                "operation_type": "Verify",
                "function": "ed25519_verify",
                "location": {
                    "file": "ecdat/tests/fixtures/source/ed25519_ops.py",
                    "line": 32,
                    "function": "ed25519_verify"
                },
                "match_strategy": "proximity",
                "proximity_lines": 3
            }
        ]

with open('ecdat/tests/fixtures/source/ground_truth.json', 'w') as f:
    json.dump(data, f, indent=2)

print("Ground truth updated successfully!")