"""Phase 4 regression: multi-language source semantics (C/C++ first).

Seeded fixtures with known ground truth (ground_truth.json entries with
``"suite": "phase4"``): precision/recall by language, parameter
extraction, wrapper resolution, noise suppression, and the OpenSSL
acceptance subset (implementation vs capability vs test vs use).

Fixtures live under ``ecdat/tests/`` so they are copied to a neutral
tmp path before scanning: path-based test-vector classification is real
behavior, and the harness must not trip it with its own directory.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from ecdat.scanners.source import SourceScanner

FIXTURES = Path(__file__).parent / "fixtures" / "source"


def _scan_copied(name: str, tmp_path: Path):
    target = tmp_path / name
    target.write_bytes((FIXTURES / name).read_bytes())
    scanner = SourceScanner()
    return scanner.scan(target), scanner


def _op(finding) -> str:
    return finding.operation_type.value if finding.operation_type else ""


def _phase4_entries() -> list[dict]:
    doc = json.loads((FIXTURES / "ground_truth.json").read_text())
    return [e for e in doc["fixtures"] if e.get("suite") == "phase4"]


def _match(expected: dict, findings: list) -> bool:
    want_file = Path(expected["location"]["file"]).name
    want_line = int(expected["location"].get("line", 0))
    window = int(expected.get("proximity_lines", 2))
    for finding in findings:
        loc = finding.location
        if loc is None or Path(str(loc.file)).name != want_file:
            continue
        try:
            line = int(loc.line or 0)
        except (TypeError, ValueError):
            continue
        if abs(line - want_line) > window:
            continue
        if finding.canonical != expected["canonical"]:
            continue
        if "operation_type" in expected and _op(finding) != expected["operation_type"]:
            continue
        return True
    return False


def test_ground_truth_precision_recall_by_language(tmp_path, capsys):
    per_lang: dict[str, dict[str, int]] = {}
    for entry in _phase4_entries():
        name = Path(entry["fixture_path"]).name
        findings, _ = _scan_copied(name, tmp_path)
        expected = entry.get("expected_findings", [])
        matched_expected = sum(1 for e in expected if _match(e, findings))
        # Precision: an actual finding counts when it matches any expected
        # entry (same proximity/canonical/op rule, reversed).
        matched_actual = 0
        for finding in findings:
            loc = finding.location
            probe = {"location": {
                "file": loc.file if loc else "",
                "line": int(loc.line or 0) if loc else 0},
                "canonical": finding.canonical,
                "operation_type": _op(finding),
                "proximity_lines": 0}
            # Reuse the matcher with the finding as "expected".
            if _match(probe, [
                    _Expectation(e, name) for e in expected]):
                matched_actual += 1
        lang = entry.get("language", "unknown")
        bucket = per_lang.setdefault(
            lang, {"tp": 0, "actual": 0, "expected": 0})
        bucket["tp"] += matched_expected
        bucket["actual"] += len(findings)
        bucket["expected"] += len(expected)
        recall = (matched_expected / len(expected)) if expected else 1.0
        precision = (matched_actual / len(findings)) if findings else 1.0
        print(f"{lang:8s} {name:22s} "
              f"recall={matched_expected}/{len(expected)} "
              f"precision={matched_actual}/{len(findings)}")
        assert recall >= 0.9, f"{name}: recall {recall}"
        assert precision >= 0.85, f"{name}: precision {precision}"
        for pattern in entry.get("negative_patterns", []):
            assert all(pattern not in (f.canonical or "")
                       for f in findings), f"{name}: leaked {pattern}"
    totals = {"tp": sum(b["tp"] for b in per_lang.values()),
              "actual": sum(b["actual"] for b in per_lang.values()),
              "expected": sum(b["expected"] for b in per_lang.values())}
    overall_recall = totals["tp"] / totals["expected"]
    overall_precision = totals["tp"] / totals["actual"]
    print(f"OVERALL recall={totals['tp']}/{totals['expected']}={overall_recall:.3f} "
          f"precision={totals['tp']}/{totals['actual']}={overall_precision:.3f}")
    assert overall_recall >= 0.9
    assert overall_precision >= 0.85
    assert per_lang["c"]["tp"] == per_lang["c"]["expected"]  # C: full recall


class _Expectation:
    """Adapter letting _match() treat a finding as ground truth."""

    def __init__(self, expected: dict, name: str):
        self.canonical = expected["canonical"]
        self._op = expected.get("operation_type", "")
        self.location = _Loc(name, int(expected["location"].get("line", 0)))

    @property
    def operation_type(self):
        return _Op(self._op)


class _Loc:
    def __init__(self, name: str, line: int):
        self.file = name
        self.line = line


class _Op:
    def __init__(self, value: str):
        self.value = value


def test_parameter_extraction_spot_checks(tmp_path):
    findings, _ = _scan_copied("c_openssl_evp.c", tmp_path)
    by_line = {}
    for finding in findings:
        by_line.setdefault(int(finding.location.line), []).append(finding)
    init = [f for f in by_line[12] if f.canonical == "AES-256-GCM"][0]
    assert init.key_size == 256 and init.mode == "GCM"
    assert init.function == "app_encrypt"
    dec = [f for f in by_line[18] if f.operation_type.value == "Decrypt"][0]
    assert (dec.key_size, dec.mode) == (128, "CBC")
    rsa = [f for f in by_line[34] if f.canonical == "RSA"][0]
    assert rsa.key_size == 2048
    tls_min = [f for f in by_line[47] if f.protocol][0]
    assert tls_min.protocol == "TLS1.2"
    node, _ = _scan_copied("node_crypto.js", tmp_path)
    ecdh = [f for f in node if f.canonical == "ECDH"][0]
    assert ecdh.curve == "P-256"


def test_wrapper_signal_and_inherited_semantics(tmp_path):
    findings, _ = _scan_copied("c_wrappers_const.c", tmp_path)
    direct = [f for f in findings
              if int(f.location.line) == 6][0]
    assert direct.evidence[0].tool == "source:api-call"
    assert direct.usage_state.value == "Confirmed"
    wrapped = [f for f in findings
               if int(f.location.line) == 10][0]
    assert wrapped.evidence[0].tool == "source:wrapper-call"
    assert wrapped.usage_state.value == "Probable"
    # Inherited, not re-guessed: the wrapper carries the AES-128-CBC
    # semantics resolved inside raw_encrypt (via #define propagation).
    assert (wrapped.canonical, wrapped.key_size, wrapped.mode) == \
        ("AES-128-CBC", 128, "CBC")
    assert "raw_encrypt" in wrapped.evidence[0].detail


def test_noise_fixture_is_silent_but_counted(tmp_path):
    findings, scanner = _scan_copied("c_noise.c", tmp_path)
    assert findings == []
    assert scanner.last_stats()["suppressed_noise"] > 0
    assert scanner.last_stats()["by_language"].get("c") == 1


def test_direct_calls_outrank_strings_and_comments(tmp_path):
    findings, _ = _scan_copied("c_openssl_evp.c", tmp_path)
    tools = {f.evidence[0].tool for f in findings}
    assert tools == {"source:api-call"}
    assert all(f.confidence >= 0.8 for f in findings
               if f.usage_state.value == "Confirmed")


def _openssl_like_tree(root: Path) -> dict[str, Path]:
    (root / "crypto").mkdir(parents=True)
    (root / "apps").mkdir()
    (root / "test").mkdir()
    (root / "include" / "openssl").mkdir(parents=True)
    impl = root / "crypto" / "e_aes.c"
    impl.write_text(
        "#include <openssl/aes.h>\n"
        "int AES_init_key(AES_KEY *key, const unsigned char *userKey) {\n"
        "    return AES_set_encrypt_key(userKey, 128, key);\n"
        "}\n")
    use = root / "apps" / "enc.c"
    use.write_text(
        "#include <openssl/evp.h>\n"
        "int app_encrypt(EVP_CIPHER_CTX *ctx) {\n"
        "    return EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),\n"
        "                              NULL, NULL, NULL);\n"
        "}\n")
    test = root / "test" / "evp_test.c"
    test.write_text(
        "#include <openssl/evp.h>\n"
        "int test_vector_encrypt(EVP_CIPHER_CTX *ctx) {\n"
        "    return EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),\n"
        "                              NULL, NULL, NULL);\n"
        "}\n")
    header = root / "include" / "openssl" / "evp.h"
    header.write_text(
        "int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,\n"
        "                       const EVP_CIPHER *cipher,\n"
        "                       const unsigned char *key,\n"
        "                       const unsigned char *iv);\n"
        "const EVP_CIPHER *EVP_aes_256_gcm(void);\n")
    return {"impl": impl, "use": use, "test": test, "header": header}


def test_openssl_subset_acceptance(tmp_path):
    """Roadmap Phase 4 OpenSSL acceptance on a representative subset."""
    paths = _openssl_like_tree(tmp_path / "openssl-like")
    scanner = SourceScanner()
    impl = scanner.scan(paths["impl"])
    use = scanner.scan(paths["use"])
    vectors = scanner.scan(paths["test"])
    headers = scanner.scan(paths["header"])

    # Real semantic results, not ~zero.
    assert len(use) >= 1
    assert any(f.canonical == "AES-256-GCM" and
               f.usage_state.value == "Confirmed" for f in use)
    # Implementation is provision, never application use.
    assert impl, "expected implementation evidence"
    assert all(f.usage_state.value == "ProvidedOnly" for f in impl)
    assert all(f.dependency_only for f in impl)
    # Test vectors stay Possible, never Confirmed.
    assert vectors, "expected test-vector evidence"
    assert all(f.usage_state.value == "Possible" for f in vectors)
    assert not any(f.usage_state.value == "Confirmed" for f in vectors)
    # Capability-only headers (prototypes) produce nothing.
    assert headers == []
    # One engine run over the tree separates all three honestly.
    all_findings = SourceScanner().scan(tmp_path / "openssl-like")
    states = {(Path(f.location.file).name, f.usage_state.value)
              for f in all_findings}
    assert ("enc.c", "Confirmed") in states
    assert ("e_aes.c", "ProvidedOnly") in states
    assert ("evp_test.c", "Possible") in states


def test_inventory_routing_restricts_source_files(tmp_path):
    tree = tmp_path / "proj"
    tree.mkdir()
    shutil.copy(FIXTURES / "c_openssl_evp.c", tree / "a.c")
    shutil.copy(FIXTURES / "c_noise.c", tree / "b.c")
    scanner = SourceScanner()
    everything = scanner.scan(tree)
    assert len(everything) > 0
    restricted = scanner.scan(tree, artifacts=[
        {"abs_path": str(tree / "b.c"), "relative_path": "b.c",
         "category": "source"}])
    assert restricted == []
    only_a = scanner.scan(tree, artifacts=[
        {"abs_path": str(tree / "a.c"), "relative_path": "a.c",
         "category": "source"},
        {"abs_path": str(tree / "b.c"), "relative_path": "b.c",
         "category": "unknown"}])
    assert only_a and all(
        Path(f.location.file).name == "a.c" for f in only_a)


def test_semgrep_status_recorded_and_python_untouched(tmp_path):
    target = tmp_path / "a.py"
    target.write_text("x = 1\n")
    scanner = SourceScanner()
    assert scanner.scan(target) == []
    # Graceful degradation is recorded, never fatal (semgrep absent here).
    assert scanner.last_stats()["semgrep"] in ("unavailable", "not-run") or \
        scanner.last_stats()["semgrep"].startswith(("available", "error"))
    py, _ = _scan_copied("aes_gcm.py", tmp_path)
    assert {(f.canonical, f.operation_type.value,
             int(f.location.line)) for f in py} == {
        ("AES-256-GCM", "Encrypt", 5), ("AES-256-GCM", "Decrypt", 9)}
    assert all(f.evidence[0].tool == "source:ast" for f in py)
