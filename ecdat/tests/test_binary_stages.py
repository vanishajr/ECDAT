"""Phase 6 regression: staged binary analysis with real escalation.

Compiled fixtures are built fresh into tmp (gcc + OpenSSL dev libs when
present; gracefully skipped otherwise) so the repo stays source-only.
Pure-Python synthetic blobs cover the staging/escalation logic on every
host. Real binaries prove the cheap pass, constants, and FP discipline.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from ecdat.scanners.binary import BinaryScanner
from ecdat.scanners.binary import stages as bin_stages

SRC = Path(__file__).parent / "fixtures" / "binary" / "src"


def _has_gcc() -> bool:
    return shutil.which("gcc") is not None


def _compile(workdir: Path) -> dict[str, Path]:
    """Build real fixtures; missing pieces are skipped, never faked."""
    built: dict[str, Path] = {}
    cc = shutil.which("gcc")
    if not cc:
        return built
    app = workdir / "crypto_app.c"
    hello = workdir / "hello.c"
    app.write_bytes((SRC / "crypto_app.c").read_bytes())
    hello.write_bytes((SRC / "hello.c").read_bytes())

    def _run(args: list[str]) -> bool:
        try:
            proc = subprocess.run(args, capture_output=True, text=True,
                                  timeout=300, cwd=str(workdir))
            return proc.returncode == 0
        except Exception:
            return False

    dynamic = workdir / "app_dynamic.exe"
    if _run([cc, str(app), "-lcrypto", "-Wno-deprecated-declarations",
             "-o", str(dynamic)]):
        built["dynamic"] = dynamic
        if shutil.which("strip"):
            stripped = workdir / "app_stripped.exe"
            try:
                shutil.copy(dynamic, stripped)
                if _run(["strip", str(stripped)]):
                    built["stripped"] = stripped
            except Exception:
                pass
    static = workdir / "app_static.exe"
    if _run([cc, str(app), r"C:\msys64\ucrt64\lib\libcrypto.a",
             "-lws2_32", "-lcrypt32", "-lgdi32", "-luser32", "-lkernel32",
             "-ladvapi32", "-Wno-deprecated-declarations", "-o", str(static)]):
        built["static"] = static
    hello_bin = workdir / "hello.exe"
    if _run([cc, str(hello), "-o", str(hello_bin)]):
        built["hello"] = hello_bin
    return built


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    workdir = tmp_path_factory.mktemp("bin-fixtures")
    return _compile(workdir)


def _synthetic_crypto_blob() -> bytes:
    return (b"MZ" + b"\x00" * 58 +
            b"EVP_aes_256_gcm\x00libcrypto.dll\x00" +
            bytes.fromhex("637c777bf26b6f") +
            bytes.fromhex("06092a864886f70d010101") +
            b"SHA256_Init\x00")


def _synthetic_clean_blob() -> bytes:
    return b"MZ" + b"\x00" * 58 + b"hello deterministic world\x00"


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


# --- synthetic staging (every host) --------------------------------------


def test_synthetic_crypto_binary_stages(tmp_path):
    target = _write(tmp_path, "synth.exe", _synthetic_crypto_blob())
    scanner = BinaryScanner()
    findings = scanner.scan(target)
    canonicals = {f.canonical for f in findings}
    assert "AES-256-GCM" in canonicals  # symbol-shaped string
    assert "OpenSSL" in canonicals  # linked library string
    assert "AES" in canonicals  # embedded S-box constant
    assert "RSA" in canonicals  # embedded OID
    report = scanner.last_report()
    assert report["summary"]["binaries"] == 1
    assert report["summary"]["with_findings"] == 1
    assert report["summary"]["cheap_pass_candidates"] == 1
    assert report["summary"]["escalated_binaries"] == 1
    binary = report["binaries"][0]
    assert binary["signals"]["format"] == "pe"
    assert binary["signals"]["has_constant_evidence"] is True
    assert binary["signals"]["has_oid_evidence"] is True
    assert any("weak-confidence" in r for r in binary["escalation"]["reasons"])
    # Expensive backends attempted (subset!) and honestly reported.
    backends = {e["backend"]: e["status"] for e in binary["expensive"]}
    assert set(backends) >= {"capa", "floss"}
    assert "cheap" in binary["signals"]["stage_times"]


def test_synthetic_clean_binary_no_evidence(tmp_path):
    target = _write(tmp_path, "clean.exe", _synthetic_clean_blob())
    scanner = BinaryScanner()
    assert scanner.scan(target) == []
    report = scanner.last_report()
    assert report["summary"]["with_findings"] == 0
    assert report["binaries"][0]["escalation"]["reasons"] == [
        "no-crypto-evidence"]
    assert report["binaries"][0]["escalation"]["escalate"] is False


def test_packed_marker_escalates_with_reason(tmp_path):
    target = _write(tmp_path, "packed.exe",
                     b"MZ" + b"\x00" * 100 + b"UPX!" + b"\x00" * 100
                     + b"aes_encrypt\x00")
    scanner = BinaryScanner()
    scanner.scan(target)
    binary = scanner.last_report()["binaries"][0]
    assert binary["signals"]["packed"] == "yes"
    assert any(r.startswith("packed:") for r in binary["escalation"]["reasons"])
    assert binary["escalation"]["escalate"] is True


def test_confidence_ordering_strings_below_symbols(tmp_path):
    target = _write(tmp_path, "ord.exe", _synthetic_crypto_blob())
    findings = BinaryScanner().scan(target)
    strings_conf = [f.confidence for f in findings
                    if f.evidence and f.evidence[0].tool == "binary-strings"]
    sig_conf = [f.confidence for f in findings
                if f.evidence and f.evidence[0].tool == "binary-signatures"]
    assert strings_conf and sig_conf
    assert max(strings_conf) < min(sig_conf)


# --- escalation taxonomy (unit level, no toolchain) -----------------------


def _signals(**overrides) -> bin_stages.CheapSignals:
    base = {"path": "x", "size": 100, "fmt": "elf", "magic": "7f454c46"}
    base.update(overrides)
    return bin_stages.CheapSignals(**base)


def test_escalation_reasons_taxonomy():
    cases = [
        ({"finding_count": 3, "min_confidence": 0.9, "stripped": True,
          "distinct_canonicals": ("AES",)},
         "stripped"),
        ({"finding_count": 2, "min_confidence": 0.9, "packed": "suspected",
          "distinct_canonicals": ("AES",)},
         "packed:"),
        ({"finding_count": 2, "min_confidence": 0.35,
          "distinct_canonicals": ("AES",)},
         "weak-confidence"),
        ({"finding_count": 4, "min_confidence": 0.35,
          "distinct_canonicals": ("AES", "RSA", "DES"), "strings_only": True},
         "ambiguous-crypto-evidence"),
        ({"finding_count": 3, "min_confidence": 0.55,
          "distinct_canonicals": ("AES", "RSA"),
          "has_import_evidence": True, "strings_only": False},
         "conflicting-evidence"),
        ({"finding_count": 1, "min_confidence": 0.9,
          "distinct_canonicals": ("TLS",), "high_value_name": True},
         "high-value-target"),
    ]
    for kwargs, needle in cases:
        decision = bin_stages.decide_escalation(_signals(**kwargs))
        assert any(needle in r for r in decision.reasons), (kwargs, decision)
        assert decision.escalate is True
        assert decision.signals["should_escalate"] is True  # real wiring


def test_escalation_disabled_by_profile_keeps_reasons():
    decision = bin_stages.decide_escalation(
        _signals(finding_count=2, min_confidence=0.35,
                 distinct_canonicals=("AES",)),
        allowed=False)
    assert decision.escalate is False
    assert any("weak-confidence" in r for r in decision.reasons)
    assert "escalation-not-allowed-by-profile" in decision.reasons


def test_expensive_candidate_only_subset(tmp_path):
    crypto = _write(tmp_path, "a.exe", _synthetic_crypto_blob())
    clean = _write(tmp_path, "b.exe", _synthetic_clean_blob())
    scanner = BinaryScanner()
    scanner.scan(crypto.parent)
    by_path = {b["signals"]["path"]: b
               for b in scanner.last_report()["binaries"]}
    assert set(by_path) == {str(crypto), str(clean)}
    # Candidate: backends attempted (unavailable here, but attempted).
    attempted = {e["backend"] for e in by_path[str(crypto)]["expensive"]}
    assert {"capa", "floss"} <= attempted
    assert all(e["status"] != "skipped" for e in by_path[str(crypto)]["expensive"])
    # Non-candidate: nothing attempted, explicitly skipped.
    skipped = {e["status"] for e in by_path[str(clean)]["expensive"]}
    assert skipped and skipped <= {"skipped"}
    summary = scanner.last_report()["summary"]
    assert summary["escalated_binaries"] == 1
    assert summary["expensive_analysis_rate"] == 0.0  # nothing installed


def test_missing_tools_reduce_coverage_not_crash(tmp_path):
    _write(tmp_path, "a.exe", _synthetic_crypto_blob())
    scanner = BinaryScanner()
    findings = scanner.scan(tmp_path)
    assert findings  # cheap pass unaffected
    tools = scanner.last_report()["tools"]
    assert tools["capa"] == "unavailable"
    assert tools["floss"] == "unavailable"
    assert tools["ghidra"] == "not-configured"
    assert tools["binary-strings"] == "available"


def test_profile_gating_and_report_shape(tmp_path):
    target = _write(tmp_path, "a.exe", _synthetic_crypto_blob())
    scanner = BinaryScanner()
    scanner.scan(target, escalation_allowed=False, expensive_backends=())
    report = scanner.last_report()["binaries"][0]
    assert report["escalation"]["escalate"] is False
    assert report["expensive"] == []
    summary = scanner.last_report()["summary"]
    for key in ("binaries", "with_findings", "cheap_pass_candidates",
                "escalated_binaries", "expensive_runs",
                "expensive_analysis_rate", "stage_times"):
        assert key in summary


# --- real compiled binaries (toolchain-gated) -----------------------------


def test_compiled_dynamic_binary(compiled):
    if "dynamic" not in compiled:
        pytest.skip("gcc/libcrypto unavailable: dynamic fixture skipped")
    scanner = BinaryScanner()
    findings = scanner.scan(compiled["dynamic"])
    canonicals = {f.canonical for f in findings}
    assert "AES-256-GCM" in canonicals
    assert "SHA-256" in canonicals
    assert "OpenSSL" in canonicals
    assert "RSA" in canonicals or "Random" in canonicals
    strings_conf = [f.confidence for f in findings
                    if f.evidence and f.evidence[0].tool == "binary-strings"]
    other_conf = [f.confidence for f in findings
                  if f.evidence and f.evidence[0].tool != "binary-strings"]
    assert max(strings_conf) < max(other_conf)
    report = scanner.last_report()["binaries"][0]
    assert report["signals"]["format"] == "pe"
    assert report["escalation"]["escalate"] is True
    assert report["escalation"]["reasons"]


def test_compiled_control_is_clean(compiled):
    if "hello" not in compiled:
        pytest.skip("gcc unavailable: control fixture skipped")
    findings = BinaryScanner().scan(compiled["hello"])
    assert findings == []


def test_stripped_binary_still_cheap_scanned(compiled):
    if "stripped" not in compiled or "dynamic" not in compiled:
        pytest.skip("gcc/strip unavailable: stripped comparison skipped")
    dynamic = BinaryScanner().scan(compiled["dynamic"])
    stripped = BinaryScanner().scan(compiled["stripped"])
    assert stripped  # strings/constants survive stripping
    assert len(stripped) < len(dynamic)  # symbol surface is gone
    report = BinaryScanner()
    report.scan(compiled["stripped"])
    assert report.last_report()["binaries"][0]["signals"]["stripped"] is None


def test_static_binary_embeds_implementation(compiled):
    if "static" not in compiled or "dynamic" not in compiled:
        pytest.skip("static link unavailable: static fixture skipped")
    static = BinaryScanner().scan(compiled["static"])
    dynamic = BinaryScanner().scan(compiled["dynamic"])
    assert len(static) > len(dynamic)
    report = BinaryScanner()
    report.scan(compiled["static"])
    assert report.last_report()["binaries"][0]["signals"] \
        ["has_constant_evidence"] is True


# --- pipeline integration --------------------------------------------------


def test_binary_auto_runs_without_manual_selection(tmp_path):
    _write(tmp_path, "auto.exe", _synthetic_crypto_blob())
    (tmp_path / "note.txt").write_text("nothing\n")
    from ecdat.core.orchestrator import ScanRequest, get_orchestrator
    result = get_orchestrator().scan(
        ScanRequest(target=str(tmp_path), caller="phase6-auto"))
    stages = result.diagnostics["binary_stages"]
    assert stages["binaries"] >= 1
    assert stages["with_findings"] >= 1
    assert result.diagnostics["binary_tools"]["binary-strings"] == "available"
    assert "binary" in result.diagnostics["surfaces"]


def test_quick_profile_never_escalates_binaries(tmp_path):
    _write(tmp_path, "q.exe", _synthetic_crypto_blob())
    from ecdat.core.orchestrator import ScanRequest, get_orchestrator
    result = get_orchestrator().scan(
        ScanRequest(target=str(tmp_path), caller="phase6-quick",
                    profile="quick"))
    assert result.diagnostics["escalation"]["binaries_escalated"] == 0


def test_binary_evidence_participates_in_fusion(tmp_path):
    _write(tmp_path, "f.exe", _synthetic_crypto_blob())
    from ecdat.core.orchestrator import ScanRequest, get_orchestrator
    result = get_orchestrator().scan(
        ScanRequest(target=str(tmp_path), caller="phase6-fusion"))
    binary_assets = [
        a for a in result.cir["assets"]
        if any(str(e.get("tool", "")).startswith("binary-")
               for e in (a.get("evidence", []) or []))]
    assert binary_assets, "binary evidence must reach fused CIR assets"
