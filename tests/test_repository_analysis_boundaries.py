from __future__ import annotations

from pathlib import Path

from ecdat.adapters.pipeline import run_real_scan
from ecdat.adapters.scanner_policy import PROJECT_SCANNERS
from ecdat.scanners.binary import BinaryScanner
from ecdat.scanners.path_policy import iter_project_files
from ecdat.web.server import _inspect, _profile_scanners


def _login_form_fixture(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "index.html").write_text("<form><input type='password'></form>", encoding="utf-8")
    (root / "styles.css").write_text("body { background: url(background-image.jpg); }", encoding="utf-8")
    (root / "background-image.jpg").write_bytes(b"\x00AES-CBC cbc gcm RSA ssl DES\x00")
    (root / ".git" / "objects" / "pack").mkdir(parents=True)
    (root / ".git" / "objects" / "pack" / "pack-test.pack").write_bytes(
        b"\x00AES-CBC cbc gcm RSA ssl DES\x00"
    )
    return root


def test_project_file_policy_excludes_git_and_generated_assets(tmp_path):
    root = _login_form_fixture(tmp_path / "repository")

    files = list(iter_project_files(root))
    assert {path.name for path in files} == {
        "index.html",
        "styles.css",
        "background-image.jpg",
    }
    assert _inspect(root, "transparent-login-form")["file_count"] == 3


def test_standard_profile_is_source_first():
    assert "binary" not in PROJECT_SCANNERS
    assert _profile_scanners("standard", None) == list(PROJECT_SCANNERS)


def test_login_form_repository_has_no_crypto_findings(tmp_path):
    root = _login_form_fixture(tmp_path / "repository")

    _cir, canonical = run_real_scan(root, scanners=list(PROJECT_SCANNERS))

    assert canonical["findings"] == []


def test_explicit_binary_scan_still_scans_known_binary_fixture(tmp_path):
    executable = tmp_path / "app.bin"
    executable.write_bytes(b"\x00AES-256-GCM\x00")
    image = tmp_path / "background-image.jpg"
    image.write_bytes(b"\x00AES-256-GCM cbc gcm\x00")

    findings = BinaryScanner().scan(tmp_path)

    assert findings
    assert all(Path(f.location.file).name == "app.bin" for f in findings)
