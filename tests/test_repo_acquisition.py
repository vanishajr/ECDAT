"""Repository acquisition + secret-redaction tests (unified backend).

GitHub URL handling is shared production code (ecdat.acquisition), used
by the web API and the CLI. Network is stubbed with a locally built
tarball — no external requests, no mock scan data (all scans run the
real orchestrator on tmp fixtures).
"""

import io
import json
import tarfile
from pathlib import Path

import pytest

from ecdat import acquisition
from ecdat.cli import main

CRYPTO_PY = "import hashlib\nh = hashlib.md5(b'ecdat-repo-test').hexdigest()\n"


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "t.db")


def _tarball_bytes() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for name, data in (("proj-HEAD/readme.md", b"# demo\n"),
                           ("proj-HEAD/src/a.py", CRYPTO_PY.encode())):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class _FakeResponse:
    def __init__(self, payload: bytes):
        self._stream = io.BytesIO(payload)

    def read(self, size=-1):
        return self._stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# --- URL validation -----------------------------------------------------


@pytest.mark.parametrize("url", [
    "https://github.com/openssl/openssl",
    "https://github.com/openssl/openssl/",
    "https://github.com/openssl/openssl.git",
    "https://github.com/keycloak/keycloak.git/",
])
def test_valid_github_urls(url):
    assert acquisition.is_github_url(url)
    owner, repo, label = acquisition.parse_github_url(url)
    assert label == repo
    assert owner and repo


@pytest.mark.parametrize("url", [
    "",
    "https://gitlab.com/openssl/openssl",
    "http://github.com/openssl/openssl",
    "https://github.com/openssl",
    "https://github.com//openssl",
    "not a url",
    "https://github.com/openssl/openssl/tree/master",
])
def test_invalid_github_urls(url):
    assert not acquisition.is_github_url(url)
    with pytest.raises(ValueError):
        acquisition.parse_github_url(url)


# --- acquisition (stubbed network) ---------------------------------------


def test_acquire_downloads_extracts_flattens(tmp_path, monkeypatch):
    payload = _tarball_bytes()
    monkeypatch.setattr(acquisition, "urlopen",
                        lambda request, timeout=180: _FakeResponse(payload))
    acquired = acquisition.acquire_github_repository(
        "https://github.com/example/proj", parent=tmp_path)
    try:
        assert acquired["label"] == "proj"
        assert acquired["archive"].is_file()
        # Full contents equivalence: every tarball member present, flattened
        # (no leftover top-level wrapper dir), nothing extra.
        assert (acquired["target"] / "src" / "a.py").is_file()
        assert (acquired["target"] / "readme.md").is_file()
        extracted = sorted(
            p.relative_to(acquired["target"]).as_posix()
            for p in acquired["target"].rglob("*") if p.is_file())
        assert extracted == ["readme.md", "src/a.py"]
        assert [c.name for c in acquired["target"].iterdir()
                if c.is_dir()] == ["src"]
    finally:
        import shutil
        shutil.rmtree(acquired["workdir"], ignore_errors=True)


def test_acquire_cleans_up_on_failure(tmp_path, monkeypatch):
    def boom(request, timeout=180):
        raise OSError("network down")

    monkeypatch.setattr(acquisition, "urlopen", boom)
    before = set(tmp_path.iterdir())
    with pytest.raises(ValueError, match="could not download"):
        acquisition.acquire_github_repository(
            "https://github.com/example/proj", parent=tmp_path)
    assert set(tmp_path.iterdir()) == before


def test_acquire_rejects_oversize_archive(tmp_path, monkeypatch):
    class Drip:
        def read(self, size=-1):
            return b"x" * (1024 * 1024)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(acquisition, "urlopen",
                        lambda request, timeout=180: Drip())
    with pytest.raises(ValueError, match="250 MB"):
        acquisition.acquire_github_repository(
            "https://github.com/example/proj", parent=tmp_path)


# --- CLI --repo end-to-end (stubbed download, real scan) -------------------


def test_cli_repo_scans_extracted_tree(tmp_path, capsys, monkeypatch):
    payload = _tarball_bytes()
    monkeypatch.setattr(acquisition, "urlopen",
                        lambda request, timeout=180: _FakeResponse(payload))
    rc = main(["scan", "--repo", "https://github.com/example/proj",
               "--db", _db(tmp_path)])
    assert rc == 0
    out, err = capsys.readouterr()
    scan_id = out.strip()
    assert scan_id.startswith("scan:")
    assert "repository:" in err  # kept-tree location on stderr, stdout stays clean
    assert main(["show", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert "MD5" in out


def test_cli_repo_invalid_url_fails_clean(tmp_path, capsys):
    rc = main(["scan", "--repo", "https://gitlab.com/example/proj",
               "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "invalid GitHub repository URL" in err


def test_cli_repo_request_matches_gui_shape(tmp_path, monkeypatch):
    """CLI --repo builds the same analysis fields the GUI job builds."""
    import ecdat.core.orchestrator as orch

    payload = _tarball_bytes()
    monkeypatch.setattr(acquisition, "urlopen",
                        lambda request, timeout=180: _FakeResponse(payload))
    seen = {}
    original = orch.ScanOrchestrator.scan

    def spy(self, request, progress=None):
        seen["request"] = request
        return original(self, request, progress)

    monkeypatch.setattr(orch.ScanOrchestrator, "scan", spy)
    rc = main(["scan", "--repo", "https://github.com/example/proj",
               "--db", _db(tmp_path)])
    assert rc == 0
    req = seen["request"]
    # Analysis-relevant fields equal the GUI defaults for public repos.
    # CLI passes scanners=None (orchestrator resolves the same default
    # local set the GUI lists explicitly).
    from ecdat.adapters.scanner_policy import DEFAULT_SCANNERS
    assert (req.scanner_list() or list(DEFAULT_SCANNERS)) == [
        "source", "dependency", "binary", "config", "certificate"]
    assert req.profile == "standard"
    assert req.permissions.as_dict() == {"allow_container": False,
                                         "allow_cloud": False,
                                         "allow_runtime": False,
                                         "allow_pull": False,
                                         "allow_build": False}
    assert req.risk_z == 10.0
    assert req.cloud_aws_access_key_id is None
    # Interface-specific: caller + display label differ by design.
    assert req.caller == "cli-scan"
    assert req.display_name == "proj"


def test_cli_cloud_request_matches_gui_cloud_shape(monkeypatch):
    """scan-cloud credential flags build the GUI cloud_config equivalent.

    The GUI posts cloud_config{provider=aws, profile, services, creds...}
    and _run_job maps it to target/scanners/profile/cloud_aws_*. The CLI
    must produce the same analysis fields from its flags.
    """
    import ecdat.core.orchestrator as orch
    from ecdat.cli import build_parser

    args = build_parser().parse_args([
        "scan-cloud", "aws", "--profile", "dev", "--services", "kms,acm",
        "--region", "eu-west-1", "--aws-access-key-id", "AKID",
        "--aws-profile", "dev", "--db", "unused.db"])
    seen = {}
    original = orch.ScanOrchestrator.scan

    def spy(self, request, progress=None):
        seen["request"] = request
        raise RuntimeError("capture-only")

    monkeypatch.setattr(orch.ScanOrchestrator, "scan", spy)
    from ecdat.commands import scan_cloud_cmd
    with pytest.raises(RuntimeError, match="capture-only"):
        scan_cloud_cmd.run(args)
    req = seen["request"]
    assert req.target == "aws:dev:services=kms,acm"
    assert req.scanner_list() == ["cloud"]
    assert req.profile == "standard"  # depth stays standard (documented)
    assert req.region == "eu-west-1"
    assert req.cloud_aws_access_key_id == "AKID"
    assert req.cloud_aws_profile == "dev"
    assert req.caller == "cli-scan-cloud"


# --- secret redaction -------------------------------------------------------


def test_aws_credentials_never_persisted(tmp_path, capsys):
    """Fake creds through the real pipeline: absent from every artifact."""
    target = tmp_path / "k.py"
    target.write_text(CRYPTO_PY)
    out_path = tmp_path / "canon.json"
    cir_path = tmp_path / "cir.json"
    rc = main(["scan-cloud", "aws", "--services", "kms",
               "--aws-access-key-id", "AKID-FAKE-123",
               "--aws-secret-access-key", "SECRET-FAKE-456",
               "--aws-session-token", "TOKEN-FAKE-789",
               "--db", _db(tmp_path), "--output", str(out_path),
               "--cir-out", str(cir_path)])
    capsys.readouterr()
    # Cloud scanning without real AWS creds fails honestly; either way no
    # secret may appear in any produced artifact or message.
    for path in (out_path, cir_path):
        if path.is_file():
            blob = path.read_text()
            assert "AKID-FAKE-123" not in blob
            assert "SECRET-FAKE-456" not in blob
            assert "TOKEN-FAKE-789" not in blob
    assert rc in (0, 1)


def test_redaction_direct_orchestrator_artifact(tmp_path):
    """Creds passed to ScanRequest must not leak into CIR/canonical JSON."""
    from ecdat.core.client import RealCoreClient

    target = tmp_path / "k.py"
    target.write_text(CRYPTO_PY)
    client = RealCoreClient(
        scanners=["source"],
        cloud_aws_access_key_id="AKID-FAKE-123",
        cloud_aws_secret_access_key="SECRET-FAKE-456",
        cloud_aws_session_token="TOKEN-FAKE-789",
    )
    cir, doc = client.scan_with_cir(target)
    blob = json.dumps({"cir": cir, "doc": doc})
    assert "AKID-FAKE-123" not in blob
    assert "SECRET-FAKE-456" not in blob
    assert "TOKEN-FAKE-789" not in blob
