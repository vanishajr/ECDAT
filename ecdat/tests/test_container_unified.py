"""Phase 7 regression: unified container engine.

Synthetic docker-save tarballs, OCI layouts, rootfs dirs, and unsafe
archives prove daemon-free local analysis, per-layer caching keyed by
individual digests, safe extraction, permission gating, and inner
evidence tagged for graph linkage. No daemon, registry, or network.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from ecdat.scanners.container import ContainerScanner


def _scanner(tmp_path: Path) -> ContainerScanner:
    """Isolated layer-cache DB: content digests persist, tests must not."""
    return ContainerScanner(cache_db=tmp_path / "cache.db")


def _layer(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as bundle:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            bundle.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf.read()


def _docker_save(path: Path, ref: str, layers: list[bytes]) -> Path:
    names = []
    target = path / "image.tar"
    with tarfile.open(target, "w") as bundle:
        for i, blob in enumerate(layers):
            name = f"layer{i}.tar"
            names.append(name)
            info = tarfile.TarInfo(name)
            info.size = len(blob)
            bundle.addfile(info, io.BytesIO(blob))
        manifest = json.dumps(
            [{"RepoTags": [ref], "Layers": names}]).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        bundle.addfile(info, io.BytesIO(manifest))
    return target


def _layers_v1() -> list[bytes]:
    return [
        _layer({"etc/app.conf": b"server { listen 443 ssl; "
                                 b"ssl_certificate /srv.crt; "
                                 b"ssl_protocols TLSv1.2 TLSv1.3; }\n",
                "srv.crt": b"-----BEGIN CERTIFICATE-----\nMIIB\n"
                           b"-----END CERTIFICATE-----\n"}),
        _layer({"app/requirements.txt": b"cryptography>=42.0\n"}),
    ]


def test_docker_save_inner_routing_and_tags(tmp_path):
    archive = _docker_save(tmp_path, "demo/app:1", _layers_v1())
    scanner = _scanner(tmp_path)
    findings = scanner.scan(archive, allow_pull=True)
    assert findings
    tools = {f.evidence[0].tool for f in findings}
    assert any(t.startswith("config-") for t in tools)
    assert any(t.startswith("certificate") for t in tools)
    assert any(t.startswith("dependency") for t in tools)
    uris = [f.location.uri or "" for f in findings]
    assert all(u.startswith("image:demo/app:1/layer:") for u in uris)
    assert len({u.split("/layer:")[1].split("/")[0] for u in uris}) == 2
    notes = " ".join((f.context.notes or "") if f.context else ""
                     for f in findings)
    assert "image=demo/app:1" in notes and "service=" in notes
    report = scanner.last_report()
    assert report["kind"] == "docker-save"
    assert report["summary"]["layers"] == 2
    assert report["summary"]["cache_hits"] == 0


def test_layer_cache_repeat_and_per_layer_keys(tmp_path):
    archive = _docker_save(tmp_path, "demo/app:1", _layers_v1())
    db = tmp_path / "c.db"
    first = ContainerScanner(cache_db=db)
    first_run = first.scan(archive, allow_pull=True)
    assert first.last_report()["summary"]["cache_hits"] == 0
    second = ContainerScanner(cache_db=db)
    second_run = second.scan(archive, allow_pull=True)
    assert second.last_report()["summary"]["cache_hits"] == 2
    assert {(f.canonical, f.location.uri) for f in first_run} == \
        {(f.canonical, f.location.uri) for f in second_run}
    # Change ONLY layer 1: layer 0 must stay cached (proves per-layer
    # keys; a first-layer-only key would miss or serve stale data).
    changed = _layers_v1()
    changed[1] = _layer({"app/requirements.txt": b"libsodium==1.0\n"})
    archive2 = _docker_save(tmp_path, "demo/app:2", changed)
    third = ContainerScanner(cache_db=db)
    third.scan(archive2, allow_pull=True)
    layers = {layer["digest"]: layer
              for layer in third.last_report()["layers"]}
    assert sum(1 for layer in layers.values() if layer["cached"]) == 1
    assert sum(1 for layer in layers.values() if not layer["cached"]) == 1
    assert any("libsodium" in (f.library or "")
               for layer in layers.values() for f in layer["findings"])


def test_normalized_cache_survives_instances(tmp_path):
    archive = _docker_save(tmp_path, "demo/app:1", _layers_v1())
    db = tmp_path / "cache.db"
    ContainerScanner(cache_db=db).scan(archive, allow_pull=True)
    fresh = ContainerScanner(cache_db=db)
    fresh.scan(archive, allow_pull=True)
    assert fresh.last_report()["summary"]["cache_hits"] == 2
    findings = fresh.scan(archive, allow_pull=True)
    assert findings and all(f.canonical for f in findings)


def test_rootfs_and_targz_and_oci_layout(tmp_path):
    rootfs = tmp_path / "rootfs"
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "etc" / "app.conf").write_text("server { listen 443 ssl; }\n")
    (rootfs / "app.py").write_text(
        "from cryptography.hazmat.primitives import hashes\n")
    scanner = _scanner(tmp_path)
    rootfs_findings = scanner.scan(rootfs)
    assert rootfs_findings
    assert scanner.last_report()["kind"] == "rootfs"

    gz = tmp_path / "rootfs.tar.gz"
    import tarfile as _tf
    with _tf.open(gz, "w:gz") as bundle:
        bundle.add(rootfs, arcname=".")
    gz_findings = _scanner(tmp_path).scan(gz)
    assert gz_findings

    layout = tmp_path / "oci"
    (layout / "blobs" / "sha256").mkdir(parents=True)
    (layout / "oci-layout").write_text(json.dumps({"imageLayoutVersion": "1.0.0"}))
    layer_blob = _layer({"app/requirements.txt": b"openssl==23.0\n"})
    import hashlib
    digest = "sha256:" + hashlib.sha256(layer_blob).hexdigest()
    (layout / "blobs" / "sha256" / digest.split(":")[1]).write_bytes(layer_blob)
    manifest = {"schemaVersion": 2, "layers": [
        {"digest": digest, "size": len(layer_blob)}]}
    manifest_blob = json.dumps(manifest).encode()
    manifest_digest = "sha256:" + hashlib.sha256(manifest_blob).hexdigest()
    (layout / "blobs" / "sha256" / manifest_digest.split(":")[1]).write_bytes(
        manifest_blob)
    (layout / "index.json").write_text(json.dumps(
        {"manifests": [{"digest": manifest_digest, "size": len(manifest_blob)}]}))
    oci_findings = _scanner(tmp_path).scan(layout)
    assert oci_findings
    assert any("layer:" in (f.location.uri or "") for f in oci_findings)


def test_unsafe_archive_members_never_escape(tmp_path):
    evil = tmp_path / "evil.tar"
    with tarfile.open(evil, "w") as bundle:
        info = tarfile.TarInfo("../escape.txt")
        payload = b"escape\n"
        info.size = len(payload)
        bundle.addfile(info, io.BytesIO(payload))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        bundle.addfile(link)
    scanner = _scanner(tmp_path)
    findings = scanner.scan(evil)
    assert not (tmp_path.parent / "escape.txt").exists()
    assert isinstance(findings, list)


def test_dockerfile_deferred_and_ref_gated(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM nginx:1.25\n")
    scanner = _scanner(tmp_path)
    assert scanner.scan(tmp_path / "Dockerfile") == []
    assert scanner.last_report()["kind"] == "dockerfile-deferred-to-config"

    refused = scanner.scan("demo/app:1")
    assert refused == []
    assert scanner.last_report().get("refused") == "pull-permission-required"

    from ecdat.adapters.pipeline import RealScanError
    from ecdat.core.orchestrator import ScanRequest, get_orchestrator
    try:
        get_orchestrator().scan(ScanRequest(
            target="demo/app:1", scanners=["container"], caller="phase7-ref"))
    except RealScanError as exc:
        assert "--allow-pull" in str(exc)
    else:
        raise AssertionError("image ref without pull permission must fail loudly")


def test_ref_with_permission_fails_loud_without_backend(tmp_path):
    from ecdat.adapters.pipeline import RealScanError
    from ecdat.core.orchestrator import (
        ScanPermissions, ScanRequest, get_orchestrator)
    try:
        get_orchestrator().scan(ScanRequest(
            target="demo/app:1", scanners=["container"], caller="phase7-be",
            permissions=ScanPermissions(allow_pull=True)))
    except RealScanError as exc:
        assert "Traceback" not in str(exc)
    else:
        raise AssertionError("ref without backend must fail loudly, not empty")


def test_tool_honesty_and_existing_pins(tmp_path):
    scanner = _scanner(tmp_path)
    assert scanner.is_available() is True  # local engine always available
    scanner.scan(tmp_path)
    tools = scanner.last_report()["tools"]
    assert tools["local-engine"] == "available"
    assert tools["docker"] == "unavailable"
    assert tools["syft"] == "unavailable"
    assert scanner.scan("docker://nonexistent:image") == []
    assert scanner.scan("not-a-valid-target") == []
    (tmp_path / "test.txt").write_text("hello")
    assert isinstance(scanner.scan(tmp_path), list)
