"""Phase 2 regression: full inventory + safe recursive artifact discovery.

Covers classify_bytes (content/magic over extension), inventory_target
(recursive directory walk, nested archives re-fed), safe_extract_archive
(traversal/link/ratio/count limits), and determinism.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

from ecdat.core.inventory import (
    CATEGORY_TO_SURFACE,
    classify_bytes,
    inventory_target,
    safe_extract_archive,
    summarize_inventory,
)


def _mixed_repo(root: Path) -> dict[str, Path]:
    (root / "app.py").write_text("from cryptography.hazmat.primitives import hashes\n")
    (root / "requirements.txt").write_text("cryptography>=42.0\n")
    (root / "nginx.conf").write_text("server { listen 443 ssl; }\n")
    (root / "server.pem").write_text(
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    (root / "tool").write_bytes(b"\x7fELF" + b"\x01" * 64)  # no extension
    (root / "data.txt").write_bytes(b"\x7fELF" + b"\x02" * 64)  # ext lies
    (root / "note.txt").write_bytes(
        b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    (root / "Dockerfile").write_text("FROM python:3.12-slim\n")
    (root / "notes.md").write_text("# docs\n")
    nested = io.BytesIO()
    with tarfile.open(fileobj=nested, mode="w") as bundle:
        payload = b"deep secret\n"
        info = tarfile.TarInfo("deep.txt")
        info.size = len(payload)
        bundle.addfile(info, io.BytesIO(payload))
    bundle_zip = root / "bundle.zip"
    with zipfile.ZipFile(bundle_zip, "w") as archive:
        archive.writestr("inner.py", "x = 1\n")
        archive.writestr("nested.tar", nested.getvalue())
    traversal = root / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../evil.txt", "escape\n")
        archive.writestr("ok.txt", "fine\n")
    return {"bundle": bundle_zip, "traversal": traversal}


def test_content_beats_extension():
    assert classify_bytes("data.txt", b"\x7fELF" + b"\x00" * 8)["category"] == "binary"
    cert = classify_bytes("note.txt", b"-----BEGIN CERTIFICATE-----\nxx")
    assert cert["category"] == "cert"
    assert classify_bytes("app.py", b"from x import y\n")["category"] == "source"
    assert classify_bytes("requirements.txt", b"cryptography\n")["category"] == "dependency"
    assert classify_bytes("nginx.conf", b"server {}\n")["category"] == "config"
    assert classify_bytes("Dockerfile", b"FROM x\n")["category"] == "container"
    assert classify_bytes("a.zip", b"PK\x03\x04" + b"\x00" * 8)["category"] == "archive"


def test_mixed_repo_inventory(tmp_path):
    _mixed_repo(tmp_path)
    records, summary = inventory_target(tmp_path)
    by_rel = {r.relative_path: r for r in records}
    assert by_rel["app.py"].category == "source"
    assert by_rel["app.py"].language == "Python"
    assert by_rel["requirements.txt"].category == "dependency"
    assert by_rel["nginx.conf"].category == "config"
    assert by_rel["server.pem"].category == "cert"
    assert by_rel["tool"].category == "binary"  # extensionless ELF
    assert by_rel["tool"].executable_format == "elf"
    assert by_rel["data.txt"].category == "binary"  # magic beat .txt
    assert by_rel["note.txt"].category == "cert"  # PEM marker beat .txt
    assert by_rel["Dockerfile"].category == "container"
    # Nested archives re-fed: zip -> tar -> txt (depth 2).
    assert by_rel["bundle.zip"].category == "archive"
    inner = by_rel["inner.py"]
    assert inner.archive.get("parent") == "bundle.zip"
    assert inner.archive.get("depth") == 1
    deep = by_rel["deep.txt"]
    assert deep.archive.get("depth") == 2
    assert "nested.tar" in str(deep.archive.get("parent", ""))
    # Every record hashes content deterministically.
    assert len({r.content_hash for r in records}) > 0
    assert all(len(r.content_hash) == 16 for r in records)
    # Summary rolls up honestly.
    assert summary.total == len(records)
    assert summary.by_category["source"] >= 2  # app.py + inner.py
    assert summary.by_category["archive"] >= 2
    assert "Python" in summary.languages
    assert "bundle.zip" in summary.archives
    assert set(CATEGORY_TO_SURFACE) >= {"source", "binary", "config", "cert"}


def test_traversal_members_skipped_safely(tmp_path):
    paths = _mixed_repo(tmp_path)
    records, summary = inventory_target(tmp_path)
    rels = {r.relative_path for r in records}
    assert "ok.txt" in rels
    assert not any("evil" in r for r in rels)
    assert not (tmp_path.parent / "evil.txt").exists()
    reasons = " ".join(s["reason"] for s in summary.skipped)
    assert "unsafe-path" in reasons or "traversal-blocked" in reasons
    _ = paths


def test_inventory_is_deterministic(tmp_path):
    _mixed_repo(tmp_path)
    first, _ = inventory_target(tmp_path)
    second, _ = inventory_target(tmp_path)
    assert [(r.relative_path, r.content_hash) for r in first] == [
        (r.relative_path, r.content_hash) for r in second]


def test_symlink_members_skipped(tmp_path):
    archive = tmp_path / "links.tar"
    payload = tmp_path / "real.txt"
    payload.write_text("real\n")
    with tarfile.open(archive, "w") as bundle:
        bundle.add(payload, arcname="real.txt")
        link = tarfile.TarInfo("sneaky.txt")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        bundle.addfile(link)
    records, summary = inventory_target(tmp_path)
    rels = {r.relative_path for r in records}
    assert "real.txt" in rels
    assert "sneaky.txt" not in rels
    assert any("link-skipped" in s["reason"] for s in summary.skipped)


def test_expansion_ratio_limit(tmp_path):
    big = tmp_path / "zeros.bin"
    big.write_bytes(b"\x00" * (2 * 1024 * 1024))
    archive = tmp_path / "big.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(big, arcname="zeros.bin")
    dest = tmp_path / "out"
    outcome = safe_extract_archive(archive, dest, max_ratio=10)
    assert outcome["extracted"] == []
    assert any("expansion-ratio-limit" in s for s in outcome["skipped"])


def test_unsupported_archive_format_recorded(tmp_path):
    fake = tmp_path / "disk.7z"
    fake.write_bytes(b"7z\xbc\xaf'\x1c" + b"\x00" * 32)
    records, summary = inventory_target(tmp_path)
    by_rel = {r.relative_path: r for r in records}
    assert by_rel["disk.7z"].category == "archive"
    assert any("unsupported" in s["reason"] or "7z" in s["reason"]
               for s in summary.skipped)


def test_single_file_and_missing_targets(tmp_path):
    target = tmp_path / "only.py"
    target.write_text("x = 1\n")
    records, summary = inventory_target(target)
    assert len(records) == 1
    assert records[0].category == "source"
    assert summary.total == 1
    records, summary = inventory_target(tmp_path / "nope")
    assert records == []
    assert summary.skipped[0]["reason"] == "target-missing"


def test_summarize_helper_shape(tmp_path):
    _mixed_repo(tmp_path)
    records, _ = inventory_target(tmp_path)
    summary = summarize_inventory(records)
    payload = summary.as_dict()
    assert payload["total"] == len(records)
    assert isinstance(payload["by_category"], dict)
    assert isinstance(payload["by_surface"], dict)
    assert payload["by_surface"].get("source", 0) >= 2
