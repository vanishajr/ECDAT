"""GUI scan-input registry + lightweight staging (Person 3 platform layer).

Stdlib only. No scanning here — this module only describes the input
types the dashboard accepts and stages browser-uploaded bytes into a
server-side directory that the real P1/P2 pipeline can scan.

Light/fast rules (enforced, not advised):
- Huge folders are NEVER copied: the ``local_path`` / ``binary_path`` /
  ``rootfs`` modes scan the given server-local path in place (zero-copy).
  Uploads are for single files and zips only.
- Zips are extracted once, streaming from disk, with zip-slip protection
  and hard caps (file count, per-file bytes, total bytes). Anything over
  a cap aborts loudly instead of filling the disk.
- Upload bodies are capped. Staging lives under one root
  (default: ``<tempdir>/ecdat-gui-uploads``) in per-batch directories so
  concurrent browser tabs never collide and cleanup is one directory
  removal.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import tempfile
import time
import zipfile
from pathlib import Path

# -- caps (lightweight by construction) ---------------------------------------

#: Single uploaded file cap (25 MiB). Certificates, single binaries and
#: config files are far below this; anything bigger should use a path.
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

#: Zip archive cap (200 MiB compressed on disk).
MAX_ZIP_BYTES = 200 * 1024 * 1024

#: Extracted zip caps: at most 2000 files, 500 MiB total, 100 MiB per file.
MAX_ZIP_FILES = 2000
MAX_ZIP_TOTAL_BYTES = 500 * 1024 * 1024
MAX_ZIP_FILE_BYTES = 100 * 1024 * 1024

#: Batch upload cap: at most 50 files staged into one batch directory.
MAX_BATCH_FILES = 50

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

#: Extensions treated as zip archives (case-insensitive).
ZIP_SUFFIXES = (".zip",)

#: Certificate-ish extensions routed to the certificate scanner family.
CERT_SUFFIXES = (
    ".pem", ".der", ".crt", ".cer", ".key", ".p12", ".pfx",
    ".jks", ".jwk", ".json", ".pub", ".ssh",
)


def staging_root(explicit: str | Path | None = None) -> Path:
    """Root directory for staged uploads. Created on demand."""
    root = Path(explicit).expanduser() if explicit else (
        Path(tempfile.gettempdir()) / "ecdat-gui-uploads")
    root.mkdir(parents=True, exist_ok=True)
    return root


def safe_filename(name: str, fallback: str = "upload.bin") -> str:
    """Strip directories and unsafe characters from an uploaded name."""
    base = Path(str(name or "")).name.strip() or fallback
    cleaned = _SAFE_NAME_RE.sub("_", base).strip("._") or fallback
    return cleaned[:128]


def describe_inputs() -> list[dict]:
    """Input-type registry served at GET /api/inputs (UI renders from this)."""
    return [
        {
            "id": "local_path",
            "label": "Source folder / file path",
            "hint": "Server-local path. Zero-copy — fastest for huge repos.",
            "scanners": ["source", "dependency", "binary", "config",
                         "certificate"],
            "needs_path": True,
            "needs_upload": False,
            "fields": [{"name": "path", "label": "Folder or file path",
                        "placeholder": "e.g. D:\\proj\\repo or ./src"}],
        },
        {
            "id": "upload",
            "label": "Upload files / ZIP",
            "hint": "Browser files staged server-side. ZIPs auto-extract. "
                    "Use paths (above) for huge folders.",
            "scanners": ["source", "dependency", "binary", "config",
                         "certificate"],
            "needs_path": False,
            "needs_upload": True,
            "fields": [{"name": "files", "label": "Files or .zip",
                        "placeholder": "drag & drop or browse"}],
        },
        {
            "id": "binary",
            "label": "Binary",
            "hint": "Single binary: local path (fast) or upload "
                    "(<= 25 MiB).",
            "scanners": ["binary"],
            "needs_path": True,
            "needs_upload": True,
            "fields": [{"name": "path", "label": "Binary path or staged file",
                        "placeholder": "e.g. ./bin/app.exe"}],
        },
        {
            "id": "container",
            "label": "Container",
            "hint": "Image ref (nginx:1.25), local .tar path / upload, "
                    "or rootfs directory. Needs docker/syft when set.",
            "scanners": ["container", "binary", "config"],
            "needs_path": True,
            "needs_upload": True,
            "fields": [
                {"name": "image_or_path",
                 "label": "Image ref, .tar path, or rootfs dir",
                 "placeholder": "e.g. nginx:1.25 or ./image.tar"},
            ],
        },
        {
            "id": "certificate",
            "label": "Certificate / key",
            "hint": "PEM/DER/CER/CRT/P12/JKS/JWK/SSH: local path or "
                    "upload. Private material stays local; snippets are "
                    "redacted.",
            "scanners": ["certificate", "config"],
            "needs_path": True,
            "needs_upload": True,
            "fields": [{"name": "path", "label": "Certificate path or staged file",
                        "placeholder": "e.g. ./certs/site.pem"}],
        },
        {
            "id": "cloud",
            "label": "Cloud (AWS)",
            "hint": "Logical label — no files. Uses ambient credentials; "
                    "read-only inventory.",
            "scanners": ["cloud"],
            "needs_path": False,
            "needs_upload": False,
            "fields": [
                {"name": "profile", "label": "Profile",
                 "placeholder": "default"},
                {"name": "services", "label": "Services (comma-separated)",
                 "placeholder": "kms,acm,elb"},
                {"name": "region", "label": "Region (optional)",
                 "placeholder": "us-east-1"},
            ],
        },
        {
            "id": "runtime",
            "label": "Runtime endpoint",
            "hint": "TLS/SSH probe target host:port. Opens real sockets — "
                    "opt-in.",
            "scanners": ["runtime"],
            "needs_path": False,
            "needs_upload": False,
            "fields": [{"name": "endpoint", "label": "host:port",
                        "placeholder": "e.g. example.com:443"}],
        },
    ]


_VALID_IDS = {d["id"] for d in describe_inputs()}


def new_batch_dir(root: str | Path | None = None) -> Path:
    """Create a fresh per-upload batch directory under the staging root."""
    base = staging_root(root)
    stamp = f"{int(time.time() * 1000) % 100000000:08d}"
    for attempt in range(100):
        name = f"batch-{stamp}-{attempt:02d}" if attempt else f"batch-{stamp}"
        path = base / name
        try:
            path.mkdir(parents=False, exist_ok=False)
            return path
        except FileExistsError:
            continue
    raise ValueError("could not allocate a staging directory")


def stage_bytes(
    filename: str,
    data: bytes,
    root: str | Path | None = None,
    batch: str | Path | None = None,
    kind: str = "upload",
) -> dict:
    """Write one uploaded file into staging. Returns its staged record."""
    if data is None:
        raise ValueError("no file content received")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError(
            f"file {filename!r} is {len(data)} bytes; "
            f"upload cap is {MAX_UPLOAD_BYTES} bytes "
            "(use a server-local path instead)")
    directory = Path(batch) if batch else new_batch_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    staged = directory / safe_filename(filename)
    # Never overwrite within a batch: suffix duplicates.
    if staged.exists():
        stem, suffix = staged.stem, staged.suffix
        for i in range(2, 1000):
            candidate = directory / safe_filename(f"{stem}-{i}{suffix}")
            if not candidate.exists():
                staged = candidate
                break
        else:
            raise ValueError(f"too many files named {filename!r} in one batch")
    staged.write_bytes(data)
    return {
        "filename": str(filename),
        "staged_path": str(staged),
        "batch": str(directory),
        "size": len(data),
        "kind": str(kind),
        "is_zip": staged.suffix.lower() in ZIP_SUFFIXES,
    }


def stage_b64(
    filename: str,
    content_b64: str,
    root: str | Path | None = None,
    batch: str | Path | None = None,
    kind: str = "upload",
) -> dict:
    """Decode one base64 upload and stage it. Raises ValueError when loud."""
    if not content_b64:
        raise ValueError(f"file {filename!r} arrived empty")
    # Strip data-URL prefixes browsers sometimes add.
    if "," in content_b64 and content_b64.strip().startswith("data:"):
        content_b64 = content_b64.split(",", 1)[1]
    try:
        data = base64.b64decode(content_b64, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"file {filename!r} is not valid base64")
    return stage_bytes(filename, data, root=root, batch=batch, kind=kind)


def extract_zip(zip_path: str | Path, dest: str | Path | None = None) -> dict:
    """Extract a staged zip once, with slip protection and hard caps."""
    archive = Path(zip_path)
    if archive.suffix.lower() not in ZIP_SUFFIXES:
        raise ValueError(f"not a .zip archive: {archive.name}")
    if archive.stat().st_size > MAX_ZIP_BYTES:
        raise ValueError(
            f"zip {archive.name} exceeds the {MAX_ZIP_BYTES}-byte cap")
    out = Path(dest) if dest else archive.parent / f"{archive.stem}-extracted"
    out.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    total = 0
    with zipfile.ZipFile(archive) as zf:
        members = [m for m in zf.infolist() if not m.is_dir()]
        if len(members) > MAX_ZIP_FILES:
            raise ValueError(
                f"zip holds {len(members)} files; cap is {MAX_ZIP_FILES}")
        for member in members:
            if member.file_size > MAX_ZIP_FILE_BYTES:
                raise ValueError(
                    f"zip member {member.filename!r} exceeds the per-file cap")
            total += member.file_size
            if total > MAX_ZIP_TOTAL_BYTES:
                raise ValueError("zip contents exceed the total-size cap")
            target = (out / member.filename).resolve()
            if target != out.resolve() and out.resolve() not in target.parents:
                raise ValueError(
                    f"zip member escapes the archive: {member.filename!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, open(target, "wb") as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    dst.write(chunk)
            extracted.append(str(target.relative_to(out)))
    return {
        "archive": str(archive),
        "extracted_dir": str(out),
        "file_count": len(extracted),
        "total_bytes": total,
        "files": sorted(extracted)[:100],
        "truncated_listing": len(extracted) > 100,
    }


def _cloud_label(profile: str, services: str) -> str:
    parts = [s.strip() for s in str(services or "").split(",")]
    parts = [s for s in parts if s]
    if not parts:
        raise ValueError("--services must list at least one service")
    return f"aws:{(profile or 'default').strip() or 'default'}:services={','.join(parts)}"


def resolve_typed_input(input_type: str, payload: dict | None) -> dict:
    """Map a GUI input-type + payload to a real-pipeline scan request.

    Returns ``{"target": ..., "scanners": [...], "allow_*": ..., "region":
    ...}``. Raises ValueError for bad input (HTTP 400 at the edge).
    Filesystem targets must exist; cloud/runtime targets are logical.
    """
    itype = str(input_type or "").strip().lower()
    if itype not in _VALID_IDS:
        raise ValueError(
            f"unknown input type {input_type!r} "
            f"(known: {', '.join(sorted(_VALID_IDS))})")
    data = dict(payload or {})

    def _path_field(*names: str) -> str:
        for name in names:
            value = str(data.get(name, "") or "").strip()
            if value:
                return value
        raise ValueError(f"input type {itype!r} needs a path value")

    if itype == "local_path":
        target = _path_field("path", "target")
        if not Path(target).exists():
            raise ValueError(f"scan target does not exist: {target}")
        return {"target": target, "scanners": None,
                "allow_container": False, "allow_cloud": False,
                "allow_runtime": False, "region": None}
    if itype == "upload":
        target = _path_field("path", "target", "staged_path", "batch")
        if not Path(target).exists():
            raise ValueError(f"staged target does not exist: {target}")
        return {"target": target, "scanners": None,
                "allow_container": False, "allow_cloud": False,
                "allow_runtime": False, "region": None}
    if itype == "binary":
        target = _path_field("path", "target", "staged_path")
        if not Path(target).exists():
            raise ValueError(f"binary does not exist: {target}")
        return {"target": target, "scanners": ["binary"],
                "allow_container": False, "allow_cloud": False,
                "allow_runtime": False, "region": None}
    if itype == "container":
        target = _path_field("image_or_path", "path", "target",
                             "staged_path")
        # Image refs and cloud-style labels are logical; local .tar /
        # rootfs paths must exist.
        text = target.strip()
        is_logical = (
            text.startswith(("docker://", "oci://"))
            or (":" in text or "/" in text or "@" in text)
            and not Path(text).exists()
        )
        if not is_logical and not Path(text).exists():
            raise ValueError(f"container target does not exist: {target}")
        return {"target": target, "scanners": ["container", "binary",
                                               "config"],
                "allow_container": True, "allow_cloud": False,
                "allow_runtime": False, "region": None}
    if itype == "certificate":
        target = _path_field("path", "target", "staged_path")
        if not Path(target).exists():
            raise ValueError(f"certificate does not exist: {target}")
        return {"target": target, "scanners": ["certificate", "config"],
                "allow_container": False, "allow_cloud": False,
                "allow_runtime": False, "region": None}
    if itype == "cloud":
        label = _cloud_label(str(data.get("profile", "default")),
                             str(data.get("services", "kms,acm,elb")))
        region = str(data.get("region", "") or "").strip() or None
        return {"target": label, "scanners": ["cloud"],
                "allow_container": False, "allow_cloud": True,
                "allow_runtime": False, "region": region}
    if itype == "runtime":
        endpoint = _path_field("endpoint", "target", "path")
        host, _, port = endpoint.rpartition(":")
        if not host.strip() or not port.strip().isdigit():
            raise ValueError(
                f"runtime endpoint must be host:port, got {endpoint!r}")
        return {"target": endpoint, "scanners": ["runtime"],
                "allow_container": False, "allow_cloud": False,
                "allow_runtime": True, "region": None}
    raise ValueError(f"unhandled input type {itype!r}")


def cleanup_old_batches(root: str | Path | None = None,
                        max_age_seconds: int = 7 * 24 * 3600) -> int:
    """Remove staging batches older than the cutoff. Returns removals."""
    import shutil

    base = staging_root(root)
    now = time.time()
    removed = 0
    for child in base.iterdir():
        try:
            if child.is_dir() and (now - child.stat().st_mtime) > max_age_seconds:
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    # Prune stray files at the root too (never touch subdirs otherwise).
    for child in base.iterdir():
        try:
            if child.is_file() and (now - child.stat().st_mtime) > max_age_seconds:
                child.unlink(missing_ok=True)
                removed += 1
        except OSError:
            continue
    return removed
