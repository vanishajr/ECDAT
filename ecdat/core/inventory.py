"""Full inventory + safe recursive artifact discovery (Phase 2).

Architecture role (SIH26164 ECDAT Solution Architecture, section 6, stage 0):
walk files, compute content hashes (the cache key for incremental and
repeated scans), classify every artifact by content/magic first and
extension second, safely expand nested archives, and re-feed extracted
artifacts back into inventory/triage.

Safety (roadmap Phase 2, tasks 6-7): path-traversal protection, maximum
nesting depth, maximum expanded byte count, maximum file count,
decompression-ratio limit, symlink/hardlink safety. Anything violating a
limit is SKIPPED with an explicit reason - never silently treated as
"nothing found" and never extracted unsafely.

Stdlib only (zipfile, tarfile, hashlib, mimetypes). No new dependencies.
Deterministic: sorted traversal, sorted output.
"""

from __future__ import annotations

import hashlib
import mimetypes
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "ArtifactRecord",
    "InventorySummary",
    "MAX_ARCHIVE_DEPTH",
    "MAX_ARCHIVE_FILES",
    "MAX_EXPANDED_BYTES",
    "MAX_EXPANSION_RATIO",
    "classify_bytes",
    "inventory_target",
    "summarize_inventory",
    "safe_extract_archive",
    "CATEGORY_TO_SURFACE",
    "ARCHIVE_FORMATS",
]

#: Safety limits for recursive archive expansion.
MAX_ARCHIVE_DEPTH = 5
MAX_ARCHIVE_FILES = 20_000
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_EXPANSION_RATIO = 200
_HASH_CHUNK = 1024 * 1024

#: Archive formats the stdlib can expand safely.
ARCHIVE_FORMATS = ("zip", "tar", "tar.gz", "tgz")

#: Inventory category -> AdaptiveScheduler surface (stable contract).
#: Archives route by their own name (tar-family -> container, like triage);
#: anything without a scanner maps to "skip" with a recorded reason.
CATEGORY_TO_SURFACE = {
    "source": "source",
    "dependency": "dependency",
    "binary": "binary",
    "container": "container",
    "config": "config",
    "cert": "cert",
    "archive": "skip",
    "unknown": "skip",
}

_SOURCE_SUFFIXES = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".jsx": "JavaScript", ".tsx": "TypeScript", ".java": "Java",
    ".go": "Go", ".rs": "Rust", ".c": "C", ".h": "C",
    ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".hpp": "C++",
    ".cs": "C#", ".rb": "Ruby", ".php": "PHP", ".swift": "Swift",
    ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala",
    ".sh": "Shell", ".ps1": "PowerShell", ".pl": "Perl", ".pm": "Perl",
}
_CONFIG_SUFFIXES = frozenset(
    {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
     ".cnf", ".env", ".xml", ".properties"}
)
_CERT_SUFFIXES = frozenset(
    {".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".jks",
     ".pub", ".asc"}
)
_BINARY_SUFFIXES = frozenset(
    {".exe", ".elf", ".so", ".dll", ".bin", ".o", ".a", ".dylib",
     ".sys", ".class", ".jar", ".apk"}
)
_MANIFEST_BASENAMES = frozenset(
    {
        "requirements.txt", "requirements.in", "package.json",
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "gemfile",
        "gemfile.lock", "go.mod", "go.sum", "cargo.toml", "cargo.lock",
        "pom.xml", "packages.config", "pipfile", "pipfile.lock",
        "poetry.lock", "composer.json", "composer.lock", "conanfile.txt",
        "conanfile.py", "vcpkg.json", "meson.build", "makefile",
        "cmakelists.txt", "configure.ac",
    }
)
_SKIP_SUFFIXES = frozenset(
    {".md", ".rst", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg",
     ".pdf", ".map", ".css", ".ico", ".woff", ".woff2", ".ttf"}
)
_PEM_MARKER = b"-----BEGIN "


def _blake16_file(path: Path) -> str:
    """blake2s-16 hex of file bytes (chunked; same width as scheduler)."""
    digest = hashlib.blake2s()
    with path.open("rb") as handle:
        while chunk := handle.read(_HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()[:16]


def classify_bytes(name: str, head: bytes) -> dict[str, Any]:
    """Classify one artifact by content/magic first, name second.

    Returns ``{"category", "language", "executable_format", "archive_format",
    "mime", "reason"}``. Extension is a hint, never the truth: magic wins
    wherever the stdlib can read it honestly.
    """
    lower = str(name or "").lower()
    suffix = Path(lower).suffix
    base = Path(lower).name
    info: dict[str, Any] = {
        "category": "unknown",
        "language": None,
        "executable_format": None,
        "archive_format": None,
        "mime": mimetypes.guess_type(lower)[0],
        "reason": "",
    }
    magic = bytes(head or b"")

    # -- magic wins ------------------------------------------------------
    if magic.startswith(b"\x7fELF"):
        info.update(category="binary", executable_format="elf")
        return info
    if magic.startswith(b"MZ"):
        info.update(category="binary", executable_format="pe")
        return info
    if magic[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                     b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        info.update(category="binary", executable_format="mach-o")
        return info
    if magic.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        info.update(category="archive", archive_format="zip")
        return info
    if magic.startswith(b"\x1f\x8b"):
        fmt = "tar.gz" if lower.endswith((".tar.gz", ".tgz")) else "gzip"
        info.update(category="archive", archive_format=fmt)
        return info
    if len(magic) >= 262 and magic[257:262] == b"ustar":
        fmt = "tar.gz" if lower.endswith((".tar.gz", ".tgz")) else "tar"
        info.update(category="archive", archive_format=fmt)
        return info
    if magic.startswith(b"7z\xbc\xaf'\x1c"):
        info.update(category="archive", archive_format="7z",
                    reason="unsupported-format: 7z needs an external tool")
        return info
    if _PEM_MARKER in magic[:4096]:
        info.update(category="cert", reason="pem-marker")
        return info
    if magic.startswith(b"\xfe\xed\xfe\xed"):
        info.update(category="cert", reason="jks-magic")
        return info

    # -- names win next ---------------------------------------------------
    if base in _MANIFEST_BASENAMES or base == "dockerfile" or "dockerfile" in base:
        if "dockerfile" in base or base in {"dockerfile", "containerfile"}:
            info.update(category="container")
        elif base.startswith("docker-compose"):
            info.update(category="container")
        else:
            info.update(category="dependency")
        return info
    if base in {"cmakelists.txt", "makefile", "meson.build", "configure.ac"} \
            or suffix in {".mk", ".cmake"}:
        info.update(category="dependency", reason="build-metadata")
        return info
    if base in {"bom.json", "cyclonedx.json", "bom.xml", "cyclonedx.xml"} \
            or lower.endswith((".cdx.json", ".cdx.xml", ".spdx.json", ".spdx")):
        info.update(category="dependency", reason="bom-manifest")
        return info
    if suffix == ".pc":
        info.update(category="dependency", reason="pkgconfig")
        return info
    if suffix in _BINARY_SUFFIXES:
        info.update(category="binary", reason="extension-hint")
        return info
    if suffix in _SOURCE_SUFFIXES:
        info.update(category="source", language=_SOURCE_SUFFIXES[suffix])
        return info
    if suffix in _CONFIG_SUFFIXES:
        info.update(category="config")
        return info
    if suffix in _CERT_SUFFIXES:
        info.update(category="cert", reason="extension-hint")
        return info
    if lower.endswith((".tar.gz", ".tgz")) or suffix in {".tar", ".zip", ".gz"}:
        info.update(category="archive", archive_format="tar.gz"
                    if lower.endswith((".tar.gz", ".tgz")) else suffix.lstrip("."))
        return info
    if suffix in _SKIP_SUFFIXES:
        info.update(category="unknown", reason="non-crypto-asset")
        return info
    info["reason"] = "unrecognized"
    return info


@dataclass(frozen=True)
class ArtifactRecord:
    """One inventoried artifact (Phase 2 target-kind record)."""

    relative_path: str
    abs_path: str
    size: int
    content_hash: str
    extension: str
    mime: str | None
    magic: str
    executable_format: str | None
    language: str | None
    category: str
    archive: dict[str, Any] = field(default_factory=dict)
    container: dict[str, Any] = field(default_factory=dict)
    candidate_routes: tuple[str, ...] = ()
    cache_state: str = "miss"
    skipped_reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "abs_path": self.abs_path,
            "size": self.size,
            "content_hash": self.content_hash,
            "extension": self.extension,
            "mime": self.mime,
            "magic": self.magic,
            "executable_format": self.executable_format,
            "language": self.language,
            "category": self.category,
            "archive": dict(self.archive),
            "container": dict(self.container),
            "candidate_routes": list(self.candidate_routes),
            "cache_state": self.cache_state,
            "skipped_reason": self.skipped_reason,
        }


@dataclass
class InventorySummary:
    """Deterministic roll-up over one inventory run."""

    total: int = 0
    total_bytes: int = 0
    by_category: dict[str, int] = field(default_factory=dict)
    by_surface: dict[str, int] = field(default_factory=dict)
    languages: list[str] = field(default_factory=list)
    archives: list[str] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    truncated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "total_bytes": self.total_bytes,
            "by_category": dict(self.by_category),
            "by_surface": dict(self.by_surface),
            "languages": list(self.languages),
            "archives": list(self.archives),
            "skipped": [dict(s) for s in self.skipped],
            "truncated": self.truncated,
        }


def _record_for(path: Path, root: Path, archive_ctx: dict[str, Any] | None) -> ArtifactRecord | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    try:
        with path.open("rb") as handle:
            head = handle.read(4096)
    except OSError:
        return None
    classified = classify_bytes(path.name, head)
    try:
        content_hash = _blake16_file(path)
    except OSError:
        return None
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = path.name
    category = str(classified["category"])
    surface = CATEGORY_TO_SURFACE.get(category, "skip")
    routes = (surface,) if surface != "skip" else ()
    archive_info = dict(archive_ctx or {})
    if category == "archive":
        archive_info.setdefault("format", classified.get("archive_format"))
    return ArtifactRecord(
        relative_path=rel,
        abs_path=str(path),
        size=size,
        content_hash=content_hash,
        extension=path.suffix.lower(),
        mime=classified.get("mime"),
        magic=head[:8].hex() if head else "",
        executable_format=classified.get("executable_format"),
        language=classified.get("language"),
        category=category,
        archive=archive_info,
        candidate_routes=routes,
    )


def _is_safe_member(name: str) -> bool:
    cleaned = str(name or "").replace("\\", "/")
    if not cleaned or cleaned.startswith(("/", "\\")):
        return False
    parts = [p for p in cleaned.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return False
    if len(cleaned) > 1024:
        return False
    return True


def safe_extract_archive(
    archive: Path,
    destination: Path,
    *,
    max_files: int = MAX_ARCHIVE_FILES,
    max_bytes: int = MAX_EXPANDED_BYTES,
    max_ratio: int = MAX_EXPANSION_RATIO,
) -> dict[str, Any]:
    """Expand one archive with all Phase 2 safety limits enforced.

    Returns ``{"extracted": [...relative paths...], "skipped": [...reasons...],
    "format": ...}``. Raises :class:`ValueError` only for unreadable or
    unsupported archives; limit violations skip members (or the whole
    archive) with recorded reasons instead of extracting unsafely.
    """
    destination.mkdir(parents=True, exist_ok=True)
    lower = archive.name.lower()
    try:
        archive_bytes = archive.stat().st_size
    except OSError as exc:
        raise ValueError(f"cannot stat archive {archive}: {exc}")
    if lower.endswith(".zip"):
        return _extract_zip(archive, destination, archive_bytes,
                            max_files, max_bytes, max_ratio)
    if lower.endswith((".tar", ".tar.gz", ".tgz", ".gz")):
        return _extract_tar(archive, destination, archive_bytes,
                            max_files, max_bytes, max_ratio)
    raise ValueError(f"unsupported archive format: {archive.name}")


def _extract_zip(archive: Path, destination: Path, archive_bytes: int,
                 max_files: int, max_bytes: int, max_ratio: int) -> dict[str, Any]:
    extracted: list[str] = []
    skipped: list[str] = []
    expanded = 0
    try:
        with zipfile.ZipFile(archive) as bundle:
            members = [m for m in bundle.infolist() if not m.is_dir()]
            if len(members) > max_files:
                return {"extracted": [], "skipped": [
                    f"file-count-limit: {len(members)} members > {max_files}"],
                    "format": "zip"}
            for member in sorted(members, key=lambda m: m.filename):
                if not _is_safe_member(member.filename):
                    skipped.append(f"unsafe-path: {member.filename[:120]}")
                    continue
                if member.file_size > max_bytes or expanded + member.file_size > max_bytes:
                    skipped.append(f"size-limit: {member.filename[:120]}")
                    continue
                output = destination / Path(*member.filename.replace("\\", "/").split("/"))
                try:
                    output.resolve().relative_to(destination.resolve())
                except ValueError:
                    skipped.append(f"traversal-blocked: {member.filename[:120]}")
                    continue
                output.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as src, output.open("wb") as dst:
                    remaining = member.file_size
                    while remaining > 0:
                        chunk = src.read(min(_HASH_CHUNK, remaining))
                        if not chunk:
                            break
                        dst.write(chunk)
                        remaining -= len(chunk)
                        expanded += len(chunk)
                extracted.append(member.filename)
    except zipfile.BadZipFile as exc:
        raise ValueError(f"unreadable zip archive {archive.name}: {exc}")
    if archive_bytes > 0 and expanded > archive_bytes * max_ratio and expanded > 1024 * 1024:
        return {"extracted": [], "skipped": [
            f"expansion-ratio-limit: {expanded} bytes from {archive_bytes}"],
            "format": "zip"}
    return {"extracted": extracted, "skipped": skipped, "format": "zip"}


def _extract_tar(archive: Path, destination: Path, archive_bytes: int,
                 max_files: int, max_bytes: int, max_ratio: int) -> dict[str, Any]:
    extracted: list[str] = []
    skipped: list[str] = []
    expanded = 0
    dest_resolved = destination.resolve()
    try:
        with tarfile.open(archive, "r:*") as bundle:
            all_members = bundle.getmembers()
            for link in sorted(all_members, key=lambda m: m.name):
                # Symlink/hardlink safety: link targets are never
                # followed; only regular files are extracted.
                if link.issym() or link.islnk():
                    skipped.append(f"link-skipped: {link.name[:120]}")
            members = [m for m in all_members if m.isfile()]
            if len(members) > max_files:
                return {"extracted": [], "skipped": skipped + [
                    f"file-count-limit: {len(members)} members > {max_files}"],
                    "format": "tar"}
            for member in sorted(members, key=lambda m: m.name):
                if not member.isreg():
                    skipped.append(f"link-skipped: {member.name[:120]}")
                    continue
                if not _is_safe_member(member.name):
                    skipped.append(f"unsafe-path: {member.name[:120]}")
                    continue
                if member.size > max_bytes or expanded + member.size > max_bytes:
                    skipped.append(f"size-limit: {member.name[:120]}")
                    continue
                output = dest_resolved / Path(*member.name.replace("\\", "/").split("/"))
                try:
                    output.resolve().relative_to(dest_resolved)
                except ValueError:
                    skipped.append(f"traversal-blocked: {member.name[:120]}")
                    continue
                output.parent.mkdir(parents=True, exist_ok=True)
                src = bundle.extractfile(member)
                if src is None:
                    skipped.append(f"unreadable-member: {member.name[:120]}")
                    continue
                with src, output.open("wb") as dst:
                    remaining = member.size
                    while remaining > 0:
                        chunk = src.read(min(_HASH_CHUNK, remaining))
                        if not chunk:
                            break
                        dst.write(chunk)
                        remaining -= len(chunk)
                        expanded += len(chunk)
                extracted.append(member.name)
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"unreadable tar archive {archive.name}: {exc}")
    if archive_bytes > 0 and expanded > archive_bytes * max_ratio and expanded > 1024 * 1024:
        return {"extracted": [], "skipped": [
            f"expansion-ratio-limit: {expanded} bytes from {archive_bytes}"],
            "format": "tar"}
    return {"extracted": extracted, "skipped": skipped, "format": "tar"}


def inventory_target(
    target: str | Path,
    *,
    max_depth: int = MAX_ARCHIVE_DEPTH,
    max_files: int = MAX_ARCHIVE_FILES,
    max_bytes: int = MAX_EXPANDED_BYTES,
    extract_root: Path | None = None,
) -> tuple[list[ArtifactRecord], InventorySummary]:
    """Inventory a filesystem target with safe recursive archive discovery.

    Returns ``(records, summary)`` sorted deterministically by relative
    path. Archives found *inside* repositories are expanded (within
    ``max_depth``) and their contents re-fed into inventory. Every skip
    carries a reason in ``summary.skipped``.
    """
    from ecdat.scanners.path_policy import iter_project_files

    root = Path(str(target))
    summary = InventorySummary()
    records: list[ArtifactRecord] = []
    if not root.exists():
        summary.skipped.append({"path": str(target), "reason": "target-missing"})
        return records, summary

    own_tmp: tempfile.TemporaryDirectory[str] | None = None
    if extract_root is None:
        own_tmp = tempfile.TemporaryDirectory(prefix="ecdat-inventory-")
        extract_root = Path(own_tmp.name)
    try:
        if root.is_file():
            files = [root]
            anchor = root.parent
        else:
            anchor = root
            files = sorted(iter_project_files(root))
        pending: list[tuple[Path, Path, dict[str, Any] | None, int]] = [
            (p, anchor, None, 0) for p in files
        ]
        seen_hashes: set[str] = set()
        archive_seq = 0
        while pending:
            path, anchor_path, ctx, depth = pending.pop(0)
            if len(records) + len(summary.skipped) >= max_files:
                summary.truncated = True
                summary.skipped.append(
                    {"path": str(path), "reason": "inventory-file-count-limit"})
                continue
            record = _record_for(path, anchor_path, ctx)
            if record is None:
                summary.skipped.append(
                    {"path": str(path), "reason": "unreadable"})
                continue
            # De-duplicate identical content seen twice (e.g. vendored
            # copies): keep the first record, note the duplicate.
            if record.content_hash in seen_hashes and record.category != "archive":
                summary.skipped.append(
                    {"path": record.relative_path, "reason": "duplicate-content"})
                continue
            seen_hashes.add(record.content_hash)
            records.append(record)
            summary.total_bytes += record.size
            if record.category == "archive":
                if record.archive.get("format") not in (
                        "zip", "tar", "tar.gz", "gzip"):
                    summary.skipped.append({
                        "path": record.relative_path,
                        "reason": "unsupported-archive-format: "
                                  f"{record.archive.get('format')}"})
                    continue
                if depth >= max_depth:
                    summary.skipped.append({
                        "path": record.relative_path,
                        "reason": f"max-depth: {depth} >= {max_depth}"})
                    continue
                archive_seq += 1
                dest = extract_root / f"a{archive_seq:04d}"
                try:
                    outcome = safe_extract_archive(path, dest)
                except ValueError as exc:
                    summary.skipped.append(
                        {"path": record.relative_path, "reason": str(exc)[:160]})
                    continue
                for reason in outcome["skipped"]:
                    summary.skipped.append(
                        {"path": record.relative_path, "reason": reason[:160]})
                child_ctx = {
                    "parent": record.relative_path,
                    "format": outcome.get("format"),
                    "depth": depth + 1,
                }
                for rel in sorted(outcome["extracted"]):
                    child = dest / Path(*rel.replace("\\", "/").split("/"))
                    if child.is_file():
                        pending.append((child, dest, child_ctx, depth + 1))
    finally:
        if own_tmp is not None:
            try:
                own_tmp.cleanup()
            except Exception:
                pass

    records.sort(key=lambda r: (r.relative_path, r.content_hash))
    summary.total = len(records)
    return records, _summarize(records, summary)


def _summarize(records: list[ArtifactRecord], summary: InventorySummary) -> InventorySummary:
    for record in records:
        summary.by_category[record.category] = summary.by_category.get(record.category, 0) + 1
        surface = CATEGORY_TO_SURFACE.get(record.category, "skip")
        if surface != "skip":
            summary.by_surface[surface] = summary.by_surface.get(surface, 0) + 1
        if record.language and record.language not in summary.languages:
            summary.languages.append(record.language)
        if record.category == "archive":
            summary.archives.append(record.relative_path)
    summary.languages.sort()
    summary.archives.sort()
    return summary


def summarize_inventory(records: list[ArtifactRecord]) -> InventorySummary:
    """Roll up pre-collected records (no filesystem access)."""
    return _summarize(records, InventorySummary(total=len(records)))
