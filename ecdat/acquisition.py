"""Shared repository acquisition (GUI + CLI).

Single production implementation of "GitHub URL -> local scan input",
used by the web API (``_github_public``) and the CLI (``--repo``).
Stdlib only; importing this module has no side effects.

GUI flow preserved exactly:
  validate public URL -> download codeload tarball (<=250 MB) ->
  safe-extract -> flatten single top-level dir -> repository/ target.

Limits mirror the GUI: 250 MB download cap, 20,000 archive members,
zip-slip-safe extraction.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from tarfile import open as tar_open
from urllib.parse import urlparse
from urllib.request import Request, urlopen

__all__ = [
    "MAX_DOWNLOAD_BYTES",
    "MAX_ARCHIVE_MEMBERS",
    "GITHUB_URL_PATTERN",
    "is_github_url",
    "parse_github_url",
    "download_github_tarball",
    "extract_archive",
    "acquire_github_repository",
]

MAX_DOWNLOAD_BYTES = 250 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000

GITHUB_URL_PATTERN = re.compile(
    r"https://github\.com/([\w.-]+)/([\w.-]+)(?:\.git)?/?"
)


def is_github_url(value: str | None) -> bool:
    """True for public ``https://github.com/<owner>/<repo>[.git][/]`` URLs."""
    return re.fullmatch(GITHUB_URL_PATTERN, (value or "").strip()) is not None


def parse_github_url(url: str) -> tuple[str, str, str]:
    """Return ``(owner, repo, label)``; raise ValueError when invalid."""
    match = re.fullmatch(GITHUB_URL_PATTERN, (url or "").strip())
    if match is None:
        raise ValueError("enter a valid public GitHub repository URL")
    owner, repo = match.groups()
    return owner, repo, repo


def _safe_relative(value: str) -> Path:
    raw = PurePosixPath(str(value or "").replace("\\", "/"))
    if raw.is_absolute() or any(part in {"", ".", ".."} for part in raw.parts):
        raise ValueError("unsafe archive member path")
    return Path(*raw.parts)


def _safe_extract_zip(path: Path, destination: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ValueError("archive contains too many files")
        for member in members:
            if member.is_dir():
                continue
            output = destination / _safe_relative(member.filename)
            output.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as src, output.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)


def _safe_extract_tar(path: Path, destination: Path) -> None:
    with tar_open(path, "r:*") as archive:
        members = archive.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ValueError("archive contains too many files")
        for member in members:
            if not member.isfile():
                continue
            output = destination / _safe_relative(member.name)
            output.parent.mkdir(parents=True, exist_ok=True)
            src = archive.extractfile(member)
            if src is not None:
                with src, output.open("wb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)


def download_github_tarball(owner: str, repo: str, destination: Path,
                            timeout: int = 180) -> Path:
    """Download the codeload HEAD tarball; raise ValueError on failure."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = Request(
        f"https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD",
        headers={"User-Agent": "ECDAT-local"},
    )
    try:
        with urlopen(request, timeout=timeout) as response, \
                destination.open("wb") as output:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise ValueError("repository archive exceeds the 250 MB limit")
                output.write(chunk)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(
            "could not download the selected GitHub repository") from exc
    return destination


def extract_archive(archive: Path, destination: Path) -> Path:
    """Safe-extract zip/tar into ``destination``; return ``destination``."""
    lower = archive.name.lower()
    destination.mkdir(parents=True, exist_ok=True)
    if lower.endswith(".zip"):
        _safe_extract_zip(archive, destination)
    elif lower.endswith((".tar", ".tar.gz", ".tgz")):
        _safe_extract_tar(archive, destination)
    else:
        raise ValueError(f"unsupported archive type: {archive.name}")
    return destination


def acquire_github_repository(url: str, parent: Path | str | None = None,
                              timeout: int = 180) -> dict[str, Path | str]:
    """Full GUI-equivalent acquisition: validate -> download -> extract.

    Creates ``<parent>/ecdat-repo-<label>-<rand>/`` holding
    ``repository.tar.gz`` + ``repository/`` (top-level flattened).
    The directory is intentionally kept (scan records reference it);
    the caller prints its location. Raises ValueError on any failure
    (partial downloads are removed).
    """
    owner, repo, label = parse_github_url(url)
    workdir = Path(tempfile.mkdtemp(prefix=f"ecdat-repo-{label}-",
                                    dir=str(parent) if parent else None))
    archive = workdir / "repository.tar.gz"
    target = workdir / "repository"
    try:
        download_github_tarball(owner, repo, archive, timeout=timeout)
        extract_archive(archive, target)
        top_level = [child for child in target.iterdir() if child.is_dir()]
        if len(top_level) == 1:
            extracted_root = top_level[0]
            for child in extracted_root.iterdir():
                child.replace(target / child.name)
            extracted_root.rmdir()
    except Exception:
        shutil.rmtree(workdir, ignore_errors=True)
        raise
    return {"workdir": workdir, "archive": archive, "target": target,
            "label": label, "owner": owner, "repo": repo,
            "url": (url or "").strip()}


def target_for_url(value: str | None) -> Path | None:
    """Return the value as a local Path, or None when it is not one.

    Helper for callers that accept either a filesystem path or a URL:
    absolute/relative existing paths (and ``file://`` URLs) resolve to
    Paths; anything else returns None so the caller can try URL handling.
    """
    text = (value or "").strip()
    if not text:
        return None
    if text.startswith("file://"):
        return Path(urlparse(text).path)
    candidate = Path(text).expanduser()
    if str(candidate) == text or text.startswith((".", "/", "~")):
        return candidate
    return None
