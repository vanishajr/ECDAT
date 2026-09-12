"""Person-1 Agent B: input registry + adaptive scheduler (stdlib only).

Owns target normalisation, surface triage, cheap-first routing with
principled escalation, an in-memory content-hash cache, and a
single-process ThreadPoolExecutor fan-out helper.

No real detector imports. All helpers are pure + deterministic so
downstream stages (fusion / operations) stay reproducible.
"""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TypeVar

__all__ = [
    "ScanJob",
    "ScanPlan",
    "InputRegistry",
    "AdaptiveScheduler",
    "ScanCache",
    "scan_paths_parallel",
    "infer_kind",
    "content_hash_for",
]

# Kinds produced by InputRegistry.normalize (stable contract).
JOB_KINDS: tuple[str, ...] = (
    "repo",
    "file",
    "binary",
    "container_tar",
    "rootfs",
    "endpoint",
    "cloud",
)

# Surfaces produced by AdaptiveScheduler.triage (stable contract).
SURFACES: tuple[str, ...] = (
    "source",
    "binary",
    "dependency",
    "container",
    "config",
    "cert",
    "skip",
)

_BINARY_EXTS = frozenset(
    {".exe", ".elf", ".so", ".dll", ".bin", ".o", ".a", ".dylib", ".sys"}
)
_CONTAINER_EXTS = frozenset({".tar", ".tgz"})
_SOURCE_EXTS = frozenset(
    {
        ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".c", ".h",
        ".cpp", ".cc", ".cxx", ".go", ".rs", ".rb", ".php", ".cs",
        ".swift", ".kt", ".kts", ".scala", ".sh", ".ps1",
    }
)
_CONFIG_EXTS = frozenset(
    {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
     ".env", ".xml", ".properties"}
)
_CERT_EXTS = frozenset(
    {".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".jks"}
)
_SKIP_EXTS = frozenset(
    {".md", ".rst", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg",
     ".pdf", ".map"}
)
_DEPENDENCY_BASENAMES = frozenset(
    {
        "requirements.txt", "requirements.in", "package.json",
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "gemfile",
        "gemfile.lock", "go.mod", "go.sum", "cargo.toml", "cargo.lock",
        "pom.xml", "packages.config", "pipfile", "pipfile.lock",
        "poetry.lock", "composer.json", "composer.lock",
    }
)


def _blake16(data: bytes) -> str:
    """blake2s hex digest truncated to 16 chars (cache-key width)."""
    return hashlib.blake2s(data).hexdigest()[:16]


def content_hash_for(target: str | Path) -> str:
    """Return blake2s-16 of file bytes, else of the label string.

    Pure + deterministic: existing regular files hash their bytes;
    directories, missing paths, and non-file URIs hash the
    ``str(target)`` label so every job still gets a stable cache key.
    """
    label = str(target)
    try:
        p = Path(label)
    except Exception:
        return _blake16(label.encode("utf-8"))
    try:
        if p.is_file():
            try:
                return _blake16(p.read_bytes())
            except OSError:
                return _blake16(label.encode("utf-8"))
    except OSError:
        pass
    return _blake16(label.encode("utf-8"))


def infer_kind(target: str | Path) -> str:
    """Infer a ScanJob kind from extension / path hints (deterministic).

    Order (first match wins):
      endpoint  — http(s):// or endpoint: prefix
      cloud     — aws:/arn:/cloud: prefix
      container — docker:/container: prefix, .tar/.tar.gz/.tgz suffix
      dir       — existing directory (rootfs if container-like, else repo)
      binary    — .exe/.elf/.so/.dll (+.bin/.o/.a/.dylib/.sys) or ELF/MZ magic
      file      — any other existing file / default single-path target
    """
    s = str(target).strip()
    low = s.lower()
    if low.startswith(("https://", "http://", "endpoint:")):
        return "endpoint"
    if low.startswith(("aws:", "arn:", "arn/", "aws/", "cloud:")):
        return "cloud"
    if (
        low.startswith(("docker:", "container:"))
        or "docker:" in low
        or low.endswith((".tar", ".tar.gz", ".tgz"))
    ):
        return "container_tar"
    try:
        p = Path(s)
    except Exception:
        return "file"
    try:
        if p.is_dir():
            name = p.name.lower()
            if "rootfs" in name:
                return "rootfs"
            try:
                children = {c.name.lower() for c in p.iterdir()}
            except OSError:
                return "repo"
            # Container rootfs lookalike: etc/ + (bin/ or usr/ or lib/).
            if "etc" in children and (
                "bin" in children or "usr" in children or "lib" in children
            ):
                return "rootfs"
            return "repo"
        if p.is_file():
            if p.suffix.lower() in _CONTAINER_EXTS or low.endswith(".tar.gz"):
                return "container_tar"
            if p.suffix.lower() in _BINARY_EXTS:
                return "binary"
            # Magic fallback so extensionless fixtures (e.g. app.bin
            # written without suffix, or extensionless ELF) still route.
            try:
                with p.open("rb") as fh:
                    magic = fh.read(4)
                if magic.startswith(b"\x7fELF") or magic[:2] == b"MZ":
                    return "binary"
            except OSError:
                pass
            return "file"
    except OSError:
        pass
    # Non-existent path: suffix hints still apply, else plain file.
    # (A trailing slash / well-known repo layout hint means repo.)
    suffix = Path(low).suffix
    if suffix in _BINARY_EXTS:
        return "binary"
    if suffix in _CONTAINER_EXTS or low.endswith(".tar.gz"):
        return "container_tar"
    if low.endswith(("/", "\\")):
        return "repo"
    return "file"


@dataclass(frozen=True)
class ScanJob:
    """Normalised scan input (Person-1 Agent B).

    Attributes:
        job_id: deterministic ``job-<blake2s12>`` over ``kind:label``.
        kind: one of repo/file/binary/container_tar/rootfs/endpoint/cloud.
        label: original target string (human + cache label).
        content_hash: blake2s-16 of file bytes or label.
        target: alias of label for callers expecting ``.target``.
    """

    job_id: str
    kind: str
    label: str
    content_hash: str
    target: str = ""


@dataclass(frozen=True)
class ScanPlan:
    """Cheap-first stage plan plus escalation flag."""

    stages: tuple[str, ...]
    escalate: bool = False


class InputRegistry:
    """Normalise raw targets into deterministic ScanJobs."""

    def normalize(
        self, target: str | Path | None = None  # type: ignore[override]
    ) -> ScanJob:
        """Normalise ``target`` -> :class:`ScanJob`.

        Accepts both ``InputRegistry().normalize(path)`` and
        ``InputRegistry.normalize(path)`` (unbound) call styles.
        """
        # Support unbound call style: InputRegistry.normalize("foo").
        actual: str | Path
        if isinstance(self, InputRegistry):
            if target is None:
                raise TypeError("normalize() missing required 'target'")
            actual = target
        else:  # called unbound; `self` is really the target.
            actual = self  # type: ignore[assignment]
        label = str(actual)
        kind = infer_kind(actual)
        chash = content_hash_for(actual)
        job_id = "job-" + _blake16(f"{kind}:{label}".encode("utf-8"))[:12]
        return ScanJob(
            job_id=job_id, kind=kind, label=label,
            content_hash=chash, target=label,
        )


class AdaptiveScheduler:
    """Cheap-first surface triage, routing, and escalation policy."""

    def triage(self, path: str | Path) -> str:
        """Map a path/URI to a scan surface (deterministic).

        Surfaces: source/binary/dependency/container/config/cert/skip.
        URI hints (docker:, https://, aws:/arn:) map to their surface;
        dependency basenames (requirements.txt, package-lock.json, ...)
        win over generic extensions; unknown/doc/image artefacts -> skip.
        """
        s = str(path).strip()
        low = s.lower()
        if low.startswith(("docker:", "container:")) or low.endswith(
            (".tar", ".tar.gz", ".tgz")
        ):
            return "container"
        if low.startswith(("https://", "http://", "endpoint:")):
            # Endpoint URLs carry config (TLS) surface; cert files below.
            return "config"
        if low.startswith(("aws:", "arn:", "cloud:")):
            return "config"
        name = Path(low).name
        if name in _DEPENDENCY_BASENAMES or name in {
            "dockerfile", "dockerfile.dev", "containerfile",
        }:
            return "dependency" if name in _DEPENDENCY_BASENAMES else "container"
        if name.startswith("docker-compose"):
            return "container"
        if "dockerfile" in name:
            return "container"
        suffix = Path(low).suffix
        # Compound suffix .tar.gz already handled; check plain suffix.
        if suffix in _BINARY_EXTS:
            return "binary"
        if suffix in _SOURCE_EXTS:
            return "source"
        if suffix in _CONFIG_EXTS:
            return "config"
        if suffix in _CERT_EXTS:
            return "cert"
        if suffix in _SKIP_EXTS:
            return "skip"
        # Bare well-known names without suffix.
        if name in {"dockerfile", "containerfile", "makefile", "cmakelists"}:
            return "container" if "docker" in name or "container" in name else "skip"
        # Extensionless or unknown: skip (avoid noisy deep scans).
        return "skip"

    def route(self, job: ScanJob) -> dict:
        """Return a cheap-first plan for ``job``.

        Returns ``{"job_id":..., "kind":..., "stages":[...],
        "escalate": False}``. Escalation is deferred to
        :meth:`should_escalate` once cheap-stage signals arrive.
        """
        kind = job.kind if isinstance(job, ScanJob) else str(job)
        if kind == "binary":
            stages = ("lief", "yara-x", "capa-quick")
        elif kind in ("container_tar", "rootfs"):
            stages = ("syft", "yara-x", "semgrep")
        elif kind == "endpoint":
            stages = ("sslyze", "gitleaks")
        elif kind == "cloud":
            stages = ("config-check", "gitleaks")
        else:  # repo / file default to source cheap stages.
            stages = ("semgrep", "tree-sitter", "gitleaks")
        job_id = job.job_id if isinstance(job, ScanJob) else ""
        return {
            "job_id": job_id,
            "kind": kind,
            "stages": list(stages),
            "escalate": False,
        }

    def should_escalate(self, signals: dict | None) -> bool:
        """Decide whether cheap hits must escalate to heavy stages.

        Escalate to capa-full / FLOSS / Ghidra / dataflow when the cheap
        pass reports a weak/uncertain hit: explicit ``weak_hit`` /
        ``needs_deep`` / ``packed`` / ``obfuscated`` flags, or a reported
        hit whose confidence is below 0.65.
        """
        if not signals:
            return False
        try:
            sig = dict(signals)
        except Exception:
            return False
        for key in ("weak_hit", "needs_deep", "packed", "obfuscated"):
            if sig.get(key) is True:
                return True
        has_hit = bool(sig.get("has_hit", sig.get("weak_hit", False)))
        if has_hit:
            try:
                conf = float(sig.get("confidence", 0.0))
            except (TypeError, ValueError):
                return True
            if conf < 0.65:
                return True
        # String-surface hint: binary weak matches escalate by default.
        if sig.get("surface") == "binary" and has_hit:
            return True
        return False


class ScanCache:
    """In-memory content-hash + layer cache with hit-rate accounting."""

    def __init__(self) -> None:
        self._store: dict[str, object] = {}
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _key(content_hash: str, layer: str = "default") -> str:
        return f"{content_hash}:{layer}"

    def get(self, content_hash: str, layer: str = "default") -> object | None:
        """Return cached value or None (counts miss on absent key)."""
        key = self._key(content_hash, layer)
        if key in self._store:
            self._hits += 1
            return self._store[key]
        self._misses += 1
        return None

    def set(
        self, content_hash: str, value: object, layer: str = "default"
    ) -> None:
        """Store ``value`` under content_hash + layer digest."""
        self._store[self._key(content_hash, layer)] = value

    @property
    def hit_rate(self) -> float:
        """Fraction of gets that hit (0.0 when nothing requested yet)."""
        total = self._hits + self._misses
        if total == 0:
            return 0.0
        return self._hits / total

    def __len__(self) -> int:  # convenience, not part of the contract.
        return len(self._store)


T = TypeVar("T")
R = TypeVar("R")


def scan_paths_parallel(
    paths: list[str | Path] | tuple[str | Path, ...],
    fn: Callable[[str | Path], R],
    max_workers: int = 8,
) -> list[R]:
    """Apply ``fn`` to each path via ThreadPoolExecutor (order-preserving).

    Single-process + threadpool only (no new deps). Deterministic order:
    results align 1:1 with ``paths``. Empty input -> [].
    """
    items = list(paths)
    if not items:
        return []
    workers = max(1, int(max_workers))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(fn, items))
