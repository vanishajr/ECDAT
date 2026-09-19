"""Unified production container engine (Phase 7).

ONE engine for every container input (task 1 — no parallel production
implementations):

- Docker/OCI image reference ... daemon/syft backends, pull-gated
- Docker/OCI tarball .......... stdlib, daemon-free (manifest or OCI
  layout detected inside; plain tar treated as rootfs tarball)
- OCI layout directory ........ stdlib index.json walk
- rootfs directory ............ stdlib inner scan
- Dockerfile .................. owned by the config family (Phase 5);
  skipped here to avoid double counting

Inner contents always use the SAME family scanners as local repos
(dependency, binary, config, certificate, source), tagged with
``image:<ref>/layer:<digest>/<rel>`` URIs and
``image=/layer=/service=`` notes appended (never overwritten).

Layer cache: keyed by EACH layer's sha256 digest (never first-layer
only), persisted as NORMALIZED evidence (explicit model_dump round
trip, never fragile ``__dict__``). Cache failures degrade to rescan.

``DockerScanner`` (docker_scanner.py) remains the daemon backend used
for image inspect/trivy where a daemon exists; it is not a second
production engine.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from ecdat.scanners.base import (
    Scanner, ScannerFinding, ScannerRegistry, create_evidence_signal,
    normalize_finding,
)
from ecdat.core.cir_models import (
    Location, Implementation, Context, UsageState, Exposure,
)

__all__ = ["ContainerScanner", "container_backend_status"]


def container_backend_status() -> dict[str, str]:
    """Daemon/tool backends for image references (no pull, never raises).

    The local engine (tarballs, rootfs, OCI layouts) needs none of
    these; only registry pulls and daemon inspection do.
    """
    import functools as _functools

    @_functools.lru_cache(maxsize=1)
    def _probe() -> dict[str, str]:
        def _run(binary: list[str]) -> bool:
            try:
                proc = subprocess.run(binary, capture_output=True, timeout=15)
                return proc.returncode == 0
            except Exception:
                return False

        return {
            "docker": "available" if _run(["docker", "version"]) else "unavailable",
            "syft": "available" if _run(["syft", "version"]) else "unavailable",
            "trivy": "available" if _run(["trivy", "--version"]) else "unavailable",
        }

    return dict(_probe())

_MAX_LAYER_BYTES = 512 * 1024 * 1024


def _finding_to_json(finding: ScannerFinding) -> dict[str, Any]:
    """Normalized evidence dict (no ``__dict__`` fragility)."""
    def _model(value: Any) -> Any:
        if value is None:
            return None
        dump = getattr(value, "model_dump", None)
        if callable(dump):
            try:
                return dump(mode="json")
            except Exception:
                pass
        return {"_repr": str(value)}

    def _enum(value: Any) -> Any:
        return getattr(value, "value", value)

    return {
        "canonical": finding.canonical,
        "original": finding.original,
        "key_size": finding.key_size,
        "mode": finding.mode,
        "curve": finding.curve,
        "protocol": finding.protocol,
        "library": finding.library,
        "usage_state": _enum(finding.usage_state),
        "confidence": finding.confidence,
        "evidence": [_model(e) for e in (finding.evidence or [])],
        "location": _model(finding.location),
        "implementation": _model(finding.implementation),
        "context": _model(finding.context),
        "operation_type": _enum(finding.operation_type),
        "function": finding.function,
        "dependency_only": bool(finding.dependency_only),
    }


def _finding_from_json(data: dict[str, Any]) -> ScannerFinding | None:
    """Rebuild a finding from normalized evidence (never raises)."""
    try:
        from ecdat.core.cir_models import (
            EvidenceSignal, OperationType)
        evidence = []
        for item in (data.get("evidence") or []):
            if isinstance(item, dict) and "tool" in item:
                try:
                    evidence.append(EvidenceSignal(**{
                        k: v for k, v in item.items()
                        if k in ("tool", "detail", "confidence", "snippet")}))
                except Exception:
                    continue
        location = None
        if isinstance(data.get("location"), dict):
            try:
                location = Location(**data["location"])
            except Exception:
                location = None
        implementation = None
        if isinstance(data.get("implementation"), dict):
            try:
                implementation = Implementation(**data["implementation"])
            except Exception:
                implementation = None
        context = None
        if isinstance(data.get("context"), dict):
            try:
                context = Context(**data["context"])
            except Exception:
                context = None
        usage = data.get("usage_state", "Possible")
        try:
            usage_state = UsageState(usage)
        except Exception:
            usage_state = UsageState.POSSIBLE
        operation_type = None
        if data.get("operation_type"):
            try:
                operation_type = OperationType(data["operation_type"])
            except Exception:
                operation_type = None
        return ScannerFinding(
            canonical=str(data.get("canonical", "UNKNOWN")),
            original=str(data.get("original", "")),
            key_size=data.get("key_size"),
            mode=data.get("mode"),
            curve=data.get("curve"),
            protocol=data.get("protocol"),
            library=data.get("library"),
            usage_state=usage_state,
            confidence=float(data.get("confidence", 0.5)),
            evidence=evidence,
            location=location,
            implementation=implementation,
            context=context,
            operation_type=operation_type,
            function=data.get("function"),
            dependency_only=bool(data.get("dependency_only", False)),
        )
    except Exception:
        return None


class ContainerScanner(Scanner[ScannerFinding]):
    name = "container"
    version = "0.2.0"

    def __init__(self, cache_db: Optional[Path] = None):
        self._has_docker = self._check_docker()
        self._has_syft = self._check_syft()
        self._has_trivy = self._check_trivy()
        self._layer_cache: dict[str, list[ScannerFinding]] = {}
        self._cache_db_path = cache_db or (
            Path(tempfile.gettempdir()) / "ecdat_container_cache.db")
        self._report: dict[str, Any] = {}
        self._init_cache_db()

    def _init_cache_db(self):
        """Initialize SQLite cache database for layer findings."""
        try:
            with sqlite3.connect(self._cache_db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS layer_cache (
                        layer_digest TEXT PRIMARY KEY,
                        findings_json TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        accessed_at REAL NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_layer_cache_accessed
                    ON layer_cache(accessed_at)
                """)
                conn.commit()
        except Exception:
            pass

    def _get_cached_layer(self, layer_digest: str) -> Optional[list[ScannerFinding]]:
        """Normalized per-layer lookup (individual digest, never first-only)."""
        if layer_digest in self._layer_cache:
            return list(self._layer_cache[layer_digest])
        try:
            with sqlite3.connect(self._cache_db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    "SELECT findings_json FROM layer_cache WHERE layer_digest = ?",
                    (layer_digest,))
                row = cursor.fetchone()
                if row:
                    raw = json.loads(row["findings_json"])
                    findings = [f for f in
                                (_finding_from_json(d) for d in raw) if f]
                    conn.execute(
                        "UPDATE layer_cache SET accessed_at = ? WHERE layer_digest = ?",
                        (time.time(), layer_digest))
                    conn.commit()
                    self._layer_cache[layer_digest] = findings
                    return list(findings)
        except Exception:
            pass
        return None

    def _cache_layer(self, layer_digest: str, findings: list[ScannerFinding]):
        """Persist NORMALIZED evidence per layer digest (best effort)."""
        self._layer_cache[layer_digest] = list(findings)
        try:
            payload = json.dumps([_finding_to_json(f) for f in findings])
            now = time.time()
            with sqlite3.connect(self._cache_db_path) as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO layer_cache
                       (layer_digest, findings_json, created_at, accessed_at)
                       VALUES (?, ?, ?, ?)""",
                    (layer_digest, payload, now, now))
                conn.commit()
        except Exception:
            pass

    @staticmethod
    def _probe(binary: list[str]) -> bool:
        try:
            proc = subprocess.run(binary, capture_output=True, timeout=15)
            return proc.returncode == 0
        except Exception:
            return False

    def _check_docker(self) -> bool:
        # CLI probe only (no daemon traffic): `docker version` fails fast
        # when the daemon is down.
        return self._probe(["docker", "version"])

    def _check_syft(self) -> bool:
        return self._probe(["syft", "version"])

    def _check_trivy(self) -> bool:
        return self._probe(["trivy", "--version"])

    def is_available(self) -> bool:
        # Phase 7: the local engine (tar/rootfs/OCI via stdlib + inner
        # scanners) is always available. Daemon tools gate only image
        # pulls and image-ref analysis, reported per-run in last_report().
        return True

    def get_tool_version(self) -> str:
        parts = ["container-stdlib"]
        if self._has_docker:
            parts.append("docker")
        if self._has_syft:
            parts.append("syft")
        if self._has_trivy:
            parts.append("trivy")
        return f"container-v{self.version}({','.join(parts)})"

    def last_report(self) -> dict[str, Any]:
        """Structured record of the most recent scan (Phase 7)."""
        return dict(self._report)

    # -- routing -------------------------------------------------------

    @staticmethod
    def _looks_like_image_reference(target_str: str) -> bool:
        text = str(target_str or "").strip()
        if not text or Path(text).exists():
            return False
        if text.startswith(("docker://", "oci://")):
            return True
        return (":" in text) or ("/" in text) or ("@" in text)

    @staticmethod
    def _is_dockerfile_target(path: Path) -> bool:
        name = path.name.lower()
        return name == "dockerfile" or name == "containerfile" or \
            name.startswith("dockerfile.") or name.endswith(".dockerfile")

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_str = str(target)
        self._report = {"target": target_str, "kind": "unknown",
                        "layers": [], "summary": {}, "tools": self._tool_map()}
        if not target_str:
            return []

        allow_pull = bool(kwargs.get("allow_pull", False))
        text = target_str.strip()
        if text.startswith(("docker://", "oci://")):
            ref = text.split("://", 1)[1]
            return self._scan_ref(ref, allow_pull=allow_pull, **kwargs)
        path = Path(target_str)
        if path.is_file():
            lower = path.name.lower()
            if self._is_dockerfile_target(path):
                # Owned by the config family (Phase 5): no double count.
                self._report["kind"] = "dockerfile-deferred-to-config"
                return []
            if lower.endswith((".tar", ".tar.gz", ".tgz")):
                return self._scan_archive(path, **kwargs)
            self._report["kind"] = "unsupported-file"
            return []
        if path.is_dir():
            if (path / "oci-layout").is_file():
                return self._scan_oci_layout(path, **kwargs)
            return self._scan_rootfs(path, image_ref="", **kwargs)
        if self._looks_like_image_reference(text):
            return self._scan_ref(text, allow_pull=allow_pull, **kwargs)
        self._report["kind"] = "unrecognized"
        return []

    def _tool_map(self) -> dict[str, str]:
        return {
            "docker": "available" if self._has_docker else "unavailable",
            "syft": "available" if self._has_syft else "unavailable",
            "trivy": "available" if self._has_trivy else "unavailable",
            "local-engine": "available",
        }

    def _finish(self, kind: str, layers: list,
                extra: dict | None = None) -> list:
        inner = sum(len(layer.get("findings", [])) for layer in layers)
        hits = sum(1 for layer in layers if layer.get("cached"))
        self._report.update({
            "kind": kind, "layers": layers,
            "summary": {
                "layers": len(layers),
                "cache_hits": hits,
                "inner_findings": inner,
                "skipped": [layer for layer in layers
                            if layer.get("skipped")],
            },
            "tools": self._tool_map(),
        })
        if extra:
            self._report.update(extra)
        out: list[ScannerFinding] = []
        for layer in layers:
            out.extend(layer.get("findings", []))
        return [normalize_finding(f) for f in out]

    # -- image references (pull-gated, backend-gated) -------------------

    def _scan_ref(self, ref: str, allow_pull: bool = False,
                  **kwargs) -> list:
        if not allow_pull:
            # No silent empty scan: the orchestrator turns this into a
            # loud permission error; direct callers get the refusal as
            # an empty result plus an explicit report entry.
            self._report.update({
                "kind": "image-ref",
                "refused": "pull-permission-required",
                "summary": {"layers": 0, "cache_hits": 0,
                            "inner_findings": 0, "skipped": []},
            })
            return []
        if self._has_syft:
            return self._finish(
                "image-ref", [{
                    "digest": f"ref:{ref}", "cached": False,
                    "findings": self._scan_with_syft(ref)}],
                extra={"backend": "syft"})
        if self._has_docker:
            return self._finish(
                "image-ref", [{
                    "digest": f"ref:{ref}", "cached": False,
                    "findings": self._scan_with_daemon(ref)}],
                extra={"backend": "docker"})
        self._report.update({
            "kind": "image-ref",
            "refused": "no-backend",
            "summary": {"layers": 0, "cache_hits": 0,
                        "inner_findings": 0, "skipped": []},
        })
        return []

    # -- archives / layouts / rootfs (daemon-free) ----------------------

    def _scan_archive(self, archive: Path, **kwargs) -> list:
        from ecdat.core.inventory import safe_extract_archive
        service = kwargs.get("service") or archive.stem
        image_ref = f"tar:{archive.name}"
        layers: list[dict] = []
        with tempfile.TemporaryDirectory(prefix="ecdat-img-") as tmp:
            tmp_path = Path(tmp)
            names = self._tar_names(archive)
            if any(n == "manifest.json" for n in names):
                return self._scan_docker_save(
                    archive, image_ref, service, **kwargs)
            if any(n == "oci-layout" for n in names):
                dest = tmp_path / "oci"
                try:
                    outcome = safe_extract_archive(archive, dest)
                except ValueError as exc:
                    return self._finish("archive", [], extra={"error": str(exc)})
                return self._scan_oci_layout(dest, image_ref=image_ref,
                                             service=service, **kwargs)
            # Plain (rootfs) tarball: one pseudo-layer keyed by content.
            digest = _sha256_file(archive)
            cached = self._get_cached_layer(f"tar:{digest}")
            if cached is not None:
                layers.append({"digest": digest, "cached": True,
                               "findings": self._retarget(
                                   cached, image_ref, digest, service)})
                return self._finish("rootfs-tar", layers)
            dest = tmp_path / "rootfs"
            try:
                outcome = safe_extract_archive(archive, dest)
            except ValueError as exc:
                return self._finish("archive", [], extra={"error": str(exc)})
            for reason in outcome.get("skipped", []):
                layers.append({"digest": "", "cached": False,
                               "findings": [], "skipped": reason})
            findings = self._scan_rootfs_inner(
                dest, image_ref, digest, service, **kwargs)
            self._cache_layer(f"tar:{digest}", findings)
            layers.append({"digest": digest, "cached": False,
                           "findings": findings})
            return self._finish("rootfs-tar", layers)

    @staticmethod
    def _tar_names(archive: Path) -> list[str]:
        try:
            with tarfile.open(archive, "r:*") as bundle:
                return bundle.getnames()[:200]
        except Exception:
            return []

    def _scan_docker_save(self, archive: Path, image_ref: str,
                          service: str, **kwargs) -> list:
        layers: list[dict] = []
        with tempfile.TemporaryDirectory(prefix="ecdat-imgsave-") as tmp:
            tmp_path = Path(tmp)
            try:
                with tarfile.open(archive, "r:*") as bundle:
                    members = [m for m in bundle.getmembers()
                               if m.isfile() and m.name == "manifest.json"]
                    if not members:
                        return self._finish("archive", [], extra={
                            "error": "docker-save without manifest.json"})
                    raw = bundle.extractfile(members[0])
                    manifest = json.loads(raw.read().decode("utf-8")) \
                        if raw else []
            except Exception as exc:
                return self._finish("archive", [],
                                    extra={"error": f"unreadable: {exc}"})
            for entry in manifest:
                repo_tags = entry.get("RepoTags", []) or [image_ref]
                ref = str(repo_tags[0])
                for layer_name in entry.get("Layers", []) or []:
                    layers.append(self._scan_save_layer(
                        archive, layer_name, ref, service, **kwargs))
            return self._finish("docker-save", layers,
                                extra={"image": image_ref})

    def _scan_save_layer(self, archive: Path, layer_name: str,
                         image_ref: str, service: str, **kwargs) -> dict:
        digest = f"save:{layer_name}"
        cached = self._get_cached_layer(digest)
        if cached is not None:
            return {"digest": digest, "cached": True,
                    "findings": self._retarget(cached, image_ref, digest,
                                               service)}
        with tempfile.TemporaryDirectory(prefix="ecdat-layer-") as tmp:
            try:
                with tarfile.open(archive, "r:*") as bundle:
                    member = bundle.getmember(layer_name)
                    if member is None or not member.isfile():
                        return {"digest": digest, "cached": False,
                                "findings": [],
                                "skipped": f"missing-layer: {layer_name}"}
                    blob = bundle.extractfile(member)
                    data = blob.read() if blob else b""
            except Exception as exc:
                return {"digest": digest, "cached": False, "findings": [],
                        "skipped": f"unreadable-layer: {exc}"}
            digest = "sha256:" + hashlib.sha256(data).hexdigest()
            cached = self._get_cached_layer(digest)
            if cached is not None:
                return {"digest": digest, "cached": True,
                        "findings": self._retarget(cached, image_ref, digest,
                                                   service)}
            findings = self._scan_layer_bytes(
                data, layer_name, image_ref, digest, service, **kwargs)
            self._cache_layer(digest, findings)
            return {"digest": digest, "cached": False, "findings": findings}

    def _scan_oci_layout(self, root: Path, image_ref: str = "",
                         service: str = "", **kwargs) -> list:
        image_ref = image_ref or f"oci:{root.name}"
        service = service or root.name
        layers: list[dict] = []
        try:
            index = json.loads((root / "index.json").read_text(
                encoding="utf-8"))
        except Exception as exc:
            return self._finish("oci-layout", [],
                                extra={"error": f"bad index.json: {exc}"})
        manifests = [m for m in index.get("manifests", [])
                     if isinstance(m, dict)]
        if not manifests:
            return self._finish("oci-layout", [],
                                extra={"error": "no manifests in index.json"})
        for manifest in manifests:
            digest = str(manifest.get("digest", ""))
            blob = root / "blobs" / "sha256" / digest.split(":", 1)[-1] \
                if digest else None
            if blob is None or not blob.is_file():
                layers.append({"digest": digest, "cached": False,
                               "findings": [],
                               "skipped": f"missing-manifest: {digest}"})
                continue
            try:
                doc = json.loads(blob.read_text(encoding="utf-8"))
            except Exception as exc:
                layers.append({"digest": digest, "cached": False,
                               "findings": [],
                               "skipped": f"bad-manifest: {exc}"})
                continue
            for layer in doc.get("layers", []) or []:
                layers.append(self._scan_oci_blob(
                    root, layer, image_ref, service, **kwargs))
        return self._finish("oci-layout", layers, extra={"image": image_ref})

    def _scan_oci_blob(self, root: Path, layer: dict, image_ref: str,
                       service: str, **kwargs) -> dict:
        digest = str(layer.get("digest", "")) or "unknown"
        cached = self._get_cached_layer(digest)
        if cached is not None:
            return {"digest": digest, "cached": True,
                    "findings": self._retarget(cached, image_ref, digest,
                                               service)}
        blob = root / "blobs" / "sha256" / digest.split(":", 1)[-1]
        try:
            data = blob.read_bytes()
        except Exception as exc:
            return {"digest": digest, "cached": False, "findings": [],
                    "skipped": f"missing-blob: {exc}"}
        if len(data) > _MAX_LAYER_BYTES:
            return {"digest": digest, "cached": False, "findings": [],
                    "skipped": f"layer-too-large: {len(data)}"}
        findings = self._scan_layer_bytes(
            data, digest, image_ref, digest, service, **kwargs)
        self._cache_layer(digest, findings)
        return {"digest": digest, "cached": False, "findings": findings}

    def _scan_layer_bytes(self, data: bytes, name: str, image_ref: str,
                          digest: str, service: str, **kwargs) -> list:
        """Extract one layer blob safely and scan it with inner scanners."""
        from ecdat.core.inventory import safe_extract_archive
        suffix = ".tar.gz" if data[:2] == b"\x1f\x8b" else ".tar"
        with tempfile.TemporaryDirectory(prefix="ecdat-layerx-") as tmp:
            tmp_path = Path(tmp)
            blob = tmp_path / f"layer{suffix}"
            try:
                blob.write_bytes(data)
                dest = tmp_path / "rootfs"
                outcome = safe_extract_archive(blob, dest)
            except ValueError:
                return []
            findings = self._scan_rootfs_inner(
                dest, image_ref, digest, service, **kwargs)
            for reason in outcome.get("skipped", []):
                for finding in findings:
                    _append_note(finding, f"layer-warning={reason[:120]}")
            return findings

    def _scan_rootfs(self, root: Path, image_ref: str = "",
                     service: str = "", **kwargs) -> list:
        service = service or root.name
        findings = self._scan_rootfs_inner(
            root, image_ref or f"rootfs:{root.name}", "", service, **kwargs)
        layers = [{"digest": "", "cached": False, "findings": findings}]
        return self._finish("rootfs", layers)

    # -- inner scanning (same families as local repos) --------------------

    def _scan_rootfs_inner(self, root: Path, image_ref: str, digest: str,
                           service: str, **kwargs) -> list:
        from ecdat.scanners.dependency.scanner import DependencyScanner
        from ecdat.scanners.binary.scanner import BinaryScanner
        from ecdat.scanners.config.scanner import ConfigScanner
        from ecdat.scanners.certificate.scanner import CertificateScanner
        from ecdat.scanners.source.scanner import SourceScanner

        findings: list[ScannerFinding] = []
        families = [
            ("dependency", DependencyScanner()),
            ("binary", BinaryScanner()),
            ("config", ConfigScanner()),
            ("certificate", CertificateScanner()),
            ("source", SourceScanner()),
        ]
        allowed = kwargs.get("scanners")
        for family, scanner in families:
            if allowed is not None and family not in allowed:
                continue
            try:
                if not scanner.is_available():
                    continue
                for finding in scanner.scan(root, **kwargs):
                    findings.append(self._tag_inner(
                        finding, image_ref, digest, service, root))
            except Exception:
                continue
        if self._has_syft and image_ref:
            try:
                from ecdat.scanners.container.syft_scanner import SyftScanner
                syft = SyftScanner()
                if syft.is_available():
                    for finding in syft.scan(f"dir:{root}"):
                        findings.append(self._tag_inner(
                            finding, image_ref, digest, service, root))
            except Exception:
                pass
        if self._has_trivy and image_ref:
            findings.extend(self._scan_with_trivy_fs(
                root, image_ref, digest, service))
        return findings

    def _tag_inner(self, finding: ScannerFinding, image_ref: str,
                   digest: str, service: str, root: Path) -> ScannerFinding:
        try:
            loc = finding.location
            rel = ""
            if loc is not None and getattr(loc, "file", None):
                try:
                    rel = str(Path(str(loc.file)).relative_to(root))
                except Exception:
                    rel = Path(str(loc.file)).name
            short = digest.replace("sha256:", "")[:12] if digest else "rootfs"
            if loc is not None:
                loc.uri = f"image:{image_ref}/layer:{short}/{rel}".replace(
                    "\\", "/")
            _append_note(
                finding, f"image={image_ref}; layer={short}; service={service}")
        except Exception:
            pass
        return finding

    @staticmethod
    def _retarget(findings: list, image_ref: str, digest: str,
                  service: str) -> list:
        """Re-tag CACHED findings for this image (no rescan)."""
        import copy as _copy
        out = []
        for finding in findings:
            try:
                clone = _copy.deepcopy(finding)
            except Exception:
                continue
            try:
                short = digest.replace("sha256:", "")[:12] if digest else "rootfs"
                loc = clone.location
                # Strip the known image/layer prefix to recover the full
                # in-layer relative path (a basename split would drop
                # directories and corrupt linkage).
                rel = ""
                if loc is not None and getattr(loc, "uri", None):
                    uri = str(loc.uri)
                    marker = "/layer:"
                    if marker in uri:
                        tail = uri.split(marker, 1)[1]
                        rel = tail.split("/", 1)[1] if "/" in tail else ""
                    else:
                        rel = uri.rsplit("/", 1)[-1].replace("\\", "/")
                elif loc is not None and getattr(loc, "file", None):
                    rel = Path(str(loc.file)).name
                if loc is not None:
                    loc.uri = (f"image:{image_ref}/layer:{short}/{rel}")
                _append_note(
                    clone, f"image={image_ref}; layer={short}; service={service}")
            except Exception:
                pass
            out.append(clone)
        return out

    # -- daemon/syft/trivy backends (all guarded) --------------------------

    def _scan_with_syft(self, image_ref: str) -> list:
        try:
            from ecdat.scanners.container.syft_scanner import SyftScanner
            syft = SyftScanner()
            if not syft.is_available():
                return []
            return list(syft.scan(image_ref))
        except Exception:
            return []

    def _scan_with_daemon(self, image_ref: str) -> list:
        try:
            from ecdat.scanners.container.docker_scanner import DockerScanner
            daemon = DockerScanner()
            if not daemon.is_available():
                return []
            return list(daemon.scan(image_ref, allow_pull=True))
        except Exception:
            return []

    def _scan_with_trivy_fs(self, root: Path, image_ref: str,
                            digest: str, service: str) -> list:
        from ecdat.scanners.dependency.crypto_packages import (
            CRYPTO_PACKAGES, capabilities_for)
        findings: list[ScannerFinding] = []
        try:
            proc = subprocess.run(
                ["trivy", "fs", "--format", "json", "--quiet", str(root)],
                capture_output=True, text=True, timeout=300)
            if proc.returncode not in (0, 1):
                return findings
            data = json.loads(proc.stdout or "{}")
        except Exception:
            return findings
        for result in data.get("Results", []) or []:
            for vuln in result.get("Vulnerabilities", []) or []:
                name = str(vuln.get("PkgName", "")).lower()
                if not name:
                    continue
                info = CRYPTO_PACKAGES.get(name)
                if info is None:
                    for key, candidate in CRYPTO_PACKAGES.items():
                        if key in name or name in key:
                            info = candidate
                            name = key
                            break
                if info is None:
                    continue
                canonical = info.get("canonical", name)
                version = str(vuln.get("InstalledVersion", ""))
                findings.append(ScannerFinding(
                    canonical=canonical, original=name,
                    library=name,
                    usage_state=UsageState.PROVIDED_ONLY, confidence=0.6,
                    evidence=[create_evidence_signal(
                        tool="container-trivy",
                        detail=f"vulnerable package {name}@{version} "
                               f"({vuln.get('VulnerabilityID', '')})",
                        confidence=0.6,
                        snippet=f"{name} {version} - "
                                f"{vuln.get('Title', '')}"[:200])],
                    location=Location(
                        file=str(root),
                        uri=f"image:{image_ref}/trivy:{vuln.get('VulnerabilityID', '')}"),
                    implementation=Implementation(
                        library=name, version=version, provider="trivy"),
                    context=Context(
                        exposure=Exposure.CLOUD,
                        notes=f"image={image_ref}; service={service}"),
                ))
                caps = capabilities_for(name)
                if caps:
                    _append_note(findings[-1], f"provides={','.join(caps)}")
        return [normalize_finding(f) for f in findings]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except Exception:
        return "unknown"
    return "sha256:" + digest.hexdigest()


def _append_note(finding: ScannerFinding, notes: str) -> None:
    """Append join keys without clobbering existing notes (Phase 5 rule)."""
    try:
        context = getattr(finding, "context", None)
        if context is None:
            return
        existing = str(getattr(context, "notes", "") or "")
        if not existing:
            context.notes = notes
        else:
            additions = [p for p in notes.split("; ")
                         if p.split("=")[0] + "=" not in existing]
            if additions:
                context.notes = existing + "; " + "; ".join(additions)
    except Exception:
        pass


ScannerRegistry.register(ContainerScanner())
