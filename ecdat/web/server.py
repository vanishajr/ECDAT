"""Local, session-scoped HTTP API for the React ECDAT user interface.

Uploads, clones, scan results, and reports are temporary.  Results are kept
in memory and input workspaces are removed when the browser asks to end its
session (and on process exit).  The API deliberately does not use SQLite or
alter P1/P2 analysis contracts.
"""

from __future__ import annotations

import argparse
import atexit
import io
import json
import os
import re
import shutil
import tempfile
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from tarfile import TarFile, open as tar_open
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen

from ecdat.adapters.graph_adapter import adapt_cir_graph
from ecdat.adapters.risk_view import summarize_wire_risks
from ecdat.adapters.scanner_policy import DEFAULT_SCANNERS, OPT_IN_SCANNERS
from ecdat.adapters.pipeline import RealScanError
from ecdat.core.orchestrator import ScanPermissions, ScanRequest, get_orchestrator
from ecdat.exports import cbom, csv_gen, sarif
from ecdat.reports import aggregate, html, markdown, pdf
from ecdat.scanners.path_policy import iter_project_files

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_UPLOAD_BYTES = 250 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
SAFE_COMPONENT = re.compile(r"[^A-Za-z0-9._-]+")
GITHUB_API = "https://api.github.com"
GITHUB_TOKEN_COOKIE = "ecdat_github_session"


def _load_local_env() -> None:
    """Load simple KEY=VALUE entries from the repository root .env file."""
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.is_file():
        return
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_local_env()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_name(value: str, fallback: str = "input") -> str:
    cleaned = SAFE_COMPONENT.sub("_", Path(value or fallback).name).strip("._")
    return cleaned[:140] or fallback


def _safe_relative(value: str) -> Path:
    raw = PurePosixPath(str(value or "").replace("\\", "/"))
    if raw.is_absolute() or any(part in {"", ".", ".."} for part in raw.parts):
        raise ValueError("unsafe relative upload path")
    return Path(*raw.parts)


def _safe_extract_zip(path: Path, destination: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ValueError("archive contains too many files")
        for member in members:
            relative = _safe_relative(member.filename)
            if member.is_dir():
                continue
            output = destination / relative
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
            relative = _safe_relative(member.name)
            output = destination / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            src = archive.extractfile(member)
            if src is not None:
                with src, output.open("wb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)


def _is_archive(path: Path) -> bool:
    lower = path.name.lower()
    return lower.endswith((".zip", ".tar", ".tar.gz", ".tgz"))


def _architecture(paths: list[Path]) -> str:
    for path in paths:
        try:
            magic = path.read_bytes()[:8]
        except OSError:
            continue
        if magic.startswith(b"\x7fELF"):
            return "ELF"
        if magic.startswith(b"MZ"):
            return "PE"
        if magic[:4] in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"}:
            return "Mach-O"
    return "Source / mixed"


def _inspect(root: Path, label: str) -> dict[str, Any]:
    """Phase 2: real inventory summary (not just file counts/extensions).

    Legacy keys (name/file_count/total_bytes/extensions/languages/
    architecture) are preserved for existing GUI clients; the inventory
    roll-up (artifact counts by category, detected surfaces, archives,
    skip reasons) is added alongside. ``name`` stays the user-supplied
    label so temp upload paths are never the primary identity.
    """
    from ecdat.core.inventory import inventory_target

    records, summary = inventory_target(root)
    files = [Path(r.abs_path) for r in records if Path(r.abs_path).is_file()]
    if not files:
        files = list(iter_project_files(root))
    extensions = sorted({p.suffix.lower() for p in files if p.suffix})[:16]
    return {
        "name": label,
        "display_name": label,
        "file_count": summary.total,
        "total_bytes": summary.total_bytes,
        "extensions": extensions,
        "languages": list(summary.languages),
        "architecture": _architecture(files),
        "artifact_counts": dict(summary.by_category),
        "surfaces": dict(summary.by_surface),
        "archives": list(summary.archives),
        "skipped_count": len(summary.skipped),
        "skipped": summary.skipped[:50],
        "inventory_truncated": summary.truncated,
    }


class AppState:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="ecdat-web-"))
        self.lock = threading.RLock()
        self.inputs: dict[str, dict[str, Any]] = {}
        self.jobs: dict[str, dict[str, Any]] = {}
        self.results: dict[str, dict[str, Any]] = {}
        self.oauth_states: dict[str, dict[str, Any]] = {}
        self.github_sessions: dict[str, dict[str, Any]] = {}
        # Phase 11: durable scan model shared with CLI/CI. Same default
        # DB file as the CLI so GUI and CLI histories unify; override
        # with --db / ECDAT_DB (tests use a temp file).
        if db_path is None:
            db_path = os.getenv("ECDAT_DB") or str(
                Path.home() / ".ecdat" / "ecdat.db")
        self.db_path = str(db_path)

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def new_input(self) -> dict[str, Any]:
        input_id = uuid.uuid4().hex
        directory = self.root / "inputs" / input_id
        directory.mkdir(parents=True, exist_ok=True)
        value = {"input_id": input_id, "directory": directory, "label": "Selected input"}
        with self.lock:
            self.inputs[input_id] = value
        return value

    def input_for(self, input_id: str) -> dict[str, Any]:
        with self.lock:
            value = self.inputs.get(input_id)
        if value is None:
            raise KeyError("unknown input")
        return value

    def remove_input(self, input_id: str) -> None:
        with self.lock:
            value = self.inputs.pop(input_id, None)
        if value:
            shutil.rmtree(value["directory"], ignore_errors=True)

    def github_session(self, session_id: str) -> dict[str, Any] | None:
        with self.lock:
            return self.github_sessions.get(session_id)

    def remove_github_session(self, session_id: str) -> None:
        with self.lock:
            self.github_sessions.pop(session_id, None)


STATE = AppState()
atexit.register(STATE.close)


def _profile_scanners(profile: str, requested: list[str] | None) -> list[str]:
    """Resolve GUI scanner selection (Phase 3: automatic local discovery).

    Local/static coverage (source, dependencies, binaries, configs,
    certs/keys) is automatic for every profile - the user no longer
    decides it with checkboxes. An explicit ``requested`` list is still
    honored as the Advanced/debug override. Depth (quick/standard/deep)
    changes analysis effort inside the orchestrator, never which local
    artifacts ECDAT knows about. External families (container pull,
    runtime probing, cloud APIs) still require explicit opt-in.
    """
    if requested:
        known = set(DEFAULT_SCANNERS) | set(OPT_IN_SCANNERS)
        unknown = sorted(set(requested) - known)
        if unknown:
            raise ValueError(f"unknown scanner layer(s): {', '.join(unknown)}")
        return requested
    profile = profile.lower()
    if profile in {"quick", "standard", "deep"}:
        return list(DEFAULT_SCANNERS)
    raise ValueError("profile must be quick, standard, or deep")


def _coverage_payload(plan: dict | None,
                      diagnostics: dict | None) -> dict[str, Any]:
    """Phase 12 coverage/diagnostics view (delegates to the shared
    aggregate helper so CLI reports and the GUI agree byte-for-byte)."""
    return aggregate.coverage_payload(plan, diagnostics)


def _limitations_payload(diagnostics: dict | None) -> dict[str, Any]:
    try:
        from ecdat.commands.ci_cmd import _limitations_from
        return dict(_limitations_from(diagnostics))
    except Exception:
        return {}


def _result_payload(cir: dict, canonical: dict,
                    plan: dict | None = None,
                    diagnostics: dict | None = None) -> dict[str, Any]:
    risks = list(cir.get("risks", []) or [])
    graph, folded_files = adapt_cir_graph(cir, risks)
    risk = summarize_wire_risks(risks, len(canonical.get("findings", [])))
    from ecdat.adapters.migration_adapter import build_real_items
    coverage = _coverage_payload(plan, diagnostics)
    limitations = _limitations_payload(diagnostics)
    try:
        _label = str(((plan or {}).get("display_target")
                       or (diagnostics or {}).get("display_target", "")) or "")
    except Exception:
        _label = ""
    report = aggregate.build_report(
        canonical, real_risk=risk,
        recommendations=build_real_items(cir, str(canonical.get("target", ""))),
        cir=cir, limitations=limitations, coverage=coverage,
        display_label=_label)
    return {
        "scan_id": canonical["scan_id"],
        "canonical": canonical,
        "cir": cir,
        "analytics": {
            "risk": risk,
            "finding_count": len(canonical.get("findings", [])),
            "asset_count": len(cir.get("assets", []) or []),
            "operation_count": len(cir.get("operations", []) or []),
            "files_scanned": canonical.get("stats", {}).get("files_scanned", 0),
            "tool_versions": canonical.get("tool_versions", {}),
            "registry_version": cir.get("registry_version"),
        },
        "findings": canonical.get("findings", []),
        "assets": cir.get("assets", []),
        "operations": cir.get("operations", []),
        "recommendations": cir.get("recommendations", []),
        "risks": risks,
        "graph": {**graph, "folded_files": folded_files},
        "coverage": coverage,
        "limitations": limitations,
        "plan": plan if isinstance(plan, dict) else {},
        "report": report,
    }


def _run_job(job_id: str) -> None:
    """Phase 1: GUI scans through the shared ScanOrchestrator.

    Same pipeline as CLI/CI; progress events drive the job's
    progress/stage so the GUI reflects real architecture stages.
    """
    with STATE.lock:
        job = STATE.jobs[job_id]
        job.update({"status": "running", "progress": 5, "stage": "Preparing input"})

    def _on_progress(event) -> None:
        with STATE.lock:
            current = STATE.jobs.get(job_id)
            if current is None:
                return
            # Orchestrator emits 0-100; keep job shape stable for the GUI.
            current.update({
                "progress": int(event.progress),
                "stage": str(event.message or event.stage),
            })

    try:
        input_data = STATE.input_for(job["input_id"])
        scanners = list(job["scanners"])
        cloud_config = job.get("cloud_config")
        
        # Determine target: for cloud scanning, use cloud label instead of local path
        if cloud_config and cloud_config.get("provider") == "aws" and "cloud" in scanners:
            profile = cloud_config.get("profile", "default")
            services = cloud_config.get("services", "kms,acm,elb,alb")
            target = f"aws:{profile}:services={services}"
            # Extract credentials for ScanRequest
            aws_access_key_id = cloud_config.get("aws_access_key_id")
            aws_secret_access_key = cloud_config.get("aws_secret_access_key")
            aws_session_token = cloud_config.get("aws_session_token")
            aws_profile = cloud_config.get("profile_name") or (profile if not aws_access_key_id else None)
        elif "runtime" in scanners:
            # Runtime targets are host:port endpoints, not filesystem paths
            # Check if input_data has a runtime_target field (set by inspect for runtime endpoints)
            runtime_target = input_data.get("runtime_target")
            if runtime_target:
                target = str(runtime_target)
            else:
                # Fallback: read the uploaded file content if it looks like host:port
                target_path = Path(input_data["target"])
                if target_path.is_file():
                    try:
                        content = target_path.read_text(encoding="utf-8").strip()
                        # Validate host:port format
                        if ":" in content and content.rsplit(":", 1)[-1].isdigit():
                            target = content
                        else:
                            target = str(target_path)
                    except Exception:
                        target = str(target_path)
                else:
                    target = str(target_path)
            aws_access_key_id = None
            aws_secret_access_key = None
            aws_session_token = None
            aws_profile = None
        else:
            target = str(Path(input_data["target"]))
            aws_access_key_id = None
            aws_secret_access_key = None
            aws_session_token = None
            aws_profile = None
        
        try:
            from ecdat.core.orchestrator import ScanContext as _ScanContext
            stored = job.get("context") or {}
            context = _ScanContext(
                environment=stored.get("environment"),
                owner=stored.get("owner"),
                exposure=stored.get("exposure"),
                business_criticality=stored.get("business_criticality"),
                data_lifetime_years=stored.get("data_lifetime_years"),
                migration_years=stored.get("migration_years"),
            )
        except Exception:
            from ecdat.core.orchestrator import ScanContext as _ScanContext
            context = _ScanContext()
        try:
            risk_z = float(job.get("risk_z", 10.0))
        except (TypeError, ValueError):
            risk_z = 10.0
        request = ScanRequest(
            target=target,
            scanners=scanners,
            permissions=ScanPermissions(
                allow_container="container" in scanners,
                allow_cloud="cloud" in scanners,
                allow_runtime="runtime" in scanners,
                allow_pull=bool(job.get("allow_pull", False)),
                allow_build=bool(job.get("allow_build", False)),
            ),
            profile=str(job.get("profile", "standard") or "standard"),
            risk_z=risk_z,
            context=context,
            caller="gui",
            display_name=str(input_data.get("label") or "Selected input"),
            cloud_aws_access_key_id=aws_access_key_id,
            cloud_aws_secret_access_key=aws_secret_access_key,
            cloud_aws_session_token=aws_session_token,
            cloud_aws_profile=aws_profile,
        )
        with STATE.lock:
            job.update({"progress": 10, "stage": "Planning scan"})
        result = get_orchestrator().scan(request, progress=_on_progress)
        cir, canonical = result.as_tuple()
        payload = _result_payload(cir, canonical, result.plan.as_dict(),
                                  result.diagnostics)
        persisted = False
        try:
            from ecdat.store.repository import ScanRepository as _Repo
            with _Repo(STATE.db_path) as repo:
                repo.save_scan(canonical, cir, result.plan.as_dict(),
                               result.diagnostics, replace=True)
            persisted = True
        except Exception:
            persisted = False  # memory payload still serves this process
        with STATE.lock:
            STATE.results[canonical["scan_id"]] = payload
            job.update({"status": "completed", "progress": 100, "stage": "Analysis complete", "scan_id": canonical["scan_id"], "persisted": persisted})
    except Exception as exc:  # surfaced to user; never hide scan failure
        with STATE.lock:
            job.update({"status": "failed", "progress": 100, "stage": "Analysis failed", "error": str(exc)})


class Handler(BaseHTTPRequestHandler):
    server_version = "ECDATWeb/1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _headers(self, code: int, content_type: str = "application/json", length: int | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", self._frontend_url())
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Input-Id, X-File-Name, X-Relative-Path")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.end_headers()

    def _json(self, code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self._headers(code, length=len(body))
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        value = json.loads(body or b"{}")
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def do_OPTIONS(self) -> None:
        self._headers(HTTPStatus.NO_CONTENT)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/github/oauth/start":
            self._github_oauth_start()
            return
        if path == "/api/github/oauth/callback":
            self._github_oauth_callback()
            return
        if path == "/api/github/session":
            self._github_session()
            return
        if path == "/api/github/repos":
            self._github_repos()
            return
        if path == "/api/health":
            self._json(200, {"ok": True, "time": _now()})
            return
        if path == "/api/scanner-capabilities":
            self._json(200, {"default": list(DEFAULT_SCANNERS), "optional": dict(OPT_IN_SCANNERS), "github_oauth": bool(os.getenv("GITHUB_CLIENT_ID") and os.getenv("GITHUB_CLIENT_SECRET"))})
            return
        if path == "/api/demos":
            try:
                from ecdat.web.demos import list_demos as _demos
                self._json(200, {"demos": _demos()})
            except Exception as exc:
                self._json(500, {"error": f"demos unavailable: {exc}"})
            return
        if path.startswith("/api/jobs/"):
            job_id = path.rsplit("/", 1)[-1]
            with STATE.lock:
                job = STATE.jobs.get(job_id)
            if job is None:
                self._json(404, {"error": "unknown scan job"})
            else:
                self._json(200, {k: v for k, v in job.items() if k != "input_id"})
            return
        if path == "/api/scans":
            try:
                from ecdat.store.repository import ScanRepository as _Repo
                with _Repo(STATE.db_path) as repo:
                    history = repo.list_scans(limit=100)
                self._json(200, {"scans": history})
            except Exception as exc:
                self._json(500, {"error": f"scan history unavailable: {exc}"})
            return
        if path.startswith("/api/results/"):
            parts = path.split("/")
            scan_id = parts[3] if len(parts) > 3 else ""
            with STATE.lock:
                result = STATE.results.get(scan_id)
            if result is None:
                # Phase 11 reopen: completed scans survive process-level
                # navigation via the shared repository, not just memory.
                try:
                    from ecdat.store.repository import (
                        ScanRepository as _Repo)
                    with _Repo(STATE.db_path) as repo:
                        stored = repo.get_payload(scan_id)
                    if stored and stored.get("canonical") \
                            and stored.get("cir"):
                        result = _result_payload(stored["cir"],
                                                 stored["canonical"],
                                                 stored.get("plan"),
                                                 stored.get("diagnostics"))
                        with STATE.lock:
                            STATE.results[scan_id] = result
                except Exception:
                    result = None
            if result is None:
                self._json(404, {"error": "results are no longer available"})
                return
            if len(parts) == 4:
                self._json(200, result)
                return
            section = parts[4]
            if section == "report":
                fmt = parts[5] if len(parts) > 5 else "markdown"
                self._report(result, fmt)
                return
            if section in result:
                self._json(200, {section: result[section]})
                return
            self._json(404, {"error": "unknown result section"})
            return
        self._json(404, {"error": "not found"})

    def _report(self, result: dict[str, Any], fmt: str) -> None:
        report = result["report"]
        if fmt == "markdown":
            body, kind = markdown.to_markdown(report).encode(), "text/markdown; charset=utf-8"
        elif fmt == "html":
            body, kind = html.to_html(report).encode(), "text/html; charset=utf-8"
        elif fmt == "pdf":
            body, kind = pdf.to_pdf_bytes(report), "application/pdf"
        elif fmt == "json":
            body, kind = json.dumps(result["canonical"], indent=2).encode(), "application/json"
        elif fmt == "cir":
            body, kind = json.dumps(result["cir"], indent=2).encode(), "application/json"
        elif fmt == "csv":
            body, kind = csv_gen.to_csv(result["canonical"]).encode(), "text/csv; charset=utf-8"
        elif fmt == "sarif":
            body, kind = sarif.to_sarif(result["canonical"]).encode(), "application/sarif+json"
        elif fmt == "cbom-json":
            body, kind = cbom.to_cbom_json(result["canonical"]).encode(), "application/json"
        elif fmt == "cbom-xml":
            body, kind = cbom.to_cbom_xml(result["canonical"]).encode(), "application/xml"
        else:
            self._json(400, {"error": "unsupported report format"})
            return
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", self._frontend_url())
        self.send_header("Content-Disposition", f'attachment; filename="ecdat-{result["scan_id"]}.{fmt}"')
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/api/uploads":
                self._upload()
            elif path == "/api/inputs/inspect":
                self._inspect_input()
            elif path == "/api/demos/select":
                self._demo_select()
            elif path == "/api/scan-plan":
                self._scan_plan()
            elif path == "/api/scan-jobs":
                self._start_job()
            elif path == "/api/github/public":
                self._github_public()
            elif path == "/api/github/repos/select":
                self._github_repo_select()
            elif path == "/api/github/logout":
                self._github_logout()
            else:
                self._json(404, {"error": "not found"})
        except (ValueError, KeyError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            self._json(500, {"error": f"server error: {exc}"})

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/inputs/"):
            STATE.remove_input(path.rsplit("/", 1)[-1])
            self._json(200, {"ok": True})
            return
        self._json(404, {"error": "not found"})

    def _upload(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_UPLOAD_BYTES:
            raise ValueError("upload must be between 1 byte and 250 MB")
        input_id = self.headers.get("X-Input-Id")
        input_data = STATE.input_for(input_id) if input_id else STATE.new_input()
        name = self.headers.get("X-File-Name", "upload")
        relative = self.headers.get("X-Relative-Path") or _safe_name(name)
        destination = input_data["directory"] / _safe_relative(relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        remaining = length
        with destination.open("wb") as handle:
            while remaining:
                chunk = self.rfile.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError("incomplete upload")
                handle.write(chunk)
                remaining -= len(chunk)
        input_data["label"] = _safe_name(name)
        self._json(201, {"input_id": input_data["input_id"], "name": name})

    def _inspect_input(self) -> None:
        from ecdat.core.inventory import safe_extract_archive

        body = self._read_json()
        data = STATE.input_for(str(body.get("input_id", "")))
        root = Path(data["directory"])
        archives = [p for p in root.rglob("*") if p.is_file() and _is_archive(p)]
        if len(archives) == 1 and len([p for p in root.rglob("*") if p.is_file()]) == 1:
            extracted = root / "extracted"
            extracted.mkdir(exist_ok=True)
            # Single hardened implementation (limits + traversal/link
            # safety); failures stay loud instead of half-extracting.
            safe_extract_archive(archives[0], extracted)
            root = extracted
        
        # Check for runtime endpoint (host:port in a single text file)
        files = [p for p in root.rglob("*") if p.is_file()]
        if len(files) == 1 and not archives:
            try:
                content = files[0].read_text(encoding="utf-8").strip()
                if ":" in content and content.rsplit(":", 1)[-1].isdigit():
                    # This looks like a runtime endpoint
                    data["runtime_target"] = content
                    # For runtime, target is the endpoint string, not the file
                    data["target"] = content
                    self._json(200, {"input_id": data["input_id"], **_inspect(root, data["label"]), "runtime_target": content})
                    return
            except Exception:
                pass
        
        data["target"] = root
        self._json(200, {"input_id": data["input_id"], **_inspect(root, data["label"])})

    def _demo_select(self) -> None:
        """Load a bundled demo directory as the scan input (judges)."""
        from ecdat.web.demos import get_demo as _get_demo

        body = self._read_json()
        directory, meta = _get_demo(str(body.get("demo_id", "")))
        data = STATE.new_input()
        root = Path(data["directory"]) / "demo"
        root.mkdir(parents=True, exist_ok=True)
        for path in sorted(directory.iterdir()):
            if not path.is_file() or path.name == "meta.json":
                continue
            shutil.copy2(path, root / _safe_name(path.name))
        data["target"] = root
        data["label"] = str(meta.get("name") or directory.name)
        self._json(200, {"input_id": data["input_id"],
                         **_inspect(root, data["label"])})

    def _scan_plan(self) -> None:
        """Phase 3: scan-plan preview for GUI use (no scanning)."""
        body = self._read_json()
        data = STATE.input_for(str(body.get("input_id", "")))
        target = data.get("target") or data["directory"]
        profile = str(body.get("profile", "standard") or "standard")
        requested = body.get("scanners")
        scanners = _profile_scanners(
            profile, requested if isinstance(requested, list) else None)
        cloud_config = body.get("cloudConfig")
        
        # Determine target for plan: for cloud scanning, use cloud label
        if cloud_config and cloud_config.get("provider") == "aws" and "cloud" in scanners:
            plan_profile = cloud_config.get("profile", "default")
            services = cloud_config.get("services", "kms,acm,elb,alb")
            plan_target = f"aws:{plan_profile}:services={services}"
            aws_access_key_id = cloud_config.get("aws_access_key_id")
            aws_secret_access_key = cloud_config.get("aws_secret_access_key")
            aws_session_token = cloud_config.get("aws_session_token")
            aws_profile = cloud_config.get("profile_name") or (plan_profile if not aws_access_key_id else None)
        else:
            plan_target = str(target)
            aws_access_key_id = None
            aws_secret_access_key = None
            aws_session_token = None
            aws_profile = None
        
        request = ScanRequest(
            target=plan_target,
            scanners=scanners,
            permissions=ScanPermissions(
                allow_container="container" in scanners,
                allow_cloud="cloud" in scanners,
                allow_runtime="runtime" in scanners,
                allow_pull=bool(body.get("allowPull", False)),
                allow_build=bool(body.get("allowBuild", False)),
            ),
            profile=profile,
            caller="gui-plan",
            display_name=str(data.get("label") or "Selected input"),
            cloud_aws_access_key_id=aws_access_key_id,
            cloud_aws_secret_access_key=aws_secret_access_key,
            cloud_aws_session_token=aws_session_token,
            cloud_aws_profile=aws_profile,
        )
        self._json(200, {"input_id": data["input_id"],
                         "plan": get_orchestrator().plan(request).as_dict()})

    def _start_job(self) -> None:
        body = self._read_json()
        input_id = str(body.get("input_id", ""))
        data = STATE.input_for(input_id)
        if not data.get("target"):
            raise ValueError("inspect the selected input before analysis")
        requested = body.get("scanners")
        profile = str(body.get("profile", "standard") or "standard").lower()
        scanners = _profile_scanners(profile, requested if isinstance(requested, list) else None)
        # Phase 7 external-discovery opt-ins (default False): pulling
        # image refs, probing runtime endpoints is already gated by
        # scanner selection, cloud APIs by scanner selection.
        allow_pull = bool(body.get("allowPull", False))
        allow_build = bool(body.get("allowBuild", False))
        # Cloud configuration (for cloud scanning)
        cloud_config = body.get("cloudConfig")
        # Phase 10 user-supplied risk context (all optional; visibly
        # tagged user-supplied in risk provenance, never defaulted up).
        try:
            from ecdat.core.orchestrator import context_from_args as _ctx
            context = _ctx(body if isinstance(body, dict) else {}).as_dict()
        except Exception:
            context = {}
        try:
            from ecdat.core.orchestrator import risk_z_from_args as _z
            risk_z = _z(body if isinstance(body, dict) else {})
        except Exception:
            risk_z = 10.0
        job_id = uuid.uuid4().hex
        job = {"job_id": job_id, "input_id": input_id, "status": "queued", "progress": 5, "stage": "Preparing input", "scanners": scanners, "profile": profile, "allow_pull": allow_pull, "allow_build": allow_build, "context": context, "risk_z": risk_z, "created_at": _now(), "cloud_config": cloud_config}
        with STATE.lock:
            STATE.jobs[job_id] = job
        threading.Thread(target=_run_job, args=(job_id,), daemon=True).start()
        self._json(202, {k: v for k, v in job.items() if k != "input_id"})

    def _github_public(self) -> None:
        from ecdat.acquisition import acquire_github_repository
        from ecdat.acquisition import is_github_url as _is_github_url

        body = self._read_json()
        url = str(body.get("url", "")).strip()
        if not _is_github_url(url):
            raise ValueError("enter a valid public GitHub repository URL")
        data = STATE.new_input()
        try:
            acquired = acquire_github_repository(
                url, parent=Path(data["directory"]))
        except Exception as exc:
            STATE.remove_input(data["input_id"])
            if isinstance(exc, ValueError):
                raise
            raise ValueError("could not download the selected GitHub repository") from exc
        data["target"] = acquired["target"]
        data["label"] = str(acquired["label"])
        self._json(201, {"input_id": data["input_id"], **_inspect(acquired["target"], data["label"])})

    def _github_configured(self) -> bool:
        return bool(os.getenv("GITHUB_CLIENT_ID") and os.getenv("GITHUB_CLIENT_SECRET"))

    def _frontend_url(self) -> str:
        return os.getenv("GITHUB_FRONTEND_URL", "http://127.0.0.1:5173").rstrip("/")

    def _cookie_session(self) -> tuple[str, dict[str, Any]] | None:
        raw = self.headers.get("Cookie", "")
        values = dict(item.strip().split("=", 1) for item in raw.split(";") if "=" in item)
        session_id = values.get(GITHUB_TOKEN_COOKIE, "")
        session = STATE.github_session(session_id) if session_id else None
        return (session_id, session) if session else None

    def _github_request(self, url: str, token: str, *, method: str = "GET", payload: bytes | None = None) -> Any:
        request = Request(
            url,
            data=payload,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Authorization": f"Bearer {token}",
                "User-Agent": "ECDAT-local",
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                return response.read()
        except Exception as exc:
            raise ValueError("GitHub API request failed") from exc

    def _github_oauth_start(self) -> None:
        if not self._github_configured():
            self._json(503, {"error": "GitHub OAuth is not configured on the backend"})
            return
        state = uuid.uuid4().hex
        requested_frontend = parse_qs(urlparse(self.path).query).get("frontend", [self._frontend_url()])[0]
        frontend_parts = urlparse(requested_frontend)
        if frontend_parts.scheme != "http" or frontend_parts.hostname not in LOOPBACK_HOSTS:
            requested_frontend = self._frontend_url()
        with STATE.lock:
            STATE.oauth_states[state] = {
                "expires": datetime.now(timezone.utc).timestamp() + 600,
                "frontend": requested_frontend.rstrip("/"),
            }
        query = urlencode({
            "client_id": os.environ["GITHUB_CLIENT_ID"],
            "redirect_uri": os.getenv("GITHUB_OAUTH_REDIRECT_URI", "http://127.0.0.1:8765/api/github/oauth/callback"),
            "scope": "repo read:user",
            "state": state,
        })
        self.send_response(302)
        self.send_header("Location", f"https://github.com/login/oauth/authorize?{query}")
        self.end_headers()

    def _github_oauth_callback(self) -> None:
        query = parse_qs(urlparse(self.path).query)
        state = query.get("state", [""])[0]
        code = query.get("code", [""])[0]
        with STATE.lock:
            state_data = STATE.oauth_states.pop(state, None)
        if not state or state_data is None or state_data["expires"] < datetime.now(timezone.utc).timestamp():
            self._json(400, {"error": "invalid or expired GitHub OAuth state"})
            return
        if not code or not self._github_configured():
            self._json(400, {"error": "GitHub OAuth authorization was not completed"})
            return
        token_payload = urlencode({
            "client_id": os.environ["GITHUB_CLIENT_ID"],
            "client_secret": os.environ["GITHUB_CLIENT_SECRET"],
            "code": code,
            "redirect_uri": os.getenv("GITHUB_OAUTH_REDIRECT_URI", "http://127.0.0.1:8765/api/github/oauth/callback"),
        }).encode()
        try:
            token_request = Request(
                "https://github.com/login/oauth/access_token",
                data=token_payload,
                method="POST",
                headers={"Accept": "application/json", "User-Agent": "ECDAT-local"},
            )
            with urlopen(token_request, timeout=30) as response:
                token_data = json.loads(response.read())
            access_token = token_data.get("access_token")
            if not access_token:
                raise ValueError("GitHub did not return an access token")
            user = json.loads(self._github_request(f"{GITHUB_API}/user", access_token))
        except Exception as exc:
            self._json(502, {"error": "GitHub authorization failed"})
            return
        session_id = uuid.uuid4().hex
        with STATE.lock:
            STATE.github_sessions[session_id] = {"token": access_token, "login": user.get("login", "GitHub user")}
        self.send_response(302)
        self.send_header("Location", f"{state_data['frontend']}?github=connected")
        self.send_header("Set-Cookie", f"{GITHUB_TOKEN_COOKIE}={session_id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600")
        self.end_headers()

    def _github_session(self) -> None:
        current = self._cookie_session()
        self._json(200, {"authenticated": bool(current), "login": current[1]["login"] if current else None})

    def _github_repos(self) -> None:
        current = self._cookie_session()
        if not current:
            self._json(401, {"error": "sign in with GitHub first"})
            return
        page = max(1, int(parse_qs(urlparse(self.path).query).get("page", ["1"])[0]))
        try:
            raw = self._github_request(f"{GITHUB_API}/user/repos?visibility=all&affiliation=owner,collaborator,organization_member&sort=updated&per_page=100&page={page}", current[1]["token"])
            repos = json.loads(raw)
        except (ValueError, json.JSONDecodeError):
            self._json(502, {"error": "could not load GitHub repositories"})
            return
        self._json(200, {"repositories": [
            {"id": repo["id"], "name": repo["name"], "full_name": repo["full_name"], "private": repo["private"], "owner": repo["owner"]["login"], "default_branch": repo.get("default_branch", "main"), "description": repo.get("description"), "language": repo.get("language"), "updated_at": repo.get("updated_at")}
            for repo in repos
        ], "page": page, "has_next": len(repos) == 100})

    def _github_repo_select(self) -> None:
        current = self._cookie_session()
        if not current:
            raise ValueError("sign in with GitHub first")
        body = self._read_json()
        owner = str(body.get("owner", "")).strip()
        repo = str(body.get("repo", "")).strip()
        ref = str(body.get("ref", "main")).strip() or "main"
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", repo) or not re.fullmatch(r"[A-Za-z0-9_./-]+", ref):
            raise ValueError("owner, repository, and ref are required")
        data = STATE.new_input()
        target = Path(data["directory"]) / "repository"
        archive_path = Path(data["directory"]) / "repository.tar.gz"
        try:
            request = Request(
                f"{GITHUB_API}/repos/{owner}/{repo}/tarball/{ref}",
                headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {current[1]['token']}", "User-Agent": "ECDAT-local"},
            )
            with urlopen(request, timeout=180) as response, archive_path.open("wb") as output:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_UPLOAD_BYTES:
                        raise ValueError("repository archive exceeds the 250 MB limit")
                    output.write(chunk)
            target.mkdir(parents=True, exist_ok=True)
            _safe_extract_tar(archive_path, target)
            data["target"] = target
            data["label"] = f"{owner}/{repo}@{ref}"
            self._json(201, {"input_id": data["input_id"], **_inspect(target, data["label"])})
        except Exception as exc:
            STATE.remove_input(data["input_id"])
            if isinstance(exc, ValueError):
                raise
            raise ValueError("could not download the selected GitHub repository") from exc

    def _github_logout(self) -> None:
        current = self._cookie_session()
        if current:
            STATE.remove_github_session(current[0])
        self.send_response(200)
        self.send_header("Set-Cookie", f"{GITHUB_TOKEN_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", self._frontend_url())
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')


def make_server(host: str = "127.0.0.1", port: int = 8765,
                db_path: str | Path | None = None) -> ThreadingHTTPServer:
    if host not in LOOPBACK_HOSTS:
        raise ValueError("ECDAT web API is localhost-only")
    if db_path is not None:
        STATE.db_path = str(db_path)
    return ThreadingHTTPServer((host, port), Handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ECDAT temporary web API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    server = make_server(args.host, args.port)
    print(f"ECDAT API listening at http://{args.host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        STATE.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
