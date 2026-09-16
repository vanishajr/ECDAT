"""GUI application service (Person 3 platform layer).

Mock-first use-case logic for the localhost GUI vertical slice. No
HTTP, no CLI, no Person 1 / Person 2 imports, no network calls.

Flow: preview(target) -> submit(target) -> status(job_id) polling ->
inventory(scan_id). Completed scans are stored through the existing
SQLite path (insert_scan + insert_findings_for_scan) and read back
via get_scan_doc(), so canonical fields (snippet/confidence/metadata)
are never lost. Duplicate submissions are idempotent: the fixture
scan_id already stored is reused instead of erroring.

Progress is explicitly simulated: the mock scan itself is
instantaneous, so status() advances queued -> scanning -> completed
per poll and every payload carries simulated/mock labels. Do NOT
present this as real scanner progress.
"""

from __future__ import annotations

import itertools
import json
import re
import sqlite3
import threading
from pathlib import Path

from ecdat.core.client import CoreClient, get_client
from ecdat.core.validate import validate
from ecdat.exports import cbom as cbom_mod
from ecdat.exports import csv_gen as csv_mod
from ecdat.exports import sarif as sarif_mod
from ecdat.gui import inputs as input_mod
from ecdat.gui.graph import GraphProvider, MockGraphProvider
from ecdat.gui.migration import MigrationProvider, MockMigrationProvider
from ecdat.reports import html as html_mod
from ecdat.reports import pdf as pdf_mod
from ecdat.reports.aggregate import build_report
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore

STAGES: tuple[tuple[str, float], ...] = (
    ("queued", 0.0),
    ("scanning", 0.5),
    ("completed", 1.0),
)
POLLS_TO_COMPLETE = 2

SIMULATED_NOTE = (
    "Simulated progress (mock): the mock scan is instantaneous, "
    "so queued -> scanning -> completed is staged for UI purposes only."
)

REAL_PROGRESS_NOTE = (
    "Staged progress for UI purposes: the real scan runs synchronously "
    "when the job completes. Queued -> scanning -> completed carries no "
    "timing information about the actual discovery work."
)

# Canonical v1 finding keys the inventory may surface. Anything else is
# dropped so the GUI can never invent CIR fields.
_FINDING_KEYS = (
    "rule_id",
    "title",
    "severity",
    "file",
    "line",
    "snippet",
    "confidence",
    "metadata",
)

# Display order for the risk dashboard. Zero-filled at the presentation
# edge so all five levels always render, even when absent from a scan.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

RISK_MODEL_NOTE = (
    "Mock/placeholder scoring (Task 6 model): severity-weight sum "
    "(critical=10, high=5, medium=3, low=1, info=0); levels none (0), "
    "low (1-4), medium (5-9), high (10-19), critical (20+). "
    "Person 1's real risk engine replaces this."
)

# v1 defines no per-finding confirmation field, so provenance is a
# uniform static label applied to every finding -- never fabricated
# per-finding data. It becomes data-driven when Person 1 adds a real
# confirmation field to the schema.
PROVENANCE_STATUS = "ProvidedOnly (mock)"
PROVENANCE_NOTE = (
    "Served from a deterministic mock fixture; no finding is confirmed "
    "by a real engine. Per-finding confirmation needs a Person 1 "
    "schema field and does not exist in canonical v1."
)

REDACTION_REASON = (
    "Canonical v1 defines no PII markers and mock fixture snippets "
    "contain no secrets; nothing was masked."
)
REDACTION_CAPABILITY = "Real PII redaction capability pending Person 1."

# Real-scan counterparts: usage_state is data (stored CIR evidence
# assessment surfaced via canonical metadata), and snippets arrive
# already redacted from the discovery/analysis stages.
REAL_PROVENANCE_NOTE = (
    "Produced by the integrated real pipeline (P2 discovery, P1 "
    "analysis) and stored with its CIR sidecar. usage_state comes from "
    "the stored CIR evidence assessment, not from a fixture."
)
REAL_REDACTION_REASON = (
    "Snippets are stored as redacted excerpts: the discovery evidence "
    "validator masks secrets/key material and analysis caps excerpts; "
    "nothing further was masked at render time."
)
REAL_REDACTION_CAPABILITY = (
    "PII/secret redaction enforced at discovery (P2 evidence validator) "
    "and analysis (P1 excerpt cap)."
)

SCAN_PROVENANCE_LABEL = (
    "Scan provenance (not a finding observation timeline): canonical v1 "
    "records only scan-level started_at/finished_at. A per-finding "
    "evidence timeline needs Person 1 fields and is not drawn."
)

ASSET_LABEL = "Flat asset inventory — relationships not available yet."

GROUPING_LABEL = "Co-occurrence grouping — not a dependency graph."

GRAPH_EMPTY_MESSAGE = "Dependency edges: awaiting Person 1 edge data."
GRAPH_EMPTY_DETAIL = "No dependency relationships are available in canonical v1."


class GuiService:
    """Mock-first GUI use cases. Thread-safe; opens a fresh DB per op."""

    def __init__(self, db_path: str | Path, client: CoreClient | None = None,
                 graph_provider: GraphProvider | None = None,
                 migration_provider: MigrationProvider | None = None) -> None:
        self.db_path = Path(db_path).expanduser()
        self.client = client if client is not None else get_client("mock")
        self.graph_provider = graph_provider if graph_provider is not None else MockGraphProvider()
        self.migration_provider = migration_provider if migration_provider is not None else MockMigrationProvider()
        self._lock = threading.Lock()
        self._jobs: dict[str, dict] = {}
        self._counter = itertools.count(1)

    # -- read-only preview -------------------------------------------------

    def preview(self, target: str) -> dict:
        """Return a read-only scan-plan preview. No DB writes, no scan."""
        cleaned = (target or "").strip()
        if not cleaned:
            raise ValueError("target must be a non-empty string")
        return {
            "target": cleaned,
            "mode": "mock",
            "mock": True,
            "simulated": True,
            "client": "MockCoreClient",
            "stages": [name for name, _ in STAGES],
            "stores_through": "SQLite via insert_scan + insert_findings_for_scan",
            "reads_back_through": "get_scan_doc (canonical source of truth)",
            "note": (
                "Mock/simulated scan. No real detection is performed; "
                "MockCoreClient serves a deterministic canonical fixture "
                "(empty/minimal/multi routing). " + SIMULATED_NOTE
            ),
        }

    # -- scan inputs (typed, real-pipeline entry) -------------------------------

    @staticmethod
    def inputs() -> list[dict]:
        """Input-type registry for the dashboard Select-files section."""
        return input_mod.describe_inputs()

    def stage_upload(self, filename: str, content_b64: str,
                     kind: str = "upload",
                     batch: str | None = None) -> dict:
        """Stage one browser-uploaded file; auto-extracts zips.

        Returns the staged record plus, for zips, an ``extracted`` block
        with the scan-ready directory. Raises ValueError when loud
        (HTTP 400/413 at the edge).
        """
        try:
            record = input_mod.stage_b64(
                filename, content_b64,
                batch=batch.strip() if batch else None, kind=kind or "upload")
        except ValueError:
            raise
        except Exception as exc:  # noqa: BLE001 - surfaced in payload
            raise ValueError(f"could not stage {filename!r}: {exc}")
        if record.get("is_zip"):
            try:
                record["extracted"] = input_mod.extract_zip(
                    record["staged_path"])
            except ValueError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise ValueError(
                    f"could not extract {filename!r}: {exc}")
        return record

    # -- jobs ---------------------------------------------------------------

    def submit(self, target: str) -> dict:
        """Create a simulated scan job. Returns its initial snapshot.

        The snapshot's ``mock`` flag mirrors the configured client: mock
        clients produce mock data, real clients (scan_with_cir) run the
        integrated pipeline. Progress stays staged in both modes.
        """
        cleaned = (target or "").strip()
        if not cleaned:
            raise ValueError("target must be a non-empty string")
        with self._lock:
            job_id = f"gui-job-{next(self._counter):04d}"
            self._jobs[job_id] = {
                "job_id": job_id,
                "target": cleaned,
                "status": "queued",
                "progress": 0.0,
                "polls": 0,
                "scan_id": None,
                "error": None,
                "real": callable(getattr(self.client, "scan_with_cir", None)),
            }
            return self._snapshot_locked(self._jobs[job_id])

    def submit_typed(self, input_type: str,
                     payload: dict | None = None) -> dict:
        """Create a real-pipeline scan job from a typed GUI input.

        Resolves the input type to an explicit scanner allowlist via
        ``ecdat.gui.inputs`` and always runs the integrated P1/P2
        pipeline (never mock, never the configured demo client).
        Raises ValueError for bad input (HTTP 400 at the edge).
        """
        request = input_mod.resolve_typed_input(input_type, payload or {})
        with self._lock:
            job_id = f"gui-job-{next(self._counter):04d}"
            self._jobs[job_id] = {
                "job_id": job_id,
                "target": str(request["target"]),
                "status": "queued",
                "progress": 0.0,
                "polls": 0,
                "scan_id": None,
                "error": None,
                "real": True,
                "input_type": str(input_type).strip().lower(),
                "scan_request": request,
            }
            return self._snapshot_locked(self._jobs[job_id])

    def status(self, job_id: str) -> dict | None:
        """Advance one simulated poll and return the job snapshot."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            if job["status"] in ("completed", "failed"):
                return self._snapshot_locked(job)
            job["polls"] += 1
            if job["polls"] >= POLLS_TO_COMPLETE:
                try:
                    job["scan_id"] = self._finish_locked(job)
                except Exception as exc:  # noqa: BLE001 - surfaced in payload
                    job["status"] = "failed"
                    job["error"] = str(exc)
                else:
                    job["status"] = "completed"
                    job["progress"] = 1.0
            else:
                job["status"] = "scanning"
                job["progress"] = 0.5
            return self._snapshot_locked(job)

    def _finish_locked(self, job: dict) -> str:
        """Run the scan (mock, legacy real, or typed real) and store it.

        Typed jobs (``scan_request`` present, from the Select-files
        section) always run the integrated P1/P2 pipeline with their
        resolved scanner allowlist. Legacy jobs keep the previous
        behavior: mock clients return canonical only, real clients
        expose scan_with_cir. Real failures propagate as job errors
        (never mock).
        """
        from typing import cast

        request = job.get("scan_request")
        if isinstance(request, dict):
            from ecdat.core.client import RealCoreClient

            client = RealCoreClient(
                scanners=request.get("scanners"),
                allow_container=bool(request.get("allow_container", False)),
                allow_cloud=bool(request.get("allow_cloud", False)),
                allow_runtime=bool(request.get("allow_runtime", False)),
                region=request.get("region"),
            )
            pair = cast("tuple[dict, dict]",
                        client.scan_with_cir(str(request["target"])))
            cir, doc = pair[0], pair[1]
            validate(doc)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = db.open_db(self.db_path)
            try:
                try:
                    sstore.insert_scan(conn, doc, cir)
                    fstore.insert_findings_for_scan(conn, doc)
                except sqlite3.IntegrityError:
                    conn.rollback()  # scan_id already stored: reuse it
            finally:
                conn.close()
            return str(doc["scan_id"])
        scan_with_cir = getattr(self.client, "scan_with_cir", None)
        cir: dict | None = None
        if callable(scan_with_cir):
            pair = cast("tuple[dict, dict]", scan_with_cir(Path(job["target"])))
            cir, doc = pair[0], pair[1]
        else:
            doc = self.client.scan(Path(job["target"]))
        validate(doc)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = db.open_db(self.db_path)
        try:
            try:
                sstore.insert_scan(conn, doc, cir)
                fstore.insert_findings_for_scan(conn, doc)
            except sqlite3.IntegrityError:
                conn.rollback()  # scan_id already stored: reuse it
        finally:
            conn.close()
        return str(doc["scan_id"])

    @staticmethod
    def _snapshot_locked(job: dict) -> dict:
        real = bool(job.get("real", False))
        snap: dict = {
            "job_id": job["job_id"],
            "target": job["target"],
            "status": job["status"],
            "progress": job["progress"],
            "mock": not real,
            "simulated": True,
            "simulated_note": REAL_PROGRESS_NOTE if real else SIMULATED_NOTE,
        }
        if job.get("input_type"):
            snap["input_type"] = job["input_type"]
        if job["scan_id"] is not None:
            snap["scan_id"] = job["scan_id"]
        if job["error"] is not None:
            snap["error"] = job["error"]
        return snap

    # -- inventory ------------------------------------------------------------

    def _load_doc(self, scan_id: str) -> dict | None:
        """Validated canonical doc via get_scan_doc(). None if unknown/corrupt."""
        conn = db.open_db(self.db_path)
        try:
            doc = sstore.get_scan_doc(conn, scan_id)
        finally:
            conn.close()
        if doc is None:
            return None
        try:
            validate(doc)
        except Exception:  # noqa: BLE001 - corrupt store row: no payload
            return None
        return doc

    @staticmethod
    def _project_findings(doc: dict) -> list[dict]:
        """Canonical findings projected to the v1 allowlist, in doc order."""
        return [{k: f[k] for k in _FINDING_KEYS if k in f} for f in doc["findings"]]

    @staticmethod
    def _enrich_row(finding: dict) -> dict:
        """GUI-only derived columns from canonical metadata (no new data).

        Surfaces backend-produced fields the table had no column for:
        ``usage_state`` (P1/P2 evidence assessment), ``library``
        (implementation), and ``asset_only`` (dependency-only findings
        with no operation). All come from ``metadata``; absent metadata
        yields honest ``None``/``False`` defaults.
        """
        meta = finding.get("metadata")
        meta = meta if isinstance(meta, dict) else {}
        enriched = dict(finding)
        enriched["usage_state"] = str(meta.get("usage_state") or "Possible") \
            if meta else None
        enriched["library"] = meta.get("library")
        enriched["asset_only"] = bool(meta.get("asset_only", False))
        enriched["cir_asset_id"] = meta.get("cir_asset_id")
        return enriched

    def inventory(
        self,
        scan_id: str,
        severity: str | None = None,
        rule: str | None = None,
    ) -> dict | None:
        """Inventory payload built from get_scan_doc(). None if unknown.

        Optional severity/rule filters power risk drill-down; they only
        narrow the findings list, never add fields.
        """
        doc = self._load_doc(scan_id)
        if doc is None:
            return None
        canonical = [self._enrich_row(f)
                     for f in self._project_findings(doc)]
        total = len(canonical)
        # index = position in the canonical findings list, so inventory
        # rows can open /api/finding deterministically. API metadata,
        # not a CIR field (finding_detail strips it back off).
        indexed = [dict(f, index=i) for i, f in enumerate(canonical)]
        findings = indexed
        if severity is not None:
            findings = [f for f in findings if str(f["severity"]) == severity]
        if rule is not None:
            findings = [f for f in findings if str(f["rule_id"]) == rule]
        counts: dict[str, int] = {}
        for f in findings:
            sev = str(f["severity"])
            counts[sev] = counts.get(sev, 0) + 1
        return {
            "scan_id": doc["scan_id"],
            "target": doc["target"],
            "started_at": doc["started_at"],
            "finished_at": doc["finished_at"],
            "tool_versions": dict(doc["tool_versions"]),
            "files_scanned": doc["stats"]["files_scanned"],
            "finding_count": len(findings),
            "total_findings": total,
            "filters": {"severity": severity, "rule": rule},
            "severity_counts": dict(sorted(counts.items())),
            "findings": findings,
            "mock": self._load_cir(scan_id) is None,
            "source": "get_scan_doc (canonical source of truth)",
        }

    # -- finding detail ---------------------------------------------------------

    def finding_detail(self, scan_id: str, index: int) -> dict | None:
        """Single-finding detail from the canonical doc. None if unknown.

        Index is the finding's position in the canonical findings list
        (deterministic). Only v1 fields are surfaced; provenance,
        redaction state, and evidence availability are honest static
        labels derived from what v1 does (and does not) define.
        """
        if not isinstance(index, int) or index < 0:
            return None
        doc = self._load_doc(scan_id)
        if doc is None:
            return None
        findings = self._project_findings(doc)
        if index >= len(findings):
            return None
        finding = findings[index]
        evidence_available = {
            "snippet": "snippet" in finding,
            "confidence": "confidence" in finding,
            "metadata": "metadata" in finding,
        }
        real = self._load_cir(scan_id) is not None
        usage_state = "Possible"
        library: str | None = None
        asset_only = False
        cir_asset_id: str | None = None
        if isinstance(finding.get("metadata"), dict):
            usage_state = str(
                finding["metadata"].get("usage_state") or "Possible")
            lib = finding["metadata"].get("library")
            library = str(lib) if lib is not None else None
            asset_only = bool(finding["metadata"].get("asset_only", False))
            cid = finding["metadata"].get("cir_asset_id")
            cir_asset_id = str(cid) if cid else None
        related_operations: list[dict] = []
        if real and cir_asset_id:
            cir_doc = self._load_cir(scan_id) or {}
            for op in cir_doc.get("operations", []) or []:
                if isinstance(op, dict) and str(op.get("asset_id")) == cir_asset_id:
                    related_operations.append({
                        "operation_id": str(op.get("operation_id")),
                        "operation_type": str(op.get("operation_type")),
                        "confidence": op.get("confidence"),
                    })
            related_operations.sort(key=lambda o: o["operation_id"])
        return {
            "scan_id": doc["scan_id"],
            "target": doc["target"],
            "index": index,
            "finding_count": len(findings),
            "finding": finding,
            "usage_state": usage_state,
            "library": library,
            "asset_only": asset_only,
            "cir_asset_id": cir_asset_id,
            "related_operations": related_operations,
            "evidence_available": evidence_available,
            "missing_evidence": sorted(
                k for k, v in evidence_available.items() if not v
            ),
            "metadata_keys": sorted(finding["metadata"].keys())
            if isinstance(finding.get("metadata"), dict)
            else [],
            "redaction": {
                "applied": False,
                "reason": REAL_REDACTION_REASON if real else REDACTION_REASON,
                "capability": REAL_REDACTION_CAPABILITY
                if real else REDACTION_CAPABILITY,
            },
            "provenance": {
                "status": f"{usage_state} (real)"
                if real else PROVENANCE_STATUS,
                "note": REAL_PROVENANCE_NOTE if real else PROVENANCE_NOTE,
            },
            "scan_provenance": {
                "started_at": doc["started_at"],
                "finished_at": doc["finished_at"],
                "label": SCAN_PROVENANCE_LABEL,
            },
            "mock": not real,
            "source": "get_scan_doc (canonical source of truth)",
        }

    # -- risk dashboard -----------------------------------------------------------

    def _load_cir(self, scan_id: str) -> dict | None:
        """Stored enriched CIR sidecar, or None (mock/legacy/unknown scan)."""
        conn = db.open_db(self.db_path)
        try:
            return sstore.get_scan_cir(conn, scan_id)
        finally:
            conn.close()

    def risk_summary(self, scan_id: str) -> dict | None:
        """Risk dashboard payload (mock or real). None if unknown.

        Mock scans reuse build_report() (Task 6 risk_from_findings) with
        mock/placeholder labels, unchanged. Real scans (CIR sidecar
        present) project P1 wire risks — no mock scoring runs on real
        data, and no new scoring is invented here.
        """
        doc = self._load_doc(scan_id)
        if doc is None:
            return None
        cir = self._load_cir(scan_id)
        rep = build_report(doc)
        severity_counts = {sev: rep["by_severity"].get(sev, 0) for sev in SEVERITY_ORDER}
        if cir is not None:
            from ecdat.adapters import risk_view as _risk_view

            posture = _risk_view.summarize_wire_risks(
                cir.get("risks", []) or [], rep["finding_count"])
            return {
                "scan_id": doc["scan_id"],
                "target": doc["target"],
                "score": posture["score"],
                "level": posture["level"],
                "breakdown": dict(sorted(rep["risk"]["breakdown"].items())),
                "finding_count": posture["finding_count"],
                "severity_counts": severity_counts,
                "by_rule": rep["by_rule"],
                "model": posture["model"],
                "mock": False,
                "source": "p1-risk over stored CIR (wire risks, score 0..10)",
            }
        return {
            "scan_id": doc["scan_id"],
            "target": doc["target"],
            "score": rep["risk"]["score"],
            "level": rep["risk"]["level"],
            "breakdown": dict(sorted(rep["risk"]["breakdown"].items())),
            "finding_count": rep["finding_count"],
            "severity_counts": severity_counts,
            "by_rule": rep["by_rule"],
            "model": RISK_MODEL_NOTE,
            "mock": True,
            "source": "build_report over get_scan_doc (Task 6 mock scoring)",
        }

    # -- asset inventory + finding groupings ------------------------------------------
    #
    # Honest Task 11 scope: canonical v1 contains no nodes, edges,
    # relationships, operations, assets, or dependency data, so no
    # dependency graph is drawn. This method only re-presents existing
    # derivations: the flat CBOM component list (one entry per finding)
    # and co-occurrence groupings of findings by file/rule. Groupings
    # must never be called dependencies and no edges are inferred.

    def assets(self, scan_id: str) -> dict | None:
        """Flat asset inventory + groupings. None if unknown.

        Assets reuse the single CBOM component derivation
        (cbom.to_cbom_json) — no second crypto-asset model. Groupings
        reuse build_report() counts enriched with file lists.
        """
        doc = self._load_doc(scan_id)
        if doc is None:
            return None
        # Single-model reuse: parse the CBOM renderer's own output so the
        # GUI can never drift into a second asset derivation.
        bom = json.loads(cbom_mod.to_cbom_json(doc))
        canonical = self._project_findings(doc)
        file_map: dict[str, list[dict]] = {}
        for i, f in enumerate(canonical):
            file_map.setdefault(str(f["file"]), []).append(
                {
                    "index": i,
                    "rule_id": str(f["rule_id"]),
                    "severity": str(f["severity"]),
                    "title": str(f["title"]),
                    "line": f["line"],
                }
            )
        by_file = [
            {"file": name, "count": len(rows), "findings": rows}
            for name, rows in sorted(
                file_map.items(), key=lambda kv: (-len(kv[1]), kv[0])
            )
        ]
        rep = build_report(doc)
        files_for_rule: dict[str, set[str]] = {}
        for f in canonical:
            files_for_rule.setdefault(str(f["rule_id"]), set()).add(str(f["file"]))
        by_rule = [
            {**row, "files": sorted(files_for_rule[row["rule_id"]])}
            for row in rep["by_rule"]
        ]
        return {
            "scan_id": doc["scan_id"],
            "target": doc["target"],
            "asset_count": len(bom["components"]),
            "assets": bom["components"],
            "asset_label": ASSET_LABEL,
            "groupings": {
                "by_file": by_file,
                "by_rule": by_rule,
                "label": GROUPING_LABEL,
            },
            "graph": {
                "available": False,
                "message": GRAPH_EMPTY_MESSAGE,
                "detail": GRAPH_EMPTY_DETAIL,
            },
            "mock": self._load_cir(scan_id) is None,
            "source": "CBOM derivation + build_report over get_scan_doc",
        }

    # -- knowledge graph ------------------------------------------------------------
    #
    # Scan-independent mock dataset (see ecdat.gui.graph): canonical v1
    # carries no nodes/edges, so the graph cannot be derived from a
    # scan. Person 1 CIR output replaces the provider, not the UI.

    def graph(self) -> dict:
        """Frontend-ready knowledge graph from the configured provider."""
        return self.graph_provider.get_graph()

    def graph_for_scan(self, scan_id: str) -> dict | None:
        """Frontend-ready graph from a stored real CIR. None if unavailable.

        Adapts the CIR wire graph through the P3-owned vocabulary
        adapter into the frozen frontend envelope (layout + validation
        via to_frontend_graph, same as the mock provider). Mock/legacy
        scans (no CIR sidecar) return None — callers fall back to the
        scan-independent mock dataset.
        """
        from ecdat.adapters import graph_adapter as _graph_adapter
        from ecdat.gui.graph import to_frontend_graph

        cir = self._load_cir(scan_id)
        if cir is None:
            return None
        raw, _folded = _graph_adapter.adapt_cir_graph(
            cir, cir.get("risks", []) or [])
        graph = to_frontend_graph(raw)
        graph.update({
            "mock": False,
            "dataset": "cir-scan",
            "note": ("Real scan topology from the stored CIR wire graph "
                     "(file nodes folded into operation metadata)."),
            "source": "stored CIR over P2 discovery",
        })
        return graph

    # -- migration planner ------------------------------------------------------------
    #
    # Mock/placeholder recombination (see ecdat.gui.migration): Task 6
    # recommendations + affected files + mock-graph rule links. Unknown
    # scans return None, following existing service conventions.

    def migration_plan(self, scan_id: str) -> dict | None:
        """Frontend-ready migration plan (mock or real). None if unknown.

        Mock scans use the severity-triage placeholder provider,
        unchanged. Real scans (CIR sidecar present) map P1 internal
        recommendation records into the same envelope.
        """
        doc = self._load_doc(scan_id)
        if doc is None:
            return None
        cir = self._load_cir(scan_id)
        if cir is not None:
            from ecdat.adapters import migration_adapter as _migration_adapter

            return _migration_adapter.to_real_plan(
                doc["scan_id"], doc["target"], cir)
        return self.migration_provider.get_plan(
            doc["scan_id"], doc["target"], self._project_findings(doc))

    # -- reports ------------------------------------------------------------------
    #
    # Reports render the stored canonical scan through the existing
    # renderers (reports.html/pdf, exports csv/sarif, canonical JSON).
    # No new report logic lives here: this layer only selects the
    # renderer and wraps bytes for download. Unknown scans return
    # None; unknown formats raise ValueError (HTTP 400 at the edge).

    REPORT_FORMATS: tuple[str, ...] = ("html", "pdf", "csv", "json", "sarif")

    _REPORT_TYPES: dict[str, str] = {
        "html": "text/html; charset=utf-8",
        "pdf": "application/pdf",
        "csv": "text/csv; charset=utf-8",
        "json": "application/json",
        "sarif": "application/json",
    }

    _REPORT_EXTS: dict[str, str] = {
        "html": "html",
        "pdf": "pdf",
        "csv": "csv",
        "json": "json",
        "sarif": "sarif.json",
    }

    def report_summary(self, scan_id: str) -> dict | None:
        """Report metadata for a stored scan (mock or real). None if unknown.

        Risk scores mirror risk_summary(): mock scans carry mock
        scoring labels, real scans carry the stored P1 posture.
        """
        doc = self._load_doc(scan_id)
        if doc is None:
            return None
        rep = build_report(doc)
        cir = self._load_cir(scan_id)
        if cir is not None:
            from ecdat.adapters import risk_view as _risk_view

            posture = _risk_view.summarize_wire_risks(
                cir.get("risks", []) or [], rep["finding_count"])
            return {
                "scan_id": doc["scan_id"],
                "target": doc["target"],
                "finding_count": rep["finding_count"],
                "risk": {"score": posture["score"],
                         "level": posture["level"]},
                "formats": list(self.REPORT_FORMATS),
                "model": posture["model"],
                "mock": False,
                "source": "p1-risk over stored CIR",
            }
        return {
            "scan_id": doc["scan_id"],
            "target": doc["target"],
            "finding_count": rep["finding_count"],
            "risk": {"score": rep["risk"]["score"],
                     "level": rep["risk"]["level"]},
            "formats": list(self.REPORT_FORMATS),
            "model": RISK_MODEL_NOTE,
            "mock": True,
            "source": "existing report/export renderers over get_scan_doc",
        }

    def scan_summary(self, scan_id: str) -> dict | None:
        """Lightweight scan-intelligence summary (new GUI section data).

        Maps every backend output family to one cheap payload without
        re-running analysis: canonical counts (findings, files), CIR
        counts (assets, operations, graph nodes/edges, risks,
        recommendations), risk posture (P1 wire or mock), and tool
        versions. None if unknown. Powers the Select-files result strip
        so huge scans render counts before the full inventory loads.
        """
        doc = self._load_doc(scan_id)
        if doc is None:
            return None
        rep = build_report(doc)
        cir = self._load_cir(scan_id)
        graph = cir.get("graph", {}) if isinstance(cir, dict) else {}
        summary: dict = {
            "scan_id": doc["scan_id"],
            "target": doc["target"],
            "started_at": doc["started_at"],
            "finished_at": doc["finished_at"],
            "finding_count": rep["finding_count"],
            "files_scanned": doc["stats"]["files_scanned"],
            "by_severity": dict(sorted(rep["by_severity"].items())),
            "tool_versions": dict(doc["tool_versions"]),
            "mock": cir is None,
        }
        if isinstance(cir, dict):
            from ecdat.adapters import risk_view as _risk_view

            posture = _risk_view.summarize_wire_risks(
                cir.get("risks", []) or [], rep["finding_count"])
            summary.update({
                "assets": len(cir.get("assets", []) or []),
                "operations": len(cir.get("operations", []) or []),
                "graph_nodes": len(graph.get("nodes", []) or []),
                "graph_edges": len(graph.get("edges", []) or []),
                "risks": len(cir.get("risks", []) or []),
                "recommendations": len(cir.get("recommendations", []) or []),
                "risk": {"score": posture["score"],
                         "level": posture["level"]},
                "risk_model": posture["model"],
                "source": "stored CIR sidecar + canonical v1",
            })
        else:
            summary.update({
                "assets": None,
                "operations": None,
                "graph_nodes": None,
                "graph_edges": None,
                "risks": None,
                "recommendations": None,
                "risk": {"score": rep["risk"]["score"],
                         "level": rep["risk"]["level"]},
                "risk_model": RISK_MODEL_NOTE,
                "source": "canonical v1 only (mock/legacy scan)",
            })
        return summary

    def report_artifact(self, scan_id: str,
                        format: str) -> tuple[str, str, bytes] | None:
        """(content_type, filename, body) for one report format.

        None if the scan is unknown. Raises ValueError for an
        unknown format. Filenames are sanitized; bodies are generated
        in memory from the stored scan — never read from disk.
        """
        if format not in self.REPORT_FORMATS:
            raise ValueError(f"unknown report format: {format!r}")
        doc = self._load_doc(scan_id)
        if doc is None:
            return None
        rep = build_report(doc)
        if format == "html":
            body = html_mod.to_html(rep).encode("utf-8")
        elif format == "pdf":
            body = pdf_mod.to_pdf_bytes(rep)
        elif format == "csv":
            body = (csv_mod.to_csv(doc) + "\n").encode("utf-8")
        elif format == "json":
            body = (json.dumps(doc, indent=2, sort_keys=True)
                    + "\n").encode("utf-8")
        else:  # sarif
            body = (sarif_mod.to_sarif(doc) + "\n").encode("utf-8")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", doc["scan_id"])
        filename = f"ecdat-{safe}-report.{self._REPORT_EXTS[format]}"
        return (self._REPORT_TYPES[format], filename, body)
