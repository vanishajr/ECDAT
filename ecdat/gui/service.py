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
import sqlite3
import threading
from pathlib import Path

from ecdat.core.client import CoreClient, get_client
from ecdat.core.validate import validate
from ecdat.exports import cbom as cbom_mod
from ecdat.gui.graph import GraphProvider, MockGraphProvider
from ecdat.gui.migration import MigrationProvider, MockMigrationProvider
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

    # -- jobs ---------------------------------------------------------------

    def submit(self, target: str) -> dict:
        """Create a simulated scan job. Returns its initial snapshot."""
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
        """Run the mock scan and store it. Caller holds the lock."""
        doc = self.client.scan(Path(job["target"]))
        validate(doc)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = db.open_db(self.db_path)
        try:
            try:
                sstore.insert_scan(conn, doc)
                fstore.insert_findings_for_scan(conn, doc)
            except sqlite3.IntegrityError:
                conn.rollback()  # fixture scan_id already stored: reuse it
        finally:
            conn.close()
        return str(doc["scan_id"])

    @staticmethod
    def _snapshot_locked(job: dict) -> dict:
        snap: dict = {
            "job_id": job["job_id"],
            "target": job["target"],
            "status": job["status"],
            "progress": job["progress"],
            "mock": True,
            "simulated": True,
            "simulated_note": SIMULATED_NOTE,
        }
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
        canonical = self._project_findings(doc)
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
            "mock": True,
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
        return {
            "scan_id": doc["scan_id"],
            "target": doc["target"],
            "index": index,
            "finding_count": len(findings),
            "finding": finding,
            "evidence_available": evidence_available,
            "missing_evidence": sorted(
                k for k, v in evidence_available.items() if not v
            ),
            "metadata_keys": sorted(finding["metadata"].keys())
            if isinstance(finding.get("metadata"), dict)
            else [],
            "redaction": {
                "applied": False,
                "reason": REDACTION_REASON,
                "capability": REDACTION_CAPABILITY,
            },
            "provenance": {
                "status": PROVENANCE_STATUS,
                "note": PROVENANCE_NOTE,
            },
            "scan_provenance": {
                "started_at": doc["started_at"],
                "finished_at": doc["finished_at"],
                "label": SCAN_PROVENANCE_LABEL,
            },
            "mock": True,
            "source": "get_scan_doc (canonical source of truth)",
        }

    # -- risk dashboard -----------------------------------------------------------

    def risk_summary(self, scan_id: str) -> dict | None:
        """Mock risk dashboard payload. None if unknown.

        Reuses build_report() (hence Task 6 risk_from_findings) without
        duplicating scoring logic; this method only zero-fills severity
        levels for display and attaches mock/placeholder labels.
        """
        doc = self._load_doc(scan_id)
        if doc is None:
            return None
        rep = build_report(doc)
        severity_counts = {sev: rep["by_severity"].get(sev, 0) for sev in SEVERITY_ORDER}
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
            "mock": True,
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

    # -- migration planner ------------------------------------------------------------
    #
    # Mock/placeholder recombination (see ecdat.gui.migration): Task 6
    # recommendations + affected files + mock-graph rule links. Unknown
    # scans return None, following existing service conventions.

    def migration_plan(self, scan_id: str) -> dict | None:
        """Frontend-ready migration plan. None if unknown."""
        doc = self._load_doc(scan_id)
        if doc is None:
            return None
        return self.migration_provider.get_plan(
            doc["scan_id"], doc["target"], self._project_findings(doc))
