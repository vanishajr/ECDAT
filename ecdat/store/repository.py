"""Unified scan persistence (Phase 11 platform layer).

``ScanRepository`` is the ONE durable scan model shared by CLI, GUI,
and CI: the validated canonical document, the enriched CIR sidecar,
the scan plan, and run diagnostics (tool versions, cache metrics,
limitations) are stored together under one scan ID and reopened as a
unit. Every export/report/CI gate derives from this stored truth;
nothing recomputes with separate logic.

SQLite via the stdlib only. Schema (``store.db`` v3):

- scans / findings: canonical doc + CIR sidecar + finding rows
  (``scans.py`` / ``findings.py`` own the row shapes);
- scan_meta: plan_json + diagnostics_json for history/reopen.

Callers must pass validated canonical docs (see ``ecdat.core.validate``).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore

__all__ = ["ScanRepository", "save_meta"]


def save_meta(conn: sqlite3.Connection, scan_id: str,
              plan: dict | None = None,
              diagnostics: dict | None = None) -> None:
    """Upsert scan plan + diagnostics for one stored scan (never raises)."""
    try:
        conn.execute(
            "INSERT OR REPLACE INTO scan_meta"
            " (scan_id, plan_json, diagnostics_json)"
            " VALUES (?, ?, ?)",
            (str(scan_id), _to_json(plan), _to_json(diagnostics)),
        )
        conn.commit()
    except sqlite3.Error:
        pass


def _to_json(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return None


def _from_json(raw: Any) -> Any:
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


class ScanRepository:
    """Durable scans shared by CLI/GUI/CI (one DB file, one model)."""

    def __init__(self, path: str | Path | None = None) -> None:
        if path is not None:
            try:
                Path(path).expanduser().parent.mkdir(
                    parents=True, exist_ok=True)
            except OSError:
                pass
        self._conn = db.open_db(
            Path(path).expanduser() if path is not None else None)

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> "ScanRepository":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- writes --------------------------------------------------------

    def save_scan(self, doc: dict, cir: dict | None = None,
                  plan: dict | None = None,
                  diagnostics: dict | None = None,
                  replace: bool = False) -> str:
        """Persist one validated scan + sidecars. Returns the scan id.

        ``replace=True`` overwrites a previous row with the same ID
        (GUI re-scans); the default raises ``sqlite3.IntegrityError``
        so CLI double-stores stay loud errors.
        """
        scan_id = str(doc["scan_id"])
        if replace:
            self._conn.execute(
                "DELETE FROM scans WHERE id = ?", (scan_id,))
            self._conn.commit()
        sstore.insert_scan(self._conn, doc, cir)
        fstore.insert_findings_for_scan(self._conn, doc)
        self._conn.execute(
            "INSERT OR REPLACE INTO scan_meta"
            " (scan_id, plan_json, diagnostics_json)"
            " VALUES (?, ?, ?)",
            (scan_id, _to_json(plan), _to_json(diagnostics)),
        )
        self._conn.commit()
        return scan_id

    # -- reads ---------------------------------------------------------

    def get_payload(self, scan_id: str) -> dict | None:
        """Full reopen payload: canonical + CIR + plan + diagnostics."""
        doc = sstore.get_scan_doc(self._conn, scan_id)
        if doc is None:
            return None
        row = self._conn.execute(
            "SELECT plan_json, diagnostics_json FROM scan_meta"
            " WHERE scan_id = ?", (scan_id,)).fetchone()
        return {
            "scan_id": scan_id,
            "canonical": doc,
            "cir": sstore.get_scan_cir(self._conn, scan_id),
            "plan": _from_json(row["plan_json"]) if row else None,
            "diagnostics": _from_json(row["diagnostics_json"])
            if row else None,
        }

    def list_scans(self, limit: int = 100) -> list[dict]:
        """Stored scan history (newest first), with meta availability."""
        rows = sstore.list_scans(self._conn, limit=limit)
        out = []
        for row in rows or []:
            scan_id = row.get("id") if isinstance(row, dict) \
                else row["id"]
            meta = self._conn.execute(
                "SELECT plan_json IS NOT NULL AS has_plan,"
                " diagnostics_json IS NOT NULL AS has_diagnostics"
                " FROM scan_meta WHERE scan_id = ?",
                (scan_id,)).fetchone()
            item = dict(row) if not isinstance(row, dict) else dict(row)
            item["has_plan"] = bool(meta["has_plan"]) if meta else False
            item["has_diagnostics"] = bool(meta["has_diagnostics"]) \
                if meta else False
            out.append(item)
        return out

    def count_scans(self) -> int:
        return int(sstore.count_scans(self._conn))
