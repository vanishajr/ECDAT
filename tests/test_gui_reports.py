"""Tests for Task 25: GUI Reports card (stdlib + loopback only).

The card reuses existing renderers (reports.html/pdf, exports csv,
canonical JSON, exports sarif) over stored scans — no new report
logic. Tests drive GuiService directly plus a live loopback server
for status codes, content types, and download bytes.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

from ecdat.gui.server import index_page, make_server
from ecdat.gui.service import GuiService


def _svc(tmp_path: Path) -> GuiService:
    return GuiService(tmp_path / "r.db")


def _complete(svc: GuiService, target: str) -> dict:
    job = svc.submit(target)
    seen = [svc.status(job["job_id"]) for _ in range(5)]
    done = [s for s in seen if s is not None and s["status"] == "completed"]
    assert done, f"job never completed: {seen}"
    return done[0]


# --- service -----------------------------------------------------------------------


def test_report_summary_fields(tmp_path):
    svc = _svc(tmp_path)
    done = _complete(svc, "x.py")
    summary = svc.report_summary(done["scan_id"])
    assert summary is not None
    assert summary["scan_id"] == done["scan_id"]
    assert summary["finding_count"] == 1
    assert summary["risk"] == {"score": 5, "level": "medium"}
    assert summary["formats"] == ["html", "pdf", "csv", "json", "sarif"]
    assert summary["mock"] is True
    assert "mock" in summary["model"].lower()


def test_report_summary_unknown_scan(tmp_path):
    assert _svc(tmp_path).report_summary("bogus-id") is None


def test_report_artifact_html_pdf_csv(tmp_path):
    svc = _svc(tmp_path)
    done = _complete(svc, "x.py")
    artifact = svc.report_artifact(done["scan_id"], "html")
    assert artifact is not None
    ctype, name, body = artifact
    assert ctype == "text/html; charset=utf-8"
    assert name == f"ecdat-{done['scan_id']}-report.html"
    assert done["scan_id"].encode() in body
    artifact = svc.report_artifact(done["scan_id"], "pdf")
    assert artifact is not None
    ctype, name, body = artifact
    assert ctype == "application/pdf"
    assert body.startswith(b"%PDF-1.4")
    artifact = svc.report_artifact(done["scan_id"], "csv")
    assert artifact is not None
    ctype, name, body = artifact
    assert ctype == "text/csv; charset=utf-8"
    assert body.decode().splitlines()[0].startswith("scan_id,rule_id")


def test_report_artifact_json_sarif_reuse(tmp_path):
    svc = _svc(tmp_path)
    done = _complete(svc, "x.py")
    artifact = svc.report_artifact(done["scan_id"], "json")
    assert artifact is not None
    ctype, _, body = artifact
    assert ctype == "application/json"
    assert json.loads(body)["scan_id"] == done["scan_id"]
    artifact = svc.report_artifact(done["scan_id"], "sarif")
    assert artifact is not None
    _, name, body = artifact
    assert name.endswith(".sarif.json")
    assert json.loads(body)["version"] == "2.1.0"


def test_report_artifact_unknown_scan_and_format(tmp_path):
    svc = _svc(tmp_path)
    assert svc.report_artifact("bogus-id", "html") is None
    done = _complete(svc, "x.py")
    try:
        svc.report_artifact(done["scan_id"], "docx")
    except ValueError as exc:
        assert "unknown report format" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_report_artifact_deterministic(tmp_path):
    svc = _svc(tmp_path)
    done = _complete(svc, "x.py")
    assert (svc.report_artifact(done["scan_id"], "csv") ==
            svc.report_artifact(done["scan_id"], "csv"))


# --- HTTP -----------------------------------------------------------------------------


class _Live:
    def __init__(self, tmp_path: Path):
        self.server = make_server(tmp_path / "r.db", host="127.0.0.1",
                                  port=0)
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05})
        self.thread.daemon = True

    @property
    def base(self) -> str:
        host, port = self.server.server_address[0], self.server.server_address[1]
        return f"http://{host}:{port}"

    def __enter__(self) -> "_Live":
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()


def _get_bytes(base: str, path: str) -> tuple[int, bytes, str, str]:
    try:
        with urllib.request.urlopen(base + path, timeout=5) as res:
            return (res.status, res.read(),
                    res.headers.get("Content-Type", ""),
                    res.headers.get("Content-Disposition", ""))
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), "", ""


def _post(base: str, path: str, obj: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        base + path, data=json.dumps(obj).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as res:
        return res.status, json.loads(res.read().decode("utf-8"))


def _complete_live(live: "_Live", target: str) -> str:
    _, job = _post(live.base, "/api/scans", {"target": target})
    for _ in range(10):
        _, raw, _, _ = _get_bytes(live.base, "/api/jobs?id=" + job["job_id"])
        snap = json.loads(raw.decode())
        if snap["status"] == "completed":
            return snap["scan_id"]
    raise AssertionError("job never completed")


def test_api_reports_summary_and_404(tmp_path):
    with _Live(tmp_path) as live:
        scan_id = _complete_live(live, "x.py")
        code, raw, _, _ = _get_bytes(
            live.base, "/api/reports?scan_id=" + scan_id)
        assert code == 200
        assert json.loads(raw.decode())["finding_count"] == 1
        code, _, _, _ = _get_bytes(live.base, "/api/reports?scan_id=nope")
        assert code == 404


def test_api_reports_download_all_formats(tmp_path):
    with _Live(tmp_path) as live:
        scan_id = _complete_live(live, "x.py")
        for fmt, ctype, needle in (
                ("html", "text/html", b"scan-minimal-001"),
                ("pdf", "application/pdf", b"%PDF-1.4"),
                ("csv", "text/csv", b"scan_id,rule_id"),
                ("json", "application/json", b"scan-minimal-001"),
                ("sarif", "application/json", b"2.1.0")):
            code, body, got_ctype, disp = _get_bytes(
                live.base,
                f"/api/reports/download?scan_id={scan_id}&format={fmt}")
            assert code == 200, fmt
            assert got_ctype.startswith(ctype), fmt
            assert needle in body, fmt
            assert disp.startswith("attachment;"), fmt


def test_api_reports_download_errors(tmp_path):
    with _Live(tmp_path) as live:
        code, _, _, _ = _get_bytes(
            live.base, "/api/reports/download?scan_id=nope&format=html")
        assert code == 404
        scan_id = _complete_live(live, "x.py")
        code, _, _, _ = _get_bytes(
            live.base,
            f"/api/reports/download?scan_id={scan_id}&format=docx")
        assert code == 400


# --- page hygiene --------------------------------------------------------------------------


def test_page_contains_reports_card():
    out = index_page()
    for section in ("10. Reports", "loadReports", "/api/reports",
                    "/api/reports/download", "Mock reports"):
        assert section in out
    assert "innerHTML" not in out
    lowered = out.lower()
    assert "cdn" not in lowered and "react" not in lowered
