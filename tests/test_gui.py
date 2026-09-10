"""Tests for Task 9 localhost GUI + Task 10 detail/risk (mock-first, stdlib only).

Covers GuiService (submit/poll/complete/store/inventory), finding
detail, risk dashboard, drill-down filters, the HTTP layer on an
ephemeral localhost port, HTML escaping, CLI parser + gui command
behavior, and regression of existing commands. No browser, Node, or
network beyond 127.0.0.1.
"""

from __future__ import annotations

import argparse
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from ecdat.cli import build_parser
from ecdat.commands import gui_cmd
from ecdat.gui.server import check_host, index_page, make_server
from ecdat.gui.service import GuiService
from ecdat.store import db
from ecdat.store import scans as sstore


def _svc(tmp_path: Path) -> GuiService:
    return GuiService(tmp_path / "gui.db")


def _complete(svc: GuiService, target: str) -> dict:
    job = svc.submit(target)
    seen = [svc.status(job["job_id"]) for _ in range(5)]
    done = [s for s in seen if s is not None and s["status"] == "completed"]
    assert done, f"job never completed: {seen}"
    return done[0]


# --- service: submit / polling / completion ---------------------------------


def test_submit_returns_queued_job(tmp_path):
    snap = _svc(tmp_path).submit("samples/rsa_small.py")
    assert snap["job_id"].startswith("gui-job-")
    assert snap["target"] == "samples/rsa_small.py"
    assert snap["status"] == "queued" and snap["progress"] == 0.0
    assert snap["mock"] is True and snap["simulated"] is True


def test_submit_rejects_empty_target(tmp_path):
    with pytest.raises(ValueError):
        _svc(tmp_path).submit("   ")


def test_preview_is_mock_labeled_and_read_only(tmp_path):
    svc = _svc(tmp_path)
    prev = svc.preview("samples/rsa_small.py")
    assert prev["mock"] is True and prev["simulated"] is True
    assert "mock" in prev["note"].lower()
    assert prev["stages"] == ["queued", "scanning", "completed"]
    assert "MockCoreClient" in prev["note"] or "MockCoreClient" in prev["client"]
    assert sstore.count_scans(db.open_db(tmp_path / "gui.db")) == 0 or True
    # preview must not store anything
    conn = db.open_db(tmp_path / "gui.db")
    try:
        assert sstore.count_scans(conn) == 0
    finally:
        conn.close()
    with pytest.raises(ValueError):
        svc.preview("")


def test_polling_progresses_to_completed(tmp_path):
    svc = _svc(tmp_path)
    job_id = svc.submit("samples/rsa_small.py")["job_id"]
    first = svc.status(job_id)
    assert first is not None and first["status"] == "scanning"
    second = svc.status(job_id)
    assert second is not None and second["status"] == "completed"
    assert second["progress"] == 1.0
    assert second["scan_id"] == "scan-minimal-001"


def test_status_unknown_job_is_none(tmp_path):
    assert _svc(tmp_path).status("gui-job-9999") is None


def test_progress_is_monotonic(tmp_path):
    svc = _svc(tmp_path)
    job_id = svc.submit("samples/app/multi_x.py")["job_id"]
    progresses = [0.0]
    for _ in range(6):
        snap = svc.status(job_id)
        assert snap is not None
        progresses.append(snap["progress"])
    assert all(b >= a for a, b in zip(progresses, progresses[1:]))
    assert progresses[-1] == 1.0


def test_completed_scan_is_stored(tmp_path):
    svc = _svc(tmp_path)
    done = _complete(svc, "samples/rsa_small.py")
    conn = db.open_db(tmp_path / "gui.db")
    try:
        doc = sstore.get_scan_doc(conn, done["scan_id"])
    finally:
        conn.close()
    assert doc is not None and doc["scan_id"] == done["scan_id"]


def test_resubmit_same_fixture_is_idempotent(tmp_path):
    svc = _svc(tmp_path)
    first = _complete(svc, "samples/rsa_small.py")
    second = _complete(svc, "samples/rsa_small.py")
    assert first["scan_id"] == second["scan_id"] == "scan-minimal-001"


# --- fixtures: empty / minimal / multi ----------------------------------------


def test_empty_fixture_inventory(tmp_path):
    svc = _svc(tmp_path)
    done = _complete(svc, "empty_demo.py")
    inv = svc.inventory(done["scan_id"])
    assert inv is not None and inv["finding_count"] == 0
    assert inv["findings"] == [] and inv["severity_counts"] == {}


def test_minimal_fixture_inventory_payload(tmp_path):
    svc = _svc(tmp_path)
    done = _complete(svc, "samples/rsa_small.py")
    inv = svc.inventory(done["scan_id"])
    assert inv is not None
    assert inv["scan_id"] == "scan-minimal-001"
    assert inv["target"] == "samples/rsa_small.py"
    assert inv["finding_count"] == 1
    (finding,) = inv["findings"]
    assert finding["rule_id"] == "RSA-1024"
    assert finding["severity"] == "high"
    assert finding["file"] == "samples/rsa_small.py"
    assert finding["line"] == 12
    assert "Weak RSA" in finding["title"]
    assert finding["confidence"] == 0.95
    assert "rsa.generate_private_key" in finding["snippet"]
    assert inv["severity_counts"] == {"high": 1}
    assert inv["source"].startswith("get_scan_doc")


def test_multi_fixture_inventory(tmp_path):
    svc = _svc(tmp_path)
    target_dir = tmp_path / "multi_proj"
    target_dir.mkdir()
    done = _complete(svc, str(target_dir))
    inv = svc.inventory(done["scan_id"])
    assert inv is not None and inv["finding_count"] == 4
    assert inv["severity_counts"] == {
        "critical": 1,
        "high": 1,
        "low": 1,
        "medium": 1,
    }
    assert {f["rule_id"] for f in inv["findings"]} == {
        "RSA-1024",
        "MD5-USAGE",
        "AES-ECB",
        "TLS-1.0",
    }


def test_inventory_unknown_scan_is_none(tmp_path):
    assert _svc(tmp_path).inventory("bogus-id") is None


# --- HTML ----------------------------------------------------------------------


def test_index_page_escapes_prefill():
    out = index_page('"><script>alert(1)</script>')
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_index_page_has_no_cdn_or_framework():
    out = index_page().lower()
    assert "cdn" not in out
    assert "http://" not in out and "https://" not in out
    assert "react" not in out and "vue" not in out and "angular" not in out
    for section in ("Select target", "Scan-plan preview", "Live scan monitor",
                    "Crypto inventory", "textContent", "MOCK / SIMULATED"):
        assert section in index_page()


def test_dynamic_rendering_avoids_innerhtml():
    out = index_page()
    assert "textContent" in out
    assert "innerHTML" not in out


# --- HTTP on ephemeral localhost port -------------------------------------------


class _Live:
    def __init__(self, tmp_path: Path):
        self.server = make_server(tmp_path / "gui.db", host="127.0.0.1", port=0)
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}
        )
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


def _get(base: str, path: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(base + path, timeout=5) as res:
            return res.status, res.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _post(base: str, path: str, obj: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        base + path,
        data=json.dumps(obj).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return res.status, json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8") or "{}")


def test_server_binds_loopback_with_ephemeral_port(tmp_path):
    with _Live(tmp_path) as live:
        host, port = live.server.server_address[0], live.server.server_address[1]
        assert host == "127.0.0.1"
        assert port != 0
        code, body = _get(live.base, "/")
        assert code == 200 and "ECDAT Local GUI" in body


def test_http_scan_flow_end_to_end(tmp_path):
    with _Live(tmp_path) as live:
        code, prev = _get(live.base, "/api/preview?target=" + urllib.parse.quote("x.py"))
        assert code == 200 and json.loads(prev)["mock"] is True
        code, job = _post(live.base, "/api/scans", {"target": "x.py"})
        assert code == 200 and job["status"] == "queued"
        snap: dict = {}
        for _ in range(5):
            code, raw = _get(live.base, "/api/jobs?id=" + job["job_id"])
            assert code == 200
            snap = json.loads(raw)
            if snap["status"] == "completed":
                break
        assert snap["status"] == "completed"
        assert snap["scan_id"]
        code, raw = _get(live.base, "/api/inventory?scan_id=" + snap["scan_id"])
        assert code == 200
        inv = json.loads(raw)
        assert inv["scan_id"] == snap["scan_id"] and inv["finding_count"] >= 0


def test_http_unknown_job_and_scan_404(tmp_path):
    with _Live(tmp_path) as live:
        code, _ = _get(live.base, "/api/jobs?id=nope")
        assert code == 404
        code, _ = _get(live.base, "/api/inventory?scan_id=nope")
        assert code == 404
        code, _ = _post(live.base, "/api/scans", {"target": "  "})
        assert code == 400


# --- CLI parser + command behavior ----------------------------------------------


def test_parser_gui_defaults():
    args = build_parser().parse_args(["gui"])
    assert args.func.__module__ == "ecdat.commands.gui_cmd"
    assert args.host == "127.0.0.1" and args.port == 8734


def test_gui_cmd_refuses_non_loopback(tmp_path, capsys):
    args = argparse.Namespace(
        db=str(tmp_path / "gui.db"), host="0.0.0.0", port=8734
    )
    assert gui_cmd.run(args) == 1
    _, err = capsys.readouterr()
    assert "127.0.0.1" in err


def test_check_host_allows_loopback_only():
    for ok in ("127.0.0.1", "localhost", "::1"):
        assert check_host(ok) == ok
    with pytest.raises(ValueError):
        check_host("0.0.0.0")


def test_existing_commands_still_dispatch():
    parser = build_parser()
    assert parser.parse_args(["scan", "a.py"]).func.__module__ == "ecdat.commands.scan_cmd"
    assert parser.parse_args(["report", "x"]).func.__module__ == "ecdat.commands.report_cmd"
    assert parser.parse_args(["export", "x"]).func.__module__ == "ecdat.commands.export_cmd"
    assert parser.parse_args(["gui", "--port", "0"]).port == 0


# --- Task 10: risk dashboard ----------------------------------------------------


def _risk(tmp_path, target="samples/rsa_small.py"):
    svc = _svc(tmp_path)
    done = _complete(svc, target)
    risk = svc.risk_summary(done["scan_id"])
    assert risk is not None
    return svc, risk


def test_risk_summary_minimal_matches_task6(tmp_path):
    _, risk = _risk(tmp_path)
    assert risk["score"] == 5 and risk["level"] == "medium"
    assert risk["breakdown"] == {"high": 1}
    assert risk["finding_count"] == 1
    assert risk["mock"] is True
    assert "mock" in risk["model"].lower() and "placeholder" in risk["model"].lower()


def test_risk_summary_zero_fills_all_severities(tmp_path):
    _, risk = _risk(tmp_path)
    assert risk["severity_counts"] == {
        "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0,
    }
    _, multi = _risk(tmp_path, "multi_proj_x")
    assert multi["score"] == 19 and multi["level"] == "high"
    assert multi["severity_counts"] == {
        "critical": 1, "high": 1, "medium": 1, "low": 1, "info": 0,
    }


def test_risk_summary_empty_scan(tmp_path):
    svc = _svc(tmp_path)
    done = _complete(svc, "empty_demo.py")
    risk = svc.risk_summary(done["scan_id"])
    assert risk is not None
    assert risk["score"] == 0 and risk["level"] == "none"
    assert risk["by_rule"] == []


def test_risk_summary_unknown_scan_is_none(tmp_path):
    assert _svc(tmp_path).risk_summary("bogus-id") is None


# --- Task 10: finding detail ------------------------------------------------------


def test_finding_detail_minimal_fields(tmp_path):
    svc = _svc(tmp_path)
    done = _complete(svc, "samples/rsa_small.py")
    det = svc.finding_detail(done["scan_id"], 0)
    assert det is not None
    assert det["index"] == 0 and det["finding_count"] == 1
    f = det["finding"]
    assert (f["rule_id"], f["severity"], f["file"], f["line"]) == (
        "RSA-1024", "high", "samples/rsa_small.py", 12)
    assert f["confidence"] == 0.95
    assert "rsa.generate_private_key" in f["snippet"]
    assert det["evidence_available"] == {
        "snippet": True, "confidence": True, "metadata": False}
    assert det["missing_evidence"] == ["metadata"]
    assert det["redaction"]["applied"] is False
    assert "Person 1" in det["redaction"]["capability"]
    assert det["provenance"]["status"] == "ProvidedOnly (mock)"
    assert det["scan_provenance"]["started_at"] < det["scan_provenance"]["finished_at"]
    assert "timeline" in det["scan_provenance"]["label"].lower()


def test_finding_detail_reports_metadata_when_present(tmp_path):
    svc = _svc(tmp_path)
    target_dir = tmp_path / "multi_meta"
    target_dir.mkdir()
    done = _complete(svc, str(target_dir))
    det = svc.finding_detail(done["scan_id"], 1)
    assert det is not None
    assert det["finding"]["rule_id"] == "MD5-USAGE"
    assert det["evidence_available"]["metadata"] is True
    assert det["metadata_keys"] == ["cwe"]
    assert det["missing_evidence"] == []


def test_finding_detail_invents_no_cir_fields(tmp_path):
    svc = _svc(tmp_path)
    done = _complete(svc, "samples/rsa_small.py")
    det = svc.finding_detail(done["scan_id"], 0)
    assert det is not None
    allowed = {"rule_id", "title", "severity", "file", "line",
               "snippet", "confidence", "metadata"}
    assert set(det["finding"].keys()) <= allowed


def test_finding_detail_bad_index_and_scan(tmp_path):
    svc = _svc(tmp_path)
    done = _complete(svc, "samples/rsa_small.py")
    assert svc.finding_detail(done["scan_id"], 1) is None
    assert svc.finding_detail(done["scan_id"], -1) is None
    assert svc.finding_detail("bogus-id", 0) is None


# --- Task 10: drill-down filters -----------------------------------------------------


def test_inventory_severity_filter(tmp_path):
    svc = _svc(tmp_path)
    target_dir = tmp_path / "multi_filt"
    target_dir.mkdir()
    done = _complete(svc, str(target_dir))
    high = svc.inventory(done["scan_id"], severity="high")
    assert high is not None and high["finding_count"] == 1
    assert high["total_findings"] == 4
    assert high["filters"] == {"severity": "high", "rule": None}
    assert [f["index"] for f in high["findings"]] == [0]
    info = svc.inventory(done["scan_id"], severity="info")
    assert info is not None and info["finding_count"] == 0


def test_inventory_rule_filter(tmp_path):
    svc = _svc(tmp_path)
    target_dir = tmp_path / "multi_rule"
    target_dir.mkdir()
    done = _complete(svc, str(target_dir))
    aes = svc.inventory(done["scan_id"], rule="AES-ECB")
    assert aes is not None and aes["finding_count"] == 1
    assert aes["findings"][0]["severity"] == "critical"
    assert aes["findings"][0]["index"] == 2


# --- Task 10: HTTP endpoints --------------------------------------------------------------


def test_http_risk_and_finding_endpoints(tmp_path):
    with _Live(tmp_path) as live:
        _, job = _post(live.base, "/api/scans", {"target": "x.py"})
        scan_id = None
        for _ in range(5):
            code, raw = _get(live.base, "/api/jobs?id=" + job["job_id"])
            snap = json.loads(raw)
            if snap["status"] == "completed":
                scan_id = snap["scan_id"]
                break
        assert scan_id is not None
        code, raw = _get(live.base, "/api/risk?scan_id=" + scan_id)
        assert code == 200
        risk = json.loads(raw)
        assert risk["mock"] is True and "mock" in risk["model"].lower()
        assert set(risk["severity_counts"]) == {
            "critical", "high", "medium", "low", "info"}
        code, raw = _get(live.base, "/api/finding?scan_id=" + scan_id + "&index=0")
        assert code == 200
        det = json.loads(raw)
        assert det["provenance"]["status"] == "ProvidedOnly (mock)"
        assert det["redaction"]["applied"] is False
        code, _ = _get(live.base, "/api/risk?scan_id=nope")
        assert code == 404
        code, _ = _get(live.base, "/api/finding?scan_id=" + scan_id + "&index=99")
        assert code == 404
        code, _ = _get(live.base, "/api/finding?scan_id=" + scan_id + "&index=bogus")
        assert code == 400
        code, raw = _get(
            live.base, "/api/inventory?scan_id=" + scan_id + "&severity=high")
        assert code == 200
        assert json.loads(raw)["filters"] == {"severity": "high", "rule": None}


def test_index_page_has_risk_and_detail_cards():
    out = index_page()
    for section in ("Risk dashboard", "Finding detail", "riskTiles", "detail",
                    "clearFilters", "mock/placeholder"):
        assert section in out
    assert "innerHTML" not in out
