"""Tests for the GUI Select-files input section (real P1/P2 pipeline).

Covers the input registry, lightweight staging (uploads/zips/caps),
typed resolution per input kind, typed real-pipeline jobs through
GuiService, the scan-summary mapping, and the new HTTP routes. Legacy
mock flows are untouched (see tests/test_gui.py).
"""

from __future__ import annotations

import base64
import json
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

import pytest

from ecdat.gui import inputs as input_mod
from ecdat.gui.server import index_page, make_server
from ecdat.gui.service import GuiService

pytestmark = pytest.mark.skipif(
    pytest.importorskip("pydantic", reason="real pipeline needs pydantic") is None,
    reason="real pipeline needs pydantic",
)


def _svc(tmp_path: Path) -> GuiService:
    return GuiService(tmp_path / "gui-inputs.db")


def _complete_typed(svc: GuiService, itype: str, payload: dict) -> dict:
    job = svc.submit_typed(itype, payload)
    assert job["mock"] is False
    seen = [svc.status(job["job_id"]) for _ in range(5)]
    done = [s for s in seen if s is not None and s["status"] == "completed"]
    assert done, f"typed job never completed: {seen}"
    return done[0]


def _write(tmp_path: Path, name: str, text: str) -> str:
    path = tmp_path / name
    path.write_text(text)
    return str(path)


# --- registry -----------------------------------------------------------------


def test_inputs_registry_covers_all_kinds():
    ids = {d["id"] for d in input_mod.describe_inputs()}
    assert ids == {"local_path", "upload", "binary", "container",
                   "certificate", "cloud", "runtime"}
    for entry in input_mod.describe_inputs():
        assert entry["label"] and entry["scanners"] and entry["hint"]


def test_resolve_unknown_input_type_rejected():
    with pytest.raises(ValueError):
        input_mod.resolve_typed_input("nope", {})


def test_resolve_local_path_requires_existing(tmp_path):
    missing = str(tmp_path / "absent")
    with pytest.raises(ValueError):
        input_mod.resolve_typed_input("local_path", {"path": missing})
    request = input_mod.resolve_typed_input(
        "local_path", {"path": str(tmp_path)})
    assert request["target"] == str(tmp_path)
    assert request["scanners"] is None  # safe default subset


def test_resolve_container_accepts_image_ref_without_path():
    request = input_mod.resolve_typed_input(
        "container", {"image_or_path": "nginx:1.25"})
    assert request["target"] == "nginx:1.25"
    assert "container" in request["scanners"]
    assert request["allow_container"] is True


def test_resolve_cloud_builds_label_and_region():
    request = input_mod.resolve_typed_input(
        "cloud", {"profile": "readonly", "services": "kms,acm",
                  "region": "us-east-1"})
    assert request["target"] == "aws:readonly:services=kms,acm"
    assert request["scanners"] == ["cloud"]
    assert request["region"] == "us-east-1"
    with pytest.raises(ValueError):
        input_mod.resolve_typed_input("cloud", {"services": "  "})


def test_resolve_runtime_validates_endpoint():
    request = input_mod.resolve_typed_input(
        "runtime", {"endpoint": "example.com:443"})
    assert request["target"] == "example.com:443"
    assert request["allow_runtime"] is True
    with pytest.raises(ValueError):
        input_mod.resolve_typed_input("runtime", {"endpoint": "not-a-target"})


def test_resolve_binary_and_certificate_need_existing(tmp_path):
    target = _write(tmp_path, "app.bin", "binary-bytes")
    assert input_mod.resolve_typed_input(
        "binary", {"path": target})["scanners"] == ["binary"]
    assert "certificate" in input_mod.resolve_typed_input(
        "certificate", {"path": target})["scanners"]
    with pytest.raises(ValueError):
        input_mod.resolve_typed_input("binary", {"path": str(tmp_path / "x")})


# --- staging: light and capped --------------------------------------------------


def test_stage_single_file_and_batch_reuse(tmp_path):
    data = base64.b64encode(b"print('hi')").decode()
    first = input_mod.stage_b64("a.py", data,
                                root=tmp_path / "staging")
    assert Path(first["staged_path"]).read_bytes() == b"print('hi')"
    assert first["is_zip"] is False
    second = input_mod.stage_b64("b.py", data,
                                 root=tmp_path / "staging",
                                 batch=first["batch"])
    assert second["batch"] == first["batch"]
    assert second["staged_path"] != first["staged_path"]


def test_stage_rejects_oversize_and_bad_base64(tmp_path):
    with pytest.raises(ValueError):
        input_mod.stage_b64("x.bin", "!!!not-base64!!!",
                            root=tmp_path / "staging")
    big = b"x" * (input_mod.MAX_UPLOAD_BYTES + 1)
    with pytest.raises(ValueError, match="cap"):
        input_mod.stage_bytes("big.bin", big, root=tmp_path / "staging")


def test_zip_extracts_once_with_manifest(tmp_path):
    archive = tmp_path / "pack.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a.py", "import hashlib\n")
        zf.writestr("sub/b.py", "x = 1\n")
    out = input_mod.extract_zip(archive)
    assert out["file_count"] == 2
    assert Path(out["extracted_dir"], "a.py").exists()
    assert Path(out["extracted_dir"], "sub", "b.py").exists()


def test_zip_slip_rejected(tmp_path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../../escape.py", "x = 1\n")
    with pytest.raises(ValueError, match="escapes"):
        input_mod.extract_zip(archive)


# --- service: typed real jobs -----------------------------------------------------


def test_submit_typed_unknown_type_rejected(tmp_path):
    with pytest.raises(ValueError):
        _svc(tmp_path).submit_typed("nope", {})


def test_submit_typed_local_path_runs_real_pipeline(tmp_path):
    target = _write(tmp_path, "crypto.py",
                    "import hashlib\nhashlib.md5(b'x').hexdigest()\n")
    svc = _svc(tmp_path)
    done = _complete_typed(svc, "local_path", {"path": target})
    assert done["input_type"] == "local_path"
    inv = svc.inventory(done["scan_id"])
    assert inv is not None and inv["mock"] is False
    assert inv["finding_count"] >= 1
    row = inv["findings"][0]
    assert "usage_state" in row and "library" in row
    assert "asset_only" in row and "cir_asset_id" in row


def test_submit_typed_upload_batch_dir_runs_real_pipeline(tmp_path):
    batch = tmp_path / "batchdir"
    batch.mkdir()
    (batch / "a.py").write_text("import hashlib\nhashlib.sha1(b'x').hexdigest()\n")
    svc = _svc(tmp_path)
    done = _complete_typed(svc, "upload", {"path": str(batch)})
    assert svc.inventory(done["scan_id"])["finding_count"] >= 1


def test_scan_summary_maps_backend_fields(tmp_path):
    target = _write(tmp_path, "s.py",
                    "import hashlib\nhashlib.md5(b'x').hexdigest()\n")
    svc = _svc(tmp_path)
    done = _complete_typed(svc, "local_path", {"path": target})
    summary = svc.scan_summary(done["scan_id"])
    assert summary is not None
    assert summary["mock"] is False
    for key in ("finding_count", "files_scanned", "assets", "operations",
                "graph_nodes", "graph_edges", "risks", "recommendations",
                "risk", "tool_versions", "target", "scan_id"):
        assert key in summary
    assert summary["risk"]["level"] in (
        "Critical", "High", "Medium", "Low", "Informational",
        "critical", "high", "medium", "low", "info", "none")
    assert summary["scan_id"] == done["scan_id"]
    assert svc.scan_summary("bogus") is None


def test_finding_detail_maps_usage_and_operations(tmp_path):
    target = _write(tmp_path, "d.py",
                    "import hashlib\nhashlib.md5(b'x').hexdigest()\n")
    svc = _svc(tmp_path)
    done = _complete_typed(svc, "local_path", {"path": target})
    inv = svc.inventory(done["scan_id"])
    det = svc.finding_detail(done["scan_id"], 0)
    assert det is not None
    assert det["usage_state"]
    assert "library" in det and "asset_only" in det
    assert "cir_asset_id" in det and "related_operations" in det
    assert det["mock"] is False
    # v1 finding body itself stays closed (existing contract).
    allowed = {"rule_id", "title", "severity", "file", "line",
               "snippet", "confidence", "metadata"}
    assert set(det["finding"].keys()) <= allowed
    assert inv["findings"][0]["usage_state"] == det["usage_state"]


def test_service_stage_upload_extracts_zip(tmp_path):
    svc = _svc(tmp_path)
    archive = tmp_path / "pack.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a.py", "import hashlib\n")
    content = base64.b64encode(archive.read_bytes()).decode()
    record = svc.stage_upload("pack.zip", content, kind="upload")
    assert record["is_zip"] is True
    assert Path(record["extracted"]["extracted_dir"], "a.py").exists()
    done = _complete_typed(
        svc, "upload", {"path": record["extracted"]["extracted_dir"]})
    assert svc.inventory(done["scan_id"]) is not None


# --- HTTP routes ------------------------------------------------------------------


def _post(base: str, path: str, obj: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        base + path, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req) as res:
            return res.status, json.loads(res.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def _get(base: str, path: str) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(base + path) as res:
            return res.status, json.loads(res.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def test_http_inputs_upload_scan_and_summary(tmp_path):
    server = make_server(tmp_path / "http.db", port=0)
    server.gui_service = GuiService(tmp_path / "http.db")
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        code, body = _get(base, "/api/inputs")
        assert code == 200 and len(body["inputs"]) == 7
        target = _write(tmp_path, "h.py",
                        "import hashlib\nhashlib.md5(b'x').hexdigest()\n")
        code, job = _post(base, "/api/scans",
                          {"input_type": "local_path",
                           "payload": {"path": target}})
        assert code == 200 and job["mock"] is False
        final = None
        for _ in range(20):
            code, snap = _get(
                base, "/api/jobs?id=" + urllib.parse.quote(job["job_id"]))
            assert code == 200
            if snap["status"] == "completed":
                final = snap
                break
        assert final is not None, job
        code, summary = _get(
            base, "/api/scan-summary?scan_id=" + urllib.parse.quote(
                final["scan_id"]))
        assert code == 200
        assert summary["finding_count"] >= 1
        assert summary["assets"] is not None
        code, _ = _get(base, "/api/scan-summary?scan_id=bogus")
        assert code == 404
        code, err = _post(base, "/api/scans",
                          {"input_type": "nope", "payload": {}})
        assert code == 400 and "error" in err
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_http_upload_round_trip_and_caps(tmp_path):
    server = make_server(tmp_path / "up.db", port=0)
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        content = base64.b64encode(b"import hashlib\n").decode()
        code, rec = _post(base, "/api/uploads",
                          {"filename": "a.py", "content_b64": content,
                           "kind": "upload"})
        assert code == 200 and Path(rec["staged_path"]).exists()
        code, err = _post(base, "/api/uploads",
                          {"filename": "x.bin", "content_b64": "!!!"})
        assert code == 400 and "error" in err
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_index_page_has_select_files_section():
    page = index_page()
    assert 'id="sec-input"' in page
    assert "Select files" in page
    assert 'id="dropZone"' in page
    assert 'id="filePick"' in page
    assert 'id="inputScanBtn"' in page
    assert 'id="scanSummary"' in page
    assert "/api/inputs" in page and "/api/uploads" in page
    assert "/api/scan-summary" in page
    assert "Scan Profile" in page  # existing card untouched
