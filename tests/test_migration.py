"""Tests for the Migration Planner (mock/placeholder, stdlib only).

Covers the provider contract, item fields, recommendation/count and
affected-file correctness, deterministic severity-triage ordering,
empty/unknown scans, API status codes, the forbidden-key scan (no
fabricated PQC/timeline/effort data), the explicit placeholder
status, page hygiene, and full-suite regression. No browser, Node, or
network beyond 127.0.0.1.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from ecdat.commands.recommend_cmd import recommend_for_findings
from ecdat.core.validate import load_json
from ecdat.Backup_GUI.migration import (
    STATUS_PLACEHOLDER,
    MigrationProvider,
    MockMigrationProvider,
    build_mock_items,
    to_frontend_plan,
)
from ecdat.Backup_GUI.server import index_page, make_server
from ecdat.Backup_GUI.service import GuiService

FORBIDDEN_KEYS = {
    "timeline",
    "effort",
    "priority",
    "confidence",
    "phase",
    "pqc_target",
    "migration_sequence",
    "migration_state",
    "sequencing",
}

CANON = Path(__file__).parent / "fixtures" / "canonical"


def _svc(tmp_path: Path) -> GuiService:
    return GuiService(tmp_path / "m.db")


def _complete(svc: GuiService, target: str) -> dict:
    job = svc.submit(target)
    seen = [svc.status(job["job_id"]) for _ in range(5)]
    done = [s for s in seen if s is not None and s["status"] == "completed"]
    assert done, f"job never completed: {seen}"
    return done[0]


def _all_keys(obj, acc):
    if isinstance(obj, dict):
        for k, v in obj.items():
            acc.add(k)
            _all_keys(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            _all_keys(v, acc)
    return acc


def _doc(fixture: str) -> dict:
    return load_json(CANON / f"{fixture}.json")


# --- provider contract -----------------------------------------------------------


def test_provider_contract_and_name():
    provider = MockMigrationProvider()
    assert isinstance(provider, MigrationProvider)
    assert provider.name == "mock-migration"


def test_item_fields_match_recommendation_source():
    doc = _doc("multi")
    items = build_mock_items(doc["findings"])
    expected = {r["rule_id"]: r for r in recommend_for_findings(doc["findings"])}
    assert {i["rule_id"] for i in items} == set(expected)
    for item in items:
        rec = expected[item["rule_id"]]
        assert item["severity"] == rec["severity"]
        assert item["title"] == rec["title"]
        assert item["action"] == rec["action"]
        assert item["refs"] == rec["refs"]
        assert item["count"] == rec["count"]
        assert item["status"] == STATUS_PLACEHOLDER
        assert set(item) == {"rule_id", "severity", "title", "action", "refs",
                             "count", "affected_files", "graph_node_ids", "status"}


def test_count_and_affected_files_correctness(tmp_path):
    svc = _svc(tmp_path)
    target_dir = tmp_path / "multi_mig"
    target_dir.mkdir()
    done = _complete(svc, str(target_dir))
    plan = svc.migration_plan(done["scan_id"])
    assert plan is not None
    by_rule = {i["rule_id"]: i for i in plan["items"]}
    assert by_rule["RSA-1024"]["count"] == 1
    assert by_rule["RSA-1024"]["affected_files"] == ["samples/app/auth.py"]
    assert by_rule["AES-ECB"]["affected_files"] == ["samples/app/crypto.py"]


def test_ordering_is_severity_triage_not_sequence(tmp_path):
    svc = _svc(tmp_path)
    target_dir = tmp_path / "multi_tri"
    target_dir.mkdir()
    done = _complete(svc, str(target_dir))
    plan = svc.migration_plan(done["scan_id"])
    assert plan is not None
    assert [i["rule_id"] for i in plan["items"]] == [
        "AES-ECB", "RSA-1024", "MD5-USAGE", "TLS-1.0"]
    assert "NOT a migration sequence" in plan["triage_label"]
    assert "sequence" not in plan["triage_label"].lower().replace(
        "not a migration sequence", "")


def test_deterministic_plan():
    doc = _doc("multi")
    first = to_frontend_plan(doc["scan_id"], doc["target"], doc["findings"])
    assert to_frontend_plan(doc["scan_id"], doc["target"], doc["findings"]) == first
    assert first["item_count"] == 4 and first["mock"] is True


def test_empty_scan_has_no_items(tmp_path):
    svc = _svc(tmp_path)
    done = _complete(svc, "empty_demo.py")
    plan = svc.migration_plan(done["scan_id"])
    assert plan is not None
    assert plan["items"] == [] and plan["item_count"] == 0


def test_unknown_scan_is_none(tmp_path):
    assert _svc(tmp_path).migration_plan("bogus-id") is None


def test_forbidden_keys_absent(tmp_path):
    svc = _svc(tmp_path)
    target_dir = tmp_path / "multi_forbid"
    target_dir.mkdir()
    done = _complete(svc, str(target_dir))
    plan = svc.migration_plan(done["scan_id"])
    assert plan is not None
    assert _all_keys(plan, set()).isdisjoint(FORBIDDEN_KEYS)


def test_no_severity_as_priority_claim(tmp_path):
    svc = _svc(tmp_path)
    done = _complete(svc, "samples/rsa_small.py")
    plan = svc.migration_plan(done["scan_id"])
    assert plan is not None
    text = json.dumps(plan).lower()
    assert "migration priority" not in text
    assert "priority" not in _all_keys(plan, set())


# --- HTTP ---------------------------------------------------------------------------


class _Live:
    def __init__(self, tmp_path: Path):
        self.server = make_server(tmp_path / "m.db", host="127.0.0.1", port=0)
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


def _get(base: str, path: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(base + path, timeout=5) as res:
            return res.status, res.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _post(base: str, path: str, obj: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        base + path, data=json.dumps(obj).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return res.status, json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8") or "{}")


def test_api_migration_codes(tmp_path):
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
        code, raw = _get(live.base, "/api/migration?scan_id=" + scan_id)
        assert code == 200
        plan = json.loads(raw)
        assert plan["item_count"] == len(plan["items"]) >= 1
        assert all(i["status"] == STATUS_PLACEHOLDER for i in plan["items"])
        assert _all_keys(plan, set()).isdisjoint(FORBIDDEN_KEYS)
        code, _ = _get(live.base, "/api/migration?scan_id=nope")
        assert code == 404


# --- page hygiene ----------------------------------------------------------------------


def test_page_contains_planner_and_missing_labels():
    out = index_page()
    for section in ("Migration Planner", "MOCK / PLACEHOLDER", "loadMigration",
                    "/api/migration", "Not included yet", "Person 1 migration"):
        assert section in out
    assert "innerHTML" not in out
    lowered = out.lower()
    assert "cdn" not in lowered and "react" not in lowered
