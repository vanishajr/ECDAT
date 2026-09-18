"""Tests for the Crypto Knowledge Graph screen (mock dataset, stdlib only).

Covers the data/transform layer (provider envelope, node/edge
validity, deterministic layout, trace paths), the service + HTTP
seam, and frontend hygiene (no framework/CDN/innerHTML). The dataset
is explicitly mock; tests assert honesty labels, not real CIR data.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path

import pytest

from ecdat.Backup_GUI.graph import (
    NODE_TYPES,
    RELATIONS,
    GraphProvider,
    MockGraphProvider,
    build_mock_graph,
    to_frontend_graph,
)
from ecdat.Backup_GUI.server import index_page, make_server
from ecdat.Backup_GUI.service import GuiService

RELATION_SET = set(RELATIONS)


def _graph() -> dict:
    return to_frontend_graph(build_mock_graph())


# --- dataset shape ------------------------------------------------------------


def test_graph_has_minimum_connected_nodes():
    g = _graph()
    assert g["node_count"] >= 20
    assert g["edge_count"] >= 20
    adj: dict[str, list[str]] = {}
    for e in g["edges"]:
        adj.setdefault(e["source"], []).append(e["target"])
        adj.setdefault(e["target"], []).append(e["source"])
    seen = {g["nodes"][0]["id"]}
    queue = deque(seen)
    while queue:
        for nxt in adj.get(queue.popleft(), []):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    assert len(seen) == g["node_count"]  # single connected component


def test_node_and_relation_vocabularies():
    g = _graph()
    types = {n["type"] for n in g["nodes"]}
    assert types <= set(NODE_TYPES) and len(types) >= 6
    assert {e["type"] for e in g["edges"]} <= RELATION_SET
    for rel in ("uses", "provides", "implements", "configures",
                "protects", "exposes", "runs_in", "depends_on"):
        assert rel in {e["type"] for e in g["edges"]}


def test_nodes_carry_required_display_fields():
    for n in _graph()["nodes"]:
        assert n["id"] and n["label"] and n["type"] in NODE_TYPES
        assert n["risk"] in ("critical", "high", "medium", "low", "info", "none")
        assert isinstance(n["confidence"], (int, float))
        assert isinstance(n["metadata"], dict)
        assert isinstance(n["x"], (int, float)) and isinstance(n["y"], (int, float))


def test_transform_is_deterministic_and_bounded():
    first = to_frontend_graph(build_mock_graph())
    assert to_frontend_graph(build_mock_graph()) == first
    W, H = first["canvas"]["width"], first["canvas"]["height"]
    positions = set()
    for n in first["nodes"]:
        assert 0 <= n["x"] <= W and 0 <= n["y"] <= H
        positions.add((n["x"], n["y"]))
    assert len(positions) == first["node_count"]  # no overlaps


def test_transform_rejects_dangling_edges_and_bad_paths():
    raw = build_mock_graph()
    bad = {"nodes": raw["nodes"], "edges": [
        {"id": "x", "source": "nope", "target": "internet", "type": "uses", "detail": ""}],
        "trace_paths": []}
    with pytest.raises(ValueError):
        to_frontend_graph(bad)
    bad_trace = {"nodes": raw["nodes"], "edges": raw["edges"],
                 "trace_paths": [{"id": "t", "label": "t",
                                  "node_ids": ["internet", "nope"], "note": ""}]}
    with pytest.raises(ValueError):
        to_frontend_graph(bad_trace)


def test_trace_path_is_walkable():
    g = _graph()
    assert g["trace_paths"], "at least one trace path required"
    linked: dict[frozenset, bool] = {}
    for e in g["edges"]:
        linked[frozenset((e["source"], e["target"]))] = True
    main = next(t for t in g["trace_paths"] if t["id"] == "internet-to-risk")
    assert main["node_ids"][0] == "internet"
    assert "RSA-2048" in main["node_ids"]
    for t in g["trace_paths"]:
        for a, b in zip(t["node_ids"], t["node_ids"][1:]):
            assert frozenset((a, b)) in linked, f"trace hop not an edge: {a}-{b}"


def test_risky_nodes_exist_for_highlighting():
    risks = {n["risk"] for n in _graph()["nodes"]}
    assert "critical" in risks and "high" in risks


# --- provider seam ------------------------------------------------------------


def test_mock_provider_envelope_and_protocol():
    provider = MockGraphProvider()
    assert isinstance(provider, GraphProvider)
    assert provider.name == "mock-graph"
    envelope = provider.get_graph()
    assert envelope["mock"] is True
    assert "Person 1" in envelope["note"]
    assert envelope["node_count"] >= 20


def test_service_graph_delegates_to_provider(tmp_path: Path):
    svc = GuiService(tmp_path / "g.db")
    g = svc.graph()
    assert g["node_count"] >= 20 and g["mock"] is True


# --- HTTP ---------------------------------------------------------------------


class _Live:
    def __init__(self, tmp_path: Path):
        self.server = make_server(tmp_path / "g.db", host="127.0.0.1", port=0)
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


def test_api_graph_endpoint(tmp_path: Path):
    with _Live(tmp_path) as live:
        with urllib.request.urlopen(live.base + "/api/graph", timeout=5) as res:
            assert res.status == 200
            payload = json.loads(res.read().decode("utf-8"))
    assert payload["node_count"] >= 20
    assert payload["mock"] is True
    assert all("x" in n and "y" in n for n in payload["nodes"])


# --- frontend hygiene ---------------------------------------------------------


def test_graph_page_uses_no_framework_or_unsafe_sinks():
    out = index_page()
    assert "Crypto Knowledge Graph" in out
    assert "/api/graph" in out
    assert "innerHTML" not in out
    lowered = out.lower()
    assert "cdn" not in lowered and "d3" not in lowered
    assert "vis-network" not in lowered and "react" not in lowered


def test_existing_cards_still_render():
    out = index_page()
    for section in ("Crypto inventory", "Risk dashboard", "Finding detail",
                    "Crypto asset inventory"):
        assert section in out
