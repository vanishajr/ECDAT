"""Consumer-contract tests: GraphProvider output accepted by P3.

Defines WHAT the GUI accepts from any GraphProvider (mock today,
real P1 CIR later): envelope/node/edge fields, the closed node and
relation vocabularies, and deterministic layout. A fake P1-style
provider injected into GuiService must flow through unchanged;
malformed graphs are rejected with ValueError, never rendered.
"""

import pytest

from ecdat.Backup_GUI.graph import (
    NODE_TYPES,
    RELATIONS,
    GraphProvider,
    MockGraphProvider,
    build_mock_graph,
    to_frontend_graph,
)
from ecdat.Backup_GUI.service import GuiService


def _tiny_raw():
    return {
        "nodes": [
            {"id": "svc", "type": "Service", "label": "svc",
             "risk": "high", "confidence": 0.9,
             "metadata": {}, "rule_id": "RSA-1024"},
            {"id": "lib", "type": "Library", "label": "lib",
             "risk": "none", "confidence": 1.0, "metadata": {}},
        ],
        "edges": [{"id": "svc|uses|lib", "source": "svc",
                   "target": "lib", "type": "uses", "detail": ""}],
        "trace_paths": [{"id": "t", "label": "t", "node_ids": ["svc", "lib"],
                         "note": ""}],
    }


class _FakeP1Graph:
    """Stands in for a future P1 CIR provider behind the Protocol."""

    name = "fake-p1-cir"

    def get_graph(self) -> dict:
        return to_frontend_graph(_tiny_raw())


def test_mock_conforms_and_labels_mock():
    provider = MockGraphProvider()
    assert isinstance(provider, GraphProvider)
    assert provider.name == "mock-graph"
    first = provider.get_graph()
    assert provider.get_graph() == first  # deterministic
    assert first["mock"] is True
    for key in ("graph_version", "nodes", "edges", "trace_paths",
                "node_count", "edge_count", "canvas", "node_types",
                "relations"):
        assert key in first


def test_node_edge_fields_consumed_by_gui():
    graph = to_frontend_graph(_tiny_raw())
    node = graph["nodes"][0]
    assert {"id", "type", "label", "risk", "confidence", "metadata",
            "x", "y"} <= set(node)
    assert node["type"] in NODE_TYPES
    edge = graph["edges"][0]
    assert {"id", "source", "target", "type", "detail"} <= set(edge)
    assert edge["type"] in RELATIONS
    assert graph["node_count"] == 2 and graph["edge_count"] == 1


def test_fake_p1_provider_flows_through_service(tmp_path):
    svc = GuiService(tmp_path / "g.db", graph_provider=_FakeP1Graph())
    graph = svc.graph()
    assert graph == to_frontend_graph(_tiny_raw())  # passed through, not reshaped
    assert "mock" not in graph  # P3 does not force mock flags on P1 data


@pytest.mark.parametrize("mutate", [
    lambda r: r["nodes"][0].__setitem__("type", "QuantumComputer"),
    lambda r: r["edges"][0].__setitem__("type", "teleports"),
    lambda r: r["edges"].append({"id": "x", "source": "ghost",
                                 "target": "lib", "type": "uses"}),
    lambda r: r["trace_paths"][0].__setitem__("node_ids", ["nope"]),
])
def test_malformed_graph_rejected(mutate):
    raw = _tiny_raw()
    mutate(raw)
    with pytest.raises(ValueError):
        to_frontend_graph(raw)


def test_mock_dataset_untouched_by_queries():
    before = build_mock_graph()
    to_frontend_graph(before)
    assert build_mock_graph() == before
