"""Minimal/mock CycloneDX CBOM renderers (JSON + XML).

Pure functions over a validated canonical v1 dict. This is a
minimal subset honestly derivable from canonical v1 — one component
and one vulnerability per finding — pending richer CIR from Person 1.
Do NOT imply every finding is a confirmed crypto component or that
this output is certified spec-complete.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

SPEC_VERSION = "1.6"
NAMESPACE = "http://cyclonedx.org/schema/bom/1.6"
MOCK_NOTE = (
    "Minimal/mock CBOM representation derived from ECDAT canonical v1 "
    "findings; pending richer CIR from Person 1."
)


def _bom_ref(doc: dict, finding: dict, index: int) -> str:
    return f"{finding['rule_id']}:{finding['file']}:{finding['line']}#{index}"


def _component(doc: dict, finding: dict, index: int) -> dict:
    ref = _bom_ref(doc, finding, index)
    occurrence: dict = {"location": f"{finding['file']}:{finding['line']}"}
    if finding.get("snippet"):
        occurrence["additionalContext"] = finding["snippet"]
    return {
        "bom-ref": ref,
        "type": "cryptographic-asset",
        "name": finding["rule_id"],
        "description": finding["title"],
        "evidence": {"occurrences": [occurrence]},
        "cryptoProperties": {"assetType": "algorithm"},
    }


def _vulnerability(doc: dict, finding: dict, index: int) -> dict:
    ref = _bom_ref(doc, finding, index)
    return {
        "bom-ref": ref,
        "id": finding["rule_id"],
        "source": {"name": "ecdat"},
        "ratings": [{"severity": finding["severity"], "method": "other"}],
        "description": finding["title"],
        "affects": [{"ref": ref}],
    }


def _bom_dict(doc: dict) -> dict:
    tools = [
        {"name": name, "version": version}
        for name, version in sorted(doc["tool_versions"].items())
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "description": MOCK_NOTE,
            "timestamp": doc["finished_at"],
            "tools": tools,
            "component": {
                "bom-ref": doc["scan_id"],
                "type": "application",
                "name": doc["target"],
                "version": doc["scan_id"],
            },
        },
        "components": [
            _component(doc, f, i) for i, f in enumerate(doc["findings"])
        ],
        "vulnerabilities": [
            _vulnerability(doc, f, i) for i, f in enumerate(doc["findings"])
        ],
    }


def to_cbom_json(doc: dict) -> str:
    """Render minimal CBOM JSON. No trailing newline (caller adds it)."""
    return json.dumps(_bom_dict(doc), indent=2, sort_keys=True)


def _text_el(parent: ET.Element, tag: str, text: str) -> ET.Element:
    el = ET.SubElement(parent, tag)
    el.text = text
    return el


def to_cbom_xml(doc: dict) -> str:
    """Render minimal CBOM XML mirroring to_cbom_json. No trailing newline."""
    ET.register_namespace("", NAMESPACE)
    bom = ET.Element(
        "bom",
        {
            "xmlns": NAMESPACE,
            "version": "1",
            "serialNumber": f"urn:ecdat:{doc['scan_id']}",
        },
    )
    metadata = ET.SubElement(bom, "metadata")
    _text_el(metadata, "description", MOCK_NOTE)
    _text_el(metadata, "timestamp", doc["finished_at"])
    tools = ET.SubElement(metadata, "tools")
    for name, version in sorted(doc["tool_versions"].items()):
        tool = ET.SubElement(tools, "tool")
        _text_el(tool, "name", name)
        _text_el(tool, "version", version)
    comp = ET.SubElement(metadata, "component", {"bom-ref": doc["scan_id"], "type": "application"})
    _text_el(comp, "name", doc["target"])
    _text_el(comp, "version", doc["scan_id"])

    components = ET.SubElement(bom, "components")
    for i, f in enumerate(doc["findings"]):
        ref = _bom_ref(doc, f, i)
        c = ET.SubElement(
            components, "component", {"bom-ref": ref, "type": "cryptographic-asset"}
        )
        _text_el(c, "name", f["rule_id"])
        _text_el(c, "description", f["title"])
        evidence = ET.SubElement(c, "evidence")
        occ = ET.SubElement(evidence, "occurrence")
        _text_el(occ, "location", f"{f['file']}:{f['line']}")
        if f.get("snippet"):
            _text_el(occ, "additionalContext", f["snippet"])
        props = ET.SubElement(c, "cryptoProperties")
        _text_el(props, "assetType", "algorithm")

    vulns = ET.SubElement(bom, "vulnerabilities")
    for i, f in enumerate(doc["findings"]):
        ref = _bom_ref(doc, f, i)
        v = ET.SubElement(vulns, "vulnerability", {"bom-ref": ref})
        _text_el(v, "id", f["rule_id"])
        source = ET.SubElement(v, "source")
        _text_el(source, "name", "ecdat")
        ratings = ET.SubElement(v, "ratings")
        rating = ET.SubElement(ratings, "rating")
        _text_el(rating, "severity", f["severity"])
        _text_el(rating, "method", "other")
        _text_el(v, "description", f["title"])
        affects = ET.SubElement(v, "affects")
        ET.SubElement(affects, "target", {"ref": ref})

    ET.indent(bom, space="  ")
    body = ET.tostring(bom, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + body.rstrip("\n")
