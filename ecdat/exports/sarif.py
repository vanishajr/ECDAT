"""Minimal SARIF 2.1.0 renderer. Pure function over a validated canonical doc."""

from __future__ import annotations

import json

SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

# Deterministic severity mapping. Line numbers are passed through
# verbatim (line 0 denotes non-file offsets in binary/cloud mocks).
LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def level_for(severity: str) -> str:
    return LEVELS.get(severity, "note")


def to_sarif(doc: dict) -> str:
    """Render minimal SARIF 2.1.0. No trailing newline (caller adds it)."""
    seen: dict[str, dict] = {}
    for f in doc["findings"]:
        if f["rule_id"] not in seen:
            seen[f["rule_id"]] = {
                "id": f["rule_id"],
                "name": f["rule_id"],
                "shortDescription": {"text": f["title"]},
            }
    rules = [seen[k] for k in sorted(seen)]
    results = []
    for f in doc["findings"]:
        region: dict = {"startLine": f["line"]}
        if f.get("snippet"):
            region["snippet"] = {"text": f["snippet"]}
        results.append(
            {
                "ruleId": f["rule_id"],
                "level": level_for(f["severity"]),
                "message": {"text": f["title"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["file"]},
                            "region": region,
                        }
                    }
                ],
            }
        )
    sarif = {
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ecdat",
                        "version": str(doc["tool_versions"].get("ecdat", "0.1.0")),
                        "informationUri": "https://ecdat.local",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)
