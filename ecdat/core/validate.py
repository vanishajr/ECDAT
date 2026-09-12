"""Canonical ECDAT JSON validation (Person 3 platform layer).

PROVISIONAL — pending Person 1 (Core Intelligence) + Person 2
(Discovery/Scanning) sign-off on canonical_v1.json. Do not extend the
schema without all-3 agreement.

This module intentionally contains no business logic: it loads the
versioned JSON Schema and validates raw dicts with jsonschema.
Typed mapping lives in models.py.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import jsonschema

SCHEMA_VERSION = "1.0"
SCHEMA_PATH = Path(__file__).with_name("canonical_v1.json")


@lru_cache(maxsize=1)
def load_schema() -> dict:
    """Load and cache the provisional canonical v1 JSON Schema."""
    with SCHEMA_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_json(path: str | Path) -> dict:
    """Load a canonical JSON document from disk (no validation)."""
    with Path(path).open("r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise ValueError(f"canonical document must be a JSON object: {path}")
    return doc


def validate(doc: dict) -> dict:
    """Validate a raw dict against canonical_v1.json.

    Returns the same dict unchanged when valid.
    Raises jsonschema.ValidationError when invalid.
    """
    schema = load_schema()
    jsonschema.validate(instance=doc, schema=schema)
    return doc
