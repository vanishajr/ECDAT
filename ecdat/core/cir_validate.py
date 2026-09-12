"""Person-1 ownership. CIR is the source of truth for all downstream stages.

JSON Schema (draft 2020-12) validation entry points for CIR v0.1.
Uses jsonschema only (already a dependency). No business logic.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import jsonschema
from jsonschema import Draft202012Validator

_SCHEMA_PATH = Path(__file__).with_name("cir.schema.json")


@lru_cache(maxsize=1)
def load_cir_schema() -> dict:
    """Load and cache the CIR v0.1 JSON Schema document."""
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_cir(doc: dict) -> dict:
    """Validate a CIR dict against cir.schema.json.

    Returns the same dict unchanged on success; raises
    jsonschema.ValidationError on the first schema violation.
    """
    schema = load_cir_schema()
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    if errors:
        raise errors[0]
    return doc


def load_cir_json(path: str | Path) -> dict:
    """Load a CIR JSON file, validate it, and return the dict."""
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    validate_cir(doc)
    return doc
