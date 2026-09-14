from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
from jsonschema import Draft202012Validator

from ecdat.core.cir_models import CIRDocument

_SCHEMA_PATH = Path(__file__).parent / "cir.schema.json"
_SCHEMA_CACHE: dict[str, Any] | None = None


def _load_schema() -> dict[str, Any]:
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is not None:
        return _SCHEMA_CACHE
    with open(_SCHEMA_PATH) as f:
        _SCHEMA_CACHE = json.load(f)
    return _SCHEMA_CACHE


def validate_cir_document(doc: CIRDocument) -> tuple[bool, list[str]]:
    schema = _load_schema()
    validator = Draft202012Validator(schema)
    errors = list(validator.iter_errors(doc.model_dump(mode="json", exclude_none=True)))
    if not errors:
        return True, []
    return False, [f"{e.json_path}: {e.message}" for e in errors]


def load_cir_json(path: str | Path) -> CIRDocument:
    with open(path) as f:
        data = json.load(f)
    return CIRDocument.model_validate(data)


def validate_cir_json_file(path: str | Path) -> tuple[bool, list[str]]:
    with open(path) as f:
        data = json.load(f)
    doc = CIRDocument.model_validate(data)
    return validate_cir_document(doc)