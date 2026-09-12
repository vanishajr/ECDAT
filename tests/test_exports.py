"""Tests for Task 7 exports (mock-first, stdlib only).

Source of truth is always the preserved canonical document
(get_scan_doc). Renderers are pure functions over validated docs.
Golden files live in tests/fixtures/exports/ and are compared
byte-for-byte. Leakage tests ensure DB internals and private-key
markers never appear in exports.
"""

import csv
import io
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from ecdat.cli import build_parser, main
from ecdat.commands import export_cmd
from ecdat.core.validate import load_json, validate
from ecdat.store import db
from ecdat.store import scans as sstore

GOLDENS = Path(__file__).parent / "fixtures" / "exports"
FORMATS = ["json", "csv", "cbom-json", "cbom-xml", "sarif"]
SUFFIX = {
    "json": "json",
    "csv": "csv",
    "cbom-json": "cbom.json",
    "cbom-xml": "cbom.xml",
    "sarif": "sarif",
}


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "t.db")


def _seed(tmp_path: Path, capsys, name: str = "a.py") -> str:
    target = tmp_path / name
    target.write_text("x = 1\n")
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    return out.strip()


def _seed_dir(tmp_path: Path, capsys) -> str:
    app = tmp_path / "app"
    app.mkdir(exist_ok=True)
    (app / "m.py").write_text("x = 1\n")
    assert main(["scan", str(app), "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    return out.strip()


def _export_stdout(scan_id, tmp_path, capsys, format):
    assert main(["export", scan_id, "--format", format, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    return out


# --- stdout + parsing ---------------------------------------------------


@pytest.mark.parametrize("format", FORMATS)
def test_export_stdout_minimal(tmp_path, capsys, format):
    scan_id = _seed(tmp_path, capsys)
    out = _export_stdout(scan_id, tmp_path, capsys, format)
    assert out.strip() != ""


def test_export_json_revalidates(tmp_path, capsys):
    scan_id = _seed(tmp_path, capsys)
    out = _export_stdout(scan_id, tmp_path, capsys, "json")
    assert validate(json.loads(out))["scan_id"] == scan_id


def test_export_csv_fields(tmp_path, capsys):
    scan_id = _seed(tmp_path, capsys)
    out = _export_stdout(scan_id, tmp_path, capsys, "csv")
    rows = list(csv.DictReader(io.StringIO(out)))
    assert len(rows) == 1
    r = rows[0]
    assert r["scan_id"] == scan_id and r["rule_id"] == "RSA-1024"
    assert r["severity"] == "high" and r["line"] == "12"
    assert r["confidence"] == "0.95" and "rsa.generate" in r["snippet"]


def test_export_cbom_json_mapping(tmp_path, capsys):
    scan_id = _seed(tmp_path, capsys)
    out = _export_stdout(scan_id, tmp_path, capsys, "cbom-json")
    doc = json.loads(out)
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    assert len(doc["components"]) == 1 and len(doc["vulnerabilities"]) == 1
    comp = doc["components"][0]
    assert comp["name"] == "RSA-1024" and comp["type"] == "cryptographic-asset"
    assert doc["vulnerabilities"][0]["affects"][0]["ref"] == comp["bom-ref"]


def test_export_cbom_xml_parses(tmp_path, capsys):
    scan_id = _seed(tmp_path, capsys)
    out = _export_stdout(scan_id, tmp_path, capsys, "cbom-xml")
    root = ET.fromstring(out)
    assert root.tag.endswith("bom")
    assert scan_id in root.attrib.get("serialNumber", "")


def test_export_sarif_mapping(tmp_path, capsys):
    scan_id = _seed(tmp_path, capsys)
    out = _export_stdout(scan_id, tmp_path, capsys, "sarif")
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["results"][0]["ruleId"] == "RSA-1024"
    assert run["results"][0]["level"] == "error"
    assert run["tool"]["driver"]["name"] == "ecdat"


def test_export_multi_counts(tmp_path, capsys):
    scan_id = _seed_dir(tmp_path, capsys)
    out = _export_stdout(scan_id, tmp_path, capsys, "csv")
    assert len(list(csv.DictReader(io.StringIO(out)))) == 4
    out = _export_stdout(scan_id, tmp_path, capsys, "sarif")
    doc = json.loads(out)
    assert len(doc["runs"][0]["results"]) == 4
    levels = {r["level"] for r in doc["runs"][0]["results"]}
    assert levels == {"error", "warning", "note"}


def test_export_empty(tmp_path, capsys):
    scan_id = _seed(tmp_path, capsys, name="clean.py")
    out = _export_stdout(scan_id, tmp_path, capsys, "csv")
    assert len(list(csv.DictReader(io.StringIO(out)))) == 0
    out = _export_stdout(scan_id, tmp_path, capsys, "sarif")
    assert json.loads(out)["runs"][0]["results"] == []
    out = _export_stdout(scan_id, tmp_path, capsys, "cbom-json")
    doc = json.loads(out)
    assert doc["components"] == [] and doc["vulnerabilities"] == []


# --- --output files -----------------------------------------------------


@pytest.mark.parametrize("format", FORMATS)
def test_export_output_file(tmp_path, capsys, format):
    scan_id = _seed(tmp_path, capsys)
    dest = tmp_path / f"out.{SUFFIX[format]}"
    rc = main(["export", scan_id, "--format", format,
               "--output", str(dest), "--db", _db(tmp_path)])
    assert rc == 0
    capsys.readouterr()
    content = dest.read_text()
    assert content.strip() != ""
    if format in ("json", "cbom-json", "sarif"):
        json.loads(content)  # must parse
    elif format == "cbom-xml":
        ET.fromstring(content)  # must parse


def test_export_json_output_revalidates(tmp_path, capsys):
    scan_id = _seed(tmp_path, capsys)
    dest = tmp_path / "canon.json"
    assert main(["export", scan_id, "--format", "json",
                 "--output", str(dest), "--db", _db(tmp_path)]) == 0
    capsys.readouterr()
    assert validate(json.loads(dest.read_text()))["scan_id"] == scan_id


# --- golden files -------------------------------------------------------


def _seed_canonical_scan_id(tmp_path: Path, fixture: str) -> str:
    """Store a canonical fixture verbatim; return its scan_id."""
    doc = validate(load_json(
        Path(__file__).parent / "fixtures" / "canonical" / f"{fixture}.json"))
    conn = db.open_db(_db(tmp_path))
    try:
        from ecdat.store import findings as fstore

        sstore.insert_scan(conn, doc)
        fstore.insert_findings_for_scan(conn, doc)
    finally:
        conn.close()
    return doc["scan_id"]


@pytest.mark.parametrize("format", FORMATS)
@pytest.mark.parametrize("fixture", ["minimal", "empty"])
def test_golden_stdout(tmp_path, capsys, format, fixture):
    scan_id = _seed_canonical_scan_id(tmp_path, fixture)
    out = _export_stdout(scan_id, tmp_path, capsys, format)
    expected = (GOLDENS / f"{fixture}.{SUFFIX[format]}").read_text()
    assert out == expected


@pytest.mark.parametrize("format", FORMATS)
def test_golden_output_file(tmp_path, capsys, format):
    scan_id = _seed_canonical_scan_id(tmp_path, "minimal")
    dest = tmp_path / f"g.{SUFFIX[format]}"
    assert main(["export", scan_id, "--format", format,
                 "--output", str(dest), "--db", _db(tmp_path)]) == 0
    capsys.readouterr()
    assert dest.read_text() == (GOLDENS / f"minimal.{SUFFIX[format]}").read_text()


# --- errors -------------------------------------------------------------


def test_export_unknown_scan(tmp_path, capsys):
    rc = main(["export", "bogus-id", "--format", "json", "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "not found" in err


def test_export_invalid_format_rejected():
    with pytest.raises(SystemExit) as exc:
        main(["export", "x", "--format", "bogus"])
    assert exc.value.code == 2


def test_render_unknown_format_rejected():
    with pytest.raises(ValueError):
        export_cmd.render({"scan_id": "x"}, "bogus")


# --- leakage ------------------------------------------------------------


@pytest.mark.parametrize("format", FORMATS)
def test_no_db_internals_or_key_markers(tmp_path, capsys, format):
    scan_id = _seed(tmp_path, capsys)
    out = _export_stdout(scan_id, tmp_path, capsys, format)
    assert "created_at" not in out
    assert "raw_json" not in out
    assert "BEGIN" not in out and "PRIVATE KEY" not in out


def test_csv_header_allowlist(tmp_path, capsys):
    scan_id = _seed(tmp_path, capsys)
    out = _export_stdout(scan_id, tmp_path, capsys, "csv")
    header = out.splitlines()[0]
    assert header == ("scan_id,rule_id,severity,file,line,title,"
                      "confidence,snippet,target")


# --- parser + regression ------------------------------------------------


def test_parser_dispatch_export():
    parser = build_parser()
    args = parser.parse_args(["export", "x"])
    assert args.func.__module__ == "ecdat.commands.export_cmd"
    assert args.format == "json" and args.output is None


def test_existing_commands_unchanged():
    parser = build_parser()
    assert parser.parse_args(["scan", "a.py"]).func.__module__ == "ecdat.commands.scan_cmd"
    assert parser.parse_args(["list"]).func.__module__ == "ecdat.commands.list_cmd"
    assert parser.parse_args(["show", "x"]).func.__module__ == "ecdat.commands.show_cmd"
    assert parser.parse_args(["risk", "x"]).func.__module__ == "ecdat.commands.risk_cmd"


def test_scan_list_show_still_work(tmp_path, capsys):
    target = tmp_path / "a.py"
    target.write_text("x = 1\n")
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    scan_id = out.strip()
    assert main(["list", "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert scan_id in out
    assert main(["show", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert scan_id in out
