"""Path-independence regression tests (OpenSSL parity follow-up).

Identical repository contents scanned from two different temporary roots
must produce equivalent normalized findings, identities, severities and
downstream analysis. Only inherently run-specific metadata (scan IDs,
timestamps, absolute paths) may differ.

Covers: finding identity/line/severity/confidence equivalence, operation
and asset ID equivalence, risk and recommendation equivalence.
"""

import json
import shutil
from pathlib import Path

from ecdat.core.orchestrator import (
    ScanContext,
    ScanPermissions,
    ScanRequest,
    get_orchestrator,
)

CRYPTO_PY = (
    "import hashlib\n"
    "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
    "key = AESGCM.generate_key(bit_length=256)\n"
    "digest = hashlib.md5(b'path-independence').hexdigest()\n"
    "print(key, digest)\n"
)

OPENSSL_CNF = (
    "[req]\ndefault_bits = 2048\ndefault_md = sha256\n"
    "distinguished_name = path-independence\n"
)


def _fixture_tree(root: Path) -> Path:
    repo = root / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "crypto_app.py").write_text(CRYPTO_PY)
    (repo / "openssl.cnf").write_text(OPENSSL_CNF)
    return repo


def _scan(repo: Path) -> tuple[dict, dict]:
    request = ScanRequest(
        target=str(repo),
        scanners=["source", "dependency", "binary", "config", "certificate"],
        permissions=ScanPermissions(),
        profile="standard",
        risk_z=10.0,
        context=ScanContext(),
        caller="path-independence-test",
    )
    result = get_orchestrator().scan(request)
    return result.as_tuple()


def _norm_finding(finding: dict, root: Path) -> str:
    doc = json.loads(json.dumps(finding, sort_keys=True, default=str))
    return json.dumps(doc, sort_keys=True).replace(str(root), "<ROOT>")


def _norm_records(records: list, root: Path) -> list:
    return sorted(
        json.dumps(r, sort_keys=True, default=str).replace(str(root), "<ROOT>")
        for r in (records or []))


def test_same_tree_different_roots_agree(tmp_path):
    root_a = tmp_path / "A"
    root_b = tmp_path / "B"
    repo_a = _fixture_tree(root_a)
    _fixture_tree(root_b)
    # Sanity: byte-identical contents under different roots.
    assert sorted(p.relative_to(repo_a).as_posix()
                  for p in repo_a.rglob("*") if p.is_file()) == \
        sorted(p.relative_to(root_b / "repo").as_posix()
               for p in (root_b / "repo").rglob("*") if p.is_file())

    cir_a, doc_a = _scan(repo_a)
    cir_b, doc_b = _scan(root_b / "repo")

    assert len(doc_a["findings"]) == len(doc_b["findings"]) > 0

    norm_a = sorted(_norm_finding(f, repo_a) for f in doc_a["findings"])
    norm_b = sorted(_norm_finding(f, root_b / "repo")
                    for f in doc_b["findings"])
    assert norm_a == norm_b  # findings incl. file/line/severity/confidence

    ops_a = _norm_records(cir_a.get("operations", []), repo_a)
    ops_b = _norm_records(cir_b.get("operations", []), root_b / "repo")
    assert ops_a == ops_b  # operation identity + representative lines

    assets_a = _norm_records(cir_a.get("assets", []), repo_a)
    assets_b = _norm_records(cir_b.get("assets", []), root_b / "repo")
    assert assets_a == assets_b  # asset identity

    risks_a = _norm_records(cir_a.get("risks", []), repo_a)
    risks_b = _norm_records(cir_b.get("risks", []), root_b / "repo")
    assert risks_a == risks_b

    recs_a = _norm_records(cir_a.get("recommendations", []), repo_a)
    recs_b = _norm_records(cir_b.get("recommendations", []), root_b / "repo")
    assert recs_a == recs_b


def test_copy_of_tree_matches_original(tmp_path):
    """Copied tree (new temp path) matches the original scan exactly."""
    repo = _fixture_tree(tmp_path / "orig")
    clone = tmp_path / "clone"
    shutil.copytree(repo, clone / "repo")
    cir_a, doc_a = _scan(repo)
    cir_b, doc_b = _scan(clone / "repo")

    # Scan IDs are run-specific metadata (target-derived); presence only.
    assert doc_a["scan_id"].startswith("scan:")
    assert doc_b["scan_id"].startswith("scan:")
    norm_a = sorted(_norm_finding(f, repo) for f in doc_a["findings"])
    norm_b = sorted(_norm_finding(f, clone / "repo")
                    for f in doc_b["findings"])
    assert norm_a == norm_b
    ops_a = _norm_records(cir_a.get("operations", []), repo)
    ops_b = _norm_records(cir_b.get("operations", []), clone / "repo")
    assert ops_a == ops_b
