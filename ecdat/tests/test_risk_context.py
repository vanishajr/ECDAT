"""Phase 10 regression: system risk with explicit assumptions + context.

Proves risk/recommendations operate on resolved operations with honest
provenance instead of severity counts or mock scoring:

- every context input (exposure, criticality, Mosca X/Y/Z, quantum
  vuln) carries observed / inferred / user-supplied / unknown provenance;
- undeclared inputs keep mid-range defaults recorded as explicit
  ``inferred`` assumptions (never silent high-risk defaults);
- user-supplied ScanContext (CLI flags, GUI fields) flows through the
  real pipeline and is tagged user-supplied;
- recommendations are operation-aware (operation id + location) and
  carry deterministic blockers, effort, and latency/cost class.
"""

from __future__ import annotations

import argparse

from ecdat.core import recommend as recommend_mod
from ecdat.core import risk as risk_mod
from ecdat.core.orchestrator import ScanContext, context_from_args


def _op(canonical="RSA", notes="", usage="Confirmed", confidence=0.9):
    return {
        "operation_id": "op:aaaaaaaaaaaaaaaa",
        "operation_type": "Encrypt",
        "canonical_name": canonical,
        "confidence": confidence,
        "usage_state": usage,
        "context": {"notes": notes} if notes else {},
        "location": {},
        "implementation": {},
        "risk_inputs": {"usage_state": usage},
    }


def test_provenance_defaults_are_inferred_not_silent():
    record = risk_mod.score_operation(_op())
    assert set(record["provenance"]) == {
        "exposure", "criticality", "data_lifetime_years",
        "migration_years", "crqc_years", "quantum_vuln"}
    assert record["provenance"]["exposure"] == "inferred"
    assert record["provenance"]["criticality"] == "inferred"
    assert record["provenance"]["data_lifetime_years"] == "inferred"
    assert record["provenance"]["crqc_years"] == "inferred"
    assert record["provenance"]["quantum_vuln"] == "observed"
    # Defaults are recorded as explicit assumptions, not hidden.
    assert any("assumed" in a for a in record["assumptions"])
    assert "Mosca" in record["explanation"] or "Mosca" in record["explanation"]


def test_unknown_algorithm_provenance_unknown():
    record = risk_mod.score_operation(_op(canonical="FROBNICATE-9000"))
    assert record["provenance"]["quantum_vuln"] == "unknown"
    assert any("unmapped" in a for a in record["assumptions"])


def test_user_context_wins_and_tagged():
    record = risk_mod.score_operation(_op(
        notes="user:exposure=internet-facing; user:criticality=critical; "
              "user:data_lifetime_years=12; user:migration_years=4"))
    assert record["provenance"]["exposure"] == "user-supplied"
    assert record["provenance"]["criticality"] == "user-supplied"
    assert record["provenance"]["data_lifetime_years"] == "user-supplied"
    assert record["provenance"]["migration_years"] == "user-supplied"
    assert any("user-supplied" in a for a in record["assumptions"])
    assert record["mosca"] == {"X": 12.0, "Y": 4.0, "Z": 10.0}
    # Internet-facing critical RSA scores at least High.
    assert record["class"] in ("Critical", "High")


def test_observed_context_beats_defaults():
    record = risk_mod.score_operation(_op(
        notes="data_lifetime_years=9; migration_years=2"))
    assert record["provenance"]["data_lifetime_years"] == "observed"
    assert record["provenance"]["migration_years"] == "observed"
    assert record["mosca"]["X"] == 9.0
    assert record["mosca"]["Y"] == 2.0


def test_recommendation_operation_aware_with_blockers():
    op = _op(canonical="RSA")
    op["location"] = {"file": "app.py"}
    rec = recommend_mod.recommend_for_operation(op, None)
    assert rec["operation_id"] == "op:aaaaaaaaaaaaaaaa"
    assert "op:aaaaaaaaaaaaaaaa" in rec["reason"]
    assert "app.py" in rec["reason"]
    assert rec["blockers"], "every path must name deterministic blockers"
    assert "Blockers:" in rec["reason"]
    assert "Effort" in rec["reason"]
    assert "latency/cost" in rec["reason"]
    assert rec["effort"] and rec["latency_cost_class"]
    assert rec["refs"], "standards references required"


def test_pqc_usage_not_blindly_migrated():
    rec = recommend_mod.recommend_for_operation(
        _op(canonical="ML-KEM-768"), None)
    assert rec["rule_key"] == "PQC-OK"
    assert rec["priority"] == "Low"


def test_context_from_args_shapes():
    ns = argparse.Namespace(
        environment="production", owner="payments", exposure="internal",
        business_criticality="high", data_lifetime_years=7.0,
        migration_years=2.0)
    ctx = context_from_args(ns)
    assert isinstance(ctx, ScanContext)
    assert ctx.owner == "payments"
    assert ctx.data_lifetime_years == 7.0
    # GUI camelCase body works too.
    gui = context_from_args({"businessCriticality": "low",
                             "dataLifetimeYears": 3})
    assert gui.business_criticality == "low"
    assert gui.data_lifetime_years == 3.0
    assert gui.owner is None  # unknown stays unknown
    # Cache keys differ when context differs.
    assert ctx.cache_seed() != ScanContext().cache_seed()


def test_pipeline_applies_user_context(tmp_path):
    (tmp_path / "app.py").write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "def f(k, n, d):\n    return AESGCM(k).encrypt(n, d, None)\n")
    from ecdat.core.orchestrator import ScanRequest, get_orchestrator
    _CTX = ScanContext(exposure="internet-facing",
                       business_criticality="critical",
                       data_lifetime_years=12.0, migration_years=4.0)
    result = get_orchestrator().scan(
        ScanRequest(target=str(tmp_path), scanners=["source"],
                    context=_CTX, caller="phase10-context"))
    notes = " ".join(
        str((o.get("context", {}) or {}).get("notes", ""))
        for o in result.cir["operations"])
    assert "user:exposure=internet-facing" in notes
    assert "user:data_lifetime_years=12.0" in notes
    # Context-bearing scan gets its own cache entry, not the default one.
    plain = get_orchestrator().scan(
        ScanRequest(target=str(tmp_path), scanners=["source"],
                    caller="phase10-context"))
    assert result.scan_id != plain.scan_id


def test_cli_context_flags_parse():
    from ecdat.cli import build_parser
    args = build_parser().parse_args(
        ["scan", "x", "--exposure", "internal", "--criticality", "high",
         "--data-lifetime", "7", "--migration-years", "2",
         "--environment", "staging", "--owner", "team-a",
         "--risk-z", "12"])
    assert args.exposure == "internal"
    assert args.business_criticality == "high"
    assert args.data_lifetime_years == 7.0
    assert args.migration_years == 2.0
    assert args.risk_z == 12.0
    ctx = context_from_args(args)
    assert ctx.environment == "staging"
    assert ctx.owner == "team-a"
