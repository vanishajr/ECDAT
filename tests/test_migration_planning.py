"""Tests for migration planning aids (additive, P1 scoring untouched).

estimate_days/app_group_for/summarize_app_groups are pure planning
helpers over P1 records: estimate ranges widen with fan-out/blockers,
groups bucket by code boundary. Forbidden keys (timeline,
migration_sequence, migration_state, sequencing, owner) must never
appear; triage order (P1 priority, then replacement score) is preserved.
"""

from ecdat.adapters import migration_adapter as M


def test_estimate_days_table():
    assert M.estimate_days("S", 1, [], "hash-upgrade")[:2] == (1, 2)
    assert M.estimate_days("M", 1, [], "sig-replace")[:2] == (3, 7)
    assert M.estimate_days("L", 1, [], "sig-replace")[:2] == (10, 20)
    assert M.estimate_days("bogus", 1, [])[:2] == (2, 5)


def test_estimate_days_fanout_and_blockers():
    small = M.estimate_days("M", 1, [], "x")
    wide = M.estimate_days("M", 5, [], "x")
    assert wide[0] >= small[0] and wide[1] > small[1]
    assert wide[1] <= 3 * small[1] + 1  # fan-out capped x3
    blocked = M.estimate_days("S", 1, ["b1", "b2"], "x")
    assert blocked[1] == 2 + 2  # +1 day per blocker on the top end
    assert "blocker" in blocked[2]


def test_estimate_days_hybrid_widens_top():
    plain = M.estimate_days("M", 1, [], "sig-replace")
    hybrid = M.estimate_days("M", 1, [], "hybrid-kem")
    assert hybrid[0] == plain[0] and hybrid[1] == plain[1] + 3
    assert "hybrid" in hybrid[2]


def test_estimate_days_never_raises():
    assert M.estimate_days(None, -3, None, None)[0] >= 1
    lo, hi, basis = M.estimate_days("L", 99, ["b"] * 99, "hybrid-x")
    assert lo <= hi <= 40 and basis


def test_app_group_for():
    assert M.app_group_for(["services/payments/vault.py"]) == \
        "services/payments"
    assert M.app_group_for(["src/a.py"]) == "src"
    assert M.app_group_for(["a.py"]) == "(root)"
    assert M.app_group_for([]) == "(root)"
    assert M.app_group_for(None) == "(root)"
    assert M.app_group_for(["a\\b\\c.py"]) == "a/b"


def test_build_real_items_carry_planning_aids():
    cir = {"operations": [
        {"operation_id": "op:1", "operation_type": "Encrypt",
         "canonical_name": "RSA-2048", "key_size": 2048, "mode": "",
         "usage_state": "Confirmed", "confidence": 0.9,
         "location": {"file": "services/payments/vault.py", "line": 7},
         "asset_ids": ["ast:1"]},
    ], "assets": [
        {"asset_id": "ast:1", "canonical": "RSA-2048", "key_size": 2048},
    ], "recommendations": []}
    items = M.build_real_items(cir, "/repo")
    assert len(items) == 1
    item = items[0]
    assert item["app_group"] == "services/payments"
    assert item["estimate_days"]["min"] <= \
        item["estimate_days"]["max"]
    assert "P1 effort" in item["estimate_basis"]
    assert item["effort"] in ("S", "M", "L")
    for forbidden in ("timeline", "migration_sequence",
                      "migration_state", "sequencing", "owner"):
        assert forbidden not in item


def test_envelope_app_groups_and_contract():
    cir = {"operations": [
        {"operation_id": "op:1", "operation_type": "Encrypt",
         "canonical_name": "RSA-2048", "key_size": 2048, "mode": "",
         "usage_state": "Confirmed", "confidence": 0.9,
         "location": {"file": "services/payments/vault.py", "line": 7},
         "asset_ids": ["ast:1"]},
        {"operation_id": "op:2", "operation_type": "Hash",
         "canonical_name": "MD5", "key_size": None, "mode": "",
         "usage_state": "Confirmed", "confidence": 0.9,
         "location": {"file": "services/auth/pw.py", "line": 3},
         "asset_ids": ["ast:2"]},
    ], "assets": [
        {"asset_id": "ast:1", "canonical": "RSA-2048", "key_size": 2048},
        {"asset_id": "ast:2", "canonical": "MD5"},
    ], "recommendations": []}
    plan = M.to_real_plan("scan:x", "/repo", cir)
    assert plan["item_count"] == 2
    groups = {g["group"]: g for g in plan["app_groups"]}
    assert set(groups) == {"services/payments", "services/auth"}
    assert all(g["item_count"] == 1 for g in groups.values())
    assert "sequence" not in plan["triage_label"].lower() or \
        "NOT a migration sequence" in plan["triage_label"]
    for forbidden in ("timeline", "migration_sequence",
                      "migration_state", "sequencing", "owner"):
        assert forbidden not in plan
