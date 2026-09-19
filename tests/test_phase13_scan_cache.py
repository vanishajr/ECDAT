"""Phase 13 tests: versioned scan caches + execution budgets (additive)."""

from __future__ import annotations

import time

from ecdat.core.scan_cache import (
    ESCALATION_STAGES,
    ScanCacheV2,
    budget_remaining,
    check_budget,
    final_scan_cache_key,
    next_stage,
    parse_cache_key,
    resolution_cache_key,
    staged_escalation,
)


def test_parse_cache_key_versions():
    base = parse_cache_key("abc123", "facts-v1", "adapter-v1")
    assert "abc123" in base and "facts-v1" in base
    assert parse_cache_key("abc123") == base  # defaults are the same vector
    assert parse_cache_key("abc123", "facts-v2") != base
    assert parse_cache_key("abc123", "facts-v1", "adapter-v2") != base
    assert parse_cache_key("other") != base


def test_resolution_cache_key_versions():
    base = resolution_cache_key("fnhash", "resolver-v1", "registry-v1")
    assert resolution_cache_key("fnhash") == base
    assert resolution_cache_key("fnhash", "resolver-v2") != base
    assert resolution_cache_key("fnhash", "resolver-v1", "registry-v2") != base


def test_final_scan_cache_key_covers_all_versions():
    scanners = {"source": "1.0", "binary": "2.0"}
    config = {"profile": "standard"}
    base = final_scan_cache_key("in", scanners, "registry-v1", "risk-v1",
                                "rec-v1", config, "cir-v1")
    assert final_scan_cache_key("in", scanners, "registry-v1", "risk-v1",
                                "rec-v1", config, "cir-v1") == base
    # Dict order must not matter.
    assert final_scan_cache_key(
        "in", {"binary": "2.0", "source": "1.0"}, "registry-v1",
        "risk-v1", "rec-v1", config, "cir-v1") == base
    for variant in (
        final_scan_cache_key("other", scanners, "registry-v1", "risk-v1",
                             "rec-v1", config, "cir-v1"),
        final_scan_cache_key("in", {"source": "9.9"}, "registry-v1",
                             "risk-v1", "rec-v1", config, "cir-v1"),
        final_scan_cache_key("in", scanners, "registry-v2", "risk-v1",
                             "rec-v1", config, "cir-v1"),
        final_scan_cache_key("in", scanners, "registry-v1", "risk-v2",
                             "rec-v1", config, "cir-v1"),
        final_scan_cache_key("in", scanners, "registry-v1", "risk-v1",
                             "rec-v2", config, "cir-v1"),
        final_scan_cache_key("in", scanners, "registry-v1", "risk-v1",
                             "rec-v1", {"profile": "deep"}, "cir-v1"),
        final_scan_cache_key("in", scanners, "registry-v1", "risk-v1",
                             "rec-v1", config, "cir-v2"),
    ):
        assert variant != base


def test_scan_cache_v2_get_set_and_hit_rate():
    cache = ScanCacheV2({"registry": "v1"})
    assert cache.hit_rate == 0.0
    assert cache.get("parse", "k1") is None
    cache.set("parse", "k1", {"facts": 3})
    assert cache.get("parse", "k1") == {"facts": 3}
    assert cache.get("parse", "missing") is None
    assert cache.get("resolve", "k1") is None  # namespaces are isolated
    assert 0.0 < cache.hit_rate < 1.0
    assert len(cache) == 1
    assert cache.stats["entries"] == 1


def test_scan_cache_v2_invalidate_on_version_change():
    cache = ScanCacheV2({"registry": "v1", "resolver": "v1"})
    cache.set("parse", "k1", "value")
    assert cache.invalidate_on_version_change(
        {"registry": "v1", "resolver": "v1"}) is False
    assert cache.get("parse", "k1") == "value"  # same vector keeps entries
    assert cache.invalidate_on_version_change(
        {"registry": "v2", "resolver": "v1"}) is True
    assert cache.get("parse", "k1") is None  # stale rows dropped
    assert cache.versions == {"registry": "v2", "resolver": "v1"}


def test_budget_enforcement():
    assert check_budget(None) is True
    assert budget_remaining(None) is None
    future = time.monotonic() + 60.0
    assert check_budget(future) is True
    assert (budget_remaining(future) or 0.0) > 0.0
    past = time.monotonic() - 1.0
    assert check_budget(past) is False
    assert (budget_remaining(past) or 0.0) <= 0.0


def test_staged_escalation_order():
    assert ESCALATION_STAGES == (
        "cheap", "parse", "direct", "dataflow", "fingerprint")
    assert staged_escalation() == "cheap"
    assert staged_escalation("cheap") == "parse"
    assert staged_escalation("parse") == "direct"
    assert staged_escalation("direct") == "dataflow"
    assert staged_escalation("dataflow") == "fingerprint"
    assert staged_escalation("fingerprint") is None  # terminal
    assert staged_escalation("unknown-stage") is None
    assert next_stage("cheap") == "parse"
    # Full walk terminates.
    stage: str | None = None
    seen: list[str] = []
    while True:
        stage = staged_escalation(stage)
        if stage is None:
            break
        seen.append(stage)
    assert seen == list(ESCALATION_STAGES)
