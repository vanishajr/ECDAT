"""Real-detector characterization providers (Person 3 platform layer).

Honest measurement only — no accuracy claims, no superiority claims:

A. Detection characterization: P2 source-fixture ground truth
   (ecdat/tests/fixtures/source/ground_truth.json, 17 labeled
   fixtures) evaluated through the existing pair()/evaluate_cases()
   machinery. Line matching uses each entry's own proximity window
   (documented per result); pairing itself stays exact-set.
B. Performance characterization: wall-time, finding/asset/operation
   counts, and peak RSS per target. Raw measurements, no thresholds.

Results are labeled characterization with dataset identity. They must
never be presented as production precision/recall, risk calibration,
PQC-migration success, or cross-tool superiority.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Iterable

from ecdat.benchmark.ground_truth import GroundTruth, evaluate_cases, finding_key
from ecdat.benchmark.predictions import Prediction, PredictionProvider
from ecdat.benchmark.suite import SuiteCase, with_predictions

GROUND_TRUTH_PATH = (
    Path(__file__).resolve().parents[2]
    / "ecdat" / "tests" / "fixtures" / "source" / "ground_truth.json"
)

DATASET_ID = "p2-source-fixtures-v1"


def _rule_id_for(canonical: str, key_size=None, mode: str = "") -> str:
    from ecdat.core.api import _rule_id_for as _p1_rule  # noqa: PLC2701

    return _p1_rule(canonical, key_size, mode or "", "")


def load_p2_ground_truth(path: str | Path | None = None) -> list[dict]:
    """Load P2 source ground-truth fixtures (raw list, documented shape)."""
    with open(path or GROUND_TRUTH_PATH, encoding="utf-8") as fh:
        doc = json.load(fh)
    fixtures = doc.get("fixtures", [])
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError(f"no fixtures in {path or GROUND_TRUTH_PATH}")
    return fixtures


def expected_keys_for_fixture(fixture: dict) -> tuple[frozenset, int]:
    """Expected finding keys with line-proximity expansion.

    Returns (keys, window). Each expected entry contributes
    ``RULE@file:line`` for line ± proximity_lines (entry default 0).
    Rule IDs reuse P1's canonical mapping so detector output and
    labels share one vocabulary.
    """
    keys: set[str] = set()
    window = 0
    for entry in fixture.get("expected_findings", []) or []:
        if not isinstance(entry, dict):
            continue
        location = entry.get("location", {}) or {}
        raw_line = location.get("line", entry.get("line", 0))
        try:
            line = int(raw_line)
        except (TypeError, ValueError):
            continue
        try:
            proximity = int(entry.get("proximity_lines", 0) or 0)
        except (TypeError, ValueError):
            proximity = 0
        window = max(window, proximity)
        rule = _rule_id_for(
            str(entry.get("canonical", "UNKNOWN")),
            entry.get("key_size"), str(entry.get("mode") or ""))
        location = entry.get("location", {}) or {}
        path = str(location.get("file") or fixture.get("fixture_path", ""))
        for delta in range(-proximity, proximity + 1):
            if line + delta >= 0:
                keys.add(finding_key(rule, path, line + delta))
    return frozenset(keys), window


def p2_ground_truth_cases(
    repo_root: str | Path | None = None,
    limit: int | None = None,
) -> list[SuiteCase]:
    """Build SuiteCases from P2 source ground truth (real labels).

    Cases are flagged synthetic=False with a dataset note: these are
    measured fixture labels, NOT production accuracy evidence.
    """
    root = Path(repo_root) if repo_root else Path.cwd()
    cases = []
    for i, fixture in enumerate(load_p2_ground_truth()):
        if limit is not None and i >= limit:
            break
        expected, window = expected_keys_for_fixture(fixture)
        path = str(fixture.get("fixture_path", ""))
        cases.append(SuiteCase(
            case_id=f"p2-source-{i:02d}",
            group="source",
            title=f"P2 source fixture: {Path(path).name}",
            description=(
                f"Real detector characterization on {path} "
                f"({DATASET_ID}, line-proximity +-{window})."
            ),
            input_ref=path,
            ground_truth=GroundTruth(expected=expected, universe=None,
                                     synthetic=False),
            tags=("real-fixtures", DATASET_ID),
            note=("Measured fixture labels; not production accuracy."),
        ))
    return cases


class RealDetectorProvider(PredictionProvider):
    """Run the integrated real pipeline per case (total function).

    Predictions are finding keys from actual canonical output with
    files relativized to the repo root when beneath it. Any failure
    yields ok=False (failed entries never score).
    """

    name = "real-detector"

    def __init__(self, repo_root: str | Path | None = None) -> None:
        self.repo_root = str(repo_root or Path.cwd())

    def _key_for(self, rule: str, path: str, line: int) -> str:
        try:
            rel = os.path.relpath(path, self.repo_root)
        except ValueError:
            rel = path
        return finding_key(rule, rel, line)

    def predict(self, case: SuiteCase) -> Prediction:
        from ecdat.adapters.pipeline import RealScanError, run_real_scan

        target = case.input_ref
        if not os.path.isabs(target):
            target = os.path.join(self.repo_root, target)
        try:
            _cir, doc = run_real_scan(target)
        except RealScanError as exc:
            return Prediction(keys=frozenset(), ok=False, error=str(exc),
                              detail={"case_id": case.case_id})
        except Exception as exc:  # noqa: BLE001 - total function
            return Prediction(keys=frozenset(), ok=False,
                              error=f"unexpected: {exc}",
                              detail={"case_id": case.case_id})
        keys = set()
        for finding in doc.get("findings", []) or []:
            try:
                keys.add(self._key_for(
                    str(finding["rule_id"]), str(finding["file"]),
                    int(finding["line"])))
            except (KeyError, TypeError, ValueError):
                continue
        return Prediction(keys=frozenset(keys), ok=True,
                          detail={"case_id": case.case_id,
                                  "scan_id": doc.get("scan_id", "")})


def characterize_detector(
    cases: Iterable[SuiteCase],
    provider: PredictionProvider | None = None,
) -> dict:
    """Run detection characterization; returns metrics + labeling.

    The metrics come solely from evaluate_cases(); this wrapper only
    attaches dataset/method labels so results cannot be mistaken for
    production accuracy.
    """
    provider = provider or RealDetectorProvider()
    evaluated = []
    for case in cases:
        prediction = provider.predict(case)
        evaluated.append(with_predictions(
            case, prediction.keys if prediction.ok else []))
    result = evaluate_cases(evaluated)
    result["characterization"] = {
        "kind": "detection-characterization",
        "dataset": DATASET_ID,
        "provider": provider.name,
        "warning": ("Fixture labels only; not production precision/recall."),
    }
    return result


def measure_performance(
    targets: Iterable[str | Path],
    scanners: list[str] | None = None,
) -> list[dict]:
    """Raw per-target measurements: time, counts, peak RSS. No verdicts."""
    from ecdat.adapters.pipeline import RealScanError, run_real_scan

    rows = []
    for target in targets:
        row: dict = {"target": str(target)}
        try:
            import resource

            rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        except Exception:
            rss_before = None
        started = time.perf_counter()
        try:
            cir, doc = run_real_scan(str(target), scanners=scanners)
        except RealScanError as exc:
            row["error"] = str(exc)
            row["elapsed_s"] = round(time.perf_counter() - started, 3)
            rows.append(row)
            continue
        except Exception as exc:  # noqa: BLE001 - record, don't raise
            row["error"] = f"unexpected: {exc}"
            row["elapsed_s"] = round(time.perf_counter() - started, 3)
            rows.append(row)
            continue
        row["elapsed_s"] = round(time.perf_counter() - started, 3)
        row["findings"] = len(doc.get("findings", []) or [])
        row["assets"] = len(cir.get("assets", []) or [])
        row["operations"] = len(cir.get("operations", []) or [])
        try:
            import resource

            rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            row["peak_rss_kb"] = max(0, rss_after - (rss_before or 0))
        except Exception:
            row["peak_rss_kb"] = None
        rows.append(row)
    return rows
