from pathlib import Path
import json
import yaml

from benchmarks.metrics import precision, recall, f1, match_operation, score_operations
from benchmarks.ground_truth import load_ground_truth


ROOT = Path(__file__).resolve().parents[1]


def test_metric_math():
    assert precision(8, 2) == 0.8
    assert recall(8, 2) == 0.8
    assert round(f1(0.8, 0.8), 3) == 0.8


def test_operation_matcher():
    expected = {"algorithm":"AES","mode":"GCM","key_size":256,"usage":"Confirmed"}
    actual = {"canonical":"AES","mode":"gcm","keySize":256,"usage_state":"confirmed"}
    assert match_operation(expected, actual)


def test_score_operations_reports_fp_fn():
    expected = [{"algorithm":"AES"}]
    actual = [{"algorithm":"AES"}, {"algorithm":"RSA"}]
    score = score_operations(expected, actual)
    assert score["tp"] == 1
    assert score["fp"] == 1
    assert score["fn"] == 0


def test_all_ground_truth_files_parse():
    for path in (ROOT/"benchmarks"/"ground_truth"/"synthetic").glob("*.yaml"):
        gt=load_ground_truth(path)
        assert "fixture" in gt
        assert (ROOT/"benchmarks"/gt["fixture"]).exists()


def test_repo_lock_has_unique_ids_and_urls():
    data=json.loads((ROOT/"benchmarks"/"repo-lock.json").read_text())
    ids=[r["id"] for r in data["repositories"]]
    assert len(ids)==len(set(ids))
    assert all(r["url"].startswith("https://github.com/") for r in data["repositories"])


def test_thresholds_are_not_empty():
    data=yaml.safe_load((ROOT/"benchmarks"/"thresholds.yaml").read_text())
    assert data["synthetic"]["operation_precision_min"] >= 0.9
    assert data["determinism"]["required"] is True
