"""Person 3 benchmarking workstream (platform layer).

FOUNDATION — engineering/performance measurements of the mock
pipeline only. Nothing here measures detection accuracy:

- Datasets (`datasets.py`) are deterministic seeded canonical docs.
  They carry NO ground-truth labels, so precision/recall/F1/accuracy
  are unavailable by design (see `metrics.accuracy_status`).
- Targets (`targets.py`) implement the `BenchmarkTarget` Protocol.
  `MockPipelineTarget` exercises validate -> store -> export/report
  today; `RealCoreClient`, real discovery outputs, grep/ripgrep and
  other baselines plug in later behind the same interface without
  rewriting the framework. The framework never imports Person 1 code.
- `runner.py` times runs and records success/failure/output size.
- `resources.py` reports peak RSS / CPU time via stdlib only, with
  explicit `None` + note where the platform cannot provide them.
  Values are never faked.
- `output.py` renders stable JSON (`to_json`) and a console summary.

Real detection-accuracy benchmarking connects after Person 1/Person 2
integration, once datasets carry ground-truth labels.
"""
