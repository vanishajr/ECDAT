# Install

Copy:

```text
benchmarks/
tests/test_benchmark_framework.py
```

into the ECDAT repository root.

Then:

```bash
pip install -r benchmarks/requirements.txt
python benchmarks/tools/pin_repos.py
pytest -q tests/test_benchmark_framework.py
python -m benchmarks.runner --mode fast
```

The repository runner uses the existing production `ScanRequest` + `ScanOrchestrator`.
If current project signatures differ, edit only `benchmarks/ecdat_adapter.py`.
