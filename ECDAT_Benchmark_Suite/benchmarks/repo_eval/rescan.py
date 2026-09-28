"""Rescan repo_eval slices -> outputs (run after each recall cluster)."""
import json
import sys
import time

sys.path.insert(0, "D:/Coding/Websites/ECDAT")
from pathlib import Path

from ecdat.core.client import RealCoreClient

BASE = Path("D:/Coding/Websites/ECDAT/ECDAT_Benchmark_Suite/benchmarks/repo_eval")
for repo in ("openssl", "pyca", "nginx", "spring", "express"):
    target = BASE / "slices" / repo
    t0 = time.perf_counter()
    res = RealCoreClient(caller="repo-eval").scan_result(str(target))
    dt = (time.perf_counter() - t0) * 1000
    cir, doc = res.as_tuple()
    (BASE / "outputs" / f"{repo}.canonical.json").write_text(
        json.dumps(doc, indent=1, sort_keys=True))
    (BASE / "outputs" / f"{repo}.cir.json").write_text(
        json.dumps(cir, indent=1, sort_keys=True))
    print(f"{repo}: {dt:.0f}ms findings={len(doc.get('findings', []))} "
          f"assets={len(cir.get('assets', []))} ops={len(cir.get('operations', []))}")
print("done")
