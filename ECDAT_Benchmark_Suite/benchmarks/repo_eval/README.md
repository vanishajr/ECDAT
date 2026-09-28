# Real-repo evaluation (EVAL) — openssl / pyca / nginx / spring / express

Op-level precision/recall on bounded slices of 5 pinned open-source repos
(72 annotated ops; `express` is a negative control). See `docs/BENCHMARKS.md`
§6.4 for the full write-up (headline: P 96.4% / R 37.5% / F1 54.0%).

## Layout

- `eval_repos.lock.json` — repos, pinned SHAs, slice paths, frozen results.
- `slices/<repo>/` — copied slice files (content-identical to the pinned SHAs).
- `outputs/<repo>.{canonical,cir}.json` — committed ECDAT scan outputs
  (`standard` profile) so scoring needs no re-scan.
- `ground_truth/EVAL-*.yaml` — annotated ops. Tiers: `strict` (canonical must
  match, size-insensitive), `dyn` (algorithm genuinely dynamic; location
  only), `file` (pyca presence), `file-strict` (pyca attribution),
  `config` (expected-canonical coverage items; clean FN when absent).
- `score.py` → `REPORT.json` — matcher (same file, ±15 lines, many-to-many
  grouping credit) + per-repo/aggregate P/R/F1.

## Re-run

```bash
python ECDAT_Benchmark_Suite/benchmarks/repo_eval/score.py
```

To re-scan (same SHAs): shallow-clone per `eval_repos.lock.json`, copy the
listed slice paths over `slices/<repo>/`, run each through
`RealCoreClient.scan_result()` into `outputs/`, then re-score.
