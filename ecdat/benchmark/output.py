"""Benchmark output renderers (Person 3 platform layer).

`to_json` is the machine-readable contract: stable structure,
sorted keys, indent 2. `to_console` is the human one-line-per-fact
summary. Both restate that mock measurements are engineering-only.
"""

from __future__ import annotations

import json


def to_json(result: dict) -> str:
    """Stable machine-readable JSON. No trailing newline (caller adds it)."""
    return json.dumps(result, indent=2, sort_keys=True)


def from_json(text: str) -> dict:
    """Parse back what to_json produced."""
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("benchmark JSON must decode to an object")
    return obj


def to_console(result: dict) -> str:
    """Human-readable summary. No trailing newline."""
    ds = result["dataset"]
    lines = [
        f"benchmark: {result['benchmark']} (target: {result['target']})",
        f"dataset:   {ds['name']} (seed {ds['seed']}, "
        f"{ds['docs']} docs, {ds['findings']} findings)",
        f"elapsed:   {result['elapsed_s']:.3f}s wall "
        f"({result['throughput']['findings_per_s']:.1f} findings/s)",
        f"success:   {result['success']['ok']}/{result['success']['total']} "
        f"(rate {result['success']['rate']:.2f})",
        f"output:    {result['output_bytes']} bytes rendered",
    ]
    rss = result["resources"]["peak_rss_bytes"]
    cpu = result["resources"]["cpu_s"]
    lines.append(
        "resources: peak RSS "
        + (f"{rss} bytes" if rss is not None else "n/a")
        + ", CPU "
        + (f"{cpu:.3f}s" if cpu is not None else "n/a")
    )
    lines.append(f"accuracy:  {result['accuracy']['status']} — {result['accuracy']['reason']}")
    lines.append("note:      mock engineering measurement only; not detection accuracy.")
    return "\n".join(lines)
