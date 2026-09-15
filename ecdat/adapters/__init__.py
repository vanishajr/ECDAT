"""P3-owned integration adapters (Person 3 platform layer).

All three-way integration logic lives here — never in vendored P1/P2
modules (read-only reference) and never in presentation code:

    scanner_policy : which P2 scanners run by default / opt-in
    normalize      : deterministic IDs, timestamps, files_scanned,
                     asset-only finding synthesis (pure helpers)
    pipeline       : ONE logical real scan (P2 CIR -> P1 stages -> canonical)
    risk_view      : real-risk display projection (no new scoring)
    migration_adapter : P1 internal recs -> P3 migration envelope
    graph_adapter  : CIR wire graph -> P3 GUI graph vocabulary

Every adapter fails loudly on invalid input. No mock fallback anywhere.
"""

from __future__ import annotations
