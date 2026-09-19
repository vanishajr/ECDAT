"""Real-risk display projection (Person 3 platform layer).

Reads P1 wire risks from a stored enriched CIR and projects the
aggregate posture the GUI/CLI render. No scoring happens here — the
numbers are P1's, verbatim.

Wire risk shape (P1 ``to_cir_risk``): {risk_id, class (Critical|High|
Medium|Low|Informational), title, confidence, operation_id, asset_id?,
score 0..10, description, rationale}.
"""

from __future__ import annotations

REAL_MODEL_NOTE = (
    "P1 quantum/classical risk engine: Mosca-style score per operation "
    "(0.35*Q + 0.20*E + 0.15*B + 0.15*C + 0.15*mosca_boost, clamped 0..1, "
    "wire scale 0..10); classes Critical >= 8, High >= 6, Medium >= 4, "
    "Low >= 2, else Informational. ProvidedOnly caps at Low; suppressed "
    "states score 0.0 Informational."
)

_LEVEL_FOR_CLASS = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}


def summarize_wire_risks(
    risks: list[dict], finding_count: int
) -> dict:
    """Aggregate posture from P1 wire risks.

    Posture = highest risk (P1 returns score-desc; ties already broken
    by operation_id upstream). Score is the wire 0..10 value, rounded
    to 2 decimals. No finding counts are invented: ``finding_count``
    is passed in from the canonical document.
    """
    valid = [r for r in risks if isinstance(r, dict)]
    if not valid:
        return {
            "score": 0.0,
            "level": "none",
            "finding_count": finding_count,
            "risk_count": 0,
            "model": REAL_MODEL_NOTE,
            "source": "p1-risk",
        }
    top = valid[0]
    try:
        score = round(min(10.0, max(0.0, float(top.get("score", 0.0)))), 2)
    except (TypeError, ValueError):
        score = 0.0
    cls = str(top.get("class", "Informational"))
    level = _LEVEL_FOR_CLASS.get(cls, "info")
    return {
        "score": score,
        "level": level,
        "finding_count": finding_count,
        "risk_count": len(valid),
        "model": REAL_MODEL_NOTE,
        "source": "p1-risk",
    }


def class_for_operation(risks: list[dict], operation_id: str) -> str | None:
    """Wire risk class for one operation ID, or None when unscored."""
    for record in risks:
        if isinstance(record, dict) and str(record.get("operation_id")) == operation_id:
            cls = str(record.get("class", ""))
            return cls if cls in _LEVEL_FOR_CLASS else None
    return None
