"""Deterministic export renderers (Person 3 platform layer).

All renderers are pure functions: validated canonical v1 dict in,
text out. No DB, no CLI, no network, no new dependencies (stdlib
only). Source of truth is always the canonical document from
get_scan_doc() — never flattened findings rows (those drop
snippet/metadata).

CBOM/SARIF here are a minimal/mock subset honestly derivable from
canonical v1, pending richer CIR from Person 1. Do NOT present them
as certified spec-complete output.
"""
