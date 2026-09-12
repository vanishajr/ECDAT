"""Deterministic report engine (Person 3 platform layer).

Pure functions over a validated canonical v1 dict. No DB, no CLI,
no network, no new dependencies (stdlib only). Canonical JSON is the
only source of truth. Risk/migration sections reuse the Task 6 mock
helpers and are labeled mock/placeholder throughout.
"""
