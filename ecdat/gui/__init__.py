"""Localhost GUI layer (Person 3 platform layer).

Mock-first vertical slice: target selection -> scan-plan preview ->
simulated staged progress -> basic inventory/results.

Seams (same independence contract as the CLI):
- service.py talks to the CoreClient Protocol (MockCoreClient by
  default), the SQLite store, and existing report aggregation.
- server.py is HTTP/routing/static-HTML only (stdlib http.server).
- No Person 1 / Person 2 imports, no network calls except the local
  127.0.0.1 GUI server itself. No new dependencies.
"""
