"""Benchmark targets (Person 3 platform layer).

Architecture:

    Benchmark runner -> BenchmarkTarget interface -> MockCoreClient today
                                                        RealCoreClient later

Targets implement the `BenchmarkTarget` Protocol (`name` + `run`).
`MockPipelineTarget` exercises the existing mock pipeline
(validate -> persist -> export/report) per canonical doc. Future
targets — real CoreClient, real discovery outputs, grep/ripgrep
baselines, other comparison tools — plug in behind the same
interface; the framework never imports Person 1 code directly.
"""

from __future__ import annotations

import sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from ecdat.commands import export_cmd
from ecdat.core.validate import validate
from ecdat.reports import aggregate, markdown
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore


@dataclass(frozen=True)
class RunContext:
    """Per-run context handed to targets. Fresh temp DB by default."""

    db_path: Path
    run_id: str


@dataclass(frozen=True)
class TargetResult:
    """What a target reports for one doc. JSON-serializable via asdict()."""

    ok: bool
    output_bytes: int
    detail: dict = field(default_factory=dict)


@runtime_checkable
class BenchmarkTarget(Protocol):
    """Interface every benchmark target implements."""

    name: str

    def run(self, doc: dict, ctx: RunContext) -> TargetResult:
        """Process one validated canonical doc. May raise on failure."""
        ...


class MockPipelineTarget:
    """Today's target: validate -> SQLite -> export/report, all mock.

    Inserts are idempotent (fixture scan_ids repeat across runs), so
    repeated benchmark runs never corrupt the database.
    """

    name = "mock-pipeline"

    def run(self, doc: dict, ctx: RunContext) -> TargetResult:
        validate(doc)
        ctx.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = db.open_db(ctx.db_path)
        try:
            try:
                sstore.insert_scan(conn, doc)
                fstore.insert_findings_for_scan(conn, doc)
            except sqlite3.IntegrityError:
                conn.rollback()  # already stored by an earlier run: reuse
        finally:
            conn.close()
        rendered = [
            export_cmd.render(doc, "json"),
            export_cmd.render(doc, "csv"),
            markdown.to_markdown(aggregate.build_report(doc)),
        ]
        output_bytes = sum(len(text.encode("utf-8")) for text in rendered)
        return TargetResult(
            ok=True,
            output_bytes=output_bytes,
            detail={"scan_id": doc["scan_id"], "formats": ["json", "csv", "markdown"]},
        )


def asdict_result(result: TargetResult) -> dict:
    """TargetResult -> plain JSON-serializable dict."""
    return asdict(result)
