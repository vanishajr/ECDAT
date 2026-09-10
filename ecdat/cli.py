"""ECDATA command-line interface (Person 3 platform layer).

Parser construction + command dispatch only — no business logic.
Each subcommand delegates to ecdat.commands.* which orchestrate the
existing CoreClient and store layers.

Exit codes: 0 success, 1 general error, 2 target not found,
3 validation failure.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ecdat.commands import list_cmd, scan_cmd, show_cmd

DEFAULT_DB = str(Path.home() / ".ecdat" / "ecdat.db")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ecdat", description="ECDATA CLI (Person 3)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a target path (mock by default)")
    p_scan.add_argument("path", help="file or directory to scan")
    p_scan.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    p_scan.add_argument("--output", default=None, help="write canonical JSON here")
    mode = p_scan.add_mutually_exclusive_group()
    mode.add_argument("--mock", action="store_true", help="use MockCoreClient (default)")
    mode.add_argument("--real", action="store_true", help="use RealCoreClient")
    p_scan.set_defaults(func=scan_cmd.run)

    p_list = sub.add_parser("list", help="list stored scans")
    p_list.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    p_list.add_argument("--limit", type=int, default=100, help="max rows")
    p_list.add_argument("--json", action="store_true", help="machine-readable output")
    p_list.set_defaults(func=list_cmd.run)

    p_show = sub.add_parser("show", help="show one scan and its findings")
    p_show.add_argument("scan_id", help="scan id to display")
    p_show.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    p_show.add_argument("--json", action="store_true", help="machine-readable output")
    p_show.set_defaults(func=show_cmd.run)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
