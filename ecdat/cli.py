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

from ecdat.commands import list_cmd, scan_binary_cmd, scan_cloud_cmd
from ecdat.commands import scan_cmd, scan_container_cmd, show_cmd

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

    p_bin = sub.add_parser("scan-binary", help="scan a binary file (mock by default)")
    p_bin.add_argument("binary", help="binary file to scan")
    p_bin.add_argument("--deep", choices=["auto"], default="auto", help="deep-scan mode (reserved, mock ignores it)")
    p_bin.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    p_bin.add_argument("--output", default=None, help="write canonical JSON here")
    mode_bin = p_bin.add_mutually_exclusive_group()
    mode_bin.add_argument("--mock", action="store_true", help="use mock fixture (default)")
    mode_bin.add_argument("--real", action="store_true", help="use RealCoreClient")
    p_bin.set_defaults(func=scan_binary_cmd.run)

    p_ctr = sub.add_parser("scan-container", help="scan a container image or rootfs path (mock by default)")
    p_ctr.add_argument("image_or_path", help="container image reference (e.g. nginx:1.25) or local path")
    p_ctr.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    p_ctr.add_argument("--output", default=None, help="write canonical JSON here")
    mode_ctr = p_ctr.add_mutually_exclusive_group()
    mode_ctr.add_argument("--mock", action="store_true", help="use mock fixture (default)")
    mode_ctr.add_argument("--real", action="store_true", help="use RealCoreClient")
    p_ctr.set_defaults(func=scan_container_cmd.run)

    p_cld = sub.add_parser("scan-cloud", help="scan a cloud provider (mock by default)")
    p_cld.add_argument("provider", choices=["aws"], help="cloud provider (only aws for now)")
    p_cld.add_argument("--profile", default="default", help="cloud profile/account label")
    p_cld.add_argument("--services", default="kms,acm,elb", help="comma-separated services, e.g. kms,acm,elb")
    p_cld.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    p_cld.add_argument("--output", default=None, help="write canonical JSON here")
    mode_cld = p_cld.add_mutually_exclusive_group()
    mode_cld.add_argument("--mock", action="store_true", help="use mock fixture (default)")
    mode_cld.add_argument("--real", action="store_true", help="use RealCoreClient")
    p_cld.set_defaults(func=scan_cloud_cmd.run)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
