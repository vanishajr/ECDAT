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

from ecdat.commands import export_cmd, list_cmd, recommend_cmd, report_cmd
from ecdat.commands import ci_cmd, demo_cmd, gui_cmd, risk_cmd, scan_binary_cmd, scan_cloud_cmd, scan_cmd
from ecdat.commands import scan_container_cmd, show_cmd

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

    p_risk = sub.add_parser("risk", help="show mock risk summary for a stored scan")
    p_risk.add_argument("scan_id", help="scan id to assess")
    p_risk.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    p_risk.add_argument("--json", action="store_true", help="machine-readable output")
    p_risk.set_defaults(func=risk_cmd.run)

    p_rec = sub.add_parser("recommend", help="show mock placeholder recommendations for a stored scan")
    p_rec.add_argument("scan_id", help="scan id to recommend for")
    p_rec.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    p_rec.add_argument("--json", action="store_true", help="machine-readable output")
    p_rec.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"], default=None, help="filter recommendations by severity")
    p_rec.set_defaults(func=recommend_cmd.run)

    p_exp = sub.add_parser("export", help="export a stored scan to json/csv/cbom/sarif")
    p_exp.add_argument("scan_id", help="scan id to export")
    p_exp.add_argument("--format", choices=["json", "csv", "cbom-json", "cbom-xml", "sarif"], default="json", help="export format")
    p_exp.add_argument("--output", default=None, help="write export to this file (default: stdout)")
    p_exp.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    p_exp.set_defaults(func=export_cmd.run)

    p_rep = sub.add_parser("report", help="render a report for a stored scan")
    p_rep.add_argument("scan_id", help="scan id to report on")
    p_rep.add_argument("--format", choices=["markdown", "console", "html", "pdf"], default="markdown", help="report format")
    p_rep.add_argument("--output", default=None, help="write report to this file (default: stdout; required for pdf)")
    p_rep.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    p_rep.set_defaults(func=report_cmd.run)

    p_gui = sub.add_parser("gui", help="launch local mock GUI dashboard (127.0.0.1 only)")
    p_gui.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    p_gui.add_argument("--host", default="127.0.0.1", help="loopback host to bind (default: 127.0.0.1)")
    p_gui.add_argument("--port", type=int, default=8734, help="port to bind (0 = OS selects)")
    p_gui.set_defaults(func=gui_cmd.run)

    p_ci = sub.add_parser("ci", help="mock-first CI gate: scan a target and enforce a severity threshold")
    p_ci.add_argument("target", help="file or directory to scan")
    p_ci.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    p_ci.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"], default=None, help="fail when a finding at/above this severity exists (default: report only, always pass)")
    p_ci.add_argument("--summary", action="store_true", help="print concise human summary (default output)")
    p_ci.add_argument("--json", action="store_true", help="print machine-readable JSON to stdout instead of the human summary")
    p_ci.add_argument("--sarif", default=None, metavar="PATH", help="write SARIF via the existing Task 7 exporter to PATH (stdout still carries summary/JSON)")
    mode_ci = p_ci.add_mutually_exclusive_group()
    mode_ci.add_argument("--mock", action="store_true", help="use MockCoreClient (default)")
    mode_ci.add_argument("--real", action="store_true", help="use RealCoreClient")
    p_ci.set_defaults(func=ci_cmd.run)

    p_demo = sub.add_parser("demo", help="seed a demo workspace and launch the local mock GUI")
    p_demo.add_argument("--db", default=None, help="SQLite DB path (default: fresh temp demo workspace)")
    p_demo.add_argument("--host", default="127.0.0.1", help="loopback host to bind (default: 127.0.0.1)")
    p_demo.add_argument("--port", type=int, default=8734, help="port to bind (0 = OS selects)")
    p_demo.set_defaults(func=demo_cmd.run)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
