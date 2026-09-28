"""Command-line interface and command dispatch."""

from __future__ import annotations

import argparse
from pathlib import Path

from ecdat.commands import ci_cmd, export_cmd, gui_cmd, list_cmd, recommend_cmd
from ecdat.commands import report_cmd, risk_cmd, scan_binary_cmd, scan_cloud_cmd
from ecdat.commands import scan_cmd, scan_container_cmd, show_cmd

DEFAULT_DB = str(Path.home() / ".ecdat" / "ecdat.db")
SEVERITIES = ("info", "low", "medium", "high", "critical")
PROFILES = ("quick", "standard", "deep")


def _context_options(parser: argparse.ArgumentParser) -> None:
    """Phase 10 user-supplied risk context (all optional, visibly tagged)."""
    parser.add_argument("--environment", default=None,
                        help="deployment environment (e.g. production, staging)")
    parser.add_argument("--owner", default=None,
                        help="owning team or service owner")
    parser.add_argument("--exposure", default=None,
                        help="exposure (internet-facing, internal, offline, cloud, third-party)")
    parser.add_argument("--business-criticality", "--criticality",
                        dest="business_criticality", default=None,
                        help="business criticality (critical, high, medium, low)")
    parser.add_argument("--data-lifetime", dest="data_lifetime_years",
                        type=float, default=None,
                        help="data confidentiality lifetime in years (Mosca X)")
    parser.add_argument("--migration-years", dest="migration_years",
                        type=float, default=None,
                        help="migration/replacement lead time in years (Mosca Y)")
    parser.add_argument("--risk-z", dest="risk_z", type=float, default=10.0,
                        help="expected years to cryptographically relevant QC (Mosca Z)")


def _common_scan_options(
    parser: argparse.ArgumentParser, *, include_profile: bool = True
) -> None:
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    parser.add_argument("--output", default=None, help="write canonical JSON here")
    parser.add_argument("--scanners", default=None, help="comma-separated scanner subset")
    parser.add_argument("--allow-container", action="store_true")
    parser.add_argument("--allow-cloud", action="store_true")
    parser.add_argument("--allow-runtime", action="store_true")
    parser.add_argument("--cir-out", default=None, help="write CIR JSON here")
    parser.add_argument("--replace", action="store_true",
                        help="overwrite the stored row when this scan ID "
                             "already exists (default: reuse the stored row)")
    _context_options(parser)
    if include_profile:
        parser.add_argument(
            "--profile",
            choices=PROFILES,
            default="standard",
            help="analysis depth (Phase 1: recorded in plan; effort tiers land in Phase 3)",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ecdat", description="ECDAT CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", nargs="?",
                      help="file or directory to scan (or omit with --repo)")
    scan.add_argument("--repo", default=None, metavar="URL",
                      help="public GitHub repository URL "
                           "(https://github.com/<owner>/<repo>); acquired with "
                           "the same downloader as the GUI into a kept temp "
                           "directory, then scanned with the same pipeline")
    _common_scan_options(scan)
    scan.set_defaults(func=scan_cmd.run)

    binary = sub.add_parser("scan-binary", help="scan a binary file")
    binary.add_argument("binary")
    _common_scan_options(binary)
    binary.set_defaults(func=scan_binary_cmd.run)

    container = sub.add_parser("scan-container", help="scan a container image, archive, or rootfs")
    container.add_argument("image_or_path")
    _common_scan_options(container)
    container.add_argument("--allow-pull", action="store_true",
                           help="permit pulling a remote image reference")
    container.add_argument("--allow-build", action="store_true",
                           help="permit building a Dockerfile (reserved)")
    container.set_defaults(func=scan_container_cmd.run)

    cloud = sub.add_parser("scan-cloud", help="scan AWS cloud resources")
    cloud.add_argument("provider", choices=["aws"])
    # NOTE: --profile here is the AWS profile (pre-existing).  Scan depth
    # stays ``standard`` for cloud until Phase 3 differentiates effort.
    cloud.add_argument("--profile", default="default")
    cloud.add_argument("--services", default="kms,acm,elb")
    cloud.add_argument("--region", default=None)
    cloud.add_argument("--aws-access-key-id", default=None,
                       help="explicit AWS access key (prefer env AWS_ACCESS_KEY_ID; never logged or stored)")
    cloud.add_argument("--aws-secret-access-key", default=None,
                       help="explicit AWS secret key (prefer env AWS_SECRET_ACCESS_KEY; never logged or stored)")
    cloud.add_argument("--aws-session-token", default=None,
                       help="optional AWS session token (prefer env AWS_SESSION_TOKEN)")
    cloud.add_argument("--aws-profile", default=None,
                       help="named AWS profile (alternative to explicit keys)")
    _common_scan_options(cloud, include_profile=False)
    cloud.set_defaults(func=scan_cloud_cmd.run)

    listed = sub.add_parser("list", help="list stored scans")
    listed.add_argument("--db", default=DEFAULT_DB)
    listed.add_argument("--limit", type=int, default=100)
    listed.add_argument("--json", action="store_true")
    listed.set_defaults(func=list_cmd.run)

    shown = sub.add_parser("show", help="show one scan and its findings")
    shown.add_argument("scan_id")
    shown.add_argument("--db", default=DEFAULT_DB)
    shown.add_argument("--json", action="store_true")
    shown.set_defaults(func=show_cmd.run)

    risk = sub.add_parser("risk", help="show stored P1 risk posture")
    risk.add_argument("scan_id")
    risk.add_argument("--db", default=DEFAULT_DB)
    risk.add_argument("--json", action="store_true")
    risk.set_defaults(func=risk_cmd.run)

    recommend = sub.add_parser("recommend", help="show stored P1 recommendations")
    recommend.add_argument("scan_id")
    recommend.add_argument("--db", default=DEFAULT_DB)
    recommend.add_argument("--json", action="store_true")
    recommend.add_argument("--severity", choices=SEVERITIES, default=None)
    recommend.set_defaults(func=recommend_cmd.run)

    export = sub.add_parser("export", help="export a stored scan")
    export.add_argument("scan_id")
    export.add_argument("--format", choices=["json", "csv", "cbom-json", "cbom-xml", "sarif"], default="json")
    export.add_argument("--output", default=None)
    export.add_argument("--db", default=DEFAULT_DB)
    export.set_defaults(func=export_cmd.run)

    report = sub.add_parser("report", help="render a stored scan report")
    report.add_argument("scan_id")
    report.add_argument("--format", choices=["markdown", "console", "html", "pdf"], default="markdown")
    report.add_argument("--output", default=None)
    report.add_argument("--db", default=DEFAULT_DB)
    report.set_defaults(func=report_cmd.run)

    gui = sub.add_parser("gui", help="launch the local React GUI API")
    gui.add_argument("--host", default="127.0.0.1")
    gui.add_argument("--port", type=int, default=8734)
    gui.add_argument("--db", default=DEFAULT_DB,
                     help="shared scan database (same default as scan/CI)")
    gui.set_defaults(func=gui_cmd.run)

    ci = sub.add_parser("ci", help="scan a target and enforce a severity threshold")
    ci.add_argument("target")
    ci.add_argument("--db", default=DEFAULT_DB)
    ci.add_argument("--fail-on", choices=SEVERITIES, default=None)
    ci.add_argument("--summary", action="store_true")
    ci.add_argument("--json", action="store_true")
    ci.add_argument("--sarif", default=None, metavar="PATH")
    ci.add_argument("--scanners", default=None)
    ci.add_argument("--allow-container", action="store_true")
    ci.add_argument("--allow-cloud", action="store_true")
    ci.add_argument("--allow-runtime", action="store_true")
    ci.add_argument("--allow-pull", action="store_true")
    ci.add_argument("--allow-build", action="store_true")
    ci.add_argument("--cir-out", default=None)
    ci.add_argument("--replace", action="store_true",
                    help="overwrite the stored row when this scan ID "
                         "already exists (default: reuse the stored row)")
    ci.add_argument("--region", default=None)
    _context_options(ci)
    ci.add_argument(
        "--profile",
        choices=PROFILES,
        default="standard",
        help="analysis depth (Phase 1: recorded in plan; effort tiers land in Phase 3)",
    )
    ci.set_defaults(func=ci_cmd.run)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
