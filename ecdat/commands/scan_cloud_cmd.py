"""Implementation of ``ecdat scan-cloud``."""

from __future__ import annotations

import argparse
import sys

from ecdat.commands import ERROR
from ecdat.commands._real_scan import run_real_and_store


def build_target_label(profile: str, services: str) -> str | None:
    parts = [item.strip() for item in str(services).split(",") if item.strip()]
    if not parts:
        return None
    return f"aws:{profile}:services={','.join(parts)}"


def run(args: argparse.Namespace) -> int:
    target = build_target_label(args.profile, args.services)
    if target is None:
        print("error: --services must list at least one service", file=sys.stderr)
        return ERROR
    # Convenience hint for cloud labels; same orchestrator pipeline as
    # every other surface (Phase 1).  NOTE: args.profile is the AWS
    # profile here, not the scan-depth profile (which stays standard).
    args.scan_profile = "standard"
    return run_real_and_store(args, target, scanners=["cloud"], caller="cli-scan-cloud")
