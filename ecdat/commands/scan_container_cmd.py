"""Implementation of ``ecdat scan-container``."""

from __future__ import annotations

import argparse
import sys

from ecdat.commands import TARGET_NOT_FOUND
from ecdat.commands._real_scan import run_real_and_store


def run(args: argparse.Namespace) -> int:
    target = str(args.image_or_path).strip()
    if not target:
        print("error: target not found: container target is empty", file=sys.stderr)
        return TARGET_NOT_FOUND
    # Convenience hint for image/rootfs/tar targets; same orchestrator
    # pipeline as every other surface (Phase 1).
    return run_real_and_store(
        args, target, scanners=["container", "binary", "config"], caller="cli-scan-container"
    )
