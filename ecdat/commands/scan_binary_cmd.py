"""Implementation of ``ecdat scan-binary``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ecdat.commands import TARGET_NOT_FOUND
from ecdat.commands._real_scan import run_real_and_store


def run(args: argparse.Namespace) -> int:
    target = Path(args.binary)
    if not target.exists():
        print(f"error: target not found: {target}", file=sys.stderr)
        return TARGET_NOT_FOUND
    # Convenience hint for an explicit binary target; same orchestrator
    # pipeline as every other surface (Phase 1).
    return run_real_and_store(args, target, scanners=["binary"], caller="cli-scan-binary")
