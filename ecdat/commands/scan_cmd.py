"""Implementation of ``ecdat scan``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ecdat.commands import TARGET_NOT_FOUND
from ecdat.commands._real_scan import run_real_and_store


def run(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"error: target not found: {target}", file=sys.stderr)
        return TARGET_NOT_FOUND
    # Generic scan: no scanner hint (orchestrator resolves the default
    # local set).  Same pipeline as every other surface (Phase 1).
    return run_real_and_store(args, target, caller="cli-scan")
