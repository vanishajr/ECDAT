"""Standalone benchmark entry point: python -m ecdat.benchmark ...

Deliberately separate from the production `ecdat` CLI so benchmark
execution never mixes with normal scan/export/report behavior:

    python -m ecdat.benchmark list
    python -m ecdat.benchmark run [--dataset {small,medium,large,all}]
        [--output PATH] [--db PATH]

`run` prints the console summary and, with --output, writes the
stable JSON result. Exit 0 unless a benchmark run itself fails.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ecdat.benchmark import datasets as datasets_mod
from ecdat.benchmark import output as output_mod
from ecdat.benchmark import runner as runner_mod


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ecdat.benchmark", description="ECDAT mock-pipeline benchmarks"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list available datasets")
    p_run = sub.add_parser("run", help="run mock-pipeline benchmarks")
    p_run.add_argument(
        "--dataset",
        choices=[*datasets_mod.list_datasets(), "all"],
        default="small",
        help="dataset to run (default: small)",
    )
    p_run.add_argument("--output", default=None, help="write JSON result here")
    p_run.add_argument(
        "--db", default=None, help="explicit SQLite DB (default: fresh temp DB)"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list":
        for name in datasets_mod.list_datasets():
            spec = datasets_mod.DATASET_SPECS[name]
            print(f"{name}: {spec[0]} docs x {spec[1]} findings (seed {spec[2]})")
        return 0
    names = datasets_mod.list_datasets() if args.dataset == "all" else [args.dataset]
    rc = 0
    for name in names:
        result = runner_mod.run_benchmark(name, db_path=args.db)
        print(output_mod.to_console(result))
        if args.output:
            out = Path(args.output)
            if len(names) > 1:
                out = out.with_name(f"{out.stem}-{name}{out.suffix or '.json'}")
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(output_mod.to_json(result) + "\n")
        if result["success"]["rate"] < 1.0:
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
