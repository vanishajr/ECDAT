"""Standalone benchmark entry point: python -m ecdat.benchmark ...

Deliberately separate from the production `ecdat` CLI so benchmark
execution never mixes with normal scan/export/report behavior:

    python -m ecdat.benchmark list
    python -m ecdat.benchmark run [--dataset {small,medium,large,all}]
        [--output PATH] [--db PATH]
    python -m ecdat.benchmark cases [--group GROUP] [--json]
    python -m ecdat.benchmark suite-run [--group GROUP] [--json]
        [--output PATH] [--html PATH] [--csv PATH]
    python -m ecdat.benchmark baselines [--json]
    python -m ecdat.benchmark suite-run [--baseline NAME] ...
        (evaluate one registered baseline instead of the mock provider)

`run` prints the console summary and, with --output, writes the
stable JSON result. Exit 0 unless a benchmark run itself fails.
`suite-run` executes the registered synthetic case suite against an
empty mock provider (no predictions supplied) and reports the
evaluation; it demonstrates the execution machinery, never detector
accuracy. `--html`/`--csv` write rendered report artifacts.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ecdat.benchmark import charts as charts_mod
from ecdat.benchmark import datasets as datasets_mod
from ecdat.benchmark import execution as execution_mod
from ecdat.benchmark import output as output_mod
from ecdat.benchmark import pdf as pdf_mod
from ecdat.benchmark import render as render_mod
from ecdat.benchmark import report as report_mod
from ecdat.benchmark import runner as runner_mod
from ecdat.benchmark import suite as suite_mod
from ecdat.benchmark.predictions import MockPredictionProvider


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
    p_cases = sub.add_parser("cases", help="list registered benchmark cases")
    p_cases.add_argument(
        "--group", choices=suite_mod.list_groups(), default=None,
        help="filter by group (default: all groups)",
    )
    p_cases.add_argument(
        "--json", action="store_true",
        help="machine-readable suite JSON on stdout (no other stdout text)",
    )
    p_suite = sub.add_parser(
        "suite-run", help="execute the synthetic case suite (mock provider)")
    p_suite.add_argument(
        "--group", choices=suite_mod.list_groups(), default=None,
        help="run one group only (default: full suite)",
    )
    p_suite.add_argument(
        "--json", action="store_true",
        help="machine-readable run JSON on stdout (no other stdout text)",
    )
    p_suite.add_argument("--output", default=None, help="write JSON result here")
    p_suite.add_argument("--html", default=None, metavar="PATH",
                         help="write rendered HTML report here")
    p_suite.add_argument("--csv", default=None, metavar="PATH",
                         help="write rendered CSV sections here "
                              "(<stem>-<section>.csv per table)")
    p_suite.add_argument("--charts", default=None, metavar="DIR",
                         help="write static SVG charts here "
                              "(<section>.svg per chart)")
    p_suite.add_argument("--pdf", default=None, metavar="PATH",
                         help="write benchmark PDF report here")
    p_suite.add_argument("--baseline", default=None, metavar="NAME",
                         help="evaluate one registered baseline "
                              "(see baselines) instead of the mock provider")
    sub.add_parser("baselines", help="list registered baseline adapters "
                                     "with local availability").add_argument(
        "--json", action="store_true",
        help="machine-readable registry JSON on stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list":
        for name in datasets_mod.list_datasets():
            spec = datasets_mod.DATASET_SPECS[name]
            print(f"{name}: {spec[0]} docs x {spec[1]} findings (seed {spec[2]})")
        return 0
    if args.command == "cases":
        # Case definitions only: no detector runs, no metrics claimed.
        suite = suite_mod.get_default_suite()
        if args.group is not None:
            suite = {**suite,
                      "cases": [c for c in suite["cases"]
                                if c["group"] == args.group],
                      "case_count": len([c for c in suite["cases"]
                                         if c["group"] == args.group])}
        if args.json:
            print(output_mod.to_json(suite))
        else:
            for case in suite["cases"]:
                print(f"{case['case_id']} [{case['group']}] {case['title']} "
                      f"(synthetic={str(case['synthetic']).lower()})")
            print(f"{suite['case_count']} case(s), all synthetic fixtures; "
                  f"no detector evaluated.")
        return 0
    if args.command == "baselines":
        # Registry + PATH discovery only: nothing is executed.
        from ecdat.benchmark import baselines as baselines_mod
        rows = [baselines_mod.get_baseline(name).describe()
                for name in baselines_mod.list_baselines()]
        if args.json:
            print(output_mod.to_json({"baselines": rows}))
        else:
            for row in rows:
                state = ("AVAILABLE" if row["available"] else "UNAVAILABLE")
                print(f"{row['baseline']}: {state} — "
                      f"{row['availability_reason']}")
            print(f"{len(rows)} baseline(s); unavailable tools are not "
                  f"failures, just unevaluated.")
        return 0
    if args.command == "suite-run":
        if args.baseline is not None:
            return _suite_run_baseline(args)
        # Empty mock provider: demonstrates execution + honest
        # unavailable metrics. Never detector accuracy.
        run = execution_mod.run_suite(MockPredictionProvider(),
                                      group=args.group)
        if args.json:
            print(execution_mod.to_json(run))
        else:
            print(execution_mod.to_console(run))
        if args.output:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(execution_mod.to_json(run) + "\n")
        if args.html or args.csv:
            report = report_mod.build_report(run)
            if args.html:
                out = Path(args.html)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(render_mod.render_html(report) + "\n")
            if args.csv:
                out = Path(args.csv)
                out.parent.mkdir(parents=True, exist_ok=True)
                for section, text in render_mod.render_csv_sections(
                        report).items():
                    out.with_name(
                        f"{out.stem}-{section}{out.suffix or '.csv'}"
                    ).write_text(text + "\n")
        if args.charts:
            report = report_mod.build_report(run)
            charts_mod.write_charts(report, args.charts)
        if args.pdf:
            report = report_mod.build_report(run)
            pdf_mod.write_pdf(report, args.pdf)
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


def _suite_run_baseline(args: argparse.Namespace) -> int:
    """Evaluate one registered baseline over the suite selection."""
    from ecdat.benchmark import baselines as baselines_mod

    try:
        adapter = baselines_mod.get_baseline(args.baseline)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    run = baselines_mod.run_baseline(adapter, group=args.group)
    if args.json:
        print(baselines_mod.logical_json(run))
    else:
        print(baselines_mod.to_console(run))
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(baselines_mod.logical_json(run) + "\n")
    # HTML/CSV/charts/PDF reuse the existing report pipeline; the
    # provider is labeled mock for test doubles, unknown otherwise —
    # never "real", so no accuracy can be implied.
    if args.html or args.csv or args.charts or args.pdf:
        report = report_mod.build_report(
            run, provider_type=("mock" if adapter.describe()["test_double"]
                                else "unknown"))
        if args.html:
            out = Path(args.html)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(render_mod.render_html(report) + "\n")
        if args.csv:
            out = Path(args.csv)
            out.parent.mkdir(parents=True, exist_ok=True)
            for section, text in render_mod.render_csv_sections(
                    report).items():
                out.with_name(
                    f"{out.stem}-{section}{out.suffix or '.csv'}"
                ).write_text(text + "\n")
        if args.charts:
            charts_mod.write_charts(report, args.charts)
        if args.pdf:
            pdf_mod.write_pdf(report, args.pdf)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
