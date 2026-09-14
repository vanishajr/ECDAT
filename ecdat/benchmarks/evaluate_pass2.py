from __future__ import annotations

import gc
import json
import time
import tracemalloc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pytest

from ecdat import create_discovery_engine
from ecdat.scanners.base import normalize_finding
from ecdat.scanners.source import SourceScanner, PythonASTScanner
from ecdat.scanners.dependency import DependencyScanner
from ecdat.scanners.config import ConfigScanner
from ecdat.scanners.certificate import CertificateScanner
from ecdat.scanners.binary import BinaryScanner
from ecdat.scanners.container import ContainerScanner
from ecdat.scanners.runtime import RuntimeScanner
from ecdat.scanners.cloud import CloudScanner
from ecdat.benchmarks.evaluation import (
    GroundTruthRegistry,
    EvaluationEngine,
    export_evaluation_results,
    load_ground_truth_from_json,
)
import statistics


@dataclass
class BenchmarkResult:
    scanner_name: str
    fixture_name: str
    iterations: int
    times: list[float] = field(default_factory=list)
    memory_usage: list[float] = field(default_factory=list)
    finding_counts: list[int] = field(default_factory=list)

    @property
    def mean_time(self) -> float:
        return statistics.mean(self.times) if self.times else 0.0

    @property
    def median_time(self) -> float:
        return statistics.median(self.times) if self.times else 0.0

    @property
    def stdev_time(self) -> float:
        return statistics.stdev(self.times) if len(self.times) > 1 else 0.0

    @property
    def min_time(self) -> float:
        return min(self.times) if self.times else 0.0

    @property
    def max_time(self) -> float:
        return max(self.times) if self.times else 0.0

    @property
    def mean_memory_mb(self) -> float:
        return statistics.mean(self.memory_usage) if self.memory_usage else 0.0

    @property
    def mean_findings(self) -> float:
        return statistics.mean(self.finding_counts) if self.finding_counts else 0.0


class BenchmarkRunner:
    def __init__(self, iterations: int = 10) -> None:
        self.iterations = iterations
        self.results: list = []

    def run_scanner_benchmark(
        self,
        scanner,
        fixture_path: Path,
        scanner_name: str,
        fixture_name: str
    ):
        result = BenchmarkResult(scanner_name=scanner_name, fixture_name=fixture_name, iterations=self.iterations)

        for _ in range(self.iterations):
            gc.collect()
            tracemalloc.start()

            start_time = time.perf_counter()
            findings = scanner.scan(fixture_path)
            end_time = time.perf_counter()

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            elapsed = end_time - start_time
            result.times.append(elapsed)
            result.memory_usage.append(peak / (1024 * 1024))
            result.finding_counts.append(len(findings))

        self.results.append(result)
        return result

    def run_discovery_engine_benchmark(
        self,
        target_dir: Path,
        scanner_names: list[str],
        name: str
    ):
        result = BenchmarkResult(scanner_name="DiscoveryEngine", fixture_name=name, iterations=self.iterations)

        for _ in range(self.iterations):
            gc.collect()
            tracemalloc.start()

            engine = create_discovery_engine(scanner_names)

            start_time = time.perf_counter()
            cir = engine.scan_and_emit_cir(target_dir, target_name=name)
            end_time = time.perf_counter()

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            elapsed = end_time - start_time
            result.times.append(elapsed)
            result.memory_usage.append(peak / (1024 * 1024))
            result.finding_counts.append(cir.stats.asset_count)

        self.results.append(result)
        return result

    def print_results(self) -> None:
        print("\n" + "=" * 80)
        print("BENCHMARK RESULTS")
        print("=" * 80)

        for result in self.results:
            print(f"\nScanner: {result.scanner_name} | Fixture: {result.fixture_name}")
            print(f"  Iterations: {result.iterations}")
            print(f"  Time (mean): {result.mean_time*1000:.2f} ms")
            print(f"  Time (median): {result.median_time*1000:.2f} ms")
            print(f"  Time (stdev): {result.stdev_time*1000:.2f} ms")
            print(f"  Time (min/max): {result.min_time*1000:.2f} / {result.max_time*1000:.2f} ms")
            print(f"  Memory (mean): {result.mean_memory_mb:.2f} MB")
            print(f"  Findings (mean): {result.mean_findings:.1f}")

    def export_json(self, output_path: Path) -> None:
        data = []
        for result in self.results:
            data.append({
                "scanner": result.scanner_name,
                "fixture": result.fixture_name,
                "iterations": result.iterations,
                "mean_time_ms": result.mean_time * 1000,
                "median_time_ms": result.median_time * 1000,
                "stdev_time_ms": result.stdev_time * 1000,
                "min_time_ms": result.min_time * 1000,
                "max_time_ms": result.max_time * 1000,
                "mean_memory_mb": result.mean_memory_mb,
                "mean_findings": result.mean_findings,
                "raw_times": result.times,
                "raw_memory": result.memory_usage,
                "raw_findings": result.finding_counts,
            })
        output_path.write_text(json.dumps(data, indent=2))


class ComprehensiveEvaluator:
    def __init__(self, ground_truth_dir: Path):
        self.ground_truth_dir = ground_truth_dir
        self.registry = load_ground_truth_from_json(ground_truth_dir / "ground_truth.json")
        self.evaluator = EvaluationEngine(self.registry)
        self.results = []
        self.performance_data = []
        self.fixture_base = Path("ecdat/tests/fixtures")

    def run_source_evaluation(self):
        print("\n" + "=" * 80)
        print("SOURCE SCANNER EVALUATION")
        print("=" * 80)

        scanners = {
            "SourceScanner": SourceScanner(),
            "PythonASTScanner": PythonASTScanner(),
        }

        source_fixtures_dir = self.fixture_base / "source"
        results = []

        for scanner_name, scanner in scanners.items():
            if not scanner.is_available():
                print(f"  {scanner_name}: SKIPPED (not available)")
                continue

            print(f"\n  Evaluating {scanner_name}...")

            for fixture_path in sorted(source_fixtures_dir.glob("*.py")):
                if fixture_path.name == "ground_truth.json":
                    continue

                fixture_key = str(fixture_path.resolve().relative_to(Path.cwd())).replace('\\', '/')

                # Skip fixtures without ground truth
                if not self.registry.get(fixture_key):
                    print(f"    {fixture_path.name}: SKIPPED (no ground truth)")
                    continue

                gc.collect()
                tracemalloc.start()

                start_time = time.perf_counter()
                findings = scanner.scan(fixture_path)
                end_time = time.perf_counter()

                current, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()

                elapsed = end_time - start_time
                memory_mb = peak / (1024 * 1024)

                result = self.evaluator.evaluate(findings, fixture_key, scanner_name)
                self.results.append(result)

                self.performance_data.append({
                    "scanner": scanner_name,
                    "fixture": fixture_key,
                    "time_ms": elapsed * 1000,
                    "memory_mb": peak / (1024 * 1024),
                    "findings_count": len(findings),
                })

                print(f"    {fixture_path.name}: TP={result.true_positives}, FP={result.false_positives}, FN={result.false_negatives}, "
                      f"P={result.precision:.2f}, R={result.recall:.2f}, F1={result.f1:.2f}, "
                      f"time={elapsed*1000:.1f}ms, mem={memory_mb:.1f}MB")

        return results

    def run_dependency_evaluation(self):
        print("\n" + "=" * 80)
        print("DEPENDENCY SCANNER EVALUATION")
        print("=" * 80)

        scanner = DependencyScanner()
        if not scanner.is_available():
            print("  DependencyScanner: SKIPPED (not available)")
            return []

        print("\n  Evaluating DependencyScanner...")

        source_fixtures_dir = self.fixture_base / "source"
        results = []

        for fixture_path in sorted(source_fixtures_dir.glob("*.json")):
            fixture_key = str(fixture_path)

            gc.collect()
            tracemalloc.start()

            start_time = time.perf_counter()
            findings = scanner.scan(fixture_path)
            end_time = time.perf_counter()

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            elapsed = end_time - start_time
            memory_mb = peak / (1024 * 1024)

            result = self.evaluator.evaluate(findings, fixture_key, "DependencyScanner")
            self.results.append(result)

            self.performance_data.append({
                "scanner": "DependencyScanner",
                "fixture": fixture_key,
                "time_ms": elapsed * 1000,
                "memory_mb": peak / (1024 * 1024),
                "findings_count": len(findings),
            })

            print(f"    {fixture_path.name}: TP={result.true_positives}, FP={result.false_positives}, FN={result.false_negatives}, "
                  f"P={result.precision:.2f}, R={result.recall:.2f}, F1={result.f1:.2f}, "
                  f"time={elapsed*1000:.1f}ms, mem={memory_mb:.1f}MB")

        return results

    def run_config_evaluation(self):
        print("\n" + "=" * 80)
        print("CONFIG SCANNER EVALUATION")
        print("=" * 80)

        scanner = ConfigScanner()
        if not scanner.is_available():
            print("  ConfigScanner: SKIPPED (not available)")
            return []

        print("\n  Evaluating ConfigScanner...")

        config_fixtures_dir = self.fixture_base / "config"
        results = []

        for fixture_path in sorted(config_fixtures_dir.glob("*")):
            if fixture_path.is_dir():
                continue
            fixture_key = str(fixture_path)

            gc.collect()
            tracemalloc.start()

            start_time = time.perf_counter()
            findings = scanner.scan(fixture_path)
            end_time = time.perf_counter()

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            elapsed = end_time - start_time
            memory_mb = peak / (1024 * 1024)

            result = self.evaluator.evaluate(findings, fixture_key, "ConfigScanner")
            self.results.append(result)

            self.performance_data.append({
                "scanner": "ConfigScanner",
                "fixture": fixture_key,
                "time_ms": elapsed * 1000,
                "memory_mb": peak / (1024 * 1024),
                "findings_count": len(findings),
            })

            print(f"    {fixture_path.name}: TP={result.true_positives}, FP={result.false_positives}, FN={result.false_negatives}, "
                  f"P={result.precision:.2f}, R={result.recall:.2f}, F1={result.f1:.2f}, "
                  f"time={elapsed*1000:.1f}ms, mem={memory_mb:.1f}MB")

        return results

    def run_certificate_evaluation(self):
        print("\n" + "=" * 80)
        print("CERTIFICATE SCANNER EVALUATION")
        print("=" * 80)

        scanner = CertificateScanner()
        if not scanner.is_available():
            print("  CertificateScanner: SKIPPED (not available)")
            return []

        print("\n  Evaluating CertificateScanner...")

        cert_fixtures_dir = self.fixture_base / "certificate"
        results = []

        for fixture_path in sorted(cert_fixtures_dir.glob("*")):
            if fixture_path.is_dir() or fixture_path.name == "generate_fixtures.py":
                continue
            fixture_key = str(fixture_path)

            gc.collect()
            tracemalloc.start()

            start_time = time.perf_counter()
            findings = scanner.scan(fixture_path)
            end_time = time.perf_counter()

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            elapsed = end_time - start_time
            memory_mb = peak / (1024 * 1024)

            result = self.evaluator.evaluate(findings, fixture_key, "CertificateScanner")
            self.results.append(result)

            self.performance_data.append({
                "scanner": "CertificateScanner",
                "fixture": fixture_key,
                "time_ms": elapsed * 1000,
                "memory_mb": peak / (1024 * 1024),
                "findings_count": len(findings),
            })

            print(f"    {fixture_path.name}: TP={result.true_positives}, FP={result.false_positives}, FN={result.false_negatives}, "
                  f"P={result.precision:.2f}, R={result.recall:.2f}, F1={result.f1:.2f}, "
                  f"time={elapsed*1000:.1f}ms, mem={memory_mb:.1f}MB")

        return results

    def run_binary_evaluation(self):
        print("\n" + "=" * 80)
        print("BINARY SCANNER EVALUATION")
        print("=" * 80)

        scanner = BinaryScanner()
        if not scanner.is_available():
            print("  BinaryScanner: SKIPPED (not available)")
            return []

        print("\n  Evaluating BinaryScanner...")

        binary_fixtures_dir = self.fixture_base / "binary"
        results = []

        for fixture_path in sorted(binary_fixtures_dir.glob("*")):
            if fixture_path.is_dir():
                continue
            fixture_key = str(fixture_path)

            gc.collect()
            tracemalloc.start()

            start_time = time.perf_counter()
            findings = scanner.scan(fixture_path)
            end_time = time.perf_counter()

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            elapsed = end_time - start_time
            memory_mb = peak / (1024 * 1024)

            result = self.evaluator.evaluate(findings, fixture_key, "BinaryScanner")
            self.results.append(result)

            self.performance_data.append({
                "scanner": "BinaryScanner",
                "fixture": fixture_key,
                "time_ms": elapsed * 1000,
                "memory_mb": peak / (1024 * 1024),
                "findings_count": len(findings),
            })

            print(f"    {fixture_path.name}: TP={result.true_positives}, FP={result.false_positives}, FN={result.false_negatives}, "
                  f"P={result.precision:.2f}, R={result.recall:.2f}, F1={result.f1:.2f}, "
                  f"time={elapsed*1000:.1f}ms, mem={memory_mb:.1f}MB")

        return results

    def run_container_evaluation(self):
        print("\n" + "=" * 80)
        print("CONTAINER SCANNER EVALUATION")
        print("=" * 80)

        scanner = ContainerScanner()
        if not scanner.is_available():
            print("  ContainerScanner: SKIPPED (not available)")
            return []

        print("\n  Evaluating ContainerScanner...")

        container_fixtures_dir = self.fixture_base / "container"
        results = []

        for fixture_path in sorted(container_fixtures_dir.glob("*")):
            if fixture_path.is_dir():
                continue
            fixture_key = str(fixture_path)

            gc.collect()
            tracemalloc.start()

            start_time = time.perf_counter()
            findings = scanner.scan(fixture_path)
            end_time = time.perf_counter()

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            elapsed = end_time - start_time
            memory_mb = peak / (1024 * 1024)

            result = self.evaluator.evaluate(findings, fixture_key, "ContainerScanner")
            self.results.append(result)

            self.performance_data.append({
                "scanner": "ContainerScanner",
                "fixture": fixture_key,
                "time_ms": elapsed * 1000,
                "memory_mb": peak / (1024 * 1024),
                "findings_count": len(findings),
            })

            print(f"    {fixture_path.name}: TP={result.true_positives}, FP={result.false_positives}, FN={result.false_negatives}, "
                  f"P={result.precision:.2f}, R={result.recall:.2f}, F1={result.f1:.2f}, "
                  f"time={elapsed*1000:.1f}ms, mem={memory_mb:.1f}MB")

        return results

    def run_runtime_evaluation(self):
        print("\n" + "=" * 80)
        print("RUNTIME SCANNER EVALUATION")
        print("=" * 80)

        scanner = RuntimeScanner()
        if not scanner.is_available():
            print("  RuntimeScanner: SKIPPED (not available)")
            return []

        print("\n  Evaluating RuntimeScanner... (SKIPPED - requires network)")
        return []

    def run_cloud_evaluation(self):
        print("\n" + "=" * 80)
        print("CLOUD SCANNER EVALUATION")
        print("=" * 80)

        scanner = CloudScanner()
        if not scanner.is_available():
            print("  CloudScanner: SKIPPED (not available)")
            return []

        print("\n  Evaluating CloudScanner... (SKIPPED - requires credentials)")
        return []

    def run_full_evaluation(self):
        print("\n" + "=" * 80)
        print("COMPREHENSIVE EVALUATION - PASS 2")
        print("=" * 80)

        start_time = time.time()

        self.run_source_evaluation()
        self.run_dependency_evaluation()
        self.run_config_evaluation()
        self.run_certificate_evaluation()
        self.run_binary_evaluation()
        self.run_container_evaluation()
        self.run_runtime_evaluation()
        self.run_cloud_evaluation()

        end_time = time.time()

        return self.generate_summary_report(end_time - start_time)

    def generate_summary_report(self, total_time):
        print("\n" + "=" * 80)
        print("EVALUATION SUMMARY")
        print("=" * 80)

        by_scanner = {}
        for r in self.results:
            if r.scanner_name not in by_scanner:
                by_scanner[r.scanner_name] = []
            by_scanner[r.scanner_name].append(r)

        summary = {
            "total_evaluation_time": total_time,
            "total_fixtures_evaluated": len(self.results),
            "total_scanners_evaluated": len(set(r.scanner_name for r in self.results)),
            "by_scanner": {},
            "overall": {
                "total_tp": sum(r.true_positives for r in self.results),
                "total_fp": sum(r.false_positives for r in self.results),
                "total_fn": sum(r.false_negatives for r in self.results),
            }
        }

        print(f"\nTotal evaluation time: {total_time:.2f}s")
        print(f"Total scanners evaluated: {summary['total_scanners_evaluated']}")
        print(f"Total fixtures evaluated: {summary['total_fixtures_evaluated']}")
        print(f"\nOverall: TP={summary['overall']['total_tp']}, FP={summary['overall']['total_fp']}, FN={summary['overall']['total_fn']}")

        for scanner_name, results in by_scanner.items():
            tp = sum(r.true_positives for r in results)
            fp = sum(r.false_positives for r in results)
            fn = sum(r.false_negatives for r in results)
            prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

            perf = [p for p in self.performance_data if p["scanner"] == scanner_name]
            avg_time = sum(p["time_ms"] for p in perf) / len(perf) if perf else 0
            avg_mem = sum(p["memory_mb"] for p in perf) / len(perf) if perf else 0

            summary["by_scanner"][scanner_name] = {
                "fixtures": len(results),
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
                "fpr": round(fp / (tp + fp) if (tp + fp) > 0 else 0.0, 4),
                "avg_time_ms": round(avg_time, 2),
                "avg_memory_mb": round(avg_mem, 2),
            }

            print(f"\n  {scanner_name}:")
            print(f"    Fixtures: {len(results)}")
            print(f"    TP={tp}, FP={fp}, FN={fn}")
            print(f"    Precision={prec:.2%}, Recall={rec:.2%}, F1={f1:.2%}, FPR={fp/(tp+fp) if (tp+fp)>0 else 0:.2%}")
            print(f"    Avg Time: {avg_time:.1f}ms, Avg Memory: {avg_mem:.1f}MB")

        total_tp = summary["overall"]["total_tp"]
        total_fp = summary["overall"]["total_fp"]
        total_fn = summary["overall"]["total_fn"]
        overall_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
        overall_rec = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
        overall_f1 = 2 * overall_prec * overall_rec / (overall_prec + overall_rec) if (overall_prec + overall_rec) > 0 else 0.0

        summary["overall"]["precision"] = round(overall_prec, 4)
        summary["overall"]["recall"] = round(overall_rec, 4)
        summary["overall"]["f1"] = round(overall_f1, 4)
        summary["overall"]["fpr"] = round(total_fp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0, 4)

        print(f"\n  OVERALL:")
        print(f"    Precision={overall_prec:.2%}, Recall={overall_rec:.2%}, F1={overall_f1:.2%}, FPR={total_fp/(total_tp+total_fp) if (total_tp+total_fp)>0 else 0:.2%}")

        return summary


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Run Pass 2 comprehensive evaluation")
    parser.add_argument("--ground-truth-dir", type=Path, default=Path("ecdat/tests/fixtures/source"),
                        help="Directory containing ground truth JSON")
    parser.add_argument("--output", type=Path, default=Path("evaluation_results.json"),
                        help="Output file for results")
    parser.add_argument("--scanners", nargs="+", help="Specific scanners to evaluate")
    args = parser.parse_args()

    evaluator = ComprehensiveEvaluator(args.ground_truth_dir)
    summary = evaluator.run_full_evaluation()

    export_evaluation_results(evaluator.results, args.output)

    summary_path = args.output.with_stem(args.output.stem + "_summary")
    summary_path.write_text(json.dumps(summary, indent=2))

    print(f"\nDetailed results written to: {args.output}")
    print(f"Summary written to: {summary_path}")

    return summary


if __name__ == "__main__":
    main()