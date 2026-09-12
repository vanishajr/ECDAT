"""External-baseline adapter framework (Person 3 platform layer).

Lets ECDAT compare its mock pipeline against external/simple baseline
approaches when those tools exist locally — without ever requiring
them, invoking them, or claiming superiority:

    SUITE REGISTRY (suite.py: same seeded cases as the main pipeline)
        -> BASELINE ADAPTER (this module: availability + normalized
           Prediction sets, never metrics of its own)
        -> EVALUATION (ground_truth.evaluate_cases, the single metric
           engine — reused verbatim, never reimplemented)
        -> REPORTING (report.build_report over the same run shape)

Safety rules (non-negotiable):

- Availability is detected with `shutil.which` (PATH lookup) ONLY.
  External tools are never executed, downloaded, installed, or
  contacted; versions are never probed by running anything. An
  unobtainable version is recorded as None with a reason — never
  fabricated.
- No subprocess, no network, no secrets, no writes outside caller-
  chosen output paths, no machine-specific hard-coded paths.
- Statuses stay distinct: a baseline is AVAILABLE or UNAVAILABLE;
  a run is EVALUATED, FAILED, UNAVAILABLE, or NOT_APPLICABLE.
  Unavailable tools are not ECDAT failures and never count as
  evaluated results.
- Deterministic test doubles (MockBaselineAdapter, clearly labeled
  TEST/MOCK) let the whole framework run green with zero external
  tools installed. Mock measurements are never real measurements.
"""

from __future__ import annotations

import platform
import shutil
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Mapping, Protocol, runtime_checkable

from ecdat.benchmark import resources as resources_mod
from ecdat.benchmark.execution import logical_result
from ecdat.benchmark.ground_truth import evaluate_cases
from ecdat.benchmark.predictions import Prediction
from ecdat.benchmark.suite import (
    SUITE_ID,
    SUITE_VERSION,
    SuiteCase,
    get_case,
    list_cases,
)

# Baseline presence on this machine.
AVAILABLE = "available"
UNAVAILABLE = "unavailable"

# Baseline run outcome. EVALUATED/FAILED mirror the per-case
# vocabulary; UNAVAILABLE means the tool was absent (zero cases
# attempted); NOT_APPLICABLE means no attempted case applied.
EVALUATED = "evaluated"
FAILED = "failed"
NOT_APPLICABLE = "not_applicable"

# Policy: external commands are discovered, never invoked.
_NO_SUBPROCESS_NOTE = (
    "no-subprocess policy: executables are located with shutil.which "
    "only and never executed; versions are not probed."
)


class NotApplicableError(Exception):
    """A baseline cannot support this case type. Not a failure."""


@runtime_checkable
class BaselineAdapter(Protocol):
    """Interface every baseline detector implements.

    Predictions reuse the Task 18 `Prediction` shape
    (`finding_key` identity semantics); metrics always come from
    `ground_truth.evaluate_cases`, never from the adapter.
    """

    name: str

    def executables(self) -> tuple[str, ...]:
        """Command names probed with shutil.which (may be empty)."""
        ...

    def supported_groups(self) -> tuple[str, ...] | None:
        """Benchmark groups this baseline applies to; None = all."""
        ...

    def check_availability(self) -> dict:
        """{'available': bool, 'found': str|None, 'reason': str}. Pure."""
        ...

    def describe(self) -> dict:
        """Reproducibility metadata. Pure, JSON-serializable."""
        ...

    def predict(self, case: SuiteCase) -> Prediction:
        """Normalized predictions for one case.

        May raise NotApplicableError for unsupported case types
        (recorded as NOT_APPLICABLE, never as a detection) and may
        raise/return unsuccessful Predictions on failure.
        """
        ...


class CommandBaseline:
    """Base for command-discovered baselines. No execution, ever.

    Availability = first registered executable found on PATH.
    `predict` defaults to abstention: without an invocation policy
    there are no honest predictions to offer, so every case is
    NOT_APPLICABLE rather than a fabricated empty detection set.
    Deterministic test doubles override `predict` with canned sets.
    """

    name = "command-baseline"
    _executables: tuple[str, ...] = ()
    _supported_groups: tuple[str, ...] | None = None
    _family_note = ""

    def executables(self) -> tuple[str, ...]:
        return tuple(self._executables)

    def supported_groups(self) -> tuple[str, ...] | None:
        return (tuple(self._supported_groups)
                if self._supported_groups is not None else None)

    def check_availability(self) -> dict:
        for exe in self._executables:
            found = shutil.which(exe)
            if found is not None:
                return {"available": True, "found": found,
                        "reason": f"executable {exe!r} found on PATH"}
        if not self._executables:
            return {"available": False, "found": None,
                    "reason": "library-only baseline family; no executable "
                              "to discover (" + _NO_SUBPROCESS_NOTE + ")"}
        probed = ", ".join(repr(e) for e in self._executables)
        return {"available": False, "found": None,
                "reason": f"none of {probed} found on PATH"}

    def describe(self) -> dict:
        availability = self.check_availability()
        return {
            "baseline": self.name,
            "family_note": self._family_note,
            "executables": list(self._executables),
            "found": availability["found"],
            "available": availability["available"],
            "availability_reason": availability["reason"],
            "version": None,
            "version_note": "version not probed (" + _NO_SUBPROCESS_NOTE + ")",
            "command_identity": (
                [self._executables[0], "--version"] if self._executables
                else []),
            "command_identity_note": (
                "identity string only; never executed"),
            "supported_groups": (list(self._supported_groups)
                                 if self._supported_groups is not None
                                 else None),
            "test_double": False,
            "policy": _NO_SUBPROCESS_NOTE,
        }

    def predict(self, case: SuiteCase) -> Prediction:  # noqa: ARG002
        raise NotApplicableError(
            "external invocation disabled by policy; no honest predictions "
            "available (see describe()['policy'])")


def _family(name: str, executables: tuple[str, ...], note: str,
            groups: tuple[str, ...] | None = None) -> type[CommandBaseline]:
    """Define one registered baseline family without behavior drift."""
    return type(name, (CommandBaseline,), {
        "name": name,
        "_executables": executables,
        "_supported_groups": groups,
        "_family_note": note,
    })


_GrepRipgrep = _family(
    "grep-ripgrep", ("rg", "grep"),
    "Pattern-matching source baseline (ripgrep preferred, grep fallback).")
_CbomkitSonar = _family(
    "cbomkit-sonar", ("cbomkit", "sonar-scanner"),
    "CBOM/Sonar-style source-analysis baseline family.")
_Cdxgen = _family(
    "cdxgen", ("cdxgen",),
    "SBOM-generator baseline family (CycloneDX output).")
_SyftTrivy = _family(
    "syft-trivy", ("syft", "trivy"),
    "Container/filesystem scanner baseline family.")
_StringsObjdump = _family(
    "strings-objdump", ("strings", "objdump"),
    "Binary string/disassembly inspection baseline family.")
_LiefOnly = _family(
    "lief-only", (),
    "LIEF library-only baseline family; Python library, no executable.")
_YaraOnly = _family(
    "yara-only", ("yara",),
    "YARA rule-matching baseline family.")

_REGISTRY: dict[str, type[CommandBaseline]] = {
    "grep-ripgrep": _GrepRipgrep,
    "cbomkit-sonar": _CbomkitSonar,
    "cdxgen": _Cdxgen,
    "syft-trivy": _SyftTrivy,
    "strings-objdump": _StringsObjdump,
    "lief-only": _LiefOnly,
    "yara-only": _YaraOnly,
}


def list_baselines() -> list[str]:
    """Registered baseline family names, sorted for determinism."""
    return sorted(_REGISTRY)


def get_baseline(name: str) -> BaselineAdapter:
    """Instantiate one registered baseline. Unknown names raise ValueError."""
    try:
        return _REGISTRY[name]()
    except KeyError:
        raise ValueError(
            f"unknown baseline: {name!r} "
            f"(registered: {', '.join(list_baselines())})") from None


@dataclass
class MockBaselineAdapter:
    """Deterministic TEST/MOCK baseline double. Never a real measurement.

    `predictions` maps case_id -> exact finding keys; `errors` maps
    case_id -> failure message; `not_applicable` lists abstained
    case_ids. `available=False` simulates a missing tool end to end.
    """

    name: str = "mock-baseline (TEST/MOCK)"
    predictions: Mapping[str, Iterable[str]] = field(default_factory=dict)
    errors: Mapping[str, str] = field(default_factory=dict)
    not_applicable: Iterable[str] = field(default_factory=tuple)
    available: bool = True

    def executables(self) -> tuple[str, ...]:
        return ()

    def supported_groups(self) -> tuple[str, ...] | None:
        return None

    def check_availability(self) -> dict:
        if self.available:
            return {"available": True, "found": None,
                    "reason": "TEST/MOCK double: always available"}
        return {"available": False, "found": None,
                "reason": "TEST/MOCK double: simulated missing tool"}

    def describe(self) -> dict:
        availability = self.check_availability()
        return {
            "baseline": self.name,
            "family_note": "TEST/MOCK double; not a real baseline measurement",
            "executables": [],
            "found": None,
            "available": availability["available"],
            "availability_reason": availability["reason"],
            "version": "0-test",
            "version_note": "TEST/MOCK double version label",
            "command_identity": [],
            "command_identity_note": "TEST/MOCK double; nothing to invoke",
            "supported_groups": None,
            "test_double": True,
            "policy": _NO_SUBPROCESS_NOTE,
        }

    def predict(self, case: SuiteCase) -> Prediction:
        if case.case_id in set(self.not_applicable):
            raise NotApplicableError("TEST/MOCK double: abstained "
                                     f"for {case.case_id}")
        if case.case_id in self.errors:
            return Prediction(keys=frozenset(), ok=False,
                              error=self.errors[case.case_id])
        return Prediction(
            keys=frozenset(self.predictions.get(case.case_id, frozenset())))


def _failed_entry(case: SuiteCase, error: str) -> dict:
    return {
        "case_id": case.case_id,
        "group": case.group,
        "status": FAILED,
        "predicted": None,
        "error": error,
        "counts": None,
        "metrics": None,
        "synthetic": case.ground_truth.synthetic,
    }


def _na_entry(case: SuiteCase, reason: str) -> dict:
    return {
        "case_id": case.case_id,
        "group": case.group,
        "status": NOT_APPLICABLE,
        "predicted": None,
        "error": None,
        "reason": reason,
        "counts": None,
        "metrics": None,
        "synthetic": case.ground_truth.synthetic,
    }


def _resolve_cases(group: str | None,
                   case_ids: Iterable[str] | None) -> list[SuiteCase]:
    """Same seeded registry selection the main pipeline uses."""
    if case_ids is not None:
        seen: list[str] = []
        for cid in case_ids:
            if cid not in seen:
                seen.append(cid)
        cases: list[SuiteCase] = []
        for cid in seen:
            case = get_case(cid)
            if case is None:
                raise ValueError(f"unknown benchmark case id: {cid!r}")
            cases.append(case)
        return cases
    return list_cases(group)


def evaluate_baseline(adapter: BaselineAdapter,
                      group: str | None = None,
                      case_ids: Iterable[str] | None = None) -> dict:
    """Evaluate registered cases with a baseline adapter. Pure
    (availability probes and `predict` calls excepted).

    Per case in registry order: normalized predictions are bridged
    with `with_predictions` and scored by `evaluate_cases` — the
    existing metric engine, reused verbatim. Failures and
    abstentions contribute no counts. Fully deterministic and
    JSON-serializable. Unavailable adapters attempt zero cases.
    """
    from ecdat.benchmark.suite import with_predictions

    requested = list(case_ids) if case_ids is not None else None
    availability = adapter.check_availability()
    if not availability["available"]:
        accuracy = evaluate_cases([])
        return {
            "suite_id": SUITE_ID,
            "version": SUITE_VERSION,
            "baseline": adapter.name,
            "availability": availability,
            "status": UNAVAILABLE,
            "selection": {"group": group, "case_ids": requested,
                          "resolved": []},
            "case_count": 0,
            "evaluated_n": 0,
            "failed_n": 0,
            "not_applicable_n": 0,
            "cases": [],
            "totals": accuracy["totals"],
            "aggregate": accuracy["aggregate"],
            "synthetic": True,
            "note": ("Baseline unavailable: "
                     f"{availability['reason']}. Zero cases attempted; "
                     "not counted as evaluated. Synthetic fixtures only; "
                     "no detector accuracy is claimed."),
        }
    cases = _resolve_cases(group, requested)
    supported = adapter.supported_groups()
    if supported is not None:
        cases = [c for c in cases if c.group in supported]
    evaluated: list = []
    failed: dict[str, dict] = {}
    not_applicable: dict[str, dict] = {}
    for case in cases:
        try:
            prediction = adapter.predict(case)
        except NotApplicableError as exc:
            not_applicable[case.case_id] = _na_entry(case, str(exc))
            continue
        except Exception as exc:  # noqa: BLE001 - recorded, run continues
            failed[case.case_id] = _failed_entry(
                case, f"{type(exc).__name__}: {exc}")
            continue
        if not prediction.ok:
            failed[case.case_id] = _failed_entry(
                case, prediction.error or "baseline reported failure")
            continue
        evaluated.append(with_predictions(case, prediction.keys))

    accuracy = evaluate_cases(evaluated)
    by_id = {c["case_id"]: c for c in accuracy["cases"]}

    def _predicted_of(case: SuiteCase) -> list[str]:
        for candidate in evaluated:
            if candidate.case_id == case.case_id:
                return sorted(candidate.predicted)
        return []

    ordered: list[dict] = []
    for case in cases:
        if case.case_id in failed:
            ordered.append(failed[case.case_id])
            continue
        if case.case_id in not_applicable:
            ordered.append(not_applicable[case.case_id])
            continue
        entry = by_id[case.case_id]
        ordered.append({
            "case_id": entry["case_id"],
            "group": entry["group"],
            "status": EVALUATED,
            "predicted": _predicted_of(case),
            "error": None,
            "counts": entry["counts"],
            "metrics": entry["metrics"],
            "synthetic": entry["synthetic"],
        })
    status = (EVALUATED if evaluated
              else (NOT_APPLICABLE if not_applicable else FAILED))
    return {
        "suite_id": SUITE_ID,
        "version": SUITE_VERSION,
        "baseline": adapter.name,
        "availability": availability,
        "status": status,
        "selection": {"group": group, "case_ids": requested,
                      "resolved": [c["case_id"] for c in ordered]},
        "case_count": len(ordered),
        "evaluated_n": len(evaluated),
        "failed_n": len(failed),
        "not_applicable_n": len(not_applicable),
        "cases": ordered,
        "totals": accuracy["totals"],
        "aggregate": accuracy["aggregate"],
        "synthetic": all(c.ground_truth.synthetic for c in cases),
        "note": ("Baseline evaluation over normalized predictions. "
                 "Failed and not-applicable cases contribute no counts. "
                 "Synthetic fixtures only; no detector accuracy is claimed."),
    }


def run_baseline(adapter: BaselineAdapter,
                 *,
                 group: str | None = None,
                 case_ids: Iterable[str] | None = None,
                 metadata: dict | None = None) -> dict:
    """Execute a baseline selection with run metadata. Only timing and
    resources are measured (via the existing resources module); logical
    content stays reproducible — use `logical_result` to compare runs.
    """
    requested = list(case_ids) if case_ids is not None else None
    cpu_start = resources_mod.cpu_times()
    wall_start = resources_mod.now_wall()
    started_at = datetime.now(timezone.utc).isoformat()
    evaluation = evaluate_baseline(adapter, group=group,
                                   case_ids=requested)
    elapsed_s = resources_mod.now_wall() - wall_start
    return {
        "run_id": f"baseline-run-{uuid.uuid4().hex[:8]}",
        "engine": "ecdat-benchmark-baseline",
        "engine_version": "1",
        "started_at": started_at,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "suite_id": evaluation["suite_id"],
        "suite_version": evaluation["version"],
        "provider": evaluation["baseline"],
        "baseline": evaluation["baseline"],
        "baseline_metadata": adapter.describe(),
        "availability": evaluation["availability"],
        "status": evaluation["status"],
        "selection": evaluation["selection"],
        "case_count": evaluation["case_count"],
        "evaluated_n": evaluation["evaluated_n"],
        "failed_n": evaluation["failed_n"],
        "not_applicable_n": evaluation["not_applicable_n"],
        "elapsed_s": elapsed_s,
        "resources": resources_mod.collect(cpu_start, wall_start),
        "totals": evaluation["totals"],
        "aggregate": evaluation["aggregate"],
        "cases": evaluation["cases"],
        "synthetic": evaluation["synthetic"],
        "metadata": dict(metadata or {}),
        "note": ("Baseline execution over normalized predictions. "
                 "Timing/resources measured on this machine for this run; "
                 "logical content (see logical_result) is reproducible. "
                 + evaluation["note"]),
    }


def to_console(run: dict) -> str:
    """Human-readable baseline summary. Metrics only when evaluated."""
    avail = run["availability"]
    lines = [
        f"baseline:  {run['baseline']}",
        f"status:    {run['status']} "
        f"({'available' if avail['available'] else 'unavailable'}: "
        f"{avail['reason']})",
        f"cases:     {run['case_count']} total, "
        f"{run['evaluated_n']} evaluated, {run['failed_n']} failed, "
        f"{run['not_applicable_n']} not applicable",
    ]
    if run["evaluated_n"] == 0:
        lines.append("metrics:   not evaluated — no baseline measurements "
                     "fabricated.")
    else:
        agg = run["aggregate"]
        lines.append(
            "metrics:   precision="
            f"{agg['precision'] if agg['precision'] is not None else 'n/a'} "
            f"recall={agg['recall'] if agg['recall'] is not None else 'n/a'} "
            f"F1={agg['f1'] if agg['f1'] is not None else 'n/a'}")
    lines.append(f"synthetic: {str(run['synthetic']).lower()} — fixtures "
                 f"only; no detector accuracy claimed.")
    return "\n".join(lines)


def logical_json(run: dict) -> str:
    """Stable JSON of the reproducible logical result. Pure.

    Reuses `execution.logical_result` (volatile run_id/timestamps/
    timing stripped) and the existing `output.to_json` contract —
    the same bytes for the same baseline + selection, every run.
    """
    from ecdat.benchmark import output as output_mod

    return output_mod.to_json(logical_result(run))
