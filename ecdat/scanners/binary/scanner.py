from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, ScannerRegistry
from ecdat.scanners.binary.lief_scanner import LIEFScanner
from ecdat.scanners.binary.strings_scanner import StringsScanner
from ecdat.scanners.binary.yara_scanner import YARAScanner
from ecdat.scanners.path_policy import iter_project_files


def re_strings(text: str, minimum: int = 4) -> list[str]:
    """Printable-string split shared by the signatures stage."""
    import re as _re
    return [s for s in _re.split(r"[^ -~]+", text or "") if len(s) >= minimum]


class BinaryScanner(Scanner[ScannerFinding]):
    name = "binary"
    version = "0.2.0"

    def __init__(self) -> None:
        self._scanners: list[Scanner] = []
        self._reports: list = []
        self._stage_times: dict[str, float] = {}
        self._init_scanners()

    def _init_scanners(self) -> None:
        self._scanners.append(StringsScanner())
        lief = LIEFScanner()
        if lief.is_available():
            self._scanners.append(lief)
        yara = YARAScanner()
        if yara.is_available():
            self._scanners.append(yara)

    def is_available(self) -> bool:
        return len(self._scanners) > 0

    def get_tool_version(self) -> str:
        versions = [s.get_tool_version() for s in self._scanners]
        return f"binary-v{self.version}({','.join(versions)})"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        """Staged scan: cheap pass for every binary, expensive only for
        escalation candidates (Phase 6)."""
        import time as _time
        from ecdat.scanners.binary import stages as _stages

        target_path = Path(target)
        if not target_path.exists():
            return []
        self._reports = []
        self._stage_times = {}

        # Phase 2/6 inventory routing: scan only inventory-confirmed
        # binaries when artifact records are passed; else own walk.
        allowed: set[str] | None = None
        artifacts = kwargs.get("artifacts")
        if artifacts:
            allowed = set()
            for item in artifacts:
                if isinstance(item, dict):
                    if item.get("category") == "binary":
                        allowed.add(str(item.get("abs_path", "")))
                else:
                    if getattr(item, "category", "") == "binary":
                        allowed.add(str(getattr(item, "abs_path", "")))

        escalation_allowed = kwargs.get("escalation_allowed", True)
        if escalation_allowed is None:
            escalation_allowed = True
        expensive = kwargs.get("expensive_backends", ("capa", "floss"))
        requested = tuple(str(b).strip().lower() for b in
                          (expensive or ()) if str(b).strip())

        if target_path.is_file():
            binaries = [target_path] if self._is_binary_file(target_path) else []
        else:
            binaries = self._find_binary_files(target_path)
        if allowed is not None:
            binaries = [b for b in binaries if str(b) in allowed]

        all_findings: list[ScannerFinding] = []
        for binary_file in sorted(binaries):
            cheap_findings: list[ScannerFinding] = []
            cheap_start = _time.monotonic()
            for scanner in self._scanners:
                try:
                    findings = scanner.scan(binary_file, **kwargs)
                    cheap_findings.extend(findings)
                except Exception:
                    continue
            sig_findings = self._signature_findings(binary_file)
            cheap_findings.extend(sig_findings)
            cheap_time = _time.monotonic() - cheap_start

            signals = _stages.analyze_cheap(binary_file, cheap_findings)
            signals.stage_times["cheap"] = round(cheap_time, 3)
            if any(f.evidence and f.evidence[0].tool == "binary-signatures"
                   and "constant" in f.evidence[0].detail
                   for f in sig_findings):
                signals.has_constant_evidence = True
            if any(f.evidence and f.evidence[0].tool == "binary-signatures"
                   and "OID" in f.evidence[0].detail
                   for f in sig_findings):
                signals.has_oid_evidence = True

            decision = _stages.decide_escalation(
                signals, allowed=bool(escalation_allowed))
            expensive_statuses: list = []
            merged = list(cheap_findings)
            if decision.escalate:
                exp_start = _time.monotonic()
                for status, extra in self._run_expensive(
                        binary_file, signals, requested):
                    expensive_statuses.append(status)
                    merged.extend(self._dedupe(merged, extra))
                signals.stage_times["expensive"] = round(
                    _time.monotonic() - exp_start, 3)
            else:
                for backend in requested:
                    expensive_statuses.append(_stages.ExpensiveStatus(
                        backend=backend, status="skipped",
                        detail="not an escalation candidate"))
            from ecdat.scanners.binary.stages import BinaryStageReport
            self._reports.append(BinaryStageReport(
                signals=signals, escalation=decision,
                expensive=expensive_statuses))
            all_findings.extend(merged)

        self._stage_times = self._summarize_times()
        return all_findings

    def last_report(self) -> dict:
        """Structured staging record of the most recent scan (Phase 6)."""
        from ecdat.scanners.binary import stages as _stages
        reports = [r.as_dict() for r in self._reports]
        candidates = sum(1 for r in self._reports if r.escalation.reasons
                         and r.escalation.reasons != ["no-crypto-evidence"]
                         and r.escalation.reasons != ["cheap-pass-conclusive"])
        escalated = sum(1 for r in self._reports if r.escalation.escalate)
        expensive_runs = sum(
            1 for r in self._reports for e in r.expensive
            if e.status == "success")
        tools = dict(_stages.expensive_tool_status())
        tools.update({s.name: ("available" if s.is_available() else "unavailable")
                      for s in self._scanners})
        return {
            "binaries": reports,
            "summary": {
                "binaries": len(self._reports),
                "with_findings": sum(
                    1 for r in self._reports if r.signals.finding_count > 0),
                "cheap_pass_candidates": candidates,
                "escalated_binaries": escalated,
                "expensive_runs": expensive_runs,
                "expensive_analysis_rate": round(
                    expensive_runs / len(self._reports), 3)
                if self._reports else 0.0,
                "stage_times": dict(self._stage_times),
            },
            "tools": tools,
        }

    def _summarize_times(self) -> dict[str, float]:
        totals: dict[str, float] = {}
        for report in self._reports:
            for stage, secs in report.signals.stage_times.items():
                totals[stage] = round(totals.get(stage, 0.0) + float(secs), 3)
        return totals

    @staticmethod
    def _dedupe(existing: list, extra: list) -> list:
        seen = set()
        for finding in existing:
            try:
                loc = finding.location
                seen.add((finding.canonical,
                          str(getattr(loc, "uri", "") or ""),
                          finding.evidence[0].tool if finding.evidence else ""))
            except Exception:
                continue
        fresh = []
        for finding in extra:
            try:
                loc = finding.location
                key = (finding.canonical,
                       str(getattr(loc, "uri", "") or ""),
                       finding.evidence[0].tool if finding.evidence else "")
            except Exception:
                continue
            if key not in seen:
                seen.add(key)
                fresh.append(finding)
        return fresh

    def _signature_findings(self, binary_file: Path) -> list:
        """Cheap signatures stage: constants, OIDs, symbol-shaped strings."""
        from ecdat.scanners.base import ScannerFinding, create_evidence_signal
        from ecdat.core.cir_models import (
            Location, Implementation, Context, UsageState, Exposure)
        from ecdat.core.signature_registry import normalize_algorithm
        from ecdat.scanners.binary import stages as _stages

        findings: list = []
        try:
            if binary_file.stat().st_size > 64 * 1024 * 1024:
                return findings
            data = binary_file.read_bytes()
        except Exception:
            return findings
        try:
            text = data.decode("ascii", errors="ignore")
        except Exception:
            text = ""
        for canonical, offset in _stages.match_constants(data):
            canonical_norm, _original = normalize_algorithm(canonical)
            findings.append(ScannerFinding(
                canonical=canonical_norm, original=canonical,
                usage_state=UsageState.PROBABLE, confidence=0.6,
                evidence=[create_evidence_signal(
                    tool="binary-signatures",
                    detail=f"crypto constant match ({canonical}) "
                           f"at offset 0x{offset:x}",
                    confidence=0.6,
                    snippet=f"{canonical} constant @0x{offset:x}")],
                location=Location(file=str(binary_file),
                                  uri=f"binary-offset:0x{offset:x}"),
                implementation=Implementation(library="unknown",
                                              provider="signatures"),
                context=Context(exposure=Exposure.INTERNAL),
            ))
        for canonical, form in _stages.match_oids(data, text):
            canonical_norm, _original = normalize_algorithm(canonical)
            findings.append(ScannerFinding(
                canonical=canonical_norm, original=canonical,
                usage_state=UsageState.PROBABLE, confidence=0.6,
                evidence=[create_evidence_signal(
                    tool="binary-signatures",
                    detail=f"crypto OID match ({canonical}, {form} form)",
                    confidence=0.6,
                    snippet=f"{canonical} OID ({form})")],
                location=Location(file=str(binary_file),
                                  uri="binary-oid:" + canonical),
                implementation=Implementation(library="unknown",
                                              provider="signatures"),
                context=Context(exposure=Exposure.INTERNAL),
            ))
        strings = re_strings(text)
        for canonical, symbol in _stages.match_symbol_strings(strings):
            canonical_norm, _original = normalize_algorithm(canonical)
            findings.append(ScannerFinding(
                canonical=canonical_norm, original=canonical,
                usage_state=UsageState.POSSIBLE, confidence=0.5,
                evidence=[create_evidence_signal(
                    tool="binary-signatures",
                    detail=f"crypto symbol string: {symbol[:100]}",
                    confidence=0.5,
                    snippet=symbol[:200])],
                location=Location(file=str(binary_file),
                                  uri="binary-symbol-string:" + symbol[:60]),
                implementation=Implementation(library="unknown",
                                              provider="signatures"),
                context=Context(exposure=Exposure.INTERNAL),
            ))
        return findings

    def _run_expensive(self, binary_file: Path, signals, requested: tuple):
        """Candidate-only expensive backends (yields (status, findings))."""
        from ecdat.scanners.binary import stages as _stages

        run_capa = "capa" in requested
        run_floss = "floss" in requested or (
            "floss-selective" in requested and (
                signals.packed in ("yes", "suspected")
                or (signals.strings_only and signals.finding_count > 0)))
        if run_capa:
            status, extra, secs = _stages.run_capa(binary_file)
            yield _stages.ExpensiveStatus(
                backend="capa", status=status,
                detail="behavior rules over candidate binary"
                if status == "success" else status,
                finding_count=len(extra), elapsed_sec=secs), extra
        elif "capa" in requested:
            yield _stages.ExpensiveStatus(
                backend="capa", status="skipped",
                detail="not requested for this profile"), []
        if run_floss:
            status, extra, secs = _stages.run_floss(binary_file)
            yield _stages.ExpensiveStatus(
                backend="floss", status=status,
                detail="decoded-string re-match over candidate binary"
                if status == "success" else status,
                finding_count=len(extra), elapsed_sec=secs), extra
        elif "floss" in requested or "floss-selective" in requested:
            yield _stages.ExpensiveStatus(
                backend="floss", status="skipped",
                detail="selective gate: no packing/obfuscation signal"), []
        if "ghidra-optional" in requested or "ghidra" in requested:
            tools = _stages.expensive_tool_status()
            if tools.get("ghidra") == "configured":
                yield _stages.ExpensiveStatus(
                    backend="ghidra", status="not-configured",
                    detail="deep-only backend requires explicit headless "
                           "configuration; recorded, not executed"), []
            else:
                yield _stages.ExpensiveStatus(
                    backend="ghidra", status="not-configured",
                    detail="Ghidra not installed/configured"), []

    def _is_binary_file(self, path: Path) -> bool:
        if path.suffix.lower() in {".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".o", ".a", ".lib"}:
            return True
        if path.suffix.lower() in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".zip", ".tar", ".gz", ".pdf"}:
            return False
        try:
            with open(path, "rb") as f:
                chunk = f.read(1024)
                if b"\x00" in chunk:
                    return True
        except Exception:
            pass
        return False

    def _find_binary_files(self, root: Path) -> list[Path]:
        binaries: list[Path] = []
        for path in iter_project_files(root):
            if self._is_binary_file(path):
                binaries.append(path)
        return binaries


ScannerRegistry.register(BinaryScanner())
