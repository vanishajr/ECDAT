from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only
from ecdat.scanners.binary.crypto_signatures import CRYPTO_SYMBOLS, CRYPTO_STRINGS, CRYPTO_LIBRARIES


class LIEFScanner(Scanner[ScannerFinding]):
    name = "binary-lief"
    version = "0.1.0"

    def __init__(self) -> None:
        self._lief_available = self._check_lief()

    def _check_lief(self) -> bool:
        try:
            import lief
            return True
        except ImportError:
            return False

    def is_available(self) -> bool:
        return self._lief_available

    def get_tool_version(self) -> str:
        try:
            import lief
            return f"lief-{lief.__version__}"
        except Exception:
            return "lief-unknown"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        if not self._lief_available:
            return []

        target_path = Path(target)
        if not target_path.is_file():
            return []

        findings: list[ScannerFinding] = []

        try:
            import lief
            binary = lief.parse(str(target_path))
            if binary is None:
                return []

            findings.extend(self._scan_imports(binary, target_path))
            findings.extend(self._scan_symbols(binary, target_path))
            findings.extend(self._scan_strings(binary, target_path))
            findings.extend(self._scan_libraries(binary, target_path))

        except Exception:
            pass

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _scan_imports(self, binary, target_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            imports = binary.imports
        except Exception:
            return findings

        for imp in imports:
            lib_name = imp.name.lower()
            for symbol in imp.entries:
                sym_name = symbol.name.lower()
                matched = self._match_crypto_symbol(sym_name, lib_name)
                if matched:
                    canonical, original = normalize_algorithm(matched)
                    category = get_category(canonical)

                    if is_library_only(canonical) or category == "library":
                        usage_state = UsageState.PROVIDED_ONLY
                        confidence = 0.3
                    else:
                        usage_state = UsageState.PROBABLE
                        confidence = 0.55

                    findings.append(ScannerFinding(
                        canonical=canonical,
                        original=original,
                        library=lib_name,
                        usage_state=usage_state,
                        confidence=confidence,
                        evidence=[create_evidence_signal(
                            tool="binary-lief",
                            detail=f"Imported symbol: {symbol.name} from {imp.name}",
                            confidence=confidence,
                            snippet=f"{imp.name}:{symbol.name}",
                        )],
                        location=Location(file=str(target_path), uri=f"binary-import:{imp.name}:{symbol.name}"),
                        implementation=Implementation(library=imp.name, api=symbol.name, provider="lief"),
                        context=Context(exposure=Exposure.INTERNAL),
                    ))
        return findings

    def _scan_symbols(self, binary, target_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            symbols = binary.symbols
        except Exception:
            return findings

        for symbol in symbols:
            sym_name = symbol.name.lower()
            matched = self._match_crypto_symbol(sym_name, "")
            if matched:
                canonical, original = normalize_algorithm(matched)
                category = get_category(canonical)

                if is_library_only(canonical) or category == "library":
                    usage_state = UsageState.PROVIDED_ONLY
                    confidence = 0.3
                else:
                    usage_state = UsageState.PROBABLE
                    confidence = 0.55

                findings.append(ScannerFinding(
                    canonical=canonical,
                    original=original,
                    usage_state=usage_state,
                    confidence=confidence,
                    evidence=[create_evidence_signal(
                        tool="binary-lief",
                        detail=f"Exported symbol: {symbol.name}",
                        confidence=confidence,
                        snippet=symbol.name,
                    )],
                    location=Location(file=str(target_path), uri=f"binary-symbol:{symbol.name}"),
                    implementation=Implementation(library="unknown", api=symbol.name, provider="lief"),
                    context=Context(exposure=Exposure.INTERNAL),
                ))
        return findings

    def _scan_strings(self, binary, target_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            strings = binary.strings
        except Exception:
            return findings

        for s in strings:
            if len(s) < 4:
                continue
            matched = self._match_crypto_string(s)
            if matched:
                canonical, original = normalize_algorithm(matched)
                category = get_category(canonical)

                if is_library_only(canonical) or category == "library":
                    usage_state = UsageState.PROVIDED_ONLY
                    confidence = 0.25
                else:
                    usage_state = UsageState.POSSIBLE
                    confidence = 0.4

                findings.append(ScannerFinding(
                    canonical=canonical,
                    original=original,
                    usage_state=usage_state,
                    confidence=confidence,
                    evidence=[create_evidence_signal(
                        tool="binary-lief",
                        detail=f"String match: {s[:100]}",
                        confidence=confidence,
                        snippet=s[:200],
                    )],
                    location=Location(file=str(target_path), uri=f"binary-string:{hash(s) & 0xffffffff:x}"),
                    implementation=Implementation(library="unknown", provider="lief"),
                    context=Context(exposure=Exposure.INTERNAL),
                ))
        return findings

    def _scan_libraries(self, binary, target_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            libraries = binary.libraries
        except Exception:
            return findings

        for lib in libraries:
            lib_lower = lib.lower()
            for crypto_lib, info in CRYPTO_LIBRARIES.items():
                if crypto_lib.lower() in lib_lower:
                    canonical = info.get("canonical", crypto_lib)
                    category = info.get("category", "library")

                    if category == "library":
                        usage_state = UsageState.PROVIDED_ONLY
                        confidence = 0.35
                    else:
                        usage_state = UsageState.PROVIDED_ONLY
                        confidence = 0.4

                    findings.append(ScannerFinding(
                        canonical=canonical,
                        original=lib,
                        library=lib,
                        usage_state=usage_state,
                        confidence=confidence,
                        evidence=[create_evidence_signal(
                            tool="binary-lief",
                            detail=f"Linked library: {lib}",
                            confidence=confidence,
                            snippet=lib,
                        )],
                        location=Location(file=str(target_path), uri=f"binary-lib:{lib}"),
                        implementation=Implementation(library=lib, provider="lief"),
                        context=Context(exposure=Exposure.INTERNAL),
                    ))
        return findings

    def _match_crypto_symbol(self, symbol: str, lib: str) -> str | None:
        for pattern, canonical in CRYPTO_SYMBOLS.items():
            if pattern.lower() in symbol:
                return canonical
        return None

    def _match_crypto_string(self, string: str) -> str | None:
        for pattern, canonical in CRYPTO_STRINGS.items():
            if pattern.lower() in string.lower():
                return canonical
        return None