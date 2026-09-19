from __future__ import annotations

import mmap
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only
from ecdat.scanners.binary.crypto_signatures import CRYPTO_STRINGS, CRYPTO_LIBRARIES


class StringsScanner(Scanner[ScannerFinding]):
    name = "binary-strings"
    version = "0.1.0"

    def __init__(self, min_length: int = 4, max_length: int = 1024) -> None:
        self.min_length = min_length
        self.max_length = max_length

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return "strings-builtin"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.is_file():
            return []

        findings: list[ScannerFinding] = []

        try:
            with open(target_path, "rb") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    content = mm.read()
        except Exception:
            try:
                content = target_path.read_bytes()
            except Exception:
                return findings

        strings = self._extract_strings(content)

        for offset, string in strings:
            matched = self._match_crypto_string(string)
            if matched:
                canonical, original = normalize_algorithm(matched)
                category = get_category(canonical)

                if is_library_only(canonical) or category == "library":
                    usage_state = UsageState.PROVIDED_ONLY
                    confidence = 0.2
                else:
                    usage_state = UsageState.POSSIBLE
                    confidence = 0.35

                findings.append(ScannerFinding(
                    canonical=canonical,
                    original=original,
                    usage_state=usage_state,
                    confidence=confidence,
                    evidence=[create_evidence_signal(
                        tool="binary-strings",
                        detail=f"String match at offset 0x{offset:x}: {string[:100]}",
                        confidence=confidence,
                        snippet=string[:200],
                    )],
                    location=Location(file=str(target_path), uri=f"binary-offset:0x{offset:x}"),
                    implementation=Implementation(library="unknown", provider="strings"),
                    context=Context(exposure=Exposure.INTERNAL),
                ))

        for lib_name, info in CRYPTO_LIBRARIES.items():
            if lib_name.lower().encode() in content:
                canonical = info.get("canonical", lib_name)
                category = info.get("category", "library")

                if category == "library":
                    usage_state = UsageState.PROVIDED_ONLY
                    confidence = 0.3
                else:
                    usage_state = UsageState.PROVIDED_ONLY
                    confidence = 0.35

                findings.append(ScannerFinding(
                    canonical=canonical,
                    original=lib_name,
                    library=lib_name,
                    usage_state=usage_state,
                    confidence=confidence,
                    evidence=[create_evidence_signal(
                        tool="binary-strings",
                        detail=f"Library string found: {lib_name}",
                        confidence=confidence,
                        snippet=lib_name,
                    )],
                    location=Location(file=str(target_path), uri=f"binary-lib:{lib_name}"),
                    implementation=Implementation(library=lib_name, provider="strings"),
                    context=Context(exposure=Exposure.INTERNAL),
                ))

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _extract_strings(self, data: bytes) -> list[tuple[int, str]]:
        strings: list[tuple[int, str]] = []
        current = []
        start_offset = 0

        for i, byte in enumerate(data):
            if 32 <= byte <= 126:
                if not current:
                    start_offset = i
                current.append(chr(byte))
            else:
                if len(current) >= self.min_length:
                    s = "".join(current)
                    if len(s) <= self.max_length:
                        strings.append((start_offset, s))
                current = []

        if len(current) >= self.min_length:
            s = "".join(current)
            if len(s) <= self.max_length:
                strings.append((start_offset, s))

        return strings

    def _match_crypto_string(self, string: str) -> str | None:
        from ecdat.scanners.binary.crypto_signatures import (
            is_plausible_crypto_string)
        for pattern, canonical in CRYPTO_STRINGS.items():
            if pattern.lower() in string.lower() and \
                    is_plausible_crypto_string(string, pattern):
                return canonical
        return None
