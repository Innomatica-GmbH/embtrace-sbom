"""Tier 4 — Regex-based parsers (adapter for existing parsers/ package).

Wraps the deterministic regex parsers in the TierScanner protocol.
Tier 4, confidence 0.70 — serves as fallback when higher-tier scanners
are unavailable or miss dependencies.

Knowledge DB Integration:
  - Blacklist: names in skip_names → filtered out
  - Whitelist: for C/C++ types, names NOT in packages table → filtered out
  - Confidence boost: names confirmed in packages → 0.85 (vs 0.70 default)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from embtrace_sbom.analyzer.models import BuildFileDependency
from embtrace_sbom.analyzer.parsers import PARSERS
from embtrace_sbom.analyzer.pipeline.base import ScanResult

if TYPE_CHECKING:
    from pathlib import Path

# Map file_type → ecosystem for enrichment routing.
_ECO_MAP: dict[str, str] = {
    "gradle": "maven",
    "maven": "maven",
    "cargo": "cargo",
    "go": "golang",
    "python": "pypi",
    "npm": "npm",
}

# C/C++ file types where whitelist filtering should be applied.
_CPP_TYPES: frozenset[str] = frozenset({
    "cmake", "meson", "autotools", "configure", "make",
})

# Minimum DB entry count for whitelist to be active.
_MIN_DB_ENTRIES_FOR_WHITELIST = 5000


class RegexScanner:
    """Adapter wrapping existing regex parsers as a TierScanner."""

    tier: int = 4
    name: str = "regex"

    def __init__(self) -> None:
        self._parsers = PARSERS
        self._db_ready: bool | None = None
        self._db_lookup: object = None
        self._db_is_skipped: object = None
        self._db_name_exists: object = None
        self._is_skippable_dep: object = None
        self._cmake_to_conan: object = None
        self._whitelist_active: bool = False

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        """Handle any file type that has a regex parser."""
        return file_type in self._parsers

    def _ensure_db(self) -> bool:
        """Lazily import Knowledge DB + enrichment functions."""
        if self._db_ready is not None:
            return self._db_ready
        try:
            from embtrace_sbom.sbom.enrich import _cmake_to_conan, is_skippable_dep
            from embtrace_sbom.sbom.knowledge_db import (
                entry_count,
            )
            from embtrace_sbom.sbom.knowledge_db import (
                is_skipped as db_is_skipped,
            )
            from embtrace_sbom.sbom.knowledge_db import (
                lookup as db_lookup,
            )
            from embtrace_sbom.sbom.knowledge_db import (
                name_exists as db_name_exists,
            )

            self._db_lookup = db_lookup
            self._db_is_skipped = db_is_skipped
            self._db_name_exists = db_name_exists
            self._is_skippable_dep = is_skippable_dep
            self._cmake_to_conan = _cmake_to_conan

            # Only enable whitelist if DB has enough entries
            try:
                count = entry_count()
                self._whitelist_active = count >= _MIN_DB_ENTRIES_FOR_WHITELIST
            except Exception:  # noqa: BLE001
                self._whitelist_active = False

            self._db_ready = True
        except ImportError:
            self._db_ready = False
        return self._db_ready

    def _validate_with_db(
        self, dep_names: list[str], file_type: str,
    ) -> list[tuple[str, float]]:
        """Validate dependency names using blacklist + whitelist.

        Blacklist (all ecosystems):
          - Names in skip_names table → filtered out
          - Names matching is_skippable_dep() → filtered out

        Whitelist (C/C++ types only, when DB has >5000 entries):
          - Names found in packages table → confidence 0.85 (confirmed)
          - Names NOT found anywhere in DB → filtered out (likely false positive)

        Non-C/C++ types:
          - Names found in packages table → confidence 0.85
          - Names not found → confidence 0.70 (kept, parsers are precise)
        """
        if not self._ensure_db():
            return [(n, 0.70) for n in dep_names]

        assert callable(self._db_is_skipped)  # noqa: S101
        assert callable(self._db_lookup)  # noqa: S101
        assert callable(self._db_name_exists)  # noqa: S101
        assert callable(self._is_skippable_dep)  # noqa: S101

        eco = _ECO_MAP.get(file_type, file_type)
        is_cpp = file_type in _CPP_TYPES
        use_whitelist = is_cpp and self._whitelist_active

        result: list[tuple[str, float]] = []
        for name in dep_names:
            # ── Blacklist ─────────────────────────────────────────
            try:
                if self._db_is_skipped(name, ecosystem=eco):
                    continue
            except Exception:  # noqa: BLE001
                pass

            # For C/C++ types, also run is_skippable_dep (hardcoded rules)
            if is_cpp:
                try:
                    if self._is_skippable_dep(name):
                        continue
                except Exception:  # noqa: BLE001
                    pass

            # ── Positive DB lookup (ecosystem-specific) ───────────
            confidence = 0.70
            try:
                hit = self._db_lookup(eco, name)
                if not hit and is_cpp:
                    hit = self._db_lookup("conan", name)
                if hit:
                    confidence = 0.85
            except Exception:  # noqa: BLE001
                hit = None

            # ── Whitelist (C/C++ only) ────────────────────────────
            if use_whitelist and not hit:
                # Name not found under specific ecosystem — check ANY ecosystem
                found_any = False
                try:
                    found_any = self._db_name_exists(name)
                except Exception:  # noqa: BLE001
                    found_any = False

                # Also check via Conan mapping (glib-2.0 → glib)
                if not found_any and callable(self._cmake_to_conan):
                    try:
                        mapped = self._cmake_to_conan(name)
                        if mapped and mapped.lower() != name.lower():
                            found_any = self._db_name_exists(mapped)
                    except Exception:  # noqa: BLE001
                        pass

                if not found_any:
                    continue  # Unknown name, likely false positive

                # Found under a different ecosystem — keep with moderate confidence
                confidence = 0.80

            result.append((name, confidence))

        return result

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        """Parse the file with the matching regex parser."""
        parser = self._parsers.get(file_type)
        if parser is None:
            return ScanResult(tier=self.tier, scanner_name=self.name)

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ScanResult(tier=self.tier, scanner_name=self.name)

        dep_names = parser(content)

        # For auto/lib/NAME/conf files (nginx pattern), add the directory name
        parts = file_path.parts
        if len(parts) >= 3 and parts[-1] == "conf" and parts[-3] == "lib":
            lib_name = parts[-2]
            if lib_name not in dep_names:
                dep_names = [*dep_names, lib_name]

        eco = _ECO_MAP.get(file_type, file_type)

        # Validate against Knowledge DB: blacklist + whitelist
        validated = self._validate_with_db(dep_names, file_type)

        deps = [
            BuildFileDependency(
                name=name,
                ecosystem=eco,
                source_file=str(file_path),
                confidence=confidence,
                tier=self.tier,
                detection_method=f"regex-{file_type}",
            )
            for name, confidence in validated
        ]

        return ScanResult(
            tier=self.tier,
            scanner_name=self.name,
            dependencies=deps,
        )


def get_scanners() -> list[RegexScanner]:
    """Return the regex scanner instance."""
    return [RegexScanner()]
