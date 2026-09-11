"""Merge engine — deduplicates scanner results across tiers.

Lower tier number = higher confidence.  When the same dependency is found
by multiple scanners, the result from the lowest tier wins.

Tier 5 (external tools like syft/trivy) undergoes additional filtering:
- File paths and CI artifacts are removed (not real dependencies)
- Only deps NOT already found by Tier 1-4 are kept (gap-filling mode)
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from embtrace_sbom.analyzer.normalize import normalize_dep_name

if TYPE_CHECKING:
    from embtrace_sbom.analyzer.models import (
        BuildFileArtifact,
        BuildFileDependency,
        BuildFileInternalDep,
    )
    from embtrace_sbom.analyzer.pipeline.base import ScanResult

# Tier 5 noise patterns — deps matching these are filtered out
_TIER5_NOISE = re.compile(
    r"^(?:"
    r"actions/"              # GitHub Actions (actions/checkout, etc.)
    r"|github/"              # GitHub internal
    r"|google/"              # Google OSS-Fuzz actions
    r"|\.github/"            # .github/ workflow files
    r"|/repos/"              # Absolute repo paths
    r"|.*\.(?:yml|yaml|json|txt|toml|lock|gemspec|jar|war|properties|kts|gradle|xml)$"  # Config
    r")",
    re.IGNORECASE,
)


def _is_tier5_noise(name: str) -> bool:
    """Check if a Tier 5 dep name is noise (file paths, CI artifacts)."""
    return bool(_TIER5_NOISE.match(name))


#: Build-script name-token ecosystems — the only place the skip list
#: may drop a dependency (see check/collector.py for the measurement).
_NAME_ONLY_ECOSYSTEMS = frozenset({
    "cmake", "meson", "make", "autotools", "configure", "generic",
})


def _skip_checker() -> Callable[[str], bool] | None:
    """The curated skip list, if the knowledge DB is importable.

    The list (build tools, system libs — 950 curated names like
    ``threads``, ``git``, ``appleframeworks``) was enforced only by
    tier 4; tier 2's structured parsers emitted the same pseudo-deps
    unfiltered into every report (measured: 60+ of the 212 missing
    occurrences in embedded-coverage run #3 were skip-listed names).
    Enforcing it here, in the merge, covers every tier once.
    """
    try:
        from embtrace_sbom.sbom.knowledge_db import is_skipped
    except ImportError:  # pragma: no cover - sbom extra not installed
        return None
    return is_skipped


def merge_results(
    results: list[ScanResult],
) -> tuple[list[BuildFileDependency], list[BuildFileArtifact], list[BuildFileInternalDep]]:
    """Merge scan results from multiple tiers.

    Deduplicates dependencies by normalized name.  The entry from the
    lowest tier (highest confidence) wins.  Version and source_file
    are taken from the winning entry.

    Tier 5 dependencies are filtered: file paths and CI artifacts are
    removed, and only deps not already found by Tier 1-4 are kept.

    Artifacts and internal deps are deduplicated by path/project name.

    Returns:
        Merged (dependencies, artifacts, internal_deps).
    """
    # --- Dependencies: deduplicate by normalized name, lowest tier wins ---
    is_skipped = _skip_checker()

    # First pass: collect Tier 1-4 deps
    dep_best: dict[str, tuple[int, BuildFileDependency]] = {}

    for result in results:
        if result.tier >= 5:
            continue  # handle Tier 5 in second pass
        for dep in result.dependencies:
            if (
                is_skipped is not None
                and getattr(dep, "ecosystem", "") in _NAME_ONLY_ECOSYSTEMS
                and is_skipped(dep.name)
            ):
                continue
            key = normalize_dep_name(dep.name)
            existing = dep_best.get(key)
            if existing is None or result.tier < existing[0]:
                dep_best[key] = (result.tier, dep)

    # Second pass: Tier 5 — only keep non-noise deps not already found
    for result in results:
        if result.tier < 5:
            continue
        for dep in result.dependencies:
            if _is_tier5_noise(dep.name):
                continue
            if (
                is_skipped is not None
                and getattr(dep, "ecosystem", "") in _NAME_ONLY_ECOSYSTEMS
                and is_skipped(dep.name)
            ):
                continue
            key = normalize_dep_name(dep.name)
            if key not in dep_best:
                dep_best[key] = (result.tier, dep)

    merged_deps = [dep for _, dep in sorted(dep_best.values(), key=lambda x: x[1].name.lower())]

    # --- Artifacts: deduplicate by path ---
    seen_paths: set[str] = set()
    merged_artifacts: list[BuildFileArtifact] = []
    for result in sorted(results, key=lambda r: r.tier):
        for art in result.artifacts:
            if art.path not in seen_paths:
                seen_paths.add(art.path)
                merged_artifacts.append(art)

    # --- Internal deps: deduplicate by project name ---
    seen_projects: set[str] = set()
    merged_internal: list[BuildFileInternalDep] = []
    for result in sorted(results, key=lambda r: r.tier):
        for idep in result.internal_deps:
            key = idep.project.lower()
            if key not in seen_projects:
                seen_projects.add(key)
                merged_internal.append(idep)

    return merged_deps, merged_artifacts, merged_internal
