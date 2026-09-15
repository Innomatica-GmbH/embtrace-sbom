"""Multi-tier scanner pipeline for build-file dependency detection.

Orchestrates multiple tiers of scanners (CLI tools, structured parsers,
tree-sitter, regex, external SBOM tools) and merges results by confidence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from embtrace_sbom.analyzer.pipeline.base import ScanResult, TierScanner
from embtrace_sbom.analyzer.pipeline.merge import merge_results
from embtrace_sbom.core.log import get_logger
from embtrace_sbom.diagnosis import record_failure

if TYPE_CHECKING:
    from pathlib import Path

    from embtrace_sbom.analyzer.models import (
        BuildFileArtifact,
        BuildFileDependency,
        BuildFileInternalDep,
    )

logger = get_logger(__name__)

__all__ = ["ScanResult", "TierScanner", "merge_results", "run_pipeline"]


def _discover_scanners(enabled_tiers: set[int] | None = None) -> list[TierScanner]:
    """Discover and instantiate all available tier scanners."""
    scanners: list[TierScanner] = []

    tiers = enabled_tiers if enabled_tiers is not None else {1, 2, 3, 4, 5}

    # Tier 1: Native CLI tools
    if 1 in tiers:
        try:
            from embtrace_sbom.analyzer.pipeline.tier1_cli import get_scanners as get_t1
            scanners.extend(get_t1())
        except ImportError:
            logger.debug("Tier 1 (CLI) not available")

    # Tier 2: Structured parsers (stdlib — always available)
    if 2 in tiers:
        try:
            from embtrace_sbom.analyzer.pipeline.tier2_structured import get_scanners as get_t2
            scanners.extend(get_t2())
        except ImportError:
            logger.debug("Tier 2 (structured) not available")

    # Tier 3: tree-sitter AST
    if 3 in tiers:
        try:
            from embtrace_sbom.analyzer.pipeline.tier3_treesitter import get_scanners as get_t3
            scanners.extend(get_t3())
        except ImportError:
            logger.debug("Tier 3 (tree-sitter) not available")

    # Tier 4: Regex (fallback — always available)
    if 4 in tiers:
        try:
            from embtrace_sbom.analyzer.pipeline.tier4_regex import get_scanners as get_t4
            scanners.extend(get_t4())
        except ImportError:
            logger.debug("Tier 4 (regex) not available")

    # Tier 5: External SBOM tools
    if 5 in tiers:
        try:
            from embtrace_sbom.analyzer.pipeline.tier5_external import get_scanners as get_t5
            scanners.extend(get_t5())
        except ImportError:
            logger.debug("Tier 5 (external) not available")

    return scanners


def run_pipeline(
    project_path: Path,
    build_files: list[tuple[Path, str]],
    *,
    enabled_tiers: set[int] | None = None,
    timeout_per_tool: float = 30.0,
) -> tuple[list[BuildFileDependency], list[BuildFileArtifact], list[BuildFileInternalDep]]:
    """Run the multi-tier scanner pipeline.

    Args:
        project_path: Root directory of the project.
        build_files: List of (file_path, file_type) from collect_build_files.
        enabled_tiers: Which tiers to run (default: all).
        timeout_per_tool: Timeout in seconds for CLI tools.

    Returns:
        Tuple of (dependencies, artifacts, internal_deps) after merge.
    """
    scanners = _discover_scanners(enabled_tiers)
    if not scanners:
        logger.warning("No scanners available for pipeline")
        return [], [], []

    # Collect file types present
    file_types = {ft for _, ft in build_files}
    file_by_type: dict[str, list[Path]] = {}
    for fp, ft in build_files:
        file_by_type.setdefault(ft, []).append(fp)

    all_results: list[ScanResult] = []

    # Run each scanner against files it can handle
    for scanner in sorted(scanners, key=lambda s: s.tier):
        for file_type in file_types:
            if not scanner.can_handle(file_type, project_path):
                continue

            for file_path in file_by_type.get(file_type, []):
                try:
                    result = scanner.scan(file_type, file_path, project_path)
                    if result.dependencies or result.artifacts or result.internal_deps:
                        all_results.append(result)
                        logger.info(
                            "Tier %d [%s] found %d deps in %s",
                            scanner.tier,
                            scanner.name,
                            len(result.dependencies),
                            file_path,
                        )
                except Exception as exc:  # noqa: BLE001
                    # A crash here is a defect of this tool, not of the
                    # customer's file: recorded for the local diagnosis
                    # file (reader = tier + scanner, pattern = the file
                    # TYPE from our table), the pipeline continues.
                    record_failure(f"tier{scanner.tier}:{scanner.name}", file_type, exc)
                    logger.debug(
                        "Tier %d [%s] failed on %s",
                        scanner.tier,
                        scanner.name,
                        file_path,
                        exc_info=True,
                    )

    # Also run project-wide scanners (tier 1 CLI and tier 5 external)
    # These don't operate on individual files but on the project root
    for scanner in sorted(scanners, key=lambda s: s.tier):
        if not scanner.can_handle("_project", project_path):
            continue
        try:
            result = scanner.scan("_project", project_path, project_path)
            if result.dependencies or result.artifacts or result.internal_deps:
                all_results.append(result)
                logger.info(
                    "Tier %d [%s] found %d deps (project-wide)",
                    scanner.tier,
                    scanner.name,
                    len(result.dependencies),
                )
        except Exception as exc:  # noqa: BLE001
            record_failure(f"tier{scanner.tier}:{scanner.name}", "_project", exc)
            logger.debug(
                "Tier %d [%s] failed (project-wide)",
                scanner.tier,
                scanner.name,
                exc_info=True,
            )

    if not all_results:
        return [], [], []

    return merge_results(all_results)
