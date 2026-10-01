"""Pydantic models for AI project analyzer.

Covers LLM analysis output, reconciliation results, and the decisions.yaml
persistence format.
"""

from __future__ import annotations

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# LLM output models
# ---------------------------------------------------------------------------

class BuildFileDependency(BaseModel):
    """A dependency detected by LLM analysis of build files."""

    name: str
    version: str = ""
    ecosystem: str = ""
    source_file: str = ""
    source_line: int = 0
    context: str = ""          # LLM context, e.g. "inside if(USE_LIBRESSL)"
    confidence: float = 1.0
    tier: int = 0              # 0=LLM, 1-5=Pipeline tier
    detection_method: str = "" # e.g. "cargo-metadata", "regex-cmake", "treesitter-meson"


class BuildFileArtifact(BaseModel):
    """An artifact (binary, library, etc.) detected in build files."""

    path: str
    artifact_type: str = "binary"  # binary | library | config | script
    source_file: str = ""
    source_line: int = 0


class BuildFileInternalDep(BaseModel):
    """An internal project dependency detected in build files."""

    project: str
    source_file: str = ""
    source_line: int = 0
    context: str = ""


class LLMAnalysisResult(BaseModel):
    """Result of analyzing a single build file with the LLM."""

    file_path: str
    dependencies: list[BuildFileDependency] = []
    artifacts: list[BuildFileArtifact] = []
    internal_deps: list[BuildFileInternalDep] = []


# ---------------------------------------------------------------------------
# Reconciliation result models
# ---------------------------------------------------------------------------

class ConfirmedEntry(BaseModel):
    """Both lockfile scanner and build-file analysis agree on this dependency."""

    name: str
    version: str
    ecosystem: str = ""
    source_file: str = ""


class LockfileOnlyEntry(BaseModel):
    """Dependency found only in the lockfile scanner output."""

    name: str
    version: str
    ecosystem: str = ""
    accept: bool | None = None


class BuildFileOnlyEntry(BaseModel):
    """Dependency found only in LLM build-file analysis."""

    name: str
    version: str = ""
    ecosystem: str = ""
    source_file: str = ""
    confidence: float = 1.0
    context: str = ""
    accept: bool | None = None


class ConflictEntry(BaseModel):
    """Version mismatch between lockfile and build-file analysis."""

    name: str
    lockfile_version: str
    build_file_version: str
    ecosystem: str = ""
    source_file: str = ""
    accept: bool | None = None
    use_version: str = ""


class ArtifactEntry(BaseModel):
    """A produced artifact detected in build files."""

    path: str
    artifact_type: str = "binary"
    source_file: str = ""


class InternalDepEntry(BaseModel):
    """An internal dependency detected in build files."""

    project: str
    source_file: str = ""
    context: str = ""
    accept: bool | None = None


# ---------------------------------------------------------------------------
# decisions.yaml root model
# ---------------------------------------------------------------------------

class DecisionsFile(BaseModel):
    """Root model for .embtrace/proposal/decisions.yaml."""

    scan_date: str
    model: str = ""
    confirmed: list[ConfirmedEntry] = []
    lockfile_only: list[LockfileOnlyEntry] = []
    build_file_only: list[BuildFileOnlyEntry] = []
    conflicts: list[ConflictEntry] = []
    artifacts: list[ArtifactEntry] = []
    internal_dependencies: list[InternalDepEntry] = []


# ---------------------------------------------------------------------------
# Reconciliation container
# ---------------------------------------------------------------------------

class ReconciliationResult(BaseModel):
    """Container for reconciliation output — input to proposal generation."""

    confirmed: list[ConfirmedEntry] = []
    lockfile_only: list[LockfileOnlyEntry] = []
    build_file_only: list[BuildFileOnlyEntry] = []
    conflicts: list[ConflictEntry] = []
    artifacts: list[ArtifactEntry] = []
    internal_dependencies: list[InternalDepEntry] = []
