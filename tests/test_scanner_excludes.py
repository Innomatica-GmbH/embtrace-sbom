"""Excludes (.embtraceignore + build outputs) and manifest-floor handling —
ported from embtrace 0.15.9 so customer payloads carry no phantom
components or dist/ duplicates."""

from __future__ import annotations

from pathlib import Path

from embtrace_sbom.collector import collect_components
from embtrace_sbom.sbom.scanner import prefer_locked, scan_directory_recursive


def test_floor_loses_against_lock_across_directories(tmp_path: Path) -> None:
    """pillow>=10.0 (sub-project pyproject) next to pillow==12.3.0 (root)
    → exactly one pillow, the resolved one."""
    (tmp_path / "requirements.txt").write_text("pillow==12.3.0\n", encoding="utf-8")
    sub = tmp_path / "subproj"
    sub.mkdir()
    (sub / "pyproject.toml").write_text(
        '[project]\nname = "subproj"\nversion = "1.0"\n'
        'dependencies = ["pillow>=10.0"]\n',
        encoding="utf-8",
    )
    pillow = [
        d for d in scan_directory_recursive(tmp_path) if d.name.lower() == "pillow"
    ]
    assert [d.version for d in pillow] == ["12.3.0"]


def test_dist_and_embtraceignore_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("real==1.0\n", encoding="utf-8")
    staged = tmp_path / "dist" / "staging"
    staged.mkdir(parents=True)
    (staged / "requirements.txt").write_text("phantom==6.6.6\n", encoding="utf-8")
    (tmp_path / ".embtraceignore").write_text("legacy\n", encoding="utf-8")
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / "requirements.txt").write_text("old==0.1\n", encoding="utf-8")

    names = {d.name for d in scan_directory_recursive(tmp_path)}
    assert names == {"real"}


def test_payload_labels_floor_as_manifest(tmp_path: Path) -> None:
    """A surviving floor (manifest-only project) must not claim to be a
    lockfile fact in the payload."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1.0"\n'
        'dependencies = ["torch>=2.0"]\n',
        encoding="utf-8",
    )
    components, _stats = collect_components(tmp_path)
    torch = next(c for c in components if c.name == "torch")
    assert torch.source_type == "manifest"
    assert torch.confidence == 0.7


def test_payload_has_no_duplicates_from_dist(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "requirements.txt").write_text("flask==3.0.0\nevil==1.0\n", encoding="utf-8")
    components, _stats = collect_components(tmp_path)
    names = sorted(c.name for c in components)
    assert names == ["flask"]


def test_prefer_locked_keeps_manifest_only() -> None:
    from embtrace_sbom.sbom.scanner import Dependency

    deps = prefer_locked([
        Dependency(name="onlyfloor", version="1.0", ecosystem="pypi",
                   source_kind="manifest"),
    ])
    assert len(deps) == 1
