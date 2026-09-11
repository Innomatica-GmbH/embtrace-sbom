"""uv.lock scanner tests (v0.2.0 coverage fix)."""

from __future__ import annotations

from pathlib import Path

from embtrace_sbom.sbom.scanner import scan_directory, scan_uv_lock

UV_LOCK = """
version = 1

[[package]]
name = "innoscout-core"
version = "0.1.0"
source = { editable = "packages/core" }

[[package]]
name = "fastapi"
version = "0.115.8"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "torch"
version = "2.6.0"
source = { registry = "https://pypi.org/simple" }
"""


def test_registry_packages_in_workspace_members_skipped(tmp_path: Path) -> None:
    f = tmp_path / "uv.lock"
    f.write_text(UV_LOCK)
    deps = scan_uv_lock(f)
    assert {d.name for d in deps} == {"fastapi", "torch"}
    assert all(d.ecosystem == "pypi" for d in deps)


def test_pyproject_defers_to_uv_lock(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(UV_LOCK)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["fastapi>=0.100"]\n'
    )
    assert {d.name for d in scan_directory(tmp_path)} == {"fastapi", "torch"}
