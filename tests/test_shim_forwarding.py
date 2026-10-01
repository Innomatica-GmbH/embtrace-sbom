"""The forwarding shell ``embtrace-check`` (shim/) must make the old module
namespace resolve to the very same modules as ``jochwacht_sbom`` — the embtrace
suite's collector check imports ``embtrace_check.sbom``. Red before: a plain
re-export answered attribute access but not ``import embtrace_check.sbom``."""

from __future__ import annotations

import subprocess
import sys

import pytest

pytest.importorskip(
    "embtrace_check", reason="shim not installed (pip install -e shim/embtrace-check)",
)

_VERSION_VIA_SHIM = (
    "import embtrace_check, sys; sys.argv = ['embtrace-check', '--version']; "
    "embtrace_check.main()"
)


def test_submodule_imports_are_the_same_objects() -> None:
    from embtrace_check.analyzer.pipeline import merge as alias_merge
    from embtrace_check.sbom import classify as alias_classify

    import jochwacht_sbom.analyzer.pipeline.merge as real_merge
    import jochwacht_sbom.sbom.classify as real_classify

    assert alias_classify is real_classify
    assert alias_merge is real_merge


def test_version_and_command_forward() -> None:
    import embtrace_check

    import jochwacht_sbom

    assert embtrace_check.__version__ == jochwacht_sbom.__version__
    out = subprocess.run(
        [sys.executable, "-c", _VERSION_VIA_SHIM],
        capture_output=True, text=True, check=False,
    )
    assert out.returncode == 0
    assert "jochwacht-sbom, version" in out.stdout
    assert "now jochwacht-sbom" in out.stderr           # the one-line notice


# --- the second forwarding shell: embtrace-sbom (the 0.9.0–0.11.1 name) ----

pytest.importorskip(
    "embtrace_sbom", reason="shim not installed (pip install -e shim/embtrace-sbom)",
)

_VERSION_VIA_SBOM_SHIM = (
    "import embtrace_sbom, sys; sys.argv = ['embtrace-sbom', '--version']; "
    "embtrace_sbom.main()"
)


def test_sbom_shim_submodules_are_the_same_objects() -> None:
    from embtrace_sbom.analyzer.pipeline import merge as alias_merge
    from embtrace_sbom.sbom import classify as alias_classify

    import jochwacht_sbom.analyzer.pipeline.merge as real_merge
    import jochwacht_sbom.sbom.classify as real_classify

    assert alias_classify is real_classify
    assert alias_merge is real_merge


def test_sbom_shim_version_and_command_forward() -> None:
    import embtrace_sbom

    import jochwacht_sbom

    assert embtrace_sbom.__version__ == jochwacht_sbom.__version__
    out = subprocess.run(
        [sys.executable, "-c", _VERSION_VIA_SBOM_SHIM],
        capture_output=True, text=True, check=False,
    )
    assert out.returncode == 0, out.stderr
    assert "jochwacht-sbom, version" in out.stdout
    assert "embtrace-sbom is now jochwacht-sbom" in out.stderr


def test_both_shims_declare_the_new_package_as_their_dependency() -> None:
    from pathlib import Path as _Path

    root = _Path(__file__).resolve().parents[1] / "shim"
    for name in ("embtrace-check", "embtrace-sbom"):
        text = (root / name / "pyproject.toml").read_text(encoding="utf-8")
        assert 'dependencies = ["jochwacht-sbom>=0.12.0"]' in text, name
        # A shim that is still "Development Status :: 4" invites a release.
        assert "Development Status :: 7 - Inactive" in text, name
