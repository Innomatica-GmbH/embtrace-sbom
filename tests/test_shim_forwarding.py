"""The forwarding shell ``embtrace-check`` (shim/) must make the old module
namespace resolve to the very same modules as ``embtrace_sbom`` — the embtrace
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

    import embtrace_sbom.analyzer.pipeline.merge as real_merge
    import embtrace_sbom.sbom.classify as real_classify

    assert alias_classify is real_classify
    assert alias_merge is real_merge


def test_version_and_command_forward() -> None:
    import embtrace_check

    import embtrace_sbom

    assert embtrace_check.__version__ == embtrace_sbom.__version__
    out = subprocess.run(
        [sys.executable, "-c", _VERSION_VIA_SHIM],
        capture_output=True, text=True, check=False,
    )
    assert out.returncode == 0
    assert "embtrace-sbom, version" in out.stdout
    assert "now embtrace-sbom" in out.stderr           # the one-line notice
