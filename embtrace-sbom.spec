# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the standalone embtrace-sbom binary.

Build with:
    pyinstaller embtrace-sbom.spec --clean
"""

from PyInstaller.utils.hooks import collect_submodules

a = Analysis(
    ["src/embtrace_sbom/cli.py"],
    pathex=["src"],
    binaries=[],
    datas=[],
    hiddenimports=[
        "embtrace_sbom.payload",
        "embtrace_sbom.collector",
        "embtrace_sbom.upload",
        "embtrace_sbom.analyzer.pipeline.tier1_cli",
        "embtrace_sbom.analyzer.pipeline.tier2_structured",
        "embtrace_sbom.analyzer.pipeline.tier4_regex",
        "embtrace_sbom.analyzer.pipeline.merge",
        "embtrace_sbom.analyzer.scanner",
        "embtrace_sbom.analyzer.normalize",
        "embtrace_sbom.sbom.scanner",
        "embtrace_sbom.core.exceptions",
        *collect_submodules("embtrace_sbom.analyzer.parsers"),
        "yaml",
        "pydantic",
        "click",
        "rich",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "mypy", "ruff"],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="embtrace-sbom",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
)
