"""Declared metadata travels — discovered components stay metadata-only.

A declaration in embtrace-deps.yaml is written FOR SBOM purposes: its
supplier/license/purl/cpe travel by default (v0.5.0) and are labelled
``source_type: "declared"`` so the report can tell declaration from
discovery apart. The privacy promise for discovered components is
unchanged: names, versions, ecosystems only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from embtrace_sbom.collector import collect_components
from embtrace_sbom.sbom.scanner import scan_embtrace_deps

if TYPE_CHECKING:
    from pathlib import Path

_DECLARATION = """\
dependencies:
  - name: zephyr
    version: 4.1.0
    supplier: Zephyr Project / Linux Foundation
    license: Apache-2.0
    purl: pkg:github/zephyrproject-rtos/zephyr@v4.1.0
    cpe: "cpe:2.3:o:zephyrproject:zephyr:4.1.0:*:*:*:*:*:*:*"
  - name: picolibc
    version: 1.8.8
    supplier: Keith Packard
    license: BSD-3-Clause AND LGPL-2.1-or-later
"""


def _project(tmp_path: Path) -> Path:
    (tmp_path / "embtrace-deps.yaml").write_text(_DECLARATION, encoding="utf-8")
    return tmp_path


def test_scanner_reads_declared_purl_and_cpe(tmp_path: Path) -> None:
    f = _project(tmp_path) / "embtrace-deps.yaml"
    deps = {d.name: d for d in scan_embtrace_deps(f)}
    zephyr = deps["zephyr"]
    assert zephyr.purl == "pkg:github/zephyrproject-rtos/zephyr@v4.1.0"
    assert zephyr.cpe == "cpe:2.3:o:zephyrproject:zephyr:4.1.0:*:*:*:*:*:*:*"
    assert zephyr.declared is True
    assert deps["picolibc"].purl  # synthesized fallback, unchanged
    assert deps["picolibc"].cpe is None


def test_collector_carries_declared_metadata(tmp_path: Path) -> None:
    components, _ = collect_components(_project(tmp_path))
    comp = {c.name: c for c in components}["zephyr"]
    assert comp.source_type == "declared"
    assert comp.supplier == "Zephyr Project / Linux Foundation"
    assert comp.license == "Apache-2.0"
    assert comp.purl == "pkg:github/zephyrproject-rtos/zephyr@v4.1.0"
    assert comp.cpe == "cpe:2.3:o:zephyrproject:zephyr:4.1.0:*:*:*:*:*:*:*"


def test_opt_out_strips_metadata_but_keeps_the_component(tmp_path: Path) -> None:
    components, _ = collect_components(
        _project(tmp_path), include_declared_metadata=False,
    )
    comp = {c.name: c for c in components}["zephyr"]
    assert comp.source_type == "declared"
    assert comp.supplier == comp.license == comp.cpe == ""


def test_discovered_components_never_carry_metadata(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("click==8.1.7\n", encoding="utf-8")
    components, _ = collect_components(tmp_path)
    comp = {c.name: c for c in components}["click"]
    assert comp.source_type != "declared"
    assert comp.supplier == comp.license == comp.cpe == ""
