"""What the collector and the suite must agree on, in one place.

The two halves are separate release lines with separate repositories.
Every file the one writes, the other reads: the collector writes a bill,
the suite enriches it and writes it again; the customer writes
``.jochwachtignore`` and both honour it.

A disagreement here does not raise — it loses data quietly. Measured risk
from the rename of 01.10.2026: had only one side moved to ``jochwacht:``,
the suite would have read a collector bill as never enriched and dropped
the provenance marks on the next round trip.

This file states the contract from the collector's side. The suite holds
the mirror image in ``tests/test_sbom/test_property_namespace.py`` and
``tests/test_core/test_filenames.py``; both must be changed together.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from jochwacht_sbom import filenames, properties


class TestThePropertyNamespace:
    def test_the_prefix_is_the_one_the_suite_reads(self) -> None:
        # Suite: embtrace/sbom/properties.py, PREFIX / LEGACY_PREFIX.
        assert properties.PREFIX == "jochwacht:"
        assert properties.LEGACY_PREFIX == "embtrace:"

    def test_a_written_bill_carries_the_new_namespace_only(
        self, tmp_path: Path,
    ) -> None:
        from jochwacht_sbom.payload import CheckComponent, CheckStats
        from jochwacht_sbom.sbom_out import write_cyclonedx

        out = write_cyclonedx(
            tmp_path / "sbom.cdx.json",
            [CheckComponent(name="jinja2", version="3.1.2", ecosystem="pypi",
                            source_type="lockfile")],
            CheckStats(build_files_scanned=1),
            project_name="demo",
        )
        doc = json.loads(out.read_text(encoding="utf-8"))
        names = [
            p["name"]
            for c in doc["components"]
            for p in c.get("properties", [])
        ]
        assert names, "ohne Eigenschaften prueft der Test nichts"
        assert all(n.startswith("jochwacht:") for n in names), names
        assert not any(n.startswith("embtrace:") for n in names)


class TestTheFilesTheCustomerWrites:
    @pytest.mark.parametrize(("new", "old"), [
        ("jochwacht.yaml", "embtrace.yaml"),
        ("jochwacht-deps.yaml", "embtrace-deps.yaml"),
        (".jochwachtignore", ".embtraceignore"),
    ])
    def test_both_spellings_are_known(self, new: str, old: str) -> None:
        assert filenames.both(new) == (new, old)

    @pytest.mark.parametrize("written", [".jochwachtignore", ".embtraceignore"])
    def test_either_ignore_file_is_honoured(
        self, written: str, tmp_path: Path,
    ) -> None:
        from jochwacht_sbom.sbom.scanner import load_ignore_patterns

        (tmp_path / written).write_text("build\nstaging\n", encoding="utf-8")
        assert load_ignore_patterns(tmp_path) == ["build", "staging"]

    def test_the_new_ignore_file_wins_when_both_exist(self, tmp_path: Path) -> None:
        from jochwacht_sbom.sbom.scanner import load_ignore_patterns

        (tmp_path / ".jochwachtignore").write_text("neu\n", encoding="utf-8")
        (tmp_path / ".embtraceignore").write_text("alt\n", encoding="utf-8")
        assert load_ignore_patterns(tmp_path) == ["neu"]

    @pytest.mark.parametrize("written", ["jochwacht.yaml", "embtrace.yaml"])
    def test_the_project_identity_is_read_from_either_config(
        self, written: str, tmp_path: Path,
    ) -> None:
        # Befund 75: both tools must agree on what "self" is, or the
        # self-reference filter drops different packages on each side.
        from jochwacht_sbom.collector import _project_name

        (tmp_path / written).write_text(
            "project:\n  name: meine-firmware\n", encoding="utf-8",
        )
        assert _project_name(tmp_path) == "meine-firmware"

    def test_without_a_config_the_directory_name_is_the_identity(
        self, tmp_path: Path,
    ) -> None:
        from jochwacht_sbom.collector import _project_name

        assert _project_name(tmp_path) == tmp_path.name
