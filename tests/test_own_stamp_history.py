"""A bill we wrote ourselves stays ours after a rename.

Measured on Ivan's machine on 01.10.2026: ``jochwacht-sbom .`` refused to
touch an existing ``sbom.cdx.json`` with

    sbom.cdx.json exists and was not written by jochwacht-sbom — it is left
    untouched. Write the bill elsewhere with --sbom PATH.

Two different things turned out to sit behind that one message, and only
one of them is a defect:

* **A defect.** The search-and-replace that renamed the package also
  rewrote ``OWN_TOOL_NAMES``, so ``embtrace-sbom`` — the name 0.9.0 to
  0.11.1 stamped into every file they wrote — was silently dropped. Those
  files became "foreign" overnight. A stamp is a record of the past; it
  never moves.
* **Correct behaviour.** Ivan's particular file was stamped ``embtrace``,
  the SUITE, not the collector. The collector has never overwritten a file
  the suite wrote, before or after the rename, and must not start.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from jochwacht_sbom.sbom_out import OWN_TOOL_NAMES, classify_existing


def _write(path: Path, tool_name: str | None) -> Path:
    doc: dict[str, object] = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": [],
    }
    if tool_name is not None:
        doc["metadata"] = {"tools": {"components": [
            {"vendor": "Innomatica GmbH", "name": tool_name, "version": "0.0.0"},
        ]}}
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


class TestOurOwnFilesStayOurs:
    @pytest.mark.parametrize("stamp", [
        "jochwacht-sbom",   # since 0.12.0
        "embtrace-sbom",    # 0.9.0 – 0.11.1 — dropped by the rename
        "embtrace-check",   # up to 0.8.6
    ])
    def test_every_name_we_ever_stamped_counts_as_our_own(
        self, stamp: str, tmp_path: Path,
    ) -> None:
        assert classify_existing(_write(tmp_path / "sbom.cdx.json", stamp)) == "own"

    def test_the_set_only_grows(self) -> None:
        # Each entry is a historical fact. Removing one makes files written
        # by that release unwritable, which is what happened on 01.10.2026.
        assert {"jochwacht-sbom", "embtrace-sbom", "embtrace-check"} <= OWN_TOOL_NAMES


class TestWhatIsNotOurs:
    def test_a_file_from_the_suite_is_left_alone(self, tmp_path: Path) -> None:
        # The suite stamps "embtrace" and writes a richer document; the free
        # collector has never overwritten one and must not start now.
        assert classify_existing(_write(tmp_path / "s.json", "embtrace")) == "foreign"

    def test_a_stranger_is_left_alone(self, tmp_path: Path) -> None:
        assert classify_existing(_write(tmp_path / "s.json", "syft")) == "foreign"

    def test_a_file_without_a_stamp_is_left_alone(self, tmp_path: Path) -> None:
        assert classify_existing(_write(tmp_path / "s.json", None)) == "foreign"

    def test_a_missing_file_is_simply_missing(self, tmp_path: Path) -> None:
        assert classify_existing(tmp_path / "nope.json") == "none"
