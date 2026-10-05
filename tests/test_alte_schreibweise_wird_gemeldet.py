"""A file the customer wrote under the former name is not read — and we say so.

The move of 01.10.2026 is complete: one spelling per file, no compatibility
layer (Ivan, 02.10.2026). That decision stands. What must not stand is doing
it in SILENCE: a hand-written declaration is the one input nothing else can
reconstruct, and dropping it without a word is a measurement loss nobody
notices.

Measured 05.10.2026 against the published 0.13.0, on the real path: a project
holding only the former ``*-deps.yaml`` produced a bill with zero declared
components and said nothing at all.  # alter-name-als-datum
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from jochwacht_sbom import filenames
from jochwacht_sbom.cli import main

#: (what the customer has, what it must be called now)
_PAARE = [
    ("embtrace-deps.yaml", "jochwacht-deps.yaml"),   # alter-name-als-datum
    ("embtrace.yaml", "jochwacht.yaml"),             # alter-name-als-datum
    (".embtraceignore", ".jochwachtignore"),         # alter-name-als-datum
]


@pytest.mark.parametrize(("former", "current"), _PAARE)
def test_the_former_spelling_is_found(former: str, current: str, tmp_path: Path) -> None:
    (tmp_path / former).write_text("x\n", encoding="utf-8")
    assert filenames.former_spelling_present(tmp_path) == [(former, current)]


def test_nothing_is_reported_for_a_clean_project(tmp_path: Path) -> None:
    for name in filenames.ALL:
        (tmp_path / name).write_text("x\n", encoding="utf-8")
    assert filenames.former_spelling_present(tmp_path) == []


def test_the_current_file_wins_and_silences_the_note(tmp_path: Path) -> None:
    """Both present: the current one is read, so there is nothing to warn about."""
    (tmp_path / "embtrace-deps.yaml").write_text("x\n", encoding="utf-8")  # alter-name-als-datum
    (tmp_path / filenames.DEPS).write_text("x\n", encoding="utf-8")
    assert filenames.former_spelling_present(tmp_path) == []


def test_the_run_says_it_out_loud(tmp_path: Path) -> None:
    """The real path: what the customer sees on their terminal."""
    (tmp_path / "embtrace-deps.yaml").write_text(  # alter-name-als-datum
        "dependencies:\n  - name: libhand\n    version: 1.2.3\n    license: MIT\n",
        encoding="utf-8",
    )
    out = tmp_path / "sbom.cdx.json"
    result = CliRunner().invoke(main, [str(tmp_path), "--sbom", str(out)])

    gesagt = result.output.replace("\n", " ")
    assert "is not read" in gesagt
    assert "jochwacht-deps.yaml" in gesagt
    # And the declaration really is absent — the note is not cosmetic.
    assert "libhand" not in gesagt


def test_the_note_is_not_an_error(tmp_path: Path) -> None:
    """It informs; it does not gate. A scan with no build system is its own case."""
    alt = tmp_path / "embtrace.yaml"  # alter-name-als-datum
    alt.write_text("project:\n  name: x\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("jinja2==3.1.2\n", encoding="utf-8")
    out = tmp_path / "sbom.cdx.json"
    result = CliRunner().invoke(main, [str(tmp_path), "--sbom", str(out)])
    assert result.exit_code == 0, result.output
    assert out.is_file()
