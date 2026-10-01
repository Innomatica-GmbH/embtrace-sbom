"""The rename must not break anything a customer already has set up.

embtrace became Jochwacht on 01.10.2026 (the old name collided with a
registered trademark, DPMA 302026254573.4). There are no customers and no
submissions, so nothing has to run in parallel — but printed instructions,
shell profiles, CI files and scripts carry the old spellings, and those
cost nothing to keep.

What this file pins:

* the default submission address is the new one;
* both old command names still exist and still work;
* ``EMBTRACE_*`` environment variables are still read, and the new
  ``JOCHWACHT_*`` spelling wins when both are set;
* the shipped text does not mention the old name except where it says it
  changed.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from jochwacht_sbom import env
from jochwacht_sbom.upload import DEFAULT_SUBMIT_URL

_REPO = Path(__file__).resolve().parents[1]


class TestWhereItSends:
    def test_the_default_address_is_the_new_one(self) -> None:
        assert DEFAULT_SUBMIT_URL == "https://api.jochwacht.dev/api/v1/check/submit"

    def test_no_shipped_module_still_points_at_the_old_host(self) -> None:
        hits = [
            f"{p.relative_to(_REPO)}:{n}"
            for p in (_REPO / "src").rglob("*.py")
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
            if "embtrace.dev" in line
        ]
        assert not hits, hits


class TestTheOldEnvironmentVariablesStillWork:
    def test_the_old_spelling_is_read(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(env.TRACEBACK_ENV, raising=False)
        monkeypatch.setenv("EMBTRACE_SBOM_TRACEBACK", "1")
        assert env.get(env.TRACEBACK_ENV) == "1"

    def test_the_new_spelling_wins_over_the_old(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv(env.TRACEBACK_ENV, "new")
        monkeypatch.setenv("EMBTRACE_SBOM_TRACEBACK", "old")
        assert env.get(env.TRACEBACK_ENV) == "new"

    def test_an_empty_new_value_switches_off_without_the_old_reviving_it(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Otherwise JOCHWACHT_X= could not turn off what EMBTRACE_X turned on.
        monkeypatch.setenv(env.TRACEBACK_ENV, "")
        monkeypatch.setenv("EMBTRACE_SBOM_TRACEBACK", "1")
        assert env.get(env.TRACEBACK_ENV) == ""

    def test_neither_set_gives_the_default(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv(env.TRACEBACK_ENV, raising=False)
        monkeypatch.delenv("EMBTRACE_SBOM_TRACEBACK", raising=False)
        assert env.get(env.TRACEBACK_ENV, "fallback") == "fallback"

    @pytest.mark.parametrize(("new", "old"), [
        (env.TRACEBACK_ENV, "EMBTRACE_SBOM_TRACEBACK"),
        (env.NO_SYSRESOLVE_ENV, "EMBTRACE_NO_SYSRESOLVE"),
    ])
    def test_the_rule_derives_every_old_name(self, new: str, old: str) -> None:
        # One mechanical rule, no table: a switch added later cannot forget
        # its old spelling.
        assert env.legacy_name(new) == old

    def test_sysresolve_still_obeys_the_old_switch(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from jochwacht_sbom.sbom import sysresolve

        monkeypatch.delenv(env.NO_SYSRESOLVE_ENV, raising=False)
        monkeypatch.setenv("EMBTRACE_NO_SYSRESOLVE", "1")
        assert sysresolve.resolve_system_libraries([]) == 0


class TestBothOldCommandsStillRun:
    @pytest.mark.parametrize("entry", ["main_check_alias", "main_sbom_alias"])
    def test_the_alias_runs_the_same_tool(self, entry: str) -> None:
        code = (
            f"import sys; sys.argv = ['x', '--version']; "
            f"from jochwacht_sbom.cli import {entry}; {entry}()"
        )
        out = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, check=False,
        )
        assert out.returncode == 0, out.stderr
        assert "jochwacht-sbom, version" in out.stdout

    @pytest.mark.parametrize(("entry", "old_name"), [
        ("main_check_alias", "embtrace-check"),
        ("main_sbom_alias", "embtrace-sbom"),
    ])
    def test_it_says_once_that_the_name_changed_on_stderr(
        self, entry: str, old_name: str,
    ) -> None:
        # stderr, so a pipeline reading stdout is unaffected.
        code = (
            f"import sys; sys.argv = ['x', '--version']; "
            f"from jochwacht_sbom.cli import {entry}; {entry}()"
        )
        out = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, check=False,
        )
        assert old_name in out.stderr
        assert "jochwacht-sbom" in out.stderr
        assert old_name not in out.stdout

    def test_both_old_commands_are_declared(self) -> None:
        text = (_REPO / "pyproject.toml").read_text(encoding="utf-8")
        assert 'embtrace-sbom = "jochwacht_sbom.cli:main_sbom_alias"' in text
        assert 'embtrace-check = "jochwacht_sbom.cli:main_check_alias"' in text


class TestTheShippedTextCarriesTheNewName:
    def test_the_readme_installs_the_new_package(self) -> None:
        readme = (_REPO / "README.md").read_text(encoding="utf-8")
        assert "pipx install jochwacht-sbom" in readme or \
               "pip install jochwacht-sbom" in readme

    #: The old name is still correct in exactly two kinds of place, and the
    #: test names them so a third one cannot slip in unnoticed.
    #:
    #: 1. Configuration files the CUSTOMER writes and the SUITE also reads.
    #:    ``.embtraceignore`` is spelled the same way in the suite's own
    #:    scanner (measured 01.10.2026: embtrace/sbom/scanner.py,
    #:    IGNORE_FILENAME), and the suite keeps its name in this package of
    #:    work. Renaming the file here alone would mean one tool honours it
    #:    and the other does not — worse than an old-fashioned name both
    #:    understand. These are renamed when the suite is.
    #: 2. The sentence that says the name changed, and the history of
    #:    releases made under the old one.
    CONFIG_NAMES_SHARED_WITH_THE_SUITE = (
        ".embtraceignore", "embtrace-deps.yaml", "embtrace.yaml",
    )
    SAYS_IT_CHANGED = (
        "former", "was called", "renamed", "now jochwacht", "trademark",
        # Licence history: the releases made under the old name keep it.
        "releases up to", "were published under",
        # The compatibility promise itself has to name what it promises,
        # and so does the migration section — telling somebody to uninstall
        # the old package requires saying the old package's name.
        "commands keep working", "packages install this one",
        "is still read", "are still read",
        "old installations are redundant", "pipx uninstall",
        "keeps the old command working", "still recognised as yours",
    )

    def test_the_old_name_appears_only_where_it_says_it_changed(self) -> None:
        # By PARAGRAPH, not by line: prose wraps, and a sentence whose
        # subject sits on one line and whose promise sits on the next would
        # otherwise read as an unexplained mention. (Same lesson as the KEV
        # wording guard in the suite — a line-wise reader misses exactly
        # the sentence it was written for.)
        readme = (_REPO / "README.md").read_text(encoding="utf-8")
        offending = []
        for block in readme.split("\n\n"):
            para = " ".join(block.split())
            rest = para
            for name in self.CONFIG_NAMES_SHARED_WITH_THE_SUITE:
                rest = rest.replace(name, "")
            if "embtrace" not in rest.lower():
                continue
            if any(w in para.lower() for w in self.SAYS_IT_CHANGED):
                continue
            offending.append(para)
        assert not offending, offending

    def test_the_shared_config_names_are_still_the_ones_the_suite_reads(self) -> None:
        # The reason the names above are exempt — if this ever stops being
        # true, the exemption has to be revisited rather than inherited.
        from jochwacht_sbom.sbom.scanner import IGNORE_FILENAME

        assert IGNORE_FILENAME == ".embtraceignore"


class TestTheOldImportsStillResolve:
    def test_the_exception_alias_is_the_same_object(self) -> None:
        # Not a subclass: `except EmbtraceError` in somebody's script must
        # catch exactly what `except JochwachtError` catches.
        from jochwacht_sbom.core.exceptions import EmbtraceError, JochwachtError

        assert EmbtraceError is JochwachtError

    def test_every_error_is_still_caught_by_the_old_name(self) -> None:
        from jochwacht_sbom.core import exceptions

        subclasses = [
            obj for name, obj in vars(exceptions).items()
            if isinstance(obj, type) and issubclass(obj, exceptions.JochwachtError)
        ]
        assert len(subclasses) > 5, len(subclasses)
        for cls in subclasses:
            assert issubclass(cls, exceptions.EmbtraceError), cls.__name__


class TestWhatTheUserReadsOnScreen:
    """The help text, not just the README.

    Found the hard way on 01.10.2026: 0.12.0 shipped with
    ``--send  Send the bill of materials to embtrace …`` because the guard
    above reads README.md and nothing else. A customer meets the help text
    far more often than the README, and it named the brand we had just
    stopped using. The check now reads the strings the CLI prints.
    """

    def _help(self) -> str:
        from click.testing import CliRunner

        from jochwacht_sbom.cli import main

        res = CliRunner().invoke(main, ["--help"])
        assert res.exit_code == 0, res.output
        return res.output

    def test_the_help_text_names_the_product_by_its_new_name(self) -> None:
        text = self._help()
        rest = text
        for name in TestTheShippedTextCarriesTheNewName.CONFIG_NAMES_SHARED_WITH_THE_SUITE:
            rest = rest.replace(name, "")
        # What is left may mention the old name only where it says it moved.
        offending = [
            line for line in rest.splitlines()
            if "embtrace" in line.lower()
            and not any(w in line.lower() for w in ("former", "now jochwacht", "renamed"))
        ]
        assert not offending, offending

    def test_the_privacy_link_points_at_the_new_domain(self) -> None:
        assert "jochwacht.dev/check-privacy" in self._help()
        assert "embtrace.dev" not in self._help()

    def test_no_string_the_cli_can_print_names_the_old_product(self) -> None:
        """Every literal, not just the ones --help happens to show.

        0.12.1 still asked "Send this to embtrace?" right before the data
        leaves the house — the most consequential sentence in the tool, and
        the help-text check could not see it because it is a prompt. Reading
        the source catches prompts, errors and hints alike.
        """
        import re
        from pathlib import Path as _Path

        from jochwacht_sbom import cli as cli_mod

        allowed = (
            *TestTheShippedTextCarriesTheNewName.CONFIG_NAMES_SHARED_WITH_THE_SUITE,
            # the two aliases must name themselves to say they moved
            '_moved_notice("embtrace-check")',
            '_moved_notice("embtrace-sbom")',
        )
        offending = []
        src = _Path(cli_mod.__file__).read_text(encoding="utf-8")
        for number, line in enumerate(src.splitlines(), start=1):
            rest = line
            for name in allowed:
                rest = rest.replace(name, "")
            if "embtrace" not in rest.lower():
                continue
            if re.match(r"\s*(from|import)\s+", rest):
                continue
            if re.match(r"\s*#", rest):      # comments explain, they do not print
                continue
            if re.match(r'\s*"""', rest):    # docstrings likewise
                continue
            offending.append(f"{number}: {line.strip()}")
        assert not offending, offending
