"""0.8.4 — the collector shows first, then sends (order collector-transparent-machen).

Ivan, 09.09.2026: the DEFAULT run generates, shows and SAVES a real CycloneDX
SBOM and transmits nothing; sending is an explicit decision (--send, or the
question after the summary), needs only an e-mail address (the mandatory code
was dropped), and shows exactly what leaves the house before the POST.

The three named tests the order asks for:
- ``default_never_uploads``
- ``send_confirms_before_post``
- ``existing_sbom_not_overwritten``
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from embtrace_sbom.cli import main


def _project(tmp_path: Path) -> Path:
    p = tmp_path / "proj"
    p.mkdir()
    (p / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\n"
        "project(proj)\n"
        "find_package(OpenSSL REQUIRED)\n",
        encoding="utf-8",
    )
    return p


class TestDefaultNeverUploads:
    """default_never_uploads: without --send nothing leaves the house."""

    def test_default_run_writes_sbom_and_uploads_nothing(
        self, tmp_path: Path,
    ) -> None:
        proj = _project(tmp_path)
        with patch("embtrace_sbom.cli.upload_payload") as up:
            res = CliRunner().invoke(main, [str(proj)])
        assert res.exit_code == 0, res.output
        up.assert_not_called()                      # nothing transmitted
        sbom = proj / "sbom.cdx.json"
        assert sbom.is_file(), res.output           # …but the SBOM is written
        doc = json.loads(sbom.read_text(encoding="utf-8"))
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.6"
        assert any(c["name"] == "OpenSSL" for c in doc["components"])
        # and the run says so, plus where the file is
        assert "Nothing was transmitted" in res.output
        assert "sbom.cdx.json" in res.output

    def test_non_tty_never_asks(self, tmp_path: Path) -> None:
        # In CI (no TTY) the tool must not block on a question — it prints the
        # invitation and exits.
        proj = _project(tmp_path)
        with patch("embtrace_sbom.cli.upload_payload") as up:
            res = CliRunner().invoke(main, [str(proj)])
        assert res.exit_code == 0
        up.assert_not_called()
        assert "Send now?" not in res.output


class TestSendConfirmsBeforePost:
    """send_confirms_before_post: the summary comes first, then the question."""

    def test_declining_the_confirmation_sends_nothing(
        self, tmp_path: Path,
    ) -> None:
        proj = _project(tmp_path)
        with patch("embtrace_sbom.cli.upload_payload") as up:
            res = CliRunner().invoke(
                main, [str(proj), "--send", "--email", "a@b.de"], input="n\n",
            )
        assert res.exit_code == 0, res.output
        up.assert_not_called()
        assert "This would be sent" in res.output   # summary shown FIRST
        assert "OpenSSL" in res.output              # names + versions
        assert "Nothing was sent" in res.output

    def test_confirming_posts_once(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        with patch("embtrace_sbom.cli.upload_payload", return_value="REF-1") as up:
            res = CliRunner().invoke(
                main, [str(proj), "--send", "--email", "a@b.de"], input="y\n",
            )
        assert res.exit_code == 0, res.output
        assert up.call_count == 1
        assert "REF-1" in res.output

    def test_yes_skips_the_question(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        with patch("embtrace_sbom.cli.upload_payload", return_value="REF-2") as up:
            res = CliRunner().invoke(
                main, [str(proj), "--send", "--yes", "--email", "a@b.de"],
            )
        assert res.exit_code == 0, res.output
        assert up.call_count == 1

    def test_send_needs_only_email_no_code(self, tmp_path: Path) -> None:
        # send_needs_only_email (Ivan 09.09.): the mandatory code is gone.
        proj = _project(tmp_path)
        with patch("embtrace_sbom.cli.upload_payload", return_value="R") as up:
            res = CliRunner().invoke(
                main, [str(proj), "--send", "--yes", "--email", "a@b.de"],
            )
        assert res.exit_code == 0, res.output
        assert up.call_count == 1
        payload = up.call_args[0][0]
        assert payload.contact_email == "a@b.de"
        assert "code is required" not in res.output

    def test_send_without_email_fails_before_scanning(
        self, tmp_path: Path,
    ) -> None:
        proj = _project(tmp_path)
        with patch("embtrace_sbom.cli.upload_payload") as up:
            res = CliRunner().invoke(main, [str(proj), "--send"])
        assert res.exit_code == 1
        up.assert_not_called()
        assert not (proj / "sbom.cdx.json").exists()  # failed before the work


class TestExistingSbomNotOverwritten:
    """existing_sbom_not_overwritten: an earlier bill is evidence."""

    def test_second_run_keeps_the_first_file(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        existing = proj / "sbom.cdx.json"
        existing.write_text('{"mine": true}', encoding="utf-8")
        res = CliRunner().invoke(main, [str(proj)])
        assert res.exit_code == 0, res.output
        # untouched
        assert json.loads(existing.read_text(encoding="utf-8")) == {"mine": True}
        # and the new one went beside it
        assert (proj / "sbom.cdx-2.json").is_file()
        assert "was kept" in res.output

    def test_explicit_sbom_path_is_honoured(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        target = tmp_path / "out" / "bill.json"
        target.parent.mkdir()
        res = CliRunner().invoke(main, [str(proj), "--sbom", str(target)])
        assert res.exit_code == 0, res.output
        assert target.is_file()
        assert json.loads(target.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"


class TestNoSend:
    """no_send_never_asks (Ivan, 09.09.): for anyone who has decided they
    will not send — never ask, never transmit, just write the SBOM."""

    def test_no_send_never_asks_and_writes(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        with patch("embtrace_sbom.cli.upload_payload") as up, \
             patch("embtrace_sbom.cli._asks_interactively", return_value=True):
            res = CliRunner().invoke(main, [str(proj), "--no-send"])
        assert res.exit_code == 0, res.output
        up.assert_not_called()
        assert "Send now?" not in res.output       # even with a TTY present
        assert (proj / "sbom.cdx.json").is_file()

    def test_no_send_with_send_is_a_contradiction(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        with patch("embtrace_sbom.cli.upload_payload") as up:
            res = CliRunner().invoke(
                main, [str(proj), "--no-send", "--send", "--email", "a@b.de"],
            )
        assert res.exit_code == 1
        up.assert_not_called()
        assert "contradict" in res.output
