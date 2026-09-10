"""0.8.5 — genau zwei Fixes (Befunde 93a und 81 im Zwilling).

93a: Der Client schrieb den wörtlichen Platzhalter "DRY-RUN" in JEDE Nutzlast,
auch beim echten --send. Serverseitig schlug das die ehrliche Einstufung, und
die Einsendung eines zahlenden Interessenten lag als CHK-…-DRY-RUN.json im
Posteingang — in einer Kette, in der jeder Bericht VON HAND weitergeleitet wird.

81: Der Zwilling stempelte nur Testmaterial ("excluded"); alles andere blieb
ohne Scope. Damit konnte der Kundenbericht Produkt und Testmaterial nicht
trennen — genau die Unterscheidung, die der Gratis-Check liefern soll.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from embtrace_check.cli import main
from embtrace_check.sbom.scanner import scan_directory_recursive


def _project(tmp_path: Path) -> Path:
    p = tmp_path / "proj"
    p.mkdir()
    (p / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\n"
        "project(proj)\nfind_package(OpenSSL REQUIRED)\n",
        encoding="utf-8",
    )
    tests = p / "tests"
    tests.mkdir()
    (tests / "requirements.txt").write_text("pytest==7.0.0\n", encoding="utf-8")
    return p


class TestNoPlaceholderVoucher:
    """93a — ein leeres Feld ist die Wahrheit: es wurde kein Code angegeben."""

    def test_a_real_send_carries_no_placeholder(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        with patch("embtrace_check.cli.upload_payload", return_value="R") as up:
            res = CliRunner().invoke(
                main, [str(proj), "--send", "--yes", "--email", "a@b.de"],
            )
        assert res.exit_code == 0, res.output
        payload = up.call_args[0][0]
        assert payload.voucher == "", payload.voucher
        assert "DRY-RUN" not in payload.voucher

    def test_a_real_voucher_still_travels(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        with patch("embtrace_check.cli.upload_payload", return_value="R") as up:
            res = CliRunner().invoke(main, [
                str(proj), "--send", "--yes", "--email", "a@b.de",
                "--voucher", "STOIL-2026",
            ])
        assert res.exit_code == 0, res.output
        assert up.call_args[0][0].voucher == "STOIL-2026"

    def test_the_dry_run_output_carries_no_placeholder_either(
        self, tmp_path: Path,
    ) -> None:
        proj = _project(tmp_path)
        res = CliRunner().invoke(
            main, [str(proj), "--send", "--email", "a@b.de", "--yes",
                   "--dry-run"],
        )
        assert res.exit_code == 0, res.output
        assert '"voucher": "DRY-RUN"' not in res.output


class TestEveryComponentCarriesAScope:
    """81 — Produkt und Testmaterial müssen unterscheidbar sein."""

    def test_the_scanner_stamps_production_components(
        self, tmp_path: Path,
    ) -> None:
        deps = scan_directory_recursive(_project(tmp_path))
        by_name = {d.name: d.scope for d in deps}
        assert by_name, deps
        assert all(s for s in by_name.values()), by_name
        assert by_name.get("pytest") == "excluded"      # unverändert

    def test_the_payload_carries_the_scope(self, tmp_path: Path) -> None:
        # Abnahme des Auftrags: das Testmaterial ist in der Einsendung
        # ausgewiesen, damit der Bericht es trennen kann.
        proj = _project(tmp_path)
        with patch("embtrace_check.cli.upload_payload", return_value="R") as up:
            res = CliRunner().invoke(
                main, [str(proj), "--send", "--yes", "--email", "a@b.de"],
            )
        assert res.exit_code == 0, res.output
        comps = up.call_args[0][0].components
        assert comps
        assert all(getattr(c, "scope", "") for c in comps), [
            (c.name, getattr(c, "scope", "")) for c in comps
        ]

    def test_the_written_sbom_separates_product_from_test_material(
        self, tmp_path: Path,
    ) -> None:
        proj = _project(tmp_path)
        res = CliRunner().invoke(main, [str(proj)])
        assert res.exit_code == 0, res.output
        doc = json.loads(
            (proj / "sbom.cdx.json").read_text(encoding="utf-8"),
        )
        scopes = {c["name"]: c.get("scope") for c in doc["components"]}
        assert scopes, doc
        assert all(scopes.values()), scopes
        assert "excluded" in scopes.values()
