"""A JSON file whose top level is not an object must not crash a reader.

Measured in the first nightly after the reader-crash detection went in
(kettenlauf #68, 16.09.2026): grpc carries two `package.json` files that
contain a JSON **string** — a note saying the examples moved to another
repository. `json.loads` succeeds, returns a `str`, and the reader then
raised `AttributeError` on `data.get`. Two crashed readers, the row red,
the proposal incomplete.

Every JSON reader now says the same thing a parse failure says, so the
file is visible and counted, and the scan continues.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from jochwacht_sbom.analyzer.pipeline.tier2_structured import PackageJsonParser
from jochwacht_sbom.sbom.scanner import (
    scan_conan_lock,
    scan_package_lock_json,
    scan_pipfile_lock,
    scan_vcpkg_json,
)

#: The literal shape from grpc's examples/node/package.json.
_GRPC_STRING = '"These examples have been moved to https://github.com/grpc/grpc-node"'

_READERS = [
    ("conan.lock", scan_conan_lock),
    ("Pipfile.lock", scan_pipfile_lock),
    ("vcpkg.json", scan_vcpkg_json),
    ("package-lock.json", scan_package_lock_json),
]


@pytest.mark.parametrize(("filename", "reader"), _READERS)
@pytest.mark.parametrize("content", [_GRPC_STRING, "[]", "42", "null", '"x"'])
def test_non_object_json_yields_nothing_and_says_so(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
    filename: str, reader: object, content: str,
) -> None:
    f = tmp_path / filename
    f.write_text(content, encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        assert reader(f) == []                      # type: ignore[operator]
    assert any("Failed to parse" in r.message or "Failed to parse" in r.getMessage()
               for r in caplog.records), caplog.text


def test_package_json_parser_does_not_crash_on_a_string(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    f = tmp_path / "package.json"
    f.write_text(_GRPC_STRING, encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        res = PackageJsonParser().scan("npm", f, tmp_path)
    assert res.dependencies == []
    assert "Failed to parse" in caplog.text


def test_a_real_manifest_still_reads(tmp_path: Path) -> None:
    f = tmp_path / "package.json"
    f.write_text('{"dependencies": {"lodash": "^4.17.21"}}', encoding="utf-8")
    res = PackageJsonParser().scan("npm", f, tmp_path)
    assert [(d.name, d.version) for d in res.dependencies] == [("lodash", "^4.17.21")]
