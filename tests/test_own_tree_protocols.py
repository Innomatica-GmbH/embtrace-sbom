"""A dependency pointing into the customer's own tree is not a component.

Measured 16.09.2026 while explaining an eight-component gap between the
suite and the collector on streamlit: both tools listed the project's OWN
packages. In the manifests they appear as `"@streamlit/lib": "workspace:^"`
— a pointer, standing where a version belongs. streamlit had seven of them,
vue-core eleven.

`file:` is deliberately not treated like the other three: it points at a
local path, and that path can be a sibling package (own tree) or a vendored
third-party archive (`file:./vendor/foo-1.2.3.tgz`) — a real component of
the product, which must not vanish. A directory is the own tree; an archive
stays in the bill, and so does anything that cannot be resolved.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from jochwacht_sbom.analyzer.parsers import npm as npm_parser
from jochwacht_sbom.analyzer.pipeline.tier2_structured import PackageJsonParser


def _manifest(tmp_path: Path, deps: dict[str, str]) -> Path:
    f = tmp_path / "package.json"
    f.write_text(json.dumps({"name": "app", "dependencies": deps}), encoding="utf-8")
    return f


class TestPointersIntoTheOwnTree:
    @pytest.mark.parametrize("spec", ["workspace:^", "workspace:*", "link:../lib",
                                      "portal:../shared"])
    def test_are_not_components(self, tmp_path: Path, spec: str) -> None:
        f = _manifest(tmp_path, {"@acme/lib": spec, "lodash": "^4.17.21"})
        names = {d.name for d in PackageJsonParser().scan("npm", f, tmp_path).dependencies}
        assert names == {"lodash"}

    def test_the_fallback_parser_agrees(self) -> None:
        content = json.dumps({"dependencies": {
            "@acme/lib": "workspace:^", "other": "link:../o", "lodash": "^4.17.21",
        }})
        assert npm_parser.parse(content) == ["lodash"]

    def test_the_run_says_how_many_it_left_out(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        f = _manifest(tmp_path, {"a": "workspace:^", "b": "link:../b", "c": "^1.0.0"})
        with caplog.at_level(logging.INFO):
            PackageJsonParser().scan("npm", f, tmp_path)
        assert "2 Eintraege zeigen in den eigenen Baum" in caplog.text


class TestFileIsDecidedByLooking:
    def test_a_directory_in_the_tree_is_the_own_tree(self, tmp_path: Path) -> None:
        (tmp_path / "shared-lib").mkdir()
        f = _manifest(tmp_path, {"shared-lib": "file:./shared-lib", "lodash": "^4.17.21"})
        names = {d.name for d in PackageJsonParser().scan("npm", f, tmp_path).dependencies}
        assert names == {"lodash"}

    def test_a_vendored_archive_stays_in_the_bill(self, tmp_path: Path) -> None:
        # How a locked-down environment pulls in a library that may not come
        # from the registry. It is a third-party component the customer ships.
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "foo-1.2.3.tgz").write_bytes(b"x")
        f = _manifest(tmp_path, {"foo": "file:./vendor/foo-1.2.3.tgz"})
        names = {d.name for d in PackageJsonParser().scan("npm", f, tmp_path).dependencies}
        assert names == {"foo"}

    def test_an_unresolvable_path_stays_too(self, tmp_path: Path) -> None:
        f = _manifest(tmp_path, {"foo": "file:../not/here"})
        names = {d.name for d in PackageJsonParser().scan("npm", f, tmp_path).dependencies}
        assert names == {"foo"}

    def test_the_fallback_keeps_every_file_entry(self) -> None:
        # No path to look at: it keeps both rather than guessing one away.
        content = json.dumps({"dependencies": {"foo": "file:./vendor/foo.tgz",
                                               "bar": "file:./bar"}})
        assert npm_parser.parse(content) == ["bar", "foo"]


def test_ordinary_ranges_are_untouched(tmp_path: Path) -> None:
    f = _manifest(tmp_path, {"lodash": "^4.17.21", "react": "18.3.1",
                             "x": "npm:alias@^2", "y": "github:org/repo"})
    names = {d.name for d in PackageJsonParser().scan("npm", f, tmp_path).dependencies}
    assert names == {"lodash", "react", "x", "y"}
