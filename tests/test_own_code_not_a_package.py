"""The customer's own tree is not a third-party component (0.11.0 backlog).

Two phantom sources measured on real trees (15.09.2026, twin comparison):

* ripgrep — `globset`, `ignore`, `grep-matcher` were listed as components.
  They are ripgrep's OWN crates: `globset = { version = "0.4.18", path =
  "../globset" }`. The version is what gets published to crates.io, the
  path is what this build uses.
* pydantic — `dev`, `docs`, `linting` were listed as components. They are
  PEP 735 dependency-GROUP names, pulled out of
  `all = [{ include-group = 'dev' }, …]`.
"""

from __future__ import annotations

from pathlib import Path

from embtrace_sbom.analyzer.parsers import python as pyparse
from embtrace_sbom.analyzer.pipeline.tier2_structured import CargoTomlParser


class TestWorkspaceCrates:
    def _tree(self, tmp_path: Path) -> Path:
        (tmp_path / "crates" / "globset").mkdir(parents=True)
        (tmp_path / "crates" / "globset" / "Cargo.toml").write_text(
            '[package]\nname = "globset"\nversion = "0.4.18"\n', encoding="utf-8",
        )
        (tmp_path / "vendor" / "thirdparty").mkdir(parents=True)
        (tmp_path / "vendor" / "thirdparty" / "Cargo.toml").write_text(
            '[package]\nname = "someone-elses-crate"\nversion = "1.0.0"\n', encoding="utf-8",
        )
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "rg"\nversion = "14.0.0"\n\n'
            "[dependencies]\n"
            'anyhow = "1.0.75"\n'
            'globset = { version = "0.4.18", path = "crates/globset" }\n'
            'renamed = { version = "2.0", path = "vendor/thirdparty" }\n'
            'elsewhere = { version = "3.0", path = "../outside-the-tree" }\n',
            encoding="utf-8",
        )
        return tmp_path

    def test_own_crate_is_not_a_component(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path)
        res = CargoTomlParser().scan("cargo", root / "Cargo.toml", root)
        names = {d.name for d in res.dependencies}
        assert "globset" not in names           # the project's own crate
        assert "anyhow" in names                # a real third-party crate

    def test_a_path_that_names_a_different_crate_is_kept(self, tmp_path: Path) -> None:
        # vendor/thirdparty/Cargo.toml says "someone-elses-crate", the
        # dependency is called "renamed" — not the same crate, so the
        # reader does not guess it away.
        root = self._tree(tmp_path)
        names = {d.name for d in CargoTomlParser().scan(
            "cargo", root / "Cargo.toml", root).dependencies}
        assert "renamed" in names

    def test_an_unresolvable_path_is_kept(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path)
        names = {d.name for d in CargoTomlParser().scan(
            "cargo", root / "Cargo.toml", root).dependencies}
        assert "elsewhere" in names

    def test_path_only_dependency_still_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "x"\nversion = "1"\n\n'
            '[dependencies]\nlocal = { path = "crates/local" }\n', encoding="utf-8",
        )
        names = {d.name for d in CargoTomlParser().scan(
            "cargo", tmp_path / "Cargo.toml", tmp_path).dependencies}
        assert names == set()


class TestDependencyGroupReferences:
    _PYPROJECT = """[project]
name = "demo"
dependencies = ["typing-extensions>=4.12"]

[dependency-groups]
dev = [
    'coverage[toml]',
    'pytest',
]
docs = [
    'mkdocs',
]
all = [
  { include-group = 'dev' },
  { include-group = 'docs' },
]
"""

    def test_group_names_are_not_packages(self) -> None:
        got = set(pyparse.parse(self._PYPROJECT))
        assert "dev" not in got
        assert "docs" not in got
        assert "all" not in got

    def test_real_dependencies_still_read(self) -> None:
        got = set(pyparse.parse(self._PYPROJECT))
        assert "typing-extensions" in got
