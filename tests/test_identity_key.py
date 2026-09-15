"""A component's identity is its own name, not its fuzzy matching form.

Measured 15.09.2026 over six real trees: the de-duplication key ran through
``normalize_dep_name``, which strips pkg-config component suffixes
(``_core``, ``_client``, ``_base``, ``_common``, …) so that a CMake name
matches a pkg-config name. As a KEY it merged packages that are not the
same package, and 9 components vanished from the bill without a trace —
serde_core behind serde, playwright-core behind playwright,
@sentry/node-core behind @sentry/node, @docusaurus/utils-common behind
@docusaurus/utils. Each has its own version and its own CVE history.
"""

from __future__ import annotations

from pathlib import Path

from embtrace_sbom.analyzer.normalize import normalize_dep_name
from embtrace_sbom.collector import collect_components


def test_the_normalizer_really_does_collapse_these_names() -> None:
    # The premise of this test file, pinned: if this ever stops being true,
    # the test below would pass for the wrong reason.
    assert normalize_dep_name("serde_core") == normalize_dep_name("serde")
    assert normalize_dep_name("playwright-core") == normalize_dep_name("playwright")


def test_cargo_sibling_packages_both_survive(tmp_path: Path) -> None:
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "serde"\nversion = "1.0.229"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
        '[[package]]\nname = "serde_core"\nversion = "1.0.229"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
        encoding="utf-8",
    )
    comps, _stats = collect_components(tmp_path)
    got = {(c.name, c.version) for c in comps}
    assert got == {("serde", "1.0.229"), ("serde_core", "1.0.229")}


def test_npm_sibling_packages_both_survive(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {'
        '"node_modules/playwright": {"version": "1.47.0"},'
        '"node_modules/playwright-core": {"version": "1.47.0"},'
        '"node_modules/@sentry/node": {"version": "8.0.0"},'
        '"node_modules/@sentry/node-core": {"version": "8.0.0"}}}',
        encoding="utf-8",
    )
    names = {c.name for c in collect_components(tmp_path)[0]}
    assert {"playwright", "playwright-core", "@sentry/node", "@sentry/node-core"} <= names


def test_one_package_listed_twice_is_still_one_component(tmp_path: Path) -> None:
    # The de-duplication itself must keep working: same name, same version,
    # two files — one component. Case folding included.
    (tmp_path / "requirements.txt").write_text("Requests==2.31.0\n", encoding="utf-8")
    sub = tmp_path / "svc"
    sub.mkdir()
    (sub / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    comps = [c for c in collect_components(tmp_path)[0] if c.name.lower() == "requests"]
    assert len(comps) == 1, comps
