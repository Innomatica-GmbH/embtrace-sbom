"""The old product name appears nowhere in what we ship.

embtrace-check became embtrace-sbom and then jochwacht-sbom on 01.10.2026
(DPMA 302026254573.4). Ivan's acceptance criterion was literal: ``grep
embtrace`` returns nothing in the repositories. There are no customers and
no installations, so the forwarding shells and the compatibility readers
are gone too — the move is complete rather than layered.

This test is that criterion, encoded.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]

_NOT_OURS = {
    ".git", ".venv", "__pycache__", ".mypy_cache", ".ruff_cache",
    ".pytest_cache", "dist", "build", "node_modules",
}

_TEXT = {
    ".py", ".md", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".json",
    ".txt", ".sh", ".spec", ".html", ".js",
}

#: This file names the old spellings in order to forbid them.
_ALLOWED_TO_NAME_IT = {Path(__file__).resolve()}


def _shipped_files() -> list[Path]:
    out = []
    for path in _REPO.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _NOT_OURS for part in path.relative_to(_REPO).parts):
            continue
        if path.resolve() in _ALLOWED_TO_NAME_IT:
            continue
        if path.suffix.lower() in _TEXT:
            out.append(path)
    return out


@pytest.mark.parametrize("needle", ["embtrace", "Embtrace", "EMBTRACE"])
def test_no_shipped_file_names_the_old_product(needle: str) -> None:
    hits: list[str] = []
    for path in _shipped_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):  # pragma: no cover - binary
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if needle in line:
                hits.append(f"{path.relative_to(_REPO)}:{number}")
    assert not hits, hits


def test_the_search_would_actually_find_something() -> None:
    files = _shipped_files()
    assert len(files) > 40, len(files)
    assert any(p.suffix == ".py" for p in files)
    assert any(p.suffix == ".md" for p in files)
