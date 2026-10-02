"""Files the customer writes, in one place.

``jochwacht.yaml`` (project configuration, written by the suite),
``jochwacht-deps.yaml`` (dependencies declared by hand) and
``.jochwachtignore`` (paths to leave out of a scan).

Mirror of ``jochwacht/core/filenames.py`` in the suite: both halves read
the same files, and a disagreement would mean one honours a file the other
ignores.
"""

from __future__ import annotations

from pathlib import Path

#: Project configuration — written by the suite, only read here.
CONFIG = "jochwacht.yaml"

#: Dependencies the customer declares by hand.
DEPS = "jochwacht-deps.yaml"

#: Paths to leave out of the scan.
IGNORE = ".jochwachtignore"

#: Every name the customer may write, for guards and listings.
ALL: tuple[str, ...] = (CONFIG, DEPS, IGNORE)


def both(name: str) -> tuple[str, ...]:
    """The spellings accepted for *name* — one each since 01.10.2026."""
    return (name,)


def find(directory: Path, name: str) -> Path | None:
    """The file in *directory*, or None when it is not there."""
    path = directory / name
    return path if path.is_file() else None
