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


#: What a customer may still have on disk under the spelling of the former
#: product name, and the name it must carry now. We deliberately do NOT read
#: these: the move of 01.10.2026 is complete, without a compatibility layer.
#:
#: But a hand-written declaration that is ignored in silence is a measurement
#: loss nobody notices — and "nothing happens silently" is this tool's own
#: promise. Measured 05.10.2026: a project holding only the former
#: ``*-deps.yaml`` produced a bill with zero declared components and no word
#: about it. So we look for them in order to SAY so, and only for that.
_FORMER_SPELLINGS = {
    CONFIG: "embtrace.yaml",        # alter-name-als-datum
    DEPS: "embtrace-deps.yaml",     # alter-name-als-datum
    IGNORE: ".embtraceignore",      # alter-name-als-datum
}


def former_spelling_present(directory: Path) -> list[tuple[str, str]]:
    """``[(file that is there, name it needs)]`` for files we will NOT read.

    Empty when the directory holds none — the normal case.
    """
    found = []
    for current, former in _FORMER_SPELLINGS.items():
        if (directory / former).is_file() and not (directory / current).is_file():
            found.append((former, current))
    return found


def find(directory: Path, name: str) -> Path | None:
    """The file in *directory*, or None when it is not there."""
    path = directory / name
    return path if path.is_file() else None
