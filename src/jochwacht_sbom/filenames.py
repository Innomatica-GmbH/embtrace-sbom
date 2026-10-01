"""Files the CUSTOMER writes — new name preferred, old name still read.

Mirror of ``embtrace/core/filenames.py`` in the suite. Three files live in
the customer's repository and carry our product name:

===========================  =========================================
``jochwacht.yaml``           the project configuration (suite)
``jochwacht-deps.yaml``      dependencies declared by hand
``.jochwachtignore``         paths to leave out of the scan
===========================  =========================================

Until 01.10.2026 they were spelled ``embtrace*``. Both spellings are
accepted, the new one wins when both exist — and that is not politeness
towards customers (there are none yet) but towards the SUITE, which is a
separate release line and at any moment older or newer than this tool.
A file one half writes, the other half has to find.
"""

from __future__ import annotations

from pathlib import Path

#: Project configuration — written by the suite, only read here.
CONFIG = "jochwacht.yaml"
LEGACY_CONFIG = "embtrace.yaml"

#: Dependencies the customer declares by hand.
DEPS = "jochwacht-deps.yaml"
LEGACY_DEPS = "embtrace-deps.yaml"

#: Paths to leave out of the scan.
IGNORE = ".jochwachtignore"
LEGACY_IGNORE = ".embtraceignore"

#: Every pair, new spelling first. Order matters: the first hit wins.
PAIRS: tuple[tuple[str, str], ...] = (
    (CONFIG, LEGACY_CONFIG),
    (DEPS, LEGACY_DEPS),
    (IGNORE, LEGACY_IGNORE),
)


def both(new: str) -> tuple[str, ...]:
    """``(new, old)`` for a known name, else just ``(new,)``."""
    for current, legacy in PAIRS:
        if new == current:
            return (current, legacy)
    return (new,)


def find(directory: Path, new: str) -> Path | None:
    """The existing file in *directory*, new spelling preferred, else None."""
    for candidate in both(new):
        path = directory / candidate
        if path.is_file():
            return path
    return None
