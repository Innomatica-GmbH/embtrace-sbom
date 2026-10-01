"""Environment variables: the new name wins, the old one still works.

The tool was called ``embtrace-sbom`` until 0.11.1, so its switches were
spelled ``EMBTRACE_*``. They live in people's shell profiles and CI files,
and a rename that silently stops reading them turns a working setup into a
setting that is simply ignored — the worst kind of breakage, because
nothing says so.

The rule is mechanical, not a table: ``JOCHWACHT_X`` is read first, and
``EMBTRACE_X`` answers when the new name is unset. One rule means a switch
added later cannot forget its old spelling.
"""

from __future__ import annotations

import os

#: Prefix of the current names, and of the names they replaced.
PREFIX = "JOCHWACHT_"
LEGACY_PREFIX = "EMBTRACE_"

#: Turn the sanitised failure report back into a plain Python traceback.
TRACEBACK_ENV = PREFIX + "SBOM_TRACEBACK"

#: Skip resolving native dependencies against the linked system.
NO_SYSRESOLVE_ENV = PREFIX + "NO_SYSRESOLVE"


def legacy_name(name: str) -> str:
    """The pre-rename spelling of *name* (unchanged when there is none)."""
    if name.startswith(PREFIX):
        return LEGACY_PREFIX + name[len(PREFIX):]
    return name


def get(name: str, default: str | None = None) -> str | None:
    """Value of *name*, falling back to its pre-rename spelling.

    An empty value counts as set-but-empty for the new name — only an
    absent variable falls through to the old one, so ``JOCHWACHT_X=``
    deliberately switches a thing off without the old name reviving it.
    """
    if name in os.environ:
        return os.environ[name]
    return os.environ.get(legacy_name(name), default)
