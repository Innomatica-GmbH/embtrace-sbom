"""Environment variables, read through one place.

All switches are spelled ``JOCHWACHT_*``. Reading them here rather than
from ``os.environ`` directly keeps the prefix in one place, so a new
switch cannot be spelled a second way by accident.
"""

from __future__ import annotations

import os

#: Prefix every switch carries.
PREFIX = "JOCHWACHT_"

#: Turn the sanitised failure report back into a plain Python traceback.
TRACEBACK_ENV = PREFIX + "SBOM_TRACEBACK"

#: Skip resolving native dependencies against the linked system.
NO_SYSRESOLVE_ENV = PREFIX + "NO_SYSRESOLVE"


def get(name: str, default: str | None = None) -> str | None:
    """Value of *name*, or *default* when it is unset."""
    return os.environ.get(name, default)
