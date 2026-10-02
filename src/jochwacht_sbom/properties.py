"""The CycloneDX property namespace this tool writes.

Three keys under ``jochwacht:`` travel with every component: the ecosystem
it was read from, which reader found it, and the build condition it sits
behind. The suite reads them back when it enriches a bill, so the spelling
lives in one place on each side.
"""

from __future__ import annotations

#: The namespace every generated file carries.
PREFIX = "jochwacht:"


def name(key: str) -> str:
    """Full property name for *key* (``"ecosystem"`` → ``jochwacht:ecosystem``)."""
    return PREFIX + key
