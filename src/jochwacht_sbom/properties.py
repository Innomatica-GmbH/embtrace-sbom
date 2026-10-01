"""The CycloneDX property namespace this tool writes.

Both halves of the product write into one namespace and read each other's
files: the collector writes a bill, the suite reads it back, enriches it
and writes it again. They are separate release lines, so at any moment one
is older than the other.

Since 01.10.2026 new files carry ``jochwacht:``; everything written before
carries ``embtrace:``. Those files sit at customers and the CRA keeps them
for ten years, so the old spelling stays readable for good — not for a
transition period.

**This half only writes.** The reading side lives in the suite
(``embtrace/sbom/properties.py``), which accepts both spellings. What has
to match between the two is the prefix, and a test holds it.
"""

from __future__ import annotations

#: The namespace new files carry, and the one they used to carry.
PREFIX = "jochwacht:"
LEGACY_PREFIX = "embtrace:"


def name(key: str) -> str:
    """Full property name for *key* (``"ecosystem"`` → ``jochwacht:ecosystem``)."""
    return PREFIX + key


def legacy_name(key: str) -> str:
    """The pre-rename spelling of the same property."""
    return LEGACY_PREFIX + key
