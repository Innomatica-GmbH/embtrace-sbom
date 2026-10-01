"""Deterministic go.mod parser.

Extracts dependency module paths from Go go.mod files by parsing:
- require blocks: require ( ... )
- single require statements: require module/path v1.2.3

Only includes direct dependencies (not indirect).
"""

from __future__ import annotations

import re

# Single require: require github.com/foo/bar v1.2.3
_SINGLE_REQUIRE = re.compile(
    r"^require\s+(\S+)\s+v[\d.]+",
    re.MULTILINE,
)

# Require block
_REQUIRE_BLOCK = re.compile(
    r"^require\s*\((.*?)\)",
    re.MULTILINE | re.DOTALL,
)

# Line inside require block: github.com/foo/bar v1.2.3
# Optional // indirect marker
_REQUIRE_LINE = re.compile(
    r"^\s+(\S+)\s+v[\S]+(?:\s+//\s*(indirect))?",
    re.MULTILINE,
)


def parse(content: str) -> list[str]:
    """Extract dependency module paths from go.mod content.

    Only returns direct dependencies (excludes lines marked // indirect).
    """
    deps: set[str] = set()

    # Single require statements
    for m in _SINGLE_REQUIRE.finditer(content):
        deps.add(m.group(1))

    # Require blocks
    for block in _REQUIRE_BLOCK.finditer(content):
        block_content = block.group(1)
        for line in _REQUIRE_LINE.finditer(block_content):
            module = line.group(1)
            indirect = line.group(2)
            if not indirect:
                deps.add(module)

    return sorted(deps)
