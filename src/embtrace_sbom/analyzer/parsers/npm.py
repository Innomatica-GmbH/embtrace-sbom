"""Deterministic package.json parser.

Extracts dependency names from Node.js package.json:
- dependencies
- devDependencies
- peerDependencies
- optionalDependencies
"""

from __future__ import annotations

import json


def parse(content: str) -> list[str]:
    """Extract dependency names from package.json content."""
    deps: set[str] = set()

    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return []

    if not isinstance(data, dict):
        return []

    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section_deps = data.get(section, {})
        if isinstance(section_deps, dict):
            deps.update(section_deps.keys())

    return sorted(deps)
