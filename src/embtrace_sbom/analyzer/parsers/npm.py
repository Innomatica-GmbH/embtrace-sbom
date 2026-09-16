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
        if not isinstance(section_deps, dict):
            continue
        for name, spec in section_deps.items():
            # `workspace:`, `link:` and `portal:` point into the customer's
            # OWN tree — not a third-party package. This is the regex
            # fallback and has no file path, so it cannot tell a `file:`
            # directory (own tree) from a vendored `file:...tgz` archive (a
            # real component); it keeps both, and the structured parser,
            # which wins the merge, makes the finer call. Without this the
            # fallback would simply re-add what tier 2 just dropped.
            if isinstance(spec, str) and spec.strip().startswith(
                ("workspace:", "link:", "portal:")
            ):
                continue
            deps.add(name)

    return sorted(deps)
