"""Deterministic Cargo.toml parser.

Extracts dependency names from Rust Cargo.toml by parsing:
- [dependencies]
- [dev-dependencies]
- [build-dependencies]
- [target.'cfg(...)'.dependencies]

Filters out path-only dependencies (workspace members).
"""

from __future__ import annotations

import re

# Section headers
_SECTION = re.compile(r"^\[([^\]]+)\]", re.MULTILINE)

# Simple dependency: name = "version"
_SIMPLE_DEP = re.compile(r"^(\w[\w-]*)\s*=\s*\"([^\"]+)\"", re.MULTILINE)

# Table dependency: name = { version = "...", ... }
# Also matches: name = { path = "..." } (internal — filter later)
_TABLE_DEP = re.compile(
    r"^(\w[\w-]*)\s*=\s*\{([^}]+)\}",
    re.MULTILINE,
)

# Workspace members in [workspace]
_WORKSPACE_MEMBERS = re.compile(
    r"members\s*=\s*\[([^\]]+)\]",
    re.DOTALL,
)


def _is_dep_section(section: str) -> bool:
    """Check if a TOML section header is a dependency section."""
    s = section.lower().strip()
    return s.endswith("dependencies") and not s.startswith("workspace")


_PACKAGE_FIELD = re.compile(r'package\s*=\s*"([^"]+)"')


def _extract_package_name(table_content: str) -> str | None:
    """Extract the actual package name from a ``package = "..."`` field."""
    m = _PACKAGE_FIELD.search(table_content)
    return m.group(1) if m else None


def _has_path_only(table_content: str) -> bool:
    """Check if a table-style dependency is path-only (internal)."""
    has_path = "path" in table_content
    has_version = "version" in table_content
    has_git = "git" in table_content
    has_workspace = re.search(r"workspace\s*=\s*true", table_content) is not None
    # workspace = true without external source = workspace/internal dep
    if has_workspace and not has_git:
        return True
    # path-only without version = workspace/internal dep
    return has_path and not has_version and not has_git


def parse(content: str) -> list[str]:
    """Extract dependency names from Cargo.toml content."""
    deps: set[str] = set()

    # Find all sections and their content ranges
    sections: list[tuple[str, int, int]] = []
    for m in _SECTION.finditer(content):
        sections.append((m.group(1), m.end(), 0))  # end will be filled below

    # Fill section end positions
    filled: list[tuple[str, int, int]] = []
    for i, (name, start, _) in enumerate(sections):
        end = (
            sections[i + 1][1] - len(sections[i + 1][0]) - 2
            if i + 1 < len(sections) else len(content)
        )
        filled.append((name, start, end))

    # Process each dependency section
    for section_name, start, end in filled:
        if not _is_dep_section(section_name):
            continue

        section_content = content[start:end]

        # Simple deps: name = "version"
        for m in _SIMPLE_DEP.finditer(section_content):
            deps.add(m.group(1))

        # Table deps: name = { version = "...", ... }
        for m in _TABLE_DEP.finditer(section_content):
            name = m.group(1)
            table = m.group(2)
            if not _has_path_only(table):
                # Use actual package name if renamed (package = "real_name")
                pkg = _extract_package_name(table)
                deps.add(pkg if pkg else name)

    return sorted(deps)
