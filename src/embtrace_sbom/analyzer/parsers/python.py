"""Deterministic Python build-file parser.

Extracts dependency names from:
- pyproject.toml: [project.dependencies], [project.optional-dependencies.*]
  (excluding test/dev/doc/lint extras), [dependency-groups.*] (PEP 735,
  excluding test/dev/doc/lint groups)
- setup.py: install_requires=[...] (tests_require and extras_require with
  test/dev names are excluded)
- setup.cfg: [options] install_requires
- requirements.txt: one dependency per line (but not requirements-dev.txt etc.)
"""

from __future__ import annotations

import re

# --- pyproject.toml patterns --------------------------------------------------

# dependencies = ["name>=version", "name[extra]>=version", ...]
_PYPROJECT_DEPS = re.compile(
    r"dependencies\s*=\s*\[(.*?)\]",
    re.DOTALL,
)

# Individual dependency string: "name>=version" or "name[extra]>=version"
# Names must start with a letter (PEP 508) — digits would match version strings
# like '3.12' inside environment markers.
_DEP_STRING = re.compile(
    r"""['"]([a-zA-Z][\w.-]*)""",
)

# [project.optional-dependencies] sections
_OPTIONAL_SECTION = re.compile(
    r"^\[(?:project\.)?optional-dependencies(?:\.\w+)?\]\s*$",
    re.MULTILINE,
)

# [dependency-groups] section (PEP 735)
_DEP_GROUPS_SECTION = re.compile(
    r"^\[dependency-groups(?:\.\w+)?\]\s*$",
    re.MULTILINE,
)

# key = ["dep1", "dep2"]  — captures key name AND list contents
_LIST_VALUE = re.compile(
    r"^(\w[\w-]*)\s*=\s*\[(.*?)\]",
    re.MULTILINE | re.DOTALL,
)

# Group names that indicate test / dev / doc / lint extras (not runtime deps)
_DEV_GROUP_NAMES = re.compile(
    r"(?:^|[-_])"
    r"(?:test|tests|testing|dev|devel|develop|development|doc|docs"
    r"|lint|linting|type|typing|typecheck|types|ci|build|style"
    r"|format|check|checks|quality|qa|static|benchmark|bench"
    r"|debug|profiling|mypy|ruff|coverage|tox|nox"
    r"|pre-commit|gha|github-actions)"
    r"(?:[-_]|$)",
    re.IGNORECASE,
)

# --- setup.py patterns -------------------------------------------------------

# install_requires=["name>=version", ...]
_SETUP_PY_INSTALL = re.compile(
    r"install_requires\s*=\s*\[(.*?)\]",
    re.DOTALL,
)

# tests_require=["name>=version", ...]
_SETUP_PY_TESTS = re.compile(
    r"tests_require\s*=\s*\[(.*?)\]",
    re.DOTALL,
)

# extras_require={"extra": ["name>=version", ...]}
_SETUP_PY_EXTRAS = re.compile(
    r"extras_require\s*=\s*\{(.*?)\}",
    re.DOTALL,
)

# --- setup.cfg patterns ------------------------------------------------------

# [options]
# install_requires =
#     name>=version
#     name>=version
_SETUP_CFG_INSTALL = re.compile(
    r"install_requires\s*=\s*\n((?:\s+\S+.*\n)*)",
    re.MULTILINE,
)

# Individual line in setup.cfg list
_CFG_DEP_LINE = re.compile(
    r"^\s+([a-zA-Z0-9][\w.-]*)",
    re.MULTILINE,
)

# --- requirements.txt patterns -----------------------------------------------

# name>=version or name==version or just name (bare name allowed)
# Uses explicit PEP 440 operators to avoid matching config key assignments
# (e.g. "allow_any_generics = false" must NOT match — bare = is not a dep operator).
# Names must start with a letter to avoid version strings like "3.9" being captured.
_REQUIREMENTS_LINE = re.compile(
    r"^\s*([a-zA-Z][\w.-]*)\s*(?:[><!~]=|===|==|[><]|\s*;|\s*$)",
    re.MULTILINE,
)

# INI-style section headers that mark a file as a config file, not requirements.txt.
# Matches [mypy], [tox], [tox:tox], [testenv], [testenv:name], [coverage:*],
# [tool:pytest], [tool.ruff], [flake8], [isort], [bandit], [pylint], etc.
_INI_CONFIG_SECTION = re.compile(
    r"^\[(?:mypy|tox|testenv|coverage|flake8|isort|black|ruff|bandit|pylint|tool[:.][^]]*)\s*[:\]]",
    re.MULTILINE | re.IGNORECASE,
)


def _extract_names_from_list(text: str) -> set[str]:
    """Extract package names from a Python list/string of dependencies.

    Each dependency string may contain environment markers after ``;`` and
    extras in ``[...]``.  We strip markers first to avoid capturing platform
    names (``CPython``, ``Windows``) or version strings (``3.12``) that
    appear inside marker expressions.

    We match double-quoted strings first (TOML standard), then fall back
    to single-quoted strings, to avoid splitting on single quotes embedded
    inside double-quoted values like ``"pkg ; impl == 'CPython'"``.
    """
    names: set[str] = set()

    # Match double-quoted strings first (preferred in TOML/pyproject.toml)
    # then single-quoted strings as fallback (setup.py, setup.cfg).
    for quoted in re.finditer(r'"([^"]+)"|\'([^\']+)\'', text):
        dep_str = (quoted.group(1) or quoted.group(2) or "").strip()
        # Strip environment marker (everything after first ;)
        dep_str = dep_str.split(";")[0].strip()
        # Strip extras: "name[extra1,extra2]>=ver" -> "name"
        dep_str = dep_str.split("[")[0].strip()
        # Extract package name from the beginning of the dep spec
        m = re.match(r"([a-zA-Z][\w.-]*)", dep_str)
        if m:
            names.add(m.group(1))
    return names


def _extract_section_deps(
    content: str,
    section_pattern: re.Pattern[str],
    *,
    skip_dev_groups: bool = False,
) -> set[str]:
    """Extract deps from TOML sections matching a pattern.

    Args:
        content: Full file content.
        section_pattern: Regex matching section headers.
        skip_dev_groups: If True, skip key groups whose name matches
            test/dev/doc/lint patterns (see ``_DEV_GROUP_NAMES``).
    """
    deps: set[str] = set()
    sections = list(section_pattern.finditer(content))
    for section_match in sections:
        start = section_match.end()
        # Find next section
        next_section = re.search(r"^\[", content[start:], re.MULTILINE)
        end = start + next_section.start() if next_section else len(content)
        section_content = content[start:end]

        for lv in _LIST_VALUE.finditer(section_content):
            key_name = lv.group(1)
            if skip_dev_groups and _DEV_GROUP_NAMES.search(key_name):
                continue
            deps.update(_extract_names_from_list(lv.group(2)))
    return deps


def _is_requirements_txt(content: str) -> bool:
    """Heuristic: detect requirements.txt format (no TOML/Python syntax)."""
    if "[project]" in content or "[build-system]" in content:
        return False
    if "[metadata]" in content or "[options]" in content:
        return False
    if "setup(" in content:
        return False
    # Reject INI-style config files (tox.ini, mypy.ini, .cfg with tool sections, etc.)
    # These have [mypy], [tox:tox], [testenv:*], [coverage:*], [tool:pytest], etc.
    if _INI_CONFIG_SECTION.search(content):
        return False
    # requirements.txt has simple "name>=version" lines
    raw = content.split("\n")
    lines = [ln.strip() for ln in raw if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return False
    # Check if most lines look like dependency specs
    dep_like = sum(1 for ln in lines if _REQUIREMENTS_LINE.match(ln))
    return dep_like > len(lines) * 0.5


def parse(content: str) -> list[str]:
    """Extract dependency names from Python build files."""
    deps: set[str] = set()

    # Detect file type by content
    is_pyproject = "[project]" in content or "[build-system]" in content
    is_setup_cfg = "[metadata]" in content or "[options]" in content
    is_setup_py = "setup(" in content
    is_requirements = _is_requirements_txt(content)

    if is_pyproject:
        # [project] dependencies = [...]
        for m in _PYPROJECT_DEPS.finditer(content):
            deps.update(_extract_names_from_list(m.group(1)))

        # [project.optional-dependencies.*] — skip test/dev/doc/lint groups
        deps.update(
            _extract_section_deps(content, _OPTIONAL_SECTION, skip_dev_groups=True),
        )

        # [dependency-groups.*] (PEP 735) — skip test/dev/doc/lint groups
        deps.update(
            _extract_section_deps(content, _DEP_GROUPS_SECTION, skip_dev_groups=True),
        )

    if is_setup_py:
        for m in _SETUP_PY_INSTALL.finditer(content):
            deps.update(_extract_names_from_list(m.group(1)))
        # NOTE: tests_require intentionally excluded — test deps are not runtime deps
        # extras_require: include only non-dev extras
        for m in _SETUP_PY_EXTRAS.finditer(content):
            # Parse individual key: [...] pairs from the dict literal
            extra_pairs = re.finditer(
                r"""['"](\w[\w-]*)['"]:\s*\[(.*?)\]""",
                m.group(1),
                re.DOTALL,
            )
            for pair in extra_pairs:
                extra_name = pair.group(1)
                if not _DEV_GROUP_NAMES.search(extra_name):
                    deps.update(_extract_names_from_list(pair.group(2)))

    if is_setup_cfg:
        for m in _SETUP_CFG_INSTALL.finditer(content):
            for dep in _CFG_DEP_LINE.finditer(m.group(1)):
                deps.add(dep.group(1))

    if is_requirements:
        for m in _REQUIREMENTS_LINE.finditer(content):
            deps.add(m.group(1))

    return sorted(deps)
