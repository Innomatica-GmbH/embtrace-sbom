"""Deterministic Gradle build-file parser.

Extracts dependency names from build.gradle / build.gradle.kts:
- implementation 'group:artifact:version'
- api 'group:artifact:version'
- compileOnly 'group:artifact:version'
- runtimeOnly 'group:artifact:version'
- testImplementation 'group:artifact:version'
- annotationProcessor 'group:artifact:version'
- classpath 'group:artifact:version'

Also handles:
- Variable references: libs.jacksonDatabind → must be resolved from dependencies.gradle
- Kotlin DSL: implementation("group:artifact:version")
- String interpolation: implementation "group:artifact:${version}"
"""

from __future__ import annotations

import re

# Dependency configurations (Groovy DSL)
# implementation 'group:artifact:version'
# api "group:artifact:version"
_GROOVY_DEP = re.compile(
    r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|"
    r"testRuntimeOnly|testCompileOnly|annotationProcessor|classpath|"
    r"kapt|ksp|compileOnlyApi)\s+"
    r"['\"]([a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+)(?::([^'\"]+))?['\"]",
)

# Kotlin DSL: implementation("group:artifact:version")
_KOTLIN_DEP = re.compile(
    r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|"
    r"testRuntimeOnly|testCompileOnly|annotationProcessor|classpath|"
    r"kapt|ksp|compileOnlyApi)\s*\(\s*"
    r"['\"]([a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+)(?::([^'\"]+))?['\"]",
)

# dependency block with group/name/version:
# compile group: 'org.foo', name: 'bar', version: '1.0'
_MAP_DEP = re.compile(
    r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|"
    r"testRuntimeOnly|classpath)\s+"
    r"group:\s*['\"]([^'\"]+)['\"]\s*,\s*name:\s*['\"]([^'\"]+)['\"]",
)

# Gradle version catalog / dependencies.gradle map entries:
# key: "group:artifact:$versions.xxx" or key: "group:artifact:version"
_CATALOG_ENTRY = re.compile(
    r"\w+:\s*['\"]([a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+)(?::[^'\"]*)?['\"]",
)

# buildscript dependencies
_BUILDSCRIPT_DEP = re.compile(
    r"classpath\s+['\"]([a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+)(?::[^'\"]+)?['\"]",
)


def _strip_comments(content: str) -> str:
    """Remove single-line and multi-line comments."""
    content = re.sub(r"//[^\n]*", "", content)
    content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    return content


def parse(content: str) -> list[str]:
    """Extract dependency coordinates (group:artifact) from build.gradle content."""
    content = _strip_comments(content)
    deps: set[str] = set()

    # Groovy DSL
    for m in _GROOVY_DEP.finditer(content):
        deps.add(m.group(1))

    # Kotlin DSL
    for m in _KOTLIN_DEP.finditer(content):
        deps.add(m.group(1))

    # Map-style dependency declarations
    for m in _MAP_DEP.finditer(content):
        group = m.group(1)
        name = m.group(2)
        deps.add(f"{group}:{name}")

    # Buildscript classpath
    for m in _BUILDSCRIPT_DEP.finditer(content):
        deps.add(m.group(1))

    # Version catalog / dependencies.gradle map entries
    for m in _CATALOG_ENTRY.finditer(content):
        coord = m.group(1)
        # Filter: must look like a real Maven coordinate (at least one dot in group)
        if "." in coord.split(":")[0]:
            deps.add(coord)

    return sorted(deps)
