"""Deterministic Meson build-file parser.

Extracts dependency names from meson.build by matching:
- dependency('name', ...)
- find_library('name', ...)
- compiler.find_library('name', ...)

find_program() is intentionally NOT included — it captures build tools,
scripts, and interpreters that are not SBOM dependencies.
"""

from __future__ import annotations

import re

# dependency('zlib', required: true, fallback: ['zlib', 'zlib_dep'])
_DEPENDENCY = re.compile(
    r"dependency\s*\(\s*'([^']+)'",
)

# Also handle double quotes
_DEPENDENCY_DQ = re.compile(
    r'dependency\s*\(\s*"([^"]+)"',
)

# cc.find_library('m', required: false)
# find_library('dl')
_FIND_LIBRARY = re.compile(
    r"find_library\s*\(\s*'([^']+)'",
)

_FIND_LIBRARY_DQ = re.compile(
    r'find_library\s*\(\s*"([^"]+)"',
)

# Meson built-in / meta-dependencies and false positives to skip
_SKIP: set[str] = {
    "threads",  # Meson built-in, maps to pthreads internally
    "appleframeworks",  # Not a real dep — Meson macOS helper
    "",
}

# Patterns that indicate a false positive (not a real dependency)
def _is_false_positive(name: str) -> bool:
    """Check if a dependency name is a false positive."""
    # Meson variable interpolation: @0@, lib@0@, gst-tester-@0@
    if "@" in name:
        return True
    # Python scripts: foo.py
    if name.endswith(".py"):
        return True
    # Single-char or two-char names are almost never real deps
    if len(name) <= 2:
        return True
    # Internal subproject variants (harfbuzz-cairo, harfbuzz-subset, etc.)
    # These are build targets, not external dependencies
    lower = name.lower()
    # Generic meson variable names
    if lower in ("depname", "dep_name", "dep"):
        return True
    # macOS frameworks
    if lower in (
        "applicationservices", "coregraphics", "coreimage", "coremedia",
        "corevideo", "coreservices", "corefoundation", "coretext",
        "coreaudio", "audiotoolbox", "avfoundation", "videotoolbox",
        "cocoa", "appkit", "iokit", "metal", "security",
        "systemconfiguration", "foundation",
    ):
        return True
    # System/build tools captured by dependency() in some projects
    if lower in (
        "g-ir-scanner", "g-ir-compiler", "gtkdoc-scan", "gdbus-codegen",
        "glib-compile-resources", "glib-compile-schemas",
        "msgfmt", "objcopy", "bpftool", "mkosi",
        "byacc", "bindgen", "cbindgen",
        "gi-docgen", "hotdoc",
        "asahi_clc",
        # Vala / Wayland / Flatpak build tools (not runtime deps)
        "vapi", "wayland-scanner", "wayland-protocols",
        "xdg-dbus-proxy", "bwrap",
    ):
        return True
    # FuzzingEngine / test infrastructure
    return lower in ("fuzzingengine",)


# Meson name → canonical name mapping
_NAME_MAP: dict[str, str] = {
    "threads": "threads",
}


def _strip_comments(content: str) -> str:
    """Remove single-line Meson comments."""
    return re.sub(r"#[^\n]*", "", content)


def parse(content: str) -> list[str]:
    """Extract dependency names from meson.build content."""
    content = _strip_comments(content)
    deps: set[str] = set()

    # dependency() calls
    # Some projects (e.g. systemd) pass space-separated pkg-config names:
    # dependency('tss2-esys tss2-rc tss2-mu') → split into individual deps
    for pattern in (_DEPENDENCY, _DEPENDENCY_DQ):
        for m in pattern.finditer(content):
            raw = m.group(1).strip()
            names = raw.split() if " " in raw else [raw]
            for name in names:
                name = name.strip()
                if name and name not in _SKIP and not _is_false_positive(name):
                    deps.add(_NAME_MAP.get(name, name))

    # find_library() calls
    for pattern in (_FIND_LIBRARY, _FIND_LIBRARY_DQ):
        for m in pattern.finditer(content):
            name = m.group(1).strip()
            if name and not _is_false_positive(name):
                deps.add(name)

    # NOTE: find_program() intentionally excluded — captures build tools,
    # not library dependencies. Build tools are not SBOM components.

    return sorted(deps)
