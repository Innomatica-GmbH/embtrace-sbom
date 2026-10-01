"""Deterministic Makefile parser.

Extracts dependency names from Makefiles by matching:
- -l flags (only after whitespace — avoids false positives from --language etc.)
- pkg-config --libs calls
- $(shell pkg-config --cflags name)
"""

from __future__ import annotations

import re

# -lfoo ONLY when preceded by whitespace, '=' or start-of-line.
# This avoids matching --language → -language → "anguage",
# fsm-listen → -listen → "isten", etc.
_DASH_L = re.compile(
    r"(?:^|[\s=])-l([A-Za-z0-9][A-Za-z0-9_.+-]{2,})",
    re.MULTILINE,
)

# pkg-config --libs name or pkg-config --cflags name
_PKG_CONFIG = re.compile(
    r"pkg-config\s+(?:--\w+\s+)*([a-zA-Z0-9_][a-zA-Z0-9_.+-]*)",
)

# $(shell pkg-config ...)
_SHELL_PKG_CONFIG = re.compile(
    r"\$\(shell\s+pkg-config\s+(?:--\w+\s+)*([a-zA-Z0-9_][a-zA-Z0-9_.+-]*)\)",
)

# EXTLIBS += -lfoo (git-style)
_EXTLIBS = re.compile(
    r"EXTLIBS\s*\+?=\s*.*?-l(\w+)",
)

# Libraries to skip (system/compiler runtime, not SBOM deps)
_SKIP: set[str] = {
    "c",       # libc
    "gcc",     # compiler runtime
    "stdc++",  # C++ standard library
    "m",       # libm (math, glibc)
    "dl",      # libdl (dynamic linker)
    "rt",      # librt (realtime, glibc)
    "pthread", # pthreads
    "resolv",  # libresolv (DNS, glibc)
    "crypt",   # libcrypt
    "util",    # libutil
    "atomic",  # libatomic (compiler)
    "supc++",  # C++ support
    "nsl",     # libnsl (NIS, Solaris)
    "socket",  # libsocket (Solaris)
    "gen",     # libgen (basename/dirname, Solaris)
    "cc",      # compiler (not a dep)
}


def _strip_comments(content: str) -> str:
    """Remove Makefile comments."""
    return re.sub(r"#[^\n]*", "", content)


def parse(content: str) -> list[str]:
    """Extract dependency names from Makefile content."""
    content = _strip_comments(content)
    deps: set[str] = set()

    # -l flags (only when preceded by whitespace/= to avoid word fragments)
    for m in _DASH_L.finditer(content):
        name = m.group(1).rstrip("-.")
        if len(name) >= 3 and name not in _SKIP:
            deps.add(name)

    # pkg-config calls
    for pattern in (_PKG_CONFIG, _SHELL_PKG_CONFIG):
        for m in pattern.finditer(content):
            name = m.group(1)
            if name and not name.startswith("-"):
                deps.add(name)

    # EXTLIBS
    for m in _EXTLIBS.finditer(content):
        name = m.group(1)
        if name not in _SKIP:
            deps.add(name)

    return sorted(deps)
