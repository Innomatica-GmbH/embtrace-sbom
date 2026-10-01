"""Deterministic Autotools parser (configure.ac / configure.in).

Extracts dependency names from GNU Autotools build files:
- AC_CHECK_LIB([name], [func])
- AC_CHECK_HEADER([header.h])
- PKG_CHECK_MODULES([VAR], [name >= version])
- AC_SEARCH_LIBS([func], [lib1 lib2 ...])
- AX_CHECK_OPENSSL / AX_CHECK_ZLIB etc.
"""

from __future__ import annotations

import re

# AC_CHECK_LIB([crypto], [SHA1_Init], ...)
# AC_CHECK_LIB(curl, curl_global_init, ...)
_AC_CHECK_LIB = re.compile(
    r"AC_CHECK_LIB\s*\(\s*\[?(\w+)\]?",
    re.IGNORECASE,
)

# PKG_CHECK_MODULES([DLT], ['automotive-dlt >= 2.11'])
# PKG_CHECK_MODULES(DLT, automotive-dlt >= 2.11)
_PKG_CHECK_MODULES = re.compile(
    r"PKG_CHECK_MODULES\s*\(\s*\[?\w+\]?\s*,\s*\[?'?\"?([a-zA-Z0-9_][a-zA-Z0-9_.+-]*)",
)

# AC_SEARCH_LIBS([clock_gettime], [rt posix4])
# Also handles unbracketed: AC_SEARCH_LIBS(fmod, m)
_AC_SEARCH_LIBS = re.compile(
    r"AC_SEARCH_LIBS\s*\(\s*\[?\w+\]?\s*,\s*\[?([^\],\)]+)",
)

# AC_CHECK_HEADER([header.h]) — not always a dependency, but useful
_AC_CHECK_HEADER = re.compile(
    r"AC_CHECK_HEADER\s*\(\s*\[?([a-zA-Z0-9_/.+-]+\.h)\]?",
)

# AX_CHECK_OPENSSL, AX_CHECK_ZLIB, etc.
_AX_CHECK = re.compile(
    r"AX_CHECK_(\w+)",
)

# Header → library name mapping (common cases)
_HEADER_TO_LIB: dict[str, str] = {
    "openssl/ssl.h": "openssl",
    "openssl/crypto.h": "openssl",
    "curl/curl.h": "libcurl",
    "zlib.h": "zlib",
    "expat.h": "libexpat",
    "pcre2.h": "libpcre2",
    "pcre.h": "libpcre",
    "iconv.h": "libiconv",
    "libintl.h": "libintl",
    "pthread.h": "pthread",
}


def _strip_comments(content: str) -> str:
    """Remove autotools comments (dnl ... and # ...)."""
    content = re.sub(r"dnl\s+[^\n]*", "", content)
    content = re.sub(r"#[^\n]*", "", content)
    return content


def parse(content: str) -> list[str]:
    """Extract dependency names from configure.ac content."""
    content = _strip_comments(content)
    deps: set[str] = set()

    # AC_CHECK_LIB
    for m in _AC_CHECK_LIB.finditer(content):
        name = m.group(1)
        # Prefix with lib if it's a short name (convention)
        if len(name) > 1:
            deps.add(name)

    # PKG_CHECK_MODULES
    for m in _PKG_CHECK_MODULES.finditer(content):
        deps.add(m.group(1))

    # AC_SEARCH_LIBS — extract each library name
    for m in _AC_SEARCH_LIBS.finditer(content):
        libs = m.group(1).split()
        for lib in libs:
            lib = lib.strip()
            if lib:
                deps.add(lib)

    # AX_CHECK_*
    for m in _AX_CHECK.finditer(content):
        name = m.group(1).lower()
        deps.add(name)

    # AC_CHECK_HEADER — map known headers to library names
    for m in _AC_CHECK_HEADER.finditer(content):
        header = m.group(1)
        if header in _HEADER_TO_LIB:
            deps.add(_HEADER_TO_LIB[header])

    return sorted(deps)
