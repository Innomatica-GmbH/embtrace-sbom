"""Classify scanned components: real / build-tool / suspect (Befund 34).

A ``find_package()`` hit is not automatically a product component:

- **Build tools** (``Git``, ``Perl``, ``Doxygen`` …) belong in the SBOM
  but marked ``scope: excluded`` — like dev dependencies (Befund 29):
  never gating, never in the coverage quota. No product ships them.
- **Suspects** (``int``, ``TC``, ``DAG``, ``Packet``) are parser false
  hits — a versionless, DB-unknown, non-library-shaped name. They are
  NOT components: an assessor who finds ``int`` in the bill stops
  trusting the rest. They go into a separate "nicht sicher erkannt"
  list, never the components.

The rule mirrors the order: a versionless name that is neither a known
library (knowledge DB or a library-shaped name) nor a build tool is a
suspect. ``libucontext`` survives (``lib`` prefix); ``OpenSSL`` survives
(DB-known); ``DAG``/``int``/``Packet`` do not.

Befund 35: names are stripped of control characters first (a scanner
once read colored tool output — ``\\x1b[38;2;…mgolang.org/x/mod\\x1b[0m``);
a name that is empty after stripping is not a component either.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from embtrace_check.sbom.scanner import Dependency

#: Build-system tools reached via find_package / find_program — never in
#: the shipped product. Lowercase for case-insensitive matching. A
#: curated list in the repo, not a guess.
BUILD_TOOLS: frozenset[str] = frozenset({
    "git", "perl", "python", "python2", "python3", "pythoninterp",
    "doxygen", "pkgconfig", "pkg-config", "pkgconf", "ruby", "sphinx",
    "bison", "flex", "gperf", "ragel", "gettext", "intltool", "asciidoc",
    "asciidoctor", "help2man", "makeinfo", "texinfo", "swig", "cython",
    "yasm", "nasm", "m4", "autoconf", "automake", "libtool", "cmake",
    "ninja", "make", "meson", "ccache", "clang-tidy", "clang-format",
    "cppcheck", "lcov", "gcovr", "valgrind", "protoc", "go-md2man",
    "pandoc", "sed", "awk", "gawk", "grep", "sphinx-build", "pod2man",
    "xxd", "objcopy", "rsync", "unzip", "patch", "gzip",
})

#: C/C++ reserved words and primitive types — never a library name.
_C_KEYWORDS: frozenset[str] = frozenset({
    "int", "char", "void", "bool", "long", "short", "float", "double",
    "unsigned", "signed", "const", "static", "struct", "enum", "union",
    "size_t", "ssize_t", "intptr_t", "uintptr_t", "ptrdiff_t", "wchar_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "true", "false", "null", "nullptr", "nil",
})

#: Ecosystems where a versionless find_package/find_library name can be a
#: suspect — the no-package-manager world. npm/pypi/cargo carry resolved
#: versions and never route through here.
_NAME_ONLY_ECOSYSTEMS: frozenset[str] = frozenset({
    "cmake", "generic", "make", "meson", "autotools", "configure", "manual",
})

#: Control / ANSI-escape characters (Befund 35).
_CONTROL_CHARS = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|[\x00-\x1f\x7f]")


def strip_control_chars(name: str) -> str:
    """Remove ANSI escapes and control characters from a component name."""
    return _CONTROL_CHARS.sub("", name).strip()


def is_build_tool(name: str) -> bool:
    """True when *name* is a known build-system tool (case-insensitive)."""
    return name.strip().lower() in BUILD_TOOLS


#: Percent-encoded control characters (``%1b`` etc.) — a purl built from
#: a garbled name carries them url-encoded, not raw (Befund 37).
_PCT_CONTROL = re.compile(r"%(?:[01][0-9a-fA-F]|7[fF])")


def _is_valid_purl(purl: str) -> bool:
    """A purl must start with ``pkg:`` and carry no control characters —
    neither raw nor percent-encoded (``%1b`` from a garbled name)."""
    return (
        purl.startswith("pkg:")
        and not _CONTROL_CHARS.search(purl)
        and not _PCT_CONTROL.search(purl)
    )


#: String fields on a Dependency that may carry text from foreign files
#: and therefore must be stripped of control characters (Befund 37).
_STRING_FIELDS = ("version", "cpe", "supplier", "license", "description")


def clean_dependency(dep: Dependency) -> None:
    """Strip control characters from EVERY string field of *dep* in place.

    The Befund-35 fix cleaned only ``name``; a control character then
    survived in ``version``/``purl`` and broke the triage YAML three
    steps later (Befund 37). The filter belongs on the object, not one
    field. A purl that is invalid after cleaning is dropped (a clean one
    is rebuilt by enrichment/generation), never repaired.
    """
    dep.name = strip_control_chars(dep.name)
    for field in _STRING_FIELDS:
        value = getattr(dep, field, None)
        if isinstance(value, str) and value:
            cleaned = strip_control_chars(value)
            if cleaned != value:
                setattr(dep, field, cleaned or None if field != "version" else cleaned)
    if dep.purl:
        cleaned_purl = strip_control_chars(dep.purl)
        dep.purl = cleaned_purl if _is_valid_purl(cleaned_purl) else None


def _looks_like_library(name: str) -> bool:
    """A name that is library-shaped is trusted even without a version.

    ``libucontext`` (lib prefix), ``foo-bar``, ``foo.baz``,
    ``@scope/pkg`` — real package spellings that a parser does not
    invent by accident.
    """
    lower = name.lower()
    return lower.startswith("lib") or any(c in name for c in "-._/:+@")


def is_suspect(
    name: str,
    version: str,
    ecosystem: str,
    *,
    db_known: Callable[[str], bool] | None = None,
) -> bool:
    """A parser false hit that must not enter the bill of materials.

    Order rule: versionless AND not in a known-library list (knowledge
    DB) AND not library-shaped AND not a build tool → suspect. C
    keywords are always suspect; the DB is the authoritative allow-list
    for capitalized single words (``OpenSSL`` stays, ``Packet`` does not).
    """
    name = strip_control_chars(name)
    if not name:
        return True  # empty after cleanup — not a component
    if version and version != "*":
        return False  # a resolved version is trust
    if ecosystem not in _NAME_ONLY_ECOSYSTEMS:
        return False
    if is_build_tool(name):
        return False
    lower = name.lower()
    # C keywords/types first — some carry '_' (size_t) and would
    # otherwise pass the library-shape gate below.
    if lower in _C_KEYWORDS:
        return True
    if _looks_like_library(name):
        return False
    if db_known is not None and db_known(name):
        return False  # OpenSSL / Boost / SDL — a real library the DB knows
    if name.isupper() and len(name) <= 5:
        return True  # DAG, SNF, TC — short acronym, DB-unknown
    if name.isalpha() and name[:1].isupper() and len(name) <= 12:
        return True  # Packet, Target — capitalized word, DB-unknown, not lib
    return len(name) <= 2


def _default_db_known(name: str) -> bool:
    """Knowledge-DB / C-bridge presence check (any curated hit)."""
    try:
        from embtrace_check.sbom.enrich import _lookup_cpp_fuzzy
        from embtrace_check.sbom.knowledge_db import lookup

        if lookup("github", name) or lookup("generic", name):
            return True
        hit = _lookup_cpp_fuzzy(name)
        return bool(hit.get("supplier") or hit.get("license") or hit.get("cpe"))
    except Exception:  # noqa: BLE001 — classification must never break a scan
        return False


def classify_components(
    deps: list[Dependency],
    *,
    db_known: Callable[[str], bool] | None = None,
) -> tuple[list[Dependency], list[str]]:
    """Split scanned deps into (components, suspect names).

    - control characters are stripped from every name (Befund 35); a
      name that becomes empty is a suspect;
    - build tools are KEPT with ``scope: excluded`` (never gating, never
      in the coverage quota);
    - suspects are removed from the components and returned separately
      for the "nicht sicher erkannt" section.

    Returns ``(kept, suspect_names_sorted)``.
    """
    known = db_known if db_known is not None else _default_db_known
    kept: list[Dependency] = []
    suspects: list[str] = []
    for dep in deps:
        # Control characters out of EVERY field (Befund 37), not just name.
        clean_dependency(dep)
        if is_build_tool(dep.name):
            if dep.scope not in ("required", "optional", "excluded"):
                dep.scope = "excluded"
            kept.append(dep)
            continue
        if is_suspect(dep.name, dep.version, dep.ecosystem, db_known=known):
            if dep.name:
                suspects.append(dep.name)
            continue
        kept.append(dep)
    return kept, sorted(set(suspects))
