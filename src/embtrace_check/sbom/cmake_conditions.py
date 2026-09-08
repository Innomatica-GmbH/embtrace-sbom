"""Branch-, option- and cache-aware CMake ``find_package`` analysis (Befund 38).

A ``find_package()`` is not automatically a component of the product. In a
C/C++ project with selectable backends the call sits inside an ``if`` branch
guarded by an ``option()``::

    option(PAHO_WITH_SSL      "..." FALSE)
    option(PAHO_WITH_LIBRESSL "..." FALSE)
    ...
    if(PAHO_WITH_SSL OR PAHO_WITH_LIBRESSL)
      if(PAHO_WITH_LIBRESSL)
        find_package(LibreSSL REQUIRED)   # only with -DPAHO_WITH_LIBRESSL=ON
      else()
        find_package(OpenSSL REQUIRED)    # only with -DPAHO_WITH_SSL=ON
      endif()
    endif()

The two are **alternatives** — no build contains both — and with both options
FALSE the default build contains *neither*. A flat regex over the file reports
both as present; that invents content.

This module reads the whole project (options live in the ROOT ``CMakeLists.txt``,
the ``find_package`` in ``src/CMakeLists.txt``) plus a ``CMakeCache.txt`` when
one exists, and classifies each ``find_package`` into three states:

- ``present``      — unconditional, or the guarding condition is true given the
  option defaults / cache. This is a real component (``confirmed``).
- ``conditional``  — behind an ``option()`` that is off by default and no cache
  decides it. An alternative, surfaced with its condition — never ``confirmed``.
- ``absent``       — a ``CMakeCache.txt`` decides the build and this branch is
  not taken. Dropped, not guessed.

Nothing is read from ``Find*.cmake`` module files — those *search* for a
dependency, they are not a declaration (same class as Befund 34).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from embtrace_check.core.log import get_logger

logger = get_logger(__name__)

# --- CMake truthiness ---------------------------------------------------------

#: Constants CMake treats as false in an ``if()`` (case-insensitive), plus the
#: empty string and the ``*-NOTFOUND`` suffix handled separately.
_FALSE_CONSTANTS: frozenset[str] = frozenset({
    "off", "no", "false", "n", "ignore", "notfound", "0", "",
})
#: Constants CMake treats as true.
_TRUE_CONSTANTS: frozenset[str] = frozenset({
    "on", "yes", "true", "y", "1",
})

#: ``if()`` operators this evaluator does not model — their presence makes the
#: whole expression undecidable (returns ``None``), never a false verdict.
_UNSUPPORTED_OPS: frozenset[str] = frozenset({
    "strequal", "equal", "less", "greater", "less_equal", "greater_equal",
    "version_less", "version_greater", "version_equal",
    "version_less_equal", "version_greater_equal",
    "matches", "defined", "exists", "command", "policy", "in_list",
    "path_equal", "is_directory", "is_absolute", "is_symlink", "is_newer_than",
})


def _const_truthiness(token: str) -> bool | None:
    """Truthiness of a bare CMake constant, or ``None`` if it is not one."""
    low = token.lower()
    if low in _TRUE_CONSTANTS:
        return True
    if low in _FALSE_CONSTANTS:
        return False
    if low.endswith("-notfound"):
        return False
    # A non-zero number is true; zero is false.
    if re.fullmatch(r"-?\d+", token):
        return token not in ("0", "-0")
    return None


@dataclass
class CMakeContext:
    """Project-wide option defaults and (optional) cache values."""

    #: option name → resolved default truthiness (only clearly-boolean defaults).
    options: dict[str, bool] = field(default_factory=dict)
    #: CMakeCache.txt variable → raw value (decides the build when present).
    cache: dict[str, str] = field(default_factory=dict)
    #: True when at least one CMakeCache.txt was found — the build is decided.
    has_cache: bool = False

    def known(self, name: str) -> bool:
        """Is *name* a variable this context can resolve (cache or option)?"""
        return name in self.cache or name in self.options

    def value(self, name: str) -> bool | None:
        """Truthiness of a variable: cache wins over option default; else None."""
        if name in self.cache:
            return _const_truthiness(self.cache[name])
        if name in self.options:
            return self.options[name]
        return None


@dataclass
class FindPackageHit:
    """One ``find_package`` occurrence with its resolved branch state."""

    name: str
    version: str
    state: str      # "present" | "conditional" | "absent"
    condition: str  # human-readable guard, "" when unconditional / present


#: A dotted version anywhere in a string (``3.0.13``, ``v1.2``, ``3.0.13()``).
_VERSION_IN = re.compile(r"v?(\d+(?:\.\d+)+[A-Za-z0-9.\-]*?)(?:\(|\s|$|\])")
#: A version embedded in a shared-object name (``libcrypto.so.3.0.2``).
_SO_VERSION = re.compile(r"\.so\.(\d+(?:\.\d+)*)")


def version_from_cache(name: str, ctx: CMakeContext) -> str:
    """Best resolved version for a configured ``find_package(NAME)`` package.

    The configured build already found the library; its version is a fact of
    the build machine recorded in the cache (Befund 41). Sources, in order of
    trust: an explicit ``<NAME>_VERSION`` variable, the pkg-config
    ``_<NAME>_VERSION``, CMake's own ``FIND_PACKAGE_MESSAGE_DETAILS_<Name>``
    record, and last the resolved library path (``libcrypto.so.3.0.2``).
    Empty when even the build does not know — an honest unknown, not a guess.
    """
    base = name.upper()
    for key in (f"{base}_VERSION", f"{base}_VERSION_STRING", f"_{base}_VERSION"):
        raw = ctx.cache.get(key, "").strip()
        if raw:
            m = _VERSION_IN.match(raw) or _VERSION_IN.search(raw)
            if m:
                return m.group(1)
    detail = ctx.cache.get(f"FIND_PACKAGE_MESSAGE_DETAILS_{name}", "")
    if detail:
        # Format: ``[lib][include][flags][v3.0.13()]`` — take the v-token.
        m = re.search(r"\[v?(\d+(?:\.\d+)+)", detail)
        if m:
            return m.group(1)
    # Resolved library FILEPATH → version in the .so name, if any.
    for key, val in ctx.cache.items():
        ku = key.upper()
        if ku.startswith(base) and ("LIBRARY" in ku or "LIBRARIES" in ku):
            m = _SO_VERSION.search(val)
            if m:
                return m.group(1)
    return ""


# --- Command tokenizer (balanced parentheses) ---------------------------------

_COMMAND = re.compile(
    r"\b(if|elseif|else|endif|find_package|find_host_package)\s*\(",
    re.IGNORECASE,
)


def _strip_comments(content: str) -> str:
    """Remove ``#`` line comments (bracket comments are rare — left intact)."""
    return re.sub(r"#[^\n]*", "", content)


def _extract_args(content: str, open_paren: int) -> tuple[str, int]:
    """Return (argument text, index past the matching ``)``)."""
    depth = 0
    i = open_paren
    n = len(content)
    while i < n:
        c = content[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return content[open_paren + 1:i], i + 1
        i += 1
    return content[open_paren + 1:], n


def _iter_commands(content: str) -> list[tuple[str, str]]:
    """Yield ``(command_lower, args_text)`` in source order."""
    out: list[tuple[str, str]] = []
    pos = 0
    for m in _COMMAND.finditer(content):
        if m.start() < pos:
            continue  # inside a previous command's arguments
        args, end = _extract_args(content, m.end() - 1)
        out.append((m.group(1).lower(), args))
        pos = end
    return out


# --- Boolean expression evaluator (three-valued / Kleene) ---------------------

_EXPR_TOKEN = re.compile(r"\(|\)|[^\s()]+")


def _tokenize_expr(expr: str) -> list[str]:
    return _EXPR_TOKEN.findall(expr)


def _clean_var(token: str) -> str:
    """Strip a ``${...}`` wrapper and surrounding quotes from a variable token."""
    t = token.strip().strip('"')
    m = re.fullmatch(r"\$\{(.+)\}", t)
    return m.group(1) if m else t


class _UndecidableError(Exception):
    """Raised when an expression uses an operator we do not model."""


def _eval_tokens(tokens: list[str], ctx: CMakeContext) -> bool | None:
    """Kleene-evaluate a CMake boolean token list. ``None`` = undecidable."""
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def kleene_or(a: bool | None, b: bool | None) -> bool | None:
        if a is True or b is True:
            return True
        if a is False and b is False:
            return False
        return None

    def kleene_and(a: bool | None, b: bool | None) -> bool | None:
        if a is False or b is False:
            return False
        if a is True and b is True:
            return True
        return None

    def parse_or() -> bool | None:
        nonlocal pos
        val = parse_and()
        while (tok := peek()) is not None and tok.lower() == "or":
            pos += 1
            val = kleene_or(val, parse_and())
        return val

    def parse_and() -> bool | None:
        nonlocal pos
        val = parse_not()
        while (tok := peek()) is not None and tok.lower() == "and":
            pos += 1
            val = kleene_and(val, parse_not())
        return val

    def parse_not() -> bool | None:
        nonlocal pos
        tok = peek()
        if tok is not None and tok.lower() == "not":
            pos += 1
            inner = parse_not()
            return None if inner is None else (not inner)
        return parse_primary()

    def parse_primary() -> bool | None:
        nonlocal pos
        tok = peek()
        if tok is None:
            return None
        if tok == "(":
            pos += 1
            val = parse_or()
            if peek() == ")":
                pos += 1
            return val
        if tok == ")":
            return None
        if tok.lower() in _UNSUPPORTED_OPS:
            raise _UndecidableError
        pos += 1
        # A binary operator immediately after an operand → undecidable.
        nxt = peek()
        if nxt is not None and nxt.lower() in _UNSUPPORTED_OPS:
            raise _UndecidableError
        const = _const_truthiness(tok)
        if const is not None:
            return const
        return ctx.value(_clean_var(tok))

    try:
        return parse_or()
    except _UndecidableError:
        return None


@dataclass
class _Atom:
    """One guard term on a branch path: an expression, possibly negated."""

    negate: bool
    expr: str

    def evaluate(self, ctx: CMakeContext) -> bool | None:
        val = _eval_tokens(_tokenize_expr(self.expr), ctx)
        if val is None:
            return None
        return (not val) if self.negate else val

    def mentions_known(self, ctx: CMakeContext) -> bool:
        return any(
            ctx.known(_clean_var(t))
            for t in _tokenize_expr(self.expr)
            if t not in ("(", ")") and t.lower() not in ("and", "or", "not")
        )

    def render(self) -> str:
        expr = self.expr.strip()
        body = f"({expr})" if re.search(r"\s", expr) else expr
        return f"NOT {body}" if self.negate else body


@dataclass
class _Frame:
    """An open ``if``/``elseif``/``else`` block during the walk."""

    #: Expressions of the ``if`` + every ``elseif`` seen so far.
    seen: list[str]
    #: Atoms describing the branch currently in effect.
    current: list[_Atom]


def _branch_atoms(stack: list[_Frame]) -> list[_Atom]:
    atoms: list[_Atom] = []
    for frame in stack:
        atoms.extend(frame.current)
    return atoms


def _classify(atoms: list[_Atom], ctx: CMakeContext) -> tuple[str, str]:
    """Return (state, condition_text) for a find_package under *atoms*."""
    if not atoms:
        return "present", ""

    # Kleene conjunction over the branch path.
    taken: bool | None = True
    for atom in atoms:
        v = atom.evaluate(ctx)
        if v is False:
            taken = False
            break
        if v is None:
            taken = None

    condition = "nur bei: " + " und ".join(a.render() for a in atoms)

    if ctx.has_cache:
        # The build is decided by the cache.
        if taken is False:
            return "absent", condition
        # True or undecidable → keep (never drop what we cannot disprove).
        return "present", ""

    # No cache: an option toggle that is off by default is an alternative.
    involves_option = any(a.mentions_known(ctx) for a in atoms)
    if taken is False and involves_option:
        return "conditional", condition
    return "present", ""


# --- find_package name filtering ---------------------------------------------

#: CMake built-in modules never treated as product dependencies (mirrors the
#: skip list of the standalone scanner).
_SKIP_FIND: frozenset[str] = frozenset({
    "Threads", "PkgConfig", "Python", "Python2", "Python3",
    "GTest", "Doxygen",
})

_FIND_ARG_NAME = re.compile(r"^\s*(\w+)(?:\s+(\d[\w._-]*))?")


def find_packages(content: str, ctx: CMakeContext) -> list[FindPackageHit]:
    """Classify every ``find_package`` in *content* against *ctx*."""
    content = _strip_comments(content)
    stack: list[_Frame] = []
    hits: list[FindPackageHit] = []

    for cmd, args in _iter_commands(content):
        if cmd == "if":
            expr = args.strip()
            stack.append(_Frame(seen=[expr], current=[_Atom(False, expr)]))
        elif cmd == "elseif":
            if not stack:
                continue
            frame = stack[-1]
            expr = args.strip()
            atoms = [_Atom(True, e) for e in frame.seen]
            atoms.append(_Atom(False, expr))
            frame.current = atoms
            frame.seen.append(expr)
        elif cmd == "else":
            if not stack:
                continue
            frame = stack[-1]
            frame.current = [_Atom(True, e) for e in frame.seen]
        elif cmd == "endif":
            if stack:
                stack.pop()
        else:  # find_package / find_host_package
            m = _FIND_ARG_NAME.match(args)
            if not m:
                continue
            name = m.group(1)
            if name in _SKIP_FIND:
                continue
            version = m.group(2) or ""
            state, condition = _classify(_branch_atoms(stack), ctx)
            hits.append(FindPackageHit(
                name=name, version=version, state=state, condition=condition,
            ))

    return hits


# --- Project-wide context building --------------------------------------------

_OPTION = re.compile(
    r"\b(?:option|cmake_dependent_option)\s*\(", re.IGNORECASE,
)
#: A CMakeCache.txt entry: ``NAME:TYPE=VALUE``.
_CACHE_LINE = re.compile(r"^\s*([A-Za-z_]\w*):[A-Za-z]+=(.*)$")


def _parse_options(content: str, into: dict[str, bool]) -> None:
    """Collect ``option(NAME "desc" DEFAULT)`` defaults from *content*."""
    content = _strip_comments(content)
    for m in _OPTION.finditer(content):
        args, _ = _extract_args(content, m.end() - 1)
        # Tokens: NAME "desc" [DEFAULT] (cmake_dependent_option adds more,
        # but its 3rd token is still the default).
        toks = re.findall(r'"[^"]*"|\S+', args)
        if not toks:
            continue
        name = toks[0].strip('"')
        if not re.fullmatch(r"\w+", name):
            continue
        default = False
        if len(toks) >= 3:  # noqa: PLR2004 — NAME, "desc", DEFAULT
            resolved = _const_truthiness(toks[2].strip('"'))
            default = bool(resolved)  # unknown/var default → treated as OFF
        into.setdefault(name, default)


def _load_cache(path: Path, into: dict[str, str]) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for line in text.splitlines():
        m = _CACHE_LINE.match(line)
        if m:
            into[m.group(1)] = m.group(2).strip()


#: Directories not walked when collecting options (mirror the scanner).
_SKIP_DIRS: frozenset[str] = frozenset({
    "node_modules", "__pycache__", "target", "vendor", "dist", "venv",
})


def _is_find_module(path: Path) -> bool:
    """A ``Find<Name>.cmake`` file is a search module, not a declaration."""
    return bool(re.fullmatch(r"Find.+\.cmake", path.name))


def build_cmake_context(root: Path, *, max_depth: int = 5) -> CMakeContext:
    """Collect option defaults and cache values across the whole project.

    ``option()`` declarations live in the top-level ``CMakeLists.txt`` while a
    ``find_package`` lives deep in a sub-directory — a per-file parser never
    sees the toggle. Build outputs and vendored trees are skipped; ``CMakeCache.txt``
    (in the source tree or a nested build directory) is loaded when present.
    """
    ctx = CMakeContext()
    if not root.is_dir():
        return ctx

    def _walk(current: Path, depth: int) -> None:
        # A directory holding CMakeCache.txt IS a build tree: read the cache,
        # but never parse its generated CMakeLists/.cmake for options and do
        # not descend — those files would inject phantom find_package hits.
        cache_file = current / "CMakeCache.txt"
        if cache_file.is_file():
            _load_cache(cache_file, ctx.cache)
            ctx.has_cache = True
            return
        try:
            entries = sorted(current.iterdir())
        except OSError:
            return
        for entry in entries:
            name = entry.name
            if entry.is_dir():
                if depth >= max_depth or name.startswith(".") or name in _SKIP_DIRS:
                    continue
                _walk(entry, depth + 1)
            elif (
                (name == "CMakeLists.txt" or name.endswith(".cmake"))
                and not _is_find_module(entry)
            ):
                try:
                    text = entry.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                _parse_options(text, ctx.options)

    _walk(root, 0)
    if ctx.options or ctx.cache:
        logger.info(
            "CMake context: %d option(s), %d cache value(s)%s",
            len(ctx.options), len(ctx.cache),
            " [build decided by cache]" if ctx.has_cache else "",
        )
    return ctx
