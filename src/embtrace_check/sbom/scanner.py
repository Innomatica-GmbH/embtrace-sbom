"""Dependency scanner — detects dependencies from lockfiles and manifests.

Supports:
- conan.lock / conanfile.txt  (C/C++ via Conan)
- requirements.txt            (Python pip)
- pyproject.toml              (Python — PEP 621/735 + Poetry; skipped when a lockfile exists)
- poetry.lock                 (Python Poetry)
- uv.lock                     (Python uv — resolved workspace closure)
- Pipfile.lock                (Python Pipenv)
- vcpkg.json                  (C/C++ vcpkg)
- CMakeLists.txt              (CMake FetchContent/find_package, best-effort)
- Cargo.lock                  (Rust Cargo)
- package-lock.json           (npm)
- yarn.lock                   (Yarn Classic)
- pnpm-lock.yaml              (pnpm)
- gradle.lockfile             (Gradle)
- pom.xml                     (Maven)
- go.sum                      (Go Modules)
- alire.lock                  (Ada/SPARK Alire)
- embtrace-deps.yaml          (manual declaration for proprietary libs)
- *.hwh / *.xci / *.tcl       (FPGA IP cores — Vivado IP-XACT VLNV, Libero
                               core_vlnv, Quartus *_hw.tcl; matched by suffix)
"""

from __future__ import annotations

import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote

import yaml
from pydantic import BaseModel

from embtrace_check.core.log import get_logger
from embtrace_check.sbom.cmake_conditions import (
    CMakeContext,
    build_cmake_context,
    find_packages,
    version_from_cache,
)

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Dependency model
# ---------------------------------------------------------------------------

_RANGE_CHARS = re.compile(r"[\^~<>=*|,]|\s")


def is_version_range(version: str) -> bool:
    """True when *version* is a declaration range, not a concrete version.

    ``^4.18.0``, ``~6.5.2``, ``>=2.0``, ``1.2 || 2.0``, ``4.x``, ``*`` —
    CycloneDX demands a concrete version; a range in that field is a
    false statement an assessor cannot check (Befund 30).
    """
    v = version.strip()
    if not v:
        return False
    return bool(_RANGE_CHARS.search(v)) or v.endswith(".x") or v.lower() in ("x", "latest")


class Dependency(BaseModel):
    """A single software dependency detected by scanning.

    Base fields cover CycloneDX / SPDX identity. The trailing block of fields
    carry BSI TR-03183-2 v2.1.0 specific metadata and stay ``None`` when no
    scanner / enricher has populated them yet — this keeps every existing
    scanner backward compatible.
    """

    name: str
    version: str
    ecosystem: str  # conan, pypi, cmake, vcpkg, manual
    #: True for a NESTED npm copy (node_modules/a/node_modules/b): it
    #: is installed and belongs in the SBOM, but it must never be
    #: compared against the project's own declaration — that invented
    #: the "globals 14.0.0 erfüllt ^15.12.0 nicht"-conflict (Befund 28).
    nested: bool = False
    #: The DECLARED range when no resolved version exists ("^4.18.0",
    #: "~6.5.2", ">=2.0"). A range is a wish, not a version — it never
    #: goes into the CycloneDX version field (Befund 30); the generator
    #: emits it as the property ``embtrace:declared-range`` instead.
    declared_range: str = ""
    license: str | None = None
    supplier: str | None = None
    purl: str | None = None
    cpe: str | None = None
    description: str | None = None
    # Provenance class of the version: "" = resolved/pinned (lockfile or
    # exact pin), "manifest" = a constraint-derived minimum from a manifest
    # (pyproject `>=`, requirements `>=`, CMake find_package). Manifest
    # versions lose against a resolved version of the same package
    # (see prefer_locked) — they are floors, not facts.
    source_kind: str = ""
    # CycloneDX component.scope ("required" | "optional" | "excluded"),
    # "" = unknown. npm lockfile v2/v3 marks pure build tooling with
    # dev/devOptional → "excluded" (never ships in the artefact); this is
    # SBOM honesty, NOT a query filter — dev components are still checked
    # for vulnerabilities (order osv-chunking A4).
    scope: str = ""
    # True only for entries the customer wrote into embtrace-deps.yaml.
    # A declaration is authoritative (its supplier/license/purl/cpe were
    # stated on purpose, they beat anything a database could guess) and,
    # for the check collector, it is the ONLY class of component whose
    # metadata may travel in the payload (order report-vollstaendigkeit).
    declared: bool = False
    #: Version of the DISTRIBUTION package the build links against
    #: (``3.0.13-0ubuntu3.15``) — the patch level that decides which CVEs
    #: are actually fixed (Reihe 19, Increment 2). Upstream stays in
    #: ``version``; both are shown, neither replaces the other.
    distro_version: str = ""
    #: Where the system resolver got its answer ("pkg-config (Host)" /
    #: "pkg-config (Sysroot)"), "" when nothing was resolved.
    resolved_from: str = ""
    #: Distribution SOURCE package (dpkg ${source:Package}: "openssl", not
    #: "libssl-dev") — OSV Ubuntu/Debian advisories key by it (Rest 1).
    distro_source: str = ""
    #: OSV ecosystem of the resolving system ("Ubuntu:24.04") — the distro
    #: view whose advisories decide the shipped patch level.
    distro_ecosystem: str = ""
    #: A CMake find_package guarded by an off-by-default option() is an
    #: ALTERNATIVE, not a present component (Befund 38). When set, this
    #: carries the plain-text guard ("nur bei: PAHO_WITH_LIBRESSL") and the
    #: entry must never be reported as confirmed — the customer decides
    #: which backend they build. Empty for unconditional dependencies.
    condition: str = ""

    # ------------------------------------------------------------------
    # BSI TR-03183-2 v2.1.0 metadata (all optional, populated on demand)
    # ------------------------------------------------------------------
    # Hash of the deployable component. BSI mandates SHA-512 explicitly;
    # we accept the raw hex digest here.
    hash_sha512: str | None = None
    # Hash of the source form, when distinct from the deployable (optional per TR).
    hash_source_sha512: str | None = None
    # Filename of the component artefact on disk (required per TR §5).
    filename: str | None = None
    # Component creator, either an RFC 5322 email or a URL (required per TR §5).
    creator: str | None = None
    # Classification properties (required per TR §5; default to ``None`` = unknown).
    is_executable: bool | None = None
    is_archive: bool | None = None
    is_structured: bool | None = None
    # Source code URI (optional per TR §5).
    source_uri: str | None = None
    # URI of deployable form (optional per TR §5).
    deployable_uri: str | None = None
    # URL of security.txt (RFC 9116) (optional per TR §5).
    security_txt_url: str | None = None
    # Effective licence distinct from declared licences (optional per TR §5).
    effective_license: str | None = None
    # List of component names this component DEPENDS_ON (for BSI-relationship).
    dependencies: list[str] | None = None


def _make_purl(ecosystem: str, name: str, version: str) -> str:
    """Build a Package URL string."""
    type_map = {
        "conan": "conan",
        "pypi": "pypi",
        "vcpkg": "vcpkg",
        "cmake": "generic",
        "meson": "generic",
        "autotools": "generic",
        "configure": "generic",
        "make": "generic",
        "manual": "generic",
        "cargo": "cargo",
        "npm": "npm",
        "golang": "golang",
        "maven": "maven",
        "gradle": "maven",
        "alire": "alire",
    }
    purl_type = type_map.get(ecosystem, "generic")

    if ecosystem == "pypi":
        # PURL names are lowercase for pypi
        purl_name = name.lower().replace("_", "-")
    elif ecosystem == "npm":
        # Scoped packages: @scope/name → %40scope/name
        purl_name = quote(name, safe="/")
    elif ecosystem == "golang":
        # Go module paths: URL-encode slashes
        purl_name = quote(name, safe="")
    elif ecosystem in ("maven", "gradle"):
        # Maven: group/artifact (name should already contain the slash)
        purl_name = name
    else:
        purl_name = name

    # No version, no "@": "pkg:npm/express@" is not a valid purl, and a
    # range there would be a false statement (Befund 30).
    if not version or version == "*" or is_version_range(version):
        return f"pkg:{purl_type}/{purl_name}"
    return f"pkg:{purl_type}/{purl_name}@{version}"


# ---------------------------------------------------------------------------
# Individual scanners
# ---------------------------------------------------------------------------

def scan_conan_lock(path: Path) -> list[Dependency]:
    """Parse a Conan 2.x conan.lock (JSON) file."""
    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    # Conan 2.x lock format: {"requires": ["zlib/1.3.1#hash", ...]}
    for ref in data.get("requires", []):
        # Format: name/version#revision or name/version
        clean = ref.split("#")[0]
        parts = clean.split("/", 1)
        if len(parts) == 2:
            name, version = parts
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="conan",
                purl=_make_purl("conan", name, version),
            ))

    # Also handle build_requires
    for ref in data.get("build_requires", []):
        clean = ref.split("#")[0]
        parts = clean.split("/", 1)
        if len(parts) == 2:
            name, version = parts
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="conan",
                purl=_make_purl("conan", name, version),
            ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_conanfile_txt(path: Path) -> list[Dependency]:
    """Parse a conanfile.txt [requires] section."""
    deps: list[Dependency] = []
    in_requires = False
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            in_requires = stripped.lower() in ("[requires]", "[build_requires]")
            continue
        if in_requires and "/" in stripped and not stripped.startswith("#"):
            parts = stripped.split("/", 1)
            if len(parts) == 2:
                name = parts[0]
                version = parts[1].split("@")[0].split("#")[0].strip()
                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem="conan",
                    purl=_make_purl("conan", name, version),
                ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_requirements_txt(path: Path) -> list[Dependency]:
    """Parse a pip requirements.txt file."""
    deps: list[Dependency] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        # Match: package==version or package>=version etc.
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=~!<>]=*)\s*([a-zA-Z0-9._*-]+)", stripped)
        if match:
            name, operator, version = match.group(1), match.group(2), match.group(3)
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="pypi",
                purl=_make_purl("pypi", name, version),
                # ">=1.2" names a floor, not the deployed version.
                source_kind="" if operator == "==" else "manifest",
            ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


# Matches a PEP 508 requirement with a version constraint:
# "click>=8.1", "uvicorn[standard]==0.23", "pydantic >= 2.0, <3" …
_PYPROJECT_REQ_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*[=~!<>]=*\s*([A-Za-z0-9._*-]+)"
)


def _poetry_spec_version(spec: object) -> str:
    """Extract a concrete version from a Poetry dependency specifier.

    Handles plain strings (``"^8.1"``, ``">=1.0,<2"``) and tables with a
    ``version`` key. Git / path / URL specifiers yield ``""``.
    """
    if isinstance(spec, dict):
        spec = spec.get("version", "")
    if not isinstance(spec, str):
        return ""
    match = re.match(r"[\^~=<>!\s]*([0-9][A-Za-z0-9._*-]*)", spec)
    return match.group(1) if match else ""


def scan_pyproject_toml(path: Path) -> list[Dependency]:
    """Parse a pyproject.toml (PEP 621, PEP 735 dependency-groups, Poetry).

    Skipped entirely when a ``poetry.lock`` or ``uv.lock`` sits next to it —
    those lockfiles carry the fully resolved closure for the same dependency
    set and win. Requirement entries without any version constraint are
    skipped (no concrete version to put into an SBOM).
    """
    deps: list[Dependency] = []
    for lockfile in ("poetry.lock", "uv.lock"):
        if path.with_name(lockfile).is_file():
            logger.info("Skipping %s — %s present", path, lockfile)
            return deps

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    def _add(name: str, version: str) -> None:
        if name and version and version != "*":
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="pypi",
                purl=_make_purl("pypi", name, version),
                # pyproject constraints are floors/ranges, not resolved
                # versions — only a lockfile knows what is deployed.
                source_kind="manifest",
            ))

    # PEP 621 [project.dependencies] / [project.optional-dependencies]
    # and PEP 735 [dependency-groups]
    project = data.get("project", {})
    req_lists: list[object] = [project.get("dependencies", [])]
    req_lists.extend(project.get("optional-dependencies", {}).values())
    req_lists.extend(data.get("dependency-groups", {}).values())
    for req_list in req_lists:
        if not isinstance(req_list, list):
            continue
        for req in req_list:
            if not isinstance(req, str):
                continue  # PEP 735 include-group tables
            match = _PYPROJECT_REQ_RE.match(req.strip())
            if match:
                _add(match.group(1), match.group(2))

    # Poetry: [tool.poetry.dependencies] / dev-dependencies / group.*.dependencies
    poetry = data.get("tool", {}).get("poetry", {})
    poetry_tables: list[object] = [
        poetry.get("dependencies", {}),
        poetry.get("dev-dependencies", {}),
    ]
    poetry_tables.extend(
        group.get("dependencies", {})
        for group in poetry.get("group", {}).values()
        if isinstance(group, dict)
    )
    for table in poetry_tables:
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if name == "python":
                continue
            _add(name, _poetry_spec_version(spec))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_poetry_lock(path: Path) -> list[Dependency]:
    """Parse a Poetry poetry.lock (TOML) file."""
    deps: list[Dependency] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if name and version:
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="pypi",
                purl=_make_purl("pypi", name, version),
                description=pkg.get("description"),
            ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_uv_lock(path: Path) -> list[Dependency]:
    """Parse a uv uv.lock (TOML) file.

    The lockfile carries the fully resolved transitive closure of a uv
    project or workspace. Workspace members themselves (``source`` is
    ``editable``/``virtual``/``directory``) are the scanned project's own
    code, not third-party dependencies, and are skipped.
    """
    deps: list[Dependency] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        source = pkg.get("source", {})
        if isinstance(source, dict) and (
            "editable" in source or "virtual" in source or "directory" in source
        ):
            continue
        if name and version:
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="pypi",
                purl=_make_purl("pypi", name, version),
            ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_pipfile_lock(path: Path) -> list[Dependency]:
    """Parse a Pipenv Pipfile.lock (JSON) file."""
    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            version = info.get("version", "").lstrip("=")
            if name and version:
                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    purl=_make_purl("pypi", name, version),
                ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_vcpkg_json(path: Path) -> list[Dependency]:
    """Parse a vcpkg.json manifest."""
    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    for entry in data.get("dependencies", []):
        if isinstance(entry, str):
            # No pinned version — "" is the honest value, never "*"
            # (order collector-embedded-buildsysteme Punkt 5).
            deps.append(Dependency(
                name=entry,
                version="",
                ecosystem="vcpkg",
                purl=f"pkg:vcpkg/{entry}",
            ))
        elif isinstance(entry, dict):
            name = entry.get("name", "")
            version = entry.get("version>=", entry.get("version", ""))
            if name:
                deps.append(Dependency(
                    name=name,
                    version=str(version),
                    ecosystem="vcpkg",
                    purl=_make_purl("vcpkg", name, str(version)),
                ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


_CMAKE_FETCH_CONTENT = re.compile(
    r"FetchContent_Declare\s*\(\s*(\w+).*?GIT_TAG\s+([v]?[\w._-]+)",
    re.DOTALL | re.IGNORECASE,
)


def scan_cmake(
    path: Path, *, cmake_ctx: CMakeContext | None = None,
) -> list[Dependency]:
    """Best-effort scan of CMakeLists.txt for FetchContent and find_package.

    ``find_package`` is classified branch-, option- and cache-aware (Befund 38):
    a call behind an off-by-default ``option()`` is an ALTERNATIVE — it carries
    its guard in :attr:`Dependency.condition` and is never reported as present.
    A ``CMakeCache.txt`` in the tree decides the build: branches not taken are
    dropped. *cmake_ctx* is the project-wide option/cache context; when omitted
    it is built from *path*'s directory (covers a standalone single-file scan).
    """
    deps: list[Dependency] = []
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    for match in _CMAKE_FETCH_CONTENT.finditer(content):
        name, version = match.group(1), match.group(2)
        deps.append(Dependency(
            name=name,
            version=version,
            ecosystem="cmake",
            purl=_make_purl("cmake", name, version),
        ))

    ctx = cmake_ctx if cmake_ctx is not None else build_cmake_context(path.parent)
    from embtrace_check.sbom.classify import is_build_tool

    for hit in find_packages(content, ctx):
        if hit.state == "absent":
            continue  # the cache decides this branch is not built
        version = hit.version
        # find_package(X 1.2) declares a MINIMUM, not the linked version.
        source_kind = "manifest"
        scope = ""
        condition = ""
        # Tooling is never a decision for the customer (Befund 57): a known
        # build tool (Git) or a project Find module that only locates a
        # PROGRAM (OpenSSLbins) travels marked excluded — listed, never asked.
        if hit.name in ctx.program_modules or is_build_tool(hit.name):
            scope = "excluded"
        if hit.state == "conditional":
            # An alternative behind an off-by-default option — surfaced with
            # its guard, never confirmed; optional in the generated SBOM.
            condition = hit.condition
            scope = "optional"
        elif ctx.has_cache:
            # The build is CONFIGURED — the branch was decided by the cache, so
            # this is a build-provenance component even when the cache carries
            # no version for it (Befund 41/45: lifecycle hangs on the cache
            # FILE, not on a variable hit — libwebsockets detects TLS in its own
            # lib/tls/CMakeLists.txt, so the cache has no OPENSSL_VERSION).
            source_kind = ""
            cache_ver = version_from_cache(hit.name, ctx)
            if cache_ver:
                version = cache_ver
        deps.append(Dependency(
            name=hit.name,
            version=version,
            ecosystem="cmake",
            purl=_make_purl("cmake", hit.name, version),
            source_kind=source_kind,
            condition=condition,
            scope=scope,
        ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_west_manifest(path: Path) -> list[Dependency]:
    """Parse a Zephyr ``west.yml`` manifest (the authoritative module list).

    The west manifest is the registry of the Zephyr world: every module
    with its repository and pinned revision (order
    wissensdatenbank-abdeckung-embedded, Stufe 4 — without this parser
    a Zephyr workspace scan missed its entire dependency declaration).
    The revision is taken verbatim as the version: tags are meaningful
    versions, commit hashes are at least an exact pin — never a guess.
    """
    deps: list[Dependency] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    manifest = data.get("manifest") if isinstance(data, dict) else None
    if not isinstance(manifest, dict):
        return deps

    remotes = {
        str(r.get("name", "")): str(r.get("url-base", ""))
        for r in manifest.get("remotes", []) or []
        if isinstance(r, dict)
    }
    default_remote = str(
        (manifest.get("defaults") or {}).get("remote", "")
    ) or (next(iter(remotes), ""))

    for project in manifest.get("projects", []) or []:
        if not isinstance(project, dict):
            continue
        name = str(project.get("name", ""))
        revision = str(project.get("revision", ""))
        if not name or not revision:
            continue
        repo_path = str(project.get("repo-path", "") or name)
        base = remotes.get(str(project.get("remote", "")) or default_remote, "")
        purl = None
        if base.startswith("https://github.com/"):
            org = base[len("https://github.com/"):].strip("/")
            purl = f"pkg:github/{org}/{repo_path}@{revision}"
        deps.append(Dependency(
            name=name,
            version=revision,
            ecosystem="github",
            purl=purl or _make_purl("generic", name, revision),
        ))

    logger.info("Found %d west modules in %s", len(deps), path)
    return deps


def scan_embtrace_deps(path: Path) -> list[Dependency]:
    """Parse a embtrace-deps.yaml manual dependency declaration."""
    deps: list[Dependency] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    if not isinstance(data, dict):
        return deps

    for entry in data.get("dependencies", []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "")
        version = entry.get("version", "")
        if name and version:
            # Optional per-entry ecosystem (e.g. written by embtrace_check.check.convert);
            # defaults to "manual" so existing declarations behave unchanged.
            ecosystem = str(entry.get("ecosystem") or "manual")
            # A declared purl/cpe wins over anything synthesized — the Zynq
            # demo declared 57 purls and 3 CPEs that this parser silently
            # dropped (order report-vollstaendigkeit P0).
            deps.append(Dependency(
                name=name,
                version=str(version),
                ecosystem=ecosystem,
                license=entry.get("license"),
                supplier=entry.get("supplier"),
                description=entry.get("description"),
                purl=str(entry.get("purl") or "") or _make_purl(ecosystem, name, str(version)),
                cpe=entry.get("cpe"),
                scope=str(entry.get("scope") or ""),
                declared=True,
            ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_cargo_lock(path: Path) -> list[Dependency]:
    """Parse a Rust Cargo.lock (TOML) file."""
    deps: list[Dependency] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        # Skip local workspace crates (no source field)
        if name and version and "source" in pkg:
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="cargo",
                purl=_make_purl("cargo", name, version),
            ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_package_lock_json(path: Path) -> list[Dependency]:
    """Parse an npm package-lock.json (v1/v2/v3) file."""
    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    # v2/v3 format: "packages" dict with node_modules paths
    packages = data.get("packages", {})
    if packages:
        for pkg_path, info in packages.items():
            if not pkg_path:  # Skip root entry ""
                continue
            # Skip workspace links (local packages, not external deps)
            if info.get("link"):
                continue
            version = info.get("version", "")
            if not version:
                continue
            # Extract name from path: "node_modules/@scope/name" → "@scope/name"
            parts = pkg_path.split("node_modules/")
            name = parts[-1] if parts else pkg_path
            # More than one "node_modules/" = a nested copy another
            # package pins for itself (Befund 28: position in the tree,
            # not the name, decides what a declaration compares against).
            nested = len(parts) > 2
            # npm lockfile v2/v3 provenance: dev/devOptional = build
            # tooling that never ships (CycloneDX "excluded"), optional =
            # may be absent at runtime ("optional"); else production tree.
            if info.get("dev") or info.get("devOptional"):
                scope = "excluded"
            elif info.get("optional"):
                scope = "optional"
            else:
                scope = "required"
            if name:
                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    purl=_make_purl("npm", name, version),
                    scope=scope,
                    nested=nested,
                ))
    else:
        # v1 fallback: "dependencies" dict
        for name, info in data.get("dependencies", {}).items():
            version = info.get("version", "")
            if name and version:
                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    purl=_make_purl("npm", name, version),
                ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


_YARN_ENTRY = re.compile(r'^"?(@?[^@\s"][^"]*?)@')
_YARN_VERSION = re.compile(r'^\s+version\s+"(.+)"')


def scan_yarn_lock(path: Path) -> list[Dependency]:
    """Parse a Yarn Classic (v1) yarn.lock file."""
    deps: list[Dependency] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    current_name: str | None = None
    seen: set[str] = set()

    for line in lines:
        if not line or line.startswith("#"):
            continue
        # Entry header: "name@version:" or "name@version, name@version:"
        entry_match = _YARN_ENTRY.match(line)
        if entry_match and not line.startswith(" "):
            current_name = entry_match.group(1)
            continue
        # Version line under current entry
        version_match = _YARN_VERSION.match(line)
        if version_match and current_name:
            version = version_match.group(1)
            key = f"{current_name}@{version}"
            if key not in seen:
                seen.add(key)
                deps.append(Dependency(
                    name=current_name,
                    version=version,
                    ecosystem="npm",
                    purl=_make_purl("npm", current_name, version),
                ))
            current_name = None

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_pnpm_lock_yaml(path: Path) -> list[Dependency]:
    """Parse a pnpm pnpm-lock.yaml file (v6 and v9 formats)."""
    deps: list[Dependency] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    if not isinstance(data, dict):
        return deps

    packages = data.get("packages", {})
    for key in packages:
        # v9 format: "name@version" (e.g. "lodash@4.17.21")
        # v6 format: "/name/version" (e.g. "/lodash/4.17.21")
        if key.startswith("/"):
            # v6: /name/version or /@scope/name/version
            parts = key.lstrip("/").rsplit("/", 1)
            if len(parts) == 2:
                name, version = parts
                # Clean version suffixes like "_peer-deps"
                version = version.split("_")[0]
            else:
                continue
        elif "@" in key and not key.startswith("@"):
            # v9: name@version
            name, _, version = key.rpartition("@")
        elif key.startswith("@") and key.count("@") >= 2:
            # v9 scoped: @scope/name@version
            name, _, version = key.rpartition("@")
        else:
            continue

        if not name or not version:
            continue
        # Skip workspace/local packages (file: protocol, link: protocol)
        if version.startswith(("file:", "link:")):
            continue
        deps.append(Dependency(
            name=name,
            version=version,
            ecosystem="npm",
            purl=_make_purl("npm", name, version),
        ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_gradle_lockfile(path: Path) -> list[Dependency]:
    """Parse a Gradle gradle.lockfile (text format)."""
    deps: list[Dependency] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Format: group:artifact:version=configuration(s)
        entry = stripped.split("=")[0].strip()
        parts = entry.split(":")
        if len(parts) == 3:
            group, artifact, version = parts
            name = f"{group}/{artifact}"
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="maven",
                purl=_make_purl("maven", name, version),
            ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


_MAVEN_NS = "{http://maven.apache.org/POM/4.0.0}"


def _get_pom_own_group_id(root: ET.Element, ns: str) -> str:
    """Extract the project's own groupId from a pom.xml root element.

    Falls back to the parent groupId if the project does not declare its own.
    Returns an empty string if neither is found.
    """
    # Direct <groupId> at the project level (not inside <dependencies>)
    group_el = root.find(f"{ns}groupId")
    if group_el is not None and group_el.text:
        return group_el.text.strip()
    # Inherit from <parent><groupId>
    parent_el = root.find(f"{ns}parent")
    if parent_el is not None:
        parent_group_el = parent_el.find(f"{ns}groupId")
        if parent_group_el is not None and parent_group_el.text:
            return parent_group_el.text.strip()
    return ""


def scan_pom_xml(path: Path) -> list[Dependency]:
    """Parse a Maven pom.xml file for <dependency> elements.

    Skips:
    - Dependencies with unresolved ``${...}`` property placeholders in
      groupId, artifactId, or version.
    - Self-references: dependencies whose groupId matches the project's
      own groupId (internal submodule references).
    """
    deps: list[Dependency] = []
    try:
        tree = ET.parse(path)  # noqa: S314
    except (ET.ParseError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    root = tree.getroot()
    # Detect namespace — some pom.xml files use the Maven namespace, some don't
    ns = _MAVEN_NS if root.tag.startswith("{") else ""

    own_group_id = _get_pom_own_group_id(root, ns)

    for dep_elem in root.iter(f"{ns}dependency"):
        group_el = dep_elem.find(f"{ns}groupId")
        artifact_el = dep_elem.find(f"{ns}artifactId")
        version_el = dep_elem.find(f"{ns}version")

        group_id = group_el.text if group_el is not None and group_el.text else ""
        artifact_id = artifact_el.text if artifact_el is not None and artifact_el.text else ""
        version = version_el.text if version_el is not None and version_el.text else ""

        if not group_id or not artifact_id:
            continue
        # Skip unresolved Maven property references (${...})
        if "${" in group_id or "${" in artifact_id or "${" in version:
            continue
        # Skip self-references (project's own submodules)
        if own_group_id and group_id == own_group_id:
            continue

        name = f"{group_id}/{artifact_id}"
        deps.append(Dependency(
            name=name,
            version=version if version else "",
            ecosystem="maven",
            purl=(_make_purl("maven", name, version) if version
                  else f"pkg:maven/{name}"),
        ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_go_sum(path: Path) -> list[Dependency]:
    """Parse a Go go.sum file."""
    deps: list[Dependency] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    seen: set[tuple[str, str]] = set()
    for line in lines:
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        module = parts[0]
        version = parts[1]
        # Remove /go.mod suffix from version
        version = version.split("/go.mod")[0]
        # Remove v prefix
        version = version.lstrip("v")
        key = (module, version)
        if key not in seen:
            seen.add(key)
            deps.append(Dependency(
                name=module,
                version=version,
                ecosystem="golang",
                purl=_make_purl("golang", module, version),
            ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_alire_lock(path: Path) -> list[Dependency]:
    """Parse an Ada/SPARK Alire alire.lock (TOML) file."""
    deps: list[Dependency] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    # Primary: solution.state.<crate>.version
    solution = data.get("solution", {})
    state = solution.get("state", {})
    for crate_name, info in state.items():
        if isinstance(info, dict):
            version = info.get("version", "")
            if version:
                deps.append(Dependency(
                    name=crate_name,
                    version=version,
                    ecosystem="alire",
                    purl=_make_purl("alire", crate_name, version),
                ))

    # Fallback: depends-on list
    if not deps:
        for entry in data.get("depends-on", []):
            if isinstance(entry, dict):
                for crate_name, version_spec in entry.items():
                    version = str(version_spec).strip("=^~>< ")
                    if crate_name and version:
                        deps.append(Dependency(
                            name=crate_name,
                            version=version,
                            ecosystem="alire",
                            purl=_make_purl("alire", crate_name, version),
                        ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def _fpga_purl(vendor: str, name: str, version: str) -> str:
    """purl for an FPGA IP core — vendor as namespace keeps same-named cores
    from different suppliers distinguishable. Version omitted when unknown."""
    base = f"pkg:generic/{quote(vendor, safe='')}/{quote(name, safe='')}"
    return f"{base}@{quote(version, safe='')}" if version else base


def _vlnv_to_dep(
    vlnv: str,
    seen: set[str],
    *,
    allow_missing_version: bool = False,
    note: str = "",
) -> Dependency | None:
    """Turn a VLNV string (``vendor:library:name:version``) into a Dependency.

    VLNV is the IP-XACT / IEEE-1685 identifier every FPGA IP core carries.
    Bus *interface* definitions (library ``interface``) are specifications,
    not delivered components, and multiple instantiations of the same core
    are one component — deduplicated over ``vendor:name:version``.

    ``allow_missing_version`` covers Libero's ``*`` wildcard: the core is
    reported with an EMPTY version (the audit then flags it honestly)
    instead of being dropped or guessed.
    """
    parts = vlnv.split(":")
    if len(parts) != 4:
        return None
    vendor, library, name, version = (p.strip() for p in parts)
    if version == "*":
        version = ""
    if not name or library.lower() == "interface":
        return None
    if not version and not allow_missing_version:
        return None
    key = f"{vendor}:{name}:{version}"
    if key in seen:
        return None
    seen.add(key)
    description = (
        f"FPGA IP core ({vendor}, library {library})" if vendor else "FPGA IP core"
    )
    if note:
        description = f"{description} — {note}"
    return Dependency(
        name=name,
        version=version,
        ecosystem="fpga-ip",
        supplier=vendor or None,
        purl=(_fpga_purl(vendor, name, version) if vendor
              else _make_purl("manual", name, version or "0")),
        description=description,
    )


def scan_vivado_hwh(path: Path) -> list[Dependency]:
    """Parse a Vivado hardware handoff (.hwh) — the full IP list of a design.

    The handoff carries one ``VLNV="vendor:library:name:version"`` attribute
    per instantiated IP core, so a single file yields the complete inventory
    of a block design including third-party cores.
    """
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    seen: set[str] = set()
    for vlnv in re.findall(r'VLNV="([^"]+)"', text):
        dep = _vlnv_to_dep(vlnv, seen)
        if dep is not None:
            deps.append(dep)
    logger.info("Found %d FPGA IP cores in %s", len(deps), path)
    return deps


def scan_vivado_xci(path: Path) -> list[Dependency]:
    """Parse a single Vivado IP configuration file (.xci, IP-XACT XML).

    Consulted only when no handoff file exists — one ``.xci`` describes one
    IP core via its ``spirit:componentRef``.
    """
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    seen: set[str] = set()
    for m in re.finditer(
        r'<spirit:componentRef\b[^>]*'
        r'spirit:vendor="([^"]*)"[^>]*'
        r'spirit:library="([^"]*)"[^>]*'
        r'spirit:name="([^"]*)"[^>]*'
        r'spirit:version="([^"]*)"',
        text,
    ):
        dep = _vlnv_to_dep(":".join(m.groups()), seen)
        if dep is not None:
            deps.append(dep)
    return deps


_LIBERO_NOTE = (
    "version not pinned in the project (Libero '*' wildcard) — resolved at "
    "generation time; declare the built version via embtrace-deps.yaml"
)


def scan_fpga_tcl(path: Path) -> list[Dependency]:
    """Parse FPGA tool TCL files — Libero component scripts and Quartus
    Platform Designer ``*_hw.tcl`` definitions.

    Measured formats (real reference designs, 2026-08-27):

    - Libero (Microchip PolarFire):
      ``create_and_configure_core -core_vlnv {Actel:DirectCore:COREI2C:*}``
      — the version is a ``*`` wildcard; the core is reported with an empty
      version and an explanatory note, never with a guessed version.
    - Quartus (Intel/Altera): ``set_module_property NAME/VERSION/GROUP`` —
      one IP definition per ``*_hw.tcl`` file.
    """
    deps: list[Dependency] = []
    try:
        if path.stat().st_size > 5_000_000:
            return deps
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    seen: set[str] = set()
    for vlnv in re.findall(r"-core_vlnv\s*\{([^}]+)\}", text):
        dep = _vlnv_to_dep(
            vlnv, seen, allow_missing_version=True, note=_LIBERO_NOTE,
        )
        if dep is not None:
            deps.append(dep)

    if not deps and path.name.endswith("_hw.tcl"):
        props = dict(re.findall(
            r'^\s*set_module_property\s+(\w+)\s+"?([^"\n]+?)"?\s*$', text, re.M,
        ))
        name = props.get("NAME", "")
        version = props.get("VERSION", "")
        if name and version:
            vendor = props.get("GROUP", "")
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="fpga-ip",
                supplier=vendor or None,
                purl=_fpga_purl(vendor, name, version) if vendor
                else _make_purl("manual", name, version),
                description=props.get(
                    "DESCRIPTION", "FPGA IP core (Quartus Platform Designer)",
                ),
            ))

    if deps:
        logger.info("Found %d FPGA IP cores in %s", len(deps), path)
    return deps


def scan_libero_cxf(path: Path) -> list[Dependency]:
    """Parse a Libero component description (.cxf) from generated project data.

    Generation resolves the ``*`` version wildcard of the project scripts —
    the .cxf carries the actually-built VLNV as XML elements (measured on
    real PolarFire and SmartFusion2 projects; namespace actel.com/sweng/afi).
    First-party SmartDesigns carry EMPTY vendor/library/version elements
    first and are skipped — they are the user's own code, not supplied IP.
    """
    deps: list[Dependency] = []
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    fields: dict[str, str] = {}
    for child in root:
        local = child.tag.rsplit("}", 1)[-1]
        if local in ("name", "vendor", "library", "version") and local not in fields:
            fields[local] = (child.text or "").strip()

    name = fields.get("name", "")
    vendor = fields.get("vendor", "")
    library = fields.get("library", "")
    version = fields.get("version", "")
    if not (name and vendor and library and version):
        return deps

    deps.append(Dependency(
        name=name,
        version=version,
        ecosystem="fpga-ip",
        supplier=vendor,
        purl=_fpga_purl(vendor, name, version),
        description=(
            f"FPGA IP core ({vendor}, library {library}) — resolved from "
            f"generated component data"
        ),
    ))
    return deps


#: Directories never descended into when sweeping for FPGA tool output.
_FPGA_EXCLUDE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", ".venv", "venv",
    "__pycache__", ".tox", ".embtrace",
}


def _find_fpga_files(
    path: Path, *, max_depth: int = 8,
) -> tuple[list[Path], list[Path], list[Path], list[Path]]:
    """Locate FPGA tool output below *path* (bounded depth, VCS/venv pruned).

    FPGA tool output is named after the design and sits deep in the build
    tree (``src/bd/<design>/hw_handoff/``, ``script_support/components/``),
    so unlike the manifest scanners it is matched recursively by suffix.
    Returns ``(hwh, xci, tcl, cxf)`` — Vivado handoffs, Vivado IP configs,
    Libero/Quartus TCL candidates, and generated Libero component data.
    """
    hwh: list[Path] = []
    xci: list[Path] = []
    tcl: list[Path] = []
    cxf: list[Path] = []
    base_depth = len(path.resolve().parts)
    for root, dirnames, filenames in os.walk(path):
        root_path = Path(root)
        if len(root_path.resolve().parts) - base_depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [
                d for d in dirnames
                if d not in _FPGA_EXCLUDE_DIRS and not d.startswith(".")
            ]
        for filename in filenames:
            if filename.endswith(".hwh"):
                hwh.append(root_path / filename)
            elif filename.endswith(".xci"):
                xci.append(root_path / filename)
            elif filename.endswith(".tcl"):
                tcl.append(root_path / filename)
            elif filename.endswith(".cxf"):
                cxf.append(root_path / filename)
    return sorted(hwh), sorted(xci), sorted(tcl), sorted(cxf)


# ---------------------------------------------------------------------------
# Auto-detect scanner
# ---------------------------------------------------------------------------

_SCANNERS: dict[str, tuple[str, type[object] | None]] = {
    "conan.lock": ("conan_lock", None),
    "conanfile.txt": ("conanfile_txt", None),
    "requirements.txt": ("requirements_txt", None),
    "pyproject.toml": ("pyproject_toml", None),
    "poetry.lock": ("poetry_lock", None),
    "uv.lock": ("uv_lock", None),
    "Pipfile.lock": ("pipfile_lock", None),
    "vcpkg.json": ("vcpkg_json", None),
    "CMakeLists.txt": ("cmake", None),
    "embtrace-deps.yaml": ("embtrace_deps", None),
    "west.yml": ("west_manifest", None),
    "Cargo.lock": ("cargo_lock", None),
    "package-lock.json": ("package_lock_json", None),
    "yarn.lock": ("yarn_lock", None),
    "pnpm-lock.yaml": ("pnpm_lock_yaml", None),
    "gradle.lockfile": ("gradle_lockfile", None),
    "pom.xml": ("pom_xml", None),
    "go.sum": ("go_sum", None),
    "alire.lock": ("alire_lock", None),
}

_SCANNER_FUNCS = {
    "conan_lock": scan_conan_lock,
    "conanfile_txt": scan_conanfile_txt,
    "requirements_txt": scan_requirements_txt,
    "pyproject_toml": scan_pyproject_toml,
    "poetry_lock": scan_poetry_lock,
    "uv_lock": scan_uv_lock,
    "pipfile_lock": scan_pipfile_lock,
    "vcpkg_json": scan_vcpkg_json,
    # "cmake" is handled specially in scan_directory (it needs the project
    # option/cache context) — deliberately not in this uniform-signature map.
    "embtrace_deps": scan_embtrace_deps,
    "west_manifest": scan_west_manifest,
    "cargo_lock": scan_cargo_lock,
    "package_lock_json": scan_package_lock_json,
    "yarn_lock": scan_yarn_lock,
    "pnpm_lock_yaml": scan_pnpm_lock_yaml,
    "gradle_lockfile": scan_gradle_lockfile,
    "pom_xml": scan_pom_xml,
    "go_sum": scan_go_sum,
    "alire_lock": scan_alire_lock,
}


def scan_directory(
    path: Path, *, fpga_recursive: bool = True,
    cmake_ctx: CMakeContext | None = None,
    cmake_extra_cache: Path | None = None,
) -> list[Dependency]:
    """Auto-detect and scan all supported dependency files in a directory.

    Args:
        path: Directory to scan.
        fpga_recursive: Sweep subdirectories for FPGA tool output (Vivado
            names its files after the design and buries them in the build
            tree, so they are matched by suffix, not by fixed filename).
            :func:`scan_directory_recursive` disables this — its own walk
            visits every directory anyway.
        cmake_ctx: Project-wide CMake option/cache context (Befund 41). When
            omitted it is built from *path* — the recursive scanner passes a
            single context so a ``find_package`` in a sub-directory sees the
            ``option()`` defaults declared in the root ``CMakeLists.txt``.

    Returns:
        Combined list of all discovered dependencies (may contain duplicates).
    """
    all_deps: list[Dependency] = []
    if cmake_ctx is None and (path / "CMakeLists.txt").is_file():
        cmake_ctx = build_cmake_context(path, extra_cache=cmake_extra_cache)

    for filename, (scanner_key, _) in _SCANNERS.items():
        filepath = path / filename
        if filepath.is_file():
            logger.info("Detected %s", filepath)
            if scanner_key == "cmake":
                all_deps.extend(scan_cmake(filepath, cmake_ctx=cmake_ctx))
            else:
                all_deps.extend(_SCANNER_FUNCS[scanner_key](filepath))

    # FPGA IP cores: a Vivado handoff (.hwh) already lists every core of a
    # block design — per-IP .xci files are only consulted when no handoff
    # exists, otherwise every core would be counted twice. Libero/Quartus
    # TCL files are an independent toolchain and always scanned.
    if fpga_recursive:
        hwh_files, xci_files, tcl_files, cxf_files = _find_fpga_files(path)
    else:
        hwh_files = sorted(path.glob("*.hwh"))
        xci_files = sorted(path.glob("*.xci"))
        tcl_files = sorted(path.glob("*.tcl"))
        cxf_files = sorted(path.glob("*.cxf"))
    for hwh_file in hwh_files:
        logger.info("Detected %s", hwh_file)
        all_deps.extend(scan_vivado_hwh(hwh_file))
    if not hwh_files:
        for xci_file in xci_files:
            logger.info("Detected %s", xci_file)
            all_deps.extend(scan_vivado_xci(xci_file))
    for tcl_file in tcl_files:
        all_deps.extend(scan_fpga_tcl(tcl_file))
    for cxf_file in cxf_files:
        all_deps.extend(scan_libero_cxf(cxf_file))

    # Post-build enrichment: generated component data (.cxf) carries the
    # resolved version — it supersedes script-derived entries whose version
    # is unpinned (Libero '*' wildcard).
    versioned_fpga = {
        f"{(d.supplier or '').lower()}:{d.name.lower()}"
        for d in all_deps if d.ecosystem == "fpga-ip" and d.version
    }
    if versioned_fpga:
        all_deps = [
            d for d in all_deps
            if not (
                d.ecosystem == "fpga-ip" and not d.version
                and f"{(d.supplier or '').lower()}:{d.name.lower()}" in versioned_fpga
            )
        ]

    # Manual deps (embtrace-deps.yaml) are authoritative — when a manual entry
    # exists for a component, drop auto-detected entries with the same name so
    # the richer metadata (supplier, license, purl) is kept.
    manual_names: set[str] = {
        dep.name for dep in all_deps if dep.ecosystem == "manual"
    }
    if manual_names:
        filtered: list[Dependency] = []
        for dep in all_deps:
            if dep.ecosystem != "manual" and dep.name in manual_names:
                logger.debug(
                    "Suppressing auto-detected %s (%s v%s) — manual entry exists",
                    dep.name, dep.ecosystem, dep.version,
                )
                continue
            filtered.append(dep)
        all_deps = filtered

    # Deduplicate by (name, version, ecosystem)
    seen: set[tuple[str, str, str]] = set()
    unique: list[Dependency] = []
    for dep in all_deps:
        key = (dep.name, dep.version, dep.ecosystem)
        if key not in seen:
            seen.add(key)
            unique.append(dep)

    logger.info("Total: %d unique dependencies in %s", len(unique), path)
    return unique


#: Directories never scanned for dependencies — build outputs and vendored
#: trees produce duplicate/phantom components (hidden dirs are skipped too).
DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset({
    "node_modules", "__pycache__", "build", "cmake-build",
    "target", "vendor", "dist", "venv",
})

#: Project-local ignore file — one glob pattern per line, ``#`` comments.
#: Patterns match directory names and paths relative to the scan root
#: (e.g. ``staging``, ``firmware/generated``, ``*.bak``).
IGNORE_FILENAME = ".embtraceignore"


def load_ignore_patterns(root: Path) -> list[str]:
    """Read ``.embtraceignore`` at *root* (empty list when absent)."""
    ignore_file = root / IGNORE_FILENAME
    if not ignore_file.is_file():
        return []
    try:
        lines = ignore_file.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("Cannot read %s: %s", ignore_file, exc)
        return []
    patterns = [
        stripped.rstrip("/")
        for line in lines
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]
    if patterns:
        logger.info("Loaded %d ignore patterns from %s", len(patterns), ignore_file)
    return patterns


def _is_ignored(rel_path: str, name: str, patterns: list[str]) -> bool:
    """Match a directory (name or root-relative path) against ignore globs."""
    import fnmatch

    return any(
        fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel_path, pat)
        for pat in patterns
    )


def prefer_locked(deps: list[Dependency]) -> list[Dependency]:
    """Drop manifest-constraint entries shadowed by a resolved version.

    A pyproject ``pillow>=10.0`` next to a lockfile ``pillow 12.3.0`` must
    not become a second, phantom component with false-positive CVEs — the
    resolved version is the deployed truth, the constraint is only a floor.
    Manifest entries without any resolved counterpart are kept (a
    manifest-only project still gets its best-effort versions).
    """
    resolved_names = {
        dep.name.lower().replace("_", "-")
        for dep in deps
        if dep.source_kind != "manifest"
    }
    kept: list[Dependency] = []
    dropped = 0
    for dep in deps:
        if (
            dep.source_kind == "manifest"
            and dep.name.lower().replace("_", "-") in resolved_names
        ):
            dropped += 1
            continue
        kept.append(dep)
    if dropped:
        logger.info(
            "Dropped %d manifest-constraint entr%s shadowed by resolved versions",
            dropped, "y" if dropped == 1 else "ies",
        )
    return kept


#: Directory names whose contents are test/example material — the
#: components inside are real and stay listed, but scope "excluded"
#: keeps them out of the traffic light (order collector-
#: mehrfachversionen Befund 10; libwebsockets added test-apps/,
#: minimal-examples*/ and contrib/ — Befund 46).
_TEST_SCOPE_DIRS = frozenset({
    "tests", "test", "test-apps", "examples", "example",
    "minimal-examples", "fixtures", "samples", "benchmarks", "docs",
    "contrib",
})


def is_test_material_part(part: str) -> bool:
    """True when a path segment marks test/example/contrib material (Befund 46).

    Matches the exact names plus the common families — ``test-*`` (test-apps,
    test-server) and anything with ``example`` in it (minimal-examples-lowlevel).
    Such components are real and stay listed, but never gate the verdict and
    never cost the customer a review question.
    """
    p = part.lower()
    return p in _TEST_SCOPE_DIRS or p.startswith("test-") or "example" in p


def scan_directory_recursive(
    path: Path, *, max_depth: int = 5, cmake_extra_cache: Path | None = None,
) -> list[Dependency]:
    """Recursively scan a directory tree for dependency files.

    Walks all subdirectories up to *max_depth* and calls :func:`scan_directory`
    for each.  Results are deduplicated by ``(name, version, ecosystem)``;
    manifest-constraint versions shadowed by a resolved version of the same
    package are dropped (:func:`prefer_locked`). Build-output directories
    (:data:`DEFAULT_EXCLUDE_DIRS`), hidden directories, and everything
    matched by a ``.embtraceignore`` at *path* are skipped.

    This is used by the analyzer flow (``embtrace init --scan``) to find
    lockfiles in mono-repos and nested sub-projects.

    Args:
        path: Root directory to scan.
        max_depth: Maximum directory depth to recurse into.

    Returns:
        Combined, deduplicated list of all discovered dependencies.
    """
    all_deps: list[Dependency] = []
    seen_dirs: set[Path] = set()
    ignore_patterns = load_ignore_patterns(path)
    # One CMake context for the whole tree: option() defaults live in the root
    # CMakeLists.txt, a find_package deep in src/; a configured build's
    # CMakeCache.txt (in build/, _build/, …) is the source of truth (Befund 41).
    cmake_ctx = build_cmake_context(path, extra_cache=cmake_extra_cache)

    def _walk(current: Path, depth: int) -> None:
        resolved = current.resolve()
        if resolved in seen_dirs:
            return
        seen_dirs.add(resolved)

        # A directory holding CMakeCache.txt is a build tree — its generated
        # CMakeLists/.cmake would inject phantom find_package hits. Its cache
        # is already folded into cmake_ctx; do not scan or descend into it.
        if (current / "CMakeCache.txt").is_file() and current != path:
            return

        # Scan this directory (FPGA sweep off — this walk visits every dir)
        found = scan_directory(current, fpga_recursive=False, cmake_ctx=cmake_ctx)
        # Test/example material travels, but marked: scope "excluded"
        # keeps it out of the traffic light while hiding nothing
        # (order collector-mehrfachversionen Befund 10, way (b) — a
        # vulnerable flask 0.12.2 from tests/fixtures/ must never gate
        # the product verdict, and must never be silently dropped
        # either). Declarations keep their author's word untouched.
        try:
            rel_parts = current.relative_to(path).parts
        except ValueError:
            rel_parts = ()
        if any(is_test_material_part(part) for part in rel_parts):
            for dep in found:
                if not dep.scope and not dep.declared:
                    dep.scope = "excluded"
        all_deps.extend(found)

        if depth >= max_depth:
            return

        # Recurse into subdirectories
        try:
            entries = sorted(current.iterdir())
        except OSError:
            return
        for entry in entries:
            if not entry.is_dir():
                continue
            # Skip hidden dirs, build-output dirs, VCS dirs, and ignores
            name = entry.name
            if name.startswith(".") or name in DEFAULT_EXCLUDE_DIRS:
                continue
            try:
                rel = entry.relative_to(path).as_posix()
            except ValueError:
                rel = name
            if _is_ignored(rel, name, ignore_patterns):
                logger.info("Skipping %s (.embtraceignore)", rel)
                continue
            _walk(entry, depth + 1)

    _walk(path, 0)

    # Manifest floors lose against resolved versions across the whole tree,
    # then deduplicate across all directories.
    all_deps = prefer_locked(all_deps)
    seen: set[tuple[str, str, str]] = set()
    unique: list[Dependency] = []
    for dep in all_deps:
        key = (dep.name, dep.version, dep.ecosystem)
        if key not in seen:
            seen.add(key)
            unique.append(dep)

    # Every component carries a scope (Befund 81, nachgezogen aus der Suite).
    # Until now only test material was stamped ("excluded") and everything
    # else stayed empty — so in the payload, and therefore in the CUSTOMER'S
    # report, "part of the product" and "never judged" looked identical. The
    # report could not separate product from test material, which is exactly
    # the distinction the free check is supposed to deliver.
    #
    # "required" is the CONSERVATIVE default, not a measurement: a component
    # found in the build tree and not recognised as test material is treated
    # as part of the product — the claim the report already makes about it.
    for dep in unique:
        if not dep.scope:
            dep.scope = "required"

    logger.info(
        "Recursive scan: %d unique dependencies in %s (depth=%d)",
        len(unique), path, max_depth,
    )
    return unique
