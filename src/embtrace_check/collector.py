"""Dependency collection for the CRA Readiness Check.

Combines the two deterministic detection paths that already power embtrace:

1. :func:`embtrace.sbom.scanner.scan_directory_recursive` — lockfiles and
   manifests (16 formats, high confidence).
2. :func:`embtrace.analyzer.pipeline.run_pipeline` — build-file analysis via
   the multi-tier pipeline, restricted to the deterministic tiers (2 = struct-
   ured parsers, 4 = regex; tier 1 CLI tools optional via ``with_tools``).

No LLM, no tree-sitter, no external tools by default — the collector must run
anywhere, instantly, with zero setup.
"""

from __future__ import annotations

from pathlib import Path

from embtrace_check.analyzer.normalize import normalize_dep_name
from embtrace_check.analyzer.pipeline import run_pipeline
from embtrace_check.analyzer.scanner import _apply_cmake_conditions, collect_build_files
from embtrace_check.core.exceptions import CheckCollectionError
from embtrace_check.payload import CheckComponent, CheckStats
from embtrace_check.sbom.classify import (
    _C_KEYWORDS,
    _looks_like_library,
    clean_dependency,
    is_invalid_name,
    strip_control_chars,
)
from embtrace_check.sbom.scanner import is_test_material_part, scan_directory_recursive

#: Deterministic pipeline tiers that need no tooling on the host.
_DEFAULT_TIERS = frozenset({2, 4})
#: Tier 1 adds native CLI tools (cargo, go, npm, …) when present on the host.
_TOOL_TIER = 1

#: Confidence assigned to lockfile-derived components (structured parse).
_LOCKFILE_CONFIDENCE = 0.95
#: Confidence for manifest-constraint floors (">=" — version unconfirmed).
_MANIFEST_CONFIDENCE = 0.7
_LOCKFILE_TIER = 2

#: Build-script name-token ecosystems — the only place the skip list
#: may drop a name (npm/pypi homonyms like bcrypt/threads/numpy are
#: real packages).
_NAME_ONLY_ECOSYSTEMS = frozenset({
    "cmake", "meson", "make", "autotools", "configure", "generic",
})


def _is_parser_noise(name: str, version: str, ecosystem: str) -> bool:
    """DB-free parser-noise check (Befund 13, collector flavour).

    The collector has no knowledge DB — the SERVER does the authoritative
    suspect classification. So the collector only drops what is noise
    *regardless* of a DB: a C keyword (``int``), an empty name, or a single
    character (``n`` harvested from ``-ln``). An ambiguous capitalized word
    (``OpenSSL``, ``Packet``) is kept and sent — dropping it here would lose a
    real library, because unlike the suite there is no DB to vouch for it.
    """
    if version and version != "*":
        return False  # a resolved version is trust
    if ecosystem not in _NAME_ONLY_ECOSYSTEMS:
        return False
    clean = strip_control_chars(name)
    if not clean:
        return True
    if clean.lower() in _C_KEYWORDS:
        return True
    if _looks_like_library(clean):
        return False
    return len(clean) <= 1


def collect_components(
    path: Path,
    *,
    with_tools: bool = False,
    max_depth: int = 5,
    include_declared_metadata: bool = True,
) -> tuple[list[CheckComponent], CheckStats]:
    """Collect deduplicated dependency metadata from a project directory.

    Args:
        path: Project root to scan.
        with_tools: Also run tier 1 (native CLI tools) of the pipeline.
        max_depth: Maximum directory depth for both detection paths.

    Returns:
        Tuple of (components sorted by insertion source, scan statistics).

    Raises:
        CheckCollectionError: If ``path`` is not a readable directory.
    """
    if not path.is_dir():
        msg = f"Not a directory: {path}"
        raise CheckCollectionError(msg)

    # Path 1: lockfiles / manifests — these win on conflict (they carry
    # pinned versions), so they are inserted first. Manifest-constraint
    # floors already lost against resolved versions inside
    # scan_directory_recursive (prefer_locked); the survivors are labelled
    # honestly — a ">=" floor is not a lockfile fact.
    from embtrace_check.sbom.skiplist import is_skipped

    # Identity of a component is (name, version, ecosystem) — never the
    # name alone: npm regularly nests two versions of one package, and
    # the older nested one is often the vulnerable one (order
    # collector-mehrfachversionen).
    # The project's own name (its directory) is not a third-party component;
    # neither is an unexpanded CMake variable (Befund 47).
    proj = normalize_dep_name(path.resolve().name)

    def _not_component(name: str) -> bool:
        return is_invalid_name(name) or (
            bool(proj) and normalize_dep_name(name) == proj
        )

    merged: dict[tuple[str, str], CheckComponent] = {}
    # Conditional ALTERNATIVES travel MARKED, not dropped (Befund 44): the
    # report can then say "your project can be built with OpenSSL or LibreSSL
    # — configure once". They are never counted as components, never gating.
    conditional_comps: list[CheckComponent] = []
    conditional_seen: set[str] = set()

    def _add_conditional(name: str, version: str, ecosystem: str,
                         condition: str, tier: int) -> None:
        ckey = normalize_dep_name(name)
        if ckey in conditional_seen:
            return
        conditional_seen.add(ckey)
        conditional_comps.append(CheckComponent(
            name=name, version=version, ecosystem=ecosystem,
            source_type="conditional", tier=tier, confidence=0.0,
            condition=condition, scope="excluded",
        ))

    for dep in scan_directory_recursive(path, max_depth=max_depth):
        # Control-char hygiene FIRST (Befund 15 — a scanner once read colored
        # tool output), so the dedup key and the uploaded payload are clean.
        clean_dependency(dep)
        if not dep.declared and _not_component(dep.name):
            continue  # ${ARGN} or the project depending on itself (Befund 47)
        # A find_package behind an off-by-default option is an ALTERNATIVE —
        # it travels marked with its guard, never as a present component.
        if dep.condition:
            _add_conditional(dep.name, dep.version, dep.ecosystem,
                             dep.condition, _LOCKFILE_TIER)
            continue
        key = (normalize_dep_name(dep.name), dep.version)
        if key in merged:
            continue
        # Curated skip list (build tools, system libs) applies only to
        # name tokens from build scripts — a resolved lockfile entry is
        # a real package regardless of its name (npm bcrypt/threads/util
        # are homonyms, not tooling); declarations are never skipped.
        if (
            not dep.declared
            and dep.ecosystem in _NAME_ONLY_ECOSYSTEMS
            and is_skipped(dep.name)
        ):
            continue
        # Parser noise the collector can judge without a DB — int/char/n
        # (Befund 13); ambiguous names go to the server, which has the DB.
        if not dep.declared and _is_parser_noise(dep.name, dep.version, dep.ecosystem):
            continue
        # Entries from embtrace-deps.yaml are the customer's own SBOM
        # declaration: they keep the metadata written there (opt-out via
        # include_declared_metadata) and are labelled "declared" so the
        # server can tell declaration from discovery apart.
        if dep.declared:
            merged[key] = CheckComponent(
                name=dep.name,
                version=dep.version,
                ecosystem=dep.ecosystem,
                source_type="declared",
                tier=_LOCKFILE_TIER,
                confidence=1.0,
                supplier=(dep.supplier or "") if include_declared_metadata else "",
                license=(dep.license or "") if include_declared_metadata else "",
                purl=(dep.purl or "") if include_declared_metadata else "",
                cpe=(dep.cpe or "") if include_declared_metadata else "",
                scope=dep.scope,
            )
            continue
        is_floor = dep.source_kind == "manifest"
        merged[key] = CheckComponent(
            name=dep.name,
            version=dep.version,
            ecosystem=dep.ecosystem,
            source_type="manifest" if is_floor else "lockfile",
            tier=_LOCKFILE_TIER,
            confidence=_MANIFEST_CONFIDENCE if is_floor else _LOCKFILE_CONFIDENCE,
            scope=dep.scope,
        )

    # Path 2: build-file pipeline (deterministic tiers only).
    tiers = set(_DEFAULT_TIERS | {_TOOL_TIER}) if with_tools else set(_DEFAULT_TIERS)
    build_files = collect_build_files(path, max_depth=max_depth)
    pipeline_deps, _artifacts, _internal = run_pipeline(
        path, build_files, enabled_tiers=tiers
    )
    # Reconcile CMake find_package hits with the branch/option/cache truth
    # (Befund 38/41): drop names the configured build did not take, mark an
    # off-by-default alternative's guard into context. run_pipeline does not
    # do this itself, so the collector must (the suite does it in
    # analyze_with_pipeline).
    pipeline_deps = _apply_cmake_conditions(pipeline_deps, path)
    seen_names = {name for name, _version in merged}
    for pdep in pipeline_deps:
        pdep.name = strip_control_chars(pdep.name)
        if _not_component(pdep.name):
            continue  # ${ARGN} or self-dependency (Befund 47)
        # A conditional alternative carries its guard in context — it travels
        # marked (Befund 44), never as a present component.
        if pdep.ecosystem == "cmake" and pdep.context:
            if normalize_dep_name(pdep.name) not in seen_names:
                _add_conditional(pdep.name, pdep.version, pdep.ecosystem,
                                 pdep.context, pdep.tier)
            continue
        if normalize_dep_name(pdep.name) in seen_names:
            continue
        if pdep.ecosystem in _NAME_ONLY_ECOSYSTEMS and is_skipped(pdep.name):
            continue
        if _is_parser_noise(pdep.name, pdep.version, pdep.ecosystem):
            continue
        key = (normalize_dep_name(pdep.name), pdep.version)
        if key in merged:
            continue
        src_parts = Path(pdep.source_file).parts if pdep.source_file else ()
        # Same family detection as the suite (Befund 52): test-apps/,
        # minimal-examples*/, contrib/ … — not just the exact names, or the
        # customer gets a DIFFERENT bill through the collector than the suite.
        pscope = (
            "excluded"
            if any(is_test_material_part(part) for part in src_parts)
            else ""
        )
        merged[key] = CheckComponent(
            name=pdep.name,
            version=pdep.version,
            ecosystem=pdep.ecosystem,
            source_type=pdep.detection_method or "build-file",
            tier=pdep.tier,
            confidence=pdep.confidence,
            scope=pscope,
        )

    # Path 3: Yocto/Buildroot BUILD OUTPUT — what is actually in the
    # customer's image (run the check in the build directory).
    from embtrace_check.sbom.buildoutput import scan_build_output

    build_output_deps, build_output_sources = scan_build_output(
        path, max_depth=max_depth,
    )
    for dep in build_output_deps:
        clean_dependency(dep)  # control-char hygiene (Befund 15)
        # Resolved, installed packages — the skip list never applies.
        key = (normalize_dep_name(dep.name), dep.version)
        if key in merged:
            continue
        merged[key] = CheckComponent(
            name=dep.name,
            version=dep.version,
            ecosystem=dep.ecosystem,
            source_type="build-output",
            tier=_LOCKFILE_TIER,
            confidence=_LOCKFILE_CONFIDENCE,
        )

    # Real components first, then the marked alternatives (Befund 44). The
    # component COUNT and the ecosystem list cover only real components; the
    # conditional ones are surfaced through stats.conditional.
    real = list(merged.values())
    components = real + conditional_comps
    ecosystems = sorted({c.ecosystem for c in real if c.ecosystem})

    # Lifecycle mirrors the suite (Befund 52): a configured build (cache) or
    # resolved output (lockfile / build output) is "build" provenance; only
    # declarations is "design"; nothing found stays "".
    from embtrace_check.sbom.cmake_conditions import build_cmake_context

    has_cache = build_cmake_context(path).has_cache
    resolved = any(
        c.source_type in ("lockfile", "build-output", "declared") for c in real
    )
    if has_cache or resolved:
        lifecycle = "build"
    elif real or conditional_comps:
        lifecycle = "design"
    else:
        lifecycle = ""

    stats = CheckStats(
        build_files_scanned=len(build_files),
        ecosystems=ecosystems,
        build_output_sources=build_output_sources,
        conditional=len(conditional_comps),
        lifecycle=lifecycle,
    )
    return components, stats
