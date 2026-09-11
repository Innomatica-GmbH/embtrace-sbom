"""Yocto/Buildroot BUILD OUTPUT scanners.

What is authoritative for a customer image is the build output —
``deploy/images/**/*.manifest`` (what is IN the image) and Buildroot's
``legal-info/manifest.csv`` — not the recipe source tree, which only
says what could be built (order collector-embedded-buildsysteme).
"""

from __future__ import annotations

import csv
from pathlib import Path

from embtrace_sbom.sbom.scanner import Dependency


def parse_yocto_manifest_file(path: Path) -> list[Dependency]:
    """Parse ONE Yocto image manifest (``name arch version`` lines)."""
    deps: list[Dependency] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            name, version = parts[0], parts[2]
        elif len(parts) == 2:
            name, version = parts[0], parts[1]
        else:
            continue
        deps.append(Dependency(
            name=name, version=version, ecosystem="yocto",
            purl=f"pkg:yocto/{name}@{version}",
        ))
    return deps


def parse_buildroot_manifest_csv(path: Path) -> list[Dependency]:
    """Parse Buildroot's ``legal-info/manifest.csv``.

    ``host-manifest.csv`` (build-host tooling) is deliberately not
    parsed: host tools never ship in the image.
    """
    deps: list[Dependency] = []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if not header or header[0].strip().upper() != "PACKAGE":
            return deps
        for row in reader:
            if len(row) < 2 or not row[0].strip():
                continue
            name, version = row[0].strip(), row[1].strip()
            deps.append(Dependency(
                name=name, version=version, ecosystem="buildroot",
                purl=f"pkg:buildroot/{name}@{version}" if version
                     else f"pkg:buildroot/{name}",
            ))
    return deps


def scan_build_output(
    path: Path, *, max_depth: int = 5,
) -> tuple[list[Dependency], list[str]]:
    """Find and parse Yocto/Buildroot build output under ``path``."""
    manifests: list[Path] = []
    legal_csvs: list[Path] = []

    def _walk(current: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            entries = sorted(current.iterdir())
        except OSError:
            return
        for entry in entries:
            if entry.is_dir():
                if entry.name.startswith(".") or entry.name in ("sources", "host-sources"):
                    continue
                if entry.name == "legal-info":
                    csv_file = entry / "manifest.csv"
                    if csv_file.is_file():
                        legal_csvs.append(csv_file)
                    continue
                _walk(entry, depth + 1)
            elif entry.name.endswith(".rootfs.manifest") or (
                entry.name.endswith(".manifest") and "images" in current.parts
            ):
                manifests.append(entry)

    _walk(path, 0)

    deps: list[Dependency] = []
    sources: list[str] = []
    for mf in manifests:
        try:
            found = parse_yocto_manifest_file(mf)
        except OSError:
            continue
        if found:
            deps.extend(found)
            sources.append(f"yocto image manifest {mf.name} ({len(found)} packages)")
    for csv_file in legal_csvs:
        try:
            found = parse_buildroot_manifest_csv(csv_file)
        except OSError:
            continue
        if found:
            deps.extend(found)
            sources.append(f"buildroot legal-info manifest.csv ({len(found)} packages)")
    return deps, sources
