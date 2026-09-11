"""System resolver — versions and suppliers from the system linked against.

Reihe 19, Increment 2: build systems (CMake, Make, Meson, Autotools) yield
NAMES; the versions live on the system the product links against. The
resolver asks that system directly:

1. ``pkg-config --modversion`` — the upstream version of the installed
   library. Sysroot-aware: honours ``PKG_CONFIG_SYSROOT_DIR`` /
   ``PKG_CONFIG_PATH`` from the environment (cross-compile, the target
   audience's scenario); the origin (host vs. sysroot) travels with the
   result.
2. The package manager (dpkg, rpm fallback) for the DISTRIBUTION package:
   its version (``3.0.13-0ubuntu3.15`` — the patch level that decides which
   CVEs are actually fixed), the maintainer as supplier, the machine-readable
   copyright as license.

Both versions are kept: ``Dependency.version`` gets the upstream number
(pkg-config), ``Dependency.distro_version`` the distribution package version.
Name mapping (find_package ``OpenSSL`` ≠ pkg-config ``openssl`` ≠ dpkg
``libssl-dev``) starts as a curated table; only a UNIQUE, confident match is
applied — ambiguity resolves to "leave it alone", never a guess.

The resolver READS what is installed. It never installs, builds or asks the
network.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from embtrace_sbom.core.log import get_logger

if TYPE_CHECKING:
    from embtrace_sbom.sbom.scanner import Dependency

logger = get_logger(__name__)

#: find_package/pkg-check name (lowercased) → pkg-config candidates, curated.
#: Only names whose mapping is unambiguous — a miss falls back to the
#: lowercased name itself, an ambiguous name stays unresolved.
_PKGCONF_MAP: dict[str, list[str]] = {
    "openssl": ["openssl"],
    "libressl": ["libtls"],
    "gnutls": ["gnutls"],
    "mbedtls": ["mbedtls"],
    "wolfssl": ["wolfssl"],
    "sqlite3": ["sqlite3"],
    "sqlite": ["sqlite3"],
    "zlib": ["zlib"],
    "freetype": ["freetype2"],
    "png": ["libpng"],
    "libpng": ["libpng"],
    "curl": ["libcurl"],
    "libevent": ["libevent"],
    "libev": ["libev"],
    "libuv": ["libuv"],
    "libcap": ["libcap"],
    "systemd": ["libsystemd"],
    "glib": ["glib-2.0"],
    "expat": ["expat"],
    "libxml2": ["libxml-2.0"],
    "pcre2": ["libpcre2-8"],
    "lz4": ["liblz4"],
    "zstd": ["libzstd"],
    "jansson": ["jansson"],
    "json-c": ["json-c"],
}

#: Ecosystems whose names come from the no-package-manager world — the only
#: ones the system resolver may touch.
_NATIVE_ECOSYSTEMS: frozenset[str] = frozenset({
    "cmake", "make", "meson", "autotools", "configure", "generic",
})


def _run(cmd: list[str], timeout: float = 10.0) -> tuple[int, str]:
    """Run *cmd*, return (returncode, stdout). Never raises."""
    try:
        proc = subprocess.run(  # noqa: S603 — fixed binaries, no shell
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("sysresolve: %s failed: %s", cmd[0], exc)
        return 127, ""
    return proc.returncode, proc.stdout.strip()


def _pc_candidates(name: str) -> list[str]:
    low = name.lower()
    mapped = _PKGCONF_MAP.get(low)
    if mapped:
        return mapped
    return [low] if low != name else [name]


def pkg_config_lookup(name: str) -> tuple[str, str, str]:
    """Resolve *name* via pkg-config → ``(pc_name, version, pc_file)``.

    Empty strings when pkg-config is missing or no candidate resolves.
    """
    if shutil.which("pkg-config") is None:
        return "", "", ""
    for cand in _pc_candidates(name):
        rc, version = _run(["pkg-config", "--modversion", cand])
        if rc != 0 or not version:
            continue
        # --path exists from pkg-config 0.29; fall back to pcfiledir.
        rc2, pc_file = _run(["pkg-config", "--path", cand])
        if rc2 != 0 or not pc_file:
            rc3, pc_dir = _run(["pkg-config", "--variable=pcfiledir", cand])
            pc_file = f"{pc_dir}/{cand}.pc" if rc3 == 0 and pc_dir else ""
        return cand, version.splitlines()[0], pc_file
    return "", "", ""


def _strip_email(who: str) -> str:
    return re.sub(r"\s*<[^>]*>", "", who).strip()


#: os-release ID → OSV ecosystem prefix (only ecosystems OSV actually serves).
_OSV_DISTRO_PREFIX: dict[str, str] = {
    "ubuntu": "Ubuntu", "debian": "Debian", "alpine": "Alpine",
}


def distro_osv_ecosystem(os_release: Path = Path("/etc/os-release")) -> str:
    """OSV ecosystem of the RUNNING system ("Ubuntu:24.04", "Debian:12",
    "Alpine:v3.20") — "" when the distro is not an OSV ecosystem. This is
    the system whose packages the resolver reads, so its advisories are the
    ones that decide the shipped patch level (Reihe 19, Rest 1)."""
    try:
        text = os_release.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    fields = dict(
        line.split("=", 1) for line in text.splitlines() if "=" in line
    )
    prefix = _OSV_DISTRO_PREFIX.get(fields.get("ID", "").strip('"').lower())
    version = fields.get("VERSION_ID", "").strip('"')
    if not prefix or not version:
        return ""
    if prefix == "Alpine":
        # OSV names Alpine releases "Alpine:v3.20".
        version = f"v{'.'.join(version.split('.')[:2])}"
    return f"{prefix}:{version}"


def dpkg_package_info(file_path: str) -> dict[str, str]:
    """Distribution package owning *file_path* via dpkg (Debian/Ubuntu)."""
    if not file_path or shutil.which("dpkg") is None:
        return {}
    rc, out = _run(["dpkg", "-S", file_path])
    if rc != 0 or ":" not in out:
        return {}
    package = out.split(":", 1)[0].strip()
    rc, fields = _run([
        "dpkg-query", "-W",
        "-f=${Version}\\t${Original-Maintainer}\\t${Maintainer}"
        "\\t${Homepage}\\t${source:Package}",
        package,
    ])
    if rc != 0 or not fields:
        return {"package": package}
    parts = (fields.split("\t") + ["", "", "", "", ""])[:5]
    supplier = _strip_email(parts[1] or parts[2])
    info = {
        "package": package,
        "distro_version": parts[0],
        "supplier": supplier,
        "homepage": parts[3],
        # OSV Ubuntu/Debian advisories key by the SOURCE package (openssl,
        # not libssl-dev) — required to query the distro view (Rest 1).
        "source_package": parts[4] or package,
    }
    lic = _license_from_copyright(package)
    if lic:
        info["license"] = lic
    return info


def rpm_package_info(file_path: str) -> dict[str, str]:
    """Distribution package owning *file_path* via rpm (Fedora/SUSE)."""
    if not file_path or shutil.which("rpm") is None:
        return {}
    rc, out = _run([
        "rpm", "-qf", file_path,
        "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{VENDOR}\\t%{LICENSE}",
    ])
    if rc != 0 or "\t" not in out:
        return {}
    parts = (out.split("\t") + ["", "", "", ""])[:4]
    info = {
        "package": parts[0],
        "distro_version": parts[1],
        "supplier": parts[2],
    }
    if parts[3]:
        info["license"] = parts[3]
    return info


def _license_from_copyright(
    package: str, base: Path = Path("/usr/share/doc"),
) -> str:
    """Collector twin: ALWAYS empty — the collector sends no license for
    discovered components (data-minimisation promise); the suite's version
    ranks the machine-readable copyright via sbom.graph, which the collector
    deliberately does not bundle."""
    return ""


def resolve_system_libraries(deps: list[Dependency]) -> int:
    """Fill versions/suppliers of native deps from the linked system.

    Touches only deps from native ecosystems, never customer declarations,
    and never overwrites an existing value. Returns the number of deps that
    received at least one field.
    """
    if os.environ.get("EMBTRACE_NO_SYSRESOLVE"):
        return 0
    origin = (
        "pkg-config (Sysroot)"
        if os.environ.get("PKG_CONFIG_SYSROOT_DIR")
        else "pkg-config (Host)"
    )
    touched = 0
    for dep in deps:
        if dep.ecosystem not in _NATIVE_ECOSYSTEMS or dep.declared:
            continue
        if dep.version and dep.supplier and dep.distro_version:
            continue
        pc_name, version, pc_file = pkg_config_lookup(dep.name)
        if not pc_name:
            continue
        changed = False
        if not dep.version and version:
            dep.version = version
            changed = True
        info = dpkg_package_info(pc_file) or rpm_package_info(pc_file)
        if info.get("distro_version") and not dep.distro_version:
            dep.distro_version = info["distro_version"]
            dep.distro_source = info.get("source_package", "")
            dep.distro_ecosystem = distro_osv_ecosystem()
            changed = True
        supplier_echo = bool(
            dep.supplier and dep.supplier.lower() == dep.name.lower()
        )
        if info.get("supplier") and (not dep.supplier or supplier_echo):
            # A supplier equal to the package name is a name echo, not a
            # party (Rest 4) — the distro maintainer is a real one.
            dep.supplier = info["supplier"]
            changed = True
        if info.get("license") and not dep.license:
            dep.license = info["license"]
            changed = True
        if changed:
            dep.resolved_from = origin
            touched += 1
    if touched:
        logger.info("System resolver filled %d component(s) via %s",
                    touched, origin)
    return touched
