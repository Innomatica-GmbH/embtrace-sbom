"""Deterministic CMake build-file parser.

Extracts dependency names from CMakeLists.txt and *.cmake files by matching:
- find_package / find_host_package(Name ...)
- include(FindXXX) — CMake module inclusion for dependency search
- FetchContent_Declare(name ...)
- pkg_check_modules / pkg_search_module / ocv_check_modules(VAR name ...)
- set(XXX_PKG_CONFIG_SPEC name) — SDL-style variable-based pkg-config
- find_library(VAR NAMES name ...)
- find_path(VAR NAMES header ...) — header search for libraries
- check_library_exists(lib ...)
- ExternalProject_Add(name ...)
"""

from __future__ import annotations

import re

# --- Regex patterns -----------------------------------------------------------

# find_package(OpenSSL REQUIRED) / find_host_package(CUDA ...) → "OpenSSL" / "CUDA"
_FIND_PACKAGE = re.compile(
    r"find_(?:host_)?package\s*\(\s*(\w+)",
    re.IGNORECASE,
)

# FetchContent_Declare(json GIT_REPOSITORY ...) → "json"
_FETCH_CONTENT = re.compile(
    r"FetchContent_Declare\s*\(\s*(\w+)",
    re.IGNORECASE,
)

# pkg_check_modules(DLT REQUIRED 'automotive-dlt >= 2.11')
# pkg_check_modules(DLT automotive-dlt>=2.11)
# pkg_check_modules(DLT REQUIRED IMPORTED_TARGET automotive-dlt)
# Also: pkg_search_module, ocv_check_modules (OpenCV wrapper)
_PKG_CHECK_MODULES = re.compile(
    r"(?:pkg_(?:check_modules|search_module)|ocv_check_modules)\s*\("
    r"\s*\w+"  # variable name
    r"(?:\s+(?:REQUIRED|QUIET|IMPORTED_TARGET|NO_CMAKE_PATH|NO_CMAKE_ENVIRONMENT_PATH))*"  # flags
    r"\s+['\"]?([a-zA-Z0-9_][a-zA-Z0-9_.+-]*)",  # package name
    re.IGNORECASE,
)

# SDL pattern: set(PipeWire_PKG_CONFIG_SPEC libpipewire-0.3>=0.3.44)
# Also: set(PKG_CONFIG_LIBDRM_SPEC libdrm) — alternate SDL naming convention
# Captures the pkg-config package name from variable-based pkg_check_modules
_SET_PKG_CONFIG_SPEC = re.compile(
    r"set\s*\(\s*(?:\w+_PKG_CONFIG_SPEC|PKG_CONFIG_\w+_SPEC)\s+"
    r"['\"]?([a-zA-Z][a-zA-Z0-9_.+-]*)",
    re.IGNORECASE,
)

# find_library(MICROHTTPD_LIBRARY NAMES microhttpd)
# find_library(MICROHTTPD_LIBRARY microhttpd)
# find_library(VIVANTE_LIBRARY REQUIRED NAMES VIVANTE vivante) — flags before NAMES
_FIND_LIBRARY = re.compile(
    r"find_library\s*\(\s*\w+"  # variable
    r"(?:\s+(?:REQUIRED|QUIET))*"  # optional flags before NAMES
    r"\s+(?:NAMES?\s+)?(\w+)",  # library name
    re.IGNORECASE,
)

# check_library_exists(rt clock_gettime "" HAVE_RT)
_CHECK_LIBRARY = re.compile(
    r"check_library_exists\s*\(\s*(\w+)",
    re.IGNORECASE,
)

# ExternalProject_Add(name ...) → "name"
_EXTERNAL_PROJECT = re.compile(
    r"ExternalProject_Add\s*\(\s*(\w+)",
    re.IGNORECASE,
)

# include(FindJPEG) / include(FindZLIB) — CMake Find-module inclusion
# Captures the library name from "FindXXX" (strips "Find" prefix)
_INCLUDE_FIND = re.compile(
    r"include\s*\(\s*Find(\w+)\s*\)",
    re.IGNORECASE,
)

# include(cmake/cares.cmake) / include(cmake/opentelemetry-cpp.cmake)
# grpc-style: dependency helper modules in cmake/ subdirectory
# Captures the filename stem (without .cmake extension)
_INCLUDE_CMAKE_SUBDIR = re.compile(
    r"include\s*\(\s*cmake/([a-zA-Z][a-zA-Z0-9_+-]*?)\.cmake\s*\)",
    re.IGNORECASE,
)

# find_path(VA_INCLUDE_DIR NAMES va/va.h ...) / find_path(VA_INCLUDE_DIR va/va.h ...)
# Extracts library hint from header path (e.g. va/va.h → va)
_FIND_PATH = re.compile(
    r"find_path\s*\(\s*\w+"  # variable
    r"\s+(?:NAMES?\s+)?([a-zA-Z0-9_]+)/",  # header directory prefix
    re.IGNORECASE,
)

# target_link_libraries(target ... -lfoo -lbar)
_TLL_BLOCK = re.compile(
    r"target_link_libraries\s*\(([^)]+)\)",
    re.IGNORECASE,
)
_DASH_L_FLAG = re.compile(r"-l(\w+)")

# --- CMake module → library name mapping --------------------------------------

_CMAKE_MODULE_MAP: dict[str, str] = {
    "Threads": "pthread",
}

# CMake built-in / meta-modules that are not real dependencies
_SKIP_MODULES: set[str] = {
    "PkgConfig",
    "CMakeDependentOption",
    "CheckIncludeFile",
    "CheckIncludeFiles",
    "CheckFunctionExists",
    "CheckLibraryExists",
    "CheckSymbolExists",
    "CheckTypeSize",
    "CheckCSourceCompiles",
    "CheckCXXSourceCompiles",
    "CheckCCompilerFlag",
    "CheckCXXCompilerFlag",
    "CheckStructHasMember",
    "CheckPrototypeDefinition",
    "CheckIPOSupported",
    "CMakePackageConfigHelpers",
    "CMakePushCheckState",
    "CTest",
    "CPack",
    "FetchContent",
    "ExternalProject",
    "GNUInstallDirs",
    "GenerateExportHeader",
    "InstallRequiredSystemLibraries",
    "WriteBasicConfigVersionFile",
    "FeatureSummary",
    "ProcessorCount",
    "FindPackageHandleStandardArgs",
    "FindPackageMessage",
    "TestBigEndian",
    # include(FindXXX) utility modules (not real deps)
    "PackageHandleStandardArgs",
    "PackageMessage",
}

# include(cmake/xxx.cmake) stems that are NOT real dependencies
# (build infrastructure, options, compiler settings, etc.)
_SKIP_CMAKE_INCLUDES: set[str] = {
    "options", "config", "settings", "compiler", "flags", "toolchain",
    "install", "pkg-config", "version", "download", "build",
    "common", "utils", "helpers", "macros", "functions",
}

# Common find_package / find_library flags that should never be treated as deps
_CMAKE_FLAGS: set[str] = {
    "REQUIRED", "QUIET", "IMPORTED_TARGET", "CONFIG", "MODULE",
    "NO_MODULE", "NO_POLICY_SCOPE", "COMPONENTS", "OPTIONAL_COMPONENTS",
    "NAMES", "HINTS", "PATHS", "PATH_SUFFIXES", "DOC", "NO_DEFAULT_PATH",
    "NO_CMAKE_PATH", "NO_CMAKE_ENVIRONMENT_PATH", "NO_SYSTEM_ENVIRONMENT_PATH",
    "NO_CMAKE_SYSTEM_PATH", "NO_CMAKE_PACKAGE_REGISTRY",
    "NAMES_PER_DIR", "NO_CMAKE_FIND_ROOT_PATH",
}


def _strip_comments(content: str) -> str:
    """Remove single-line CMake comments."""
    return re.sub(r"#[^\n]*", "", content)


def parse(content: str) -> list[str]:
    """Extract dependency names from CMakeLists.txt content."""
    content = _strip_comments(content)
    deps: set[str] = set()

    # find_package
    for m in _FIND_PACKAGE.finditer(content):
        name = m.group(1)
        if name in _SKIP_MODULES:
            continue
        deps.add(_CMAKE_MODULE_MAP.get(name, name))

    # FetchContent_Declare
    for m in _FETCH_CONTENT.finditer(content):
        deps.add(m.group(1))

    # pkg_check_modules / pkg_search_module / ocv_check_modules
    for m in _PKG_CHECK_MODULES.finditer(content):
        deps.add(m.group(1))

    # set(XXX_PKG_CONFIG_SPEC name) — SDL-style variable-based pkg-config
    for m in _SET_PKG_CONFIG_SPEC.finditer(content):
        deps.add(m.group(1))

    # include(FindXXX) — CMake module-based dependency search
    for m in _INCLUDE_FIND.finditer(content):
        name = m.group(1)
        if name in _SKIP_MODULES:
            continue
        deps.add(_CMAKE_MODULE_MAP.get(name, name))

    # include(cmake/xxx.cmake) — grpc-style dependency helper modules
    for m in _INCLUDE_CMAKE_SUBDIR.finditer(content):
        name = m.group(1)
        if name.lower() in _SKIP_CMAKE_INCLUDES:
            continue
        # An "…_import" helper IMPORTS a dependency, it is not one itself
        # (Befund 52: cmake/pico_sdk_import.cmake became the component
        # "pico_sdk_import" — the real dep, pico_sdk, is found inside it).
        if name.lower().endswith(("_import", "-import")):
            continue
        deps.add(name)

    # find_path — header search (extracts directory prefix as library name)
    for m in _FIND_PATH.finditer(content):
        name = m.group(1)
        # Skip generic paths and cmake flags
        if name.lower() in ("include", "src", "lib", "usr", "opt", "sys"):
            continue
        if name.upper() in _CMAKE_FLAGS:
            continue
        deps.add(name)

    # find_library
    for m in _FIND_LIBRARY.finditer(content):
        name = m.group(1)
        if name.upper() in _CMAKE_FLAGS:
            continue
        deps.add(name)

    # check_library_exists
    for m in _CHECK_LIBRARY.finditer(content):
        deps.add(m.group(1))

    # ExternalProject_Add
    for m in _EXTERNAL_PROJECT.finditer(content):
        deps.add(m.group(1))

    # target_link_libraries -l flags
    for m in _TLL_BLOCK.finditer(content):
        block = m.group(1)
        for flag in _DASH_L_FLAG.finditer(block):
            deps.add(flag.group(1))

    return sorted(deps)
