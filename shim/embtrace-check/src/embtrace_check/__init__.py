"""embtrace-check has moved to embtrace-sbom — this package forwards to it.

``import embtrace_check.<module>`` resolves to the very same module object as
``embtrace_sbom.<module>`` (a meta-path finder aliases the namespace), so
existing scripts and the embtrace suite's collector check keep working.
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import sys
from types import ModuleType

import embtrace_sbom

__version__ = embtrace_sbom.__version__

_PREFIX = __name__ + "."


class _AliasFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """``embtrace_check.X`` → the already-imported ``embtrace_sbom.X``."""

    def find_spec(
        self, fullname: str, path: object = None, target: object = None,
    ) -> importlib.machinery.ModuleSpec | None:
        if not fullname.startswith(_PREFIX):
            return None
        real = "embtrace_sbom." + fullname[len(_PREFIX):]
        try:
            module = importlib.import_module(real)
        except ModuleNotFoundError:
            return None
        spec = importlib.machinery.ModuleSpec(
            fullname, self, is_package=hasattr(module, "__path__"),
        )
        spec.loader_state = module
        return spec

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType:
        module: ModuleType = spec.loader_state
        return module

    def exec_module(self, module: ModuleType) -> None:
        return None


if not any(isinstance(f, _AliasFinder) for f in sys.meta_path):
    sys.meta_path.insert(0, _AliasFinder())


def __getattr__(name: str) -> object:
    """Attribute access (``embtrace_check.sbom``) resolves the same way."""
    return importlib.import_module(_PREFIX + name)


def main() -> None:
    from embtrace_sbom.cli import main_check_alias

    main_check_alias()
