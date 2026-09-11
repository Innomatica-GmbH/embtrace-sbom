"""Structured logging with Rich console output.

Usage::

    from embtrace_sbom.core.log import console, get_logger

    logger = get_logger(__name__)
    logger.info("Processing artifact %s", name)
    console.print("[green]Done.[/green]")
"""

from __future__ import annotations

import logging
import sys

from rich.console import Console
from rich.logging import RichHandler

# Shared console instances — use `console` for normal output,
# `error_console` for errors/warnings.
console = Console(stderr=False)
error_console = Console(stderr=True)

_LOG_FORMAT = "%(message)s"
_configured = False


def setup_logging(*, verbosity: int = 0, json_mode: bool = False) -> None:
    """Configure the root embtrace logger.

    Args:
        verbosity: 0 = WARNING, 1 = INFO, 2+ = DEBUG.
        json_mode: If True, suppress Rich markup and use plain text
                   suitable for machine parsing.
    """
    global _configured  # noqa: PLW0603

    level = logging.WARNING
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity >= 1:
        level = logging.INFO

    handler: logging.Handler
    if json_mode:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s: %(name)s: %(message)s"))
    else:
        handler = RichHandler(
            console=error_console,
            show_time=False,
            show_path=False,
            markup=True,
        )

    root = logging.getLogger("embtrace")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the ``embtrace`` namespace.

    Args:
        name: Typically ``__name__`` of the calling module.
    """
    if not _configured:
        setup_logging()
    return logging.getLogger(name)
