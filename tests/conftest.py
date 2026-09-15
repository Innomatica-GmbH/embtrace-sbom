"""Shared fixtures — every test starts with an empty diagnosis record."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from embtrace_sbom import diagnosis


@pytest.fixture(autouse=True)
def _fresh_diagnosis() -> Iterator[None]:
    diagnosis.reset()
    yield
    diagnosis.reset()
