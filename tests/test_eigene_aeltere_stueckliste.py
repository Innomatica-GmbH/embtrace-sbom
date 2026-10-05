"""A bill written by an older release of this tool is still our bill.

``write_cyclonedx`` refuses to overwrite a FOREIGN file — that is somebody's
evidence. The classification reads the ``metadata.tools`` stamp, and the tool
has signed its output under three names over its life. A rename of the
PACKAGE must not drop a historical stamp from that set: the stamp sits inside
a file that already exists on a disk and cannot be renamed retroactively.

This has gone wrong twice (01.10.2026 and 02.10.2026), the second time
together with the comment that warned about the first. Measured on
05.10.2026 against the published 0.13.0: a bill stamped with the 0.11.1 name
classified as ``foreign``, so the tool aborted with exit 1 and told the user
their own file "was not written by jochwacht-sbom".  # alter-name-als-datum
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from jochwacht_sbom.core.exceptions import JochwachtError
from jochwacht_sbom.sbom_out import OWN_TOOL_NAMES, classify_existing

#: Name, and the releases that wrote it. Pinned so a replacement cannot
#: quietly collapse the set again.  # alter-name-als-datum
_STAMPS = {
    "jochwacht-sbom": "since 0.12.0",
    "embtrace-sbom": "0.9.0 - 0.11.1",   # alter-name-als-datum
    "embtrace-check": "up to 0.8.6",     # alter-name-als-datum
}


def _bill(tool: str) -> str:
    return json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"tools": [
            {"vendor": "Innomatica GmbH", "name": tool, "version": "0.11.1"},
        ]},
        "components": [],
    })


def test_the_set_holds_every_name_this_tool_ever_signed_with() -> None:
    assert frozenset(_STAMPS) == OWN_TOOL_NAMES, (
        "a stamp was dropped — a bill from an older release would be refused "
        "as foreign"
    )


@pytest.mark.parametrize("tool", sorted(_STAMPS))
def test_a_bill_from_any_of_our_releases_is_own(tool: str, tmp_path: Path) -> None:
    target = tmp_path / "sbom.cdx.json"
    target.write_text(_bill(tool), encoding="utf-8")
    assert classify_existing(target) == "own"


@pytest.mark.parametrize("tool", ["syft", "trivy", "cdxgen", "Jochwacht-SBOM"])
def test_somebody_elses_bill_stays_foreign(tool: str, tmp_path: Path) -> None:
    """Including a near-miss spelling: the stamp is compared exactly."""
    target = tmp_path / "sbom.cdx.json"
    target.write_text(_bill(tool), encoding="utf-8")
    assert classify_existing(target) == "foreign"


def test_an_older_own_bill_is_overwritten_not_refused(tmp_path: Path) -> None:
    """The real path, because that is where the user hit it."""
    from jochwacht_sbom.collector import CheckStats
    from jochwacht_sbom.sbom_out import write_cyclonedx

    target = tmp_path / "sbom.cdx.json"
    target.write_text(_bill("embtrace-sbom"), encoding="utf-8")  # alter-name-als-datum

    written = write_cyclonedx(
        target, [], CheckStats(), project_name="demo",
    )
    assert written == target
    doc = json.loads(target.read_text(encoding="utf-8"))
    # Written in the CycloneDX 1.5+ form; the bill we replaced used the
    # legacy list form, and the classifier reads both.
    assert doc["metadata"]["tools"]["components"][0]["name"] == "jochwacht-sbom"
    assert classify_existing(target) == "own"


def test_a_foreign_bill_is_still_refused(tmp_path: Path) -> None:
    """The protection itself must stay — this is somebody's evidence."""
    from jochwacht_sbom.collector import CheckStats
    from jochwacht_sbom.sbom_out import write_cyclonedx

    target = tmp_path / "sbom.cdx.json"
    target.write_text(_bill("syft"), encoding="utf-8")
    with pytest.raises(JochwachtError):
        write_cyclonedx(target, [], CheckStats(), project_name="demo")


def test_both_stamp_forms_are_read(tmp_path: Path) -> None:
    """Older bills carry ``metadata.tools`` as a LIST, newer as an object.

    A classifier that knows only one form calls half our own history foreign.
    """
    stamp = {"vendor": "Innomatica GmbH", "name": "embtrace-sbom",  # alter-name-als-datum
             "version": "0.11.1"}
    for tools in ({"components": [stamp]}, [stamp]):
        target = tmp_path / "sbom.cdx.json"
        target.write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"tools": tools}, "components": [],
        }), encoding="utf-8")
        assert classify_existing(target) == "own", tools
