"""CycloneDX 1.6 output — the customer's own result, written locally.

Order collector-transparent-machen (Ivan, 09.09.2026): the default run
GENERATES, SHOWS and SAVES; it uploads nothing. What it saves must be a real
SBOM the customer can use with any other tool — not our upload payload. So
this writer emits CycloneDX 1.6 JSON from the same components the check
collected, with the honest markings the suite uses:

- ``scope`` travels ("excluded" = test material / build tooling — listed,
  never gating),
- a conditional alternative behind an off-by-default build option is
  ``scope: optional`` with its guard as a property (Befund 44: marked, never
  silently counted as present),
- ``metadata.lifecycles`` states whether this was read from a configured
  build or from declarations only (Befund 41).

No network, no upload, no telemetry: this function only formats what is
already on the customer's disk.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from embtrace_sbom import __version__
from embtrace_sbom.core.exceptions import EmbtraceError

if TYPE_CHECKING:
    from pathlib import Path

    from embtrace_sbom.payload import CheckComponent, CheckStats

#: CycloneDX spec version we emit.
SPEC_VERSION = "1.6"


def _component(comp: CheckComponent) -> dict[str, object]:
    """One CycloneDX component entry from a collected component."""
    out: dict[str, object] = {"type": "library", "name": comp.name}
    if comp.version:
        out["version"] = comp.version
    if comp.purl:
        out["purl"] = comp.purl
    if comp.cpe:
        out["cpe"] = comp.cpe
    if comp.supplier:
        out["supplier"] = {"name": comp.supplier}
    if comp.license:
        out["licenses"] = [{"license": {"id": comp.license}}]
    # A conditional alternative is OPTIONAL, never required: no default build
    # contains it, and mutually exclusive ones never both ship (Befund 44).
    if comp.condition:
        out["scope"] = "optional"
    elif comp.scope in ("required", "optional", "excluded"):
        out["scope"] = comp.scope

    props: list[dict[str, str]] = []
    if comp.condition:
        props.append({"name": "embtrace:condition", "value": comp.condition})
    if comp.ecosystem:
        props.append({"name": "embtrace:ecosystem", "value": comp.ecosystem})
    if comp.source_type:
        props.append({"name": "embtrace:detected-by", "value": comp.source_type})
    if props:
        out["properties"] = props
    return out


def build_cyclonedx(
    components: list[CheckComponent],
    stats: CheckStats,
    *,
    project_name: str,
) -> dict[str, object]:
    """Build the CycloneDX 1.6 document for *components*."""
    lifecycle = stats.lifecycle or "design"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(tz=UTC).isoformat(timespec="seconds"),
            # What this bill was read FROM: "build" = a configured build /
            # resolved output, "design" = declarations only (Befund 41).
            "lifecycles": [{"phase": lifecycle}],
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "embtrace-sbom",
                    "version": __version__,
                    "publisher": "Innomatica GmbH",
                }],
            },
            "component": {
                "type": "application",
                "name": project_name,
                "version": "unspecified",
            },
        },
        "components": [_component(c) for c in components],
    }


#: Names this tool has signed its own output with (metadata.tools).
OWN_TOOL_NAMES = frozenset({"embtrace-sbom", "embtrace-check"})


def classify_existing(path: Path) -> str:
    """What is at *path*: ``"none"``, ``"own"`` (written by this tool — the
    ``metadata.tools`` stamp says so) or ``"foreign"`` (anything else)."""
    if not path.exists():
        return "none"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        tools = doc.get("metadata", {}).get("tools")
    except (OSError, ValueError, AttributeError):
        return "foreign"
    entries: list[object] = []
    if isinstance(tools, dict):                     # CycloneDX 1.5+ form
        entries = list(tools.get("components") or [])
    elif isinstance(tools, list):                   # legacy form
        entries = tools
    names = {str(e.get("name", "")) for e in entries if isinstance(e, dict)}
    return "own" if names & OWN_TOOL_NAMES else "foreign"


def write_cyclonedx(
    path: Path,
    components: list[CheckComponent],
    stats: CheckStats,
    *,
    project_name: str,
) -> Path:
    """Write the SBOM to *path*.

    This tool's own earlier output at *path* is UPDATED (the stamp in
    ``metadata.tools`` identifies it) — a second run refreshes the bill
    instead of leaving ``sbom.cdx-2.json`` behind (Ivan, 11.09.2026: a
    wandering file name is a graveyard and breaks CI). A file that was not
    written by this tool is never touched: that is someone's evidence, and
    the caller must choose another name (``--sbom``).

    Returns the path written.
    """
    kind = classify_existing(path)
    if kind == "foreign":
        raise EmbtraceError(
            f"{path} exists and was not written by embtrace-sbom — it is left "
            f"untouched. Write the bill elsewhere with --sbom PATH.",
            exit_code=1,
        )
    doc = build_cyclonedx(components, stats, project_name=project_name)
    path.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
    )
    return path
