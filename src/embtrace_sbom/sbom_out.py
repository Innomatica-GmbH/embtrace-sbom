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


def write_cyclonedx(
    path: Path,
    components: list[CheckComponent],
    stats: CheckStats,
    *,
    project_name: str,
) -> Path:
    """Write the SBOM to *path*, never silently overwriting.

    An existing file is kept: the new document goes to ``<stem>-<n><suffix>``
    (order collector-transparent-machen: "eine vorhandene Datei nie stumm
    überschreiben" — a customer's earlier bill is evidence, not scratch).

    Returns the path actually written.
    """
    target = path
    if target.exists():
        n = 2
        while True:
            candidate = target.with_name(f"{path.stem}-{n}{path.suffix}")
            if not candidate.exists():
                target = candidate
                break
            n += 1
    doc = build_cyclonedx(components, stats, project_name=project_name)
    target.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
    )
    return target
