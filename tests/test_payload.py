"""Tests for the check payload models (schema v1)."""

from __future__ import annotations

import json

from embtrace_check.payload import (
    MAX_PAYLOAD_BYTES,
    CheckComponent,
    CheckStats,
    anonymize_label,
    build_payload,
)


def _components() -> list[CheckComponent]:
    return [
        CheckComponent(name="zlib", version="1.3", ecosystem="conan"),
        CheckComponent(name="OpenSSL", version="3.0.13", ecosystem="conan"),
    ]


def test_build_payload_sorts_components_and_stamps_utc() -> None:
    payload = build_payload(
        voucher="TEST-1",
        contact_email="a@b.c",
        tool_version="0.0.1",
        project_label="demo",
        components=_components(),
        stats=CheckStats(build_files_scanned=2, ecosystems=["conan"]),
    )
    assert payload.schema_version == 1
    assert [c.name for c in payload.components] == ["OpenSSL", "zlib"]  # case-insensitive sort
    assert payload.collected_at.endswith("+00:00")
    assert payload.project_label == "demo"


def test_build_payload_anonymize_replaces_label_stably() -> None:
    kwargs = {
        "voucher": "TEST-1",
        "contact_email": "a@b.c",
        "tool_version": "0.0.1",
        "components": _components(),
        "stats": CheckStats(),
    }
    p1 = build_payload(project_label="secret-project", anonymize=True, **kwargs)
    p2 = build_payload(project_label="secret-project", anonymize=True, **kwargs)
    assert p1.project_label == p2.project_label
    assert p1.project_label.startswith("anon-")
    assert "secret" not in p1.project_label


def test_anonymize_label_is_short_hash() -> None:
    label = anonymize_label("x")
    assert label.startswith("anon-")
    assert len(label) == len("anon-") + 12


def test_payload_json_contains_no_paths() -> None:
    """The serialised payload must never contain filesystem paths."""
    payload = build_payload(
        voucher="TEST-1",
        contact_email="a@b.c",
        tool_version="0.0.1",
        project_label="demo",
        components=_components(),
        stats=CheckStats(build_files_scanned=1, ecosystems=["conan"]),
    )
    raw = payload.model_dump_json()
    parsed = json.loads(raw)
    # Explicit allowlist — extending it is a product decision.
    # supplier/license/purl/cpe: filled only for source_type "declared"
    # (the customer's own embtrace-deps.yaml), v0.5.0.
    assert set(parsed["components"][0].keys()) == {
        "name",
        "version",
        "ecosystem",
        "source_type",
        "tier",
        "confidence",
        "supplier",
        "license",
        "purl",
        "cpe",
        "scope",
        "condition",
    }
    assert "/" not in json.dumps([c["source_type"] for c in parsed["components"]])
    assert len(raw.encode()) < MAX_PAYLOAD_BYTES
