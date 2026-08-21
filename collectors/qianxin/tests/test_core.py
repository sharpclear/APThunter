from __future__ import annotations

import hashlib
import json
from datetime import date

import pytest

from scripts.qianxin.core import (
    CheckpointStore,
    EventRecord,
    MetadataStore,
    Organization,
    event_duplicate_decision,
    match_platform_actor,
    new_metadata_record,
    normalize_url,
    parse_cli_date,
    parse_report_date,
    safe_url_for_storage,
    sanitize_filename,
    split_aliases,
    validate_pdf,
)


def make_minimal_pdf() -> bytes:
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] /Contents 4 0 R >>",
        b"<< /Length 0 >>\nstream\n\nendstream",
    ]
    data = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, body in enumerate(objects, 1):
        offsets.append(len(data))
        data.extend(f"{number} 0 obj\n".encode())
        data.extend(body)
        data.extend(b"\nendobj\n")
    xref = len(data)
    data.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    data.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        data.extend(f"{offset:010d} 00000 n \n".encode())
    data.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n"
        ).encode()
    )
    return bytes(data)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-04-01", date(2026, 4, 1)),
        ("2026/4/7", date(2026, 4, 7)),
        ("2026年4月7日", date(2026, 4, 7)),
        ("2026-07-01T06:37:51Z", date(2026, 7, 1)),
        ("2026-04", None),
        ("2026", None),
        ("", None),
        ("2026-02-30", None),
    ],
)
def test_parse_report_date_requires_complete_explicit_date(raw, expected):
    assert parse_report_date(raw) == expected


def test_parse_cli_today_uses_supplied_today():
    assert parse_cli_date("today", today=date(2026, 8, 3)) == date(2026, 8, 3)


def test_aliases_and_strict_actor_matching_priority():
    organizations = [
        Organization("1", "魔罗桫", split_aliases("Confucius | G0142")),
        Organization("2", "Other", split_aliases("Unrelated")),
        Organization("40", "APT28", split_aliases("Fancy Bear | APT-28")),
    ]
    assert match_platform_actor("APT28", organizations) == (organizations[2], "exact_name")
    assert match_platform_actor("Confucius", organizations) == (organizations[0], "exact_alias")
    assert match_platform_actor("apt_28", organizations) == (
        organizations[2],
        "normalized_name_or_alias",
    )
    assert match_platform_actor("APT29-ish", organizations) == (None, "no_exact_match")


def test_ambiguous_normalized_actor_match_is_rejected():
    organizations = [
        Organization("1", "APT-28", ()),
        Organization("2", "APT_28", ()),
    ]
    assert match_platform_actor("apt 28", organizations) == (
        None,
        "ambiguous_normalized_name_or_alias",
    )


def test_signed_and_tracking_query_values_are_removed_from_stored_url():
    raw = (
        "HTTPS://Example.COM:443/a//report.pdf/?X-Amz-Signature=secret&"
        "X-Amz-Date=20260803T010000Z&utm_source=test&name=42"
    )
    assert safe_url_for_storage(raw) == "https://example.com/a/report.pdf?name=42"


def test_normalized_event_url_and_exact_triple_are_definite_duplicates():
    events = [
        EventRecord("40", "2026-07-01", "A Report", "https://EXAMPLE.com/r/?b=2&a=1"),
    ]
    by_url = event_duplicate_decision(
        "99", "2020-01-01", "Other", ["https://example.com/r?a=1&b=2#fragment"], events
    )
    assert by_url and by_url.status == "duplicate_event"
    assert by_url.reason == "same_normalized_source_url"
    by_triple = event_duplicate_decision("40", "2026-07-01", "  A   Report ", [], events)
    assert by_triple and by_triple.reason == "same_organization_date_title"


def test_related_title_on_same_org_and_date_requires_manual_review():
    events = [
        EventRecord("40", "2026-07-01", "APT28 campaign analysis report", ""),
    ]
    decision = event_duplicate_decision(
        "40", "2026-07-01", "APT28 campaign analysis", [], events
    )
    assert decision and decision.status == "manual_required"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('bad<>:"/\\|?*name. ', "bad_________name"),
        ("CON", "_CON"),
        ("   ", "untitled"),
    ],
)
def test_windows_safe_filename(raw, expected):
    assert sanitize_filename(raw) == expected


def test_pdf_validation_checks_header_parser_size_and_sha():
    pytest.importorskip("pypdf")
    data = make_minimal_pdf()
    result = validate_pdf(data)
    assert result.file_size == len(data)
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    assert result.page_count == 1
    with pytest.raises(ValueError, match="HTML"):
        validate_pdf(b"<html>login</html>")


def test_metadata_and_checkpoint_roundtrip(tmp_path):
    jsonl = tmp_path / "reports.jsonl"
    csv_path = tmp_path / "reports.csv"
    metadata = MetadataStore(jsonl, csv_path)
    record = new_metadata_record(
        organization_id="40",
        organization_name="APT28",
        report_title="Report",
        report_date="2026-07-01",
        preview_url="https://example.com/detail#x",
        pdf_url="https://example.com/report.pdf?X-Amz-Signature=secret",
        sha256="a" * 64,
        file_size=100,
        download_status="downloaded",
    )
    metadata.append(record)
    assert metadata.preflight_duplicate("40", "Report", "2026-07-01") is not None
    assert json.loads(jsonl.read_text(encoding="utf-8").splitlines()[0])["download_status"] == "downloaded"
    assert csv_path.read_text(encoding="utf-8-sig").startswith("organization_id,")

    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint = CheckpointStore(checkpoint_path)
    checkpoint.mark_report(record.preview_url, record.pdf_url, record.sha256)
    checkpoint.mark_organization("40")
    reloaded = CheckpointStore(checkpoint_path)
    assert "40" in reloaded.completed_organizations
    assert reloaded.is_processed_url(pdf_url="https://example.com/report.pdf")
    assert "a" * 64 in reloaded.sha256s


def test_url_normalization_keeps_meaningful_query_and_drops_fragment():
    assert normalize_url("https://Example.com/a/?z=2&a=1#frag") == (
        "https://example.com/a?a=1&z=2"
    )
