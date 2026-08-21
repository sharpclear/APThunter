from __future__ import annotations

from scripts.qianxin.parse_reports import (
    build_quality_metrics,
    combined_markdown,
    suspicious_character_count,
)


def test_quality_metrics_accept_well_formed_text_pages():
    pages = [
        "# Report\n\n" + "This is useful threat intelligence. " * 20,
        "## Findings\n\n" + "APT activity and evidence. " * 20,
        "## Indicators\n\n" + "example.test and CVE-2026-1234. " * 20,
    ]
    result = build_quality_metrics(pages, table_count=1, image_count=2)
    assert result["status"] == "ready_for_small_model"
    assert result["textual_page_ratio"] == 1.0
    assert result["markdown_heading_count"] == 3


def test_quality_metrics_routes_image_only_document_to_ocr():
    result = build_quality_metrics(["", "logo", ""], table_count=0, image_count=12)
    assert result["status"] == "needs_ocr"
    assert result["empty_or_low_text_pages"] == [1, 2, 3]


def test_quality_metrics_detects_repeated_headers_and_garble():
    pages = [
        f"APT CONFIDENTIAL\n# Page {number}\n" + "body " * 40 + "\ufffd" * 20
        for number in range(1, 5)
    ]
    result = build_quality_metrics(pages, table_count=0, image_count=0)
    assert result["status"] == "needs_review"
    assert result["repeated_lines"][0]["page_count"] == 4
    assert suspicious_character_count("abc\ufffd(cid:12)\ue001") == 3


def test_combined_markdown_preserves_source_and_page_boundaries():
    rendered = combined_markdown(
        "data/reports/example.pdf",
        [
            {"page_number": 1, "markdown": "# One\n"},
            {"page_number": 2, "markdown": "# Two\n"},
        ],
    )
    assert rendered.startswith("<!-- source: data/reports/example.pdf -->")
    assert "<!-- page: 1 -->\n\n# One" in rendered
    assert "<!-- page: 2 -->\n\n# Two" in rendered
