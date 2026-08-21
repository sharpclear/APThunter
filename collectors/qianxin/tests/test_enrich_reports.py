from __future__ import annotations

from scripts.qianxin.enrich_reports import (
    language_for_sha,
    mineru_block_to_markdown,
    pages_requiring_ocr,
)


def test_language_routing_prefers_specialized_models():
    assert language_for_sha("234b2a87ffff") == "korean"
    assert language_for_sha("04975abbffff") == "east_slavic"
    assert language_for_sha("deadbeefffff") == "ch"


def test_mineru_text_and_heading_rendering():
    assert mineru_block_to_markdown({"type": "text", "text": "Title", "text_level": 1}) == "# Title"
    assert mineru_block_to_markdown({"type": "text", "text": "Body"}) == "Body"


def test_mineru_noise_is_omitted_and_footnotes_are_preserved():
    assert mineru_block_to_markdown({"type": "header", "text": "Repeated"}) == ""
    assert mineru_block_to_markdown({"type": "page_footnote", "text": "Evidence"}) == "> 页下注：Evidence"


def test_mineru_table_and_list_rendering():
    table = mineru_block_to_markdown(
        {
            "type": "table",
            "table_caption": ["Indicators"],
            "table_body": "<table><tr><td>ioc</td></tr></table>",
        }
    )
    assert "**表：Indicators**" in table
    assert "<table>" in table
    assert mineru_block_to_markdown({"type": "list", "list_items": ["one", "two"]}) == "- one\n- two"


def test_low_text_page_is_routed_even_when_document_is_overall_ready():
    record = {
        "source": {"path": "report.pdf", "pdf_page_count": 10},
        "metrics": {
            "status": "ready_for_small_model",
            "empty_or_low_text_pages": [7],
        },
    }
    assert pages_requiring_ocr(record) == [7]
