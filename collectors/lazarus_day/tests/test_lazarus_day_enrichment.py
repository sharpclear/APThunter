from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest

from scripts.lazarus_day.enrichment import (
    EnrichmentError,
    LazarusEnrichmentClient,
    build_source_content,
    validate_enrichment_response,
)
from scripts.lazarus_day.models import ReportSeed
from scripts.lazarus_day.parser import parse_report_detail


FIXTURES = Path(__file__).parent / "fixtures" / "lazarus_day"
URL = "https://lazarus.day/reports/fixture-AbC12/"


def _report():
    html = (FIXTURES / "detail_event.html").read_text(encoding="utf-8")
    return parse_report_detail(
        html,
        seed=ReportSeed(
            detail_url=URL,
            title="Kimsuky phishing fixture",
            published_date="2026-07-23",
        ),
        requested_url=URL,
        final_url=URL,
        http_status=200,
        content_sha256=hashlib.sha256(html.encode("utf-8")).hexdigest(),
        fetched_at="2026-07-29T08:00:00+00:00",
    )


def _response(report, source: str) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "prompt_version": "lazarus-event-enrichment-v1",
        "source_event_id": report.source_record_id,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "model": "Qwen3-4B-Q4_K_M",
        "runtime": "llama.cpp",
        "title_zh": "Kimsuky针对研究机构开展钓鱼活动",
        "description_zh": "公开报告披露，Kimsuky针对研究机构开展钓鱼活动。",
        "threat_type": "钓鱼攻击",
        "threat_type_evidence_quote": "Phishing",
        "actor_mentions": [
            {
                "name": "Kimsuky",
                "evidence_quote": "Related Actors: Kimsuky",
            }
        ],
        "factual_points": [
            {
                "text_zh": "该活动使用鱼叉式钓鱼手法",
                "evidence_quote": "Phishing",
            }
        ],
        "confidence": 0.9,
    }


def test_enrichment_response_is_revalidated_against_local_source() -> None:
    report = _report()
    source = build_source_content(report, None)
    result = validate_enrichment_response(
        _response(report, source),
        source_event_id=report.source_record_id,
        source_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
        source_content=source,
    )
    assert result.actor_names == ("Kimsuky",)

    invalid = _response(report, source)
    invalid["factual_points"] = [
        {"text_zh": "使用零日漏洞", "evidence_quote": "CVE-2099-0001"}
    ]
    with pytest.raises(EnrichmentError, match="not grounded"):
        validate_enrichment_response(
            invalid,
            source_event_id=report.source_record_id,
            source_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
            source_content=source,
        )


def test_enrichment_client_caches_validated_response(tmp_path: Path) -> None:
    report = _report()
    source = build_source_content(report, None)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.headers["X-API-Key"] == "test-only-key"
        payload = json.loads(request.content)
        assert payload["source_sha256"] == hashlib.sha256(
            source.encode("utf-8")
        ).hexdigest()
        return httpx.Response(200, json=_response(report, source))

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = LazarusEnrichmentClient(
        base_url="http://model.example:8787",
        api_key="test-only-key",
        cache_root=tmp_path / "cache",
        http_client=http_client,
    )
    first = client.enrich(report, None)
    second = client.enrich(report, None)
    assert first.cached is False
    assert second.cached is True
    assert calls == 1
    http_client.close()


def test_invalid_model_output_is_not_retried() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            502,
            json={"detail": {"code": "invalid_model_output"}},
        )

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = LazarusEnrichmentClient(
        base_url="http://model.example:8787",
        api_key="test-only-key",
        http_client=http_client,
        sleeper=lambda _seconds: None,
    )
    with pytest.raises(EnrichmentError, match="ungrounded"):
        client.enrich(_report(), None)
    assert calls == 1
    http_client.close()
