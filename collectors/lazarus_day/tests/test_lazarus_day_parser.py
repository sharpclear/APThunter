from __future__ import annotations

from pathlib import Path

import pytest

from scripts.lazarus_day.models import ParseError, ReportSeed
from scripts.lazarus_day.parser import (
    parse_original_source,
    parse_report_detail,
    parse_report_list,
    parse_rss,
)


FIXTURES = Path(__file__).parent / "fixtures" / "lazarus_day"
FETCHED_AT = "2026-07-29T08:00:00+00:00"


def _text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _seed() -> ReportSeed:
    return ReportSeed(
        detail_url=(
            "https://lazarus.day/reports/"
            "kimsuky-phishing-fixture-AbC12/"
        ),
        title="Kimsuky phishing activity fixture",
        published_date="2026-07-23",
        publisher="AhnLab",
    )


def _parse_detail(name: str, seed: ReportSeed | None = None):
    return parse_report_detail(
        _text(name),
        seed=seed or _seed(),
        requested_url=(seed or _seed()).detail_url,
        final_url=(seed or _seed()).detail_url,
        http_status=200,
        content_sha256="a" * 64,
        fetched_at=FETCHED_AT,
    )


def test_parse_rss_extracts_source_tags_and_publisher() -> None:
    seeds = parse_rss(_text("feed.xml"))
    assert len(seeds) == 2
    assert seeds[0].publisher == "AhnLab"
    assert seeds[0].published_date == "2026-07-23"
    assert seeds[0].original_url == (
        "https://asec.example/research/kimsuky-fixture"
    )
    assert seeds[0].tags == ("Kimsuky", "Phishing", "LNK")


def test_parse_reports_list_pagination_cards() -> None:
    seeds = parse_report_list(
        _text("reports.html"), "https://lazarus.day/reports/?page=1"
    )
    assert [seed.published_date for seed in seeds] == [
        "2026-07-23",
        "2026-07-22",
    ]
    assert seeds[0].detail_url.endswith("kimsuky-phishing-fixture-AbC12/")
    assert seeds[0].tags == ("Kimsuky", "Phishing")


def test_parse_detail_semantic_fields_and_related_actor() -> None:
    report = _parse_detail("detail_event.html")
    assert report.title == "Kimsuky针对外交相关人员开展钓鱼攻击"
    assert report.publisher == "AhnLab"
    assert report.original_url == (
        "https://asec.example/research/kimsuky-fixture"
    )
    assert report.tags == ("Kimsuky", "Phishing", "LNK")
    assert report.related_actors == ("Kimsuky",)
    assert report.date_precision == "day"
    assert not report.parse_warnings


def test_detail_missing_source_and_actor_are_explicit_warnings() -> None:
    missing_source = _parse_detail("detail_missing_source.html")
    assert missing_source.original_url is None
    assert "详情页未提供原始来源 URL" in missing_source.parse_warnings

    missing_actor = _parse_detail("detail_missing_actor.html")
    assert missing_actor.related_actors == ()
    assert "详情页未提供 Related Actors" in missing_actor.parse_warnings


def test_detail_supports_multi_actor_and_month_only_date() -> None:
    multi = _parse_detail("detail_multi_actor.html")
    assert multi.related_actors == ("Kimsuky", "Bluenoroff")

    month_seed = ReportSeed(
        detail_url="https://lazarus.day/reports/month-fixture-AbC12/",
        title="month fixture",
        published_date="2026-07",
        date_precision="month",
    )
    month = _parse_detail("detail_month_date.html", month_seed)
    assert month.published_date == "2026-07"
    assert month.date_precision == "month"


def test_parse_original_metadata() -> None:
    source = parse_original_source(
        _text("original.html"),
        requested_url="https://asec.example/research/kimsuky-fixture",
        final_url="https://asec.example/research/kimsuky-fixture",
        http_status=200,
        content_sha256="b" * 64,
        fetched_at=FETCHED_AT,
        source_level="B",
    )
    assert source.title == "Kimsuky钓鱼攻击研究"
    assert source.published_date == "2026-07-23"
    assert "恶意快捷方式" in source.summary


def test_structure_change_raises_clear_parse_error() -> None:
    seed = _seed()
    with pytest.raises(ParseError, match="缺少标题"):
        parse_report_detail(
            "<html><main><section><p>no semantic fields</p></section></main></html>",
            seed=ReportSeed(
                detail_url=seed.detail_url,
                title="",
                published_date="",
            ),
            requested_url=seed.detail_url,
            final_url=seed.detail_url,
            http_status=200,
            content_sha256="c" * 64,
            fetched_at=FETCHED_AT,
        )
