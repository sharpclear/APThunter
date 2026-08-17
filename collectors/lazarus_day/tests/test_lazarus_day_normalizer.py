from __future__ import annotations

from pathlib import Path

from scripts.lazarus_day.matcher import OrganizationMatcher, load_organizations
from scripts.lazarus_day.models import (
    FORBIDDEN_EVENT_FIELDS,
    REQUIRED_EVENT_FIELDS,
    OriginalSource,
    ReportSeed,
)
from scripts.lazarus_day.normalizer import (
    canonicalize_url,
    make_event_key,
    normalize_report,
)
from scripts.lazarus_day.parser import parse_report_detail


ROOT = Path(__file__).parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "lazarus_day"
FETCHED_AT = "2026-07-29T08:00:00+00:00"


def _report(name: str, published_date: str = "2026-07-23"):
    url = "https://lazarus.day/reports/fixture-AbC12/"
    return parse_report_detail(
        (FIXTURES / name).read_text(encoding="utf-8"),
        seed=ReportSeed(
            detail_url=url,
            title="fixture",
            published_date=published_date,
            date_precision=("month" if len(published_date) == 7 else "day"),
        ),
        requested_url=url,
        final_url=url,
        http_status=200,
        content_sha256="a" * 64,
        fetched_at=FETCHED_AT,
    )


def _matcher() -> OrganizationMatcher:
    organizations, _encoding = load_organizations(
        ROOT / "data" / "reference" / "apt_organizations.csv"
    )
    return OrganizationMatcher(organizations)


def _original() -> OriginalSource:
    return OriginalSource(
        requested_url="https://asec.example/research/kimsuky-fixture",
        final_url="https://asec.example/research/kimsuky-fixture",
        http_status=200,
        content_sha256="b" * 64,
        fetched_at=FETCHED_AT,
        title="Kimsuky钓鱼攻击研究",
        published_date="2026-07-23",
        summary="研究记录了一起Kimsuky实施的钓鱼攻击。",
        source_level="B",
    )


def test_url_normalization_and_stable_event_key() -> None:
    url = canonicalize_url(
        "HTTPS://Example.COM:443/report/?utm_source=x&b=2&a=1#part"
    )
    assert url == "https://example.com/report?a=1&b=2"
    assert make_event_key(url, 53, "2026-07-23", "  Test Title ") == (
        make_event_key(url, 53, "2026-07-23", "test-title")
    )


def test_normal_report_matches_real_org_and_emits_strict_event() -> None:
    report = _report("detail_event.html")
    match = _matcher().match(
        related_actors=report.related_actors,
        tags=report.tags,
        title=report.title,
    )
    result = normalize_report(report, match, _original())
    assert result.event is not None
    assert result.event["organization_id"] == 53
    assert result.event["organization_name"] == "Kimsuky"
    assert result.event["db_id"] is None
    assert result.event["review_status"] == "accepted"
    assert set(result.event) == set(REQUIRED_EVENT_FIELDS)
    assert not set(result.event).intersection(FORBIDDEN_EVENT_FIELDS)


def test_non_event_report_is_rejected() -> None:
    report = _report("detail_non_event.html", "2026-07-22")
    match = _matcher().match(
        related_actors=report.related_actors,
        tags=report.tags,
        title=report.title,
    )
    result = normalize_report(report, match, _original())
    assert result.event is None
    assert "命名" in (result.rejected_reason or "")


def test_month_date_is_not_fabricated_and_requires_review() -> None:
    report = _report("detail_month_date.html", "2026-07")
    match = _matcher().match(
        related_actors=report.related_actors,
        tags=report.tags,
        title=report.title,
    )
    result = normalize_report(report, match, _original())
    assert result.event is not None
    assert result.event["event_date"] == "2026-07"
    assert result.event["date_precision"] == "month"
    assert result.event["review_status"] == "needs_review"


def test_multi_actor_report_is_review_not_auto_split() -> None:
    report = _report("detail_multi_actor.html")
    match = _matcher().match(
        related_actors=report.related_actors,
        tags=report.tags,
        title=report.title,
    )
    result = normalize_report(report, match, _original())
    assert result.event is not None
    assert result.event["organization_id"] is None
    assert result.event["review_status"] == "needs_review"


def test_unknown_related_actor_is_isolated_for_review() -> None:
    report = _report("detail_unknown_actor.html")
    match = _matcher().match(
        related_actors=report.related_actors,
        tags=report.tags,
        title=report.title,
    )
    result = normalize_report(report, match, _original())
    assert match.status == "unmatched"
    assert result.event is not None
    assert result.event["organization_id"] is None
    assert result.event["review_status"] == "needs_review"
    assert result.unmatched is True


def test_missing_actor_event_is_preserved_for_review_without_tag_as_actor() -> None:
    report = _report("detail_missing_actor.html")
    match = _matcher().match(
        related_actors=report.related_actors,
        tags=report.tags,
        title="Generic malicious backdoor activity",
    )
    result = normalize_report(report, match, _original())
    assert match.status == "unmatched"
    assert match.raw_names == ()
    assert result.event is not None
    assert result.event["organization_id"] is None
    assert result.event["organization_name"] == "未匹配组织"
    assert result.event["review_status"] == "needs_review"
