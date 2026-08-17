from __future__ import annotations

from pathlib import Path

from scripts.lazarus_day.deduplicator import EventDeduplicator
from scripts.lazarus_day.matcher import OrganizationMatcher
from scripts.lazarus_day.models import Organization, ReportRecord
from scripts.lazarus_day.relationships import (
    load_actor_relationships,
    resolve_report_relationships,
)


def _report(*actors: str) -> ReportRecord:
    url = "https://lazarus.day/reports/multi-actor-test-AbC12/"
    return ReportRecord(
        source_record_id="multi-actor-test-AbC12",
        lazarus_day_url=url,
        requested_url=url,
        title="Multiple actors deploy malicious backdoors",
        published_date="2026-08-01",
        date_precision="day",
        publisher="Example Research",
        original_url="https://research.example/multi-actor-test",
        summary="The actors used malicious backdoors in an attack campaign.",
        tags=("Backdoor",),
        related_actors=actors,
        http_status=200,
        final_url=url,
        content_sha256="a" * 64,
        fetched_at="2026-08-03T00:00:00+00:00",
        raw_html="<html></html>",
    )


def test_relationship_resolution_splits_mapped_organizations(
    tmp_path: Path,
) -> None:
    matcher = OrganizationMatcher(
        [
            Organization(id=53, name="Kimsuky", aliases=()),
            Organization(id=55, name="Lazarus Group", aliases=()),
        ]
    )
    path = tmp_path / "relationships.csv"
    path.write_text(
        "source_name,decision,organization_id,organization_name,"
        "relationship_type,related_organization_ids,confidence,reason\n"
        "Contagious Interview,map,55,Lazarus Group,campaign,,high,test\n"
        "Earth Imp,map,53,Kimsuky,related_subgroup,,high,test\n"
        "JINX-0164,exclude,,,,,none,test\n",
        encoding="utf-8",
        newline="\n",
    )
    relationships, _encoding = load_actor_relationships(path, matcher)
    resolution = resolve_report_relationships(
        _report("Contagious Interview", "Earth Imp"),
        matcher,
        relationships,
    )
    assert tuple(
        match.organization.id for match in resolution.matches if match.organization
    ) == (53, 55)
    assert resolution.excluded_names == ()
    assert resolution.unresolved_names == ()


def test_excluded_actor_blocks_indirect_mapping_from_coactor(
    tmp_path: Path,
) -> None:
    matcher = OrganizationMatcher(
        [Organization(id=52, name="APT38", aliases=("Sapphire Sleet",))]
    )
    path = tmp_path / "relationships.csv"
    path.write_text(
        "source_name,decision,organization_id,organization_name,"
        "relationship_type,related_organization_ids,confidence,reason\n"
        "JINX-0164,exclude,,,,,none,test\n",
        encoding="utf-8",
        newline="\n",
    )
    relationships, _encoding = load_actor_relationships(path, matcher)
    resolution = resolve_report_relationships(
        _report("JINX-0164", "Sapphire Sleet"), matcher, relationships
    )
    assert resolution.matches == ()
    assert resolution.excluded_names == ("JINX-0164",)


def test_cross_organization_dedup_allows_split_source_once_per_org() -> None:
    deduplicator = EventDeduplicator(allow_cross_organization_links=True)
    base = {
        "event_date": "2026-08-01",
        "title": "组织相关恶意软件活动",
        "link": "https://research.example/shared-report",
    }
    first = dict(base, organization_id=53)
    second = dict(base, organization_id=55)
    repeated = dict(base, organization_id=55)
    detail = "https://lazarus.day/reports/shared-report-AbC12/"
    assert deduplicator.check_and_register(
        first, lazarus_day_url=detail
    ).status == "unique"
    assert deduplicator.check_and_register(
        second, lazarus_day_url=detail
    ).status == "unique"
    assert deduplicator.check_and_register(
        repeated, lazarus_day_url=detail
    ).status == "exact_duplicate"
