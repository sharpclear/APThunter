from __future__ import annotations

from pathlib import Path

from scripts.lazarus_day.matcher import (
    OrganizationMatcher,
    load_organizations,
    split_aliases,
)
from scripts.lazarus_day.models import Organization


ROOT = Path(__file__).parents[1]


def test_real_organization_index_matches_main_name_and_alias() -> None:
    organizations, encoding = load_organizations(
        ROOT / "data" / "reference" / "apt_organizations.csv"
    )
    matcher = OrganizationMatcher(organizations)
    kimsuky = matcher.match(
        related_actors=["Kimsuky"], tags=[], title="irrelevant"
    )
    bluenoroff = matcher.match(
        related_actors=["Bluenoroff"], tags=[], title="irrelevant"
    )
    assert encoding == "UTF-8 with BOM"
    assert kimsuky.organization and kimsuky.organization.id == 53
    assert kimsuky.method == "related_actor_main_exact"
    assert bluenoroff.organization and bluenoroff.organization.id == 52
    assert bluenoroff.method == "related_actor_alias_exact"


def test_alias_parser_supports_real_and_compatibility_formats() -> None:
    assert split_aliases("A | B | C") == ("A", "B", "C")
    assert split_aliases('["A", "B"]') == ("A", "B")
    assert split_aliases("A; B") == ("A", "B")
    assert split_aliases("A，B") == ("A", "B")


def test_normalized_exact_match_does_not_use_fuzzy_similarity() -> None:
    matcher = OrganizationMatcher(
        [Organization(id=1, name="Blue Noroff", aliases=("APT-38",))]
    )
    result = matcher.match(
        related_actors=["blue-noroff"], tags=[], title=""
    )
    unknown = matcher.match(
        related_actors=["Blue Norof"], tags=[], title=""
    )
    assert result.status == "matched"
    assert result.method == "related_actor_normalized_exact"
    assert unknown.status == "unmatched"
    assert tuple(item.id for item in matcher.exact_candidates("APT_38")) == (1,)


def test_same_normalized_name_mapping_to_two_organizations_is_conflict() -> None:
    matcher = OrganizationMatcher(
        [
            Organization(id=1, name="Alpha", aliases=("Shared-Actor",)),
            Organization(id=2, name="Beta", aliases=("Shared Actor",)),
        ]
    )
    result = matcher.match(
        related_actors=["shared_actor"], tags=[], title=""
    )
    assert result.status == "conflict"
    assert {item.id for item in result.candidate_organizations} == {1, 2}


def test_multiple_related_actors_are_not_automatically_split() -> None:
    matcher = OrganizationMatcher(
        [
            Organization(id=1, name="Kimsuky", aliases=()),
            Organization(id=2, name="APT38", aliases=("Bluenoroff",)),
        ]
    )
    result = matcher.match(
        related_actors=["Kimsuky", "Bluenoroff"],
        tags=[],
        title="Two campaigns",
    )
    assert result.status == "conflict"


def test_tags_matching_main_name_and_another_alias_are_conflict() -> None:
    matcher = OrganizationMatcher(
        [
            Organization(id=1, name="Kimsuky", aliases=()),
            Organization(id=2, name="APT38", aliases=("Bluenoroff",)),
        ]
    )
    result = matcher.match(
        related_actors=[],
        tags=["T1059.001", "Phishing", "Kimsuky", "Bluenoroff"],
        title="A report",
    )
    assert result.status == "conflict"
    assert result.raw_names == ("Kimsuky", "Bluenoroff")


def test_unmatched_technical_tags_are_not_reported_as_actor_names() -> None:
    matcher = OrganizationMatcher(
        [Organization(id=1, name="Kimsuky", aliases=())]
    )
    result = matcher.match(
        related_actors=[],
        tags=["T1059.001", "Phishing", "NPM", "UnknownCampaign"],
        title="Generic supply chain report",
    )
    assert result.status == "unmatched"
    assert result.raw_names == ()
    assert "未将技术标签当作组织名称" in (result.reason or "")


def test_user_confirmed_alias_override_is_deterministic() -> None:
    matcher = OrganizationMatcher(
        [Organization(id=55, name="Lazarus Group", aliases=())]
    )
    assert matcher.exact_candidates("Lazarus") == ()
    matcher.add_alias_override("Lazarus", 55)
    candidates = matcher.exact_candidates("lazarus")
    assert tuple(item.id for item in candidates) == (55,)
    result = matcher.match(
        related_actors=["Lazarus"], tags=[], title=""
    )
    assert result.organization and result.organization.id == 55
