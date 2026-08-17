from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from pathlib import Path

from .matcher import (
    OrganizationMatcher,
    normalize_actor_name,
    read_text_compatible,
)
from .models import MatchResult, ReportRecord, ValidationError


@dataclass(frozen=True)
class ActorRelationship:
    source_name: str
    decision: str
    organization_id: int | None
    organization_name: str
    relationship_type: str
    related_organization_ids: tuple[int, ...]
    confidence: str
    reason: str


@dataclass(frozen=True)
class RelationshipResolution:
    matches: tuple[MatchResult, ...]
    mapped_relationships: tuple[ActorRelationship, ...]
    excluded_names: tuple[str, ...]
    unresolved_names: tuple[str, ...]


def load_actor_relationships(
    path: Path, matcher: OrganizationMatcher
) -> tuple[dict[str, ActorRelationship], str]:
    text, encoding = read_text_compatible(path)
    reader = csv.DictReader(io.StringIO(text, newline=""))
    required = {
        "source_name",
        "decision",
        "organization_id",
        "organization_name",
        "relationship_type",
        "related_organization_ids",
        "confidence",
        "reason",
    }
    if reader.fieldnames is None or not required.issubset(reader.fieldnames):
        raise ValidationError(
            f"Actor 关系 CSV 缺少字段 {sorted(required)}：{path}"
        )

    relationships: dict[str, ActorRelationship] = {}
    for line_number, row in enumerate(reader, start=2):
        source_name = (row.get("source_name") or "").strip()
        decision = (row.get("decision") or "").strip().casefold()
        organization_name = (row.get("organization_name") or "").strip()
        relationship_type = (row.get("relationship_type") or "").strip()
        confidence = (row.get("confidence") or "").strip().casefold()
        reason = (row.get("reason") or "").strip()
        if not source_name:
            raise ValidationError(
                f"Actor 关系 CSV 第 {line_number} 行 source_name 为空"
            )
        if decision not in {"map", "exclude"}:
            raise ValidationError(
                f"Actor 关系 CSV 第 {line_number} 行 decision 必须为 map/exclude"
            )
        if confidence not in {"high", "medium", "low", "none"}:
            raise ValidationError(
                f"Actor 关系 CSV 第 {line_number} 行 confidence 无效"
            )

        organization_id: int | None = None
        raw_organization_id = (row.get("organization_id") or "").strip()
        if decision == "map":
            try:
                organization_id = int(raw_organization_id)
            except ValueError as exc:
                raise ValidationError(
                    f"Actor 关系 CSV 第 {line_number} 行 organization_id 无效"
                ) from exc
            if not matcher.validates_id_name(
                organization_id, organization_name
            ):
                raise ValidationError(
                    f"Actor 关系 CSV 第 {line_number} 行组织 ID 与名称不匹配："
                    f"{organization_id}/{organization_name}"
                )
            if not relationship_type:
                raise ValidationError(
                    f"Actor 关系 CSV 第 {line_number} 行 relationship_type 为空"
                )
        elif raw_organization_id or organization_name:
            raise ValidationError(
                f"Actor 关系 CSV 第 {line_number} 行 exclude 决策不能指定组织"
            )

        related_ids: list[int] = []
        for raw_id in (row.get("related_organization_ids") or "").split("|"):
            raw_id = raw_id.strip()
            if not raw_id:
                continue
            try:
                related_id = int(raw_id)
            except ValueError as exc:
                raise ValidationError(
                    f"Actor 关系 CSV 第 {line_number} 行关联组织 ID 无效"
                ) from exc
            if related_id not in matcher.by_id:
                raise ValidationError(
                    f"Actor 关系 CSV 第 {line_number} 行关联组织不存在：{related_id}"
                )
            if related_id not in related_ids:
                related_ids.append(related_id)

        key = normalize_actor_name(source_name)
        if not key:
            raise ValidationError(
                f"Actor 关系 CSV 第 {line_number} 行 source_name 无效"
            )
        if key in relationships:
            raise ValidationError(
                f"Actor 关系 CSV 出现重复名称：{source_name}"
            )
        relationships[key] = ActorRelationship(
            source_name=source_name,
            decision=decision,
            organization_id=organization_id,
            organization_name=organization_name,
            relationship_type=relationship_type,
            related_organization_ids=tuple(related_ids),
            confidence=confidence,
            reason=reason,
        )
    return relationships, encoding


def resolve_report_relationships(
    report: ReportRecord,
    matcher: OrganizationMatcher,
    relationships: dict[str, ActorRelationship],
) -> RelationshipResolution:
    """Resolve Related Actors independently and return one match per organization."""

    if not report.related_actors:
        fallback = matcher.match(
            related_actors=(), tags=report.tags, title=report.title
        )
        matches = (fallback,) if fallback.status == "matched" else ()
        return RelationshipResolution(
            matches=matches,
            mapped_relationships=(),
            excluded_names=(),
            unresolved_names=() if matches else tuple(fallback.raw_names),
        )

    excluded_names = tuple(
        name
        for raw_name in report.related_actors
        if (name := str(raw_name).strip().lstrip("#"))
        and (relationship := relationships.get(normalize_actor_name(name)))
        is not None
        and relationship.decision == "exclude"
    )
    if excluded_names:
        return RelationshipResolution(
            matches=(),
            mapped_relationships=(),
            excluded_names=tuple(dict.fromkeys(excluded_names)),
            unresolved_names=(),
        )

    names_by_organization: dict[int, list[str]] = {}
    methods_by_organization: dict[int, set[str]] = {}
    mapped_relationships: list[ActorRelationship] = []
    unresolved_names: list[str] = []

    for raw_name in report.related_actors:
        name = str(raw_name).strip().lstrip("#")
        if not name:
            continue
        candidates = matcher.exact_candidates(name)
        if len(candidates) == 1:
            organization = candidates[0]
            names_by_organization.setdefault(organization.id, []).append(name)
            methods_by_organization.setdefault(organization.id, set()).add(
                "related_actor_index"
            )
            continue
        if len(candidates) > 1:
            unresolved_names.append(name)
            continue

        relationship = relationships.get(normalize_actor_name(name))
        if relationship is None:
            unresolved_names.append(name)
            continue
        if relationship.decision == "exclude":
            continue
        organization_id = relationship.organization_id
        if organization_id is None:
            unresolved_names.append(name)
            continue
        names_by_organization.setdefault(organization_id, []).append(name)
        methods_by_organization.setdefault(organization_id, set()).add(
            f"related_actor_relationship_{relationship.relationship_type}"
        )
        mapped_relationships.append(relationship)

    matches: list[MatchResult] = []
    for organization_id in sorted(names_by_organization):
        methods = sorted(methods_by_organization[organization_id])
        matches.append(
            MatchResult(
                status="matched",
                organization=matcher.by_id[organization_id],
                method="+".join(methods),
                raw_names=tuple(dict.fromkeys(names_by_organization[organization_id])),
            )
        )
    return RelationshipResolution(
        matches=tuple(matches),
        mapped_relationships=tuple(mapped_relationships),
        excluded_names=(),
        unresolved_names=tuple(dict.fromkeys(unresolved_names)),
    )
