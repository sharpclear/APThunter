from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .deduplicator import EventDeduplicator
from .matcher import (
    OrganizationMatcher,
    load_actor_alias_overrides,
    load_organizations,
    read_text_compatible,
)
from .models import (
    COLLECTOR_VERSION,
    BatchStats,
    MatchResult,
    OriginalSource,
    ReportRecord,
    ValidationError,
)
from .normalizer import make_event_key, normalize_report, validate_event
from .relationships import (
    ActorRelationship,
    load_actor_relationships,
    resolve_report_relationships,
)
from .storage import atomic_write_text, sha256_file, write_json, write_jsonl


REVIEW_CSV_FIELDS = (
    "review_decision",
    "reviewer_notes",
    "event_key",
    "organization_id",
    "organization_name",
    "event_date",
    "date_precision",
    "title",
    "description",
    "threat_type",
    "releasing_product",
    "link",
    "confidence",
    "review_reasons",
    "candidate_organizations",
    "raw_related_actors",
    "raw_tags",
    "source_title",
    "dedup_existing_id",
    "lazarus_day_url",
    "evidence_json",
    "collection_notes",
    "collected_at",
)

DISPLAY_DECISION_FIELDS = (
    "event_key",
    "review_decision",
    "reviewer_notes",
    "title",
    "description",
    "threat_type",
)

DISPLAY_FORBIDDEN_PHRASES = (
    "需要人工复核",
    "需人工审核",
    "人工复核",
    "人工审核",
    "人工确认",
    "应由人工",
    "待审核",
    "待确认",
    "置信度不足",
    "低于阈值",
    "疑似重复，需判重",
    "需判重",
    "当前采集器",
    "采集器未调用",
    "采集器",
    "未调用外部翻译或生成模型",
    "lazarus.day 的公开页面将该报告与",
    "具体技术细节和攻击发生日期应由人工依据原始报告复核",
)

FINAL_CSV_FIELDS = (
    "id",
    "event_date",
    "title",
    "description",
    "threat_type",
    "organization_id",
    "releasing_product",
    "link",
)

UNKNOWN_ORGANIZATION_CSV_FIELDS = (
    "unknown_organization_names",
    "known_organization_matches",
    "event_date",
    "source_title",
    "title",
    "description",
    "threat_type",
    "releasing_product",
    "link",
    "lazarus_day_url",
    "raw_related_actors",
    "raw_tags",
    "review_reasons",
    "candidate_organizations",
    "confidence",
    "event_key",
)

ACCEPT_DECISIONS = {"accept", "accepted", "接受", "通过", "保留"}
REJECT_DECISIONS = {"reject", "rejected", "拒绝", "不通过", "删除"}


def prepare_review_from_raw(
    *,
    organizations_path: Path,
    existing_events_path: Path,
    output_root: Path,
    raw_path: Path | None = None,
    raw_paths: Iterable[Path] | None = None,
    actor_overrides_path: Path | None = None,
    actor_relationships_path: Path | None = None,
    output_name: str = "lazarus-day",
    now: datetime | None = None,
) -> dict[str, Any]:
    """Re-run matching, normalization, and deduplication without network access."""

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    selected_raw_paths = _resolve_raw_paths(raw_path, raw_paths)
    organizations_path = organizations_path.resolve()
    existing_events_path = existing_events_path.resolve()
    output_root = output_root.resolve()
    actor_overrides_path = (
        actor_overrides_path.resolve()
        if actor_overrides_path is not None
        else None
    )
    actor_relationships_path = (
        actor_relationships_path.resolve()
        if actor_relationships_path is not None
        else None
    )
    if not output_name or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        for character in output_name
    ):
        raise ValidationError("output_name 只能包含字母、数字、点、下划线和连字符")
    for label, path in (
        ("组织文件", organizations_path),
        ("现有事件文件", existing_events_path),
    ):
        if not path.is_file():
            raise ValidationError(f"{label}不存在：{path}")
    for path in selected_raw_paths:
        if not path.is_file():
            raise ValidationError(f"原始 JSONL 不存在：{path}")
    if actor_overrides_path is not None and not actor_overrides_path.is_file():
        raise ValidationError(f"Actor 覆盖文件不存在：{actor_overrides_path}")
    if (
        actor_relationships_path is not None
        and not actor_relationships_path.is_file()
    ):
        raise ValidationError(
            f"Actor 关系文件不存在：{actor_relationships_path}"
        )

    input_hashes_before = {
        "organizations": sha256_file(organizations_path),
        "existing_events": sha256_file(existing_events_path),
    }
    raw_hashes_before = {
        str(path): sha256_file(path) for path in selected_raw_paths
    }
    if actor_overrides_path is not None:
        input_hashes_before["actor_overrides"] = sha256_file(
            actor_overrides_path
        )
    if actor_relationships_path is not None:
        input_hashes_before["actor_relationships"] = sha256_file(
            actor_relationships_path
        )
    organizations, organizations_encoding = load_organizations(
        organizations_path
    )
    matcher = OrganizationMatcher(organizations)
    actor_overrides: list[dict[str, object]] = []
    actor_overrides_encoding: str | None = None
    if actor_overrides_path is not None:
        actor_overrides, actor_overrides_encoding = (
            load_actor_alias_overrides(actor_overrides_path, matcher)
        )
    actor_relationships: dict[str, ActorRelationship] = {}
    actor_relationships_encoding: str | None = None
    if actor_relationships_path is not None:
        actor_relationships, actor_relationships_encoding = (
            load_actor_relationships(actor_relationships_path, matcher)
        )
    deduplicator = EventDeduplicator.from_csv(
        existing_events_path,
        allow_cross_organization_links=actor_relationships_path is not None,
    )
    stats = BatchStats()
    accepted: list[dict[str, Any]] = []
    needs_review: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    rejections: list[dict[str, Any]] = []
    report_dates: list[str] = []
    seen_report_urls: set[str] = set()
    duplicate_raw_records_skipped = 0

    for current_raw_path in selected_raw_paths:
        with current_raw_path.open(
            "r", encoding="utf-8", newline=""
        ) as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    raw_record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValidationError(
                        f"原始 JSONL {current_raw_path} 第 {line_number} 行无效：{exc}"
                    ) from exc
                if not isinstance(raw_record, dict):
                    raise ValidationError(
                        f"原始 JSONL {current_raw_path} 第 {line_number} 行必须是对象"
                    )
                report = _report_from_raw(raw_record, line_number)
                if report.lazarus_day_url in seen_report_urls:
                    duplicate_raw_records_skipped += 1
                    continue
                seen_report_urls.add(report.lazarus_day_url)
                original = _original_from_raw(raw_record, line_number)
                _process_offline_report(
                    report=report,
                    original=original,
                    matcher=matcher,
                    deduplicator=deduplicator,
                    stats=stats,
                    accepted=accepted,
                    needs_review=needs_review,
                    unmatched=unmatched,
                    rejections=rejections,
                    actor_relationships=(
                        actor_relationships
                        if actor_relationships_path is not None
                        else None
                    ),
                )
                if len(report.published_date) == 10:
                    report_dates.append(report.published_date)

    input_hashes_after = {
        "organizations": sha256_file(organizations_path),
        "existing_events": sha256_file(existing_events_path),
    }
    raw_hashes_after = {
        str(path): sha256_file(path) for path in selected_raw_paths
    }
    if actor_overrides_path is not None:
        input_hashes_after["actor_overrides"] = sha256_file(
            actor_overrides_path
        )
    if actor_relationships_path is not None:
        input_hashes_after["actor_relationships"] = sha256_file(
            actor_relationships_path
        )
    if (
        input_hashes_before != input_hashes_after
        or raw_hashes_before != raw_hashes_after
    ):
        raise ValidationError("只读输入在离线处理期间发生变化，终止输出")

    date_text = now.date().isoformat()
    paths = {
        "normalized": (
            output_root / "normalized" / f"{output_name}.events.jsonl"
        ),
        "needs_review": (
            output_root
            / "review"
            / f"{output_name}.events.needs-review.jsonl"
        ),
        "unmatched": (
            output_root
            / "review"
            / f"{output_name}.events.unmatched-organizations.jsonl"
        ),
        "review_csv": (
            output_root / "review" / f"{output_name}.events.review.csv"
        ),
        "report": (
            output_root
            / "reports"
            / f"{output_name}-review-preparation-{date_text}.json"
        ),
    }
    write_jsonl(paths["normalized"], accepted)
    write_jsonl(paths["needs_review"], needs_review)
    write_jsonl(paths["unmatched"], unmatched)
    write_review_csv(paths["review_csv"], needs_review)
    report = {
        "status": "success",
        "mode": "offline-review-preparation",
        "collector_version": COLLECTOR_VERSION,
        "generated_at": now.isoformat(),
        "network_accessed": False,
        "database_accessed": False,
        "checkpoint_updated": False,
        "reference_files_modified": False,
        "window": {
            "start": min(report_dates) if report_dates else None,
            "end": max(report_dates) if report_dates else None,
        },
        "input_files": {
            "raw": [
                {"path": str(path), "sha256": raw_hashes_after[str(path)]}
                for path in selected_raw_paths
            ],
            "organizations": {
                "path": str(organizations_path),
                "sha256": input_hashes_after["organizations"],
                "encoding": organizations_encoding,
                "rows": len(organizations),
            },
            "existing_events": {
                "path": str(existing_events_path),
                "sha256": input_hashes_after["existing_events"],
                "encoding": deduplicator.encoding,
                "rows": deduplicator.row_count,
            },
            "actor_overrides": (
                {
                    "path": str(actor_overrides_path),
                    "sha256": input_hashes_after["actor_overrides"],
                    "encoding": actor_overrides_encoding,
                    "rows": len(actor_overrides),
                }
                if actor_overrides_path is not None
                else None
            ),
            "actor_relationships": (
                {
                    "path": str(actor_relationships_path),
                    "sha256": input_hashes_after["actor_relationships"],
                    "encoding": actor_relationships_encoding,
                    "rows": len(actor_relationships),
                    "split_related_actors": True,
                }
                if actor_relationships_path is not None
                else None
            ),
        },
        "duplicate_raw_records_skipped": duplicate_raw_records_skipped,
        "stats": stats.as_dict(),
        "rejections": rejections,
        "outputs": {key: str(value) for key, value in paths.items()},
    }
    write_json(paths["report"], report)
    return report


def _process_offline_report(
    *,
    report: ReportRecord,
    original: OriginalSource | None,
    matcher: OrganizationMatcher,
    deduplicator: EventDeduplicator,
    stats: BatchStats,
    accepted: list[dict[str, Any]],
    needs_review: list[dict[str, Any]],
    unmatched: list[dict[str, Any]],
    rejections: list[dict[str, Any]],
    actor_relationships: dict[str, ActorRelationship] | None = None,
) -> None:
    stats.discovered += 1
    stats.fetched += 1
    stats.raw_records += 1
    mapped_relationships: tuple[ActorRelationship, ...] = ()
    excluded_names: tuple[str, ...] = ()
    unresolved_names: tuple[str, ...] = ()
    split_mode = actor_relationships is not None
    if split_mode:
        resolution = resolve_report_relationships(
            report, matcher, actor_relationships
        )
        matches = resolution.matches
        mapped_relationships = resolution.mapped_relationships
        excluded_names = resolution.excluded_names
        unresolved_names = resolution.unresolved_names
        if not matches:
            reason_parts = ["没有可生成事件的已确认组织归属"]
            if excluded_names:
                reason_parts.append(
                    "用户决定暂不映射：" + " | ".join(excluded_names)
                )
            if unresolved_names:
                reason_parts.append(
                    "仍未解析：" + " | ".join(unresolved_names)
                )
            matches = (
                MatchResult(
                    status="unmatched",
                    organization=None,
                    method=None,
                    raw_names=tuple(report.related_actors),
                    reason="；".join(reason_parts),
                ),
            )
    else:
        matches = (
            matcher.match(
                related_actors=report.related_actors,
                tags=report.tags,
                title=report.title,
            ),
        )

    for match in matches:
        normalized = normalize_report(
            report,
            match,
            original,
            related_actors_split=split_mode and bool(report.related_actors),
        )
        if normalized.event is None:
            stats.rejected += 1
            rejections.append(
                {
                    "lazarus_day_url": report.lazarus_day_url,
                    "title": report.title,
                    "reason": normalized.rejected_reason,
                }
            )
            return
        _store_offline_event(
            report=report,
            match=match,
            normalized=normalized,
            deduplicator=deduplicator,
            stats=stats,
            accepted=accepted,
            needs_review=needs_review,
            unmatched=unmatched,
            rejections=rejections,
            split_mode=split_mode,
            split_organization_count=len(matches),
            mapped_relationships=mapped_relationships,
            excluded_names=excluded_names,
            unresolved_names=unresolved_names,
        )


def _store_offline_event(
    *,
    report: ReportRecord,
    match: MatchResult,
    normalized: Any,
    deduplicator: EventDeduplicator,
    stats: BatchStats,
    accepted: list[dict[str, Any]],
    needs_review: list[dict[str, Any]],
    unmatched: list[dict[str, Any]],
    rejections: list[dict[str, Any]],
    split_mode: bool,
    split_organization_count: int,
    mapped_relationships: tuple[ActorRelationship, ...],
    excluded_names: tuple[str, ...],
    unresolved_names: tuple[str, ...],
) -> None:
    event = normalized.event
    event_key = make_event_key(
        canonical_link=str(event["link"]),
        organization_id=event["organization_id"],
        event_date=str(event["event_date"]),
        title=str(event["title"]),
    )
    decision = deduplicator.check_and_register(
        event, lazarus_day_url=report.lazarus_day_url
    )
    if decision.status == "exact_duplicate":
        stats.duplicates += 1
        stats.rejected += 1
        rejections.append(
            {
                "lazarus_day_url": report.lazarus_day_url,
                "title": report.title,
                "organization_id": event["organization_id"],
                "reason": decision.reason,
                "existing_id": decision.existing_id,
            }
        )
        return

    review_reasons = list(normalized.review_reasons)
    if decision.status == "suspected_duplicate":
        stats.suspected_duplicates += 1
        review_reasons.append(decision.reason or "疑似重复")
        event["review_status"] = "needs_review"
        event["collection_notes"] = _append_note(
            event.get("collection_notes"), decision.reason
        )
    relevant_relationships = tuple(
        item
        for item in mapped_relationships
        if item.organization_id == event["organization_id"]
    )
    for relationship in relevant_relationships:
        event["collection_notes"] = _append_note(
            event.get("collection_notes"),
            (
                "用户确认关系映射："
                f"{relationship.source_name}=>"
                f"{relationship.organization_id}:{relationship.organization_name}"
                f"（{relationship.relationship_type}/{relationship.confidence}）"
            ),
        )
    if split_mode and split_organization_count > 1:
        event["collection_notes"] = _append_note(
            event.get("collection_notes"),
            f"报告按 {split_organization_count} 个已确认组织拆分事件",
        )
    if split_mode:
        review_reasons.append("依据用户确认的 Actor 关系映射和拆分规则重建归属")
        event["review_status"] = "needs_review"
    validate_event(
        event,
        allow_partial_date=event["review_status"] == "needs_review",
    )
    stats.normalized += 1
    if event["review_status"] == "accepted":
        accepted.append(event)
        stats.accepted += 1
        return

    review_record = dict(event)
    review_record["review_context"] = {
        "reasons": list(dict.fromkeys(review_reasons)),
        "raw_organization_names": list(match.raw_names),
        "candidate_organizations": [
            {"id": item.id, "name": item.name}
            for item in match.candidate_organizations
        ],
        "raw_related_actors": list(report.related_actors),
        "raw_tags": list(report.tags),
        "source_title": report.title,
        "event_key": event_key,
        "lazarus_day_url": report.lazarus_day_url,
        "dedup_existing_id": decision.existing_id,
        "mapped_relationships": [
            {
                "source_name": item.source_name,
                "organization_id": item.organization_id,
                "organization_name": item.organization_name,
                "relationship_type": item.relationship_type,
                "related_organization_ids": list(item.related_organization_ids),
                "confidence": item.confidence,
            }
            for item in relevant_relationships
        ],
        "excluded_actor_names": list(excluded_names),
        "unresolved_actor_names": list(unresolved_names),
        "split_organization_count": split_organization_count,
    }
    needs_review.append(review_record)
    stats.needs_review += 1
    if normalized.unmatched:
        unmatched.append(review_record)
        stats.unmatched += 1


def _resolve_raw_paths(
    raw_path: Path | None, raw_paths: Iterable[Path] | None
) -> list[Path]:
    values: list[Path] = []
    if raw_path is not None:
        values.append(raw_path)
    if raw_paths is not None:
        values.extend(raw_paths)
    resolved: list[Path] = []
    for value in values:
        path = value.resolve()
        if path not in resolved:
            resolved.append(path)
    if not resolved:
        raise ValidationError("至少需要一个原始 JSONL 输入")
    return resolved


def write_review_csv(
    path: Path, records: Iterable[dict[str, Any]]
) -> None:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=REVIEW_CSV_FIELDS,
        lineterminator="\n",
        extrasaction="ignore",
    )
    writer.writeheader()
    for record in records:
        context = record.get("review_context") or {}
        candidates = context.get("candidate_organizations") or []
        row = {
            "review_decision": "",
            "reviewer_notes": "",
            "event_key": context.get("event_key") or "",
            "organization_id": (
                "" if record.get("organization_id") is None
                else record.get("organization_id")
            ),
            "organization_name": record.get("organization_name") or "",
            "event_date": record.get("event_date") or "",
            "date_precision": record.get("date_precision") or "",
            "title": record.get("title") or "",
            "description": record.get("description") or "",
            "threat_type": record.get("threat_type") or "",
            "releasing_product": record.get("releasing_product") or "",
            "link": record.get("link") or "",
            "confidence": record.get("confidence"),
            "review_reasons": " | ".join(context.get("reasons") or []),
            "candidate_organizations": " | ".join(
                f"{item.get('id')}:{item.get('name')}"
                for item in candidates
                if isinstance(item, dict)
            ),
            "raw_related_actors": " | ".join(
                (
                    context.get("raw_related_actors")
                    if "raw_related_actors" in context
                    else context.get("raw_organization_names")
                )
                or []
            ),
            "raw_tags": " | ".join(context.get("raw_tags") or []),
            "source_title": context.get("source_title") or "",
            "dedup_existing_id": context.get("dedup_existing_id") or "",
            "lazarus_day_url": context.get("lazarus_day_url") or "",
            "evidence_json": json.dumps(
                record.get("evidence") or [],
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            "collection_notes": record.get("collection_notes") or "",
            "collected_at": record.get("collected_at") or "",
        }
        writer.writerow(
            {
                key: _excel_safe(value)
                if key
                not in {
                    "review_decision",
                    "organization_id",
                    "confidence",
                    "evidence_json",
                }
                else value
                for key, value in row.items()
            }
        )
    # UTF-8 BOM lets Windows Excel open Chinese text without guessing GBK.
    atomic_write_text(path, "\ufeff" + buffer.getvalue())


def accept_matched_review_rows(
    *,
    review_csv_path: Path,
    organizations_path: Path,
    reviewer_note: str,
) -> dict[str, Any]:
    """Mark rows with a valid existing organization ID/name as accepted."""

    review_csv_path = review_csv_path.resolve()
    organizations_path = organizations_path.resolve()
    for label, path in (
        ("人工复核 CSV", review_csv_path),
        ("组织文件", organizations_path),
    ):
        if not path.is_file():
            raise ValidationError(f"{label}不存在：{path}")
    hashes_before = {
        "review_csv": sha256_file(review_csv_path),
        "organizations": sha256_file(organizations_path),
    }
    organizations, _encoding = load_organizations(organizations_path)
    matcher = OrganizationMatcher(organizations)
    text, _review_encoding = read_text_compatible(review_csv_path)
    reader = csv.DictReader(io.StringIO(text, newline=""))
    required = set(REVIEW_CSV_FIELDS)
    if reader.fieldnames is None or not required.issubset(reader.fieldnames):
        missing = sorted(required - set(reader.fieldnames or []))
        raise ValidationError(f"人工复核 CSV 缺少字段：{missing}")

    rows = list(reader)
    accepted_rows = 0
    pending_rows = 0
    for line_number, row in enumerate(rows, start=2):
        organization_id_text = _remove_excel_guard(
            row.get("organization_id") or ""
        ).strip()
        if not organization_id_text:
            pending_rows += 1
            continue
        try:
            organization_id = int(organization_id_text)
        except ValueError as exc:
            raise ValidationError(
                f"第 {line_number} 行 organization_id 必须是整数"
            ) from exc
        organization_name = _remove_excel_guard(
            row.get("organization_name") or ""
        ).strip()
        if not matcher.validates_id_name(organization_id, organization_name):
            raise ValidationError(
                f"第 {line_number} 行组织 ID 与名称不匹配："
                f"{organization_id}/{organization_name}"
            )
        row["review_decision"] = "接受"
        current_note = _remove_excel_guard(
            row.get("reviewer_notes") or ""
        ).strip()
        row["reviewer_notes"] = _excel_safe(
            "；".join(
                value
                for value in (current_note, reviewer_note.strip())
                if value
            )
        )
        accepted_rows += 1

    if sha256_file(organizations_path) != hashes_before["organizations"]:
        raise ValidationError("组织参考文件在审核标记期间发生变化，终止输出")
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=reader.fieldnames,
        lineterminator="\n",
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(rows)
    atomic_write_text(review_csv_path, "\ufeff" + buffer.getvalue())
    return {
        "review_csv": str(review_csv_path),
        "before_sha256": hashes_before["review_csv"],
        "after_sha256": sha256_file(review_csv_path),
        "accepted_rows": accepted_rows,
        "pending_rows": pending_rows,
        "reference_files_modified": False,
    }


def apply_display_decisions(
    *,
    review_csv_path: Path,
    decisions_csv_path: Path,
    organizations_path: Path,
    output_csv_path: Path,
) -> dict[str, Any]:
    """Apply source-checked display copy without mutating the source review CSV."""

    review_csv_path = review_csv_path.resolve()
    decisions_csv_path = decisions_csv_path.resolve()
    organizations_path = organizations_path.resolve()
    output_csv_path = output_csv_path.resolve()
    for label, path in (
        ("人工复核 CSV", review_csv_path),
        ("展示文案决策 CSV", decisions_csv_path),
        ("组织文件", organizations_path),
    ):
        if not path.is_file():
            raise ValidationError(f"{label}不存在：{path}")
    hashes_before = {
        "review_csv": sha256_file(review_csv_path),
        "decisions_csv": sha256_file(decisions_csv_path),
        "organizations": sha256_file(organizations_path),
    }
    organizations, _encoding = load_organizations(organizations_path)
    matcher = OrganizationMatcher(organizations)

    review_text, review_encoding = read_text_compatible(review_csv_path)
    review_reader = csv.DictReader(io.StringIO(review_text, newline=""))
    if review_reader.fieldnames is None or not set(REVIEW_CSV_FIELDS).issubset(
        review_reader.fieldnames
    ):
        missing = sorted(
            set(REVIEW_CSV_FIELDS) - set(review_reader.fieldnames or [])
        )
        raise ValidationError(f"人工复核 CSV 缺少字段：{missing}")
    rows = list(review_reader)
    rows_by_key: dict[str, dict[str, str]] = {}
    for line_number, row in enumerate(rows, start=2):
        key = _remove_excel_guard(row.get("event_key") or "").strip()
        if not key:
            raise ValidationError(f"人工复核 CSV 第 {line_number} 行 event_key 为空")
        if key in rows_by_key:
            raise ValidationError(f"人工复核 CSV 出现重复 event_key：{key}")
        rows_by_key[key] = row

    decisions_text, decisions_encoding = read_text_compatible(
        decisions_csv_path
    )
    decisions_reader = csv.DictReader(
        io.StringIO(decisions_text, newline="")
    )
    if decisions_reader.fieldnames is None or not set(
        DISPLAY_DECISION_FIELDS
    ).issubset(decisions_reader.fieldnames):
        missing = sorted(
            set(DISPLAY_DECISION_FIELDS)
            - set(decisions_reader.fieldnames or [])
        )
        raise ValidationError(f"展示文案决策 CSV 缺少字段：{missing}")

    applied = 0
    accepted = 0
    rejected = 0
    seen_decision_keys: set[str] = set()
    for line_number, source_decision in enumerate(decisions_reader, start=2):
        decision = {
            key: _remove_excel_guard(value or "").strip()
            for key, value in source_decision.items()
        }
        event_key = decision["event_key"]
        if not event_key or event_key in seen_decision_keys:
            raise ValidationError(
                f"展示文案决策 CSV 第 {line_number} 行 event_key 为空或重复"
            )
        seen_decision_keys.add(event_key)
        row = rows_by_key.get(event_key)
        if row is None:
            raise ValidationError(
                f"展示文案决策引用不存在的 event_key：{event_key}"
            )
        normalized_decision = _normalize_decision(
            decision["review_decision"]
        )
        if normalized_decision is None:
            raise ValidationError(
                f"展示文案决策 CSV 第 {line_number} 行 review_decision 无效"
            )
        if not decision["reviewer_notes"]:
            raise ValidationError(
                f"展示文案决策 CSV 第 {line_number} 行 reviewer_notes 为空"
            )
        row["reviewer_notes"] = _excel_safe(decision["reviewer_notes"])
        if normalized_decision == "rejected":
            row["review_decision"] = "拒绝"
            rejected += 1
            applied += 1
            continue

        try:
            organization_id = int(
                _remove_excel_guard(row.get("organization_id") or "").strip()
            )
        except ValueError as exc:
            raise ValidationError(
                f"展示文案决策 CSV 第 {line_number} 行对应记录没有有效组织 ID"
            ) from exc
        organization_name = _remove_excel_guard(
            row.get("organization_name") or ""
        ).strip()
        if not matcher.validates_id_name(organization_id, organization_name):
            raise ValidationError(
                f"展示文案决策对应组织 ID/名称不匹配："
                f"{organization_id}/{organization_name}"
            )
        _validate_display_copy(
            title=decision["title"],
            description=decision["description"],
            organization_name=organization_name,
            line_number=line_number,
        )
        if not decision["threat_type"]:
            raise ValidationError(
                f"展示文案决策 CSV 第 {line_number} 行 threat_type 为空"
            )
        row["review_decision"] = "接受"
        row["title"] = _excel_safe(decision["title"])
        row["description"] = _excel_safe(decision["description"])
        row["threat_type"] = decision["threat_type"]
        accepted += 1
        applied += 1

    hashes_after = {
        "review_csv": sha256_file(review_csv_path),
        "decisions_csv": sha256_file(decisions_csv_path),
        "organizations": sha256_file(organizations_path),
    }
    if hashes_after != hashes_before:
        raise ValidationError("只读输入在展示文案应用期间发生变化，终止输出")
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=review_reader.fieldnames,
        lineterminator="\n",
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(rows)
    atomic_write_text(output_csv_path, "\ufeff" + buffer.getvalue())
    return {
        "status": "success",
        "input_review_csv": str(review_csv_path),
        "input_review_encoding": review_encoding,
        "decisions_csv": str(decisions_csv_path),
        "decisions_encoding": decisions_encoding,
        "output_csv": str(output_csv_path),
        "applied_rows": applied,
        "accepted_rows": accepted,
        "rejected_rows": rejected,
        "pending_rows": len(rows) - applied,
        "reference_files_modified": False,
    }


def _validate_display_copy(
    *,
    title: str,
    description: str,
    organization_name: str,
    line_number: int,
) -> None:
    if not title or not description:
        raise ValidationError(
            f"展示文案决策 CSV 第 {line_number} 行标题或描述为空"
        )
    if organization_name not in title or organization_name not in description:
        raise ValidationError(
            f"展示文案决策 CSV 第 {line_number} 行标题和描述必须包含规范组织名称"
        )
    if not re.search(r"[\u4e00-\u9fff]", title + description):
        raise ValidationError(
            f"展示文案决策 CSV 第 {line_number} 行没有中文展示文案"
        )
    combined = title + "\n" + description
    forbidden = [
        phrase for phrase in DISPLAY_FORBIDDEN_PHRASES if phrase in combined
    ]
    if forbidden:
        raise ValidationError(
            f"展示文案决策 CSV 第 {line_number} 行包含内部流程措辞：{forbidden}"
        )
    if re.search(r"相关.+活动（.+报告）", title):
        raise ValidationError(
            f"展示文案决策 CSV 第 {line_number} 行标题仍使用机械报告模板"
        )


def export_unknown_organization_rows(
    *,
    review_csv_path: Path,
    organizations_path: Path,
    output_csv_path: Path,
    actor_overrides_path: Path | None = None,
) -> dict[str, Any]:
    """Export reports containing Actor labels absent from the organization index."""

    review_csv_path = review_csv_path.resolve()
    organizations_path = organizations_path.resolve()
    output_csv_path = output_csv_path.resolve()
    actor_overrides_path = (
        actor_overrides_path.resolve()
        if actor_overrides_path is not None
        else None
    )
    for label, path in (
        ("人工复核 CSV", review_csv_path),
        ("组织文件", organizations_path),
    ):
        if not path.is_file():
            raise ValidationError(f"{label}不存在：{path}")
    input_hashes_before = {
        "review_csv": sha256_file(review_csv_path),
        "organizations": sha256_file(organizations_path),
    }
    if actor_overrides_path is not None:
        if not actor_overrides_path.is_file():
            raise ValidationError(
                f"Actor 覆盖文件不存在：{actor_overrides_path}"
            )
        input_hashes_before["actor_overrides"] = sha256_file(
            actor_overrides_path
        )
    organizations, organizations_encoding = load_organizations(
        organizations_path
    )
    matcher = OrganizationMatcher(organizations)
    override_records: list[dict[str, object]] = []
    override_encoding: str | None = None
    if actor_overrides_path is not None:
        override_records, override_encoding = load_actor_alias_overrides(
            actor_overrides_path, matcher
        )
    text, review_encoding = read_text_compatible(review_csv_path)
    reader = csv.DictReader(io.StringIO(text, newline=""))
    required = set(UNKNOWN_ORGANIZATION_CSV_FIELDS) - {
        "unknown_organization_names",
        "known_organization_matches",
    }
    if reader.fieldnames is None or not required.issubset(reader.fieldnames):
        missing = sorted(required - set(reader.fieldnames or []))
        raise ValidationError(f"人工复核 CSV 缺少字段：{missing}")

    output_rows: list[dict[str, Any]] = []
    unique_unknown_names: set[str] = set()
    source_rows = 0
    for source_row in reader:
        source_rows += 1
        row = {
            key: _remove_excel_guard(value or "")
            for key, value in source_row.items()
        }
        actor_names = _split_pipe_values(row["raw_related_actors"])
        if not actor_names:
            continue
        unknown_names: list[str] = []
        known_matches: list[str] = []
        for actor_name in actor_names:
            candidates = matcher.exact_candidates(actor_name)
            if not candidates:
                unknown_names.append(actor_name)
                unique_unknown_names.add(actor_name)
                continue
            known_matches.append(
                f"{actor_name}=>"
                + "/".join(
                    f"{item.id}:{item.name}" for item in candidates
                )
            )
        if not unknown_names:
            continue
        output_rows.append(
            {
                "unknown_organization_names": " | ".join(unknown_names),
                "known_organization_matches": " | ".join(known_matches),
                "event_date": row["event_date"],
                "source_title": row["source_title"],
                "title": row["title"],
                "description": row["description"],
                "threat_type": row["threat_type"],
                "releasing_product": row["releasing_product"],
                "link": row["link"],
                "lazarus_day_url": row["lazarus_day_url"],
                "raw_related_actors": row["raw_related_actors"],
                "raw_tags": row["raw_tags"],
                "review_reasons": row["review_reasons"],
                "candidate_organizations": row["candidate_organizations"],
                "confidence": row["confidence"],
                "event_key": row["event_key"],
            }
        )

    input_hashes_after = {
        "review_csv": sha256_file(review_csv_path),
        "organizations": sha256_file(organizations_path),
    }
    if actor_overrides_path is not None:
        input_hashes_after["actor_overrides"] = sha256_file(
            actor_overrides_path
        )
    if input_hashes_after != input_hashes_before:
        raise ValidationError("只读输入在未知组织导出期间发生变化，终止输出")
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=UNKNOWN_ORGANIZATION_CSV_FIELDS,
        lineterminator="\n",
        extrasaction="ignore",
    )
    writer.writeheader()
    for row in output_rows:
        writer.writerow(
            {
                key: _excel_safe(value)
                if key not in {"confidence", "event_key"}
                else value
                for key, value in row.items()
            }
        )
    atomic_write_text(output_csv_path, "\ufeff" + buffer.getvalue())
    return {
        "status": "success",
        "input_review_csv": str(review_csv_path),
        "input_encoding": review_encoding,
        "source_rows": source_rows,
        "output_csv": str(output_csv_path),
        "output_rows": len(output_rows),
        "unique_unknown_organization_names": len(unique_unknown_names),
        "unknown_organization_names": sorted(
            unique_unknown_names, key=str.casefold
        ),
        "organizations": {
            "path": str(organizations_path),
            "encoding": organizations_encoding,
            "rows": len(organizations),
            "sha256": input_hashes_before["organizations"],
        },
        "actor_overrides": (
            {
                "path": str(actor_overrides_path),
                "encoding": override_encoding,
                "rows": len(override_records),
                "sha256": input_hashes_before["actor_overrides"],
            }
            if actor_overrides_path is not None
            else None
        ),
        "reference_files_modified": False,
        "database_accessed": False,
    }


def apply_actor_alias_overrides(
    *,
    review_csv_path: Path,
    organizations_path: Path,
    actor_overrides_path: Path,
    output_csv_path: Path,
    reviewer_note: str,
) -> dict[str, Any]:
    """Apply user-confirmed Actor aliases without changing the organization CSV."""

    review_csv_path = review_csv_path.resolve()
    organizations_path = organizations_path.resolve()
    actor_overrides_path = actor_overrides_path.resolve()
    output_csv_path = output_csv_path.resolve()
    for label, path in (
        ("人工复核 CSV", review_csv_path),
        ("组织文件", organizations_path),
        ("Actor 覆盖文件", actor_overrides_path),
    ):
        if not path.is_file():
            raise ValidationError(f"{label}不存在：{path}")
    hashes_before = {
        "review_csv": sha256_file(review_csv_path),
        "organizations": sha256_file(organizations_path),
        "actor_overrides": sha256_file(actor_overrides_path),
    }
    organizations, organizations_encoding = load_organizations(
        organizations_path
    )
    matcher = OrganizationMatcher(organizations)
    overrides, overrides_encoding = load_actor_alias_overrides(
        actor_overrides_path, matcher
    )
    text, review_encoding = read_text_compatible(review_csv_path)
    reader = csv.DictReader(io.StringIO(text, newline=""))
    required = set(REVIEW_CSV_FIELDS)
    if reader.fieldnames is None or not required.issubset(reader.fieldnames):
        missing = sorted(required - set(reader.fieldnames or []))
        raise ValidationError(f"人工复核 CSV 缺少字段：{missing}")

    rows = list(reader)
    newly_matched = 0
    already_matched = 0
    pending = 0
    breakdown: dict[tuple[int, str], int] = {}
    for row in rows:
        if (row.get("organization_id") or "").strip():
            already_matched += 1
            continue
        match = matcher.match(
            related_actors=_split_pipe_values(
                _remove_excel_guard(row.get("raw_related_actors") or "")
            ),
            tags=_split_pipe_values(
                _remove_excel_guard(row.get("raw_tags") or "")
            ),
            title=_remove_excel_guard(
                row.get("source_title") or ""
            ),
        )
        if match.status != "matched" or match.organization is None:
            pending += 1
            continue
        organization = match.organization
        row["organization_id"] = str(organization.id)
        row["organization_name"] = organization.name
        row["review_decision"] = "接受"
        current_note = _remove_excel_guard(
            row.get("reviewer_notes") or ""
        ).strip()
        row["reviewer_notes"] = _excel_safe(
            "；".join(
                value
                for value in (current_note, reviewer_note.strip())
                if value
            )
        )
        breakdown[(organization.id, organization.name)] = (
            breakdown.get((organization.id, organization.name), 0) + 1
        )
        newly_matched += 1

    if {
        "review_csv": sha256_file(review_csv_path),
        "organizations": sha256_file(organizations_path),
        "actor_overrides": sha256_file(actor_overrides_path),
    } != hashes_before:
        raise ValidationError("只读输入在 Actor 覆盖处理期间发生变化")
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=reader.fieldnames,
        lineterminator="\n",
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(rows)
    atomic_write_text(output_csv_path, "\ufeff" + buffer.getvalue())
    return {
        "status": "success",
        "input_review_csv": str(review_csv_path),
        "input_encoding": review_encoding,
        "output_csv": str(output_csv_path),
        "already_matched_rows": already_matched,
        "newly_matched_rows": newly_matched,
        "pending_rows": pending,
        "newly_matched_breakdown": [
            {
                "organization_id": organization_id,
                "organization_name": organization_name,
                "count": count,
            }
            for (organization_id, organization_name), count in sorted(
                breakdown.items()
            )
        ],
        "actor_overrides": {
            "path": str(actor_overrides_path),
            "encoding": overrides_encoding,
            "rows": len(overrides),
            "sha256": hashes_before["actor_overrides"],
        },
        "organizations": {
            "path": str(organizations_path),
            "encoding": organizations_encoding,
            "rows": len(organizations),
            "sha256": hashes_before["organizations"],
        },
        "reference_files_modified": False,
        "database_accessed": False,
    }


def finalize_review_csv(
    *,
    review_csv_path: Path,
    organizations_path: Path,
    existing_events_path: Path,
    output_csv_path: Path,
    report_path: Path | None = None,
    allow_undecided: bool = False,
    allow_cross_organization_links: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate completed human decisions and emit the 8-column import CSV."""

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    review_csv_path = review_csv_path.resolve()
    organizations_path = organizations_path.resolve()
    existing_events_path = existing_events_path.resolve()
    output_csv_path = output_csv_path.resolve()
    report_path = (
        report_path.resolve()
        if report_path is not None
        else output_csv_path.with_name(
            f"{output_csv_path.stem}.validation.json"
        )
    )
    for label, path in (
        ("人工复核 CSV", review_csv_path),
        ("组织文件", organizations_path),
        ("现有事件文件", existing_events_path),
    ):
        if not path.is_file():
            raise ValidationError(f"{label}不存在：{path}")

    input_hashes_before = {
        "review_csv": sha256_file(review_csv_path),
        "organizations": sha256_file(organizations_path),
        "existing_events": sha256_file(existing_events_path),
    }
    organizations, organizations_encoding = load_organizations(
        organizations_path
    )
    matcher = OrganizationMatcher(organizations)
    deduplicator = EventDeduplicator.from_csv(
        existing_events_path,
        allow_cross_organization_links=allow_cross_organization_links,
    )
    text, review_encoding = read_text_compatible(review_csv_path)
    reader = csv.DictReader(io.StringIO(text, newline=""))
    required = set(REVIEW_CSV_FIELDS)
    if reader.fieldnames is None or not required.issubset(reader.fieldnames):
        missing = sorted(required - set(reader.fieldnames or []))
        raise ValidationError(f"人工复核 CSV 缺少字段：{missing}")

    final_rows: list[dict[str, Any]] = []
    errors: list[str] = []
    rejected_rows = 0
    undecided_rows = 0
    suspected_duplicates = 0
    total_rows = 0
    for line_number, source_row in enumerate(reader, start=2):
        total_rows += 1
        row = {
            key: _remove_excel_guard(value or "")
            for key, value in source_row.items()
        }
        decision_text = row["review_decision"].strip()
        if not decision_text:
            undecided_rows += 1
            if not allow_undecided:
                errors.append(
                    f"第 {line_number} 行 review_decision 未填写"
                )
            continue
        decision = _normalize_decision(decision_text)
        if decision is None:
            errors.append(
                f"第 {line_number} 行 review_decision 无效"
            )
            continue
        if decision == "rejected":
            rejected_rows += 1
            continue
        try:
            organization_id = int(row["organization_id"].strip())
        except ValueError:
            errors.append(f"第 {line_number} 行 organization_id 必须是整数")
            continue
        organization_name = row["organization_name"].strip()
        if not matcher.validates_id_name(organization_id, organization_name):
            errors.append(
                f"第 {line_number} 行组织 ID 与名称不匹配："
                f"{organization_id}/{organization_name}"
            )
            continue
        try:
            evidence = json.loads(row["evidence_json"])
        except json.JSONDecodeError as exc:
            errors.append(
                f"第 {line_number} 行 evidence_json 无效：{exc.msg}"
            )
            continue
        try:
            confidence = float(row["confidence"])
        except ValueError:
            errors.append(f"第 {line_number} 行 confidence 必须是数字")
            continue
        event = {
            "schema_version": "1.0",
            "record_type": "event",
            "db_id": None,
            "event_date": row["event_date"].strip(),
            "date_precision": row["date_precision"].strip() or "day",
            "title": row["title"].strip(),
            "description": row["description"].strip(),
            "threat_type": row["threat_type"].strip(),
            "organization_id": organization_id,
            "organization_name": organization_name,
            "releasing_product": row["releasing_product"].strip() or None,
            "link": row["link"].strip(),
            "confidence": confidence,
            "review_status": "accepted",
            "evidence": evidence,
            "collection_notes": _append_note(
                row["collection_notes"].strip() or None,
                (
                    f"人工复核通过：{row['reviewer_notes'].strip()}"
                    if row["reviewer_notes"].strip()
                    else "人工复核通过"
                ),
            ),
            "collected_at": row["collected_at"].strip(),
        }
        try:
            validate_event(event, allow_partial_date=False)
            decision_result = deduplicator.check_and_register(
                event,
                lazarus_day_url=row["lazarus_day_url"].strip()
                or event["link"],
            )
        except ValidationError as exc:
            errors.append(f"第 {line_number} 行校验失败：{exc}")
            continue
        if decision_result.status == "exact_duplicate":
            errors.append(
                f"第 {line_number} 行是精确重复：{decision_result.reason}"
            )
            continue
        if decision_result.status == "suspected_duplicate":
            suspected_duplicates += 1
        final_rows.append(
            {
                "id": "",
                "event_date": event["event_date"],
                "title": event["title"],
                "description": event["description"],
                "threat_type": event["threat_type"],
                "organization_id": event["organization_id"],
                "releasing_product": event["releasing_product"] or "",
                "link": event["link"],
            }
        )

    if errors:
        preview = "；".join(errors[:10])
        suffix = f"；另有 {len(errors) - 10} 项" if len(errors) > 10 else ""
        raise ValidationError(
            f"人工复核 CSV 尚不能生成最终文件：{preview}{suffix}"
        )

    input_hashes_after = {
        "review_csv": sha256_file(review_csv_path),
        "organizations": sha256_file(organizations_path),
        "existing_events": sha256_file(existing_events_path),
    }
    if input_hashes_before != input_hashes_after:
        raise ValidationError("只读输入在最终校验期间发生变化，终止输出")

    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=FINAL_CSV_FIELDS,
        lineterminator="\n",
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(final_rows)
    atomic_write_text(output_csv_path, buffer.getvalue())
    report = {
        "status": "success",
        "mode": "review-finalization",
        "generated_at": now.isoformat(),
        "database_accessed": False,
        "reference_files_modified": False,
        "input_files": {
            "review_csv": {
                "path": str(review_csv_path),
                "sha256": input_hashes_after["review_csv"],
                "encoding": review_encoding,
                "rows": total_rows,
            },
            "organizations": {
                "path": str(organizations_path),
                "sha256": input_hashes_after["organizations"],
                "encoding": organizations_encoding,
                "rows": len(organizations),
            },
            "existing_events": {
                "path": str(existing_events_path),
                "sha256": input_hashes_after["existing_events"],
                "encoding": deduplicator.encoding,
                "rows": deduplicator.row_count,
            },
        },
        "stats": {
            "review_rows": total_rows,
            "accepted_rows": len(final_rows),
            "rejected_rows": rejected_rows,
            "undecided_rows": undecided_rows,
            "suspected_duplicates_approved": suspected_duplicates,
        },
        "partial_export": bool(allow_undecided and undecided_rows),
        "allow_cross_organization_links": allow_cross_organization_links,
        "output": {
            "path": str(output_csv_path),
            "sha256": sha256_file(output_csv_path),
            "fields": list(FINAL_CSV_FIELDS),
        },
    }
    write_json(report_path, report)
    return report


def _report_from_raw(
    value: dict[str, Any], line_number: int
) -> ReportRecord:
    if value.get("parse_error"):
        raise ValidationError(
            f"原始 JSONL 第 {line_number} 行包含详情解析错误，不能离线重算"
        )
    required = (
        "source_record_id",
        "lazarus_day_url",
        "requested_url",
        "raw_title",
        "published_date",
        "http_status",
        "final_url",
        "content_sha256",
        "fetched_at",
        "raw_detail_html",
    )
    missing = [key for key in required if value.get(key) in {None, ""}]
    if missing:
        raise ValidationError(
            f"原始 JSONL 第 {line_number} 行缺少字段：{missing}"
        )
    return ReportRecord(
        source_record_id=str(value["source_record_id"]),
        lazarus_day_url=str(value["lazarus_day_url"]),
        requested_url=str(value["requested_url"]),
        title=str(value["raw_title"]),
        published_date=str(value["published_date"]),
        date_precision=str(value.get("date_precision") or "day"),
        publisher=str(value.get("publisher") or ""),
        original_url=(
            str(value["original_url"]) if value.get("original_url") else None
        ),
        summary=str(value.get("raw_summary") or ""),
        tags=tuple(str(item) for item in value.get("raw_tags") or []),
        related_actors=tuple(
            str(item) for item in value.get("raw_related_actors") or []
        ),
        http_status=int(value["http_status"]),
        final_url=str(value["final_url"]),
        content_sha256=str(value["content_sha256"]),
        fetched_at=str(value["fetched_at"]),
        raw_html=str(value["raw_detail_html"]),
        parse_warnings=tuple(
            str(item) for item in value.get("parse_warnings") or []
        ),
    )


def _original_from_raw(
    value: dict[str, Any], line_number: int
) -> OriginalSource | None:
    raw_original = value.get("original_source")
    if raw_original is None:
        return None
    if not isinstance(raw_original, dict):
        raise ValidationError(
            f"原始 JSONL 第 {line_number} 行 original_source 必须是对象"
        )
    allowed = set(OriginalSource.__dataclass_fields__)
    kwargs = {key: raw_original.get(key) for key in allowed}
    try:
        return OriginalSource(**kwargs)
    except TypeError as exc:
        raise ValidationError(
            f"原始 JSONL 第 {line_number} 行 original_source 无效：{exc}"
        ) from exc


def _normalize_decision(value: str) -> str | None:
    normalized = value.strip().casefold()
    if normalized in ACCEPT_DECISIONS:
        return "accepted"
    if normalized in REJECT_DECISIONS:
        return "rejected"
    return None


def _excel_safe(value: object) -> object:
    if not isinstance(value, str):
        return value
    if value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _remove_excel_guard(value: str) -> str:
    if len(value) >= 2 and value[0] == "'" and value[1] in "=+-@":
        return value[1:]
    return value


def _split_pipe_values(value: str) -> list[str]:
    return [
        item.strip()
        for item in value.split("|")
        if item.strip()
    ]


def _append_note(current: object, note: str | None) -> str | None:
    values = [str(current).strip()] if current else []
    if note:
        values.append(note)
    return "；".join(value for value in values if value) or None
