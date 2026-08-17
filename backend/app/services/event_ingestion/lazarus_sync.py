from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Mapping, Protocol

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from app.services.event_ingestion.lazarus_adapter import (
    SOURCE,
    IngestionCandidate,
    build_event_candidates,
    canonicalize_url,
    normalize_title,
    validate_lazarus_variant,
)

logger = logging.getLogger("uvicorn.error")


class EventFeedClient(Protocol):
    def list_events(
        self,
        *,
        cursor: str | None,
        limit: int,
    ) -> dict[str, Any]:
        ...


@dataclass
class SyncSummary:
    source: str = SOURCE
    status: str = "running"
    pages_processed: int = 0
    source_records: int = 0
    candidates_written: int = 0
    events_inserted: int = 0
    events_updated: int = 0
    duplicates_linked: int = 0
    review_queued: int = 0
    events_unchanged: int = 0
    cursor_advanced: bool = False
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status,
            "pages_processed": self.pages_processed,
            "source_records": self.source_records,
            "candidates_written": self.candidates_written,
            "events_inserted": self.events_inserted,
            "events_updated": self.events_updated,
            "duplicates_linked": self.duplicates_linked,
            "review_queued": self.review_queued,
            "events_unchanged": self.events_unchanged,
            "cursor_advanced": self.cursor_advanced,
            "errors": list(self.errors),
        }


def _json_object(value: Any) -> Any:
    if value is None or isinstance(value, (list, dict)):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _organization_names(row: Mapping[str, Any]) -> set[str]:
    values = {str(row.get("name") or "").strip()}
    aliases = _json_object(row.get("alias"))
    if isinstance(aliases, list):
        values.update(str(item).strip() for item in aliases if str(item).strip())
    elif isinstance(aliases, str):
        values.update(item.strip() for item in aliases.split("|") if item.strip())
    return {value for value in values if value}


class LazarusEventSyncService:
    LOCK_NAME = "apthunter:lazarus-event-sync"

    def __init__(
        self,
        engine: Engine,
        client: EventFeedClient,
        *,
        page_limit: int = 100,
        max_pages: int = 20,
        auto_import: bool = True,
        source: str = SOURCE,
        source_label: str = "Lazarus.day",
        lock_name: str | None = None,
    ) -> None:
        self.engine = engine
        self.client = client
        self.page_limit = max(1, min(200, int(page_limit)))
        self.max_pages = max(1, int(max_pages))
        self.auto_import = bool(auto_import)
        self.source = str(source or "").strip()
        if not self.source or len(self.source) > 64:
            raise ValueError("事件来源标识无效")
        self.source_label = source_label.strip() or self.source
        self.lock_name = lock_name or self.LOCK_NAME

    def sync(self, *, trigger_type: str = "scheduled") -> dict[str, Any]:
        lock_connection = self.engine.connect()
        lock_acquired = False
        try:
            if self.engine.dialect.name == "mysql":
                lock_acquired = bool(
                    lock_connection.execute(
                        text("SELECT GET_LOCK(:name, 0)"),
                        {"name": self.lock_name},
                    ).scalar()
                )
                if not lock_acquired:
                    return SyncSummary(
                        source=self.source,
                        status="skipped_locked",
                    ).as_dict()
            else:
                lock_acquired = True
            return self._sync_locked(trigger_type=trigger_type)
        finally:
            if lock_acquired and self.engine.dialect.name == "mysql":
                try:
                    lock_connection.execute(
                        text("SELECT RELEASE_LOCK(:name)"),
                        {"name": self.lock_name},
                    )
                except Exception:
                    logger.exception("释放 %s 同步锁失败", self.source_label)
            lock_connection.close()

    def _sync_locked(self, *, trigger_type: str) -> dict[str, Any]:
        summary = SyncSummary(source=self.source)
        run_id = self._start_run(trigger_type)
        cursor = self._read_cursor()
        try:
            self._mark_attempt()
            for _ in range(self.max_pages):
                page = self.client.list_events(cursor=cursor, limit=self.page_limit)
                items = page["items"]
                next_cursor = page["next_cursor"]
                with self.engine.begin() as connection:
                    page_counts = self._process_page(connection, items)
                    self._advance_cursor(connection, next_cursor)
                summary.pages_processed += 1
                summary.source_records += len(items)
                summary.cursor_advanced = (
                    summary.cursor_advanced or next_cursor != cursor
                )
                for key, value in page_counts.items():
                    setattr(summary, key, getattr(summary, key) + value)
                previous_cursor = cursor
                cursor = next_cursor
                if not bool(page.get("has_more")):
                    break
                if not items and cursor == previous_cursor:
                    raise RuntimeError(f"{self.source_label} 变更流游标未前进")
            summary.status = "completed"
            self._finish_run(run_id, summary)
            return summary.as_dict()
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            summary.status = "failed"
            summary.errors.append(error)
            self._record_failure(run_id, summary, error)
            raise

    def _start_run(self, trigger_type: str) -> int:
        with self.engine.begin() as connection:
            result = connection.execute(
                text(
                    """
                    INSERT INTO apt_event_import_runs (source, trigger_type, status)
                    VALUES (:source, :trigger_type, 'running')
                    """
                ),
                {"source": self.source, "trigger_type": trigger_type[:32]},
            )
            return int(result.lastrowid)

    def _read_cursor(self) -> str | None:
        with self.engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT cursor_value FROM apt_event_sync_state "
                        "WHERE source = :source"
                    ),
                    {"source": self.source},
                )
                .mappings()
                .first()
            )
        return str(row["cursor_value"]) if row and row["cursor_value"] else None

    def _mark_attempt(self) -> None:
        with self.engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO apt_event_sync_state (
                        source, cursor_value, last_attempt_at, last_error
                    ) VALUES (:source, NULL, NOW(), NULL)
                    ON DUPLICATE KEY UPDATE
                        last_attempt_at = NOW(), last_error = NULL
                    """
                ),
                {"source": self.source},
            )

    def _advance_cursor(self, connection: Connection, cursor: str) -> None:
        connection.execute(
            text(
                """
                INSERT INTO apt_event_sync_state (
                    source, cursor_value, last_attempt_at, last_success_at, last_error
                ) VALUES (:source, :cursor, NOW(), NOW(), NULL)
                ON DUPLICATE KEY UPDATE
                    cursor_value = VALUES(cursor_value),
                    last_success_at = NOW(),
                    last_error = NULL
                """
            ),
            {"source": self.source, "cursor": cursor},
        )

    def _process_page(
        self,
        connection: Connection,
        items: list[Any],
    ) -> dict[str, int]:
        counts = {
            "candidates_written": 0,
            "events_inserted": 0,
            "events_updated": 0,
            "duplicates_linked": 0,
            "review_queued": 0,
            "events_unchanged": 0,
        }
        impacted_organizations: set[int] = set()
        impacted_stats: set[tuple[date, str]] = set()
        for value in items:
            if not isinstance(value, Mapping):
                raise ValueError(f"{self.source_label} 变更流包含非对象事件")
            for candidate in build_event_candidates(value, source=self.source):
                result = self._process_candidate(connection, candidate)
                counts["candidates_written"] += 1
                counts[result["counter"]] += 1
                if result.get("organization_id"):
                    impacted_organizations.add(int(result["organization_id"]))
                if result.get("event_date") and result.get("region"):
                    impacted_stats.add((result["event_date"], result["region"]))
        for organization_id in impacted_organizations:
            connection.execute(
                text(
                    """
                    UPDATE apt_organizations
                    SET event_count = (
                        SELECT COUNT(*) FROM apt_events
                        WHERE organization_id = :organization_id
                    )
                    WHERE id = :organization_id
                    """
                ),
                {"organization_id": organization_id},
            )
        for event_date, region in impacted_stats:
            connection.execute(
                text(
                    """
                    INSERT INTO region_event_stats (
                        stat_date, region, event_count, major_count
                    )
                    SELECT :event_date, :region, COUNT(*),
                           COALESCE(SUM(event_type = 'major'), 0)
                    FROM apt_events
                    WHERE event_date = :event_date
                      AND COALESCE(NULLIF(region, ''), '未知') = :region
                    ON DUPLICATE KEY UPDATE
                        event_count = VALUES(event_count),
                        major_count = VALUES(major_count)
                    """
                ),
                {"event_date": event_date, "region": region},
            )
        return counts

    def _process_candidate(
        self,
        connection: Connection,
        candidate: IngestionCandidate,
    ) -> dict[str, Any]:
        if candidate.source != self.source:
            raise ValueError("候选来源与同步服务不匹配")
        existing_candidate = (
            connection.execute(
                text(
                    """
                SELECT source_version, payload_sha256, decision, apt_event_id,
                       event_managed
                FROM apt_event_candidates
                WHERE source_identity_hash = :identity_hash
                LIMIT 1
                """
                ),
                {"identity_hash": candidate.source_identity_hash},
            )
            .mappings()
            .first()
        )

        organization_id = self._parse_organization_id(
            candidate.variant.get("organization_id")
        )
        organization = self._load_organization(connection, organization_id)
        duplicate = self._find_duplicate(connection, candidate)
        managed_existing_event = bool(
            existing_candidate
            and existing_candidate.get("apt_event_id")
            and existing_candidate.get("event_managed")
        )
        duplicate_is_managed_event = bool(
            duplicate
            and managed_existing_event
            and int(existing_candidate["apt_event_id"]) == int(duplicate["id"])
        )
        if (
            duplicate is not None
            and managed_existing_event
            and not duplicate_is_managed_event
        ):
            self._store_candidate(
                connection,
                candidate,
                decision="needs_review",
                reason="来源更新与另一条现有事件冲突，保留原正式事件并等待审核",
                apt_event_id=int(existing_candidate["apt_event_id"]),
                event_managed=True,
            )
            return {"counter": "review_queued"}
        if duplicate is not None and not duplicate_is_managed_event:
            self._store_candidate(
                connection,
                candidate,
                decision="duplicate",
                reason="现有 apt_events 中已存在相同链接/组织/日期或标题",
                apt_event_id=int(duplicate["id"]),
                event_managed=False,
            )
            return {
                "counter": "duplicates_linked",
                "organization_id": duplicate.get("organization_id"),
                "event_date": duplicate.get("event_date"),
                "region": duplicate.get("region"),
            }

        organization_names = _organization_names(organization or {})
        validation_errors, clean = validate_lazarus_variant(
            candidate,
            organization_names,
        )
        if organization_id is None or organization is None:
            validation_errors.append("organization_id 不存在")
        clean["organization_id"] = organization_id
        clean["region"] = str((organization or {}).get("region") or "未知")

        if validation_errors or not self.auto_import:
            reason_items = list(dict.fromkeys(validation_errors))
            if not self.auto_import:
                reason_items.append("自动导入已关闭")
            mapped_event_id = (
                int(existing_candidate["apt_event_id"])
                if existing_candidate and existing_candidate.get("apt_event_id")
                else None
            )
            self._store_candidate(
                connection,
                candidate,
                decision="needs_review",
                reason="；".join(reason_items),
                apt_event_id=mapped_event_id,
                event_managed=managed_existing_event,
            )
            return {"counter": "review_queued"}

        should_update = bool(
            managed_existing_event
            and (
                int(existing_candidate.get("source_version") or 0)
                < candidate.source_version
                or existing_candidate.get("payload_sha256") != candidate.payload_sha256
            )
        )
        if should_update:
            event_id = int(existing_candidate["apt_event_id"])
            self._update_event(connection, event_id, clean)
            counter = "events_updated"
        elif managed_existing_event:
            event_id = int(existing_candidate["apt_event_id"])
            counter = "events_unchanged"
        else:
            event_id = self._insert_event(connection, clean)
            counter = "events_inserted"
        self._store_candidate(
            connection,
            candidate,
            decision="auto_imported",
            reason=None,
            apt_event_id=event_id,
            event_managed=True,
        )
        return {
            "counter": counter,
            "organization_id": organization_id,
            "event_date": clean["event_date"],
            "region": clean["region"],
        }

    @staticmethod
    def _parse_organization_id(value: Any) -> int | None:
        try:
            parsed = int(str(value or "").strip())
            return parsed if parsed > 0 else None
        except ValueError:
            return None

    @staticmethod
    def _load_organization(
        connection: Connection,
        organization_id: int | None,
    ) -> Mapping[str, Any] | None:
        if organization_id is None:
            return None
        return (
            connection.execute(
                text(
                    """
                SELECT id, name, alias, region
                FROM apt_organizations WHERE id = :organization_id LIMIT 1
                """
                ),
                {"organization_id": organization_id},
            )
            .mappings()
            .first()
        )

    def _find_duplicate(
        self,
        connection: Connection,
        candidate: IngestionCandidate,
    ) -> Mapping[str, Any] | None:
        variant = candidate.variant
        event_key = str(variant.get("event_key") or "").strip().lower()
        if len(event_key) == 64:
            by_key = (
                connection.execute(
                    text(
                        """
                    SELECT id, organization_id, event_date, region
                    FROM apt_events WHERE event_key = :event_key LIMIT 1
                    """
                    ),
                    {"event_key": event_key},
                )
                .mappings()
                .first()
            )
            if by_key:
                return by_key

        organization_id = self._parse_organization_id(variant.get("organization_id"))
        try:
            event_date = date.fromisoformat(str(variant.get("event_date") or ""))
        except ValueError:
            return None
        if organization_id is None:
            return None
        rows = (
            connection.execute(
                text(
                    """
                SELECT id, organization_id, event_date, region, link, title
                FROM apt_events
                WHERE organization_id = :organization_id
                  AND event_date = :event_date
                """
                ),
                {"organization_id": organization_id, "event_date": event_date},
            )
            .mappings()
            .all()
        )
        link = canonicalize_url(variant.get("link"))
        title = normalize_title(variant.get("title"))
        for row in rows:
            if link and canonicalize_url(row.get("link")) == link:
                return row
            if title and normalize_title(row.get("title")) == title:
                return row
        return None

    @staticmethod
    def _insert_event(connection: Connection, clean: Mapping[str, Any]) -> int:
        result = connection.execute(
            text(
                """
                INSERT INTO apt_events (
                    event_key, event_date, date_precision, title, description,
                    link, event_type, threat_type, releasing_product, region,
                    organization_id, severity, confidence, review_status,
                    evidence, collection_notes
                ) VALUES (
                    :event_key, :event_date, :date_precision, :title, :description,
                    :link, :event_type, :threat_type, :releasing_product, :region,
                    :organization_id, :severity, :confidence, 'accepted',
                    :evidence, :collection_notes
                )
                ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)
                """
            ),
            {
                **clean,
                "evidence": json.dumps(clean["evidence"], ensure_ascii=False),
            },
        )
        return int(result.lastrowid)

    @staticmethod
    def _update_event(
        connection: Connection,
        event_id: int,
        clean: Mapping[str, Any],
    ) -> None:
        connection.execute(
            text(
                """
                UPDATE apt_events SET
                    event_key = :event_key,
                    event_date = :event_date,
                    date_precision = :date_precision,
                    title = :title,
                    description = :description,
                    link = :link,
                    event_type = :event_type,
                    threat_type = :threat_type,
                    releasing_product = :releasing_product,
                    region = :region,
                    organization_id = :organization_id,
                    severity = :severity,
                    confidence = :confidence,
                    review_status = 'accepted',
                    evidence = :evidence,
                    collection_notes = :collection_notes
                WHERE id = :event_id
                """
            ),
            {
                **clean,
                "event_id": event_id,
                "evidence": json.dumps(clean["evidence"], ensure_ascii=False),
            },
        )

    @staticmethod
    def _store_candidate(
        connection: Connection,
        candidate: IngestionCandidate,
        *,
        decision: str,
        reason: str | None,
        apt_event_id: int | None,
        event_managed: bool,
    ) -> None:
        connection.execute(
            text(
                """
                INSERT INTO apt_event_candidates (
                    source, source_record_id, variant_key, source_identity_hash,
                    source_version, quality_status, review_required, decision,
                    decision_reason, payload, payload_sha256, apt_event_id,
                    event_managed
                ) VALUES (
                    :source, :source_record_id, :variant_key, :identity_hash,
                    :source_version, :quality_status, :review_required, :decision,
                    :decision_reason, :payload, :payload_sha256, :apt_event_id,
                    :event_managed
                )
                ON DUPLICATE KEY UPDATE
                    source_version = VALUES(source_version),
                    quality_status = VALUES(quality_status),
                    review_required = VALUES(review_required),
                    decision = VALUES(decision),
                    decision_reason = VALUES(decision_reason),
                    payload = VALUES(payload),
                    payload_sha256 = VALUES(payload_sha256),
                    apt_event_id = COALESCE(VALUES(apt_event_id), apt_event_id),
                    event_managed = VALUES(event_managed)
                """
            ),
            {
                "source": candidate.source,
                "source_record_id": candidate.source_record_id,
                "variant_key": candidate.variant_key,
                "identity_hash": candidate.source_identity_hash,
                "source_version": candidate.source_version,
                "quality_status": candidate.quality_status,
                "review_required": int(candidate.review_required),
                "decision": decision,
                "decision_reason": reason,
                "payload": candidate.payload_json,
                "payload_sha256": candidate.payload_sha256,
                "apt_event_id": apt_event_id,
                "event_managed": int(event_managed),
            },
        )

    def _finish_run(self, run_id: int, summary: SyncSummary) -> None:
        with self.engine.begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE apt_event_import_runs SET
                        status = :status,
                        pages_processed = :pages_processed,
                        source_records = :source_records,
                        candidates_written = :candidates_written,
                        events_inserted = :events_inserted,
                        events_updated = :events_updated,
                        events_unchanged = :events_unchanged,
                        duplicates_linked = :duplicates_linked,
                        review_queued = :review_queued,
                        completed_at = NOW()
                    WHERE id = :run_id
                    """
                ),
                {**summary.as_dict(), "run_id": run_id},
            )

    def _record_failure(
        self,
        run_id: int,
        summary: SyncSummary,
        error: str,
    ) -> None:
        try:
            with self.engine.begin() as connection:
                connection.execute(
                    text(
                        """
                        UPDATE apt_event_import_runs SET
                            status = 'failed',
                            pages_processed = :pages_processed,
                            source_records = :source_records,
                            candidates_written = :candidates_written,
                            events_inserted = :events_inserted,
                            events_updated = :events_updated,
                            events_unchanged = :events_unchanged,
                            duplicates_linked = :duplicates_linked,
                            review_queued = :review_queued,
                            error_message = :error,
                            completed_at = NOW()
                        WHERE id = :run_id
                        """
                    ),
                    {**summary.as_dict(), "run_id": run_id, "error": error[:4000]},
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO apt_event_sync_state (
                            source, cursor_value, last_attempt_at, last_error
                        ) VALUES (:source, NULL, NOW(), :error)
                        ON DUPLICATE KEY UPDATE last_error = VALUES(last_error)
                        """
                    ),
                    {"source": self.source, "error": error[:4000]},
                )
        except Exception:
            logger.exception("记录 %s 同步失败状态时发生异常", self.source_label)
