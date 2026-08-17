from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


ACTIVE_RUN_STATUSES = ("queued", "running")
TERMINAL_RUN_STATUSES = (
    "completed",
    "completed_with_review",
    "failed",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _future(seconds: float) -> str:
    value = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return value.isoformat().replace("+00:00", "Z")


class StoreConflict(RuntimeError):
    """Raised when another collection run is already active."""

    def __init__(self, active_run_id: str) -> None:
        super().__init__("another collection run is active")
        self.active_run_id = active_run_id


class ApiStore:
    """SQLite repository shared by API request threads and worker instances."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path).resolve()
        self._init_lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.database_path),
            timeout=30,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row is not None else None

    def initialize(self) -> None:
        with self._init_lock:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS api_meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS runs (
                        id TEXT PRIMARY KEY,
                        invocation_id TEXT NOT NULL UNIQUE,
                        idempotency_key TEXT UNIQUE,
                        mode TEXT NOT NULL,
                        status TEXT NOT NULL,
                        request_json TEXT NOT NULL,
                        worker_id TEXT,
                        lease_expires_at TEXT,
                        pid INTEGER,
                        exit_code INTEGER,
                        native_status TEXT,
                        native_invocation_id TEXT,
                        manifest_relpath TEXT,
                        log_relpath TEXT,
                        error TEXT,
                        created_at TEXT NOT NULL,
                        started_at TEXT,
                        completed_at TEXT,
                        updated_at TEXT NOT NULL,
                        available_at TEXT NOT NULL,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        discovered_count INTEGER NOT NULL DEFAULT 0,
                        new_count INTEGER NOT NULL DEFAULT 0,
                        recovered_count INTEGER NOT NULL DEFAULT 0,
                        completed_count INTEGER NOT NULL DEFAULT 0,
                        completed_with_review_count INTEGER NOT NULL DEFAULT 0,
                        manual_review_count INTEGER NOT NULL DEFAULT 0,
                        failed_count INTEGER NOT NULL DEFAULT 0
                    );

                    CREATE UNIQUE INDEX IF NOT EXISTS uq_runs_one_active
                    ON runs ((1)) WHERE status IN ('queued', 'running');

                    CREATE INDEX IF NOT EXISTS ix_runs_created_at
                    ON runs (created_at DESC);

                    CREATE TABLE IF NOT EXISTS events (
                        source_event_id TEXT PRIMARY KEY,
                        source TEXT NOT NULL,
                        source_record_id TEXT NOT NULL,
                        source_url TEXT NOT NULL,
                        original_url TEXT,
                        content_sha256 TEXT NOT NULL,
                        product_digest TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        event_time TEXT,
                        report_time TEXT,
                        collected_at TEXT,
                        updated_at TEXT NOT NULL,
                        first_seen_at TEXT NOT NULL,
                        quality_status TEXT NOT NULL,
                        review_required INTEGER NOT NULL,
                        organization_id TEXT,
                        organization_name TEXT,
                        threat_type TEXT,
                        releasing_product TEXT,
                        primary_link TEXT,
                        structured_json TEXT NOT NULL,
                        evidence_json TEXT NOT NULL,
                        provenance_json TEXT NOT NULL,
                        quality_json TEXT NOT NULL,
                        raw_relpath TEXT NOT NULL,
                        raw_line INTEGER NOT NULL,
                        raw_line_sha256 TEXT NOT NULL,
                        last_run_id TEXT REFERENCES runs(id) ON DELETE SET NULL
                    );

                    CREATE INDEX IF NOT EXISTS ix_events_source_record
                    ON events (source_record_id);

                    CREATE TABLE IF NOT EXISTS run_items (
                        run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                        source_event_id TEXT NOT NULL,
                        origin TEXT NOT NULL,
                        status TEXT NOT NULL,
                        review_required INTEGER NOT NULL DEFAULT 0,
                        error_kind TEXT,
                        error TEXT,
                        PRIMARY KEY (run_id, source_event_id)
                    );

                    CREATE TABLE IF NOT EXISTS event_changes (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        source_event_id TEXT NOT NULL
                            REFERENCES events(source_event_id) ON DELETE CASCADE,
                        operation TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
                        changed_at TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS ix_event_changes_event
                    ON event_changes (source_event_id, seq);
                    """
                )

    def ping(self) -> bool:
        try:
            with self._connect() as connection:
                journal = connection.execute("PRAGMA journal_mode").fetchone()
                foreign_keys = connection.execute(
                    "PRAGMA foreign_keys"
                ).fetchone()
                busy_timeout = connection.execute(
                    "PRAGMA busy_timeout"
                ).fetchone()
            return bool(
                journal
                and foreign_keys
                and busy_timeout
                and str(journal[0]).lower() == "wal"
                and int(foreign_keys[0]) == 1
                and int(busy_timeout[0]) >= 1000
            )
        except sqlite3.Error:
            return False

    def get_meta(self, key: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM api_meta WHERE key = ?", (key,)
            ).fetchone()
        return str(row[0]) if row else None

    def set_meta_if_absent(self, key: str, value: str) -> str:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR IGNORE INTO api_meta(key, value) VALUES (?, ?)",
                (key, value),
            )
            row = connection.execute(
                "SELECT value FROM api_meta WHERE key = ?", (key,)
            ).fetchone()
            connection.commit()
        if row is None:
            raise RuntimeError("failed to persist API metadata")
        return str(row[0])

    def create_run(
        self,
        *,
        run_id: str,
        invocation_id: str,
        idempotency_key: str | None,
        request: Mapping[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        now = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if idempotency_key:
                existing = connection.execute(
                    "SELECT * FROM runs WHERE idempotency_key = ?",
                    (idempotency_key,),
                ).fetchone()
                if existing is not None:
                    connection.commit()
                    return dict(existing), False
            active = connection.execute(
                "SELECT id FROM runs "
                "WHERE status IN ('queued', 'running') LIMIT 1"
            ).fetchone()
            if active is not None:
                connection.rollback()
                raise StoreConflict(str(active["id"]))
            try:
                connection.execute(
                    """
                    INSERT INTO runs (
                        id, invocation_id, idempotency_key, mode, status,
                        request_json, created_at, updated_at, available_at
                    ) VALUES (?, ?, ?, 'incremental', 'queued', ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        invocation_id,
                        idempotency_key,
                        json.dumps(
                            dict(request), ensure_ascii=False, sort_keys=True
                        ),
                        now,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError:
                active = connection.execute(
                    "SELECT id FROM runs "
                    "WHERE status IN ('queued', 'running') LIMIT 1"
                ).fetchone()
                connection.rollback()
                if active is not None:
                    raise StoreConflict(str(active["id"]))
                raise
            row = connection.execute(
                "SELECT * FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
            connection.commit()
        if row is None:
            raise RuntimeError("new run disappeared before commit")
        return dict(row), True

    def claim_next_run(
        self, worker_id: str, *, lease_seconds: float
    ) -> dict[str, Any] | None:
        now = utc_now()
        lease = _future(lease_seconds)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                UPDATE runs
                SET status = 'queued', worker_id = NULL, pid = NULL,
                    lease_expires_at = NULL, available_at = ?, updated_at = ?,
                    error = 'Worker lease expired; run safely requeued.'
                WHERE status = 'running' AND lease_expires_at IS NOT NULL
                  AND lease_expires_at < ?
                """,
                (now, now, now),
            )
            row = connection.execute(
                """
                SELECT * FROM runs
                WHERE status = 'queued' AND available_at <= ?
                ORDER BY created_at, id LIMIT 1
                """,
                (now,),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            updated = connection.execute(
                """
                UPDATE runs
                SET status = 'running', worker_id = ?, lease_expires_at = ?,
                    started_at = COALESCE(started_at, ?), updated_at = ?,
                    attempts = attempts + 1, error = NULL
                WHERE id = ? AND status = 'queued'
                """,
                (worker_id, lease, now, now, row["id"]),
            )
            if updated.rowcount != 1:
                connection.rollback()
                return None
            claimed = connection.execute(
                "SELECT * FROM runs WHERE id = ?", (row["id"],)
            ).fetchone()
            connection.commit()
        return self._row(claimed)

    def heartbeat(
        self, run_id: str, worker_id: str, *, lease_seconds: float
    ) -> bool:
        with self._connect() as connection:
            result = connection.execute(
                """
                UPDATE runs SET lease_expires_at = ?, updated_at = ?
                WHERE id = ? AND status = 'running' AND worker_id = ?
                """,
                (_future(lease_seconds), utc_now(), run_id, worker_id),
            )
        return result.rowcount == 1

    def set_run_process(
        self,
        run_id: str,
        worker_id: str,
        *,
        pid: int,
        log_relpath: str,
        manifest_relpath: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE runs
                SET pid = ?, log_relpath = ?, manifest_relpath = ?, updated_at = ?
                WHERE id = ? AND status = 'running' AND worker_id = ?
                """,
                (
                    pid,
                    log_relpath,
                    manifest_relpath,
                    utc_now(),
                    run_id,
                    worker_id,
                ),
            )

    def finish_run(
        self,
        run_id: str,
        *,
        status: str,
        exit_code: int | None,
        native_status: str | None,
        native_invocation_id: str | None,
        error: str | None,
        counts: Mapping[str, int] | None = None,
        worker_id: str | None = None,
    ) -> None:
        if status not in TERMINAL_RUN_STATUSES:
            raise ValueError("invalid terminal run status")
        counts = counts or {}
        now = utc_now()
        where = "id = ?"
        params: list[Any] = [run_id]
        if worker_id is not None:
            where += " AND worker_id = ?"
            params.append(worker_id)
        with self._connect() as connection:
            connection.execute(
                f"""
                UPDATE runs
                SET status = ?, exit_code = ?, native_status = ?,
                    native_invocation_id = ?, pid = NULL, worker_id = NULL,
                    lease_expires_at = NULL, error = ?, completed_at = ?,
                    updated_at = ?, discovered_count = ?, new_count = ?,
                    recovered_count = ?, completed_count = ?,
                    completed_with_review_count = ?, manual_review_count = ?,
                    failed_count = ?
                WHERE {where}
                """,
                (
                    status,
                    exit_code,
                    native_status,
                    native_invocation_id,
                    error,
                    now,
                    now,
                    int(counts.get("discovered", 0)),
                    int(counts.get("new", 0)),
                    int(counts.get("recovered", 0)),
                    int(counts.get("completed", 0)),
                    int(counts.get("completed_with_review", 0)),
                    int(counts.get("manual_review", 0)),
                    int(counts.get("failed", 0)),
                    *params,
                ),
            )

    def reschedule_run(
        self,
        run_id: str,
        worker_id: str,
        *,
        available_at: str,
        error: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE runs
                SET status = 'queued', worker_id = NULL, pid = NULL,
                    lease_expires_at = NULL, exit_code = 20, error = ?,
                    updated_at = ?, available_at = ?
                WHERE id = ? AND status = 'running' AND worker_id = ?
                """,
                (error, utc_now(), available_at, run_id, worker_id),
            )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
        return self._row(row)

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM runs ORDER BY created_at DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def replace_run_items(
        self, run_id: str, items: Iterable[Mapping[str, Any]]
    ) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM run_items WHERE run_id = ?", (run_id,))
            for item in items:
                connection.execute(
                    """
                    INSERT INTO run_items (
                        run_id, source_event_id, origin, status,
                        review_required, error_kind, error
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        item["source_event_id"],
                        item.get("origin", "current"),
                        item.get("status", "failed"),
                        int(bool(item.get("review_required"))),
                        item.get("error_kind"),
                        item.get("error"),
                    ),
                )
            connection.commit()

    def list_run_items(self, run_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM run_items WHERE run_id = ? "
                "ORDER BY source_event_id",
                (run_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def failed_before(self, source_event_id: str, run_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM run_items i
                JOIN runs r ON r.id = i.run_id
                WHERE i.source_event_id = ? AND i.run_id <> ?
                  AND (i.status = 'failed' OR r.status = 'failed')
                LIMIT 1
                """,
                (source_event_id, run_id),
            ).fetchone()
        return row is not None

    def upsert_event(
        self, event: Mapping[str, Any], run_id: str | None = None
    ) -> bool:
        source_event_id = str(event["source_event_id"])
        now = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT product_digest, version, first_seen_at FROM events "
                "WHERE source_event_id = ?",
                (source_event_id,),
            ).fetchone()
            if (
                existing is not None
                and existing["product_digest"] == event["product_digest"]
            ):
                connection.commit()
                return False
            version = 1 if existing is None else int(existing["version"]) + 1
            first_seen = now if existing is None else str(existing["first_seen_at"])
            values = (
                source_event_id,
                event.get("source", "lazarus.day"),
                event["source_record_id"],
                event["source_url"],
                event.get("original_url"),
                event["content_sha256"],
                event["product_digest"],
                version,
                event.get("title") or "Untitled source report",
                event.get("description"),
                event.get("event_time"),
                event.get("report_time"),
                event.get("collected_at"),
                now,
                first_seen,
                event["quality_status"],
                int(bool(event["review_required"])),
                event.get("organization_id"),
                event.get("organization_name"),
                event.get("threat_type"),
                event.get("releasing_product"),
                event.get("primary_link"),
                json.dumps(event["structured"], ensure_ascii=False, sort_keys=True),
                json.dumps(event["evidence"], ensure_ascii=False, sort_keys=True),
                json.dumps(event["provenance"], ensure_ascii=False, sort_keys=True),
                json.dumps(event["quality"], ensure_ascii=False, sort_keys=True),
                event["raw_relpath"],
                int(event["raw_line"]),
                event["raw_line_sha256"],
                run_id,
            )
            connection.execute(
                """
                INSERT INTO events (
                    source_event_id, source, source_record_id, source_url,
                    original_url, content_sha256, product_digest, version,
                    title, description, event_time, report_time, collected_at,
                    updated_at, first_seen_at, quality_status, review_required,
                    organization_id, organization_name, threat_type,
                    releasing_product, primary_link, structured_json,
                    evidence_json, provenance_json, quality_json, raw_relpath,
                    raw_line, raw_line_sha256, last_run_id
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                ON CONFLICT(source_event_id) DO UPDATE SET
                    source_record_id = excluded.source_record_id,
                    source_url = excluded.source_url,
                    original_url = excluded.original_url,
                    content_sha256 = excluded.content_sha256,
                    product_digest = excluded.product_digest,
                    version = excluded.version,
                    title = excluded.title,
                    description = excluded.description,
                    event_time = excluded.event_time,
                    report_time = excluded.report_time,
                    collected_at = excluded.collected_at,
                    updated_at = excluded.updated_at,
                    quality_status = excluded.quality_status,
                    review_required = excluded.review_required,
                    organization_id = excluded.organization_id,
                    organization_name = excluded.organization_name,
                    threat_type = excluded.threat_type,
                    releasing_product = excluded.releasing_product,
                    primary_link = excluded.primary_link,
                    structured_json = excluded.structured_json,
                    evidence_json = excluded.evidence_json,
                    provenance_json = excluded.provenance_json,
                    quality_json = excluded.quality_json,
                    raw_relpath = excluded.raw_relpath,
                    raw_line = excluded.raw_line,
                    raw_line_sha256 = excluded.raw_line_sha256,
                    last_run_id = excluded.last_run_id
                """,
                values,
            )
            connection.execute(
                """
                INSERT INTO event_changes (
                    source_event_id, operation, version, run_id, changed_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    source_event_id,
                    "created" if existing is None else "updated",
                    version,
                    run_id,
                    now,
                ),
            )
            connection.commit()
        return True

    def get_event(self, source_event_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM events WHERE source_event_id = ?",
                (source_event_id,),
            ).fetchone()
        return self._row(row)

    def count_events(self) -> int:
        with self._connect() as connection:
            return int(
                connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            )

    def count_changes(self) -> int:
        with self._connect() as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM event_changes"
                ).fetchone()[0]
            )

    def list_changes(
        self, after_seq: int, limit: int
    ) -> tuple[list[dict[str, Any]], bool]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT c.seq AS change_seq, c.operation,
                       c.version AS change_version, c.changed_at, e.*
                FROM event_changes c
                JOIN events e ON e.source_event_id = c.source_event_id
                WHERE c.seq > ? ORDER BY c.seq LIMIT ?
                """,
                (after_seq, limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        return [dict(row) for row in rows[:limit]], has_more
