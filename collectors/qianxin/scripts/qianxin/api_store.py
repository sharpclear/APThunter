from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


ACTIVE_RUN_STATUSES = ("queued", "running")
TERMINAL_RUN_STATUSES = (
    "completed",
    "completed_with_review",
    "failed",
    "interrupted",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class StoreConflict(RuntimeError):
    """Raised when a second active collection run is requested."""

    def __init__(self, active_run_id: str) -> None:
        super().__init__(f"run already active: {active_run_id}")
        self.active_run_id = active_run_id


class ApiStore:
    """Small SQLite repository used by the API and its durable worker.

    Connections are deliberately short lived.  This keeps the store safe when FastAPI
    request threads and the single worker thread use it at the same time.
    """

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
                        native_status TEXT,
                        native_run_id TEXT,
                        pid INTEGER,
                        exit_code INTEGER,
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
                        completed_count INTEGER NOT NULL DEFAULT 0,
                        review_count INTEGER NOT NULL DEFAULT 0,
                        failed_count INTEGER NOT NULL DEFAULT 0
                    );

                    CREATE UNIQUE INDEX IF NOT EXISTS uq_runs_one_active
                    ON runs ((1)) WHERE status IN ('queued', 'running');

                    CREATE INDEX IF NOT EXISTS ix_runs_created_at
                    ON runs (created_at DESC);

                    CREATE TABLE IF NOT EXISTS run_items (
                        run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                        sha256 TEXT NOT NULL,
                        origin TEXT NOT NULL DEFAULT 'current',
                        status TEXT NOT NULL,
                        organization TEXT,
                        review_required INTEGER NOT NULL DEFAULT 0,
                        error_kind TEXT,
                        error TEXT,
                        PRIMARY KEY (run_id, sha256)
                    );

                    CREATE TABLE IF NOT EXISTS reports (
                        sha256 TEXT PRIMARY KEY,
                        organization_id TEXT,
                        organization_name TEXT NOT NULL,
                        report_title TEXT NOT NULL,
                        report_date TEXT,
                        collected_at TEXT,
                        pdf_relpath TEXT NOT NULL,
                        summary_relpath TEXT NOT NULL,
                        quality_relpath TEXT NOT NULL,
                        markdown_relpath TEXT,
                        file_size INTEGER NOT NULL,
                        page_count INTEGER NOT NULL,
                        quality_status TEXT NOT NULL,
                        review_required INTEGER NOT NULL,
                        model_name TEXT,
                        prompt_version TEXT,
                        validator_version TEXT,
                        parsed_content_sha256 TEXT,
                        product_digest TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        first_seen_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        last_run_id TEXT REFERENCES runs(id) ON DELETE SET NULL
                    );

                    CREATE TABLE IF NOT EXISTS report_changes (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        sha256 TEXT NOT NULL REFERENCES reports(sha256) ON DELETE CASCADE,
                        operation TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
                        changed_at TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS ix_report_changes_sha
                    ON report_changes (sha256, seq);
                    """
                )
                now = utc_now()
                running = connection.execute(
                    "SELECT id FROM runs WHERE status = 'running'"
                ).fetchall()
                for row in running:
                    connection.execute(
                        """
                        UPDATE runs
                        SET status = 'queued', pid = NULL, available_at = ?, updated_at = ?,
                            error = CASE
                                WHEN error IS NULL OR error = '' THEN 'API restarted; run requeued.'
                                ELSE error
                            END
                        WHERE id = ? AND status = 'running'
                        """,
                        (now, now, row["id"]),
                    )

    def ping(self) -> bool:
        try:
            with self._connect() as connection:
                return connection.execute("SELECT 1").fetchone()[0] == 1
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
                "SELECT id FROM runs WHERE status IN ('queued', 'running') LIMIT 1"
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
                        json.dumps(dict(request), ensure_ascii=False, sort_keys=True),
                        now,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError:
                active = connection.execute(
                    "SELECT id FROM runs WHERE status IN ('queued', 'running') LIMIT 1"
                ).fetchone()
                connection.rollback()
                if active is not None:
                    raise StoreConflict(str(active["id"]))
                raise
            row = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            connection.commit()
        if row is None:
            raise RuntimeError("new run disappeared before commit")
        return dict(row), True

    def claim_next_run(self) -> dict[str, Any] | None:
        now = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT * FROM runs
                WHERE status = 'queued' AND available_at <= ?
                ORDER BY created_at, id
                LIMIT 1
                """,
                (now,),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            updated = connection.execute(
                """
                UPDATE runs
                SET status = 'running', started_at = COALESCE(started_at, ?),
                    updated_at = ?, attempts = attempts + 1, error = NULL
                WHERE id = ? AND status = 'queued'
                """,
                (now, now, row["id"]),
            )
            if updated.rowcount != 1:
                connection.rollback()
                return None
            claimed = connection.execute(
                "SELECT * FROM runs WHERE id = ?", (row["id"],)
            ).fetchone()
            connection.commit()
        return self._row(claimed)

    def set_run_process(
        self,
        run_id: str,
        *,
        pid: int,
        log_relpath: str,
        manifest_relpath: str,
    ) -> None:
        now = utc_now()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE runs
                SET pid = ?, log_relpath = ?, manifest_relpath = ?, updated_at = ?
                WHERE id = ? AND status = 'running'
                """,
                (pid, log_relpath, manifest_relpath, now, run_id),
            )

    def finish_run(
        self,
        run_id: str,
        *,
        status: str,
        exit_code: int | None,
        native_status: str | None,
        native_run_id: str | None,
        error: str | None,
        counts: Mapping[str, int] | None = None,
    ) -> None:
        if status not in TERMINAL_RUN_STATUSES:
            raise ValueError(f"invalid terminal run status: {status}")
        now = utc_now()
        counts = counts or {}
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE runs
                SET status = ?, exit_code = ?, native_status = ?, native_run_id = ?,
                    pid = NULL, error = ?, completed_at = ?, updated_at = ?,
                    discovered_count = ?, completed_count = ?, review_count = ?,
                    failed_count = ?
                WHERE id = ?
                """,
                (
                    status,
                    exit_code,
                    native_status,
                    native_run_id,
                    error,
                    now,
                    now,
                    int(counts.get("discovered", 0)),
                    int(counts.get("completed", 0)),
                    int(counts.get("review", 0)),
                    int(counts.get("failed", 0)),
                    run_id,
                ),
            )

    def reschedule_run(self, run_id: str, *, available_at: str, error: str) -> None:
        now = utc_now()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE runs
                SET status = 'queued', pid = NULL, exit_code = 20, error = ?,
                    updated_at = ?, available_at = ?
                WHERE id = ? AND status = 'running'
                """,
                (error, now, available_at, run_id),
            )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return self._row(row)

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM runs ORDER BY created_at DESC, id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def replace_run_items(self, run_id: str, items: Iterable[Mapping[str, Any]]) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM run_items WHERE run_id = ?", (run_id,))
            for item in items:
                connection.execute(
                    """
                    INSERT INTO run_items (
                        run_id, sha256, origin, status, organization,
                        review_required, error_kind, error
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        item["sha256"],
                        item.get("origin", "current"),
                        item.get("status", "unknown"),
                        item.get("organization"),
                        int(bool(item.get("review_required"))),
                        item.get("error_kind"),
                        item.get("error"),
                    ),
                )
            connection.commit()

    def list_run_items(self, run_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM run_items WHERE run_id = ? ORDER BY sha256", (run_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def upsert_report(self, report: Mapping[str, Any], run_id: str | None = None) -> bool:
        sha256 = str(report["sha256"])
        now = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT product_digest, version FROM reports WHERE sha256 = ?", (sha256,)
            ).fetchone()
            if existing is not None and existing["product_digest"] == report["product_digest"]:
                connection.commit()
                return False

            version = 1 if existing is None else int(existing["version"]) + 1
            first_seen_at = now
            if existing is not None:
                row = connection.execute(
                    "SELECT first_seen_at FROM reports WHERE sha256 = ?", (sha256,)
                ).fetchone()
                first_seen_at = str(row["first_seen_at"])

            values = (
                sha256,
                report.get("organization_id"),
                report.get("organization_name") or "unknown",
                report.get("report_title") or "untitled",
                report.get("report_date"),
                report.get("collected_at"),
                report["pdf_relpath"],
                report["summary_relpath"],
                report["quality_relpath"],
                report.get("markdown_relpath"),
                int(report.get("file_size") or 0),
                int(report.get("page_count") or 0),
                report["quality_status"],
                int(bool(report["review_required"])),
                report.get("model_name"),
                report.get("prompt_version"),
                report.get("validator_version"),
                report.get("parsed_content_sha256"),
                report["product_digest"],
                version,
                first_seen_at,
                now,
                run_id,
            )
            connection.execute(
                """
                INSERT INTO reports (
                    sha256, organization_id, organization_name, report_title,
                    report_date, collected_at, pdf_relpath, summary_relpath,
                    quality_relpath, markdown_relpath, file_size, page_count,
                    quality_status, review_required, model_name, prompt_version,
                    validator_version, parsed_content_sha256, product_digest,
                    version, first_seen_at, updated_at, last_run_id
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                ON CONFLICT(sha256) DO UPDATE SET
                    organization_id = excluded.organization_id,
                    organization_name = excluded.organization_name,
                    report_title = excluded.report_title,
                    report_date = excluded.report_date,
                    collected_at = excluded.collected_at,
                    pdf_relpath = excluded.pdf_relpath,
                    summary_relpath = excluded.summary_relpath,
                    quality_relpath = excluded.quality_relpath,
                    markdown_relpath = excluded.markdown_relpath,
                    file_size = excluded.file_size,
                    page_count = excluded.page_count,
                    quality_status = excluded.quality_status,
                    review_required = excluded.review_required,
                    model_name = excluded.model_name,
                    prompt_version = excluded.prompt_version,
                    validator_version = excluded.validator_version,
                    parsed_content_sha256 = excluded.parsed_content_sha256,
                    product_digest = excluded.product_digest,
                    version = excluded.version,
                    updated_at = excluded.updated_at,
                    last_run_id = excluded.last_run_id
                """,
                values,
            )
            connection.execute(
                """
                INSERT INTO report_changes (sha256, operation, version, run_id, changed_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (sha256, "created" if existing is None else "updated", version, run_id, now),
            )
            connection.commit()
        return True

    def get_report(self, sha256: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM reports WHERE sha256 = ?", (sha256,)
            ).fetchone()
        return self._row(row)

    def count_reports(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0])

    def list_reports_for_run(self, run_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM reports WHERE last_run_id = ? ORDER BY sha256", (run_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def list_changes(self, after_seq: int, limit: int) -> tuple[list[dict[str, Any]], bool]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT c.seq AS change_seq, c.operation, c.version AS change_version,
                       c.changed_at, r.*
                FROM report_changes AS c
                JOIN reports AS r ON r.sha256 = c.sha256
                WHERE c.seq > ?
                ORDER BY c.seq
                LIMIT ?
                """,
                (after_seq, limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        return [dict(row) for row in rows[:limit]], has_more
