#!/usr/bin/env python3
"""Bootstrap APTHunter database schema, migrations and seed data.

This script is the deployment-time database entrypoint. Deployment shell
scripts should call it instead of embedding business SQL directly.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
from pathlib import Path
from typing import Iterable

import pymysql
from pymysql.constants import CLIENT
from sqlalchemy.engine import make_url


CURRENT_ENUM_MODEL_CATEGORY = "ENUM('malicious','impersonation','dga','history_similarity','apt_template_nrd')"
CURRENT_ENUM_TASK_TYPE = "ENUM('malicious','impersonation','malicious_ip','dga','history_similarity','apt_template_nrd')"

# These migrations are represented by init SQL plus the compatibility stage
# below. They are not reliably idempotent, so adopting an existing database
# records them instead of replaying them.
BOOTSTRAP_COVERED_MIGRATIONS = {
    "001_alert_details.sql",
    "002_alerts_feishu_notify.sql",
    "003_alert_domain_match_rule_v2.sql",
    "004_subscription_nullable_threshold.sql",
    "005_add_malicious_ip_task_type.sql",
    "006_add_tasks_created_by_created_at_index.sql",
    "007_add_dga_detection_task.sql",
    "008_add_history_similarity_detection_task.sql",
    "009_switch_dga_binary_detector.sql",
    "010_add_apt_template_nrd_detection_task.sql",
    "010_switch_dga_local_family_model.sql",
    "011_add_domain_monitoring.sql",
    "012_update_templated_apt_domain_model.sql",
}

CORE_INIT_FILES = (
    "00_init.sql",
    "01_schema.sql",
    "02_dashboard.sql",
    "06_actor_matcher_schema.sql",
)


def log(message: str) -> None:
    print(f"[db-bootstrap] {message}", flush=True)


def fail(message: str) -> None:
    print(f"[db-bootstrap] ERROR: {message}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def resolve_db_dir() -> Path:
    explicit = os.getenv("APTHUNTER_DB_DIR")
    if explicit:
        return Path(explicit).expanduser().resolve()

    script_path = Path(__file__).resolve()
    candidates = [
        script_path.parents[1] / "db",  # backend/scripts -> backend/db
        script_path.parents[1].parent / "db",
        Path("/app/db"),
        Path.cwd().parent / "db",
    ]
    for candidate in candidates:
        if (candidate / "init").is_dir() and (candidate / "migrations").is_dir():
            return candidate.resolve()
    fail("cannot locate backend/db; set APTHUNTER_DB_DIR")


def parse_mysql_url() -> dict:
    mysql_url = os.getenv("MYSQL_URL", "").strip()
    if not mysql_url:
        fail("MYSQL_URL is required")
    url = make_url(mysql_url)
    if not url.drivername.startswith("mysql"):
        fail(f"MYSQL_URL must use a MySQL driver, got: {url.drivername}")
    if not url.database:
        fail("MYSQL_URL must include database name")
    return {
        "host": url.host or "127.0.0.1",
        "port": int(url.port or 3306),
        "user": url.username or "",
        "password": url.password or "",
        "database": url.database,
        "charset": "utf8mb4",
        "autocommit": True,
        "local_infile": True,
        "client_flag": CLIENT.MULTI_STATEMENTS,
    }


def connect_with_retry(retries: int, delay: float):
    params = parse_mysql_url()
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            conn = pymysql.connect(**params)
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
            return conn
        except Exception as exc:
            last_error = exc
            log(f"waiting for MySQL ({attempt}/{retries}): {exc}")
            time.sleep(delay)
    fail(f"cannot connect to MySQL after {retries} attempts: {last_error}")


def execute_sql(conn, sql: str, *, label: str) -> None:
    sql = sql.strip()
    if not sql:
        return
    with conn.cursor() as cursor:
        cursor.execute(sql)
        while True:
            try:
                cursor.fetchall()
            except Exception:
                pass
            if not cursor.nextset():
                break
    log(f"executed {label}")


def execute_sql_file(conn, path: Path) -> None:
    execute_sql(conn, path.read_text(encoding="utf-8"), label=str(path.relative_to(path.parents[2])))


def query_scalar(conn, sql: str, params: tuple = ()):
    with conn.cursor() as cursor:
        cursor.execute(sql, params)
        row = cursor.fetchone()
    return row[0] if row else None


def table_exists(conn, table_name: str) -> bool:
    return bool(
        query_scalar(
            conn,
            """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
              AND table_name = %s
            """,
            (table_name,),
        )
    )


def column_exists(conn, table_name: str, column_name: str) -> bool:
    return bool(
        query_scalar(
            conn,
            """
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = %s
              AND column_name = %s
            """,
            (table_name, column_name),
        )
    )


def index_exists(conn, table_name: str, index_name: str) -> bool:
    return bool(
        query_scalar(
            conn,
            """
            SELECT COUNT(*)
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = %s
              AND index_name = %s
            """,
            (table_name, index_name),
        )
    )


def create_schema_migrations(conn) -> None:
    execute_sql(
        conn,
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
          filename VARCHAR(255) NOT NULL PRIMARY KEY,
          checksum CHAR(64) NOT NULL,
          applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """,
        label="schema_migrations table",
    )


def migration_record_exists(conn, filename: str) -> str | None:
    return query_scalar(
        conn,
        "SELECT checksum FROM schema_migrations WHERE filename = %s LIMIT 1",
        (filename,),
    )


def record_migration(conn, filename: str, checksum: str) -> None:
    with conn.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO schema_migrations (filename, checksum)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE checksum = VALUES(checksum)
            """,
            (filename, checksum),
        )


def file_checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_init_if_needed(conn, db_dir: Path) -> None:
    if table_exists(conn, "users") and table_exists(conn, "models"):
        log("core tables already exist; init SQL skipped")
        return

    log("core tables missing; running stable core init SQL files")
    init_dir = db_dir / "init"
    for filename in CORE_INIT_FILES:
        path = init_dir / filename
        if path.exists():
            execute_sql_file(conn, path)


def ensure_column(conn, table_name: str, column_name: str, ddl: str) -> None:
    if column_exists(conn, table_name, column_name):
        return
    execute_sql(conn, ddl, label=f"add column {table_name}.{column_name}")


def ensure_index(conn, table_name: str, index_name: str, ddl: str) -> None:
    if index_exists(conn, table_name, index_name):
        return
    execute_sql(conn, ddl, label=f"add index {table_name}.{index_name}")


def ensure_current_schema(conn, db_dir: Path) -> None:
    log("ensuring current schema compatibility")

    safe_schema_files = [
        db_dir / "init" / "01_schema.sql",
        db_dir / "init" / "02_dashboard.sql",
        db_dir / "init" / "06_actor_matcher_schema.sql",
        db_dir / "migrations" / "011_add_domain_monitoring.sql",
    ]
    for path in safe_schema_files:
        if path.exists():
            execute_sql_file(conn, path)

    compatibility_sql = f"""
    ALTER TABLE subscriptions
      MODIFY COLUMN threshold INT NULL DEFAULT NULL;

    ALTER TABLE alerts
      MODIFY COLUMN threshold INT NULL DEFAULT NULL;

    ALTER TABLE models
      MODIFY COLUMN model_category {CURRENT_ENUM_MODEL_CATEGORY} DEFAULT NULL;

    ALTER TABLE tasks
      MODIFY COLUMN task_type {CURRENT_ENUM_TASK_TYPE} NOT NULL COMMENT '任务类型';

    ALTER TABLE training_tasks
      MODIFY COLUMN model_category {CURRENT_ENUM_MODEL_CATEGORY} NOT NULL DEFAULT 'malicious';

    ALTER TABLE alerts
      MODIFY COLUMN task_type {CURRENT_ENUM_TASK_TYPE} NOT NULL COMMENT '任务类型：恶意域名检测/仿冒域名检测/恶意IP检测/DGA域名检测/历史APT域名相似性检测/模板化APT域名检测';

    ALTER TABLE alert_files
      MODIFY COLUMN task_type {CURRENT_ENUM_TASK_TYPE} NOT NULL COMMENT '任务类型';
    """
    execute_sql(conn, compatibility_sql, label="current enum/threshold compatibility")

    if table_exists(conn, "alerts"):
        ensure_column(
            conn,
            "alerts",
            "feishu_notified",
            """
            ALTER TABLE alerts
              ADD COLUMN feishu_notified TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否已成功推送飞书' AFTER status
            """,
        )
        ensure_column(
            conn,
            "alerts",
            "feishu_notified_at",
            """
            ALTER TABLE alerts
              ADD COLUMN feishu_notified_at DATETIME NULL COMMENT '飞书推送成功时间' AFTER feishu_notified
            """,
        )

    if table_exists(conn, "tasks"):
        ensure_index(
            conn,
            "tasks",
            "idx_tasks_created_by_created_at",
            "CREATE INDEX idx_tasks_created_by_created_at ON tasks (created_by, created_at)",
        )

    if table_exists(conn, "alert_domain_matches"):
        execute_sql(
            conn,
            "ALTER TABLE alert_domain_matches ALTER COLUMN match_method SET DEFAULT 'rule_v2_infra'",
            label="alert_domain_matches.match_method default",
        )

    execute_sql(
        conn,
        """
        CREATE TABLE IF NOT EXISTS alert_details (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            alert_id VARCHAR(64) NOT NULL COMMENT '预警ID，关联 alerts.alert_id',
            high_risk_domains JSON NULL COMMENT '高风险域名列表（JSON数组）',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uk_alert_id (alert_id),
            CONSTRAINT fk_alert_details_alert_id FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='预警详情表（高风险域名等大字段）'
        """,
        label="alert_details table",
    )


def seed_current_data(conn, db_dir: Path) -> None:
    log("ensuring current seed data")
    seed_files = [
        db_dir / "init" / "05_seed_core_data.sql",
        db_dir / "migrations" / "010_switch_dga_local_family_model.sql",
        db_dir / "migrations" / "012_update_templated_apt_domain_model.sql",
    ]
    for path in seed_files:
        if path.exists():
            execute_sql_file(conn, path)

    execute_sql(
        conn,
        """
        INSERT INTO user_models (user_id, model_id, acquired_at, is_active, source)
        SELECT u.id, m.id, NOW(), 1, 'official'
        FROM users u
        JOIN models m
          ON m.model_type = 'official'
         AND m.status = 'active'
        WHERE NOT EXISTS (
          SELECT 1
          FROM user_models um
          WHERE um.user_id = u.id
            AND um.model_id = m.id
        )
        """,
        label="official model bindings for all users",
    )


def migration_files(db_dir: Path) -> list[Path]:
    return sorted((db_dir / "migrations").glob("*.sql"), key=lambda item: item.name)


def record_bootstrap_covered_migrations(conn, files: Iterable[Path]) -> None:
    for path in files:
        if path.name not in BOOTSTRAP_COVERED_MIGRATIONS:
            continue
        checksum = file_checksum(path)
        record_migration(conn, path.name, checksum)
        log(f"recorded bootstrap-covered migration: {path.name}")


def apply_unrecorded_migrations(conn, db_dir: Path) -> None:
    for path in migration_files(db_dir):
        checksum = file_checksum(path)
        existing = migration_record_exists(conn, path.name)
        if existing:
            if existing != checksum:
                fail(f"migration checksum changed after being applied: {path.name}")
            log(f"skipping already applied migration: {path.name}")
            continue

        log(f"applying migration: {path.name}")
        execute_sql_file(conn, path)
        record_migration(conn, path.name, checksum)


def validate_current_state(conn) -> None:
    checks = {
        "active official DGA v2 model": """
            SELECT COUNT(*)
            FROM models
            WHERE model_category = 'dga'
              AND model_type = 'official'
              AND status = 'active'
              AND model_path = 'saved_model/dga_detection_local_model'
        """,
        "active official template APT model": """
            SELECT COUNT(*)
            FROM models
            WHERE model_category = 'apt_template_nrd'
              AND model_type = 'official'
              AND status = 'active'
        """,
        "active official history similarity model": """
            SELECT COUNT(*)
            FROM models
            WHERE model_category = 'history_similarity'
              AND model_type = 'official'
              AND status = 'active'
        """,
        "admin user": "SELECT COUNT(*) FROM users WHERE username = 'admin'",
    }
    for label, sql in checks.items():
        value = int(query_scalar(conn, sql) or 0)
        if value <= 0:
            fail(f"validation failed: missing {label}")
        log(f"validated {label}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap APTHunter database")
    parser.add_argument("--skip-init", action="store_true", help="do not run init SQL when core tables are missing")
    parser.add_argument("--skip-migrations", action="store_true", help="do not apply unrecorded migration files")
    parser.add_argument("--skip-seed", action="store_true", help="do not apply current seed data")
    parser.add_argument("--wait-retries", type=int, default=int(os.getenv("DB_BOOTSTRAP_WAIT_RETRIES", "60")))
    parser.add_argument("--wait-delay", type=float, default=float(os.getenv("DB_BOOTSTRAP_WAIT_DELAY", "2")))
    args = parser.parse_args()

    db_dir = resolve_db_dir()
    log(f"db directory: {db_dir}")

    conn = connect_with_retry(args.wait_retries, args.wait_delay)
    try:
        if not args.skip_init:
            run_init_if_needed(conn, db_dir)
        else:
            log("init SQL skipped by request")

        create_schema_migrations(conn)
        ensure_current_schema(conn, db_dir)

        if not args.skip_seed:
            seed_current_data(conn, db_dir)
        else:
            log("seed data skipped by request")

        migrations = migration_files(db_dir)
        record_bootstrap_covered_migrations(conn, migrations)

        if not args.skip_migrations:
            apply_unrecorded_migrations(conn, db_dir)
        else:
            log("migration execution skipped by request")

        validate_current_state(conn)
        log("database bootstrap complete")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
