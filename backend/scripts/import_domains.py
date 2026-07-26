#!/usr/bin/env python3
"""将版本化域名 CSV 幂等导入 domains 表。

设计约束：
- CSV 的 id 仅用于原始数据标识，导入时不会写入，避免不同环境自增主键冲突。
- domain_name 统一转为小写并去除首尾空白，按首次出现记录去重。
- 已标记为恶意的域名不会被后续良性记录降级。
- 默认保留数据库中已有组织关联，仅为空时使用 CSV 的 organization_id。
- first_seen 取更早日期，last_seen 取更晚日期，空日期不会覆盖已有值。
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

import pymysql
from sqlalchemy.engine import make_url


STANDARD_DOMAIN_PATTERN = re.compile(r"^[a-z0-9.-]+$")
REQUIRED_COLUMNS = {"domain_name"}


@dataclass(frozen=True)
class DomainRecord:
    domain_name: str
    is_malicious: int
    first_seen: date | None
    last_seen: date | None
    organization_id: int | None

    def as_params(self) -> tuple[Any, ...]:
        return (
            self.domain_name,
            self.is_malicious,
            self.first_seen,
            self.last_seen,
            self.organization_id,
        )


def log(message: str) -> None:
    print(f"[domain-import] {message}", flush=True)


def fail(message: str) -> None:
    print(f"[domain-import] ERROR: {message}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def default_csv_path() -> Path:
    return Path(__file__).resolve().parents[1] / "db" / "init" / "domains.csv"


def parse_date(value: Any, *, row_number: int, column: str) -> date | None:
    text = str(value or "").strip()
    if not text:
        return None

    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return date(1899, 12, 30) + timedelta(days=int(float(text)))

    normalized = text.replace("/", "-")
    for parser in (
        date.fromisoformat,
        lambda item: datetime.strptime(item, "%Y-%m-%d %H:%M:%S").date(),
    ):
        try:
            return parser(normalized)
        except ValueError:
            continue
    raise ValueError(f"第 {row_number} 行 {column} 日期无效: {text}")


def parse_malicious_flag(value: Any, *, row_number: int) -> int:
    text = str(value or "").strip().lower()
    if not text:
        return 1
    if text in {"1", "true", "yes", "y", "恶意"}:
        return 1
    if text in {"0", "false", "no", "n", "良性"}:
        return 0
    raise ValueError(f"第 {row_number} 行 is_malicious 无效: {value}")


def parse_organization_id(value: Any, *, row_number: int) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        organization_id = int(text)
    except ValueError as exc:
        raise ValueError(f"第 {row_number} 行 organization_id 无效: {value}") from exc
    if organization_id <= 0:
        raise ValueError(f"第 {row_number} 行 organization_id 必须为正整数: {value}")
    return organization_id


def load_records(csv_path: Path) -> tuple[list[DomainRecord], dict[str, Any]]:
    if not csv_path.is_file():
        fail(f"CSV 文件不存在: {csv_path}")

    records_by_domain: dict[str, DomainRecord] = {}
    duplicate_count = 0
    conflicting_organization_count = 0
    nonstandard_domains: list[str] = []
    raw_count = 0
    errors: list[str] = []

    with csv_path.open("r", encoding="utf-8-sig", newline="") as file_handle:
        reader = csv.DictReader(file_handle)
        columns = set(reader.fieldnames or [])
        missing_columns = sorted(REQUIRED_COLUMNS - columns)
        if missing_columns:
            fail(f"CSV 缺少必要字段: {', '.join(missing_columns)}")

        for row_number, row in enumerate(reader, start=2):
            raw_count += 1
            domain_name = str(row.get("domain_name") or "").strip().lower()
            if not domain_name:
                errors.append(f"第 {row_number} 行 domain_name 为空")
                continue
            if len(domain_name) > 255:
                errors.append(f"第 {row_number} 行域名超过 255 字符: {domain_name[:80]}")
                continue

            try:
                record = DomainRecord(
                    domain_name=domain_name,
                    is_malicious=parse_malicious_flag(
                        row.get("is_malicious"),
                        row_number=row_number,
                    ),
                    first_seen=parse_date(
                        row.get("first_seen"),
                        row_number=row_number,
                        column="first_seen",
                    ),
                    last_seen=parse_date(
                        row.get("last_seen"),
                        row_number=row_number,
                        column="last_seen",
                    ),
                    organization_id=parse_organization_id(
                        row.get("organization_id"),
                        row_number=row_number,
                    ),
                )
            except ValueError as exc:
                errors.append(str(exc))
                continue

            if not STANDARD_DOMAIN_PATTERN.fullmatch(domain_name):
                nonstandard_domains.append(domain_name)

            existing = records_by_domain.get(domain_name)
            if existing is not None:
                duplicate_count += 1
                if existing.organization_id != record.organization_id:
                    conflicting_organization_count += 1
                continue
            records_by_domain[domain_name] = record

    if errors:
        preview = "\n".join(f"  - {item}" for item in errors[:20])
        suffix = f"\n  ... 另有 {len(errors) - 20} 项" if len(errors) > 20 else ""
        fail(f"CSV 校验失败，共 {len(errors)} 项:\n{preview}{suffix}")

    records = list(records_by_domain.values())
    summary = {
        "csv_path": str(csv_path),
        "raw_rows": raw_count,
        "unique_domains": len(records),
        "duplicate_rows_ignored": duplicate_count,
        "duplicate_organization_conflicts": conflicting_organization_count,
        "nonstandard_domain_count": len(set(nonstandard_domains)),
        "nonstandard_domain_examples": sorted(set(nonstandard_domains))[:10],
        "csv_id_policy": "ignored",
        "duplicate_policy": "first occurrence wins",
    }
    return records, summary


def parse_mysql_url(mysql_url: str) -> dict[str, Any]:
    if not mysql_url.strip():
        fail("缺少 MYSQL_URL；请通过环境变量或 --mysql-url 提供")
    url = make_url(mysql_url)
    if not url.drivername.startswith("mysql"):
        fail(f"MYSQL_URL 必须是 MySQL 连接: {url.drivername}")
    if not url.database:
        fail("MYSQL_URL 必须包含数据库名")
    return {
        "host": url.host or "127.0.0.1",
        "port": int(url.port or 3306),
        "user": url.username or "",
        "password": url.password or "",
        "database": url.database,
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
        "autocommit": False,
    }


def chunks(items: list[DomainRecord], size: int) -> Iterable[list[DomainRecord]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def load_existing_domains(cursor) -> dict[str, dict[str, Any]]:
    cursor.execute(
        """
        SELECT domain_name, is_malicious, organization_id, first_seen, last_seen
        FROM domains
        """
    )
    return {
        str(row["domain_name"]).strip().lower(): row
        for row in cursor.fetchall()
    }


def validate_organization_ids(cursor, records: list[DomainRecord]) -> None:
    required_ids = {
        record.organization_id
        for record in records
        if record.organization_id is not None
    }
    if not required_ids:
        return
    cursor.execute("SELECT id FROM apt_organizations")
    existing_ids = {int(row["id"]) for row in cursor.fetchall()}
    missing_ids = sorted(required_ids - existing_ids)
    if missing_ids:
        fail(
            "CSV 引用了不存在的 APT 组织 ID: "
            + ", ".join(str(item) for item in missing_ids)
        )


def build_plan(
    records: list[DomainRecord],
    existing: dict[str, dict[str, Any]],
) -> dict[str, int]:
    new_count = 0
    existing_count = 0
    promote_count = 0
    organization_fill_count = 0
    for record in records:
        current = existing.get(record.domain_name)
        if current is None:
            new_count += 1
            continue
        existing_count += 1
        if record.is_malicious and not int(current.get("is_malicious") or 0):
            promote_count += 1
        if current.get("organization_id") is None and record.organization_id is not None:
            organization_fill_count += 1
    return {
        "new_domains": new_count,
        "existing_domains": existing_count,
        "promote_to_malicious": promote_count,
        "fill_missing_organization": organization_fill_count,
    }


def upsert_sql(*, sync_organization: bool) -> str:
    if sync_organization:
        organization_update = (
            "organization_id = COALESCE(VALUES(organization_id), organization_id)"
        )
    else:
        organization_update = (
            "organization_id = COALESCE(organization_id, VALUES(organization_id))"
        )

    return f"""
        INSERT INTO domains (
            domain_name,
            is_malicious,
            first_seen,
            last_seen,
            organization_id
        ) VALUES (%s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            is_malicious = GREATEST(
                COALESCE(is_malicious, 0),
                COALESCE(VALUES(is_malicious), 0)
            ),
            first_seen = CASE
                WHEN VALUES(first_seen) IS NULL THEN first_seen
                WHEN first_seen IS NULL THEN VALUES(first_seen)
                ELSE LEAST(first_seen, VALUES(first_seen))
            END,
            last_seen = CASE
                WHEN VALUES(last_seen) IS NULL THEN last_seen
                WHEN last_seen IS NULL THEN VALUES(last_seen)
                ELSE GREATEST(last_seen, VALUES(last_seen))
            END,
            {organization_update}
    """


def import_records(
    *,
    mysql_url: str,
    records: list[DomainRecord],
    csv_summary: dict[str, Any],
    batch_size: int,
    dry_run: bool,
    sync_organization: bool,
) -> dict[str, Any]:
    connection = pymysql.connect(**parse_mysql_url(mysql_url))
    try:
        with connection.cursor() as cursor:
            validate_organization_ids(cursor, records)
            existing = load_existing_domains(cursor)
            plan = build_plan(records, existing)
            before = {
                "total_domains": len(existing),
                "malicious_domains": sum(
                    1
                    for row in existing.values()
                    if int(row.get("is_malicious") or 0) == 1
                ),
            }

            result = {
                **csv_summary,
                **plan,
                "before": before,
                "dry_run": dry_run,
                "sync_organization": sync_organization,
            }
            if dry_run:
                return result

            sql = upsert_sql(sync_organization=sync_organization)
            processed = 0
            for batch in chunks(records, batch_size):
                cursor.executemany(sql, [record.as_params() for record in batch])
                processed += len(batch)
                log(f"已处理 {processed}/{len(records)}")

            cursor.execute(
                """
                SELECT
                    COUNT(*) AS total_domains,
                    COALESCE(SUM(is_malicious = 1), 0) AS malicious_domains
                FROM domains
                """
            )
            after = cursor.fetchone()
            connection.commit()
            result["after"] = {
                "total_domains": int(after["total_domains"]),
                "malicious_domains": int(after["malicious_domains"]),
            }
            result["imported_records"] = processed
            return result
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="幂等导入 APTHunter domains.csv",
    )
    parser.add_argument(
        "--file",
        default=str(default_csv_path()),
        help="域名 CSV 路径，默认 backend/db/init/domains.csv",
    )
    parser.add_argument(
        "--mysql-url",
        default=os.getenv("MYSQL_URL", ""),
        help="MySQL SQLAlchemy URL，默认读取 MYSQL_URL",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="每批写入数量，默认 1000",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只校验并显示导入计划，不写数据库",
    )
    parser.add_argument(
        "--sync-organization",
        action="store_true",
        help="CSV 有 organization_id 时同步覆盖数据库关联；默认仅补空值",
    )
    args = parser.parse_args()

    if args.batch_size <= 0:
        fail("--batch-size 必须大于 0")

    csv_path = Path(args.file).expanduser().resolve()
    records, csv_summary = load_records(csv_path)
    log(
        f"CSV 校验完成 raw={csv_summary['raw_rows']} "
        f"unique={csv_summary['unique_domains']} "
        f"duplicates={csv_summary['duplicate_rows_ignored']}"
    )
    if csv_summary["nonstandard_domain_count"]:
        log(
            "警告：保留 "
            f"{csv_summary['nonstandard_domain_count']} 个非标准域名指标"
        )

    result = import_records(
        mysql_url=args.mysql_url,
        records=records,
        csv_summary=csv_summary,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
        sync_organization=args.sync_organization,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
