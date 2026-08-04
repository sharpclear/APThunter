#!/usr/bin/env python3
"""事务化、幂等导入 APT 组织和事件参考 CSV。"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable

import pymysql
from sqlalchemy.engine import make_url


ORGANIZATION_COLUMNS = {
    "id", "name", "aliases", "origin", "region", "target_countries",
    "target_industries", "update_time", "description_zh", "ioc_count",
    "event_count",
}
EVENT_COLUMNS = {
    "id", "event_date", "title", "description", "threat_type",
    "organization_id", "releasing_product", "link",
}
MAJOR_EVENT_TYPES = {"供应链攻击", "漏洞利用", "勒索软件", "APT攻击"}
HIGH_SEVERITY_TYPES = {"C2通信", "钓鱼攻击"}


@dataclass(frozen=True)
class OrganizationRecord:
    id: int
    name: str
    aliases: str
    origin: str | None
    region: str | None
    target_countries: str
    target_industries: str
    update_time: date | None
    description: str | None
    ioc_count: int
    event_count: int

    def as_params(self) -> tuple[Any, ...]:
        return (
            self.id, self.name, self.aliases, self.description,
            self.ioc_count, self.event_count, self.update_time, self.region,
            self.origin, self.target_countries, self.target_industries,
        )


@dataclass(frozen=True)
class EventRecord:
    id: int
    event_date: date
    title: str
    description: str | None
    event_type: str
    threat_type: str
    releasing_product: str | None
    region: str
    organization_id: int
    severity: int
    link: str | None

    def as_params(self) -> tuple[Any, ...]:
        return (
            self.id, self.event_date, self.title, self.description,
            self.event_type, self.threat_type, self.releasing_product,
            self.region, self.organization_id, self.severity, self.link,
        )


def log(message: str) -> None:
    print(f"[apt-reference-import] {message}", flush=True)


def fail(message: str) -> None:
    print(f"[apt-reference-import] ERROR: {message}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def default_init_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "db" / "init"


def parse_mysql_url(mysql_url: str) -> dict[str, Any]:
    if not mysql_url.strip():
        fail("缺少 MYSQL_URL；请通过环境变量或 --mysql-url 提供")
    url = make_url(mysql_url)
    if not url.drivername.startswith("mysql") or not url.database:
        fail("MYSQL_URL 必须是包含数据库名的 MySQL 连接")
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


def parse_id(value: Any, *, row_number: int, column: str) -> int:
    try:
        parsed = int(str(value or "").strip())
    except ValueError as exc:
        raise ValueError(f"第 {row_number} 行 {column} 不是有效整数: {value}") from exc
    if parsed <= 0:
        raise ValueError(f"第 {row_number} 行 {column} 必须大于 0")
    return parsed


def parse_count(value: Any, *, row_number: int, column: str) -> int:
    text = str(value or "").strip()
    if not text:
        return 0
    try:
        return max(0, int(text))
    except ValueError as exc:
        raise ValueError(f"第 {row_number} 行 {column} 不是有效整数: {value}") from exc


def parse_date(value: Any, *, row_number: int, column: str, required: bool) -> date | None:
    text = str(value or "").strip()
    if not text:
        if required:
            raise ValueError(f"第 {row_number} 行 {column} 不能为空")
        return None
    for pattern in ("%Y/%m/%d", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, pattern).date()
        except ValueError:
            continue
    raise ValueError(f"第 {row_number} 行 {column} 日期无效: {text}")


def nullable_text(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def json_list(value: Any) -> str:
    items = [item.strip() for item in str(value or "").split("|") if item.strip()]
    return json.dumps(items, ensure_ascii=False)


def read_csv(path: Path, required_columns: set[str]) -> list[dict[str, str]]:
    if not path.is_file():
        fail(f"CSV 文件不存在: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = set(reader.fieldnames or [])
        missing = sorted(required_columns - columns)
        if missing:
            fail(f"{path.name} 缺少字段: {', '.join(missing)}")
        return list(reader)


def load_organizations(path: Path) -> list[OrganizationRecord]:
    rows = read_csv(path, ORGANIZATION_COLUMNS)
    records: list[OrganizationRecord] = []
    seen_ids: set[int] = set()
    seen_names: set[str] = set()
    errors: list[str] = []
    for row_number, row in enumerate(rows, start=2):
        try:
            organization_id = parse_id(row.get("id"), row_number=row_number, column="id")
            name = str(row.get("name") or "").strip()
            if not name:
                raise ValueError(f"第 {row_number} 行 name 不能为空")
            if organization_id in seen_ids:
                raise ValueError(f"第 {row_number} 行组织 ID 重复: {organization_id}")
            if name in seen_names:
                raise ValueError(f"第 {row_number} 行组织名称重复: {name}")
            seen_ids.add(organization_id)
            seen_names.add(name)
            records.append(OrganizationRecord(
                id=organization_id,
                name=name,
                aliases=json_list(row.get("aliases")),
                origin=nullable_text(row.get("origin")),
                region=nullable_text(row.get("region")),
                target_countries=json_list(row.get("target_countries")),
                target_industries=json_list(row.get("target_industries")),
                update_time=parse_date(
                    row.get("update_time"), row_number=row_number,
                    column="update_time", required=False,
                ),
                description=nullable_text(row.get("description_zh")),
                ioc_count=parse_count(row.get("ioc_count"), row_number=row_number, column="ioc_count"),
                event_count=parse_count(row.get("event_count"), row_number=row_number, column="event_count"),
            ))
        except ValueError as exc:
            errors.append(str(exc))
    if errors:
        fail("组织 CSV 校验失败:\n" + "\n".join(f"  - {item}" for item in errors[:20]))
    return records


def load_events(
    path: Path,
    organizations: list[OrganizationRecord],
) -> list[EventRecord]:
    rows = read_csv(path, EVENT_COLUMNS)
    organization_regions = {item.id: item.region or "未知" for item in organizations}
    records: list[EventRecord] = []
    seen_ids: set[int] = set()
    errors: list[str] = []
    for row_number, row in enumerate(rows, start=2):
        try:
            event_id = parse_id(row.get("id"), row_number=row_number, column="id")
            organization_id = parse_id(
                row.get("organization_id"), row_number=row_number,
                column="organization_id",
            )
            title = str(row.get("title") or "").strip()
            threat_type = str(row.get("threat_type") or "").strip() or "未分类"
            if not title:
                raise ValueError(f"第 {row_number} 行 title 不能为空")
            if event_id in seen_ids:
                raise ValueError(f"第 {row_number} 行事件 ID 重复: {event_id}")
            if organization_id not in organization_regions:
                raise ValueError(f"第 {row_number} 行引用不存在的组织 ID: {organization_id}")
            seen_ids.add(event_id)
            event_type = "major" if threat_type in MAJOR_EVENT_TYPES else "normal"
            severity = 5 if event_type == "major" else (4 if threat_type in HIGH_SEVERITY_TYPES else 3)
            records.append(EventRecord(
                id=event_id,
                event_date=parse_date(
                    row.get("event_date"), row_number=row_number,
                    column="event_date", required=True,
                ),
                title=title,
                description=nullable_text(row.get("description")),
                event_type=event_type,
                threat_type=threat_type,
                releasing_product=nullable_text(row.get("releasing_product")),
                region=organization_regions[organization_id],
                organization_id=organization_id,
                severity=severity,
                link=nullable_text(row.get("link")),
            ))
        except ValueError as exc:
            errors.append(str(exc))
    if errors:
        fail("事件 CSV 校验失败:\n" + "\n".join(f"  - {item}" for item in errors[:20]))
    return records


def chunks(items: list[Any], size: int) -> Iterable[list[Any]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


def validate_database_schema(cursor) -> None:
    cursor.execute(
        """
        SELECT COLUMN_NAME
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'apt_events'
        """
    )
    columns = {row["COLUMN_NAME"] for row in cursor.fetchall()}
    required = {"link", "threat_type", "releasing_product"}
    missing = sorted(required - columns)
    if missing:
        fail("apt_events 尚缺少字段，请先执行数据库迁移: " + ", ".join(missing))


def import_records(
    mysql_url: str,
    organizations: list[OrganizationRecord],
    events: list[EventRecord],
    batch_size: int,
    dry_run: bool,
) -> dict[str, Any]:
    connection = pymysql.connect(**parse_mysql_url(mysql_url))
    try:
        with connection.cursor() as cursor:
            validate_database_schema(cursor)
            cursor.execute("SELECT id, alias FROM apt_organizations")
            existing_organizations = {int(row["id"]): row for row in cursor.fetchall()}
            cursor.execute("SELECT id FROM apt_events")
            existing_event_ids = {int(row["id"]) for row in cursor.fetchall()}
            alias_updates = sum(
                1 for item in organizations
                if item.id in existing_organizations
                and json.loads(existing_organizations[item.id]["alias"] or "[]") != json.loads(item.aliases)
            )
            result = {
                "organizations_in_csv": len(organizations),
                "new_organizations": sum(item.id not in existing_organizations for item in organizations),
                "organization_alias_updates": alias_updates,
                "events_in_csv": len(events),
                "new_events": sum(item.id not in existing_event_ids for item in events),
                "existing_events_updated": sum(item.id in existing_event_ids for item in events),
                "database_events_before": len(existing_event_ids),
                "dry_run": dry_run,
            }
            if dry_run:
                return result

            organization_sql = """
                INSERT INTO apt_organizations (
                    id, name, alias, description, ioc_count, event_count,
                    update_time, region, origin, target_countries,
                    target_industries, previous_domains, vps_providers
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, JSON_ARRAY(), JSON_ARRAY())
                ON DUPLICATE KEY UPDATE
                    name = VALUES(name), alias = VALUES(alias),
                    description = VALUES(description), ioc_count = VALUES(ioc_count),
                    event_count = VALUES(event_count), update_time = VALUES(update_time),
                    region = VALUES(region), origin = VALUES(origin),
                    target_countries = VALUES(target_countries),
                    target_industries = VALUES(target_industries)
            """
            event_sql = """
                INSERT INTO apt_events (
                    id, event_date, title, description, event_type, threat_type,
                    releasing_product, region, organization_id, severity, link
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    event_date = VALUES(event_date), title = VALUES(title),
                    description = VALUES(description), event_type = VALUES(event_type),
                    threat_type = VALUES(threat_type),
                    releasing_product = VALUES(releasing_product), region = VALUES(region),
                    organization_id = VALUES(organization_id), severity = VALUES(severity),
                    link = VALUES(link)
            """

            cursor.executemany(organization_sql, [item.as_params() for item in organizations])
            processed = 0
            for batch in chunks(events, batch_size):
                cursor.executemany(event_sql, [item.as_params() for item in batch])
                processed += len(batch)
                log(f"事件已处理 {processed}/{len(events)}")

            cursor.execute(
                """
                UPDATE apt_organizations o
                LEFT JOIN (
                    SELECT organization_id, COUNT(*) AS event_count
                    FROM apt_events
                    WHERE organization_id IS NOT NULL
                    GROUP BY organization_id
                ) e ON e.organization_id = o.id
                SET o.event_count = COALESCE(e.event_count, 0)
                """
            )
            cursor.execute(
                """
                INSERT INTO region_event_stats (stat_date, region, event_count, major_count)
                SELECT event_date, COALESCE(NULLIF(region, ''), '未知'),
                       COUNT(*), SUM(event_type = 'major')
                FROM apt_events
                GROUP BY event_date, COALESCE(NULLIF(region, ''), '未知')
                ON DUPLICATE KEY UPDATE
                    event_count = VALUES(event_count),
                    major_count = VALUES(major_count)
                """
            )
            cursor.execute("SELECT COUNT(*) AS count, MAX(id) AS max_id FROM apt_events")
            after = cursor.fetchone()
            connection.commit()
            result["database_events_after"] = int(after["count"])
            result["database_event_max_id"] = int(after["max_id"] or 0)
            result["imported_event_records"] = processed
            return result
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def main() -> None:
    init_dir = default_init_dir()
    parser = argparse.ArgumentParser(description="幂等导入 APT 组织和事件参考 CSV")
    parser.add_argument("--organizations", default=str(init_dir / "apt_organizations.csv"))
    parser.add_argument("--events", default=str(init_dir / "apt_events.csv"))
    parser.add_argument("--mysql-url", default=os.getenv("MYSQL_URL", ""))
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.batch_size <= 0:
        fail("--batch-size 必须大于 0")

    organizations = load_organizations(Path(args.organizations).expanduser().resolve())
    events = load_events(Path(args.events).expanduser().resolve(), organizations)
    log(f"CSV 校验完成 organizations={len(organizations)} events={len(events)}")
    result = import_records(
        args.mysql_url, organizations, events, args.batch_size, args.dry_run,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
