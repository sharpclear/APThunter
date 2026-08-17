from __future__ import annotations

import csv
import io
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .matcher import read_text_compatible
from .models import DedupDecision, ValidationError
from .normalizer import canonicalize_url, normalize_title_for_key


def normalize_legacy_date(value: str) -> str:
    cleaned = value.strip()
    for pattern in ("%Y-%m-%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(cleaned, pattern).date().isoformat()
        except ValueError:
            continue
    raise ValidationError(f"无法识别现有事件日期：{value!r}")


class EventDeduplicator:
    def __init__(self, *, allow_cross_organization_links: bool = False) -> None:
        self.allow_cross_organization_links = allow_cross_organization_links
        self._existing_links: dict[str, str] = {}
        self._existing_link_org: dict[tuple[str, str], str] = {}
        self._existing_link_org_date: dict[tuple[str, str, str], str] = {}
        self._existing_org_date_title: dict[tuple[str, str, str], str] = {}
        self._existing_org_date: dict[tuple[str, str], list[str]] = defaultdict(list)
        self._batch_links: set[str] = set()
        self._batch_lazarus_links: set[str] = set()
        self._batch_link_org: set[tuple[str, str]] = set()
        self._batch_lazarus_link_org: set[tuple[str, str]] = set()
        self._batch_link_org_date: set[tuple[str, str, str]] = set()
        self._batch_org_date_title: set[tuple[str, str, str]] = set()
        self._batch_org_date: set[tuple[str, str]] = set()
        self.encoding = ""
        self.row_count = 0

    @classmethod
    def from_csv(
        cls, path: Path, *, allow_cross_organization_links: bool = False
    ) -> "EventDeduplicator":
        instance = cls(
            allow_cross_organization_links=allow_cross_organization_links
        )
        text, encoding = read_text_compatible(path)
        instance.encoding = encoding
        reader = csv.DictReader(io.StringIO(text, newline=""))
        required = {
            "id",
            "event_date",
            "title",
            "organization_id",
            "link",
        }
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise ValidationError(
                f"现有事件 CSV 缺少字段 {sorted(required)}：{path}"
            )
        for line_number, row in enumerate(reader, start=2):
            event_id = (row.get("id") or "").strip()
            try:
                date_value = normalize_legacy_date(row.get("event_date") or "")
                link = canonicalize_url(row.get("link") or "")
            except ValidationError as exc:
                raise ValidationError(
                    f"现有事件 CSV 第 {line_number} 行无效：{exc}"
                ) from exc
            organization_id = (row.get("organization_id") or "").strip()
            title_key = normalize_title_for_key(row.get("title") or "")
            instance._existing_links.setdefault(link, event_id)
            instance._existing_link_org.setdefault(
                (link, organization_id), event_id
            )
            instance._existing_link_org_date.setdefault(
                (link, organization_id, date_value), event_id
            )
            instance._existing_org_date_title.setdefault(
                (organization_id, date_value, title_key), event_id
            )
            instance._existing_org_date[(organization_id, date_value)].append(
                event_id
            )
            instance.row_count += 1
        return instance

    def check_and_register(
        self, event: dict[str, object], *, lazarus_day_url: str
    ) -> DedupDecision:
        link = canonicalize_url(str(event["link"]))
        lazarus_link = canonicalize_url(lazarus_day_url)
        organization_id = (
            "" if event["organization_id"] is None else str(event["organization_id"])
        )
        event_date = str(event["event_date"])
        title_key = normalize_title_for_key(str(event["title"]))
        link_org_date = (link, organization_id, event_date)
        org_date_title = (organization_id, event_date, title_key)
        org_date = (organization_id, event_date)
        link_org = (link, organization_id)
        lazarus_link_org = (lazarus_link, organization_id)

        if self.allow_cross_organization_links and organization_id:
            existing_id = self._existing_link_org.get(link_org)
        else:
            existing_id = self._existing_links.get(link)
        if existing_id is not None:
            return DedupDecision(
                status="exact_duplicate",
                reason=(
                    "同一组织的规范化原始来源 URL 已存在"
                    if self.allow_cross_organization_links and organization_id
                    else "规范化原始来源 URL 已存在"
                ),
                existing_id=existing_id,
            )
        if self.allow_cross_organization_links and organization_id:
            existing_id = self._existing_link_org.get(lazarus_link_org)
        else:
            existing_id = self._existing_links.get(lazarus_link)
        if existing_id is not None:
            return DedupDecision(
                status="exact_duplicate",
                reason="lazarus.day 详情 URL 已存在",
                existing_id=existing_id,
            )
        existing_id = self._existing_link_org_date.get(link_org_date)
        if existing_id is not None:
            return DedupDecision(
                status="exact_duplicate",
                reason="来源 URL、组织和日期与历史事件一致",
                existing_id=existing_id,
            )
        existing_id = self._existing_org_date_title.get(org_date_title)
        if existing_id is not None:
            return DedupDecision(
                status="exact_duplicate",
                reason="组织、日期和规范化标题与历史事件一致",
                existing_id=existing_id,
            )
        if self.allow_cross_organization_links and organization_id:
            duplicate_batch_link = (
                link_org in self._batch_link_org
                or lazarus_link_org in self._batch_lazarus_link_org
            )
        else:
            duplicate_batch_link = (
                link in self._batch_links
                or lazarus_link in self._batch_lazarus_links
            )
        if duplicate_batch_link:
            return DedupDecision(
                status="exact_duplicate",
                reason=(
                    "本批次同一组织出现相同来源 URL"
                    if self.allow_cross_organization_links and organization_id
                    else "本批次出现相同来源 URL"
                ),
            )
        if (
            link_org_date in self._batch_link_org_date
            or org_date_title in self._batch_org_date_title
        ):
            return DedupDecision(
                status="exact_duplicate",
                reason="本批次出现相同组织、日期和来源/标题",
            )

        suspected_existing = self._existing_org_date.get(org_date, [])
        suspected = bool(organization_id and suspected_existing)
        suspected_batch = bool(
            organization_id and org_date in self._batch_org_date
        )
        self._register(
            link=link,
            lazarus_link=lazarus_link,
            link_org_date=link_org_date,
            org_date_title=org_date_title,
            org_date=org_date,
            link_org=link_org,
            lazarus_link_org=lazarus_link_org,
        )
        if suspected or suspected_batch:
            return DedupDecision(
                status="suspected_duplicate",
                reason="同一组织和日期已有不同来源或标题，需人工判重",
                existing_id=(
                    suspected_existing[0] if suspected_existing else None
                ),
            )
        return DedupDecision(status="unique")

    def _register(
        self,
        *,
        link: str,
        lazarus_link: str,
        link_org_date: tuple[str, str, str],
        org_date_title: tuple[str, str, str],
        org_date: tuple[str, str],
        link_org: tuple[str, str],
        lazarus_link_org: tuple[str, str],
    ) -> None:
        self._batch_links.add(link)
        self._batch_lazarus_links.add(lazarus_link)
        self._batch_link_org.add(link_org)
        self._batch_lazarus_link_org.add(lazarus_link_org)
        self._batch_link_org_date.add(link_org_date)
        self._batch_org_date_title.add(org_date_title)
        self._batch_org_date.add(org_date)
