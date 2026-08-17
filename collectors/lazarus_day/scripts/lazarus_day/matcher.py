from __future__ import annotations

import csv
import io
import json
import re
import unicodedata
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from .models import MatchResult, Organization, ValidationError


NAME_SEPARATOR_RE = re.compile(r"\s*(?:\||;|；|,|，)\s*")
NORMALIZATION_PUNCTUATION_RE = re.compile(r"[\s\-_.·•()（）\[\]【】{}<>《》]+")


def read_text_compatible(path: Path) -> tuple[str, str]:
    data = path.read_bytes()
    attempts: list[tuple[str, str]] = []
    if data.startswith(b"\xef\xbb\xbf"):
        attempts.append(("utf-8-sig", "UTF-8 with BOM"))
    attempts.extend(
        (
            ("utf-8", "UTF-8"),
            ("gb18030", "GB18030"),
            ("gbk", "GBK"),
        )
    )
    errors: list[str] = []
    for codec, label in attempts:
        try:
            return data.decode(codec), label
        except UnicodeDecodeError as exc:
            errors.append(f"{label}: {exc}")
    raise ValidationError(
        f"无法按 UTF-8/GB18030/GBK 解码文件：{path}; {'; '.join(errors)}"
    )


def split_aliases(raw: str | None) -> tuple[str, ...]:
    value = (raw or "").strip()
    if not value:
        return ()
    if value.startswith("["):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            return tuple(
                str(item).strip() for item in parsed if str(item).strip()
            )
    return tuple(part for part in NAME_SEPARATOR_RE.split(value) if part)


def normalize_actor_name(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold().strip()
    return NORMALIZATION_PUNCTUATION_RE.sub("", normalized)


def load_organizations(path: Path) -> tuple[list[Organization], str]:
    text, encoding = read_text_compatible(path)
    reader = csv.DictReader(io.StringIO(text, newline=""))
    required = {"id", "name", "aliases"}
    if reader.fieldnames is None or not required.issubset(reader.fieldnames):
        raise ValidationError(
            f"组织 CSV 缺少字段 {sorted(required)}：{path}"
        )
    organizations: list[Organization] = []
    seen_ids: set[int] = set()
    for line_number, row in enumerate(reader, start=2):
        try:
            organization_id = int((row.get("id") or "").strip())
        except ValueError as exc:
            raise ValidationError(
                f"组织 CSV 第 {line_number} 行 id 无效"
            ) from exc
        name = (row.get("name") or "").strip()
        if not name:
            raise ValidationError(f"组织 CSV 第 {line_number} 行 name 为空")
        if organization_id in seen_ids:
            raise ValidationError(f"组织 CSV 出现重复 id：{organization_id}")
        seen_ids.add(organization_id)
        organizations.append(
            Organization(
                id=organization_id,
                name=name,
                aliases=split_aliases(row.get("aliases")),
            )
        )
    return organizations, encoding


def load_actor_alias_overrides(
    path: Path, matcher: "OrganizationMatcher"
) -> tuple[list[dict[str, object]], str]:
    text, encoding = read_text_compatible(path)
    reader = csv.DictReader(io.StringIO(text, newline=""))
    required = {
        "source_name",
        "organization_id",
        "organization_name",
        "reason",
    }
    if reader.fieldnames is None or not required.issubset(reader.fieldnames):
        raise ValidationError(
            f"Actor 覆盖 CSV 缺少字段 {sorted(required)}：{path}"
        )
    records: list[dict[str, object]] = []
    for line_number, row in enumerate(reader, start=2):
        source_name = (row.get("source_name") or "").strip()
        organization_name = (row.get("organization_name") or "").strip()
        reason = (row.get("reason") or "").strip()
        try:
            organization_id = int(
                (row.get("organization_id") or "").strip()
            )
        except ValueError as exc:
            raise ValidationError(
                f"Actor 覆盖 CSV 第 {line_number} 行 organization_id 无效"
            ) from exc
        if not source_name:
            raise ValidationError(
                f"Actor 覆盖 CSV 第 {line_number} 行 source_name 为空"
            )
        if not matcher.validates_id_name(organization_id, organization_name):
            raise ValidationError(
                f"Actor 覆盖 CSV 第 {line_number} 行组织 ID 与名称不匹配："
                f"{organization_id}/{organization_name}"
            )
        matcher.add_alias_override(source_name, organization_id)
        records.append(
            {
                "source_name": source_name,
                "organization_id": organization_id,
                "organization_name": organization_name,
                "reason": reason,
            }
        )
    return records, encoding


class OrganizationMatcher:
    def __init__(self, organizations: Iterable[Organization]) -> None:
        self.organizations = tuple(organizations)
        self.by_id = {organization.id: organization for organization in self.organizations}
        self._main_exact: dict[str, set[int]] = defaultdict(set)
        self._alias_exact: dict[str, set[int]] = defaultdict(set)
        self._normalized: dict[str, set[int]] = defaultdict(set)
        self._title_names: list[tuple[str, int, str]] = []
        for organization in self.organizations:
            self._main_exact[organization.name].add(organization.id)
            self._normalized[normalize_actor_name(organization.name)].add(
                organization.id
            )
            self._title_names.append(
                (organization.name, organization.id, "title_main_name")
            )
            for alias in organization.aliases:
                self._alias_exact[alias].add(organization.id)
                self._normalized[normalize_actor_name(alias)].add(organization.id)
                self._title_names.append(
                    (alias, organization.id, "title_alias")
                )
        self._title_names.sort(key=lambda item: len(item[0]), reverse=True)

    def match(
        self,
        *,
        related_actors: Iterable[str],
        tags: Iterable[str],
        title: str,
    ) -> MatchResult:
        actors = tuple(_dedupe_nonempty(related_actors))
        if actors:
            result = self._match_explicit_names(actors, "related_actor")
            if result.status == "matched" and len(actors) == 1:
                return result
            if result.status == "matched" and len(actors) > 1:
                return MatchResult(
                    status="conflict",
                    organization=None,
                    method=None,
                    raw_names=actors,
                    candidate_organizations=(
                        (result.organization,) if result.organization else ()
                    ),
                    reason="报告包含多个 Related Actors，无法自动拆分活动",
                )
            return result

        tag_names = tuple(_dedupe_nonempty(tags))
        tag_result = self._match_explicit_names(tag_names, "tag")
        if tag_result.status != "unmatched":
            return tag_result

        title_result = self._match_title(title)
        if title_result.status != "unmatched":
            return title_result
        return MatchResult(
            status="unmatched",
            organization=None,
            method=None,
            raw_names=(),
            reason=(
                "Related Actors 缺失，标签和标题均未精确匹配现有组织；"
                "未将技术标签当作组织名称"
            ),
        )

    def validates_id_name(self, organization_id: int, name: str) -> bool:
        organization = self.by_id.get(organization_id)
        if organization is None:
            return False
        return name == organization.name or name in organization.aliases

    def exact_candidates(self, name: str) -> tuple[Organization, ...]:
        """Return deterministic main-name/alias matches without fuzzy search."""

        cleaned = str(name).strip().lstrip("#")
        if not cleaned:
            return ()
        ids = set(self._main_exact.get(cleaned, set()))
        ids.update(self._alias_exact.get(cleaned, set()))
        normalized = normalize_actor_name(cleaned)
        if normalized:
            ids.update(self._normalized.get(normalized, set()))
        return tuple(self.by_id[item] for item in sorted(ids))

    def add_alias_override(
        self, source_name: str, organization_id: int
    ) -> None:
        cleaned = str(source_name).strip().lstrip("#")
        if not cleaned:
            raise ValidationError("Actor 覆盖名称不能为空")
        if organization_id not in self.by_id:
            raise ValidationError(
                f"Actor 覆盖引用不存在的组织 ID：{organization_id}"
            )
        existing_ids = {item.id for item in self.exact_candidates(cleaned)}
        if existing_ids and existing_ids != {organization_id}:
            raise ValidationError(
                f"Actor 覆盖名称 {cleaned!r} 已映射到其他组织："
                f"{sorted(existing_ids)}"
            )
        self._alias_exact[cleaned].add(organization_id)
        normalized = normalize_actor_name(cleaned)
        if normalized:
            self._normalized[normalized].add(organization_id)
        entry = (cleaned, organization_id, "title_override_alias")
        if entry not in self._title_names:
            self._title_names.append(entry)
            self._title_names.sort(
                key=lambda item: len(item[0]), reverse=True
            )

    def _match_explicit_names(
        self, names: tuple[str, ...], source: str
    ) -> MatchResult:
        if not names:
            return MatchResult(
                status="unmatched",
                organization=None,
                method=None,
                raw_names=(),
                reason="没有可匹配的组织名称",
            )
        ids: set[int] = set()
        matched_names: list[str] = []
        matched_methods: list[str] = []
        for name in names:
            found = self._main_exact.get(name, set())
            method = "main_exact"
            if not found:
                found = self._alias_exact.get(name, set())
                method = "alias_exact"
            if not found:
                normalized = normalize_actor_name(name)
                found = (
                    self._normalized.get(normalized, set())
                    if normalized
                    else set()
                )
                method = "normalized_exact"
            if found:
                ids.update(found)
                matched_names.append(name)
                matched_methods.append(method)
        if ids:
            priority = {
                "main_exact": 0,
                "alias_exact": 1,
                "normalized_exact": 2,
            }
            strongest_method = min(
                matched_methods, key=lambda value: priority[value]
            )
            return self._result_for_ids(
                ids,
                names,
                f"{source}_{strongest_method}",
                matched_names,
            )
        return MatchResult(
            status="unmatched",
            organization=None,
            method=None,
            raw_names=names,
            reason="名称未精确匹配现有组织主名称或别名",
        )

    def _match_title(self, title: str) -> MatchResult:
        normalized_title = unicodedata.normalize("NFKC", title).casefold()
        matches: dict[int, str] = {}
        raw_names: list[str] = []
        for name, organization_id, method in self._title_names:
            if not _safe_title_name(name):
                continue
            normalized_name = unicodedata.normalize("NFKC", name).casefold()
            pattern = rf"(?<![\w]){re.escape(normalized_name)}(?![\w])"
            if re.search(pattern, normalized_title):
                matches[organization_id] = method
                raw_names.append(name)
        if not matches:
            return MatchResult(
                status="unmatched",
                organization=None,
                method=None,
                raw_names=(),
                reason="标题中未找到边界明确的现有组织名称或别名",
            )
        if len(matches) > 1:
            candidates = tuple(
                self.by_id[organization_id]
                for organization_id in sorted(matches)
            )
            return MatchResult(
                status="conflict",
                organization=None,
                method=None,
                raw_names=tuple(raw_names),
                candidate_organizations=candidates,
                reason="标题同时精确命中多个组织",
            )
        organization_id = next(iter(matches))
        return MatchResult(
            status="matched",
            organization=self.by_id[organization_id],
            method=matches[organization_id],
            raw_names=tuple(raw_names),
        )

    def _result_for_ids(
        self,
        ids: set[int],
        raw_names: tuple[str, ...],
        method: str,
        matched_names: list[str],
    ) -> MatchResult:
        if len(ids) == 1:
            organization_id = next(iter(ids))
            return MatchResult(
                status="matched",
                organization=self.by_id[organization_id],
                method=method,
                raw_names=tuple(matched_names),
            )
        return MatchResult(
            status="conflict",
            organization=None,
            method=None,
            raw_names=tuple(matched_names),
            candidate_organizations=tuple(
                self.by_id[organization_id] for organization_id in sorted(ids)
            ),
            reason="同一确定性名称映射到多个现有组织",
        )


def _dedupe_nonempty(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        cleaned = str(value).strip().lstrip("#")
        if cleaned and cleaned not in result:
            result.append(cleaned)
    return result


def _safe_title_name(value: str) -> bool:
    compact = normalize_actor_name(value)
    if not compact:
        return False
    if compact.isascii():
        return len(compact) >= 4
    return len(compact) >= 2
