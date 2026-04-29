import json
import logging
import re
from datetime import date, datetime
from typing import Any, Dict, List, Sequence, Set

from sqlalchemy import text

logger = logging.getLogger("uvicorn.error")

_TOKEN_STOPWORDS = {
    "com",
    "net",
    "org",
    "www",
}


def _safe_to_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    if isinstance(value, str):
        text_value = value.strip()
        if not text_value:
            return []
        try:
            parsed = json.loads(text_value)
            if isinstance(parsed, list):
                return parsed
            if parsed is None:
                return []
            return [parsed]
        except Exception:
            parts = re.split(r"[,;|\n\r\t]+", text_value)
            return [p.strip() for p in parts if p and p.strip()]
    return [value]


def _normalize_str_list(value: Any) -> List[str]:
    result: List[str] = []
    for item in _safe_to_list(value):
        try:
            if item is None:
                continue
            text_item = str(item).strip()
            if text_item:
                result.append(text_item)
        except Exception:
            continue
    return result


def _extract_keywords_from_domains(domains: Sequence[str]) -> List[str]:
    tokens: Set[str] = set()
    for raw_domain in domains:
        domain = str(raw_domain or "").strip().lower()
        if not domain:
            continue
        labels = [label for label in domain.split(".") if label]
        if not labels:
            continue
        stem = ".".join(labels[:-1]) if len(labels) > 1 else labels[0]
        for token in re.split(r"[-_.\d]+", stem):
            token = token.strip().lower()
            if len(token) < 3:
                continue
            if token in _TOKEN_STOPWORDS:
                continue
            tokens.add(token)
    return sorted(tokens)


def _extract_common_tlds(domains: Sequence[str]) -> List[str]:
    tlds: Set[str] = set()
    for raw_domain in domains:
        domain = str(raw_domain or "").strip().lower()
        if not domain:
            continue
        labels = [label for label in domain.split(".") if label]
        if len(labels) < 2:
            continue
        tld = labels[-1].strip()
        if not tld:
            continue
        tlds.add(tld)
    return sorted(tlds)


def _build_profile_version(row: Dict[str, Any], has_profile_version: bool) -> str:
    if has_profile_version:
        explicit = row.get("profile_version")
        if explicit is not None:
            text_version = str(explicit).strip()
            if text_version:
                return text_version
    updated_at = row.get("updated_at")
    update_time = row.get("update_time")
    try:
        if isinstance(updated_at, datetime):
            return f"apt_org:{updated_at.strftime('%Y%m%d%H%M%S')}"
        if isinstance(update_time, (datetime, date)):
            return f"apt_org:{update_time.strftime('%Y%m%d')}"
    except Exception:
        pass
    return "actor_profile_v1"


def _get_column_set(db) -> Set[str]:
    query = text(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = 'apt_organizations'
        """
    )
    rows = db.execute(query).mappings().all()
    return {str(row.get("column_name", "")).lower() for row in rows}


def _load_historical_domains_by_org(db) -> Dict[int, List[str]]:
    """
    从 domains 表按 organization_id 聚合历史域名样本。
    """
    query = text(
        """
        SELECT organization_id, domain_name
        FROM domains
        WHERE organization_id IS NOT NULL
          AND domain_name IS NOT NULL
          AND TRIM(domain_name) <> ''
        ORDER BY organization_id ASC, domain_name ASC
        """
    )
    rows = db.execute(query).mappings().all()
    grouped: Dict[int, List[str]] = {}
    seen_by_org: Dict[int, Set[str]] = {}
    for row in rows:
        try:
            org_id = int(row.get("organization_id"))
        except Exception:
            continue
        domain_name = str(row.get("domain_name") or "").strip().lower()
        if not domain_name:
            continue
        if org_id not in grouped:
            grouped[org_id] = []
            seen_by_org[org_id] = set()
        if domain_name in seen_by_org[org_id]:
            continue
        seen_by_org[org_id].add(domain_name)
        grouped[org_id].append(domain_name)
    return grouped


def load_actor_profiles(db) -> List[Dict[str, Any]]:
    """
    从 apt_organizations 读取组织基础画像，并从 domains 聚合历史域名样本。
    返回字段：
    - organization_id
    - name
    - alias
    - description
    - previous_domains (来源：domains.organization_id -> domains.domain_name)
    - historical_domains (与 previous_domains 同源别名)
    - ioc_domains (与 previous_domains 同源别名)
    - keywords
    - common_tlds
    - vps_providers
    - profile_version
    """
    profiles: List[Dict[str, Any]] = []

    try:
        columns = _get_column_set(db)
    except Exception as exc:
        logger.exception("读取 apt_organizations 列信息失败: %s", exc)
        return []

    has_keywords = "keywords" in columns
    has_common_tlds = "common_tlds" in columns
    has_is_active = "is_active" in columns
    has_profile_version = "profile_version" in columns

    select_parts = [
        "id",
        "name",
        "alias",
        "description",
        "region",
        "origin",
        "target_countries",
        "target_industries",
        "vps_providers",
        "update_time",
        "updated_at",
    ]
    if has_keywords:
        select_parts.append("keywords")
    if has_common_tlds:
        select_parts.append("common_tlds")
    if has_profile_version:
        select_parts.append("profile_version")

    where_sql = "WHERE is_active = 1" if has_is_active else ""
    query_sql = f"""
        SELECT {", ".join(select_parts)}
        FROM apt_organizations
        {where_sql}
        ORDER BY id ASC
    """

    try:
        rows = db.execute(text(query_sql)).mappings().all()
    except Exception as exc:
        logger.exception("读取 apt_organizations 数据失败: %s", exc)
        return []

    try:
        historical_domains_by_org = _load_historical_domains_by_org(db)
    except Exception as exc:
        logger.exception("读取 domains 历史域名样本失败: %s", exc)
        historical_domains_by_org = {}

    for row in rows:
        row_dict = dict(row)
        try:
            org_id = row_dict.get("id")
            name = str(row_dict.get("name") or "").strip()
            if not org_id or not name:
                continue

            alias = _normalize_str_list(row_dict.get("alias"))
            description = str(row_dict.get("description") or "").strip()
            historical_domains = historical_domains_by_org.get(int(org_id), [])
            previous_domains = list(historical_domains)
            vps_providers = _normalize_str_list(row_dict.get("vps_providers"))
            region = str(row_dict.get("region") or "").strip()
            origin = str(row_dict.get("origin") or "").strip()
            target_countries = _normalize_str_list(row_dict.get("target_countries"))
            target_industries = _normalize_str_list(row_dict.get("target_industries"))

            keywords = (
                _normalize_str_list(row_dict.get("keywords"))
                if has_keywords
                else []
            )
            if not keywords:
                keywords = _extract_keywords_from_domains(previous_domains)

            common_tlds = (
                _normalize_str_list(row_dict.get("common_tlds"))
                if has_common_tlds
                else []
            )
            if not common_tlds:
                common_tlds = _extract_common_tlds(previous_domains)

            profiles.append(
                {
                    "organization_id": int(org_id),
                    "name": name,
                    "alias": alias,
                    "description": description,
                    "region": region,
                    "origin": origin,
                    "target_countries": target_countries,
                    "target_industries": target_industries,
                    "previous_domains": previous_domains,
                    "historical_domains": list(previous_domains),
                    "ioc_domains": list(previous_domains),
                    "keywords": keywords,
                    "common_tlds": common_tlds,
                    "vps_providers": vps_providers,
                    "profile_version": _build_profile_version(row_dict, has_profile_version),
                }
            )
        except Exception as exc:
            logger.warning(
                "组织画像行解析失败，已跳过 organization_id=%s err=%s",
                row_dict.get("id"),
                exc,
            )
            continue

    return profiles
