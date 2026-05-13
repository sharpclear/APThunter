import json
import logging
import re
from datetime import date, datetime
from typing import Any, Dict, Mapping

from sqlalchemy import text

logger = logging.getLogger("uvicorn.error")

GLOBAL_PROFILE_KEY = "global:default"


def _parse_json_field(value: Any) -> Any:
    if value is None:
        return {}
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    if isinstance(value, (datetime, date, int, float, bool)):
        return value

    text_value = str(value).strip()
    if not text_value:
        return {}
    try:
        parsed = json.loads(text_value)
    except Exception:
        logger.warning("actor_infra_profiles JSON 字段解析失败，已按空对象处理")
        return {}
    return parsed if parsed is not None else {}


def _normalize_scalar(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    normalized = re.sub(r"\s+", " ", str(value).strip().lower())
    if not normalized:
        return ""
    return normalized.rstrip(".")


def _plain_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_parsed_json(parsed: Any) -> Any:
    if isinstance(parsed, Mapping):
        return {
            str(key).strip().lower(): _normalize_parsed_json(nested)
            for key, nested in parsed.items()
            if str(key).strip()
        }
    if isinstance(parsed, list):
        normalized_list = []
        for item in parsed:
            normalized_item = _normalize_parsed_json(item)
            if normalized_item in ("", None, {}, []):
                continue
            normalized_list.append(normalized_item)
        return normalized_list
    return _normalize_scalar(parsed)


def _normalize_profile_json(value: Any) -> Any:
    return _normalize_parsed_json(_parse_json_field(value))


def _empty_cache() -> Dict[str, Any]:
    return {"actors": {}, "global_stats": {}}


def load_actor_infra_profiles_from_cache(db) -> dict:
    """
    Load active rule_v2_infra profiles from actor_infra_profiles.

    Returns:
    {
        "actors": {
            organization_id: {
                "organization_id": ...,
                "organization_name": ...,
                "domain_profile": {...},
                "whois_profile": {...},
                "dns_profile": {...},
                "ssl_profile": {...},
                "summary": {...}
            }
        },
        "global_stats": {...}
    }
    """
    result = _empty_cache()

    try:
        rows = db.execute(
            text(
                """
                SELECT
                    profile_key,
                    profile_type,
                    organization_id,
                    organization_name,
                    domain_profile_json,
                    whois_profile_json,
                    dns_profile_json,
                    ssl_profile_json,
                    global_stats_json,
                    summary_json
                FROM actor_infra_profiles
                WHERE profile_status = 'active'
                  AND (
                    profile_type = 'actor'
                    OR profile_key = :global_profile_key
                  )
                ORDER BY profile_type ASC, organization_id ASC, profile_key ASC
                """
            ),
            {"global_profile_key": GLOBAL_PROFILE_KEY},
        ).mappings().all()
    except Exception as exc:
        logger.exception("加载 actor_infra_profiles 缓存画像失败: %s", exc)
        return result

    for row in rows:
        try:
            profile_key = str(row.get("profile_key") or "").strip()
            profile_type = str(row.get("profile_type") or "").strip().lower()

            if profile_key == GLOBAL_PROFILE_KEY:
                result["global_stats"] = _normalize_profile_json(
                    row.get("global_stats_json")
                )
                continue

            if profile_type != "actor":
                continue

            organization_id = row.get("organization_id")
            if organization_id is None:
                continue
            try:
                organization_id = int(organization_id)
            except Exception:
                continue

            result["actors"][organization_id] = {
                "organization_id": organization_id,
                "organization_name": _plain_text(row.get("organization_name")),
                "domain_profile": _normalize_profile_json(row.get("domain_profile_json")),
                "whois_profile": _normalize_profile_json(row.get("whois_profile_json")),
                "dns_profile": _normalize_profile_json(row.get("dns_profile_json")),
                "ssl_profile": _normalize_profile_json(row.get("ssl_profile_json")),
                "summary": _normalize_profile_json(row.get("summary_json")),
            }
        except Exception as exc:
            logger.warning(
                "解析 actor_infra_profiles 缓存画像失败 profile_key=%s err=%s",
                row.get("profile_key"),
                exc,
            )
            continue

    return result
