import json
import logging
import re
from datetime import date, datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional

from sqlalchemy import text

logger = logging.getLogger("uvicorn.error")


def _empty_snapshot(status: str = "not_collected") -> Dict[str, Any]:
    return {
        "whois": {
            "status": status,
            "registrar": None,
            "name_servers": [],
            "registration_date": None,
            "expiration_date": None,
            "statuses": [],
        },
        "dns": {
            "status": status,
            "ips": [],
            "cnames": [],
            "ns_records": [],
            "mx_records": [],
            "txt_records": [],
            "ttls": [],
        },
        "ssl": {
            "status": status,
            "fingerprints": [],
            "serial_numbers": [],
            "san_names": [],
            "subjects": [],
            "issuers": [],
            "not_before_dates": [],
            "not_after_dates": [],
            "is_self_signed": None,
        },
    }


def _normalize_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    normalized = re.sub(r"\s+", " ", str(value).strip().lower())
    if not normalized:
        return None
    return normalized.rstrip(".")


def _normalize_domain(value: Any) -> Optional[str]:
    normalized = _normalize_text(value)
    if not normalized:
        return None
    normalized = re.sub(r"^[a-z][a-z0-9+.-]*://", "", normalized)
    normalized = normalized.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if ":" in normalized:
        normalized = normalized.split(":", 1)[0]
    normalized = normalized.strip(".")
    return normalized or None


def _parse_json_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list, tuple, set)):
        return value
    if isinstance(value, (datetime, date, int, float, bool)):
        return value
    text_value = str(value).strip()
    if not text_value:
        return None
    try:
        return json.loads(text_value)
    except Exception:
        logger.warning("域名基础设施 JSON 字段解析失败，已按原始文本处理")
        return text_value


def _iter_values(value: Any) -> Iterable[Any]:
    parsed = _parse_json_value(value)
    if parsed is None:
        return []
    if isinstance(parsed, Mapping):
        return parsed.values()
    if isinstance(parsed, (list, tuple, set)):
        return parsed
    return [parsed]


def _append_unique(target: List[Any], value: Any) -> None:
    if value is None or value == "":
        return
    if value not in target:
        target.append(value)


def _normalized_text_list(value: Any) -> List[str]:
    result: List[str] = []
    for item in _iter_values(value):
        if isinstance(item, Mapping):
            for nested in item.values():
                normalized = _normalize_text(nested)
                _append_unique(result, normalized)
            continue
        normalized = _normalize_text(item)
        _append_unique(result, normalized)
    return result


def _normalized_json_object_text(value: Any) -> Optional[str]:
    parsed = _parse_json_value(value)
    if parsed is None:
        return None
    if isinstance(parsed, Mapping):
        normalized = {
            str(key).strip().lower(): _normalize_text(val)
            for key, val in parsed.items()
            if _normalize_text(val)
        }
        if not normalized:
            return None
        return json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    return _normalize_text(parsed)


def _coerce_bool_or_none(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = _normalize_text(value)
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    return None


def _load_domain_row(db, domain_name: str) -> Optional[Mapping[str, Any]]:
    normalized_domain = _normalize_domain(domain_name)
    if not normalized_domain:
        return None
    return db.execute(
        text(
            """
            SELECT id AS domain_id, domain_name
            FROM domains
            WHERE LOWER(TRIM(domain_name)) = :domain_name
            LIMIT 1
            """
        ),
        {"domain_name": normalized_domain},
    ).mappings().first()


def _build_whois_snapshot(db, domain_id: int) -> Dict[str, Any]:
    rows = db.execute(
        text(
            """
            SELECT registrar,
                   name_servers,
                   registration_date,
                   expiration_date,
                   status
            FROM whois_info
            WHERE domain_id = :domain_id
            ORDER BY query_time DESC, id DESC
            """
        ),
        {"domain_id": domain_id},
    ).mappings().all()

    whois = _empty_snapshot("not_found")["whois"]
    if not rows:
        return whois
    whois["status"] = "collected"
    for row in rows:
        if not whois["registrar"]:
            whois["registrar"] = _normalize_text(row.get("registrar"))
        if not whois["registration_date"]:
            whois["registration_date"] = _normalize_text(row.get("registration_date"))
        if not whois["expiration_date"]:
            whois["expiration_date"] = _normalize_text(row.get("expiration_date"))
        for name_server in _normalized_text_list(row.get("name_servers")):
            _append_unique(whois["name_servers"], name_server)
        for status in _normalized_text_list(row.get("status")):
            _append_unique(whois["statuses"], status)
    return whois


def _build_dns_snapshot(db, domain_id: int) -> Dict[str, Any]:
    rows = db.execute(
        text(
            """
            SELECT record_type,
                   record_value,
                   ttl
            FROM dns_records
            WHERE domain_id = :domain_id
            ORDER BY created_at DESC, id DESC
            """
        ),
        {"domain_id": domain_id},
    ).mappings().all()

    dns = _empty_snapshot("not_found")["dns"]
    if not rows:
        return dns
    dns["status"] = "collected"
    for row in rows:
        record_type = _normalize_text(row.get("record_type")) or ""
        record_value = _normalize_text(row.get("record_value"))
        ttl = row.get("ttl")
        if ttl is not None:
            try:
                _append_unique(dns["ttls"], int(ttl))
            except Exception:
                pass
        if not record_value:
            continue
        if record_type in {"a", "aaaa"}:
            _append_unique(dns["ips"], record_value)
        elif record_type == "cname":
            _append_unique(dns["cnames"], record_value)
        elif record_type == "ns":
            _append_unique(dns["ns_records"], record_value)
        elif record_type == "mx":
            _append_unique(dns["mx_records"], record_value)
        elif record_type == "txt":
            _append_unique(dns["txt_records"], record_value)
    return dns


def _build_ssl_snapshot(db, domain_id: int) -> Dict[str, Any]:
    rows = db.execute(
        text(
            """
            SELECT fingerprint,
                   serial_number,
                   san_names,
                   subject,
                   issuer,
                   not_before,
                   not_after,
                   is_self_signed
            FROM ssl_certificates
            WHERE domain_id = :domain_id
            ORDER BY created_at DESC, id DESC
            """
        ),
        {"domain_id": domain_id},
    ).mappings().all()

    ssl_snapshot = _empty_snapshot("not_found")["ssl"]
    if not rows:
        return ssl_snapshot
    ssl_snapshot["status"] = "collected"
    self_signed_seen = False
    for row in rows:
        _append_unique(ssl_snapshot["fingerprints"], _normalize_text(row.get("fingerprint")))
        _append_unique(ssl_snapshot["serial_numbers"], _normalize_text(row.get("serial_number")))
        for san_name in _normalized_text_list(row.get("san_names")):
            _append_unique(ssl_snapshot["san_names"], san_name)
        _append_unique(ssl_snapshot["subjects"], _normalized_json_object_text(row.get("subject")))
        _append_unique(ssl_snapshot["issuers"], _normalized_json_object_text(row.get("issuer")))
        _append_unique(ssl_snapshot["not_before_dates"], _normalize_text(row.get("not_before")))
        _append_unique(ssl_snapshot["not_after_dates"], _normalize_text(row.get("not_after")))
        is_self_signed = _coerce_bool_or_none(row.get("is_self_signed"))
        if is_self_signed is True:
            ssl_snapshot["is_self_signed"] = True
            self_signed_seen = True
        elif is_self_signed is False and not self_signed_seen:
            ssl_snapshot["is_self_signed"] = False
    return ssl_snapshot


def load_domain_infra_snapshot(db, domain_name) -> dict:
    """
    Load a WHOIS/DNS/SSL infrastructure snapshot for one domain from cached tables.
    The function is read-only and does not trigger live collection.
    """
    snapshot = _empty_snapshot("not_collected")
    try:
        domain_row = _load_domain_row(db, str(domain_name or ""))
        if not domain_row:
            return snapshot

        domain_id = int(domain_row["domain_id"])
        snapshot["whois"] = _build_whois_snapshot(db, domain_id)
        snapshot["dns"] = _build_dns_snapshot(db, domain_id)
        snapshot["ssl"] = _build_ssl_snapshot(db, domain_id)
        return snapshot
    except Exception as exc:
        logger.exception(
            "加载域名基础设施快照失败 domain=%s err=%s",
            domain_name,
            exc,
        )
        return snapshot
