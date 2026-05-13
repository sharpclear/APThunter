import json
import logging
import re
from collections import Counter, defaultdict
from datetime import date, datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from sqlalchemy import text

logger = logging.getLogger("uvicorn.error")

SOURCE_TABLES = ["domains", "whois_info", "dns_records", "ssl_certificates"]
GLOBAL_PROFILE_KEY = "global:default"


def _json_default(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def _json_dumps(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    )


def _parse_json_value(value: Any, stats: Dict[str, int]) -> Any:
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
        stats["json_parse_errors"] += 1
        return text_value


def _iter_values(value: Any, stats: Dict[str, int]) -> Iterable[Any]:
    parsed = _parse_json_value(value, stats)
    if parsed is None:
        return []
    if isinstance(parsed, Mapping):
        return parsed.values()
    if isinstance(parsed, (list, tuple, set)):
        return parsed
    return [parsed]


def _normalize_text(value: Any) -> Optional[str]:
    if value is None:
        return None
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


def _normalize_json_values(value: Any, stats: Dict[str, int]) -> List[str]:
    result: List[str] = []
    seen: Set[str] = set()
    for item in _iter_values(value, stats):
        if isinstance(item, Mapping):
            for nested in item.values():
                normalized = _normalize_text(nested)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    result.append(normalized)
            continue
        normalized = _normalize_text(item)
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def _date_to_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    normalized = _normalize_text(value)
    return normalized


def _counter_to_dict(counter: Counter) -> Dict[str, int]:
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def _top(counter: Counter, limit: int = 20) -> List[Dict[str, Any]]:
    return [
        {"value": value, "count": count}
        for value, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


def _sld_structure_pattern(sld: str) -> str:
    parts: List[str] = []
    for token in re.split(r"([-.])", sld):
        if not token:
            continue
        if token in {"-", "."}:
            parts.append(token)
            continue
        has_alpha = bool(re.search(r"[a-z]", token))
        has_digit = bool(re.search(r"\d", token))
        if has_alpha and has_digit:
            parts.append("alpha_digit")
        elif has_alpha:
            parts.append("alpha")
        elif has_digit:
            parts.append("digit")
        else:
            parts.append("symbol")
    return "".join(parts) or "unknown"


def _domain_parts(domain: str) -> Tuple[str, str, List[str], str]:
    labels = [label for label in domain.split(".") if label]
    if len(labels) >= 2:
        sld = labels[-2]
        tld = labels[-1]
    elif labels:
        sld = labels[0]
        tld = ""
    else:
        sld = ""
        tld = ""
    tokens = [
        token
        for token in re.split(r"[-_.\d]+", domain)
        if len(token.strip()) >= 2
    ]
    return sld, tld, tokens, _sld_structure_pattern(sld)


def _build_domain_profile(domain_rows: List[Mapping[str, Any]]) -> Tuple[Dict[str, Any], Set[str]]:
    domains: List[str] = []
    seen: Set[str] = set()
    tld_counter: Counter = Counter()
    token_counter: Counter = Counter()
    pattern_counter: Counter = Counter()
    sld_counter: Counter = Counter()

    for row in domain_rows:
        domain = _normalize_domain(row.get("domain_name"))
        if not domain or domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)
        sld, tld, tokens, pattern = _domain_parts(domain)
        if sld:
            sld_counter[sld] += 1
        if tld:
            tld_counter[tld] += 1
        for token in tokens:
            token_counter[token] += 1
        if pattern:
            pattern_counter[pattern] += 1

    return (
        {
            "historical_domains": sorted(domains),
            "tld": _counter_to_dict(tld_counter),
            "tld_frequency": _counter_to_dict(tld_counter),
            "tokens": _counter_to_dict(token_counter),
            "token_frequency": _counter_to_dict(token_counter),
            "sld_patterns": _counter_to_dict(pattern_counter),
            "sld_structure_patterns": _counter_to_dict(pattern_counter),
            "sld_frequency": _counter_to_dict(sld_counter),
        },
        set(domains) | set(tld_counter) | set(token_counter) | set(pattern_counter),
    )


def _build_whois_profile(
    rows: List[Mapping[str, Any]], stats: Dict[str, int]
) -> Tuple[Dict[str, Any], Set[str]]:
    registrar_counter: Counter = Counter()
    ns_counter: Counter = Counter()
    status_counter: Counter = Counter()
    registration_dates: Counter = Counter()
    expiration_dates: Counter = Counter()
    org_values: Set[str] = set()

    for row in rows:
        registrar = _normalize_text(row.get("registrar"))
        if registrar:
            registrar_counter[registrar] += 1
            org_values.add(f"whois:registrar:{registrar}")
        for name_server in _normalize_json_values(row.get("name_servers"), stats):
            ns_counter[name_server] += 1
            org_values.add(f"whois:name_server:{name_server}")
        for status in _normalize_json_values(row.get("status"), stats):
            status_counter[status] += 1
            org_values.add(f"whois:status:{status}")
        registration_date = _date_to_text(row.get("registration_date"))
        if registration_date:
            registration_dates[registration_date] += 1
        expiration_date = _date_to_text(row.get("expiration_date"))
        if expiration_date:
            expiration_dates[expiration_date] += 1

    return (
        {
            "registrar": _counter_to_dict(registrar_counter),
            "registrar_frequency": _counter_to_dict(registrar_counter),
            "name_servers": _counter_to_dict(ns_counter),
            "name_server_frequency": _counter_to_dict(ns_counter),
            "registration_dates": _counter_to_dict(registration_dates),
            "expiration_dates": _counter_to_dict(expiration_dates),
            "statuses": _counter_to_dict(status_counter),
            "status_frequency": _counter_to_dict(status_counter),
        },
        org_values,
    )


def _build_dns_profile(rows: List[Mapping[str, Any]]) -> Tuple[Dict[str, Any], Set[str]]:
    counters: Dict[str, Counter] = {
        "ips": Counter(),
        "cname": Counter(),
        "ns": Counter(),
        "mx": Counter(),
        "txt": Counter(),
        "ttl": Counter(),
        "other": Counter(),
    }
    org_values: Set[str] = set()

    for row in rows:
        record_type = _normalize_text(row.get("record_type")) or "unknown"
        record_value = _normalize_text(row.get("record_value"))
        ttl = row.get("ttl")
        if ttl is not None:
            try:
                ttl_key = str(int(ttl))
                counters["ttl"][ttl_key] += 1
                org_values.add(f"dns:ttl:{ttl_key}")
            except Exception:
                pass
        if not record_value:
            continue
        if record_type in {"a", "aaaa"}:
            bucket = "ips"
        elif record_type in {"cname", "ns", "mx", "txt"}:
            bucket = record_type
        else:
            bucket = "other"
        counters[bucket][record_value] += 1
        org_values.add(f"dns:{bucket}:{record_value}")

    return (
        {
            "ips": _counter_to_dict(counters["ips"]),
            "ip_frequency": _counter_to_dict(counters["ips"]),
            "cname": _counter_to_dict(counters["cname"]),
            "cname_frequency": _counter_to_dict(counters["cname"]),
            "ns": _counter_to_dict(counters["ns"]),
            "ns_frequency": _counter_to_dict(counters["ns"]),
            "mx": _counter_to_dict(counters["mx"]),
            "mx_frequency": _counter_to_dict(counters["mx"]),
            "txt": _counter_to_dict(counters["txt"]),
            "txt_frequency": _counter_to_dict(counters["txt"]),
            "ttl": _counter_to_dict(counters["ttl"]),
            "ttl_frequency": _counter_to_dict(counters["ttl"]),
            "other_record_frequency": _counter_to_dict(counters["other"]),
        },
        org_values,
    )


def _normalize_json_object(value: Any, stats: Dict[str, int]) -> Optional[str]:
    parsed = _parse_json_value(value, stats)
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
        return _json_dumps(normalized)
    return _normalize_text(parsed)


def _build_ssl_profile(
    rows: List[Mapping[str, Any]], stats: Dict[str, int]
) -> Tuple[Dict[str, Any], Set[str]]:
    fingerprint_counter: Counter = Counter()
    serial_counter: Counter = Counter()
    san_counter: Counter = Counter()
    subject_counter: Counter = Counter()
    issuer_counter: Counter = Counter()
    not_before_counter: Counter = Counter()
    not_after_counter: Counter = Counter()
    self_signed_count = 0
    org_values: Set[str] = set()

    for row in rows:
        fingerprint = _normalize_text(row.get("fingerprint"))
        if fingerprint:
            fingerprint_counter[fingerprint] += 1
            org_values.add(f"ssl:fingerprint:{fingerprint}")
        serial_number = _normalize_text(row.get("serial_number"))
        if serial_number:
            serial_counter[serial_number] += 1
            org_values.add(f"ssl:serial_number:{serial_number}")
        for san in _normalize_json_values(row.get("san_names"), stats):
            san_counter[san] += 1
            org_values.add(f"ssl:san:{san}")
        subject = _normalize_json_object(row.get("subject"), stats)
        if subject:
            subject_counter[subject] += 1
            org_values.add(f"ssl:subject:{subject}")
        issuer = _normalize_json_object(row.get("issuer"), stats)
        if issuer:
            issuer_counter[issuer] += 1
            org_values.add(f"ssl:issuer:{issuer}")
        not_before = _date_to_text(row.get("not_before"))
        if not_before:
            not_before_counter[not_before] += 1
        not_after = _date_to_text(row.get("not_after"))
        if not_after:
            not_after_counter[not_after] += 1
        if row.get("is_self_signed"):
            self_signed_count += 1

    return (
        {
            "fingerprints": _counter_to_dict(fingerprint_counter),
            "fingerprint_frequency": _counter_to_dict(fingerprint_counter),
            "serial_numbers": _counter_to_dict(serial_counter),
            "serial_number_frequency": _counter_to_dict(serial_counter),
            "san": _counter_to_dict(san_counter),
            "san_frequency": _counter_to_dict(san_counter),
            "subject": _counter_to_dict(subject_counter),
            "subject_frequency": _counter_to_dict(subject_counter),
            "issuer": _counter_to_dict(issuer_counter),
            "issuer_frequency": _counter_to_dict(issuer_counter),
            "not_before": _counter_to_dict(not_before_counter),
            "not_after": _counter_to_dict(not_after_counter),
            "self_signed_count": self_signed_count,
        },
        org_values,
    )


def _load_rows(db) -> Tuple[
    Dict[int, List[Mapping[str, Any]]],
    Dict[int, str],
    Dict[int, List[Mapping[str, Any]]],
    Dict[int, List[Mapping[str, Any]]],
    Dict[int, List[Mapping[str, Any]]],
]:
    domain_rows = db.execute(
        text(
            """
            SELECT d.id AS domain_id,
                   d.domain_name,
                   d.organization_id,
                   o.name AS organization_name
            FROM domains d
            LEFT JOIN apt_organizations o ON o.id = d.organization_id
            WHERE d.organization_id IS NOT NULL
              AND d.domain_name IS NOT NULL
              AND TRIM(d.domain_name) <> ''
            ORDER BY d.organization_id ASC, d.domain_name ASC
            """
        )
    ).mappings().all()

    domains_by_org: Dict[int, List[Mapping[str, Any]]] = defaultdict(list)
    org_names: Dict[int, str] = {}
    for row in domain_rows:
        org_id = int(row["organization_id"])
        domains_by_org[org_id].append(row)
        if row.get("organization_name"):
            org_names[org_id] = str(row.get("organization_name"))

    whois_by_org = _load_source_rows(
        db,
        """
        SELECT d.organization_id,
               w.registrar,
               w.name_servers,
               w.registration_date,
               w.expiration_date,
               w.status
        FROM whois_info w
        INNER JOIN domains d ON d.id = w.domain_id
        WHERE d.organization_id IS NOT NULL
        """,
    )
    dns_by_org = _load_source_rows(
        db,
        """
        SELECT d.organization_id,
               r.record_type,
               r.record_value,
               r.ttl
        FROM dns_records r
        INNER JOIN domains d ON d.id = r.domain_id
        WHERE d.organization_id IS NOT NULL
        """,
    )
    ssl_by_org = _load_source_rows(
        db,
        """
        SELECT d.organization_id,
               c.fingerprint,
               c.serial_number,
               c.san_names,
               c.subject,
               c.issuer,
               c.not_before,
               c.not_after,
               c.is_self_signed
        FROM ssl_certificates c
        INNER JOIN domains d ON d.id = c.domain_id
        WHERE d.organization_id IS NOT NULL
        """,
    )
    return domains_by_org, org_names, whois_by_org, dns_by_org, ssl_by_org


def _load_source_rows(db, query_sql: str) -> Dict[int, List[Mapping[str, Any]]]:
    rows = db.execute(text(query_sql)).mappings().all()
    grouped: Dict[int, List[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[int(row["organization_id"])].append(row)
    return grouped


def _upsert_profile(
    db,
    *,
    profile_key: str,
    profile_type: str,
    organization_id: Optional[int],
    organization_name: Optional[str],
    domain_profile: Optional[Dict[str, Any]],
    whois_profile: Optional[Dict[str, Any]],
    dns_profile: Optional[Dict[str, Any]],
    ssl_profile: Optional[Dict[str, Any]],
    global_stats: Optional[Dict[str, Any]],
    summary: Dict[str, Any],
    build_meta: Dict[str, Any],
    source_domain_count: int,
    whois_record_count: int,
    dns_record_count: int,
    ssl_record_count: int,
    built_at: datetime,
) -> None:
    db.execute(
        text(
            """
            INSERT INTO actor_infra_profiles (
                profile_key,
                profile_type,
                organization_id,
                organization_name,
                profile_version,
                profile_status,
                domain_profile_json,
                whois_profile_json,
                dns_profile_json,
                ssl_profile_json,
                global_stats_json,
                summary_json,
                build_meta_json,
                source_domain_count,
                whois_record_count,
                dns_record_count,
                ssl_record_count,
                last_built_at
            ) VALUES (
                :profile_key,
                :profile_type,
                :organization_id,
                :organization_name,
                1,
                'active',
                :domain_profile_json,
                :whois_profile_json,
                :dns_profile_json,
                :ssl_profile_json,
                :global_stats_json,
                :summary_json,
                :build_meta_json,
                :source_domain_count,
                :whois_record_count,
                :dns_record_count,
                :ssl_record_count,
                :last_built_at
            )
            ON DUPLICATE KEY UPDATE
                profile_type = VALUES(profile_type),
                organization_id = VALUES(organization_id),
                organization_name = VALUES(organization_name),
                profile_version = profile_version + 1,
                profile_status = 'active',
                domain_profile_json = VALUES(domain_profile_json),
                whois_profile_json = VALUES(whois_profile_json),
                dns_profile_json = VALUES(dns_profile_json),
                ssl_profile_json = VALUES(ssl_profile_json),
                global_stats_json = VALUES(global_stats_json),
                summary_json = VALUES(summary_json),
                build_meta_json = VALUES(build_meta_json),
                source_domain_count = VALUES(source_domain_count),
                whois_record_count = VALUES(whois_record_count),
                dns_record_count = VALUES(dns_record_count),
                ssl_record_count = VALUES(ssl_record_count),
                last_built_at = VALUES(last_built_at)
            """
        ),
        {
            "profile_key": profile_key,
            "profile_type": profile_type,
            "organization_id": organization_id,
            "organization_name": organization_name,
            "domain_profile_json": _json_dumps(domain_profile) if domain_profile is not None else None,
            "whois_profile_json": _json_dumps(whois_profile) if whois_profile is not None else None,
            "dns_profile_json": _json_dumps(dns_profile) if dns_profile is not None else None,
            "ssl_profile_json": _json_dumps(ssl_profile) if ssl_profile is not None else None,
            "global_stats_json": _json_dumps(global_stats) if global_stats is not None else None,
            "summary_json": _json_dumps(summary),
            "build_meta_json": _json_dumps(build_meta),
            "source_domain_count": source_domain_count,
            "whois_record_count": whois_record_count,
            "dns_record_count": dns_record_count,
            "ssl_record_count": ssl_record_count,
            "last_built_at": built_at,
        },
    )


def rebuild_actor_infra_profiles(db) -> dict:
    """
    Rebuild actor and global infrastructure profiles from historical domain data.
    Source tables are read-only; only actor_infra_profiles is inserted/updated.
    """
    built_at = datetime.now()
    stats = {"json_parse_errors": 0, "row_errors": 0, "organization_errors": 0}
    org_value_sets: Dict[int, Set[str]] = defaultdict(set)

    try:
        domains_by_org, org_names, whois_by_org, dns_by_org, ssl_by_org = _load_rows(db)

        total_domain_count = sum(len(rows) for rows in domains_by_org.values())
        total_whois_count = sum(len(rows) for rows in whois_by_org.values())
        total_dns_count = sum(len(rows) for rows in dns_by_org.values())
        total_ssl_count = sum(len(rows) for rows in ssl_by_org.values())
        built_org_count = 0

        for org_id, domain_rows in sorted(domains_by_org.items()):
            try:
                whois_rows = whois_by_org.get(org_id, [])
                dns_rows = dns_by_org.get(org_id, [])
                ssl_rows = ssl_by_org.get(org_id, [])

                domain_profile, domain_values = _build_domain_profile(domain_rows)
                whois_profile, whois_values = _build_whois_profile(whois_rows, stats)
                dns_profile, dns_values = _build_dns_profile(dns_rows)
                ssl_profile, ssl_values = _build_ssl_profile(ssl_rows, stats)

                org_value_sets[org_id].update(f"domain:{value}" for value in domain_values)
                org_value_sets[org_id].update(whois_values)
                org_value_sets[org_id].update(dns_values)
                org_value_sets[org_id].update(ssl_values)

                summary = {
                    "organization_id": org_id,
                    "organization_name": org_names.get(org_id),
                    "source_domain_count": len(domain_rows),
                    "whois_record_count": len(whois_rows),
                    "dns_record_count": len(dns_rows),
                    "ssl_record_count": len(ssl_rows),
                    "top_tlds": _top(Counter(domain_profile["tld_frequency"])),
                    "top_tokens": _top(Counter(domain_profile["token_frequency"])),
                    "top_registrars": _top(Counter(whois_profile["registrar_frequency"])),
                    "top_dns_ips": _top(Counter(dns_profile["ip_frequency"])),
                    "top_ssl_issuers": _top(Counter(ssl_profile["issuer_frequency"])),
                }
                build_meta = {
                    "built_at": built_at.isoformat(),
                    "source_tables": SOURCE_TABLES,
                    "exception_counts": dict(stats),
                }

                _upsert_profile(
                    db,
                    profile_key=f"actor:{org_id}",
                    profile_type="actor",
                    organization_id=org_id,
                    organization_name=org_names.get(org_id),
                    domain_profile=domain_profile,
                    whois_profile=whois_profile,
                    dns_profile=dns_profile,
                    ssl_profile=ssl_profile,
                    global_stats=None,
                    summary=summary,
                    build_meta=build_meta,
                    source_domain_count=len(domain_rows),
                    whois_record_count=len(whois_rows),
                    dns_record_count=len(dns_rows),
                    ssl_record_count=len(ssl_rows),
                    built_at=built_at,
                )
                built_org_count += 1
            except Exception as exc:
                stats["organization_errors"] += 1
                logger.exception("构建组织基础设施画像失败 organization_id=%s err=%s", org_id, exc)

        global_counter: Counter = Counter()
        for org_values in org_value_sets.values():
            for value in org_values:
                global_counter[value] += 1

        global_stats = {
            "organization_count": built_org_count,
            "value_organization_frequency": _counter_to_dict(global_counter),
            "public_infra_candidates": [
                {"value": value, "organization_count": count}
                for value, count in sorted(
                    global_counter.items(), key=lambda item: (-item[1], item[0])
                )
                if count > 1
            ],
        }
        global_summary = {
            "organization_count": built_org_count,
            "source_domain_count": total_domain_count,
            "whois_record_count": total_whois_count,
            "dns_record_count": total_dns_count,
            "ssl_record_count": total_ssl_count,
            "public_infra_candidate_count": len(global_stats["public_infra_candidates"]),
        }
        global_build_meta = {
            "built_at": built_at.isoformat(),
            "source_tables": SOURCE_TABLES,
            "exception_counts": dict(stats),
            "aggregation_rule": "each infrastructure value is counted once per organization",
        }

        _upsert_profile(
            db,
            profile_key=GLOBAL_PROFILE_KEY,
            profile_type="global",
            organization_id=None,
            organization_name=None,
            domain_profile=None,
            whois_profile=None,
            dns_profile=None,
            ssl_profile=None,
            global_stats=global_stats,
            summary=global_summary,
            build_meta=global_build_meta,
            source_domain_count=total_domain_count,
            whois_record_count=total_whois_count,
            dns_record_count=total_dns_count,
            ssl_record_count=total_ssl_count,
            built_at=built_at,
        )

        db.commit()
        return {
            "success": True,
            "built_organization_count": built_org_count,
            "global_profile_built": True,
            "source_domain_count": total_domain_count,
            "whois_record_count": total_whois_count,
            "dns_record_count": total_dns_count,
            "ssl_record_count": total_ssl_count,
            "exception_counts": dict(stats),
        }
    except Exception as exc:
        db.rollback()
        logger.exception("重建组织基础设施画像失败: %s", exc)
        return {
            "success": False,
            "built_organization_count": 0,
            "global_profile_built": False,
            "source_domain_count": 0,
            "whois_record_count": 0,
            "dns_record_count": 0,
            "ssl_record_count": 0,
            "exception_counts": dict(stats),
            "error": str(exc),
        }
