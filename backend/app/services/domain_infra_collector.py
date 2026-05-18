import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List

from sqlalchemy import bindparam, text

from app.api.domain_lookup import DomainLookupRequest, lookup_all

logger = logging.getLogger("uvicorn.error")


def _normalize_domains(domains: Iterable[str]) -> List[str]:
    normalized = []
    seen = set()
    for value in domains or []:
        domain = str(value or "").strip()
        domain_key = domain.lower()
        if not domain or domain_key in seen:
            continue
        seen.add(domain_key)
        normalized.append(domain)
    return normalized


def _find_domains_without_cached_infra(db, domains: List[str]) -> List[str]:
    """
    Return domains that currently have no cached WHOIS/DNS/SSL data at all.

    We intentionally only collect domains with completely empty infrastructure
    snapshots here. This fixes the all-zero attribution case without repeatedly
    re-querying domains that already have at least some usable cached evidence.
    """
    if not domains:
        return []

    statement = text(
        """
        SELECT
            d.domain_name,
            EXISTS(SELECT 1 FROM whois_info w WHERE w.domain_id = d.id) AS has_whois,
            EXISTS(SELECT 1 FROM dns_records r WHERE r.domain_id = d.id) AS has_dns,
            EXISTS(SELECT 1 FROM ssl_certificates c WHERE c.domain_id = d.id) AS has_ssl
        FROM domains d
        WHERE d.domain_name IN :domains
        """
    ).bindparams(bindparam("domains", expanding=True))

    rows = db.execute(statement, {"domains": domains}).mappings().all()
    cached_by_domain = {
        str(row["domain_name"]).lower(): bool(row["has_whois"] or row["has_dns"] or row["has_ssl"])
        for row in rows
    }
    return [
        domain
        for domain in domains
        if not cached_by_domain.get(domain.lower(), False)
    ]


def _collect_one_domain(domain: str) -> Dict[str, Any]:
    try:
        response = lookup_all(DomainLookupRequest(domain=domain, save=True))
        payload = json.loads(response.body)
        data = payload.get("data") or {}
        return {
            "domain": domain,
            "code": payload.get("code"),
            "saved": bool(data.get("saved")),
            "has_whois": bool(data.get("whois")),
            "has_dns": bool(data.get("dns")),
            "has_ssl": bool(data.get("certificate")),
            "errors": data.get("errors") or [],
        }
    except Exception as exc:
        logger.exception("归因前基础设施采集失败 domain=%s", domain)
        return {
            "domain": domain,
            "code": None,
            "saved": False,
            "has_whois": False,
            "has_dns": False,
            "has_ssl": False,
            "errors": [str(exc)],
        }


def collect_missing_domain_infra(
    db,
    domains: Iterable[str],
    *,
    max_workers: int = 8,
) -> Dict[str, Any]:
    """
    Collect WHOIS/DNS/SSL for domains that have no cached infra at all.

    The collector reuses the existing lookup-all path and parallelizes across
    domains because WHOIS/DNS/SSL are network-bound operations.
    """
    normalized_domains = _normalize_domains(domains)
    missing_domains = _find_domains_without_cached_infra(db, normalized_domains)
    if not missing_domains:
        return {
            "requested_count": len(normalized_domains),
            "to_collect_count": 0,
            "collected_count": 0,
            "saved_count": 0,
            "results": [],
        }

    worker_count = max(1, min(int(max_workers or 1), len(missing_domains)))
    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_domain = {
            executor.submit(_collect_one_domain, domain): domain
            for domain in missing_domains
        }
        for future in as_completed(future_to_domain):
            results.append(future.result())

    collected_count = sum(
        1
        for item in results
        if item["has_whois"] or item["has_dns"] or item["has_ssl"]
    )
    saved_count = sum(1 for item in results if item["saved"])
    logger.info(
        "归因前基础设施采集完成 requested=%s to_collect=%s collected=%s saved=%s workers=%s",
        len(normalized_domains),
        len(missing_domains),
        collected_count,
        saved_count,
        worker_count,
    )
    return {
        "requested_count": len(normalized_domains),
        "to_collect_count": len(missing_domains),
        "collected_count": collected_count,
        "saved_count": saved_count,
        "results": results,
    }
