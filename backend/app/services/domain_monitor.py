from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.api.domain_lookup import DomainLookupRequest, lookup_all
from app.db.session import SessionLocal
from app.entities import DomainMonitorSnapshot, DomainMonitorSource, DomainMonitorTarget

logger = logging.getLogger("uvicorn.error")

ALLOWED_SOURCE_TYPES = {"subscription_alert", "detection_task", "manual"}
DEFAULT_MONITOR_INTERVAL_HOURS = int(os.getenv("DOMAIN_MONITOR_INTERVAL_HOURS", "24"))
DOMAIN_MONITOR_BATCH_LIMIT = int(os.getenv("DOMAIN_MONITOR_BATCH_LIMIT", "50"))
DOMAIN_MONITOR_LEASE_MINUTES = int(os.getenv("DOMAIN_MONITOR_LEASE_MINUTES", "30"))
DOMAIN_MONITOR_RETRY_HOURS = int(os.getenv("DOMAIN_MONITOR_RETRY_HOURS", "6"))
WEB_TIMEOUT_SECONDS = float(os.getenv("DOMAIN_MONITOR_WEB_TIMEOUT_SECONDS", "8"))
WEB_MAX_BYTES = int(os.getenv("DOMAIN_MONITOR_WEB_MAX_BYTES", str(1024 * 1024)))
WEB_MAX_REDIRECTS = int(os.getenv("DOMAIN_MONITOR_WEB_MAX_REDIRECTS", "3"))
WEB_USER_AGENT = os.getenv(
    "DOMAIN_MONITOR_WEB_USER_AGENT",
    "APTHunter-Domain-Monitor/1.0",
)
WEB_ALLOW_NON_PUBLIC_NETWORKS = (
    os.getenv("DOMAIN_MONITOR_WEB_ALLOW_NON_PUBLIC_NETWORKS", "false").strip().lower()
    in {"1", "true", "yes", "y", "on"}
)


def _now() -> datetime:
    return datetime.now().replace(microsecond=0)


def normalize_domain(value: Any) -> Optional[str]:
    domain = str(value or "").strip().lower()
    if not domain:
        return None
    domain = re.sub(r"^[a-z][a-z0-9+.-]*://", "", domain)
    domain = domain.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in domain:
        domain = domain.rsplit("@", 1)[-1]
    if domain.startswith("*."):
        domain = domain[2:]
    if ":" in domain:
        domain = domain.split(":", 1)[0]
    domain = domain.strip(".")
    if not domain or len(domain) > 255:
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass
    try:
        domain = domain.encode("idna").decode("ascii")
    except Exception:
        return None
    if "." not in domain:
        return None
    if not re.match(r"^[a-z0-9.-]+$", domain):
        return None
    return domain


def _coerce_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _json_compatible(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(k): _json_compatible(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_compatible(v) for v in value]
    return str(value)


def _domain_from_risk_record(record: Mapping[str, Any]) -> Optional[str]:
    for key in ("domain", "域名", "phishing_domain", "钓鱼域名", "candidate_domain", "候选域名"):
        domain = normalize_domain(record.get(key))
        if domain:
            return domain
    return None


def _build_risk_record_map(risk_records: Optional[Sequence[Mapping[str, Any]]]) -> Dict[str, Mapping[str, Any]]:
    result: Dict[str, Mapping[str, Any]] = {}
    for record in risk_records or []:
        if not isinstance(record, Mapping):
            continue
        domain = _domain_from_risk_record(record)
        if domain and domain not in result:
            result[domain] = record
    return result


def _risk_score_from_record(record: Optional[Mapping[str, Any]]) -> Optional[float]:
    if not record:
        return None
    for key in ("risk_score", "score", "dga_score", "恶意概率", "相似度", "置信度"):
        score = _coerce_float(record.get(key))
        if score is not None:
            return score
    return None


def _risk_level_from_record(record: Optional[Mapping[str, Any]], score: Optional[float]) -> Optional[str]:
    if record:
        for key in ("risk_level", "level", "风险等级"):
            value = record.get(key)
            if value:
                return str(value)
    if score is None:
        return None
    if score >= 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


def _source_exists(
    db: Session,
    *,
    target_id: int,
    source_type: str,
    task_id: Optional[str],
    subscription_id: Optional[str],
    alert_id: Optional[str],
) -> bool:
    query = db.query(DomainMonitorSource).filter(
        DomainMonitorSource.target_id == target_id,
        DomainMonitorSource.source_type == source_type,
    )
    if task_id:
        query = query.filter(DomainMonitorSource.task_id == task_id)
    else:
        query = query.filter(DomainMonitorSource.task_id.is_(None))
    if subscription_id:
        query = query.filter(DomainMonitorSource.subscription_id == subscription_id)
    else:
        query = query.filter(DomainMonitorSource.subscription_id.is_(None))
    if alert_id:
        query = query.filter(DomainMonitorSource.alert_id == alert_id)
    else:
        query = query.filter(DomainMonitorSource.alert_id.is_(None))
    return db.query(query.exists()).scalar()


def register_monitor_targets(
    db: Session,
    *,
    user_id: int,
    domains: Iterable[str],
    source_type: str,
    task_id: Optional[str] = None,
    task_type: Optional[str] = None,
    model_id: Optional[int] = None,
    subscription_id: Optional[str] = None,
    alert_id: Optional[str] = None,
    risk_records: Optional[Sequence[Mapping[str, Any]]] = None,
    detected_at: Optional[datetime] = None,
    monitor_interval_hours: Optional[int] = None,
) -> Dict[str, Any]:
    """
    将检测结果域名注册为持续监控目标。
    当前接入 subscription_alert；后续人工任务只需传 source_type=detection_task。
    """
    if source_type not in ALLOWED_SOURCE_TYPES:
        raise ValueError(f"unsupported monitor source_type: {source_type}")
    if user_id is None:
        raise ValueError("user_id is required")

    now = _now()
    interval_hours = max(1, int(monitor_interval_hours or DEFAULT_MONITOR_INTERVAL_HOURS))
    risk_by_domain = _build_risk_record_map(risk_records)

    requested_domains = list(domains or [])
    normalized_domains: List[tuple[str, str]] = []
    seen = set()
    skipped_domains = []
    for value in requested_domains:
        display_domain = str(value or "").strip()
        normalized = normalize_domain(display_domain)
        if not normalized:
            if display_domain:
                skipped_domains.append(display_domain)
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        normalized_domains.append((display_domain or normalized, normalized))

    created_targets = 0
    reused_targets = 0
    created_sources = 0
    for display_domain, normalized in normalized_domains:
        target = (
            db.query(DomainMonitorTarget)
            .filter(
                DomainMonitorTarget.user_id == int(user_id),
                DomainMonitorTarget.normalized_domain == normalized,
            )
            .first()
        )
        if target is None:
            target = DomainMonitorTarget(
                user_id=int(user_id),
                domain=display_domain,
                normalized_domain=normalized,
                is_active=True,
                monitor_interval_hours=interval_hours,
                next_check_at=now,
                status="pending",
                consecutive_failures=0,
            )
            db.add(target)
            db.flush()
            created_targets += 1
        else:
            reused_targets += 1
            target.is_active = True
            target.domain = target.domain or display_domain
            target.monitor_interval_hours = target.monitor_interval_hours or interval_hours
            if not target.last_checked_at and (not target.next_check_at or target.next_check_at > now):
                target.next_check_at = now
            if target.status == "paused":
                target.status = "pending"

        if _source_exists(
            db,
            target_id=int(target.id),
            source_type=source_type,
            task_id=task_id,
            subscription_id=subscription_id,
            alert_id=alert_id,
        ):
            continue

        risk_record = risk_by_domain.get(normalized)
        risk_score = _risk_score_from_record(risk_record)
        db.add(
            DomainMonitorSource(
                target_id=int(target.id),
                source_type=source_type,
                task_id=task_id,
                task_type=task_type,
                model_id=model_id,
                subscription_id=subscription_id,
                alert_id=alert_id,
                risk_score=risk_score,
                risk_level=_risk_level_from_record(risk_record, risk_score),
                risk_record=_json_compatible(risk_record) if risk_record else None,
                detected_at=detected_at or now,
            )
        )
        created_sources += 1

    return {
        "requested_count": len(requested_domains),
        "accepted_count": len(normalized_domains),
        "created_targets": created_targets,
        "reused_targets": reused_targets,
        "created_sources": created_sources,
        "skipped_domains": skipped_domains,
    }


def _parse_lookup_response(domain: str) -> Dict[str, Any]:
    response = lookup_all(DomainLookupRequest(domain=domain, save=True))
    try:
        payload = json.loads(response.body)
    except Exception as exc:
        raise RuntimeError(f"域名基础设施查询响应解析失败: {exc}") from exc
    data = payload.get("data") or {}
    if not isinstance(data, Mapping):
        data = {}
    return dict(data)


def _normalize_whois_snapshot(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping):
        return None
    return _json_compatible(
        {
            "domain": value.get("domain"),
            "registrar": value.get("registrar"),
            "registration_date": value.get("registrationDate"),
            "expiration_date": value.get("expirationDate"),
            "updated_date": value.get("updatedDate"),
            "name_servers": sorted(value.get("nameServers") or []),
            "status": sorted(value.get("status") or []),
            "registrant": value.get("registrant"),
            "emails": sorted(value.get("emails") or []),
        }
    )


def _normalize_dns_snapshot(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping):
        return None
    records = []
    for item in value.get("records") or []:
        if not isinstance(item, Mapping):
            continue
        records.append(
            {
                "type": item.get("type"),
                "name": item.get("name"),
                "value": item.get("value"),
                "ttl": item.get("ttl"),
                "priority": item.get("priority"),
            }
        )
    records.sort(
        key=lambda item: (
            str(item.get("type") or ""),
            str(item.get("name") or ""),
            str(item.get("value") or ""),
            str(item.get("ttl") or ""),
            str(item.get("priority") or ""),
        )
    )
    return _json_compatible({"domain": value.get("domain"), "records": records})


def _normalize_certificate_snapshot(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping):
        return None
    validity = value.get("validity") if isinstance(value.get("validity"), Mapping) else {}
    return _json_compatible(
        {
            "domain": value.get("domain"),
            "issuer": value.get("issuer"),
            "subject": value.get("subject"),
            "not_before": validity.get("notBefore"),
            "not_after": validity.get("notAfter"),
            "algorithm": value.get("algorithm"),
            "key_size": value.get("keySize"),
            "serial_number": value.get("serialNumber"),
            "fingerprint": value.get("fingerprint"),
            "san_names": sorted(value.get("sanNames") or []),
            "is_expired": value.get("isExpired"),
            "is_self_signed": value.get("isSelfSigned"),
        }
    )


def _is_public_ip(ip_text: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    return bool(getattr(ip, "is_global", False))


def _is_always_blocked_web_ip(ip_text: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return True
    return any(
        [
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_unspecified,
        ]
    )


def _ensure_public_hostname(hostname: str) -> None:
    normalized = normalize_domain(hostname)
    if not normalized:
        try:
            if _is_always_blocked_web_ip(hostname):
                raise ValueError("目标不是公网域名或公网IP")
            if not WEB_ALLOW_NON_PUBLIC_NETWORKS and not _is_public_ip(hostname):
                raise ValueError("目标不是公网域名或公网IP")
        except ValueError as exc:
            raise ValueError("目标不是可抓取的公网域名") from exc
        return
    if normalized in {"localhost"} or normalized.endswith(".localhost"):
        raise ValueError("禁止抓取本地域名")
    try:
        infos = socket.getaddrinfo(normalized, None)
    except socket.gaierror as exc:
        raise ValueError(f"域名解析失败: {exc}") from exc
    ips = {info[4][0] for info in infos if info and info[4]}
    if not ips:
        raise ValueError("域名未解析出IP")
    blocked = [
        ip
        for ip in ips
        if _is_always_blocked_web_ip(ip)
        or (not WEB_ALLOW_NON_PUBLIC_NETWORKS and not _is_public_ip(ip))
    ]
    if blocked:
        raise ValueError("域名解析到非公网地址，已阻止网页抓取")


def _validate_fetch_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("只允许抓取 HTTP/HTTPS URL")
    if not parsed.hostname:
        raise ValueError("URL 缺少主机名")
    _ensure_public_hostname(parsed.hostname)
    return url


def _read_limited_response(response: requests.Response, max_bytes: int) -> tuple[bytes, bool]:
    chunks: List[bytes] = []
    total = 0
    truncated = False
    for chunk in response.iter_content(chunk_size=16384):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            remaining = max(0, max_bytes - sum(len(item) for item in chunks))
            if remaining:
                chunks.append(chunk[:remaining])
            truncated = True
            break
        chunks.append(chunk)
    return b"".join(chunks), truncated


def _extract_web_page_summary(content: bytes, content_type: str) -> Dict[str, Any]:
    encoding = "utf-8"
    text = content.decode(encoding, errors="replace")
    title = None
    body_text = ""
    if "html" in (content_type or "").lower() or text.lstrip().startswith("<"):
        soup = BeautifulSoup(text, "lxml")
        if soup.title and soup.title.string:
            title = re.sub(r"\s+", " ", soup.title.string).strip()
        body_text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()
    else:
        body_text = re.sub(r"\s+", " ", text).strip()
    return {
        "title": title,
        "text_hash": hashlib.sha256(body_text.encode("utf-8", errors="ignore")).hexdigest(),
        "html_hash": hashlib.sha256(content).hexdigest(),
        "body_excerpt": body_text[:1000] if body_text else None,
    }


def collect_web_snapshot(domain: str) -> Dict[str, Any]:
    errors = []
    for scheme in ("https", "http"):
        current_url = f"{scheme}://{domain}/"
        redirect_chain = []
        try:
            session = requests.Session()
            session.trust_env = False
            for _ in range(WEB_MAX_REDIRECTS + 1):
                _validate_fetch_url(current_url)
                response = session.get(
                    current_url,
                    headers={"User-Agent": WEB_USER_AGENT},
                    timeout=WEB_TIMEOUT_SECONDS,
                    allow_redirects=False,
                    stream=True,
                    verify=False,
                )
                status_code = int(response.status_code)
                redirect_chain.append({"url": current_url, "status_code": status_code})
                if status_code in {301, 302, 303, 307, 308} and response.headers.get("Location"):
                    current_url = urljoin(current_url, response.headers["Location"])
                    continue

                content, truncated = _read_limited_response(response, WEB_MAX_BYTES)
                content_type = response.headers.get("content-type") or ""
                summary = _extract_web_page_summary(content, content_type)
                return _json_compatible(
                    {
                        "status": "collected",
                        "scheme": scheme,
                        "status_code": status_code,
                        "final_url": current_url,
                        "redirect_chain": redirect_chain,
                        "content_type": content_type,
                        "content_length": len(content),
                        "truncated": truncated,
                        "fetched_at": _now().isoformat(),
                        **summary,
                    }
                )
            errors.append(f"{scheme.upper()} 重定向超过限制")
        except Exception as exc:
            errors.append(f"{scheme.upper()}: {exc}")
    return {
        "status": "failed",
        "errors": errors,
        "fetched_at": _now().isoformat(),
    }


def _stable_compare_value(section_name: str, value: Any) -> Any:
    normalized = _json_compatible(value)
    if section_name == "dns" and isinstance(normalized, Mapping):
        records = []
        for record in normalized.get("records") or []:
            if not isinstance(record, Mapping):
                continue
            records.append({key: val for key, val in record.items() if key != "ttl"})
        records.sort(
            key=lambda item: (
                str(item.get("type") or ""),
                str(item.get("name") or ""),
                str(item.get("value") or ""),
                str(item.get("priority") or ""),
            )
        )
        normalized = {**normalized, "records": records}
    elif section_name == "web" and isinstance(normalized, Mapping):
        normalized = {key: val for key, val in normalized.items() if key != "fetched_at"}
    return normalized


def _section_hash(section_name: str, value: Any) -> Optional[str]:
    if value is None:
        return None
    payload = json.dumps(
        _stable_compare_value(section_name, value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _snapshot_hashes(snapshot: Optional[DomainMonitorSnapshot] = None, sections: Optional[Mapping[str, Any]] = None) -> Dict[str, Optional[str]]:
    if sections is None:
        sections = {
            "whois": snapshot.whois_snapshot if snapshot else None,
            "dns": snapshot.dns_snapshot if snapshot else None,
            "certificate": snapshot.certificate_snapshot if snapshot else None,
            "web": snapshot.web_snapshot if snapshot else None,
        }
    return {name: _section_hash(name, value) for name, value in sections.items()}


def _build_changed_fields(previous: Optional[DomainMonitorSnapshot], current_sections: Mapping[str, Any]) -> Dict[str, Any]:
    current_hashes = _snapshot_hashes(sections=current_sections)
    if previous is None:
        return {
            "is_first_snapshot": True,
            "sections": [],
            "previous_hashes": {},
            "current_hashes": current_hashes,
        }
    previous_hashes = _snapshot_hashes(previous)
    changed = [
        name
        for name, current_hash in current_hashes.items()
        if current_hash != previous_hashes.get(name)
    ]
    return {
        "is_first_snapshot": False,
        "sections": changed,
        "previous_hashes": previous_hashes,
        "current_hashes": current_hashes,
    }


def collect_domain_monitor_snapshot(target_id: int) -> Dict[str, Any]:
    db = SessionLocal()
    try:
        target = db.query(DomainMonitorTarget).filter(DomainMonitorTarget.id == int(target_id)).first()
        if not target or not target.is_active:
            return {"ok": False, "target_id": target_id, "reason": "monitor target not found or inactive"}

        target.status = "checking"
        db.commit()
        db.refresh(target)

        collected_at = _now()
        errors: List[str] = []
        lookup_data: Dict[str, Any] = {}
        try:
            lookup_data = _parse_lookup_response(target.normalized_domain)
        except Exception as exc:
            logger.exception("域名基础设施监控采集失败 target_id=%s domain=%s", target.id, target.normalized_domain)
            errors.append(str(exc))

        raw_lookup_errors = list(lookup_data.get("errors") or [])
        errors.extend(str(item) for item in raw_lookup_errors)
        whois_snapshot = _normalize_whois_snapshot(lookup_data.get("whois"))
        dns_snapshot = _normalize_dns_snapshot(lookup_data.get("dns"))
        certificate_snapshot = _normalize_certificate_snapshot(lookup_data.get("certificate"))
        web_snapshot = collect_web_snapshot(target.normalized_domain)
        if web_snapshot.get("status") == "failed":
            errors.extend(str(item) for item in web_snapshot.get("errors") or [])

        sections = {
            "whois": whois_snapshot,
            "dns": dns_snapshot,
            "certificate": certificate_snapshot,
            "web": web_snapshot,
        }
        previous = (
            db.query(DomainMonitorSnapshot)
            .filter(DomainMonitorSnapshot.target_id == target.id)
            .order_by(DomainMonitorSnapshot.collected_at.desc(), DomainMonitorSnapshot.id.desc())
            .first()
        )
        changed_fields = _build_changed_fields(previous, sections)

        collected_sections = [
            bool(whois_snapshot),
            bool(dns_snapshot and dns_snapshot.get("records")),
            bool(certificate_snapshot),
            bool(web_snapshot and web_snapshot.get("status") == "collected"),
        ]
        if any(collected_sections) and errors:
            snapshot_status = "partial"
        elif any(collected_sections):
            snapshot_status = "success"
        else:
            snapshot_status = "failed"

        error_message = "; ".join(errors[:5]) if errors else None
        snapshot = DomainMonitorSnapshot(
            target_id=int(target.id),
            status=snapshot_status,
            collected_at=collected_at,
            whois_snapshot=whois_snapshot,
            dns_snapshot=dns_snapshot,
            certificate_snapshot=certificate_snapshot,
            web_snapshot=web_snapshot,
            changed_fields=changed_fields,
            raw_lookup_errors=raw_lookup_errors or None,
            error_message=error_message,
        )
        db.add(snapshot)
        db.flush()

        target.last_checked_at = collected_at
        if snapshot_status == "failed":
            target.status = "failed"
            target.consecutive_failures = int(target.consecutive_failures or 0) + 1
            target.last_error = error_message
            target.next_check_at = collected_at + timedelta(hours=max(1, min(DOMAIN_MONITOR_RETRY_HOURS, target.monitor_interval_hours or DEFAULT_MONITOR_INTERVAL_HOURS)))
        else:
            target.status = "active"
            target.consecutive_failures = 0
            target.last_error = None
            target.next_check_at = collected_at + timedelta(hours=max(1, int(target.monitor_interval_hours or DEFAULT_MONITOR_INTERVAL_HOURS)))

        db.commit()
        return {
            "ok": True,
            "target_id": int(target.id),
            "snapshot_id": int(snapshot.id),
            "status": snapshot_status,
            "changed_fields": changed_fields.get("sections") or [],
        }
    except Exception:
        db.rollback()
        logger.exception("域名持续监控快照任务异常 target_id=%s", target_id)
        raise
    finally:
        db.close()


def dispatch_due_monitor_targets(limit: Optional[int] = None) -> Dict[str, Any]:
    from app.services.task_dispatcher import dispatch_domain_monitor_snapshot_task

    db = SessionLocal()
    now = _now()
    max_count = max(1, int(limit or DOMAIN_MONITOR_BATCH_LIMIT))
    dispatched = 0
    failed = 0
    target_ids: List[int] = []
    try:
        targets = (
            db.query(DomainMonitorTarget)
            .filter(
                DomainMonitorTarget.is_active == True,
                DomainMonitorTarget.next_check_at <= now,
            )
            .order_by(DomainMonitorTarget.next_check_at.asc(), DomainMonitorTarget.id.asc())
            .limit(max_count)
            .all()
        )
        for target in targets:
            target.status = "checking"
            target.next_check_at = now + timedelta(minutes=max(5, DOMAIN_MONITOR_LEASE_MINUTES))
            db.commit()
            try:
                dispatch_domain_monitor_snapshot_task(int(target.id))
                dispatched += 1
                target_ids.append(int(target.id))
            except Exception as exc:
                db.rollback()
                failed += 1
                failed_target = db.query(DomainMonitorTarget).filter(DomainMonitorTarget.id == target.id).first()
                if failed_target:
                    failed_target.status = "failed"
                    failed_target.last_error = f"入队失败: {exc}"
                    failed_target.next_check_at = now + timedelta(hours=1)
                    db.commit()
                logger.exception("域名监控任务入队失败 target_id=%s", target.id)
        return {
            "checked_at": now.isoformat(),
            "due_count": len(targets),
            "dispatched_count": dispatched,
            "failed_count": failed,
            "target_ids": target_ids,
        }
    finally:
        db.close()


def mark_target_due_now(db: Session, *, target_id: int, user_id: int) -> DomainMonitorTarget:
    target = (
        db.query(DomainMonitorTarget)
        .filter(
            DomainMonitorTarget.id == int(target_id),
            DomainMonitorTarget.user_id == int(user_id),
        )
        .first()
    )
    if not target:
        raise ValueError("监控目标不存在")
    target.is_active = True
    target.next_check_at = _now()
    if target.status == "paused":
        target.status = "pending"
    db.flush()
    return target
