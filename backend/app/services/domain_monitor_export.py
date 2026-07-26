from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.entities import DomainMonitorSnapshot, DomainMonitorSource, DomainMonitorTarget


TARGET_STATUS_LABELS = {
    "pending": "待查询",
    "checking": "查询中",
    "active": "正常追踪",
    "failed": "查询失败",
    "paused": "已暂停",
}

SNAPSHOT_STATUS_LABELS = {
    "success": "全部成功",
    "partial": "部分成功",
    "failed": "全部失败",
}

EXPORT_COLUMNS = [
    ("追踪目标ID", "target_id"),
    ("域名", "domain"),
    ("标准化域名", "normalized_domain"),
    ("是否启用追踪", "is_active"),
    ("追踪状态代码", "target_status"),
    ("追踪状态", "target_status_label"),
    ("查询周期（小时）", "monitor_interval_hours"),
    ("检测来源数量", "source_count"),
    ("检测来源详情（JSON）", "source_details"),
    ("最近查询时间", "last_checked_at"),
    ("下次查询时间", "next_check_at"),
    ("连续失败次数", "consecutive_failures"),
    ("追踪错误", "target_error"),
    ("追踪创建时间", "target_created_at"),
    ("追踪更新时间", "target_updated_at"),
    ("最新快照ID", "snapshot_id"),
    ("快照状态代码", "snapshot_status"),
    ("快照状态", "snapshot_status_label"),
    ("快照采集时间", "snapshot_collected_at"),
    ("变化分区", "changed_sections"),
    ("变化详情（JSON）", "changed_fields"),
    ("查询错误明细（JSON）", "raw_lookup_errors"),
    ("快照错误", "snapshot_error"),
    ("WHOIS域名", "whois_domain"),
    ("注册商", "whois_registrar"),
    ("标准化注册商", "whois_registrar_normalized"),
    ("注册时间", "whois_registration_date"),
    ("过期时间", "whois_expiration_date"),
    ("WHOIS更新时间", "whois_updated_date"),
    ("NameServer", "whois_name_servers"),
    ("NameServer集合SHA-256", "whois_name_server_set_sha256"),
    ("域名状态", "whois_status"),
    ("注册人信息（JSON）", "whois_registrant"),
    ("注册身份SHA-256", "whois_registrant_identity_sha256"),
    ("联系邮箱", "whois_emails"),
    ("联系邮箱域", "whois_email_domains"),
    ("是否使用隐私代理", "whois_privacy_proxy_detected"),
    ("DNS记录（JSON）", "dns_records"),
    ("DNS记录类型统计（JSON）", "dns_record_counts"),
    ("IPv4地址", "dns_ipv4_addresses"),
    ("IPv6地址", "dns_ipv6_addresses"),
    ("解析IP", "dns_resolved_ips"),
    ("网络前缀", "dns_network_prefixes"),
    ("CNAME", "dns_cnames"),
    ("DNS NameServer", "dns_name_servers"),
    ("邮件服务器（JSON）", "dns_mail_servers"),
    ("TTL最小值", "dns_ttl_min"),
    ("TTL最大值", "dns_ttl_max"),
    ("TTL中位数", "dns_ttl_median"),
    ("TTL取值集合", "dns_ttl_unique_values"),
    ("DNS记录集合SHA-256", "dns_record_set_sha256"),
    ("解析IP集合SHA-256", "dns_resolved_ip_set_sha256"),
    ("证书颁发者（JSON）", "certificate_issuer"),
    ("证书主体（JSON）", "certificate_subject"),
    ("证书生效时间", "certificate_not_before"),
    ("证书过期时间", "certificate_not_after"),
    ("证书签名算法", "certificate_algorithm"),
    ("证书公钥类型", "certificate_public_key_type"),
    ("证书密钥长度", "certificate_key_size"),
    ("证书序列号", "certificate_serial_number"),
    ("证书SAN", "certificate_san_names"),
    ("证书SHA-256", "certificate_fingerprint"),
    ("SPKI SHA-256", "certificate_spki_fingerprint"),
    ("证书是否过期", "certificate_is_expired"),
    ("证书是否自签名", "certificate_is_self_signed"),
    ("TLS连接IP", "tls_connected_ip"),
    ("TLS版本", "tls_version"),
    ("TLS密码套件（JSON）", "tls_cipher"),
    ("TLS ALPN", "tls_alpn_protocol"),
    ("网页采集状态", "web_status"),
    ("访问协议", "web_scheme"),
    ("HTTP状态码", "web_status_code"),
    ("最终URL", "web_final_url"),
    ("重定向链（JSON）", "web_redirect_chain"),
    ("内容类型", "web_content_type"),
    ("内容长度", "web_content_length"),
    ("内容是否截断", "web_truncated"),
    ("网页采集时间", "web_fetched_at"),
    ("页面标题", "web_title"),
    ("页面生成器", "web_generator"),
    ("正文摘要", "web_body_excerpt"),
    ("HTML SHA-256", "web_html_hash"),
    ("正文SHA-256", "web_text_hash"),
    ("DOM结构SHA-256", "web_dom_structure_sha256"),
    ("响应头（JSON）", "web_response_headers"),
    ("响应头SHA-256", "web_response_header_sha256"),
    ("Cookie名称与属性（JSON）", "web_cookies"),
    ("Cookie名称集合SHA-256", "web_cookie_name_set_sha256"),
    ("JavaScript URL", "web_script_urls"),
    ("样式表URL", "web_stylesheet_urls"),
    ("外部资源主机", "web_external_resource_hosts"),
    ("资源URL集合SHA-256", "web_resource_url_set_sha256"),
    ("站点图标（JSON）", "web_favicons"),
    ("表单目标（JSON）", "web_form_targets"),
    ("统计标识（JSON）", "web_analytics_identifiers"),
    ("指纹结构版本", "fingerprint_schema_version"),
    ("注册至WHOIS更新间隔（天）", "registration_to_update_days"),
    ("注册至证书签发间隔（天）", "registration_to_certificate_days"),
    ("域名注册周期（天）", "domain_registration_period_days"),
    ("证书有效周期（天）", "certificate_validity_days"),
    ("注册指纹（JSON）", "fingerprint_registration"),
    ("网络指纹（JSON）", "fingerprint_network"),
    ("TLS指纹（JSON）", "fingerprint_tls"),
    ("应用指纹（JSON）", "fingerprint_application"),
    ("完整WHOIS快照（JSON）", "whois_snapshot"),
    ("完整DNS快照（JSON）", "dns_snapshot"),
    ("完整证书快照（JSON）", "certificate_snapshot"),
    ("完整网页快照（JSON）", "web_snapshot"),
    ("完整指纹快照（JSON）", "fingerprint_snapshot"),
]


def _plain(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(item) for item in value]
    return str(value)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _protect_csv_formula(value: str) -> str:
    normalized = value.replace("\x00", "")
    if normalized.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return f"'{normalized}"
    return normalized


def _csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, datetime):
        return value.isoformat(sep=" ", timespec="seconds")
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, Mapping) or isinstance(value, (list, tuple, set)):
        value = json.dumps(
            _plain(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    return _protect_csv_formula(str(value))


def _source_items(sources: Sequence[DomainMonitorSource]) -> List[Dict[str, Any]]:
    return [
        {
            "source_type": source.source_type,
            "task_id": source.task_id,
            "task_type": source.task_type,
            "model_id": source.model_id,
            "subscription_id": source.subscription_id,
            "alert_id": source.alert_id,
            "risk_score": source.risk_score,
            "risk_level": source.risk_level,
            "risk_record": source.risk_record,
            "detected_at": source.detected_at,
            "created_at": source.created_at,
        }
        for source in sources
    ]


def build_export_row(
    target: DomainMonitorTarget,
    snapshot: Optional[DomainMonitorSnapshot],
    sources: Sequence[DomainMonitorSource],
) -> Dict[str, Any]:
    whois = _mapping(snapshot.whois_snapshot if snapshot else None)
    dns = _mapping(snapshot.dns_snapshot if snapshot else None)
    certificate = _mapping(snapshot.certificate_snapshot if snapshot else None)
    web = _mapping(snapshot.web_snapshot if snapshot else None)
    fingerprint = _mapping(snapshot.fingerprint_snapshot if snapshot else None)
    temporal = _mapping(fingerprint.get("temporal"))
    ttl_profile = _mapping(dns.get("ttl_profile"))
    changed_fields = _mapping(snapshot.changed_fields if snapshot else None)

    return {
        "target_id": target.id,
        "domain": target.domain,
        "normalized_domain": target.normalized_domain,
        "is_active": bool(target.is_active),
        "target_status": target.status,
        "target_status_label": TARGET_STATUS_LABELS.get(target.status, target.status),
        "monitor_interval_hours": target.monitor_interval_hours,
        "source_count": len(sources),
        "source_details": _source_items(sources),
        "last_checked_at": target.last_checked_at,
        "next_check_at": target.next_check_at,
        "consecutive_failures": target.consecutive_failures,
        "target_error": target.last_error,
        "target_created_at": target.created_at,
        "target_updated_at": target.updated_at,
        "snapshot_id": snapshot.id if snapshot else None,
        "snapshot_status": snapshot.status if snapshot else None,
        "snapshot_status_label": (
            SNAPSHOT_STATUS_LABELS.get(snapshot.status, snapshot.status)
            if snapshot
            else "暂无快照"
        ),
        "snapshot_collected_at": snapshot.collected_at if snapshot else None,
        "changed_sections": changed_fields.get("sections") or [],
        "changed_fields": snapshot.changed_fields if snapshot else None,
        "raw_lookup_errors": snapshot.raw_lookup_errors if snapshot else None,
        "snapshot_error": snapshot.error_message if snapshot else None,
        "whois_domain": whois.get("domain"),
        "whois_registrar": whois.get("registrar"),
        "whois_registrar_normalized": whois.get("registrar_normalized"),
        "whois_registration_date": whois.get("registration_date"),
        "whois_expiration_date": whois.get("expiration_date"),
        "whois_updated_date": whois.get("updated_date"),
        "whois_name_servers": whois.get("name_servers") or [],
        "whois_name_server_set_sha256": whois.get("name_server_set_sha256"),
        "whois_status": whois.get("status") or [],
        "whois_registrant": whois.get("registrant"),
        "whois_registrant_identity_sha256": whois.get("registrant_identity_sha256"),
        "whois_emails": whois.get("emails") or [],
        "whois_email_domains": whois.get("email_domains") or [],
        "whois_privacy_proxy_detected": whois.get("privacy_proxy_detected"),
        "dns_records": dns.get("records") or [],
        "dns_record_counts": dns.get("record_counts") or {},
        "dns_ipv4_addresses": dns.get("ipv4_addresses") or [],
        "dns_ipv6_addresses": dns.get("ipv6_addresses") or [],
        "dns_resolved_ips": dns.get("resolved_ips") or [],
        "dns_network_prefixes": dns.get("network_prefixes") or [],
        "dns_cnames": dns.get("cnames") or [],
        "dns_name_servers": dns.get("name_servers") or [],
        "dns_mail_servers": dns.get("mail_servers") or [],
        "dns_ttl_min": ttl_profile.get("min"),
        "dns_ttl_max": ttl_profile.get("max"),
        "dns_ttl_median": ttl_profile.get("median"),
        "dns_ttl_unique_values": ttl_profile.get("unique_values") or [],
        "dns_record_set_sha256": dns.get("record_set_sha256"),
        "dns_resolved_ip_set_sha256": dns.get("resolved_ip_set_sha256"),
        "certificate_issuer": certificate.get("issuer"),
        "certificate_subject": certificate.get("subject"),
        "certificate_not_before": certificate.get("not_before"),
        "certificate_not_after": certificate.get("not_after"),
        "certificate_algorithm": certificate.get("algorithm"),
        "certificate_public_key_type": certificate.get("public_key_type"),
        "certificate_key_size": certificate.get("key_size"),
        "certificate_serial_number": certificate.get("serial_number"),
        "certificate_san_names": certificate.get("san_names") or [],
        "certificate_fingerprint": certificate.get("fingerprint"),
        "certificate_spki_fingerprint": certificate.get("spki_fingerprint"),
        "certificate_is_expired": certificate.get("is_expired"),
        "certificate_is_self_signed": certificate.get("is_self_signed"),
        "tls_connected_ip": certificate.get("connected_ip"),
        "tls_version": certificate.get("tls_version"),
        "tls_cipher": certificate.get("cipher"),
        "tls_alpn_protocol": certificate.get("alpn_protocol"),
        "web_status": web.get("status"),
        "web_scheme": web.get("scheme"),
        "web_status_code": web.get("status_code"),
        "web_final_url": web.get("final_url"),
        "web_redirect_chain": web.get("redirect_chain") or [],
        "web_content_type": web.get("content_type"),
        "web_content_length": web.get("content_length"),
        "web_truncated": web.get("truncated"),
        "web_fetched_at": web.get("fetched_at"),
        "web_title": web.get("title"),
        "web_generator": web.get("generator"),
        "web_body_excerpt": web.get("body_excerpt"),
        "web_html_hash": web.get("html_hash"),
        "web_text_hash": web.get("text_hash"),
        "web_dom_structure_sha256": web.get("dom_structure_sha256"),
        "web_response_headers": web.get("response_headers") or {},
        "web_response_header_sha256": web.get("response_header_sha256"),
        "web_cookies": web.get("cookies") or [],
        "web_cookie_name_set_sha256": web.get("cookie_name_set_sha256"),
        "web_script_urls": web.get("script_urls") or [],
        "web_stylesheet_urls": web.get("stylesheet_urls") or [],
        "web_external_resource_hosts": web.get("external_resource_hosts") or [],
        "web_resource_url_set_sha256": web.get("resource_url_set_sha256"),
        "web_favicons": web.get("favicons") or [],
        "web_form_targets": web.get("form_targets") or [],
        "web_analytics_identifiers": web.get("analytics_identifiers") or {},
        "fingerprint_schema_version": fingerprint.get("schema_version"),
        "registration_to_update_days": temporal.get("registration_to_update_days"),
        "registration_to_certificate_days": temporal.get(
            "registration_to_certificate_days"
        ),
        "domain_registration_period_days": temporal.get(
            "domain_registration_period_days"
        ),
        "certificate_validity_days": temporal.get("certificate_validity_days"),
        "fingerprint_registration": fingerprint.get("registration") or {},
        "fingerprint_network": fingerprint.get("network") or {},
        "fingerprint_tls": fingerprint.get("tls") or {},
        "fingerprint_application": fingerprint.get("application") or {},
        "whois_snapshot": snapshot.whois_snapshot if snapshot else None,
        "dns_snapshot": snapshot.dns_snapshot if snapshot else None,
        "certificate_snapshot": snapshot.certificate_snapshot if snapshot else None,
        "web_snapshot": snapshot.web_snapshot if snapshot else None,
        "fingerprint_snapshot": snapshot.fingerprint_snapshot if snapshot else None,
    }


def render_export_csv(rows: Iterable[Mapping[str, Any]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow([label for label, _ in EXPORT_COLUMNS])
    for row in rows:
        writer.writerow([_csv_value(row.get(key)) for _, key in EXPORT_COLUMNS])
    return ("\ufeff" + output.getvalue()).encode("utf-8")


def build_domain_monitor_export(
    db: Session,
    *,
    user_id: int,
    active_only: bool = False,
    domain: Optional[str] = None,
) -> tuple[bytes, int]:
    latest_snapshot_id = (
        select(DomainMonitorSnapshot.id)
        .where(DomainMonitorSnapshot.target_id == DomainMonitorTarget.id)
        .order_by(
            DomainMonitorSnapshot.collected_at.desc(),
            DomainMonitorSnapshot.id.desc(),
        )
        .limit(1)
        .correlate(DomainMonitorTarget)
        .scalar_subquery()
    )
    query = (
        db.query(DomainMonitorTarget, DomainMonitorSnapshot)
        .outerjoin(
            DomainMonitorSnapshot,
            DomainMonitorSnapshot.id == latest_snapshot_id,
        )
        .filter(DomainMonitorTarget.user_id == int(user_id))
    )
    if active_only:
        query = query.filter(DomainMonitorTarget.is_active == True)
    if domain:
        keyword = f"%{domain.strip().lower()}%"
        query = query.filter(
            or_(
                DomainMonitorTarget.domain.like(keyword),
                DomainMonitorTarget.normalized_domain.like(keyword),
            )
        )

    target_rows = query.order_by(
        DomainMonitorTarget.created_at.desc(),
        DomainMonitorTarget.id.desc(),
    ).all()
    target_ids = [int(target.id) for target, _ in target_rows]
    sources_by_target: Dict[int, List[DomainMonitorSource]] = {
        target_id: [] for target_id in target_ids
    }
    if target_ids:
        source_rows = (
            db.query(DomainMonitorSource)
            .filter(DomainMonitorSource.target_id.in_(target_ids))
            .order_by(
                DomainMonitorSource.target_id.asc(),
                DomainMonitorSource.detected_at.asc(),
                DomainMonitorSource.id.asc(),
            )
            .all()
        )
        for source in source_rows:
            sources_by_target.setdefault(int(source.target_id), []).append(source)

    export_rows = [
        build_export_row(
            target,
            snapshot,
            sources_by_target.get(int(target.id), []),
        )
        for target, snapshot in target_rows
    ]
    return render_export_csv(export_rows), len(export_rows)
