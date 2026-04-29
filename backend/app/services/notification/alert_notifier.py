"""
预警通知分发：在「已落库预警」之后调用，不改变判定逻辑。
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Mapping, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import ALERT_EMAIL_ENABLED, APP_PUBLIC_BASE_URL, FEISHU_ENABLE_PUSH, FEISHU_WEBHOOK_URL
from app.entities import User
from app.infra.minio_client import minio_client
from app.services.notification.email_service import (
    beijing_datetime_to_naive,
    beijing_now,
    send_alert_email,
)
from app.services.notification import feishu_service

logger = logging.getLogger("uvicorn.error")


def _get_user_email(db: Session, user_id: int) -> Optional[str]:
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if user and user.email:
            return user.email
        return None
    except Exception as e:
        logger.error("获取用户邮箱失败: %s", e)
        return None


def _safe_text(value: Any, default: str = "") -> str:
    text_value = str(value or "").strip()
    return text_value if text_value else default


def _build_suspected_association_text_from_results(match_results_by_domain: Mapping[str, Any]) -> str:
    if not match_results_by_domain:
        return "暂无明显疑似关联组织。"

    association_lines = []
    known_org_count = 0
    for domain_key, result in match_results_by_domain.items():
        domain_name = _safe_text(
            (result or {}).get("domain_name") if isinstance(result, Mapping) else "",
            _safe_text(domain_key, "未知域名"),
        )
        if not isinstance(result, Mapping):
            continue

        org_name = _safe_text(result.get("matched_organization_name"))
        if not org_name:
            top_candidates = result.get("top_candidates_json") or result.get("top_candidates") or []
            if isinstance(top_candidates, list) and top_candidates:
                first = top_candidates[0] if isinstance(top_candidates[0], Mapping) else {}
                org_name = _safe_text(first.get("name"))
        if not org_name:
            org_name = "未知"
        else:
            known_org_count += 1

        association_lines.append(f"{domain_name} -> {org_name}")

    if not association_lines:
        return "暂无明显疑似关联组织。"
    total_count = len(association_lines)
    sections = [
        "【域名与组织关联列表】",
        f"本批次高风险域名数量：{total_count}",
        f"已形成组织关联的域名数量：{known_org_count}",
        "",
        "\n".join(association_lines),
    ]
    return "\n".join(sections).strip()


def _load_suspected_association_text_from_minio(db: Session, alert_id: str) -> str:
    row = db.execute(
        text(
            """
            SELECT f.bucket, f.object_key
            FROM alert_files af
            JOIN files f ON f.id = af.file_id
            WHERE af.alert_id = :alert_id
              AND af.file_role = 'full_result'
              AND af.file_format = 'json'
            ORDER BY af.created_at DESC
            LIMIT 1
            """
        ),
        {"alert_id": alert_id},
    ).mappings().first()
    if not row:
        return "暂无明显疑似关联组织。"

    bucket = row.get("bucket")
    object_key = row.get("object_key")
    if not bucket or not object_key:
        return "暂无明显疑似关联组织。"

    try:
        response = minio_client.get_object(bucket, object_key)
        content_bytes = response.read()
        response.close()
        response.release_conn()
        payload = json.loads(content_bytes.decode("utf-8"))
    except Exception:
        logger.exception(
            "读取 MinIO 预警结果失败，无法构造疑似关联组织文案 alert_id=%s bucket=%s object_key=%s",
            alert_id,
            bucket,
            object_key,
        )
        return "暂无明显疑似关联组织。"

    match_results_by_domain: Dict[str, Any] = {}
    for item in payload.get("high_risk_domains") or []:
        if not isinstance(item, Mapping):
            continue
        domain_name = _safe_text(item.get("domain"))
        if not domain_name:
            continue
        matched_organizations = item.get("matched_organizations") or []
        top_candidates = item.get("top_candidates") or []
        primary = matched_organizations[0] if isinstance(matched_organizations, list) and matched_organizations else {}
        match_results_by_domain[domain_name.lower()] = {
            "domain_name": domain_name,
            "matched_organization_name": _safe_text(primary.get("organization_name")) if isinstance(primary, Mapping) else "",
            "top_candidates_json": top_candidates,
        }
    return _build_suspected_association_text_from_results(match_results_by_domain)


def dispatch_alert_notifications(
    db: Session,
    *,
    alert_row,
    alert_data: dict,
    domains_csv_content: Optional[bytes],
    user_id: int,
) -> None:
    """
    在预警记录已提交数据库之后调用。内部异常不影响调用方事务（调用方已 commit）。

    - 邮件：ALERT_EMAIL_ENABLED 且用户有邮箱且 SMTP 配置完整（见 email_service）
    - 飞书：FEISHU_ENABLE_PUSH 且配置 webhook（仅应由「预警已落库」路径调用本函数）
    - 飞书幂等：依赖 alerts.feishu_notified，成功后再更新
    """
    # 邮件通道
    if ALERT_EMAIL_ENABLED:
        user_email = _get_user_email(db, user_id)
        if user_email:
            try:
                send_alert_email(user_email, alert_data, domains_csv_content)
            except Exception:
                logger.exception("预警邮件分发异常（已吞掉）")
        else:
            logger.warning("用户 %s 没有配置邮箱，跳过邮件发送", user_id)
    else:
        logger.info("ALERT_EMAIL_ENABLED=false，跳过邮件")

    # 飞书通道
    if not FEISHU_ENABLE_PUSH or not (FEISHU_WEBHOOK_URL or "").strip():
        return
    try:
        if getattr(alert_row, "feishu_notified", False):
            logger.info("预警 %s 已标记飞书已推送，跳过", getattr(alert_row, "alert_id", ""))
            return
    except Exception:
        pass

    alert_id = alert_data.get("alert_id") or getattr(alert_row, "alert_id", "")
    task_id = getattr(alert_row, "task_id", "")
    subscription_id = getattr(alert_row, "subscription_id", "")
    model_name = alert_data.get("model_name", "")
    task_type = alert_data.get("task_type", "malicious")
    detected_count = int(alert_data.get("detected_count", 0))
    high_risk_count = int(alert_data.get("high_risk_count", 0))
    threshold = int(alert_data.get("threshold", 0))
    created_at = alert_data.get("created_at", "")
    domains = alert_data.get("high_risk_domains") or []

    detail = ""
    if APP_PUBLIC_BASE_URL:
        detail = f"{APP_PUBLIC_BASE_URL}/detection/alert"

    ratio_txt = ""
    if detected_count > 0:
        ratio_txt = f"高风险占比约 {(high_risk_count / detected_count) * 100:.2f}%"
    risk_summary = f"{ratio_txt}；订阅检测阈值 {threshold}。" if ratio_txt else f"订阅检测阈值 {threshold}。"
    suspected_association_text = "暂无明显疑似关联组织。"
    try:
        in_memory_matches = alert_data.get("match_results_by_domain")
        if isinstance(in_memory_matches, Mapping) and in_memory_matches:
            suspected_association_text = _build_suspected_association_text_from_results(in_memory_matches)
        else:
            suspected_association_text = _load_suspected_association_text_from_minio(db, str(alert_id))
    except Exception:
        logger.exception("构建疑似关联组织推送文案失败，将使用默认文案")

    ok = False
    try:
        ok = feishu_service.send_alert_notification(
            alert_id=str(alert_id),
            task_id=str(task_id),
            subscription_id=str(subscription_id),
            model_name=str(model_name),
            task_type=str(task_type),
            detected_count=detected_count,
            high_risk_count=high_risk_count,
            threshold=threshold,
            created_at=str(created_at),
            high_risk_domains=list(domains) if isinstance(domains, list) else [],
            detail_page_url=detail,
            risk_summary=risk_summary,
            suspected_association_text=suspected_association_text,
        )
    except Exception:
        logger.exception("飞书预警推送异常（已吞掉，不影响主流程）")
        return

    if ok:
        try:
            if hasattr(alert_row, "feishu_notified"):
                alert_row.feishu_notified = True
            if hasattr(alert_row, "feishu_notified_at"):
                alert_row.feishu_notified_at = beijing_datetime_to_naive(beijing_now())
            db.add(alert_row)
            db.commit()
        except Exception:
            logger.exception("更新飞书推送状态失败（可能未执行迁移 SQL）")


def build_alert_data_dict(
    *,
    alert_id: str,
    model_name: str,
    task_type: str,
    detected_count: int,
    high_risk_count: int,
    threshold: int,
    created_at: str,
    high_risk_domains: list,
    match_results_by_domain: Optional[dict] = None,
) -> dict:
    return {
        "alert_id": alert_id,
        "model_name": model_name,
        "task_type": task_type,
        "detected_count": detected_count,
        "high_risk_count": high_risk_count,
        "threshold": threshold,
        "created_at": created_at,
        "high_risk_domains": high_risk_domains,
        "match_results_by_domain": match_results_by_domain or {},
    }
