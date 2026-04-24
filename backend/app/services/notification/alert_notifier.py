"""
预警通知分发：在「已落库预警」之后调用，不改变判定逻辑。
"""
from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import ALERT_EMAIL_ENABLED, APP_PUBLIC_BASE_URL, FEISHU_ENABLE_PUSH, FEISHU_WEBHOOK_URL
from app.entities import User
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
    }
