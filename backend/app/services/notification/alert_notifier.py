from __future__ import annotations

from typing import Any, Dict, Iterable, Optional
import logging

logger = logging.getLogger("uvicorn.error")


def build_alert_data_dict(
	*,
	alert_id: str,
	model_name: str,
	task_type: str,
	detected_count: int,
	high_risk_count: int,
	threshold: int,
	created_at: str,
	high_risk_domains: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
	"""构建订阅预警通知的数据字典。"""
	return {
		"alert_id": alert_id,
		"model_name": model_name,
		"task_type": task_type,
		"detected_count": int(detected_count or 0),
		"high_risk_count": int(high_risk_count or 0),
		"threshold": int(threshold or 0),
		"created_at": created_at,
		"high_risk_domains": list(high_risk_domains or []),
	}


def dispatch_alert_notifications(
	db,
	*,
	alert_row,
	alert_data: Dict[str, Any],
	domains_csv_content: Optional[bytes],
	user_id: int,
) -> None:
	"""
	通知分发占位实现。
	先保证主流程可启动与可运行，后续可在此接入邮件/飞书。
	"""
	_ = db
	_ = domains_csv_content
	_ = user_id

	logger.info(
		"[alert-notify] alert_id=%s model=%s type=%s high_risk=%s",
		alert_data.get("alert_id"),
		alert_data.get("model_name"),
		alert_data.get("task_type"),
		alert_data.get("high_risk_count"),
	)

	if hasattr(alert_row, "feishu_notified"):
		setattr(alert_row, "feishu_notified", False)
