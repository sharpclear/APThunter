from __future__ import annotations

from datetime import date, datetime
from typing import Any, Optional

from app.entities import AlertFile


class AlertFileMappingError(RuntimeError):
    """预警与结果文件索引关系写入异常。"""


def _coerce_alert_date(value: Any) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        text_value = value.strip()
        if text_value.endswith("Z"):
            text_value = text_value[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(text_value).date()
        except ValueError as exc:
            raise AlertFileMappingError(f"invalid alert_date: {value}") from exc
    raise AlertFileMappingError("alert_date must be date/datetime/isoformat string")


def create_alert_file_mapping(
    db,
    *,
    alert_id: str,
    subscription_id: str,
    task_id: str,
    user_id: int,
    model_id: int,
    task_type: str,
    frequency: str,
    file_id: int,
    domain_count: int,
    alert_date: Any,
    file_role: str = "full_result",
    file_format: str = "json",
) -> AlertFile:
    """
    写入 alert_files 索引关系（不重复保存 bucket/object_key）。
    调用顺序要求：先写 files，再写 alert_files。
    """
    if not alert_id or not subscription_id or not task_id:
        raise AlertFileMappingError("alert_id/subscription_id/task_id are required")
    if file_id is None:
        raise AlertFileMappingError("file_id is required (files row must be created first)")
    if task_type not in {"malicious", "impersonation"}:
        raise AlertFileMappingError(f"invalid task_type: {task_type}")
    if frequency not in {"daily", "weekly", "monthly"}:
        raise AlertFileMappingError(f"invalid frequency: {frequency}")
    if file_role not in {"full_result", "report"}:
        raise AlertFileMappingError(f"invalid file_role: {file_role}")
    if file_format != "json":
        raise AlertFileMappingError(f"invalid file_format: {file_format}")

    domain_count_value = int(domain_count or 0)
    if domain_count_value < 0:
        raise AlertFileMappingError("domain_count must be >= 0")

    row = AlertFile(
        alert_id=str(alert_id),
        subscription_id=str(subscription_id),
        task_id=str(task_id),
        user_id=int(user_id),
        model_id=int(model_id),
        task_type=task_type,
        frequency=frequency,
        file_id=int(file_id),
        file_role=file_role,
        file_format=file_format,
        domain_count=domain_count_value,
        alert_date=_coerce_alert_date(alert_date),
    )
    db.add(row)
    db.flush()
    return row
