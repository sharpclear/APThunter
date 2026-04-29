from __future__ import annotations

import io
import json
import logging
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Mapping, Optional

from app.core.config import ALERT_RESULT_BUCKET
from app.entities import StoredFile
from app.infra.minio_client import minio_client

logger = logging.getLogger("uvicorn.error")


class AlertResultStorageError(RuntimeError):
    """预警结果 JSON 存储异常。"""
    def __init__(
        self,
        message: str,
        *,
        bucket: Optional[str] = None,
        object_key: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.bucket = bucket
        self.object_key = object_key


def _to_json_compatible(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): _to_json_compatible(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_json_compatible(v) for v in value]
    return str(value)


def _coerce_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time())
    if isinstance(value, str):
        text_value = value.strip()
        if text_value.endswith("Z"):
            text_value = text_value[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(text_value)
        except ValueError as exc:
            raise AlertResultStorageError(f"invalid alert_time format: {value}") from exc
    raise AlertResultStorageError("alert_time must be datetime/date/isoformat string")


def _build_alert_result_object_key(
    *,
    alert_time: datetime,
    user_id: int,
    subscription_id: str,
    task_id: str,
    alert_id: str,
) -> str:
    return (
        f"alerts/{alert_time:%Y}/{alert_time:%m}/{alert_time:%d}/"
        f"user_{user_id}/subscription_{subscription_id}/task_{task_id}/"
        f"alert_{alert_id}/full_result.json"
    )


def save_alert_result_json_to_minio(
    db,
    *,
    alert_id: str,
    subscription_id: str,
    task_id: str,
    user_id: int,
    model_id: int,
    task_type: str,
    alert_time: Any,
    json_data: Mapping[str, Any],
    uploaded_by: Optional[str] = None,
    bucket: Optional[str] = None,
) -> StoredFile:
    """
    保存预警完整结果 JSON 到 MinIO，并写入 files 表。
    仅处理文件存储与 files 记录，不写 alert_files / alert_domain_matches。
    """
    if not alert_id or not subscription_id or not task_id:
        raise AlertResultStorageError("alert_id/subscription_id/task_id are required")
    if user_id is None or model_id is None:
        raise AlertResultStorageError("user_id/model_id are required")
    if not isinstance(json_data, Mapping):
        raise AlertResultStorageError("json_data must be a mapping object")

    resolved_time = _coerce_datetime(alert_time)
    target_bucket = (bucket or ALERT_RESULT_BUCKET or "apthunter-alert-results").strip()
    if not target_bucket:
        raise AlertResultStorageError("resolved target bucket is empty")

    object_key = _build_alert_result_object_key(
        alert_time=resolved_time,
        user_id=int(user_id),
        subscription_id=str(subscription_id),
        task_id=str(task_id),
        alert_id=str(alert_id),
    )

    payload = _to_json_compatible(dict(json_data))
    payload_text = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
    )
    payload_bytes = payload_text.encode("utf-8")

    try:
        if not minio_client.bucket_exists(target_bucket):
            minio_client.make_bucket(target_bucket)

        minio_client.put_object(
            target_bucket,
            object_key,
            io.BytesIO(payload_bytes),
            length=len(payload_bytes),
            content_type="application/json",
        )
    except Exception as exc:
        logger.exception(
            "upload alert result json to minio failed alert_id=%s bucket=%s key=%s",
            alert_id,
            target_bucket,
            object_key,
        )
        raise AlertResultStorageError(
            f"failed to upload alert result json to minio: {target_bucket}/{object_key}",
            bucket=target_bucket,
            object_key=object_key,
        ) from exc

    metadata = {
        "source": "scheduled_alert",
        "artifact_type": "full_result",
        "file_format": "json",
        "schema_version": payload.get("schema_version", "v1"),
        "alert_id": str(alert_id),
        "subscription_id": str(subscription_id),
        "task_id": str(task_id),
        "user_id": int(user_id),
        "model_id": int(model_id),
        "task_type": str(task_type),
    }

    uploaded_by_value = uploaded_by if uploaded_by is not None else str(user_id or "system")
    row = StoredFile(
        bucket=target_bucket,
        object_key=object_key,
        filename="full_result.json",
        content_type="application/json",
        size=len(payload_bytes),
        uploaded_by=str(uploaded_by_value),
        metadata_json=metadata,
    )
    try:
        db.add(row)
        db.flush()
    except Exception as exc:
        logger.exception(
            "insert files row failed after minio upload alert_id=%s bucket=%s key=%s",
            alert_id,
            target_bucket,
            object_key,
        )
        try:
            minio_client.remove_object(target_bucket, object_key)
        except Exception:
            logger.exception(
                "rollback minio object failed after files insert error alert_id=%s bucket=%s key=%s",
                alert_id,
                target_bucket,
                object_key,
            )
        raise AlertResultStorageError(
            "failed to persist files record for alert result json",
            bucket=target_bucket,
            object_key=object_key,
        ) from exc

    return row
