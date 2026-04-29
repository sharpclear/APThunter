from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel


class _OrmSchema(BaseModel):
    model_config = {"from_attributes": True}


class AlertFileCreate(BaseModel):
    alert_id: str
    subscription_id: str
    task_id: str
    user_id: int
    model_id: int
    task_type: str
    frequency: str
    file_id: int
    file_role: str = "full_result"
    file_format: str = "json"
    domain_count: int = 0
    alert_date: date


class AlertFileResponse(_OrmSchema):
    id: int
    alert_id: str
    subscription_id: str
    task_id: str
    user_id: int
    model_id: int
    task_type: str
    frequency: str
    file_id: int
    file_role: str
    file_format: str
    domain_count: int
    alert_date: date
    created_at: datetime


class AlertFileWithStoredFile(BaseModel):
    alert_file: AlertFileResponse
    bucket: Optional[str] = None
    object_key: Optional[str] = None
    filename: Optional[str] = None
    content_type: Optional[str] = None
