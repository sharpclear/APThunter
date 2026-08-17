import logging
from datetime import datetime, timedelta, timezone

from app.celery_app import celery_app
from app.core.config import (
    QIANXIN_API_KEY,
    QIANXIN_API_URL,
    QIANXIN_EVENT_AUTO_IMPORT,
    QIANXIN_EVENT_HTTP_TIMEOUT_SEC,
    QIANXIN_EVENT_MAX_PAGES_PER_SYNC,
    QIANXIN_EVENT_PAGE_LIMIT,
)
from app.db.session import engine
from app.services.event_ingestion.qianxin_client import QianxinClient
from app.services.event_ingestion.qianxin_sync import QianxinEventSyncService

logger = logging.getLogger("uvicorn.error")
SHANGHAI_TIME = timezone(timedelta(hours=8), name="Asia/Shanghai")


def _client() -> QianxinClient:
    return QianxinClient(
        QIANXIN_API_URL,
        QIANXIN_API_KEY,
        timeout_seconds=QIANXIN_EVENT_HTTP_TIMEOUT_SEC,
    )


def _sync_service() -> QianxinEventSyncService:
    return QianxinEventSyncService(
        engine,
        _client(),
        page_limit=QIANXIN_EVENT_PAGE_LIMIT,
        max_pages=QIANXIN_EVENT_MAX_PAGES_PER_SYNC,
        auto_import=QIANXIN_EVENT_AUTO_IMPORT,
    )


@celery_app.task(
    name="tasks.trigger_qianxin_collection",
    bind=True,
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 2, "countdown": 60},
    retry_backoff=True,
    retry_jitter=True,
)
def trigger_qianxin_collection_job(self):
    now = datetime.now(SHANGHAI_TIME)
    iso_year, iso_week, _ = now.isocalendar()
    idempotency_key = f"apthunter-qianxin-{iso_year}-W{iso_week:02d}"
    result = _client().create_incremental_run(idempotency_key)
    logger.info(
        "Qianxin 增量采集已提交 run_id=%s status=%s",
        result.get("id"),
        result.get("status"),
    )
    return result


@celery_app.task(
    name="tasks.sync_qianxin_events",
    bind=True,
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 2, "countdown": 60},
    retry_backoff=True,
    retry_jitter=True,
)
def sync_qianxin_events_job(self, trigger_type: str = "scheduled"):
    result = _sync_service().sync(trigger_type=trigger_type)
    logger.info("Qianxin 事件同步完成: %s", result)
    return result
