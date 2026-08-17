import logging
from datetime import datetime, timedelta, timezone

from app.celery_app import celery_app
from app.core.config import (
    LAZARUS_DAY_API_KEY,
    LAZARUS_DAY_API_URL,
    LAZARUS_EVENT_AUTO_IMPORT,
    LAZARUS_EVENT_HTTP_TIMEOUT_SEC,
    LAZARUS_EVENT_MAX_PAGES_PER_SYNC,
    LAZARUS_EVENT_PAGE_LIMIT,
)
from app.db.session import engine
from app.services.event_ingestion.lazarus_client import LazarusDayClient
from app.services.event_ingestion.lazarus_sync import LazarusEventSyncService

logger = logging.getLogger("uvicorn.error")
SHANGHAI_TIME = timezone(timedelta(hours=8), name="Asia/Shanghai")


def _client() -> LazarusDayClient:
    return LazarusDayClient(
        LAZARUS_DAY_API_URL,
        LAZARUS_DAY_API_KEY,
        timeout_seconds=LAZARUS_EVENT_HTTP_TIMEOUT_SEC,
    )


def _sync_service() -> LazarusEventSyncService:
    return LazarusEventSyncService(
        engine,
        _client(),
        page_limit=LAZARUS_EVENT_PAGE_LIMIT,
        max_pages=LAZARUS_EVENT_MAX_PAGES_PER_SYNC,
        auto_import=LAZARUS_EVENT_AUTO_IMPORT,
    )


@celery_app.task(
    name="tasks.trigger_lazarus_collection",
    bind=True,
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 2, "countdown": 60},
    retry_backoff=True,
    retry_jitter=True,
)
def trigger_lazarus_collection_job(self):
    now = datetime.now(SHANGHAI_TIME)
    iso_year, iso_week, _ = now.isocalendar()
    idempotency_key = f"apthunter-lazarus-{iso_year}-W{iso_week:02d}"
    result = _client().create_incremental_run(idempotency_key)
    logger.info(
        "Lazarus.day 增量采集已提交 run_id=%s status=%s",
        result.get("id"),
        result.get("status"),
    )
    return result


@celery_app.task(
    name="tasks.sync_lazarus_events",
    bind=True,
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 2, "countdown": 60},
    retry_backoff=True,
    retry_jitter=True,
)
def sync_lazarus_events_job(self, trigger_type: str = "scheduled"):
    result = _sync_service().sync(trigger_type=trigger_type)
    logger.info("Lazarus.day 事件同步完成: %s", result)
    return result
