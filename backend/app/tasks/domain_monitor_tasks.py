import logging

from app.celery_app import celery_app
from app.services.domain_monitor import collect_domain_monitor_snapshot

logger = logging.getLogger("uvicorn.error")


@celery_app.task(
    name="tasks.collect_domain_monitor_snapshot",
    bind=True,
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 1, "countdown": 30},
    retry_backoff=True,
    retry_jitter=True,
)
def collect_domain_monitor_snapshot_job(self, target_id: int):
    try:
        return collect_domain_monitor_snapshot(int(target_id))
    except Exception as exc:
        logger.exception("Celery domain monitor snapshot task failed: %s", exc)
        raise
