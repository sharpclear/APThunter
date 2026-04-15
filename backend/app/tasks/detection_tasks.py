import logging

from app.celery_app import celery_app
from app.services.task_executor import (
    execute_impersonation_task,
    execute_malicious_task,
)

logger = logging.getLogger("uvicorn.error")


@celery_app.task(
    name="tasks.execute_malicious_task",
    bind=True,
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 3, "countdown": 5},
    retry_backoff=True,
    retry_jitter=True,
)
def execute_malicious_task_job(self, task_id: str):
    try:
        execute_malicious_task(task_id)
        return {"ok": True, "task_id": task_id}
    except Exception as exc:
        logger.exception("Celery malicious task failed: %s", exc)
        raise


@celery_app.task(
    name="tasks.execute_impersonation_task",
    bind=True,
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 3, "countdown": 5},
    retry_backoff=True,
    retry_jitter=True,
)
def execute_impersonation_task_job(self, task_id: str):
    try:
        execute_impersonation_task(task_id)
        return {"ok": True, "task_id": task_id}
    except Exception as exc:
        logger.exception("Celery impersonation task failed: %s", exc)
        raise
