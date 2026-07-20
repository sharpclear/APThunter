import logging

from app.celery_app import celery_app
from app.services.task_executor import (
    execute_apt_template_nrd_task,
    execute_dga_task,
    execute_history_similarity_task,
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
    name="tasks.execute_dga_task",
    bind=True,
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 3, "countdown": 5},
    retry_backoff=True,
    retry_jitter=True,
)
def execute_dga_task_job(self, task_id: str):
    try:
        execute_dga_task(task_id)
        return {"ok": True, "task_id": task_id}
    except Exception as exc:
        logger.exception("Celery dga task failed: %s", exc)
        raise


@celery_app.task(
    name="tasks.execute_history_similarity_task",
    bind=True,
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 3, "countdown": 5},
    retry_backoff=True,
    retry_jitter=True,
)
def execute_history_similarity_task_job(self, task_id: str):
    try:
        execute_history_similarity_task(task_id)
        return {"ok": True, "task_id": task_id}
    except Exception as exc:
        logger.exception("Celery history similarity task failed: %s", exc)
        raise


@celery_app.task(
    name="tasks.execute_apt_template_nrd_task",
    bind=True,
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 3, "countdown": 5},
    retry_backoff=True,
    retry_jitter=True,
)
def execute_apt_template_nrd_task_job(self, task_id: str):
    try:
        execute_apt_template_nrd_task(task_id)
        return {"ok": True, "task_id": task_id}
    except Exception as exc:
        logger.exception("Celery apt template nrd task failed: %s", exc)
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
        execute_impersonation_task(
            task_id,
            mark_failed_on_error=self.request.retries >= self.max_retries,
        )
        return {"ok": True, "task_id": task_id}
    except Exception as exc:
        logger.exception("Celery impersonation task failed: %s", exc)
        raise
