import os

from celery import Celery
from kombu import Exchange, Queue

from app.core.config import CELERY_BROKER_URL, CELERY_RESULT_BACKEND

celery_app = Celery(
    "atdv_pro",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_track_started=True,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="Asia/Shanghai",
    enable_utc=False,
    imports=("app.tasks.detection_tasks",),
)

# 多队列扩展预留：默认不启用，避免影响现有 worker 的队列消费行为。
CELERY_MULTI_QUEUE_ENABLED = (
    os.getenv("CELERY_MULTI_QUEUE_ENABLED", "false").strip().lower()
    in {"1", "true", "yes", "y", "on"}
)
CELERY_DEFAULT_QUEUE = os.getenv("CELERY_DEFAULT_QUEUE", "celery")

celery_app.conf.update(task_default_queue=CELERY_DEFAULT_QUEUE)

if CELERY_MULTI_QUEUE_ENABLED:
    atdv_exchange = Exchange("atdv", type="direct")
    malicious_queue_name = os.getenv("CELERY_MALICIOUS_QUEUE", "atdv_malicious")
    impersonation_queue_name = os.getenv("CELERY_IMPERSONATION_QUEUE", "atdv_impersonation")

    celery_app.conf.update(
        task_queues=(
            Queue(malicious_queue_name, exchange=atdv_exchange, routing_key=malicious_queue_name),
            Queue(impersonation_queue_name, exchange=atdv_exchange, routing_key=impersonation_queue_name),
            # 保留默认队列，便于兼容
            Queue(CELERY_DEFAULT_QUEUE, exchange=atdv_exchange, routing_key=CELERY_DEFAULT_QUEUE),
        ),
        task_routes={
            "tasks.execute_malicious_task": {
                "queue": malicious_queue_name,
                "routing_key": malicious_queue_name,
            },
            "tasks.execute_impersonation_task": {
                "queue": impersonation_queue_name,
                "routing_key": impersonation_queue_name,
            },
        },
    )
