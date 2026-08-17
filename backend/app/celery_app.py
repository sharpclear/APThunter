import os

from celery import Celery
from celery.schedules import crontab
from kombu import Exchange, Queue

from app.core.config import CELERY_BROKER_URL, CELERY_RESULT_BACKEND

celery_app = Celery(
    "apthunter",
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
    imports=(
        "app.tasks.detection_tasks",
        "app.tasks.domain_monitor_tasks",
        "app.tasks.lazarus_event_tasks",
        "app.tasks.qianxin_event_tasks",
    ),
)

from app.core.config import (  # noqa: E402
    LAZARUS_EVENT_SYNC_ENABLED,
    LAZARUS_EVENT_SYNC_INTERVAL_SEC,
    QIANXIN_COLLECTION_TRIGGER_ENABLED,
    QIANXIN_EVENT_SYNC_ENABLED,
    QIANXIN_EVENT_SYNC_INTERVAL_SEC,
)

event_ingestion_schedule = dict(celery_app.conf.beat_schedule or {})
if LAZARUS_EVENT_SYNC_ENABLED:
    event_ingestion_schedule.update(
        {
            "trigger-lazarus-collection-weekly": {
                "task": "tasks.trigger_lazarus_collection",
                "schedule": crontab(minute=0, hour=9, day_of_week="sun"),
            },
            "sync-lazarus-events": {
                "task": "tasks.sync_lazarus_events",
                "schedule": float(LAZARUS_EVENT_SYNC_INTERVAL_SEC),
            },
        }
    )
if QIANXIN_COLLECTION_TRIGGER_ENABLED:
    event_ingestion_schedule["trigger-qianxin-collection-weekly"] = {
        "task": "tasks.trigger_qianxin_collection",
        "schedule": crontab(minute=5, hour=3, day_of_week="sun"),
    }
if QIANXIN_EVENT_SYNC_ENABLED:
    event_ingestion_schedule["sync-qianxin-events"] = {
        "task": "tasks.sync_qianxin_events",
        "schedule": float(QIANXIN_EVENT_SYNC_INTERVAL_SEC),
    }
celery_app.conf.beat_schedule = event_ingestion_schedule

# 多队列扩展预留：默认不启用，避免影响现有 worker 的队列消费行为。
CELERY_MULTI_QUEUE_ENABLED = os.getenv(
    "CELERY_MULTI_QUEUE_ENABLED", "false"
).strip().lower() in {"1", "true", "yes", "y", "on"}
CELERY_DEFAULT_QUEUE = os.getenv("CELERY_DEFAULT_QUEUE", "celery")

celery_app.conf.update(task_default_queue=CELERY_DEFAULT_QUEUE)

if CELERY_MULTI_QUEUE_ENABLED:
    apthunter_exchange = Exchange("apthunter", type="direct")
    malicious_queue_name = os.getenv("CELERY_MALICIOUS_QUEUE", "apthunter_malicious")
    impersonation_queue_name = os.getenv(
        "CELERY_IMPERSONATION_QUEUE", "apthunter_impersonation"
    )
    dga_queue_name = os.getenv("CELERY_DGA_QUEUE", "apthunter_dga")
    apt_template_nrd_queue_name = os.getenv(
        "CELERY_APT_TEMPLATE_NRD_QUEUE", "apthunter_apt_template_nrd"
    )

    celery_app.conf.update(
        task_queues=(
            Queue(
                malicious_queue_name,
                exchange=apthunter_exchange,
                routing_key=malicious_queue_name,
            ),
            Queue(
                impersonation_queue_name,
                exchange=apthunter_exchange,
                routing_key=impersonation_queue_name,
            ),
            Queue(
                dga_queue_name, exchange=apthunter_exchange, routing_key=dga_queue_name
            ),
            Queue(
                apt_template_nrd_queue_name,
                exchange=apthunter_exchange,
                routing_key=apt_template_nrd_queue_name,
            ),
            # 保留默认队列，便于兼容
            Queue(
                CELERY_DEFAULT_QUEUE,
                exchange=apthunter_exchange,
                routing_key=CELERY_DEFAULT_QUEUE,
            ),
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
            "tasks.execute_dga_task": {
                "queue": dga_queue_name,
                "routing_key": dga_queue_name,
            },
            "tasks.execute_apt_template_nrd_task": {
                "queue": apt_template_nrd_queue_name,
                "routing_key": apt_template_nrd_queue_name,
            },
        },
    )
