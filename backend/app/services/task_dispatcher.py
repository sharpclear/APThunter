from app.tasks.detection_tasks import (
    execute_impersonation_task_job,
    execute_malicious_task_job,
)


def dispatch_malicious_task(task_id: str) -> str:
    try:
        execute_malicious_task_job.delay(task_id=task_id)
        return task_id
    except Exception as exc:
        # 入队失败通常来自 broker 不可用/连接失败；抛出让 API 层落库一致性
        raise RuntimeError(
            f"enqueue_failed malicious task_id={task_id}: {exc}"
        ) from exc


def dispatch_impersonation_task(task_id: str) -> str:
    try:
        execute_impersonation_task_job.delay(task_id=task_id)
        return task_id
    except Exception as exc:
        # 入队失败通常来自 broker 不可用/连接失败；抛出让 API 层落库一致性
        raise RuntimeError(
            f"enqueue_failed impersonation task_id={task_id}: {exc}"
        ) from exc
