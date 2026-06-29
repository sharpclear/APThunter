from app.tasks.detection_tasks import (
    execute_apt_template_nrd_task_job,
    execute_dga_task_job,
    execute_history_similarity_task_job,
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


def dispatch_dga_task(task_id: str) -> str:
    try:
        execute_dga_task_job.delay(task_id=task_id)
        return task_id
    except Exception as exc:
        raise RuntimeError(
            f"enqueue_failed dga task_id={task_id}: {exc}"
        ) from exc


def dispatch_history_similarity_task(task_id: str) -> str:
    try:
        execute_history_similarity_task_job.delay(task_id=task_id)
        return task_id
    except Exception as exc:
        raise RuntimeError(
            f"enqueue_failed history_similarity task_id={task_id}: {exc}"
        ) from exc


def dispatch_apt_template_nrd_task(task_id: str) -> str:
    try:
        execute_apt_template_nrd_task_job.delay(task_id=task_id)
        return task_id
    except Exception as exc:
        raise RuntimeError(
            f"enqueue_failed apt_template_nrd task_id={task_id}: {exc}"
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
