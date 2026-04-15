"""Celery worker 入口模块：仅导出 `celery_app`。

本地在 ``backend`` 目录下可执行（需能解析包 ``app``）::

    PYTHONPATH=. celery -A celery_worker worker --loglevel=info

Docker Compose 推荐使用与镜像一致的模块路径（镜像已设置 ``PYTHONPATH=/app``）::

    celery -A app.celery_app:celery_app worker --loglevel=info
"""
from app.celery_app import celery_app

__all__ = ["celery_app"]
