import logging
import os
import subprocess
import sys
import threading
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

logger = logging.getLogger("uvicorn.error")


def _apply_runtime_schema_compatibility(engine) -> None:
    """
    容器重建不会重放 MySQL 初始化 SQL；旧数据卷需要少量幂等 DDL 兼容当前代码。
    """
    statements = [
        "ALTER TABLE subscriptions MODIFY COLUMN threshold INT NULL DEFAULT NULL",
        "ALTER TABLE alerts MODIFY COLUMN threshold INT NULL DEFAULT NULL",
        "ALTER TABLE models MODIFY COLUMN model_category ENUM('malicious','impersonation','dga','history_similarity','apt_template_nrd') DEFAULT NULL",
        "ALTER TABLE tasks MODIFY COLUMN task_type ENUM('malicious','impersonation','malicious_ip','dga','history_similarity','apt_template_nrd') NOT NULL COMMENT '任务类型'",
        "ALTER TABLE training_tasks MODIFY COLUMN model_category ENUM('malicious','impersonation','dga','history_similarity','apt_template_nrd') NOT NULL DEFAULT 'malicious'",
        "ALTER TABLE alerts MODIFY COLUMN task_type ENUM('malicious','impersonation','malicious_ip','dga','history_similarity','apt_template_nrd') NOT NULL COMMENT '任务类型：恶意域名检测/仿冒域名检测/恶意IP检测/DGA域名检测/历史APT域名相似性检测/模板化APT域名检测'",
        "ALTER TABLE alert_files MODIFY COLUMN task_type ENUM('malicious','impersonation','malicious_ip','dga','history_similarity','apt_template_nrd') NOT NULL COMMENT '任务类型'",
    ]
    with engine.begin() as conn:
        for statement in statements:
            try:
                conn.execute(text(statement))
            except Exception:
                logger.exception("运行时数据库兼容迁移失败: %s", statement)
                raise

        model_seed_sql = text(
            """
            INSERT INTO models (
              name, version, description, model_path, file_size, accuracy_metrics,
              model_type, model_category, is_public, is_official, created_by, status
            )
            SELECT
              '模板化APT域名检测模型',
              'v1.0',
              '基于模板化APT域名模板库匹配待检测域名的官方规则模型',
              'dataset/history_data/APTdomain_templates.xlsx',
              NULL,
              JSON_OBJECT('note', '官方模板化APT域名匹配模型', 'template_source', 'dataset/history_data/APTdomain_templates.xlsx', 'default_score_threshold', 0.90),
              'official',
              'apt_template_nrd',
              1,
              1,
              'system',
              'active'
            WHERE NOT EXISTS (
              SELECT 1 FROM models
              WHERE model_category = 'apt_template_nrd'
                AND model_type = 'official'
                AND status = 'active'
            )
            """
        )
        model_update_sql = text(
            """
            UPDATE models
            SET
              name = '模板化APT域名检测模型',
              model_path = 'dataset/history_data/APTdomain_templates.xlsx',
              description = '基于模板化APT域名模板库匹配待检测域名的官方规则模型',
              accuracy_metrics = JSON_OBJECT('note', '官方模板化APT域名匹配模型', 'template_source', 'dataset/history_data/APTdomain_templates.xlsx', 'default_score_threshold', 0.90),
              is_public = 1,
              is_official = 1,
              status = 'active'
            WHERE model_category = 'apt_template_nrd'
              AND model_type = 'official'
            """
        )
        user_binding_sql = text(
            """
            INSERT IGNORE INTO user_models (user_id, model_id, acquired_at, is_active, source)
            SELECT u.id, m.id, NOW(), 1, 'official'
            FROM users u
            JOIN models m
              ON m.model_category = 'apt_template_nrd'
             AND m.model_type = 'official'
             AND m.status = 'active'
            """
        )
        try:
            conn.execute(model_seed_sql)
            conn.execute(model_update_sql)
            conn.execute(user_binding_sql)
        except Exception:
            logger.exception("运行时模板化APT域名官方模型初始化失败")
            raise


def create_app() -> FastAPI:
    # 勿命名为 app：会与顶层包 app 冲突，导致 from app.api... 解析失败
    fastapi_app = FastAPI()
    fastapi_app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
    )

    @fastapi_app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        errors = exc.errors()
        errors_serializable = []
        for error in errors:
            error_dict = {
                "type": error.get("type"),
                "loc": error.get("loc"),
                "msg": error.get("msg"),
                "input": str(error.get("input", "")),
            }
            if "ctx" in error:
                error_dict["ctx"] = {k: str(v) for k, v in error["ctx"].items()}
            errors_serializable.append(error_dict)

        logger.error(f"Validation error: {errors_serializable}")
        logger.error(f"Request URL: {request.url}")
        logger.error(f"Request method: {request.method}")
        logger.error(f"Request headers: {dict(request.headers)}")
        try:
            body = await request.body()
            logger.error(
                f"Request body type: {type(body)}, length: {len(body) if body else 0}"
            )
        except Exception as e:
            logger.error(f"Failed to read request body: {e}")
        return JSONResponse(
            status_code=422,
            content={
                "detail": errors_serializable,
                "message": "请求参数验证失败，请检查表单数据格式",
            },
        )

    # 初始化 MinIO 客户端与默认桶（模块导入即执行）
    import app.infra.minio_client  # noqa: F401

    from app.db.base import Base
    from app.db.session import engine
    from app.entities import Model, StoredFile, Task, User, UserModel  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _apply_runtime_schema_compatibility(engine)

    from app.api.login import router as login_router

    fastapi_app.include_router(login_router)

    from app.api.menu import router as menu_router

    fastapi_app.include_router(menu_router)

    from app.api.dashboard_stats import router as dashboard_stats_router

    fastapi_app.include_router(dashboard_stats_router)

    from app.api.dashboard_organization import router as dashboard_organization_router

    fastapi_app.include_router(dashboard_organization_router)

    from app.api.dashboard_spatial import router as dashboard_spatial_router

    fastapi_app.include_router(dashboard_spatial_router)

    from app.api.dashboard_domain import router as dashboard_domain_router

    fastapi_app.include_router(dashboard_domain_router)

    from app.api.detection import router as detection_router

    fastapi_app.include_router(detection_router)

    from app.api.models import router as models_router

    fastapi_app.include_router(models_router)

    from app.api.account import router as account_router

    fastapi_app.include_router(account_router)

    from app.api.training import router as training_router

    fastapi_app.include_router(training_router)

    from app.api.subscription import router as subscription_router, init_scheduler

    fastapi_app.include_router(subscription_router)

    from app.api.domain_matches import router as domain_matches_router

    fastapi_app.include_router(domain_matches_router)

    from app.api.domain_monitor import router as domain_monitor_router

    fastapi_app.include_router(domain_monitor_router)

    from app.api.domain_lookup import router as domain_lookup_router

    fastapi_app.include_router(domain_lookup_router)

    from app.api.domain_attribution import router as domain_attribution_router

    fastapi_app.include_router(domain_attribution_router)

    @fastapi_app.on_event("startup")
    async def startup_event():
        """应用启动时初始化订阅调度器"""
        try:
            from app.api.subscription import check_missed_subscriptions

            check_missed_subscriptions()

            init_scheduler()
            logger.info("订阅调度器初始化完成")
        except Exception as e:
            logger.exception(f"订阅调度器初始化失败: {e}")

        auto_domain_bootstrap_enabled = os.getenv("AUTO_DOMAIN_BOOTSTRAP", "false").lower() in {"1", "true", "yes"}

        def run_domain_bootstrap():
            try:
                logger.info("启动域名属性自动补全任务")
                backend_root = Path(__file__).resolve().parents[2]
                script_path = backend_root / "scripts" / "domain_attributes_bootstrap.py"
                if not script_path.exists():
                    logger.warning("域名属性自动补全脚本不存在: %s", script_path)
                    return
                subprocess.run([sys.executable, str(script_path)], check=True)
                logger.info("域名属性自动补全任务完成")
            except Exception as exc:
                logger.exception("域名属性自动补全任务失败: %s", exc)

        if auto_domain_bootstrap_enabled:
            threading.Thread(target=run_domain_bootstrap, daemon=True).start()
        else:
            logger.info("域名属性自动补全已关闭")

    @fastapi_app.on_event("shutdown")
    async def shutdown_event():
        """应用关闭时停止订阅调度器"""
        try:
            from app.api.subscription import scheduler

            if scheduler and scheduler.running:
                scheduler.shutdown()
                logger.info("订阅调度器已停止")
        except Exception as e:
            logger.exception(f"停止订阅调度器失败: {e}")

    return fastapi_app
