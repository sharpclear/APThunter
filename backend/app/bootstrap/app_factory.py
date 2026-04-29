import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

logger = logging.getLogger("uvicorn.error")


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
