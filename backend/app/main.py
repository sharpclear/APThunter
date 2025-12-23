# ...existing code...
from fastapi import FastAPI, File, Form, UploadFile, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from minio import Minio
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    Enum as SqlEnum,
    JSON,
    BigInteger,
    text,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import uuid
import io
from datetime import datetime
import json
import logging

logger = logging.getLogger("uvicorn.error")

app = FastAPI()
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# 添加422异常处理器来显示详细的验证错误
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    # 将错误信息转换为可序列化的格式
    errors_serializable = []
    for error in errors:
        error_dict = {
            "type": error.get("type"),
            "loc": error.get("loc"),
            "msg": error.get("msg"),
            "input": str(error.get("input", ""))  # 确保input可以被序列化
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
        logger.error(f"Request body type: {type(body)}, length: {len(body) if body else 0}")
    except Exception as e:
        logger.error(f"Failed to read request body: {e}")
    return JSONResponse(
        status_code=422,
        content={
            "detail": errors_serializable,
            "message": "请求参数验证失败，请检查表单数据格式"
        }
    )

# 配置通过环境变量设置
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "123456789")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "uploads")

MYSQL_URL = os.getenv("MYSQL_URL", "mysql+pymysql://apthunter:4CyUhr2zu6!@localhost:3306/apthunter_new")
IMPERSONATION_MODEL_NAME = os.getenv("IMPERSONATION_MODEL_NAME", "impersonation_detector")

# 初始化 MinIO 客户端
minio_client = Minio(MINIO_ENDPOINT, access_key=MINIO_ACCESS_KEY, secret_key=MINIO_SECRET_KEY, secure=False)
if not minio_client.bucket_exists(MINIO_BUCKET):
    minio_client.make_bucket(MINIO_BUCKET)

# 初始化 DB
engine = create_engine(MYSQL_URL, echo=False, future=True)
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False)


class Model(Base):
    __tablename__ = "models"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    version = Column(String(64), nullable=True)
    description = Column(Text, nullable=True)
    model_path = Column(String(500), nullable=True)
    file_size = Column(BigInteger, nullable=True)
    #accuracy_metrics = Column(JSON, nullable=True)
    model_type = Column(SqlEnum("official", "custom", "market", name="model_type_enum"), nullable=True, server_default="custom")
    is_public = Column(Integer, nullable=True, server_default=text("0"))
    #is_official = Column(Integer, nullable=True, server_default=text("0"))
    created_by = Column(String(64), nullable=True)
    status = Column(SqlEnum("active", "inactive", name="model_status_enum"), nullable=False, server_default="active")
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    # updated_at 字段：数据库models表中没有此字段，已移除
    model_category = Column(SqlEnum("malicious", "impersonation", name="model_category_enum"), nullable=True)


class StoredFile(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True, autoincrement=True)
    bucket = Column(String(128), nullable=False)
    object_key = Column(String(512), nullable=False)
    filename = Column(String(255), nullable=True)
    content_type = Column(String(128), nullable=True)
    size = Column(BigInteger, nullable=True)
    uploaded_by = Column(String(64), nullable=True)
    uploaded_at = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    metadata_json = Column("metadata", JSON, nullable=True)


class UserModel(Base):
    __tablename__ = "user_models"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    model_id = Column(Integer, ForeignKey("models.id"), nullable=False)
    acquired_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    is_active = Column(Integer, nullable=True, server_default=text("1"))


class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(String(64), unique=True, index=True, nullable=False)
    task_type = Column(
        SqlEnum("malicious", "impersonation", name="task_type_enum"),
        nullable=False,
    )
    model_id = Column(Integer, ForeignKey("models.id"), nullable=False)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=True)
    extra = Column(JSON, nullable=True)
    status = Column(
        SqlEnum("pending", "processing", "completed", "failed", name="task_status_enum"),
        nullable=False,
        server_default="pending",
    )
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    updated_at = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=datetime.utcnow,
    )

Base.metadata.create_all(bind=engine)

# 添加一个简单的 db 依赖供路由使用（保持和现有 SessionLocal 一致）
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def upload_to_minio(file: UploadFile, bucket: str = MINIO_BUCKET):
    ext = file.filename.split(".")[-1] if file.filename else ""
    key = f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex
    data = file.file.read()
    file_stream = io.BytesIO(data)
    minio_client.put_object(
        bucket,
        key,
        file_stream,
        length=len(data),
        content_type=file.content_type or "application/octet-stream",
    )
    file.file.seek(0)
    return key, len(data)

# 在这里不要直接实现 /api/login、/api/user/info —— 改为由独立路由模块提供
# 把导入放在 engine/SessionLocal/get_db 定义之后，避免循环导入问题
from api.login import router as login_router  # 导入 login 路由
app.include_router(login_router)

from api.menu import router as menu_router # 导入 menu 路由
app.include_router(menu_router)

from api.detection import router as detection_router  # 导入 detection 路由
app.include_router(detection_router)

from api.models import router as models_router  # 导入 models 路由
app.include_router(models_router)

from api.account import router as account_router  # 导入 account 路由
app.include_router(account_router)

from api.training import router as training_router  # 导入 training 路由
app.include_router(training_router)

# 仿冒域名检测任务API已移至 api/detection.py 中的 create_impersonation_task 函数
# ...existing code...
