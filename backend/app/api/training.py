from fastapi import APIRouter, File, Form, UploadFile, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text
from typing import Optional, List
import jwt
import logging
import uuid
import io
import os
import sys
import json
import threading
import time
from datetime import datetime
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# 添加models目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'models'))
from app.infra.minio_client import minio_client
from app.db.session import engine
from app.core.config import MINIO_BUCKET
import utils_ML

logger = logging.getLogger("uvicorn.error")

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

router = APIRouter()

# MinIO训练数据桶名称
TRAINING_DATA_BUCKET = "traindata"
# 模型保存目录（与 malicious_detection.load_model 相对路径 saved_model/ 一致；使用绝对路径避免工作目录变化）
_MODELS_ROOT = os.path.normpath(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models')))
MODEL_SAVE_DIR = os.path.join(_MODELS_ROOT, 'saved_model')
os.makedirs(MODEL_SAVE_DIR, exist_ok=True)

# 全局训练任务字典，用于存储训练状态（实际生产环境应使用Redis等）
training_tasks_status = {}
training_tasks_lock = threading.Lock()

# 设置全局keywords（utils_ML的edit_dist函数需要）
# 注意：utils_ML.py中edit_dist函数直接使用keywords变量，需要在模块级别设置
utils_ML.keywords = ['gov', 'pk', 'mail', 'serve']


def get_current_user_id(request: Request, authorization: Optional[str] = None) -> Optional[int]:
    """从Authorization header、query params或cookies中提取用户ID"""
    token = None
    if authorization:
        if authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1]
        else:
            token = authorization
    if not token:
        token = request.query_params.get("token") or request.cookies.get("token")
    if not token:
        return None
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        return int(user_id) if user_id else None
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except Exception as e:
        logger.error(f"Token decode error: {e}")
        return None


def upload_file_to_minio(file_content: bytes, filename: str, content_type: Optional[str] = None, bucket: str = TRAINING_DATA_BUCKET) -> str:
    """上传文件到MinIO"""
    ext = filename.split(".")[-1] if "." in filename else ""
    key = f"{uuid.uuid4().hex}.{ext}"
    file_stream = io.BytesIO(file_content)
    
    # 确保bucket存在
    if not minio_client.bucket_exists(bucket):
        minio_client.make_bucket(bucket)
    
    minio_client.put_object(
        bucket,
        key,
        file_stream,
        length=len(file_content),
        content_type=content_type or "application/octet-stream"
    )
    return key


def download_file_from_minio(file_key: str, bucket: str = TRAINING_DATA_BUCKET) -> bytes:
    """从MinIO下载文件"""
    try:
        response = minio_client.get_object(bucket, file_key)
        file_content = response.read()
        response.close()
        response.release_conn()
        return file_content
    except Exception as e:
        logger.error(f"从MinIO下载文件失败: {e}")
        raise


def parse_training_data(file_content: bytes, filename: str) -> tuple:
    """解析训练数据文件，返回域名列表和标签列表"""
    domains = []
    labels = []
    
    try:
        content = file_content.decode('utf-8', errors='ignore')
        lines = content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # 解析格式：域名,标签(0/1)
            parts = line.split(',')
            if len(parts) < 2:
                continue
            
            domain = parts[0].strip()
            try:
                label = int(parts[1].strip())
                if label not in [0, 1]:
                    continue
                domains.append(domain)
                labels.append(label)
            except ValueError:
                continue
        
        if len(domains) == 0:
            raise ValueError("文件中没有找到有效的训练数据")
        
        return domains, labels
    except Exception as e:
        logger.error(f"解析训练数据失败: {e}")
        raise ValueError(f"解析训练数据失败: {str(e)}")


def train_model_task(task_id: str, training_data_file_id: int, model_name: str, model_desc: str):
    """异步训练模型任务"""
    try:
        # 更新状态为training
        with training_tasks_lock:
            if task_id in training_tasks_status:
                training_tasks_status[task_id]['status'] = 'training'
                training_tasks_status[task_id]['progress'] = 0.0
        
        # 更新数据库状态
        with engine.connect() as conn:
            conn.execute(text("""
                UPDATE training_tasks 
                SET training_status = 'training', started_at = NOW(), progress = 0.0
                WHERE task_id = :task_id
            """), {"task_id": task_id})
            conn.commit()
        
        # 1. 从数据库获取文件信息
        with engine.connect() as conn:
            file_query = text("""
                SELECT object_key, bucket FROM files WHERE id = :file_id
            """)
            file_row = conn.execute(file_query, {"file_id": training_data_file_id}).mappings().first()
            if not file_row:
                raise ValueError("训练数据文件不存在")
            
            object_key = file_row["object_key"]
            bucket = file_row["bucket"] or TRAINING_DATA_BUCKET
        
        # 2. 下载训练数据
        logger.info(f"任务 {task_id}: 开始下载训练数据")
        file_content = download_file_from_minio(object_key, bucket)
        
        # 更新进度 10%
        with training_tasks_lock:
            if task_id in training_tasks_status:
                training_tasks_status[task_id]['progress'] = 10.0
        
        with engine.connect() as conn:
            conn.execute(text("UPDATE training_tasks SET progress = 10.0 WHERE task_id = :task_id"), 
                       {"task_id": task_id})
            conn.commit()
        
        # 3. 解析训练数据
        logger.info(f"任务 {task_id}: 开始解析训练数据")
        domains, labels = parse_training_data(file_content, "training_data.csv")
        logger.info(f"任务 {task_id}: 解析完成，共 {len(domains)} 条数据")
        
        # 更新进度 20%
        with training_tasks_lock:
            if task_id in training_tasks_status:
                training_tasks_status[task_id]['progress'] = 20.0
        
        with engine.connect() as conn:
            conn.execute(text("UPDATE training_tasks SET progress = 20.0 WHERE task_id = :task_id"), 
                       {"task_id": task_id})
            conn.commit()
        
        # 4. 提取特征（确保keywords已设置）
        logger.info(f"任务 {task_id}: 开始提取特征")
        # 确保keywords已设置（edit_dist函数需要）
        if not hasattr(utils_ML, 'keywords') or not utils_ML.keywords:
            utils_ML.keywords = ['gov', 'pk', 'mail', 'serve']
        features = utils_ML.feature_extract(domains)
        features = np.array(features)
        labels = np.array(labels)
        
        logger.info(f"任务 {task_id}: 特征提取完成，特征维度: {features.shape}")
        
        # 更新进度 50%
        with training_tasks_lock:
            if task_id in training_tasks_status:
                training_tasks_status[task_id]['progress'] = 50.0
        
        with engine.connect() as conn:
            conn.execute(text("UPDATE training_tasks SET progress = 50.0 WHERE task_id = :task_id"), 
                       {"task_id": task_id})
            conn.commit()
        
        # 5. 数据划分
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # 6. 特征标准化
        logger.info(f"任务 {task_id}: 开始标准化特征")
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # 更新进度 60%
        with training_tasks_lock:
            if task_id in training_tasks_status:
                training_tasks_status[task_id]['progress'] = 60.0
        
        with engine.connect() as conn:
            conn.execute(text("UPDATE training_tasks SET progress = 60.0 WHERE task_id = :task_id"), 
                       {"task_id": task_id})
            conn.commit()
        
        # 7. 训练模型（使用RandomForest）
        logger.info(f"任务 {task_id}: 开始训练模型")
        model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        model.fit(X_train_scaled, y_train)
        
        # 更新进度 85%
        with training_tasks_lock:
            if task_id in training_tasks_status:
                training_tasks_status[task_id]['progress'] = 85.0
        
        with engine.connect() as conn:
            conn.execute(text("UPDATE training_tasks SET progress = 85.0 WHERE task_id = :task_id"), 
                       {"task_id": task_id})
            conn.commit()
        
        # 8. 评估模型
        logger.info(f"任务 {task_id}: 开始评估模型")
        y_pred = model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        metrics = {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1)
        }
        
        logger.info(f"任务 {task_id}: 评估完成 - Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
        
        # 更新进度 90%
        with training_tasks_lock:
            if task_id in training_tasks_status:
                training_tasks_status[task_id]['progress'] = 90.0
        
        with engine.connect() as conn:
            conn.execute(text("UPDATE training_tasks SET progress = 90.0 WHERE task_id = :task_id"), 
                       {"task_id": task_id})
            conn.commit()
        
        # 9. 保存模型和scaler（Docker 下需 bind mount ./backend/app/models/saved_model 才能在宿主机看到文件）
        logger.info(
            "任务 %s: 开始保存模型，目录=%s 可写=%s",
            task_id,
            MODEL_SAVE_DIR,
            os.access(MODEL_SAVE_DIR, os.W_OK),
        )
        model_filename = f"model_{task_id}_{int(time.time())}.pkl"
        scaler_filename = f"scaler_{task_id}_{int(time.time())}.pkl"
        model_path = os.path.join(MODEL_SAVE_DIR, model_filename)
        scaler_path = os.path.join(MODEL_SAVE_DIR, scaler_filename)
        
        # 规范化路径（移除 ../ 等符号）
        model_path_abs = os.path.normpath(os.path.abspath(model_path))
        scaler_path_abs = os.path.normpath(os.path.abspath(scaler_path))
        
        joblib.dump(model, model_path_abs)
        joblib.dump(scaler, scaler_path_abs)
        
        logger.info(f"任务 {task_id}: 模型已保存到 {model_path_abs}")
        
        # 规范化保存到数据库的路径：优先保存相对路径（相对于 models 目录）
        models_base_dir = _MODELS_ROOT
        
        # 如果模型路径在 models 目录下，转换为相对路径；否则使用规范化后的绝对路径
        try:
            # 尝试转换为相对路径
            model_path_for_db = os.path.relpath(model_path_abs, models_base_dir)
            # 验证相对路径是否有效（不以 .. 开头）
            if not model_path_for_db.startswith('..'):
                logger.info(f"任务 {task_id}: 使用相对路径保存到数据库: {model_path_for_db}")
            else:
                # 如果相对路径包含 ..，说明不在 models 目录下，使用绝对路径
                model_path_for_db = model_path_abs
                logger.info(f"任务 {task_id}: 模型不在 models 目录下，使用绝对路径保存: {model_path_for_db}")
        except ValueError:
            # 如果无法计算相对路径（不同驱动器等），使用绝对路径
            model_path_for_db = model_path_abs
            logger.info(f"任务 {task_id}: 无法计算相对路径，使用绝对路径保存: {model_path_for_db}")
        
        # 10. 创建模型记录
        with engine.connect() as conn:
            # 获取用户信息
            task_query = text("SELECT user_id FROM training_tasks WHERE task_id = :task_id")
            task_row = conn.execute(task_query, {"task_id": task_id}).mappings().first()
            if not task_row:
                raise ValueError("训练任务不存在")
            
            user_id = task_row["user_id"]
            
            # 获取用户名
            user_query = text("SELECT username FROM users WHERE id = :user_id")
            user_row = conn.execute(user_query, {"user_id": user_id}).mappings().first()
            username = user_row["username"] if user_row else str(user_id)
            
            # 计算模型文件大小（使用规范化后的路径）
            model_file_size = os.path.getsize(model_path_abs) + os.path.getsize(scaler_path_abs)
            
            # 插入模型记录（使用规范化后的路径）
            model_insert = text("""
                INSERT INTO models (name, description, model_path, file_size, model_type, model_category, created_by, status)
                VALUES (:name, :description, :model_path, :file_size, 'custom', 'malicious', :created_by, 'active')
            """)
            result = conn.execute(model_insert, {
                "name": model_name,
                "description": model_desc,
                "model_path": model_path_for_db,
                "file_size": model_file_size,
                "created_by": username
            })
            conn.commit()
            
            model_id = result.lastrowid
            
            # 创建user_models关联
            user_model_insert = text("""
                INSERT INTO user_models (user_id, model_id, acquired_at, is_active, source)
                VALUES (:user_id, :model_id, NOW(), 1, 'custom')
            """)
            conn.execute(user_model_insert, {
                "user_id": user_id,
                "model_id": model_id
            })
            conn.commit()
        
        # 11. 更新训练任务状态为完成
        with training_tasks_lock:
            if task_id in training_tasks_status:
                training_tasks_status[task_id]['status'] = 'completed'
                training_tasks_status[task_id]['progress'] = 100.0
                training_tasks_status[task_id]['model_id'] = model_id
                training_tasks_status[task_id]['metrics'] = metrics
        
        with engine.connect() as conn:
            conn.execute(text("""
                UPDATE training_tasks 
                SET training_status = 'completed', 
                    progress = 100.0,
                    model_id = :model_id,
                    accuracy_metrics = :metrics,
                    completed_at = NOW()
                WHERE task_id = :task_id
            """), {
                "task_id": task_id,
                "model_id": model_id,
                "metrics": json.dumps(metrics)
            })
            conn.commit()
        
        logger.info(f"任务 {task_id}: 训练完成")
        
    except Exception as e:
        logger.error(f"任务 {task_id}: 训练失败 - {str(e)}", exc_info=True)
        
        # 更新状态为失败
        with training_tasks_lock:
            if task_id in training_tasks_status:
                training_tasks_status[task_id]['status'] = 'failed'
                training_tasks_status[task_id]['error'] = str(e)
        
        with engine.connect() as conn:
            conn.execute(text("""
                UPDATE training_tasks 
                SET training_status = 'failed', 
                    error_message = :error_message,
                    completed_at = NOW()
                WHERE task_id = :task_id
            """), {
                "task_id": task_id,
                "error_message": str(e)
            })
            conn.commit()


# Pydantic模型定义
class TrainingStartRequest(BaseModel):
    modelName: str
    modelDesc: Optional[str] = None
    fileId: int


@router.post("/api/training/upload-data")
async def upload_training_data(
    file: UploadFile = File(...),
    request: Request = None,
    authorization: Optional[str] = Header(None)
):
    """上传训练数据文件"""
    try:
        user_id = get_current_user_id(request, authorization)
        if not user_id:
            return JSONResponse(
                status_code=401,
                content={"code": 401, "message": "未认证或token已过期，请重新登录", "data": None}
            )
        
        # 验证文件类型
        file_ext = file.filename.split(".")[-1].lower() if file.filename else ""
        if file_ext not in ["csv", "txt"]:
            return JSONResponse(
                status_code=400,
                content={"code": 400, "message": "仅支持CSV/TXT格式的文件", "data": None}
            )
        
        # 验证文件大小（5MB）
        file_content = await file.read()
        file_size = len(file_content)
        max_size = 5 * 1024 * 1024  # 5MB
        if file_size > max_size:
            return JSONResponse(
                status_code=400,
                content={"code": 400, "message": f"文件大小不能超过 {max_size / 1024 / 1024}MB", "data": None}
            )
        
        # 上传到MinIO
        try:
            file_key = upload_file_to_minio(file_content, file.filename or "training_data.csv", file.content_type)
        except Exception as e:
            logger.error(f"上传文件到MinIO失败: {e}")
            return JSONResponse(
                status_code=500,
                content={"code": 500, "message": f"文件上传失败: {str(e)}", "data": None}
            )
        
        # 获取用户名
        with engine.connect() as conn:
            user_query = text("SELECT username FROM users WHERE id = :user_id")
            user_row = conn.execute(user_query, {"user_id": user_id}).mappings().first()
            username = user_row["username"] if user_row else str(user_id)
        
        # 保存文件记录到数据库
        try:
            with engine.connect() as conn:
                file_insert = text("""
                    INSERT INTO files (bucket, object_key, filename, content_type, size, uploaded_by, uploaded_at)
                    VALUES (:bucket, :object_key, :filename, :content_type, :size, :uploaded_by, NOW())
                """)
                result = conn.execute(file_insert, {
                    "bucket": TRAINING_DATA_BUCKET,
                    "object_key": file_key,
                    "filename": file.filename or "training_data.csv",
                    "content_type": file.content_type or "text/plain",
                    "size": file_size,
                    "uploaded_by": username
                })
                conn.commit()
                
                file_id = result.lastrowid
        except Exception as e:
            logger.error(f"保存文件记录到数据库失败: {e}")
            return JSONResponse(
                status_code=500,
                content={"code": 500, "message": f"保存文件记录失败: {str(e)}", "data": None}
            )
        
        return {
            "code": 0,
            "message": "文件上传成功",
            "data": {
                "fileId": file_id,
                "filename": file.filename,
                "size": file_size
            }
        }
    except Exception as e:
        logger.exception("上传训练数据文件时发生未知错误")
        return JSONResponse(
            status_code=500,
            content={"code": 500, "message": f"上传失败: {str(e)}", "data": None}
        )


@router.post("/api/training/start")
async def start_training(
    payload: TrainingStartRequest,
    request: Request = None,
    authorization: Optional[str] = Header(None)
):
    """创建并启动训练任务"""
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 验证模型名称
    if not payload.modelName or len(payload.modelName.strip()) < 2 or len(payload.modelName.strip()) > 50:
        raise HTTPException(status_code=400, detail="模型名称长度应为2-50个字符")
    
    # 验证文件是否存在
    with engine.connect() as conn:
        file_query = text("SELECT id FROM files WHERE id = :file_id")
        file_row = conn.execute(file_query, {"file_id": payload.fileId}).mappings().first()
        if not file_row:
            raise HTTPException(status_code=404, detail="训练数据文件不存在")
    
    # 生成任务ID
    task_id = f"TRAIN_{uuid.uuid4().hex[:16]}"
    
    # 创建训练任务记录
    with engine.connect() as conn:
        task_insert = text("""
            INSERT INTO training_tasks (
                task_id, user_id, model_name, model_desc, model_category,
                training_data_file_id, training_status, progress, created_at
            )
            VALUES (
                :task_id, :user_id, :model_name, :model_desc, 'malicious',
                :file_id, 'pending', 0.0, NOW()
            )
        """)
        conn.execute(task_insert, {
            "task_id": task_id,
            "user_id": user_id,
            "model_name": payload.modelName.strip(),
            "model_desc": (payload.modelDesc or "").strip()[:500],
            "file_id": payload.fileId
        })
        conn.commit()
    
    # 初始化任务状态
    with training_tasks_lock:
        training_tasks_status[task_id] = {
            'status': 'pending',
            'progress': 0.0,
            'started_at': None
        }
    
    # 启动异步训练任务
    training_thread = threading.Thread(
        target=train_model_task,
        args=(task_id, payload.fileId, payload.modelName.strip(), (payload.modelDesc or "").strip()),
        daemon=True
    )
    training_thread.start()
    
    return {
        "code": 0,
        "message": "训练任务已提交，开始训练",
        "data": {
            "taskId": task_id
        }
    }


@router.get("/api/training/tasks/{task_id}/status")
async def get_training_status(
    task_id: str,
    request: Request = None,
    authorization: Optional[str] = Header(None)
):
    """获取训练任务状态和进度"""
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 从数据库查询任务信息
    with engine.connect() as conn:
        task_query = text("""
            SELECT 
                task_id, model_name, training_status, progress,
                accuracy_metrics, model_id, error_message,
                started_at, completed_at, created_at,
                estimated_remaining_seconds
            FROM training_tasks
            WHERE task_id = :task_id AND user_id = :user_id
        """)
        task_row = conn.execute(task_query, {"task_id": task_id, "user_id": user_id}).mappings().first()
        
        if not task_row:
            raise HTTPException(status_code=404, detail="训练任务不存在")
        
        # 计算预计剩余时间
        estimated_remaining = None
        if task_row["training_status"] == "training" and task_row["started_at"] and task_row["progress"] > 0:
            elapsed = (datetime.now() - task_row["started_at"]).total_seconds()
            if elapsed > 0 and task_row["progress"] < 100:
                rate = task_row["progress"] / elapsed  # % per second
                if rate > 0:
                    remaining = (100 - task_row["progress"]) / rate
                    estimated_remaining = int(remaining)
                    
                    # 更新数据库
                    conn.execute(text("""
                        UPDATE training_tasks 
                        SET estimated_remaining_seconds = :remaining
                        WHERE task_id = :task_id
                    """), {"task_id": task_id, "remaining": estimated_remaining})
                    conn.commit()
        
        # 解析metrics
        metrics = None
        if task_row["accuracy_metrics"]:
            try:
                metrics = json.loads(task_row["accuracy_metrics"]) if isinstance(task_row["accuracy_metrics"], str) else task_row["accuracy_metrics"]
            except:
                pass
        
        # 状态映射（数据库 -> 前端）
        status_map = {
            "pending": "idle",
            "training": "running",
            "paused": "paused",
            "stopped": "stopped",
            "completed": "completed",
            "failed": "failed"
        }
        
        return {
            "code": 0,
            "message": "ok",
            "data": {
                "taskId": task_row["task_id"],
                "status": status_map.get(task_row["training_status"], task_row["training_status"]),
                "progress": float(task_row["progress"]),
                "estimatedRemaining": estimated_remaining,
                "metrics": metrics,
                "modelId": task_row["model_id"],
                "errorMessage": task_row["error_message"],
                "startedAt": task_row["started_at"].isoformat() if task_row["started_at"] else None,
                "completedAt": task_row["completed_at"].isoformat() if task_row["completed_at"] else None,
            }
        }


@router.post("/api/training/tasks/{task_id}/pause")
async def pause_training(
    task_id: str,
    request: Request = None,
    authorization: Optional[str] = Header(None)
):
    """暂停训练任务（暂不支持，返回提示）"""
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 检查任务是否存在
    with engine.connect() as conn:
        task_query = text("""
            SELECT training_status FROM training_tasks
            WHERE task_id = :task_id AND user_id = :user_id
        """)
        task_row = conn.execute(task_query, {"task_id": task_id, "user_id": user_id}).mappings().first()
        
        if not task_row:
            raise HTTPException(status_code=404, detail="训练任务不存在")
        
        if task_row["training_status"] != "training":
            raise HTTPException(status_code=400, detail="只有运行中的任务才能暂停")
    
    # 注意：当前实现不支持真正的暂停，因为训练是同步进行的
    # 这里只是更新状态，实际训练会继续完成
    return {
        "code": 0,
        "message": "暂停功能暂未实现，训练将继续进行"
    }


@router.post("/api/training/tasks/{task_id}/resume")
async def resume_training(
    task_id: str,
    request: Request = None,
    authorization: Optional[str] = Header(None)
):
    """恢复训练任务（暂不支持）"""
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    return {
        "code": 0,
        "message": "恢复功能暂未实现"
    }


@router.post("/api/training/tasks/{task_id}/stop")
async def stop_training(
    task_id: str,
    request: Request = None,
    authorization: Optional[str] = Header(None)
):
    """停止训练任务（暂不支持，返回提示）"""
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 检查任务是否存在
    with engine.connect() as conn:
        task_query = text("""
            SELECT training_status FROM training_tasks
            WHERE task_id = :task_id AND user_id = :user_id
        """)
        task_row = conn.execute(task_query, {"task_id": task_id, "user_id": user_id}).mappings().first()
        
        if not task_row:
            raise HTTPException(status_code=404, detail="训练任务不存在")
        
        if task_row["training_status"] not in ["training", "paused"]:
            raise HTTPException(status_code=400, detail="只有运行中或已暂停的任务才能停止")
    
    # 注意：当前实现不支持真正的停止，因为训练是同步进行的
    # 这里只是更新状态，实际训练会继续完成
    with engine.connect() as conn:
        conn.execute(text("""
            UPDATE training_tasks 
            SET training_status = 'stopped'
            WHERE task_id = :task_id
        """), {"task_id": task_id})
        conn.commit()
    
    return {
        "code": 0,
        "message": "停止功能暂未完全实现，训练可能继续完成"
    }


@router.get("/api/training/tasks")
async def get_training_tasks(
    request: Request = None,
    authorization: Optional[str] = Header(None),
    status: Optional[str] = None
):
    """获取用户的训练任务列表"""
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 构建查询条件
    conditions = ["user_id = :user_id"]
    params = {"user_id": user_id}
    
    if status:
        conditions.append("training_status = :status")
        params["status"] = status
    
    where_clause = " AND ".join(conditions)
    
    with engine.connect() as conn:
        query = text(f"""
            SELECT 
                task_id, model_name, model_desc, training_status, progress,
                accuracy_metrics, model_id, error_message,
                started_at, completed_at, created_at
            FROM training_tasks
            WHERE {where_clause}
            ORDER BY created_at DESC
        """)
        rows = conn.execute(query, params).mappings().all()
    
    tasks = []
    for row in rows:
        metrics = None
        if row["accuracy_metrics"]:
            try:
                metrics = json.loads(row["accuracy_metrics"]) if isinstance(row["accuracy_metrics"], str) else row["accuracy_metrics"]
            except:
                pass
        
        status_map = {
            "pending": "idle",
            "training": "running",
            "paused": "paused",
            "stopped": "stopped",
            "completed": "completed",
            "failed": "failed"
        }
        
        tasks.append({
            "taskId": row["task_id"],
            "modelName": row["model_name"],
            "modelDesc": row["model_desc"],
            "status": status_map.get(row["training_status"], row["training_status"]),
            "progress": float(row["progress"]),
            "metrics": metrics,
            "modelId": row["model_id"],
            "errorMessage": row["error_message"],
            "startedAt": row["started_at"].isoformat() if row["started_at"] else None,
            "completedAt": row["completed_at"].isoformat() if row["completed_at"] else None,
            "createdAt": row["created_at"].isoformat() if row["created_at"] else None,
        })
    
    return {
        "code": 0,
        "message": "ok",
        "data": tasks
    }


@router.get("/api/training/tasks/{task_id}/result")
async def get_training_result(
    task_id: str,
    request: Request = None,
    authorization: Optional[str] = Header(None)
):
    """获取训练结果"""
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    with engine.connect() as conn:
        task_query = text("""
            SELECT 
                task_id, model_name, training_status, accuracy_metrics,
                model_id, completed_at
            FROM training_tasks
            WHERE task_id = :task_id AND user_id = :user_id
        """)
        task_row = conn.execute(task_query, {"task_id": task_id, "user_id": user_id}).mappings().first()
        
        if not task_row:
            raise HTTPException(status_code=404, detail="训练任务不存在")
        
        if task_row["training_status"] != "completed":
            raise HTTPException(status_code=400, detail="训练任务尚未完成")
        
        # 解析metrics
        metrics = None
        if task_row["accuracy_metrics"]:
            try:
                metrics = json.loads(task_row["accuracy_metrics"]) if isinstance(task_row["accuracy_metrics"], str) else task_row["accuracy_metrics"]
            except:
                pass
        
        return {
            "code": 0,
            "message": "ok",
            "data": {
                "taskId": task_row["task_id"],
                "modelId": task_row["model_id"],
                "modelName": task_row["model_name"],
                "finishedAt": task_row["completed_at"].isoformat() if task_row["completed_at"] else None,
                "metrics": metrics
            }
        }
