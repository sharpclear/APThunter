from fastapi import APIRouter, File, Form, UploadFile, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse, StreamingResponse
from datetime import datetime, timedelta
from typing import Optional, List, Tuple
import logging
import json
import uuid
import io
import sys
import os
import zipfile
from urllib.parse import quote
from sqlalchemy import text
# 添加models目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'models'))
# 从 entities / main / db / core 导入必要的依赖
from app.entities import Task, Model, StoredFile
from app.infra.minio_client import minio_client
from app.db.session import SessionLocal, engine
from app.core.config import MINIO_BUCKET, IMPERSONATION_MODEL_NAME
from app.services.task_dispatcher import dispatch_impersonation_task, dispatch_malicious_task

logger = logging.getLogger("uvicorn.error")

# MinIO results 桶名称
RESULTS_BUCKET = "results"
DAILY_DATA_DIR = os.path.abspath(
    os.getenv("DAILY_DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "daily_data"))
)

STATUS_LABEL_MAP = {
    "pending": "待执行",
    "processing": "执行中",
    "completed": "已完成",
    "failed": "失败",
}
TASK_TYPE_LABEL_MAP = {
    "malicious": "恶意性检测",
    "impersonation": "仿冒域名检测",
}
DATA_SOURCE_LABEL_MAP = {
    "upload": "上传文件",
    "newDomain": "新注册域名",
}
STATUS_PROGRESS_MAP = {
    "pending": 0,
    "processing": 60,
    "completed": 100,
    "failed": 0,
}


def upload_file_content_to_minio(file_content: bytes, filename: str, content_type: Optional[str] = None, bucket: str = MINIO_BUCKET) -> str:
    """上传文件内容到 MinIO"""
    ext = filename.split(".")[-1] if "." in filename else ""
    key = f"{uuid.uuid4().hex}.{ext}"
    # MinIO 的 put_object 需要一个可读对象（有 read 方法），所以需要将 bytes 包装成 BytesIO
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


def download_file_from_minio(file_key: str, bucket: str = MINIO_BUCKET) -> bytes:
    """从 MinIO 下载文件内容"""
    try:
        response = minio_client.get_object(bucket, file_key)
        file_content = response.read()
        response.close()
        response.release_conn()
        return file_content
    except Exception as e:
        logger.error(f"从MinIO下载文件失败: {e}")
        raise

router = APIRouter()


def _extract_user_id(request: Request) -> Optional[int]:
    user_id_header = request.headers.get("X-User-Id")
    if not user_id_header:
        return None
    try:
        return int(user_id_header)
    except ValueError:
        logger.warning("Invalid X-User-Id header value: %s", user_id_header)
        return None


def _require_user_id(request: Request) -> int:
    user_id = _extract_user_id(request)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-User-Id header",
        )
    return user_id


def _normalize_extra(extra_value):
    if not extra_value:
        return {}
    if isinstance(extra_value, str):
        try:
            return json.loads(extra_value)
        except json.JSONDecodeError:
            logger.warning("Failed to parse task extra JSON")
            return {}
    return dict(extra_value)


def _task_result_status_payload(task: Task, extra_data: dict) -> dict:
    """pending / processing / failed，或 completed 但缺少结果文件时的统一 JSON 结构。"""
    raw = task.status
    err = extra_data.get("error")
    if raw == "pending":
        msg = "任务等待执行中"
        err_out = None
    elif raw == "processing":
        msg = "任务正在执行中，请稍后重试"
        err_out = None
    elif raw == "failed":
        err_out = err if err is not None else None
        msg = str(err_out) if err_out else "任务执行失败"
    elif raw == "completed":
        err_out = err if err is not None else None
        msg = "任务已完成，但结果文件不可用或尚未写入"
    else:
        err_out = None
        msg = f"未知任务状态: {raw}"

    return {
        "ok": False,
        "task_id": task.task_id,
        "task_type": task.task_type,
        "status": raw,
        "rawStatus": raw,
        "message": msg,
        "result": None,
        "error": err_out,
    }


def _parse_date_string(date_str: str) -> datetime.date:
    if not isinstance(date_str, str):
        raise ValueError("date string required")
    cleaned = date_str.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    return datetime.fromisoformat(cleaned).date()


# 新注册域名日期范围：开始日期从 2024-09-01 起，最多可选往后一个月
_MIN_START_DATE = datetime(2024, 9, 1).date()


def _validate_new_domain_date_range(start_date, end_date) -> None:
    """校验新注册域名日期范围：开始>=2024-09-01，范围最多一个月"""
    if start_date < _MIN_START_DATE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="开始日期不能早于 2024-09-01"
        )
    max_end = start_date + timedelta(days=30)  # 最多往后一个月
    if end_date > max_end:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="日期范围最多为一个月"
        )


def _collect_daily_domains(date_range: List[str]) -> Tuple[List[str], List[str]]:
    if not isinstance(date_range, list) or len(date_range) < 2:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="dateRange 参数无效")
    try:
        start_date = _parse_date_string(str(date_range[0]))
        end_date = _parse_date_string(str(date_range[1]))
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="dateRange 解析失败")
    if start_date > end_date:
        start_date, end_date = end_date, start_date
    _validate_new_domain_date_range(start_date, end_date)
    domains_set = set()
    missing_dates = []
    current = start_date
    while current <= end_date:
        month_folder = os.path.join(DAILY_DATA_DIR, current.strftime("%Y-%m"))
        zip_name = f"{current.strftime('%Y-%m-%d')}-domain.zip"
        zip_path = os.path.join(month_folder, zip_name)
        if not os.path.exists(zip_path):
            missing_dates.append(current.isoformat())
            current += timedelta(days=1)
            continue
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                if "dailyupdate.txt" not in zf.namelist():
                    missing_dates.append(current.isoformat())
                    current += timedelta(days=1)
                    continue
                with zf.open("dailyupdate.txt") as file_handle:
                    content = file_handle.read().decode("utf-8", errors="ignore")
                    for line in content.splitlines():
                        domain = line.strip()
                        if domain:
                            domains_set.add(domain)
        except Exception as exc:
            logger.exception("读取每日数据失败: %s (%s)", exc, zip_path)
            missing_dates.append(current.isoformat())
        current += timedelta(days=1)
    domains = list(domains_set)
    if not domains:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="指定日期范围内没有可用的新注册域名数据")
    return domains, missing_dates


@router.post("/api/tasks")
async def create_detection_task(
    request: Request,
    model: str = Form(...),
    dataSource: str = Form(...),
    withAttribution: str = Form("false"),
    file: Optional[UploadFile] = File(None),
    dateRange: Optional[str] = Form(None)
):
    """
    创建恶意性检测任务
    
    参数:
    - model: 检测模型ID
    - dataSource: 数据来源 ('upload' 或 'newDomain')
    - withAttribution: 是否包含归因分析 ('true' 或 'false')
    - file: 上传的文件（当 dataSource 为 'upload' 时必填）
    - dateRange: 日期范围JSON字符串（当 dataSource 为 'newDomain' 时必填）
    """
    try:
        created_by_user_id: Optional[int] = _extract_user_id(request)
        uploaded_by_header = request.headers.get("X-User-Name") or request.headers.get("X-User")
        uploaded_file_meta = None

        # 记录接收到的参数
        file_info = None
        if file is not None:
            file_info = {
                "filename": file.filename,
                "content_type": file.content_type,
                "size": getattr(file, 'size', 'unknown')
            }
        logger.info(f"Received task creation request: model={model}, dataSource={dataSource}, withAttribution={withAttribution}, file={file_info}, dateRange={dateRange}")
        # 验证数据来源参数
        if dataSource not in ["upload", "newDomain"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="dataSource must be 'upload' or 'newDomain'"
            )
        
        # 验证文件上传
        if dataSource == "upload" and file is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="file is required when dataSource is 'upload'"
            )
        
        # 验证日期范围
        if dataSource == "newDomain" and (not dateRange or dateRange.strip() == ""):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="dateRange is required when dataSource is 'newDomain'"
            )
        
        # 处理文件上传
        file_key = None
        if file is not None:
            # 验证文件类型
            file_ext = file.filename.split(".")[-1].lower() if file.filename else ""
            allowed_extensions = ["csv", "txt", "xlsx"]
            if file_ext not in allowed_extensions:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File type not allowed. Only {', '.join(allowed_extensions)} are supported"
                )
            
            # 读取文件内容验证大小
            file_content = await file.read()
            file_size = len(file_content)
            max_size = 5 * 1024 * 1024  # 5MB
            
            if file_size > max_size:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File size exceeds maximum allowed size of {max_size / 1024 / 1024}MB"
                )
            
            # 直接使用文件内容上传到 MinIO
            file_key = upload_file_content_to_minio(
                file_content,
                file.filename or "unknown",
                file.content_type
            )
            uploaded_file_meta = {
                "bucket": MINIO_BUCKET,
                "object_key": file_key,
                "filename": file.filename or "unknown",
                "content_type": file.content_type,
                "size": file_size,
            }
        
        # 解析日期范围（如果提供）
        date_range_parsed = None
        if dateRange:
            try:
                date_range_parsed = json.loads(dateRange)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse dateRange: {dateRange}")
        
        # 构建 extra 字段
        extra_data = {
            "dataSource": dataSource,
            "dateRange": date_range_parsed,
            "withAttribution": withAttribution.lower() == "true"
        }
        if uploaded_file_meta:
            extra_data["file_bucket"] = uploaded_file_meta["bucket"]
            extra_data["file_object_key"] = uploaded_file_meta["object_key"]
        
        # 生成任务ID
        task_id = f"T{int(datetime.utcnow().timestamp())}"
        
        # 保存任务到数据库
        db = SessionLocal()
        try:
            # 先尝试将model参数作为ID（整数）查找，如果失败则作为name查找（保持向后兼容）
            model_record = None
            model_id_int = None
            try:
                model_id_int = int(model)
                model_record = db.query(Model).filter(Model.id == model_id_int).first()
            except ValueError:
                # 如果不是整数，则作为name查找
                model_record = db.query(Model).filter(Model.name == model).first()
                if model_record:
                    model_id_int = model_record.id
            
            if not model_record:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"模型 {model} 不存在"
                )
            
            # 验证用户是否有权限使用该模型（从user_models表检查）
            if created_by_user_id is not None:
                with engine.connect() as conn:
                    user_model_query = text("""
                        SELECT um.id 
                        FROM user_models um
                        WHERE um.user_id = :user_id 
                          AND um.model_id = :model_id 
                          AND um.is_active = 1
                    """)
                    user_model_result = conn.execute(
                        user_model_query, 
                        {"user_id": created_by_user_id, "model_id": model_record.id}
                    ).first()
                    
                    if not user_model_result:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"您没有权限使用模型 {model_record.name}，请从模型市场获取或创建自己的模型"
                        )

            file_record = None
            if uploaded_file_meta:
                file_record = StoredFile(
                    bucket=uploaded_file_meta["bucket"],
                    object_key=uploaded_file_meta["object_key"],
                    filename=uploaded_file_meta["filename"],
                    content_type=uploaded_file_meta["content_type"],
                    size=uploaded_file_meta["size"],
                    uploaded_by=uploaded_by_header,
                    metadata_json={
                        "source": "malicious_detection",
                        "original_filename": uploaded_file_meta["filename"],
                    },
                )
                db.add(file_record)
                db.flush()

            task = Task(
                task_id=task_id,
                task_type="malicious",
                model_id=model_record.id,
                file_id=file_record.id if file_record else None,
                extra=extra_data,
                status="pending",
                created_by=created_by_user_id,
            )
            db.add(task)
            db.commit()
            db.refresh(task)
            
            # 通过 Celery 异步执行检测，接口仅负责创建任务并入队
            try:
                dispatch_malicious_task(task.task_id)
            except Exception as exc:
                # 处理入队失败：避免任务长期停留在 pending（DB 已创建但 Redis 未入队）
                logger.exception("enqueue malicious task failed: %s", exc)
                task.status = "failed"
                extra_data_failed = dict(task.extra or {})
                extra_data_failed["error"] = str(exc)
                extra_data_failed["enqueue_failed"] = True
                extra_data_failed["enqueue_failed_at"] = datetime.utcnow().isoformat()
                task.extra = extra_data_failed
                db.commit()
                db.refresh(task)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to enqueue task",
                ) from exc
            
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "ok": True,
                    "task_id": task.task_id,
                    "status": "pending"
                }
            )
        except HTTPException:
            # 入队失败或参数异常：已根据具体情况落库/处理
            raise
        except Exception as e:
            db.rollback()
            logger.exception(f"Failed to create task: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create task"
            )
        finally:
            db.close()
            
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error in create_detection_task: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred"
        )


@router.get("/api/tasks")
async def list_tasks(
    request: Request,
    page: int = Query(1, ge=1),
    pageSize: int = Query(100, ge=1, le=500),
):
    """获取当前用户的任务列表"""
    user_id = _require_user_id(request)
    db = SessionLocal()
    try:
        total = (
            db.query(Task)
            .filter(Task.created_by == user_id)
            .count()
        )
        records = (
            db.query(Task, Model, StoredFile)
            .join(Model, Model.id == Task.model_id)
            .outerjoin(StoredFile, StoredFile.id == Task.file_id)
            .filter(Task.created_by == user_id)
            .order_by(Task.created_at.desc())
            .offset((page - 1) * pageSize)
            .limit(pageSize)
            .all()
        )
        items = []
        for task, model, stored_file in records:
            extra_data = _normalize_extra(task.extra)
            task_type_label = TASK_TYPE_LABEL_MAP.get(task.task_type, task.task_type)
            status_label = STATUS_LABEL_MAP.get(task.status, task.status)
            progress = STATUS_PROGRESS_MAP.get(task.status, 0)
            
            # 对于仿冒域名检测任务，使用 detectionSource；对于恶意性检测任务，使用 dataSource
            data_source_type = ""
            if task.task_type == "impersonation":
                data_source_type = extra_data.get("detectionSource", "")
            else:
                data_source_type = extra_data.get("dataSource", "")
            
            data_source_label = DATA_SOURCE_LABEL_MAP.get(data_source_type, "上传文件")
            data_source_payload = {"type": data_source_label}
            
            if data_source_type == "upload":
                if task.task_type == "impersonation":
                    # 仿冒域名检测任务：显示检测文件名（如果有），否则显示官方文件名
                    detection_file_id = extra_data.get("detection_file_id")
                    if detection_file_id:
                        # 查询检测文件记录
                        detection_file = db.query(StoredFile).filter(StoredFile.id == detection_file_id).first()
                        if detection_file:
                            data_source_payload["fileName"] = detection_file.filename
                        else:
                            # 如果没有检测文件记录，使用官方文件名
                            data_source_payload["fileName"] = stored_file.filename if stored_file else None
                    else:
                        # 只有官方文件
                        data_source_payload["fileName"] = stored_file.filename if stored_file else None
                else:
                    # 恶意性检测任务：使用主文件
                    data_source_payload["fileName"] = stored_file.filename if stored_file else None
            elif data_source_type == "newDomain":
                date_range = extra_data.get("dateRange") or []
                if isinstance(date_range, list) and len(date_range) >= 2:
                    data_source_payload["dateRange"] = [str(date_range[0]), str(date_range[1])]
            items.append({
                "id": task.task_id,
                "createdAt": task.created_at.isoformat() if task.created_at else "",
                "taskType": task_type_label,
                "model": model.name if model else "",
                "dataSource": data_source_payload,
                "status": status_label,
                "progress": progress,
                "eta": "",
                "resultFileKey": extra_data.get("result_file_key"),
                "resultBucket": extra_data.get("result_bucket"),
                "resultFileName": extra_data.get("result_filename") or extra_data.get("result_file_key"),
                "rawStatus": task.status,
            })
        return {"items": items, "total": total}
    finally:
        db.close()


@router.delete("/api/tasks/{task_id}")
async def delete_task(task_id: str, request: Request):
    """删除指定任务"""
    user_id = _require_user_id(request)
    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.task_id == task_id).first()
        if not task:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
        if task.created_by != user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        db.delete(task)
        db.commit()
        return {"ok": True}
    finally:
        db.close()


@router.get("/api/tasks/{task_id}/result")
async def get_task_result_json(task_id: str, request: Request):
    """获取任务结果（JSON格式，用于前端展示）。

    pending / processing / failed 以及 completed 但无结果文件时返回 200 + 结构化状态，不再使用 404。
    completed 且存在结果文件时，保持原有成功响应结构（向后兼容）。
    """
    user_id = _require_user_id(request)
    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.task_id == task_id).first()
        if not task:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
        if task.created_by != user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

        extra_data = _normalize_extra(task.extra)
        result_key = extra_data.get("result_file_key")

        # 非终态或尚无结果文件：返回结构化状态（200），便于前端轮询
        if task.status in ("pending", "processing", "failed"):
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=_task_result_status_payload(task, extra_data),
            )
        if task.status == "completed" and not result_key:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=_task_result_status_payload(task, extra_data),
            )

        result_bucket = extra_data.get("result_bucket") or RESULTS_BUCKET
        
        try:
            # 从MinIO下载Excel文件
            file_bytes = download_file_from_minio(result_key, result_bucket)
        except Exception as exc:
            logger.exception("获取结果文件失败: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to fetch result file"
            )
        
        try:
            # 解析Excel文件
            import pandas as pd
            excel_file = io.BytesIO(file_bytes)

            # 根据任务类型读取不同的工作表
            if task.task_type == "impersonation":
                # 仿冒域名检测结果
                try:
                    results_df = pd.read_excel(excel_file, sheet_name='检测结果')
                except Exception:
                    # 如果没有检测结果工作表，创建一个空的DataFrame
                    results_df = pd.DataFrame(columns=["钓鱼域名", "目标域名", "公司名称", "相似度", "匹配类型"])

                # 读取统计信息表
                stats_df = pd.read_excel(excel_file, sheet_name='统计信息')

                # 读取钓鱼域名列表（如果存在）
                phishing_list = []
                try:
                    phishing_df = pd.read_excel(excel_file, sheet_name='钓鱼域名列表')
                    phishing_list = phishing_df.to_dict('records')
                except Exception:
                    # 如果没有钓鱼域名列表工作表，从结果中筛选
                    pass

                # 将DataFrame转换为字典列表
                results_list = results_df.to_dict('records')

                # 将统计信息转换为字典
                statistics_dict = {}
                for _, row in stats_df.iterrows():
                    statistics_dict[row['统计项']] = row['数值']

                # 如果没有钓鱼域名列表，从结果中筛选
                if not phishing_list:
                    phishing_list = [r for r in results_list if r.get('钓鱼域名')]

                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={
                        "ok": True,
                        "task_id": task.task_id,
                        "task_type": task.task_type,
                        "statistics": statistics_dict,
                        "results": results_list,
                        "phishing_domains": phishing_list,
                        "result_file_key": result_key,
                        "result_filename": extra_data.get("result_filename") or f"{task.task_id}_result.xlsx",
                        "total_count": len(results_list),
                        "phishing_count": len(phishing_list),
                    }
                )
            else:
                # 恶意性检测结果（原有的逻辑）
                # 读取预测结果表
                results_df = pd.read_excel(excel_file, sheet_name='预测结果')

                # 读取统计信息表
                stats_df = pd.read_excel(excel_file, sheet_name='统计信息')

                # 读取恶意域名列表（如果存在）
                malicious_list = []
                try:
                    malicious_df = pd.read_excel(excel_file, sheet_name='恶意域名列表')
                    malicious_list = malicious_df.to_dict('records')
                except Exception:
                    # 如果没有恶意域名列表工作表，从结果中筛选
                    pass

                # 将DataFrame转换为字典列表
                results_list = results_df.to_dict('records')

                # 将统计信息转换为字典
                statistics_dict = {}
                for _, row in stats_df.iterrows():
                    statistics_dict[row['统计项']] = row['数值']

                # 如果没有恶意域名列表，从结果中筛选
                if not malicious_list:
                    malicious_list = [r for r in results_list if r.get('预测标签') == 1 or r.get('预测结果') == '恶意']

                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={
                        "ok": True,
                        "task_id": task.task_id,
                        "task_type": task.task_type,
                        "statistics": statistics_dict,
                        "results": results_list,
                        "malicious_domains": malicious_list,
                        "result_file_key": result_key,
                        "result_filename": extra_data.get("result_filename") or f"{task.task_id}_result.xlsx",
                        "total_count": len(results_list),
                        "malicious_count": len(malicious_list),
                    }
                )
        except Exception as exc:
            logger.exception("解析结果文件失败: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to parse result file: {str(exc)}"
            )
    finally:
        db.close()


@router.get("/api/tasks/{task_id}/download")
async def download_task_result(task_id: str, request: Request):
    """下载任务结果文件"""
    user_id = _require_user_id(request)
    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.task_id == task_id).first()
        if not task:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
        if task.created_by != user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        extra_data = _normalize_extra(task.extra)
        result_key = extra_data.get("result_file_key")
        if not result_key:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Result file not found")
        result_bucket = extra_data.get("result_bucket") or RESULTS_BUCKET
        filename = extra_data.get("result_filename") or f"{task.task_id}_result.xlsx"
        try:
            file_bytes = download_file_from_minio(result_key, result_bucket)
        except Exception as exc:
            logger.exception("下载结果文件失败: %s", exc)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to fetch result file")
        response = StreamingResponse(
            io.BytesIO(file_bytes),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        response.headers["Content-Disposition"] = f"attachment; filename*=utf-8''{quote(filename)}"
        return response
    finally:
        db.close()


@router.post("/api/impersonation-tasks")
async def create_impersonation_task(
    request: Request,
    officialFile: UploadFile = File(...),
    detectionSource: str = Form(...),
    detectionFile: Optional[UploadFile] = File(None),
    detectionDateRange: Optional[str] = Form(None),
):
    """
    创建仿冒域名检测任务
    
    参数:
    - officialFile: 官方域名文件（必填，csv/txt/xlsx格式，每行为企业名,域名）
    - detectionSource: 待检测域名来源 ('upload' 或 'newDomain')
    - detectionFile: 待检测域名文件（当 detectionSource 为 'upload' 时必填）
    - detectionDateRange: 日期范围JSON字符串（当 detectionSource 为 'newDomain' 时必填）
    """
    try:
        logger.info("收到仿冒域名检测任务创建请求")
        created_by_user_id: Optional[int] = _extract_user_id(request)
        uploaded_by_header = request.headers.get("X-User-Name") or request.headers.get("X-User")
        logger.info(f"用户ID: {created_by_user_id}, 上传者: {uploaded_by_header}")
        
        # 验证参数
        if detectionSource not in ["upload", "newDomain"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="detectionSource must be 'upload' or 'newDomain'"
            )
        if detectionSource == "upload" and detectionFile is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="detectionFile is required when detectionSource is 'upload'"
            )
        if detectionSource == "newDomain" and (not detectionDateRange or detectionDateRange.strip() == ""):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="detectionDateRange is required when detectionSource is 'newDomain'"
            )
        
        # 验证官方文件类型
        official_file_ext = officialFile.filename.split(".")[-1].lower() if officialFile.filename else ""
        allowed_extensions = ["csv", "txt", "xlsx"]
        if official_file_ext not in allowed_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Official file type not allowed. Only {', '.join(allowed_extensions)} are supported"
            )
        
        # 读取官方文件内容
        official_file_content = await officialFile.read()
        official_file_size = len(official_file_content)
        max_size = 5 * 1024 * 1024  # 5MB
        if official_file_size > max_size:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Official file size exceeds maximum allowed size of {max_size / 1024 / 1024}MB"
            )
        
        # 上传官方文件到MinIO
        official_file_key = upload_file_content_to_minio(
            official_file_content,
            officialFile.filename or "unknown",
            officialFile.content_type
        )
        
        # 处理待检测域名
        detection_file_key = None
        detection_file_content = None
        detection_domains = None
        missing_dates = []
        
        if detectionSource == "upload":
            # 验证待检测文件类型
            if detectionFile is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="detectionFile is required"
                )
            detection_file_ext = detectionFile.filename.split(".")[-1].lower() if detectionFile.filename else ""
            if detection_file_ext not in allowed_extensions:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Detection file type not allowed. Only {', '.join(allowed_extensions)} are supported"
                )
            
            # 读取待检测文件内容
            detection_file_content = await detectionFile.read()
            detection_file_size = len(detection_file_content)
            if detection_file_size > max_size:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Detection file size exceeds maximum allowed size of {max_size / 1024 / 1024}MB"
                )
            
            # 上传待检测文件到MinIO
            detection_file_key = upload_file_content_to_minio(
                detection_file_content,
                detectionFile.filename or "unknown",
                detectionFile.content_type
            )
        else:  # newDomain
            # 解析日期范围
            try:
                date_range_parsed = json.loads(detectionDateRange)
                logger.info(f"解析日期范围: {date_range_parsed}")
            except json.JSONDecodeError as e:
                logger.error(f"日期范围JSON解析失败: {e}, 原始数据: {detectionDateRange}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid detectionDateRange format"
                )
            
            # 收集每日数据
            logger.info("开始收集每日域名数据")
            detection_domains, missing_dates = _collect_daily_domains(date_range_parsed)
            logger.info(f"收集到域名数量: {len(detection_domains) if detection_domains else 0}, 缺失日期: {missing_dates}")
            
            if not detection_domains:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="指定日期范围内没有找到域名数据"
                )
        
        # 生成任务ID
        task_id = f"T{int(datetime.utcnow().timestamp())}"
        
        # 保存任务到数据库
        db = SessionLocal()
        try:
            logger.info(f"查找模型: {IMPERSONATION_MODEL_NAME}")
            # 查找模型
            model_record = db.query(Model).filter(Model.name == IMPERSONATION_MODEL_NAME).first()
            if not model_record:
                logger.error(f"模型 '{IMPERSONATION_MODEL_NAME}' 不存在于数据库中")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Impersonation model '{IMPERSONATION_MODEL_NAME}' not configured"
                )
            logger.info(f"找到模型记录: id={model_record.id}, name={model_record.name}")
            
            # 保存官方文件记录
            official_file_record = StoredFile(
                bucket=MINIO_BUCKET,
                object_key=official_file_key,
                filename=officialFile.filename,
                content_type=officialFile.content_type,
                size=official_file_size,
                uploaded_by=uploaded_by_header,
                metadata_json={"source": "impersonation_task", "role": "official"},
            )
            db.add(official_file_record)
            
            # 保存待检测文件记录（如果有）
            detection_file_record = None
            if detection_file_key:
                detection_file_record = StoredFile(
                    bucket=MINIO_BUCKET,
                    object_key=detection_file_key,
                    filename=detectionFile.filename if detectionFile else None,
                    content_type=detectionFile.content_type if detectionFile else None,
                    size=len(detection_file_content) if detection_file_content else None,
                    uploaded_by=uploaded_by_header,
                    metadata_json={"source": "impersonation_task", "role": "detection"},
                )
                db.add(detection_file_record)
            
            db.flush()
            
            # 构建extra字段
            extra_data = {
                "detectionSource": detectionSource,
                "official_file_id": official_file_record.id,
                "official_file_object_key": official_file_key,
            }
            if detection_file_record:
                extra_data["detection_file_id"] = detection_file_record.id
                extra_data["detection_file_object_key"] = detection_file_key
            if detectionSource == "newDomain":
                extra_data["dateRange"] = date_range_parsed
                if missing_dates:
                    extra_data["missing_dates"] = missing_dates
            
            # 创建任务
            task = Task(
                task_id=task_id,
                task_type="impersonation",
                model_id=model_record.id,
                file_id=official_file_record.id,
                extra=extra_data,
                status="pending",
                created_by=created_by_user_id,
            )
            db.add(task)
            db.commit()
            db.refresh(task)
            
            # 通过 Celery 异步执行检测，接口仅负责创建任务并入队
            try:
                dispatch_impersonation_task(task.task_id)
            except Exception as exc:
                # 处理入队失败：避免任务长期停留在 pending（DB 已创建但 Redis 未入队）
                logger.exception("enqueue impersonation task failed: %s", exc)
                task.status = "failed"
                extra_data_failed = dict(task.extra or {})
                extra_data_failed["error"] = str(exc)
                extra_data_failed["enqueue_failed"] = True
                extra_data_failed["enqueue_failed_at"] = datetime.utcnow().isoformat()
                task.extra = extra_data_failed
                db.commit()
                db.refresh(task)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to enqueue task",
                ) from exc
            
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "ok": True,
                    "task_id": task.task_id,
                    "status": "pending"
                }
            )
        except HTTPException:
            db.rollback()
            raise
        except Exception as e:
            db.rollback()
            logger.exception(f"Failed to create impersonation task: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create impersonation task"
            )
        finally:
            db.close()
            
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error in create_impersonation_task: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred"
        )