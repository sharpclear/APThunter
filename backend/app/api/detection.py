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
# 从 main 导入必要的依赖
from main import SessionLocal, Task, Model, StoredFile, minio_client, MINIO_BUCKET, IMPERSONATION_MODEL_NAME, engine
# 导入恶意检测模块
from malicious_detection import predict_from_file, predict_from_domains
# 导入仿冒检测模块
from phishing_detector import (
    detect_phishing_domains,
    read_official_domains_from_file,
    read_detection_domains_from_file,
    predict_from_file as phishing_predict_from_file,
    predict_from_domains as phishing_predict_from_domains,
)

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


def _parse_date_string(date_str: str) -> datetime.date:
    if not isinstance(date_str, str):
        raise ValueError("date string required")
    cleaned = date_str.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    return datetime.fromisoformat(cleaned).date()


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
            
            # 如果上传了文件，异步执行恶意检测
            if file_key and dataSource == "upload":
                # 在后台执行检测（这里使用同步方式，实际生产环境建议使用异步任务队列）
                try:
                    # 更新任务状态为处理中
                    task.status = "processing"
                    db.commit()
                    
                    # 从MinIO下载文件
                    logger.info(f"开始处理任务 {task_id}，从MinIO下载文件: {file_key}")
                    download_bucket = uploaded_file_meta["bucket"] if uploaded_file_meta else MINIO_BUCKET
                    file_content = download_file_from_minio(file_key, download_bucket)
                    
                    # 获取原始文件名
                    original_filename = file.filename or "unknown"
                    
                    # 获取模型路径（从数据库记录中获取）
                    model_path_to_use = model_record.model_path
                    if not model_path_to_use:
                        logger.warning(f"模型 {model_record.name} 的 model_path 为空，使用默认路径")
                        model_path_to_use = None
                    else:
                        logger.info(f"使用模型路径: {model_path_to_use}")
                    
                    # 执行恶意检测
                    logger.info(f"开始执行恶意检测，域名数量从文件读取")
                    excel_content, statistics = predict_from_file(file_content, original_filename, model_path_to_use)
                    
                    # 生成结果文件名
                    result_filename = f"result_{task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                    
                    # 上传结果到MinIO results桶
                    result_key = upload_file_content_to_minio(
                        excel_content,
                        result_filename,
                        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        bucket=RESULTS_BUCKET
                    )
                    
                    # 更新任务状态和结果
                    task.status = "completed"
                    # 将结果信息添加到extra字段
                    extra_data['result_file_key'] = result_key
                    extra_data['result_bucket'] = RESULTS_BUCKET
                    extra_data['result_filename'] = result_filename
                    extra_data['statistics'] = statistics
                    extra_data['completed_at'] = datetime.utcnow().isoformat()
                    task.extra = extra_data
                    
                    db.commit()
                    logger.info(f"任务 {task_id} 处理完成，结果文件: {result_key}")
                    
                except Exception as e:
                    # 更新任务状态为失败
                    task.status = "failed"
                    extra_data['error'] = str(e)
                    task.extra = extra_data
                    db.commit()
                    logger.exception(f"任务 {task_id} 处理失败: {e}")
                    # 不抛出异常，任务已创建，只是处理失败
            elif dataSource == "newDomain" and date_range_parsed:
                try:
                    task.status = "processing"
                    db.commit()

                    domains, missing_dates = _collect_daily_domains(date_range_parsed)
                    logger.info(f"任务 {task_id} 使用 {len(domains)} 条每日数据进行检测")

                    # 获取模型路径（从数据库记录中获取）
                    model_path_to_use = model_record.model_path
                    if not model_path_to_use:
                        logger.warning(f"模型 {model_record.name} 的 model_path 为空，使用默认路径")
                        model_path_to_use = None
                    else:
                        logger.info(f"使用模型路径: {model_path_to_use}")

                    source_label = f"daily_{task_id}"
                    excel_content, statistics = predict_from_domains(domains, source_label, model_path_to_use)

                    result_filename = f"result_{task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                    result_key = upload_file_content_to_minio(
                        excel_content,
                        result_filename,
                        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        bucket=RESULTS_BUCKET
                    )

                    task.status = "completed"
                    extra_data['result_file_key'] = result_key
                    extra_data['result_bucket'] = RESULTS_BUCKET
                    extra_data['result_filename'] = result_filename
                    extra_data['statistics'] = statistics
                    extra_data['daily_missing_dates'] = missing_dates
                    extra_data['daily_domain_count'] = len(domains)
                    extra_data['completed_at'] = datetime.utcnow().isoformat()
                    task.extra = extra_data
                    db.commit()
                except Exception as e:
                    task.status = "failed"
                    extra_data['error'] = str(e)
                    task.extra = extra_data
                    db.commit()
                    logger.exception(f"任务 {task_id} 处理失败: {e}")
            
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "ok": True,
                    "task_id": task.task_id,
                    "status": task.status
                }
            )
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
            
            # 执行检测
            try:
                # 更新任务状态为处理中
                task.status = "processing"
                db.commit()
                
                logger.info(f"开始处理仿冒域名检测任务 {task_id}")
                
                # 执行检测
                try:
                    if detectionSource == "upload" and detection_file_content:
                        # 从文件检测
                        logger.info(f"使用文件模式进行检测，官方文件: {officialFile.filename}, 检测文件: {detectionFile.filename if detectionFile else 'unknown'}")
                        excel_content, statistics = phishing_predict_from_file(
                            official_file_content,
                            officialFile.filename or "unknown",
                            detection_file_content,
                            detectionFile.filename if detectionFile else "unknown"
                        )
                    else:
                        # 从域名列表检测
                        logger.info(f"使用域名列表模式进行检测，检测域名数量: {len(detection_domains) if detection_domains else 0}")
                        official_domains = read_official_domains_from_file(
                            official_file_content,
                            officialFile.filename or "unknown"
                        )
                        logger.info(f"读取到官方域名数量: {len(official_domains)}")
                        if not detection_domains:
                            raise ValueError("待检测域名列表为空")
                        if not official_domains:
                            raise ValueError("官方域名列表为空")
                        excel_content, statistics = phishing_predict_from_domains(
                            official_domains,
                            detection_domains
                        )
                    logger.info(f"检测完成，统计信息: {statistics}")
                except Exception as detection_error:
                    logger.exception(f"检测过程出错: {detection_error}")
                    raise
                
                # 生成结果文件名
                result_filename = f"result_{task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                
                # 上传结果到MinIO results桶
                result_key = upload_file_content_to_minio(
                    excel_content,
                    result_filename,
                    content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    bucket=RESULTS_BUCKET
                )
                
                # 更新任务状态和结果
                task.status = "completed"
                extra_data['result_file_key'] = result_key
                extra_data['result_bucket'] = RESULTS_BUCKET
                extra_data['result_filename'] = result_filename
                extra_data['statistics'] = statistics
                extra_data['completed_at'] = datetime.utcnow().isoformat()
                task.extra = extra_data
                
                db.commit()
                logger.info(f"仿冒域名检测任务 {task_id} 处理完成，结果文件: {result_key}")
                
            except Exception as e:
                # 更新任务状态为失败
                task.status = "failed"
                extra_data['error'] = str(e)
                task.extra = extra_data
                db.commit()
                logger.exception(f"仿冒域名检测任务 {task_id} 处理失败: {e}")
                # 不抛出异常，任务已创建，只是处理失败
            
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "ok": True,
                    "task_id": task.task_id,
                    "status": task.status
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