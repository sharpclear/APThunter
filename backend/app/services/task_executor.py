import io
import logging
import os
import sys
import uuid
import zipfile
from datetime import datetime, timedelta
from typing import List, Tuple

from app.entities import Model, Task
from app.infra.minio_client import minio_client
from app.db.session import SessionLocal
from app.core.config import MINIO_BUCKET

# 添加models目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "models"))
from malicious_detection import predict_from_file, predict_from_domains
from phishing_detector import (
    predict_from_file as phishing_predict_from_file,
    predict_from_domains as phishing_predict_from_domains,
    read_official_domains_from_file,
)

logger = logging.getLogger("uvicorn.error")

RESULTS_BUCKET = "results"
DAILY_DATA_DIR = os.path.abspath(
    os.getenv("DAILY_DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "daily_data"))
)
_MIN_START_DATE = datetime(2024, 9, 1).date()


def _upload_file_content_to_minio(file_content: bytes, filename: str, content_type: str = None, bucket: str = MINIO_BUCKET) -> str:
    ext = filename.split(".")[-1] if "." in filename else ""
    key = f"{uuid.uuid4().hex}.{ext}"
    file_stream = io.BytesIO(file_content)
    if not minio_client.bucket_exists(bucket):
        minio_client.make_bucket(bucket)
    minio_client.put_object(
        bucket,
        key,
        file_stream,
        length=len(file_content),
        content_type=content_type or "application/octet-stream",
    )
    return key


def _download_file_from_minio(file_key: str, bucket: str = MINIO_BUCKET) -> bytes:
    response = minio_client.get_object(bucket, file_key)
    try:
        return response.read()
    finally:
        response.close()
        response.release_conn()


def _parse_date_string(date_str: str) -> datetime.date:
    cleaned = str(date_str).strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    return datetime.fromisoformat(cleaned).date()


def _collect_daily_domains(date_range: List[str]) -> Tuple[List[str], List[str]]:
    start_date = _parse_date_string(date_range[0])
    end_date = _parse_date_string(date_range[1])
    if start_date > end_date:
        start_date, end_date = end_date, start_date
    if start_date < _MIN_START_DATE:
        raise ValueError("开始日期不能早于 2024-09-01")
    if end_date > start_date + timedelta(days=30):
        raise ValueError("日期范围最多为一个月")

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
        raise ValueError("指定日期范围内没有可用的新注册域名数据")
    return domains, missing_dates


def execute_malicious_task(task_id: str):
    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.task_id == task_id).first()
        if not task:
            raise ValueError(f"任务不存在: {task_id}")
        model_record = db.query(Model).filter(Model.id == task.model_id).first()
        if not model_record:
            raise ValueError(f"模型不存在: {task.model_id}")

        extra_data = dict(task.extra or {})

        # 幂等性：任务已完成且已写入结果文件时，跳过重复执行
        if task.status == "completed" and extra_data.get("result_file_key"):
            logger.info("Skip already completed malicious task_id=%s", task_id)
            return

        task.status = "processing"
        db.commit()

        data_source = extra_data.get("dataSource")
        model_path_to_use = model_record.model_path or None
        result_filename = f"result_{task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

        if data_source == "upload":
            file_key = extra_data.get("file_object_key")
            file_bucket = extra_data.get("file_bucket") or MINIO_BUCKET
            if not file_key:
                raise ValueError("上传文件任务缺少 file_object_key")
            file_content = _download_file_from_minio(file_key, file_bucket)
            original_filename = file_key
            excel_content, statistics = predict_from_file(
                file_content,
                original_filename,
                model_path_to_use,
                malicious_only=False,
            )
        elif data_source == "newDomain":
            date_range = extra_data.get("dateRange")
            if not date_range or len(date_range) < 2:
                raise ValueError("newDomain 任务缺少 dateRange")
            domains, missing_dates = _collect_daily_domains(date_range)
            source_label = f"daily_{task_id}"
            excel_content, statistics = predict_from_domains(
                domains,
                source_label,
                model_path_to_use,
                malicious_only=True,
            )
            extra_data["daily_missing_dates"] = missing_dates
            extra_data["daily_domain_count"] = len(domains)
        else:
            raise ValueError(f"未知 dataSource: {data_source}")

        result_key = _upload_file_content_to_minio(
            excel_content,
            result_filename,
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            bucket=RESULTS_BUCKET,
        )

        task.status = "completed"
        extra_data["result_file_key"] = result_key
        extra_data["result_bucket"] = RESULTS_BUCKET
        extra_data["result_filename"] = result_filename
        extra_data["statistics"] = statistics
        extra_data["completed_at"] = datetime.utcnow().isoformat()
        task.extra = extra_data
        db.commit()
    except Exception as exc:
        logger.exception("执行恶意检测任务失败 %s: %s", task_id, exc)
        task = db.query(Task).filter(Task.task_id == task_id).first()
        if task:
            extra_data = dict(task.extra or {})
            task.status = "failed"
            extra_data["error"] = str(exc)
            task.extra = extra_data
            db.commit()
        raise
    finally:
        db.close()


def execute_impersonation_task(task_id: str):
    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.task_id == task_id).first()
        if not task:
            raise ValueError(f"任务不存在: {task_id}")

        extra_data = dict(task.extra or {})

        # 幂等性：任务已完成且已写入结果文件时，跳过重复执行
        if task.status == "completed" and extra_data.get("result_file_key"):
            logger.info("Skip already completed impersonation task_id=%s", task_id)
            return

        task.status = "processing"
        db.commit()

        official_key = extra_data.get("official_file_object_key")
        if not official_key:
            raise ValueError("缺少 official_file_object_key")
        official_file_content = _download_file_from_minio(official_key, MINIO_BUCKET)
        official_filename = official_key

        detection_source = extra_data.get("detectionSource")
        if detection_source == "upload":
            detection_key = extra_data.get("detection_file_object_key")
            if not detection_key:
                raise ValueError("upload 模式缺少 detection_file_object_key")
            detection_file_content = _download_file_from_minio(detection_key, MINIO_BUCKET)
            excel_content, statistics = phishing_predict_from_file(
                official_file_content,
                official_filename,
                detection_file_content,
                detection_key,
            )
        elif detection_source == "newDomain":
            detection_domains, missing_dates = _collect_daily_domains(extra_data.get("dateRange") or [])
            official_domains = read_official_domains_from_file(
                official_file_content,
                official_filename,
            )
            excel_content, statistics = phishing_predict_from_domains(
                official_domains,
                detection_domains,
            )
            extra_data["missing_dates"] = missing_dates
        else:
            raise ValueError(f"未知 detectionSource: {detection_source}")

        result_filename = f"result_{task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        result_key = _upload_file_content_to_minio(
            excel_content,
            result_filename,
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            bucket=RESULTS_BUCKET,
        )

        task.status = "completed"
        extra_data["result_file_key"] = result_key
        extra_data["result_bucket"] = RESULTS_BUCKET
        extra_data["result_filename"] = result_filename
        extra_data["statistics"] = statistics
        extra_data["completed_at"] = datetime.utcnow().isoformat()
        task.extra = extra_data
        db.commit()
    except Exception as exc:
        logger.exception("执行仿冒检测任务失败 %s: %s", task_id, exc)
        task = db.query(Task).filter(Task.task_id == task_id).first()
        if task:
            extra_data = dict(task.extra or {})
            task.status = "failed"
            extra_data["error"] = str(exc)
            task.extra = extra_data
            db.commit()
        raise
    finally:
        db.close()
