import io
import logging
import os
import sys
import uuid
import zipfile
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

import pandas as pd
from app.entities import Model, Task
from app.infra.minio_client import minio_client
from app.db.session import SessionLocal
from app.core.config import MINIO_BUCKET
from app.services.actor_matcher import match_domain_to_actors_v2_infra
from app.services.domain_infra_collector import collect_missing_domain_infra

# 添加models目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "models"))
from malicious_detection import predict_from_file, predict_from_domains
from dga_domain_detection import (
    predict_from_file as dga_predict_from_file,
    predict_from_domains as dga_predict_from_domains,
)
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

_ACTOR_CONFIDENCE_LABELS = {
    "high": "高",
    "medium": "中",
    "low": "低",
    "candidate": "候选",
    "none": "无",
}

_MATCH_STATUS_LABELS = {
    "suspected_match": "疑似关联",
    "candidate_only": "候选关联",
    "ambiguous": "多候选不确定",
    "no_match": "未关联",
    "match_failed": "关联失败",
}


def _clamp_progress(progress: int) -> int:
    return max(0, min(100, int(progress)))


def _set_task_progress(db, task: Task, extra_data: dict, progress: int, stage: str) -> None:
    extra_data["progress"] = _clamp_progress(progress)
    extra_data["progress_stage"] = stage
    extra_data["progress_updated_at"] = datetime.utcnow().isoformat()
    task.extra = dict(extra_data)
    db.commit()


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


def _extract_malicious_domains_from_excel(excel_content: bytes) -> List[str]:
    excel_file = io.BytesIO(excel_content)
    try:
        malicious_df = pd.read_excel(excel_file, sheet_name="恶意域名列表")
    except Exception:
        excel_file.seek(0)
        results_df = pd.read_excel(excel_file, sheet_name="预测结果")
        malicious_df = results_df[
            (results_df.get("预测标签") == 1)
            | (results_df.get("预测结果") == "恶意")
        ]

    if "域名" not in malicious_df.columns:
        return []
    domains = []
    seen = set()
    for value in malicious_df["域名"].dropna().tolist():
        domain = str(value).strip()
        domain_key = domain.lower()
        if domain and domain_key not in seen:
            seen.add(domain_key)
            domains.append(domain)
    return domains


def _run_domain_attribution(db, domains: List[str]) -> List[Dict[str, Any]]:
    attribution_results = []
    for domain in domains:
        try:
            match_result = match_domain_to_actors_v2_infra(domain, [], db=db)
        except Exception:
            logger.exception("恶意域名组织关联失败，已按空匹配继续 domain=%s", domain)
            match_result = {"domain_name": domain, "match_status": "match_failed"}

        attribution_results.append({
            "domain": domain,
            "match_status": match_result.get("match_status"),
            "match_status_label": _MATCH_STATUS_LABELS.get(
                str(match_result.get("match_status") or ""),
                match_result.get("match_status"),
            ),
            "matched_organization_id": match_result.get("matched_organization_id"),
            "matched_organization_name": match_result.get("matched_organization_name"),
            "actor_score": match_result.get("actor_score"),
            "actor_confidence": match_result.get("actor_confidence"),
            "actor_confidence_label": _ACTOR_CONFIDENCE_LABELS.get(
                str(match_result.get("actor_confidence") or ""),
                match_result.get("actor_confidence"),
            ),
            "scores": match_result.get("scores") or {},
            "reason_summary": match_result.get("reason_summary"),
            "evidence_json": match_result.get("evidence_json"),
            "top_candidates_json": match_result.get("top_candidates_json"),
        })
    return attribution_results


def _append_attribution_sheet(excel_content: bytes, attribution_results: List[Dict[str, Any]]) -> bytes:
    attribution_index = {
        str(item.get("domain") or "").strip().lower(): item
        for item in attribution_results
        if item.get("domain")
    }
    rows = []
    for item in attribution_results:
        rows.append({
            "域名": item.get("domain"),
            "匹配状态": item.get("match_status_label") or item.get("match_status"),
            "关联组织": item.get("matched_organization_name") or "",
            "组织ID": item.get("matched_organization_id") or "",
            "组织评分": item.get("actor_score") if item.get("actor_score") is not None else "",
            "组织置信度": item.get("actor_confidence_label") or item.get("actor_confidence") or "",
            "关联说明": item.get("reason_summary") or "",
        })

    def enrich_result_sheet(df: pd.DataFrame) -> pd.DataFrame:
        if "预测标签" in df.columns:
            df = df.drop(columns=["预测标签"])
        for column in ["关联组织", "组织置信度", "组织评分"]:
            if column not in df.columns:
                df[column] = ""

        if "域名" not in df.columns:
            return df

        for index, row in df.iterrows():
            match = attribution_index.get(str(row.get("域名") or "").strip().lower())
            if not match:
                continue
            df.at[index, "关联组织"] = match.get("matched_organization_name") or ""
            df.at[index, "组织置信度"] = match.get("actor_confidence_label") or match.get("actor_confidence") or ""
            df.at[index, "组织评分"] = match.get("actor_score") if match.get("actor_score") is not None else ""

        preferred_columns = ["域名", "预测结果"]
        if "二分类置信度" in df.columns:
            preferred_columns.append("二分类置信度")
        preferred_columns.extend(["关联组织", "组织置信度", "组织评分"])
        remaining_columns = [column for column in df.columns if column not in preferred_columns]
        return df[preferred_columns + remaining_columns]

    source = io.BytesIO(excel_content)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        for sheet_name in pd.ExcelFile(source).sheet_names:
            source.seek(0)
            sheet_df = pd.read_excel(source, sheet_name=sheet_name)
            if sheet_name in {"预测结果", "恶意域名列表"}:
                sheet_df = enrich_result_sheet(sheet_df)
            sheet_df.to_excel(writer, sheet_name=sheet_name, index=False)
        pd.DataFrame(rows).to_excel(writer, sheet_name="组织关联结果", index=False)
    return output.getvalue()


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
        _set_task_progress(db, task, extra_data, 10, "任务开始执行")

        data_source = extra_data.get("dataSource")
        model_path_to_use = model_record.model_path or None
        result_filename = f"result_{task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

        if data_source == "upload":
            _set_task_progress(db, task, extra_data, 20, "读取上传文件")
            file_key = extra_data.get("file_object_key")
            file_bucket = extra_data.get("file_bucket") or MINIO_BUCKET
            if not file_key:
                raise ValueError("上传文件任务缺少 file_object_key")
            file_content = _download_file_from_minio(file_key, file_bucket)
            original_filename = file_key
            _set_task_progress(db, task, extra_data, 45, "模型检测中")
            excel_content, statistics = predict_from_file(
                file_content,
                original_filename,
                model_path_to_use,
                malicious_only=False,
            )
        elif data_source == "newDomain":
            _set_task_progress(db, task, extra_data, 20, "收集新注册域名")
            date_range = extra_data.get("dateRange")
            if not date_range or len(date_range) < 2:
                raise ValueError("newDomain 任务缺少 dateRange")
            domains, missing_dates = _collect_daily_domains(date_range)
            _set_task_progress(db, task, extra_data, 40, "模型检测中")
            source_label = f"daily_{task_id}"
            excel_content, statistics = predict_from_domains(
                domains,
                source_label,
                model_path_to_use,
                malicious_only=True,
            )
            extra_data["daily_missing_dates"] = missing_dates
            extra_data["daily_domain_count"] = len(domains)
        elif data_source == "manualInput":
            _set_task_progress(db, task, extra_data, 20, "读取手动输入域名")
            domains = extra_data.get("manual_domains") or []
            if not isinstance(domains, list) or not domains:
                raise ValueError("manualInput 任务缺少有效域名")
            _set_task_progress(db, task, extra_data, 40, "模型检测中")
            source_label = f"manual_{task_id}"
            excel_content, statistics = predict_from_domains(
                domains,
                source_label,
                model_path_to_use,
                malicious_only=True,
            )
        else:
            raise ValueError(f"未知 dataSource: {data_source}")

        attribution_results = []
        if extra_data.get("withAttribution"):
            malicious_domains = _extract_malicious_domains_from_excel(excel_content)
            _set_task_progress(db, task, extra_data, 68, "归因前采集基础设施")
            infra_collection = collect_missing_domain_infra(db, malicious_domains)
            extra_data["attribution_infra_collection"] = infra_collection
            _set_task_progress(db, task, extra_data, 75, "组织关联分析中")
            attribution_results = _run_domain_attribution(db, malicious_domains)
            excel_content = _append_attribution_sheet(excel_content, attribution_results)
            extra_data["attribution_enabled"] = True
            extra_data["attribution_results"] = attribution_results
            extra_data["attribution_domain_count"] = len(malicious_domains)
            extra_data["attribution_completed_at"] = datetime.utcnow().isoformat()
        else:
            extra_data["attribution_enabled"] = False

        _set_task_progress(db, task, extra_data, 85, "上传结果文件")
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
        extra_data["progress"] = 100
        extra_data["progress_stage"] = "任务完成"
        extra_data["progress_updated_at"] = datetime.utcnow().isoformat()
        task.extra = extra_data
        db.commit()
    except Exception as exc:
        logger.exception("执行恶意检测任务失败 %s: %s", task_id, exc)
        task = db.query(Task).filter(Task.task_id == task_id).first()
        if task:
            extra_data = dict(task.extra or {})
            task.status = "failed"
            extra_data["progress"] = 0
            extra_data["progress_stage"] = "任务失败"
            extra_data["error"] = str(exc)
            task.extra = extra_data
            db.commit()
        raise
    finally:
        db.close()


def execute_dga_task(task_id: str):
    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.task_id == task_id).first()
        if not task:
            raise ValueError(f"任务不存在: {task_id}")
        model_record = db.query(Model).filter(Model.id == task.model_id).first()
        if not model_record:
            raise ValueError(f"模型不存在: {task.model_id}")

        extra_data = dict(task.extra or {})
        if task.status == "completed" and extra_data.get("result_file_key"):
            logger.info("Skip already completed dga task_id=%s", task_id)
            return

        task.status = "processing"
        _set_task_progress(db, task, extra_data, 10, "任务开始执行")

        data_source = extra_data.get("dataSource")
        model_path_to_use = model_record.model_path or None
        candidate_threshold = float(extra_data.get("candidate_threshold") or 0.99)
        result_filename = f"result_{task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

        if data_source == "upload":
            _set_task_progress(db, task, extra_data, 20, "读取上传文件")
            file_key = extra_data.get("file_object_key")
            file_bucket = extra_data.get("file_bucket") or MINIO_BUCKET
            if not file_key:
                raise ValueError("上传文件任务缺少 file_object_key")
            file_content = _download_file_from_minio(file_key, file_bucket)
            _set_task_progress(db, task, extra_data, 40, "DGA CNN模型评分中")
            excel_content, statistics, dga_meta = dga_predict_from_file(
                file_content,
                file_key,
                model_path_to_use,
                candidate_threshold=candidate_threshold,
            )
        elif data_source == "newDomain":
            _set_task_progress(db, task, extra_data, 20, "收集新注册域名")
            date_range = extra_data.get("dateRange")
            if not date_range or len(date_range) < 2:
                raise ValueError("newDomain 任务缺少 dateRange")
            domains, missing_dates = _collect_daily_domains(date_range)
            _set_task_progress(db, task, extra_data, 40, "DGA CNN模型评分中")
            excel_content, statistics, dga_meta = dga_predict_from_domains(
                domains,
                f"daily_{task_id}",
                model_path_to_use,
                candidate_threshold=candidate_threshold,
            )
            extra_data["daily_missing_dates"] = missing_dates
            extra_data["daily_domain_count"] = len(domains)
        elif data_source == "manualInput":
            _set_task_progress(db, task, extra_data, 20, "读取手动输入域名")
            domains = extra_data.get("manual_domains") or []
            if not isinstance(domains, list) or not domains:
                raise ValueError("manualInput 任务缺少有效域名")
            _set_task_progress(db, task, extra_data, 40, "DGA CNN模型评分中")
            excel_content, statistics, dga_meta = dga_predict_from_domains(
                domains,
                f"manual_{task_id}",
                model_path_to_use,
                candidate_threshold=candidate_threshold,
            )
        else:
            raise ValueError(f"未知 dataSource: {data_source}")

        extra_data["dga_detection"] = dga_meta
        _set_task_progress(db, task, extra_data, 85, "上传结果文件")
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
        extra_data["progress"] = 100
        extra_data["progress_stage"] = "任务完成"
        extra_data["progress_updated_at"] = datetime.utcnow().isoformat()
        task.extra = extra_data
        db.commit()
    except Exception as exc:
        logger.exception("执行DGA检测任务失败 %s: %s", task_id, exc)
        task = db.query(Task).filter(Task.task_id == task_id).first()
        if task:
            extra_data = dict(task.extra or {})
            task.status = "failed"
            extra_data["progress"] = 0
            extra_data["progress_stage"] = "任务失败"
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

        official_domains = extra_data.get("official_domains") or []
        official_key = extra_data.get("official_file_object_key")
        official_bucket = extra_data.get("official_file_bucket") or MINIO_BUCKET
        official_file_content = None
        official_filename = extra_data.get("official_file_filename") or official_key
        if not official_domains and official_key:
            official_file_content = _download_file_from_minio(official_key, official_bucket)
            official_domains = read_official_domains_from_file(
                official_file_content,
                official_filename,
            )
        if not official_domains:
            extra_data["official_domain_resolution_status"] = "pending"
            extra_data["official_domain_resolution_pending"] = True
            extra_data["official_domain_resolution_message"] = "官方域名检索能力尚未接入或未检索到官方域名"
            extra_data["progress"] = 0
            extra_data["progress_stage"] = "等待官方域名解析"
            task.status = "pending"
            task.extra = extra_data
            db.commit()
            logger.info("Impersonation task waits for official domain resolution task_id=%s", task_id)
            return

        task.status = "processing"
        _set_task_progress(db, task, extra_data, 10, "任务开始执行")

        detection_source = extra_data.get("detectionSource")
        similarity_threshold = extra_data.get("similarity_threshold")
        if similarity_threshold is not None:
            try:
                similarity_threshold = float(similarity_threshold)
            except (TypeError, ValueError):
                similarity_threshold = None
        if detection_source == "upload":
            _set_task_progress(db, task, extra_data, 20, "读取上传文件")
            detection_key = extra_data.get("detection_file_object_key")
            if not detection_key:
                raise ValueError("upload 模式缺少 detection_file_object_key")
            if official_file_content is None:
                raise ValueError("upload 模式缺少 official_file_object_key")
            detection_file_content = _download_file_from_minio(detection_key, MINIO_BUCKET)
            _set_task_progress(db, task, extra_data, 45, "仿冒域名检测中")
            excel_content, statistics = phishing_predict_from_file(
                official_file_content,
                official_filename,
                detection_file_content,
                detection_key,
                similarity_threshold=similarity_threshold,
            )
        elif detection_source == "newDomain":
            _set_task_progress(db, task, extra_data, 25, "收集新注册域名")
            detection_domains, missing_dates = _collect_daily_domains(extra_data.get("dateRange") or [])
            _set_task_progress(db, task, extra_data, 45, "仿冒域名检测中")
            excel_content, statistics = phishing_predict_from_domains(
                official_domains,
                detection_domains,
                similarity_threshold=similarity_threshold,
            )
            extra_data["missing_dates"] = missing_dates
        else:
            raise ValueError(f"未知 detectionSource: {detection_source}")

        _set_task_progress(db, task, extra_data, 85, "上传结果文件")
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
        extra_data["progress"] = 100
        extra_data["progress_stage"] = "任务完成"
        extra_data["progress_updated_at"] = datetime.utcnow().isoformat()
        task.extra = extra_data
        db.commit()
    except Exception as exc:
        logger.exception("执行仿冒检测任务失败 %s: %s", task_id, exc)
        task = db.query(Task).filter(Task.task_id == task_id).first()
        if task:
            extra_data = dict(task.extra or {})
            task.status = "failed"
            extra_data["progress"] = 0
            extra_data["progress_stage"] = "任务失败"
            extra_data["error"] = str(exc)
            task.extra = extra_data
            db.commit()
        raise
    finally:
        db.close()
