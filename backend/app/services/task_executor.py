import io
import logging
import os
import sys
import uuid
import zipfile
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from app.entities import Model, StoredFile, Task
from app.infra.minio_client import minio_client
from app.db.session import SessionLocal
from app.core.config import MINIO_BUCKET
from app.core.config import IMPERSONATION_FULL_WHITELIST_PATH
from app.services.actor_matcher import match_domain_to_actors_v2_infra
from app.services.apt_template_nrd_report import (
    build_apt_template_nrd_result_json,
    build_apt_template_nrd_result_payload,
    generate_apt_template_nrd_pdf_report,
)
from app.services.dga_report import (
    build_dga_result_json,
    build_dga_result_payload,
    generate_dga_pdf_report,
)
from app.services.domain_infra_collector import collect_missing_domain_infra
from app.services.domain_monitor import normalize_domain, register_monitor_targets
from app.services.focus_impersonation_report import (
    build_focus_impersonation_report_payload,
    generate_focus_impersonation_pdf_report,
    normalize_official_domain_rows,
)
from app.services.history_similarity_report import (
    build_history_similarity_result_json,
    build_history_similarity_result_payload,
    generate_history_similarity_pdf_report,
)
from app.services.unified_malicious_domain_report import (
    build_impersonation_result_payload,
    build_unified_malicious_domain_payload,
    build_unified_malicious_domain_result_json,
    generate_unified_malicious_domain_pdf_report,
)

# 添加models目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "models"))
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
if MODELS_DIR not in sys.path:
    sys.path.insert(0, MODELS_DIR)

from dga_domain_detection import (
    predict_from_file as dga_predict_from_file,
    predict_from_domains as dga_predict_from_domains,
)
from impersonation_detector import (
    predict_from_file as phishing_predict_from_file,
    predict_from_file_with_report as phishing_predict_from_file_with_report,
    predict_from_domains as phishing_predict_from_domains,
    predict_from_domains_with_report as phishing_predict_from_domains_with_report,
    read_detection_domains_from_file,
    read_official_domains_from_file,
)
from history_similarity_detection import (
    alert_rows_to_score_records as history_alert_rows_to_score_records,
    predict_from_file as history_similarity_predict_from_file,
    predict_from_domains as history_similarity_predict_from_domains,
)
from apt_template_nrd_matcher import (
    alert_rows_to_score_records as apt_template_nrd_alert_rows_to_score_records,
    predict_from_file as apt_template_nrd_predict_from_file,
    predict_from_domains as apt_template_nrd_predict_from_domains,
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


def _domain_from_monitor_record(record: Mapping[str, Any]) -> Optional[str]:
    for key in (
        "域名",
        "domain",
        "domain_name",
        "normalized_domain",
        "仿冒域名",
        "钓鱼域名",
        "phishing_domain",
        "candidate_domain",
        "DGA域名",
        "历史相似域名",
        "模板化APT域名",
        "apt_template_nrd_domain",
    ):
        domain = normalize_domain(record.get(key))
        if domain:
            return domain
    return None


def _domains_from_monitor_records(records: Sequence[Mapping[str, Any]]) -> List[str]:
    domains: List[str] = []
    seen = set()
    for record in records or []:
        if not isinstance(record, Mapping):
            continue
        domain = _domain_from_monitor_record(record)
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains


def _register_detection_monitor_targets(
    db,
    *,
    task: Task,
    records: Sequence[Mapping[str, Any]],
    extra_data: dict,
    completed_at: datetime,
) -> None:
    if task.created_by is None:
        return
    domains = _domains_from_monitor_records(records)
    if not domains:
        return

    try:
        monitor_summary = register_monitor_targets(
            db,
            user_id=int(task.created_by),
            domains=domains,
            source_type="detection_task",
            task_id=task.task_id,
            task_type=task.task_type,
            model_id=task.model_id,
            risk_records=records,
            detected_at=completed_at,
        )
        extra_data["domain_monitor_summary"] = monitor_summary
        task.extra = dict(extra_data)
        db.commit()
        logger.info(
            "检测任务恶意域名已注册持续追踪 task_id=%s task_type=%s summary=%s",
            task.task_id,
            task.task_type,
            monitor_summary,
        )
    except Exception:
        db.rollback()
        logger.exception("注册检测任务恶意域名持续追踪失败 task_id=%s", task.task_id)


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


UNIFIED_DOMAIN_MODULES = ("impersonation", "dga", "history_similarity", "apt_template_nrd")


def _get_active_model_record(db, category: str, model_id: Any = None) -> Model:
    query = db.query(Model).filter(Model.model_category == category, Model.status == "active")
    if model_id:
        try:
            query = query.filter(Model.id == int(model_id))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{category} 模型ID无效: {model_id}") from exc
    model_record = query.order_by(Model.model_type.asc(), Model.id.asc()).first()
    if not model_record:
        raise ValueError(f"未找到可用的 {category} 检测模型")
    return model_record


def _load_unified_input_domains(extra_data: dict) -> tuple[list[str], dict[str, Any]]:
    data_source = extra_data.get("dataSource")
    if data_source == "upload":
        file_key = extra_data.get("file_object_key")
        file_bucket = extra_data.get("file_bucket") or MINIO_BUCKET
        filename = extra_data.get("file_filename") or file_key or "uploaded_domains"
        if not file_key:
            raise ValueError("上传文件任务缺少 file_object_key")
        file_content = _download_file_from_minio(file_key, file_bucket)
        domains = read_detection_domains_from_file(file_content, filename)
        return domains, {"input_file": filename}

    if data_source == "newDomain":
        date_range = extra_data.get("dateRange")
        if not date_range or len(date_range) < 2:
            raise ValueError("newDomain 任务缺少 dateRange")
        domains, missing_dates = _collect_daily_domains(date_range)
        return domains, {
            "daily_missing_dates": missing_dates,
            "daily_domain_count": len(domains),
        }

    if data_source == "manualInput":
        domains = extra_data.get("manual_domains") or []
        if not isinstance(domains, list) or not domains:
            raise ValueError("manualInput 任务缺少有效域名")
        return domains, {"manual_domain_count": len(domains)}

    raise ValueError(f"未知 dataSource: {data_source}")


def _load_unified_official_domains(extra_data: dict):
    official_domains = extra_data.get("official_domains") or []
    if official_domains:
        return official_domains

    official_key = extra_data.get("official_file_object_key")
    if official_key:
        official_bucket = extra_data.get("official_file_bucket") or MINIO_BUCKET
        official_filename = extra_data.get("official_file_filename") or official_key
        official_content = _download_file_from_minio(official_key, official_bucket)
        return read_official_domains_from_file(official_content, official_filename)

    official_file_path = (
        extra_data.get("official_file_path")
        or os.path.abspath(os.path.expanduser(IMPERSONATION_FULL_WHITELIST_PATH))
    )
    official_file_path = os.path.abspath(os.path.expanduser(str(official_file_path)))
    if not os.path.isfile(official_file_path):
        raise ValueError(f"系统全量白名单不存在: {official_file_path}")
    with open(official_file_path, "rb") as file_handle:
        official_content = file_handle.read()
    return read_official_domains_from_file(
        official_content,
        extra_data.get("official_file_filename") or os.path.basename(official_file_path),
    )


def _serialize_official_domains_for_extra(official_domains) -> list[dict[str, Any]]:
    return normalize_official_domain_rows(official_domains)


def execute_malicious_task(task_id: str):
    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.task_id == task_id).first()
        if not task:
            raise ValueError(f"任务不存在: {task_id}")

        extra_data = dict(task.extra or {})
        if task.status == "completed" and extra_data.get("result_file_key"):
            logger.info("Skip already completed malicious task_id=%s", task_id)
            return

        task.status = "processing"
        _set_task_progress(db, task, extra_data, 10, "任务开始执行")

        data_source = extra_data.get("dataSource")

        _set_task_progress(db, task, extra_data, 18, "读取待检测域名")
        domains, input_meta = _load_unified_input_domains(extra_data)
        extra_data.update(input_meta)
        if not domains:
            raise ValueError("没有可检测的有效域名")

        module_model_ids = extra_data.get("module_model_ids") or {}
        model_records = {
            module: _get_active_model_record(db, module, module_model_ids.get(module))
            for module in UNIFIED_DOMAIN_MODULES
        }
        model_names = {module: str(record.name or "") for module, record in model_records.items()}
        model_paths = {module: record.model_path or None for module, record in model_records.items()}
        extra_data["module_model_ids"] = {module: record.id for module, record in model_records.items()}
        extra_data["module_model_names"] = model_names
        extra_data["unified_detection"] = True

        _set_task_progress(db, task, extra_data, 28, "仿冒域名检测中")
        official_domains = _load_unified_official_domains(extra_data)
        impersonation_excel, impersonation_statistics = phishing_predict_from_domains(
            official_domains,
            domains,
            similarity_threshold=None,
        )
        impersonation_payload = build_impersonation_result_payload(
            impersonation_excel,
            task_id=task_id,
            statistics=impersonation_statistics,
            official_domain_count=len(official_domains),
        )
        extra_data["official_domain_count"] = len(official_domains)

        candidate_threshold = float(extra_data.get("candidate_threshold") or 0.90)
        _set_task_progress(db, task, extra_data, 42, "DGA域名检测中")
        dga_excel, dga_statistics, dga_meta = dga_predict_from_domains(
            domains,
            f"unified_{task_id}",
            model_paths["dga"],
            candidate_threshold=candidate_threshold,
        )
        dga_payload = build_dga_result_payload(
            dga_excel,
            task_id=task_id,
            dga_meta=dga_meta,
        )

        min_score = float(extra_data.get("min_score") or 0.65)
        top_k = int(extra_data.get("top_k") or 10)
        _set_task_progress(db, task, extra_data, 56, "历史APT域名相似性检测中")
        history_excel, history_statistics, history_meta, history_alert_rows = history_similarity_predict_from_domains(
            domains,
            f"unified_{task_id}",
            model_paths["history_similarity"],
            min_score=min_score,
            top_k=top_k,
            suspicious_only=False,
        )
        history_payload = build_history_similarity_result_payload(
            history_excel,
            task_id=task_id,
            history_meta=history_meta,
        )
        extra_data["history_similarity_alert_rows"] = history_alert_rows_to_score_records(history_alert_rows)

        score_threshold = float(extra_data.get("score_threshold") or 0.90)
        _set_task_progress(db, task, extra_data, 70, "模板化APT域名检测中")
        apt_excel, apt_statistics, apt_meta, apt_alert_rows = apt_template_nrd_predict_from_domains(
            domains,
            f"unified_{task_id}",
            model_paths["apt_template_nrd"],
            score_threshold=score_threshold,
            high_risk_only=False,
        )
        apt_payload = build_apt_template_nrd_result_payload(
            apt_excel,
            task_id=task_id,
            apt_meta=apt_meta,
        )
        extra_data["apt_template_nrd_alert_rows"] = apt_template_nrd_alert_rows_to_score_records(apt_alert_rows)

        module_payloads = {
            "impersonation": impersonation_payload,
            "dga": dga_payload,
            "history_similarity": history_payload,
            "apt_template_nrd": apt_payload,
        }
        thresholds = {
            "dga_candidate_threshold": candidate_threshold,
            "history_min_score": min_score,
            "history_top_k": top_k,
            "apt_template_score_threshold": score_threshold,
        }
        result_payload = build_unified_malicious_domain_payload(
            task_id=task_id,
            input_domains=domains,
            data_source=str(data_source or ""),
            module_payloads=module_payloads,
            model_names=model_names,
            thresholds=thresholds,
            date_range=extra_data.get("dateRange") if isinstance(extra_data.get("dateRange"), list) else None,
            generated_at=datetime.utcnow(),
        )
        result_payload["module_statistics"] = {
            "impersonation": impersonation_statistics,
            "dga": dga_statistics,
            "history_similarity": history_statistics,
            "apt_template_nrd": apt_statistics,
        }

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_filename = f"malicious_domain_detection_report_{task_id}_{timestamp}.pdf"
        result_data_filename = f"malicious_domain_detection_result_{task_id}_{timestamp}.json"
        report_content = generate_unified_malicious_domain_pdf_report(result_payload)

        _set_task_progress(db, task, extra_data, 88, "上传统一检测报告")
        result_key = _upload_file_content_to_minio(
            report_content,
            result_filename,
            content_type="application/pdf",
            bucket=RESULTS_BUCKET,
        )
        result_payload["result_file_key"] = result_key
        result_payload["result_filename"] = result_filename
        result_data_content = build_unified_malicious_domain_result_json(result_payload)
        result_data_key = _upload_file_content_to_minio(
            result_data_content,
            result_data_filename,
            content_type="application/json",
            bucket=RESULTS_BUCKET,
        )

        report_file_record = StoredFile(
            bucket=RESULTS_BUCKET,
            object_key=result_key,
            filename=result_filename,
            content_type="application/pdf",
            size=len(report_content),
            uploaded_by=str(task.created_by) if task.created_by is not None else None,
            metadata_json={
                "source": "unified_malicious_domain_pdf_report",
                "task_id": task_id,
                "task_type": "malicious",
            },
        )
        db.add(report_file_record)
        db.flush()
        result_data_file_record = StoredFile(
            bucket=RESULTS_BUCKET,
            object_key=result_data_key,
            filename=result_data_filename,
            content_type="application/json",
            size=len(result_data_content),
            uploaded_by=str(task.created_by) if task.created_by is not None else None,
            metadata_json={
                "source": "unified_malicious_domain_result_json",
                "task_id": task_id,
                "task_type": "malicious",
            },
        )
        db.add(result_data_file_record)
        db.flush()

        task.status = "completed"
        extra_data["result_file_id"] = report_file_record.id
        extra_data["result_file_key"] = result_key
        extra_data["result_bucket"] = RESULTS_BUCKET
        extra_data["result_filename"] = result_filename
        extra_data["result_content_type"] = "application/pdf"
        extra_data["result_data_file_id"] = result_data_file_record.id
        extra_data["result_data_file_key"] = result_data_key
        extra_data["result_data_bucket"] = RESULTS_BUCKET
        extra_data["result_data_filename"] = result_data_filename
        extra_data["result_data_content_type"] = "application/json"
        extra_data["statistics"] = result_payload.get("statistics") or {}
        extra_data["label_counts"] = result_payload.get("label_counts") or {}
        extra_data["overlap_counts"] = result_payload.get("overlap_counts") or {}
        completed_at = datetime.utcnow()
        extra_data["completed_at"] = completed_at.isoformat()
        extra_data["progress"] = 100
        extra_data["progress_stage"] = "任务完成"
        extra_data["progress_updated_at"] = datetime.utcnow().isoformat()
        task.extra = extra_data
        db.commit()
        _register_detection_monitor_targets(
            db,
            task=task,
            records=result_payload.get("unified_malicious_domains") or result_payload.get("malicious_domains") or [],
            extra_data=extra_data,
            completed_at=completed_at,
        )
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
        candidate_threshold_value = extra_data.get("candidate_threshold")
        candidate_threshold = (
            0.90 if candidate_threshold_value is None else float(candidate_threshold_value)
        )
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_filename = f"dga_domain_detection_report_{task_id}_{timestamp}.pdf"
        result_data_filename = f"dga_domain_detection_result_{task_id}_{timestamp}.json"

        if data_source == "upload":
            _set_task_progress(db, task, extra_data, 20, "读取上传文件")
            file_key = extra_data.get("file_object_key")
            file_bucket = extra_data.get("file_bucket") or MINIO_BUCKET
            if not file_key:
                raise ValueError("上传文件任务缺少 file_object_key")
            file_content = _download_file_from_minio(file_key, file_bucket)
            _set_task_progress(db, task, extra_data, 40, "DGA主模型评分与家族识别中")
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
            _set_task_progress(db, task, extra_data, 40, "DGA主模型评分与家族识别中")
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
            _set_task_progress(db, task, extra_data, 40, "DGA主模型评分与家族识别中")
            excel_content, statistics, dga_meta = dga_predict_from_domains(
                domains,
                f"manual_{task_id}",
                model_path_to_use,
                candidate_threshold=candidate_threshold,
            )
        else:
            raise ValueError(f"未知 dataSource: {data_source}")

        extra_data["dga_detection"] = dga_meta
        result_payload = build_dga_result_payload(
            excel_content,
            task_id=task_id,
            dga_meta=dga_meta,
        )
        report_content = generate_dga_pdf_report(
            result_payload,
            task_id=task_id,
            model_name=str(model_record.name or ""),
            data_source=str(data_source or ""),
            candidate_threshold=candidate_threshold,
            date_range=extra_data.get("dateRange") if isinstance(extra_data.get("dateRange"), list) else None,
            generated_at=datetime.utcnow(),
        )

        _set_task_progress(db, task, extra_data, 85, "上传PDF报告")
        result_key = _upload_file_content_to_minio(
            report_content,
            result_filename,
            content_type="application/pdf",
            bucket=RESULTS_BUCKET,
        )
        result_payload["result_file_key"] = result_key
        result_payload["result_filename"] = result_filename
        result_data_content = build_dga_result_json(result_payload)
        result_data_key = _upload_file_content_to_minio(
            result_data_content,
            result_data_filename,
            content_type="application/json",
            bucket=RESULTS_BUCKET,
        )

        report_file_record = StoredFile(
            bucket=RESULTS_BUCKET,
            object_key=result_key,
            filename=result_filename,
            content_type="application/pdf",
            size=len(report_content),
            uploaded_by=str(task.created_by) if task.created_by is not None else None,
            metadata_json={
                "source": "dga_pdf_report",
                "task_id": task_id,
                "task_type": "dga",
            },
        )
        db.add(report_file_record)
        db.flush()
        result_data_file_record = StoredFile(
            bucket=RESULTS_BUCKET,
            object_key=result_data_key,
            filename=result_data_filename,
            content_type="application/json",
            size=len(result_data_content),
            uploaded_by=str(task.created_by) if task.created_by is not None else None,
            metadata_json={
                "source": "dga_result_json",
                "task_id": task_id,
                "task_type": "dga",
            },
        )
        db.add(result_data_file_record)
        db.flush()

        task.status = "completed"
        extra_data["result_file_id"] = report_file_record.id
        extra_data["result_file_key"] = result_key
        extra_data["result_bucket"] = RESULTS_BUCKET
        extra_data["result_filename"] = result_filename
        extra_data["result_content_type"] = "application/pdf"
        extra_data["result_data_file_id"] = result_data_file_record.id
        extra_data["result_data_file_key"] = result_data_key
        extra_data["result_data_bucket"] = RESULTS_BUCKET
        extra_data["result_data_filename"] = result_data_filename
        extra_data["result_data_content_type"] = "application/json"
        extra_data["statistics"] = statistics
        completed_at = datetime.utcnow()
        extra_data["completed_at"] = completed_at.isoformat()
        extra_data["progress"] = 100
        extra_data["progress_stage"] = "任务完成"
        extra_data["progress_updated_at"] = datetime.utcnow().isoformat()
        task.extra = extra_data
        db.commit()
        _register_detection_monitor_targets(
            db,
            task=task,
            records=result_payload.get("dga_domains") or [],
            extra_data=extra_data,
            completed_at=completed_at,
        )
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


def execute_history_similarity_task(task_id: str):
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
            logger.info("Skip already completed history similarity task_id=%s", task_id)
            return

        task.status = "processing"
        _set_task_progress(db, task, extra_data, 10, "任务开始执行")

        data_source = extra_data.get("dataSource")
        model_path_to_use = model_record.model_path or None
        min_score = float(extra_data.get("min_score") or 0.65)
        top_k = int(extra_data.get("top_k") or 10)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_filename = f"history_apt_similarity_report_{task_id}_{timestamp}.pdf"
        result_data_filename = f"history_apt_similarity_result_{task_id}_{timestamp}.json"

        if data_source == "upload":
            _set_task_progress(db, task, extra_data, 20, "读取上传文件")
            file_key = extra_data.get("file_object_key")
            file_bucket = extra_data.get("file_bucket") or MINIO_BUCKET
            if not file_key:
                raise ValueError("上传文件任务缺少 file_object_key")
            file_content = _download_file_from_minio(file_key, file_bucket)
            _set_task_progress(db, task, extra_data, 45, "历史APT域名相似性匹配中")
            excel_content, statistics, history_meta, alert_rows = history_similarity_predict_from_file(
                file_content,
                file_key,
                model_path_to_use,
                min_score=min_score,
                top_k=top_k,
                suspicious_only=False,
            )
        elif data_source == "newDomain":
            _set_task_progress(db, task, extra_data, 20, "收集新注册域名")
            date_range = extra_data.get("dateRange")
            if not date_range or len(date_range) < 2:
                raise ValueError("newDomain 任务缺少 dateRange")
            domains, missing_dates = _collect_daily_domains(date_range)
            _set_task_progress(db, task, extra_data, 45, "历史APT域名相似性匹配中")
            excel_content, statistics, history_meta, alert_rows = history_similarity_predict_from_domains(
                domains,
                f"daily_{task_id}",
                model_path_to_use,
                min_score=min_score,
                top_k=top_k,
                suspicious_only=True,
            )
            extra_data["daily_missing_dates"] = missing_dates
            extra_data["daily_domain_count"] = len(domains)
        elif data_source == "manualInput":
            _set_task_progress(db, task, extra_data, 20, "读取手动输入域名")
            domains = extra_data.get("manual_domains") or []
            if not isinstance(domains, list) or not domains:
                raise ValueError("manualInput 任务缺少有效域名")
            _set_task_progress(db, task, extra_data, 45, "历史APT域名相似性匹配中")
            excel_content, statistics, history_meta, alert_rows = history_similarity_predict_from_domains(
                domains,
                f"manual_{task_id}",
                model_path_to_use,
                min_score=min_score,
                top_k=top_k,
                suspicious_only=False,
            )
        else:
            raise ValueError(f"未知 dataSource: {data_source}")

        extra_data["history_similarity_detection"] = history_meta
        extra_data["history_similarity_alert_rows"] = history_alert_rows_to_score_records(alert_rows)

        result_payload = build_history_similarity_result_payload(
            excel_content,
            task_id=task_id,
            history_meta=history_meta,
        )
        report_content = generate_history_similarity_pdf_report(
            result_payload,
            task_id=task_id,
            model_name=(
                str(model_record.name or "")
                .replace("历史高度相似检测", "历史APT域名相似性检测")
                .replace("历史高度相似", "历史APT域名相似")
            ),
            data_source=str(data_source or ""),
            min_score=min_score,
            top_k=top_k,
            date_range=extra_data.get("dateRange") if isinstance(extra_data.get("dateRange"), list) else None,
            generated_at=datetime.utcnow(),
        )

        _set_task_progress(db, task, extra_data, 85, "上传PDF报告")
        result_key = _upload_file_content_to_minio(
            report_content,
            result_filename,
            content_type="application/pdf",
            bucket=RESULTS_BUCKET,
        )
        result_payload["result_file_key"] = result_key
        result_payload["result_filename"] = result_filename
        result_data_content = build_history_similarity_result_json(result_payload)
        result_data_key = _upload_file_content_to_minio(
            result_data_content,
            result_data_filename,
            content_type="application/json",
            bucket=RESULTS_BUCKET,
        )

        report_file_record = StoredFile(
            bucket=RESULTS_BUCKET,
            object_key=result_key,
            filename=result_filename,
            content_type="application/pdf",
            size=len(report_content),
            uploaded_by=str(task.created_by) if task.created_by is not None else None,
            metadata_json={
                "source": "history_similarity_pdf_report",
                "task_id": task_id,
                "task_type": "history_similarity",
            },
        )
        db.add(report_file_record)
        db.flush()
        result_data_file_record = StoredFile(
            bucket=RESULTS_BUCKET,
            object_key=result_data_key,
            filename=result_data_filename,
            content_type="application/json",
            size=len(result_data_content),
            uploaded_by=str(task.created_by) if task.created_by is not None else None,
            metadata_json={
                "source": "history_similarity_result_json",
                "task_id": task_id,
                "task_type": "history_similarity",
            },
        )
        db.add(result_data_file_record)
        db.flush()

        task.status = "completed"
        extra_data["result_file_id"] = report_file_record.id
        extra_data["result_file_key"] = result_key
        extra_data["result_bucket"] = RESULTS_BUCKET
        extra_data["result_filename"] = result_filename
        extra_data["result_content_type"] = "application/pdf"
        extra_data["result_data_file_id"] = result_data_file_record.id
        extra_data["result_data_file_key"] = result_data_key
        extra_data["result_data_bucket"] = RESULTS_BUCKET
        extra_data["result_data_filename"] = result_data_filename
        extra_data["result_data_content_type"] = "application/json"
        extra_data["statistics"] = statistics
        completed_at = datetime.utcnow()
        extra_data["completed_at"] = completed_at.isoformat()
        extra_data["progress"] = 100
        extra_data["progress_stage"] = "任务完成"
        extra_data["progress_updated_at"] = datetime.utcnow().isoformat()
        task.extra = extra_data
        db.commit()
        _register_detection_monitor_targets(
            db,
            task=task,
            records=result_payload.get("history_similarity_domains") or [],
            extra_data=extra_data,
            completed_at=completed_at,
        )
    except Exception as exc:
        logger.exception("执行历史APT域名相似性检测任务失败 %s: %s", task_id, exc)
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


def execute_apt_template_nrd_task(task_id: str):
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
            logger.info("Skip already completed apt template nrd task_id=%s", task_id)
            return

        task.status = "processing"
        _set_task_progress(db, task, extra_data, 10, "任务开始执行")

        data_source = extra_data.get("dataSource")
        model_path_to_use = model_record.model_path or None
        score_threshold = float(extra_data.get("score_threshold") or 0.90)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_filename = f"apt_template_nrd_report_{task_id}_{timestamp}.pdf"
        result_data_filename = f"apt_template_nrd_result_{task_id}_{timestamp}.json"

        if data_source == "upload":
            _set_task_progress(db, task, extra_data, 20, "读取上传文件")
            file_key = extra_data.get("file_object_key")
            file_bucket = extra_data.get("file_bucket") or MINIO_BUCKET
            if not file_key:
                raise ValueError("上传文件任务缺少 file_object_key")
            file_content = _download_file_from_minio(file_key, file_bucket)
            _set_task_progress(db, task, extra_data, 45, "模板化APT域名匹配中")
            excel_content, statistics, apt_meta, alert_rows = apt_template_nrd_predict_from_file(
                file_content,
                file_key,
                model_path_to_use,
                score_threshold=score_threshold,
                high_risk_only=False,
            )
        elif data_source == "newDomain":
            _set_task_progress(db, task, extra_data, 20, "收集新注册域名")
            date_range = extra_data.get("dateRange")
            if not date_range or len(date_range) < 2:
                raise ValueError("newDomain 任务缺少 dateRange")
            domains, missing_dates = _collect_daily_domains(date_range)
            _set_task_progress(db, task, extra_data, 45, "模板化APT域名匹配中")
            excel_content, statistics, apt_meta, alert_rows = apt_template_nrd_predict_from_domains(
                domains,
                f"daily_{task_id}",
                model_path_to_use,
                score_threshold=score_threshold,
                high_risk_only=False,
            )
            extra_data["daily_missing_dates"] = missing_dates
            extra_data["daily_domain_count"] = len(domains)
        elif data_source == "manualInput":
            _set_task_progress(db, task, extra_data, 20, "读取手动输入域名")
            domains = extra_data.get("manual_domains") or []
            if not isinstance(domains, list) or not domains:
                raise ValueError("manualInput 任务缺少有效域名")
            _set_task_progress(db, task, extra_data, 45, "模板化APT域名匹配中")
            excel_content, statistics, apt_meta, alert_rows = apt_template_nrd_predict_from_domains(
                domains,
                f"manual_{task_id}",
                model_path_to_use,
                score_threshold=score_threshold,
                high_risk_only=False,
            )
        else:
            raise ValueError(f"未知 dataSource: {data_source}")

        extra_data["apt_template_nrd_detection"] = apt_meta
        extra_data["apt_template_nrd_alert_rows"] = apt_template_nrd_alert_rows_to_score_records(alert_rows)

        result_payload = build_apt_template_nrd_result_payload(
            excel_content,
            task_id=task_id,
            apt_meta=apt_meta,
        )
        report_content = generate_apt_template_nrd_pdf_report(
            result_payload,
            task_id=task_id,
            model_name=str(model_record.name or "").replace("APT模板新注册域名检测", "模板化APT域名检测"),
            data_source=str(data_source or ""),
            score_threshold=score_threshold,
            date_range=extra_data.get("dateRange") if isinstance(extra_data.get("dateRange"), list) else None,
            generated_at=datetime.utcnow(),
        )

        _set_task_progress(db, task, extra_data, 85, "上传PDF报告")
        result_key = _upload_file_content_to_minio(
            report_content,
            result_filename,
            content_type="application/pdf",
            bucket=RESULTS_BUCKET,
        )
        result_payload["result_file_key"] = result_key
        result_payload["result_filename"] = result_filename
        result_data_content = build_apt_template_nrd_result_json(result_payload)
        result_data_key = _upload_file_content_to_minio(
            result_data_content,
            result_data_filename,
            content_type="application/json",
            bucket=RESULTS_BUCKET,
        )

        report_file_record = StoredFile(
            bucket=RESULTS_BUCKET,
            object_key=result_key,
            filename=result_filename,
            content_type="application/pdf",
            size=len(report_content),
            uploaded_by=str(task.created_by) if task.created_by is not None else None,
            metadata_json={
                "source": "apt_template_nrd_pdf_report",
                "task_id": task_id,
                "task_type": "apt_template_nrd",
            },
        )
        db.add(report_file_record)
        db.flush()
        result_data_file_record = StoredFile(
            bucket=RESULTS_BUCKET,
            object_key=result_data_key,
            filename=result_data_filename,
            content_type="application/json",
            size=len(result_data_content),
            uploaded_by=str(task.created_by) if task.created_by is not None else None,
            metadata_json={
                "source": "apt_template_nrd_result_json",
                "task_id": task_id,
                "task_type": "apt_template_nrd",
            },
        )
        db.add(result_data_file_record)
        db.flush()

        task.status = "completed"
        extra_data["result_file_id"] = report_file_record.id
        extra_data["result_file_key"] = result_key
        extra_data["result_bucket"] = RESULTS_BUCKET
        extra_data["result_filename"] = result_filename
        extra_data["result_content_type"] = "application/pdf"
        extra_data["result_data_file_id"] = result_data_file_record.id
        extra_data["result_data_file_key"] = result_data_key
        extra_data["result_data_bucket"] = RESULTS_BUCKET
        extra_data["result_data_filename"] = result_data_filename
        extra_data["result_data_content_type"] = "application/json"
        extra_data["statistics"] = statistics
        completed_at = datetime.utcnow()
        extra_data["completed_at"] = completed_at.isoformat()
        extra_data["progress"] = 100
        extra_data["progress_stage"] = "任务完成"
        extra_data["progress_updated_at"] = datetime.utcnow().isoformat()
        task.extra = extra_data
        db.commit()
        _register_detection_monitor_targets(
            db,
            task=task,
            records=result_payload.get("apt_template_nrd_domains") or [],
            extra_data=extra_data,
            completed_at=completed_at,
        )
    except Exception as exc:
        logger.exception("执行模板化APT域名检测任务失败 %s: %s", task_id, exc)
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
        official_file_path = extra_data.get("official_file_path")
        official_file_content = None
        official_filename = extra_data.get("official_file_filename") or official_key
        loaded_from_full_whitelist_path = False
        if not official_domains and official_key:
            official_file_content = _download_file_from_minio(official_key, official_bucket)
            official_domains = read_official_domains_from_file(
                official_file_content,
                official_filename,
            )
        elif not official_domains and official_file_path:
            official_file_path = os.path.abspath(os.path.expanduser(str(official_file_path)))
            if not os.path.isfile(official_file_path):
                raise ValueError(f"系统全量白名单不存在: {official_file_path}")
            with open(official_file_path, "rb") as file_handle:
                official_file_content = file_handle.read()
            official_filename = official_filename or os.path.basename(official_file_path)
            official_domains = read_official_domains_from_file(
                official_file_content,
                official_filename,
            )
            loaded_from_full_whitelist_path = True

        if official_domains:
            if not loaded_from_full_whitelist_path:
                extra_data["official_domains"] = _serialize_official_domains_for_extra(official_domains)
            extra_data["official_domain_count"] = len(official_domains)
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
            detection_bucket = extra_data.get("detection_file_bucket") or MINIO_BUCKET
            detection_filename = extra_data.get("detection_file_filename") or detection_key
            detection_file_content = _download_file_from_minio(detection_key, detection_bucket)
            _set_task_progress(db, task, extra_data, 45, "仿冒域名检测中")
            if official_file_content is not None:
                excel_content, statistics, word_report_content = phishing_predict_from_file_with_report(
                    official_file_content,
                    official_filename,
                    detection_file_content,
                    detection_filename,
                    similarity_threshold=similarity_threshold,
                )
            else:
                detection_domains = read_detection_domains_from_file(
                    detection_file_content,
                    detection_filename,
                )
                excel_content, statistics, word_report_content = phishing_predict_from_domains_with_report(
                    official_domains,
                    detection_domains,
                    similarity_threshold=similarity_threshold,
                )
        elif detection_source == "newDomain":
            _set_task_progress(db, task, extra_data, 25, "收集新注册域名")
            detection_domains, missing_dates = _collect_daily_domains(extra_data.get("dateRange") or [])
            _set_task_progress(db, task, extra_data, 45, "仿冒域名检测中")
            excel_content, statistics, word_report_content = phishing_predict_from_domains_with_report(
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
        word_report_filename = f"prediction_report_{task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
        word_report_key = _upload_file_content_to_minio(
            word_report_content,
            word_report_filename,
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            bucket=RESULTS_BUCKET,
        )
        if extra_data.get("focus_impersonation_detection"):
            focus_payload = build_focus_impersonation_report_payload(
                excel_content,
                task_id=task_id,
                query_name=str(extra_data.get("focus_query_name") or extra_data.get("queryName") or ""),
                official_domains=extra_data.get("official_domains") or official_domains,
                statistics=statistics,
                date_range=extra_data.get("dateRange") if isinstance(extra_data.get("dateRange"), list) else None,
                generated_at=datetime.utcnow(),
            )
            focus_report_content = generate_focus_impersonation_pdf_report(focus_payload)
            focus_report_filename = f"focus_impersonation_report_{task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            focus_report_key = _upload_file_content_to_minio(
                focus_report_content,
                focus_report_filename,
                content_type="application/pdf",
                bucket=RESULTS_BUCKET,
            )
        else:
            focus_report_key = None
            focus_report_filename = None

        impersonation_monitor_payload = build_impersonation_result_payload(
            excel_content,
            task_id=task_id,
            statistics=statistics,
            official_domain_count=len(official_domains),
        )

        task.status = "completed"
        extra_data["result_file_key"] = result_key
        extra_data["result_bucket"] = RESULTS_BUCKET
        extra_data["result_filename"] = result_filename
        extra_data["word_report_file_key"] = word_report_key
        extra_data["word_report_bucket"] = RESULTS_BUCKET
        extra_data["word_report_filename"] = word_report_filename
        if focus_report_key:
            extra_data["focus_report_file_key"] = focus_report_key
            extra_data["focus_report_bucket"] = RESULTS_BUCKET
            extra_data["focus_report_filename"] = focus_report_filename
            extra_data["focus_report_content_type"] = "application/pdf"
        extra_data["statistics"] = statistics
        completed_at = datetime.utcnow()
        extra_data["completed_at"] = completed_at.isoformat()
        extra_data["progress"] = 100
        extra_data["progress_stage"] = "任务完成"
        extra_data["progress_updated_at"] = datetime.utcnow().isoformat()
        task.extra = extra_data
        db.commit()
        _register_detection_monitor_targets(
            db,
            task=task,
            records=impersonation_monitor_payload.get("phishing_domains") or [],
            extra_data=extra_data,
            completed_at=completed_at,
        )
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
