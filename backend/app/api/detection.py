from fastapi import APIRouter, File, Form, UploadFile, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse, StreamingResponse
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional, List, Tuple
import logging
import json
import math
import uuid
import io
import sys
import os
import ipaddress
import re
import zipfile
from urllib.parse import quote, urlsplit
import pandas as pd
from sqlalchemy import text
# 添加models目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'models'))
# 从 entities / main / db / core 导入必要的依赖
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
if MODELS_DIR not in sys.path:
    sys.path.insert(0, MODELS_DIR)

from app.entities import Task, Model, StoredFile
from app.infra.minio_client import minio_client
from app.db.session import SessionLocal, engine
from app.core.config import (
    IMPERSONATION_FULL_WHITELIST_PATH,
    IMPERSONATION_MODEL_NAME,
    MINIO_BUCKET,
)
from app.services.official_domain_resolver import (
    OfficialDomainResolverConfigError,
    OfficialDomainResolutionError,
    resolve_official_domains,
)
from app.services.task_dispatcher import (
    dispatch_apt_template_nrd_task,
    dispatch_dga_task,
    dispatch_history_similarity_task,
    dispatch_impersonation_task,
    dispatch_malicious_task,
)
from malicious_detection import predict_from_domains as malicious_predict_from_domains
from dga_domain_detection import predict_from_domains as dga_predict_from_domains
from history_similarity_detection import (
    predict_from_domains as history_similarity_predict_from_domains,
)
from impersonation_detector import (
    predict_from_domains as impersonation_predict_from_domains,
    read_official_domains_from_file,
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
    "malicious": "恶意域名检测",
    "impersonation": "仿冒域名检测",
    "malicious_ip": "恶意IP检测",
    "dga": "DGA域名检测",
    "history_similarity": "历史高度相似检测",
    "apt_template_nrd": "模板化APT域名检测",
}
DATA_SOURCE_LABEL_MAP = {
    "upload": "上传文件",
    "newDomain": "新注册域名",
    "manualInput": "手动输入域名",
}
STATUS_PROGRESS_MAP = {
    "pending": 0,
    "processing": 10,
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


def _get_impersonation_model_record(db):
    """
    仿冒检测是内置算法任务，历史环境中模型名可能不是 IMPERSONATION_MODEL_NAME。
    优先尊重配置名；配置名不存在时回退到启用的仿冒模型。
    """
    configured_name = (IMPERSONATION_MODEL_NAME or "").strip()
    if configured_name:
        model_record = (
            db.query(Model)
            .filter(
                Model.name == configured_name,
                Model.model_category == "impersonation",
                Model.status == "active",
            )
            .first()
        )
        if model_record:
            return model_record

    return (
        db.query(Model)
        .filter(
            Model.model_category == "impersonation",
            Model.status == "active",
        )
        .order_by(Model.model_type.asc(), Model.id.asc())
        .first()
    )


def _get_dga_model_record(db):
    return (
        db.query(Model)
        .filter(
            Model.model_category == "dga",
            Model.status == "active",
        )
        .order_by(Model.model_type.asc(), Model.id.asc())
        .first()
    )


def _get_history_similarity_model_record(db):
    return (
        db.query(Model)
        .filter(
            Model.model_category == "history_similarity",
            Model.status == "active",
        )
        .order_by(Model.model_type.asc(), Model.id.asc())
        .first()
    )


def _get_apt_template_nrd_model_record(db):
    return (
        db.query(Model)
        .filter(
            Model.model_category == "apt_template_nrd",
            Model.status == "active",
        )
        .order_by(Model.model_type.asc(), Model.id.asc())
        .first()
    )


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


def _build_attribution_index(extra_data: dict) -> dict:
    results = extra_data.get("attribution_results") or []
    if not isinstance(results, list):
        return {}
    indexed = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or item.get("domain_name") or "").strip().lower()
        if domain:
            indexed[domain] = item
    return indexed


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


def _actor_confidence_label(value) -> str:
    raw = str(value or "").strip()
    return _ACTOR_CONFIDENCE_LABELS.get(raw, raw)


def _match_status_label(value) -> str:
    raw = str(value or "").strip()
    return _MATCH_STATUS_LABELS.get(raw, raw)


def _json_safe_value(value):
    if value is None:
        return None
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else ""
    if isinstance(value, dict):
        return {key: _json_safe_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe_value(item) for item in value]
    if hasattr(value, "item"):
        try:
            return _json_safe_value(value.item())
        except Exception:
            pass
    return value


def _attach_attribution_fields(rows: list, attribution_index: dict) -> list:
    if not attribution_index:
        return rows
    enriched_rows = []
    for row in rows:
        item = dict(row)
        domain = str(item.get("域名") or item.get("domain") or "").strip().lower()
        match = attribution_index.get(domain)
        if match:
            item["关联组织"] = match.get("matched_organization_name") or ""
            item["组织置信度"] = match.get("actor_confidence_label") or _actor_confidence_label(match.get("actor_confidence")) or ""
            item["组织评分"] = match.get("actor_score")
            item["关联状态"] = match.get("match_status_label") or _match_status_label(match.get("match_status")) or ""
            item["关联说明"] = match.get("reason_summary") or ""
            item["组织关联详情"] = match
        enriched_rows.append(item)
    return enriched_rows


def _history_similarity_cell_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and not math.isfinite(value):
        return ""
    text_value = str(value).strip()
    return "" if text_value.lower() in {"nan", "none", "nat"} else text_value


def _history_similarity_row_domain(row: dict) -> str:
    for key in ("域名", "规范化域名", "domain", "domain_name"):
        domain = _history_similarity_cell_text(row.get(key)).lower()
        if domain:
            return domain
    return ""


def _history_similarity_row_score(row: dict) -> float:
    try:
        score = float(row.get("综合相似度") or 0)
        return score if math.isfinite(score) else 0.0
    except (TypeError, ValueError):
        return 0.0


def _dedupe_history_similarity_rows(rows: list) -> list:
    best_by_domain = {}
    ordered_domains = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        domain = _history_similarity_row_domain(row)
        if not domain:
            continue
        current = best_by_domain.get(domain)
        if current is None:
            ordered_domains.append(domain)
            best_by_domain[domain] = row
            continue
        if _history_similarity_row_score(row) > _history_similarity_row_score(current):
            best_by_domain[domain] = row
    return [best_by_domain[domain] for domain in ordered_domains]


def _normalize_official_domain_rows(official_domains) -> list:
    rows = []
    seen = set()
    for item in official_domains or []:
        company = ""
        domain = ""
        confidence = ""
        source = ""
        reason = ""
        if isinstance(item, dict):
            company = item.get("单位名称") or item.get("公司名称") or item.get("company") or item.get("organization") or ""
            domain = item.get("官方域名") or item.get("域名") or item.get("domain") or item.get("目标域名") or item.get("target_domain") or ""
            confidence = item.get("confidence") if item.get("confidence") is not None else ""
            source = item.get("source") or ""
            reason = item.get("reason") or item.get("evidence") or ""
        elif isinstance(item, (list, tuple)):
            if len(item) >= 2:
                company, domain = item[0], item[1]
            elif len(item) == 1:
                domain = item[0]
        else:
            domain = item
        domain = str(domain or "").strip().lower()
        if not domain or domain in seen:
            continue
        seen.add(domain)
        rows.append({
            "单位名称": str(company or "").strip(),
            "官方域名": domain,
            "置信度": confidence,
            "来源": source,
            "说明": str(reason or "").strip(),
        })
    return rows


def _replace_impersonation_official_sheet(file_bytes: bytes, official_domain_rows: list) -> bytes:
    import pandas as pd

    excel_input = io.BytesIO(file_bytes)
    excel_file = pd.ExcelFile(excel_input)
    output = io.BytesIO()
    official_df = pd.DataFrame(
        official_domain_rows,
        columns=["单位名称", "官方域名", "置信度", "来源", "说明"],
    )
    official_written = False
    kept_count = 0
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        for sheet_name in excel_file.sheet_names:
            if sheet_name in {"钓鱼域名列表", "官方域名列表"}:
                continue
            excel_input.seek(0)
            sheet_df = pd.read_excel(excel_input, sheet_name=sheet_name)
            sheet_df.to_excel(writer, sheet_name=sheet_name, index=False)
            kept_count += 1
            if kept_count == 2:
                official_df.to_excel(writer, sheet_name="官方域名列表", index=False)
                official_written = True
        if not official_written:
            official_df.to_excel(writer, sheet_name="官方域名列表", index=False)
    return output.getvalue()


def _dedupe_history_similarity_sheet(file_bytes: bytes) -> bytes:
    import pandas as pd

    excel_input = io.BytesIO(file_bytes)
    excel_file = pd.ExcelFile(excel_input)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        for sheet_name in excel_file.sheet_names:
            excel_input.seek(0)
            sheet_df = pd.read_excel(excel_input, sheet_name=sheet_name)
            if sheet_name == "历史相似域名列表":
                deduped_rows = _dedupe_history_similarity_rows(sheet_df.to_dict("records"))
                sheet_df = pd.DataFrame(deduped_rows, columns=list(sheet_df.columns))
            sheet_df.to_excel(writer, sheet_name=sheet_name, index=False)
    return output.getvalue()


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


def _normalize_impersonation_result_rows(rows):
    normalized = []
    for row in rows or []:
        item = dict(row)
        impersonation_domain = item.get("仿冒域名") or item.get("钓鱼域名") or item.get("candidate_domain")
        official_domain = item.get("官方域名") or item.get("目标域名") or item.get("target_domain")
        organization = (
            item.get("官方域名单位名称")
            or item.get("公司名称")
            or item.get("单位名称")
            or item.get("target_name")
        )
        unit_type = item.get("单位类型") or item.get("matched_target_type")
        if impersonation_domain:
            item["仿冒域名"] = impersonation_domain
            item.setdefault("钓鱼域名", impersonation_domain)
        if official_domain:
            item["官方域名"] = official_domain
            item.setdefault("目标域名", official_domain)
        if organization:
            item["官方域名单位名称"] = organization
            item.setdefault("公司名称", organization)
        if unit_type:
            item["单位类型"] = unit_type
        normalized.append(item)
    return normalized


def _parse_date_string(date_str: str) -> datetime.date:
    if not isinstance(date_str, str):
        raise ValueError("date string required")
    cleaned = date_str.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    return datetime.fromisoformat(cleaned).date()


# 新注册域名日期范围：开始日期从 2024-09-01 起，最多可选往后一个月
_MIN_START_DATE = datetime(2024, 9, 1).date()
_MAX_MANUAL_DOMAIN_COUNT = 1000
_MAX_MANUAL_INPUT_LENGTH = 20000
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


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


def _inspect_daily_domain_availability(start_date, end_date) -> dict:
    available_dates = []
    missing_dates = []
    invalid_dates = []
    total_domain_count = 0
    current = start_date

    while current <= end_date:
        date_key = current.isoformat()
        month_folder = os.path.join(DAILY_DATA_DIR, current.strftime("%Y-%m"))
        zip_name = f"{current.strftime('%Y-%m-%d')}-domain.zip"
        zip_path = os.path.join(month_folder, zip_name)

        if not os.path.exists(zip_path):
            missing_dates.append(date_key)
            current += timedelta(days=1)
            continue

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                if "dailyupdate.txt" not in zf.namelist():
                    invalid_dates.append(date_key)
                    current += timedelta(days=1)
                    continue
                with zf.open("dailyupdate.txt") as file_handle:
                    content = file_handle.read().decode("utf-8", errors="ignore")
                    domain_count = sum(1 for line in content.splitlines() if line.strip())
                    if domain_count > 0:
                        available_dates.append(date_key)
                        total_domain_count += domain_count
                    else:
                        invalid_dates.append(date_key)
        except Exception:
            logger.exception("检查每日域名数据失败: %s", zip_path)
            invalid_dates.append(date_key)
        current += timedelta(days=1)

    return {
        "available": len(available_dates) > 0,
        "availableDates": available_dates,
        "missingDates": missing_dates,
        "invalidDates": invalid_dates,
        "domainCount": total_domain_count,
    }


def _extract_hostname_from_input(raw_value: str) -> Optional[str]:
    candidate = raw_value.strip().strip("\"'`<>[](){}")
    if not candidate:
        return None

    parsed_host = None
    try:
        if "://" in candidate:
            parsed_host = urlsplit(candidate).hostname
        elif candidate.startswith("//"):
            parsed_host = urlsplit(f"http:{candidate}").hostname
        elif any(separator in candidate for separator in ["/", "?", "#"]):
            parsed_host = urlsplit(f"http://{candidate}").hostname
        elif ":" in candidate:
            parsed_host = urlsplit(f"//{candidate}").hostname
        else:
            parsed_host = candidate
    except ValueError:
        return None

    if not parsed_host:
        return None

    return parsed_host.strip().strip(".").lower()


def _normalize_domain(hostname: str) -> Optional[str]:
    if not hostname:
        return None
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass

    try:
        ascii_domain = hostname.encode("idna").decode("ascii").lower().strip(".")
    except UnicodeError:
        return None

    if len(ascii_domain) > 253 or "." not in ascii_domain:
        return None

    labels = ascii_domain.split(".")
    if any(not label or not _DOMAIN_LABEL_RE.match(label) for label in labels):
        return None
    return ascii_domain


def _parse_manual_domains(manual_domains: str) -> Tuple[List[str], dict]:
    if not manual_domains or not manual_domains.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="manualDomains is required when dataSource is 'manualInput'"
        )
    if len(manual_domains) > _MAX_MANUAL_INPUT_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"manualDomains length exceeds {_MAX_MANUAL_INPUT_LENGTH} characters"
        )

    raw_items = [
        item.strip()
        for item in re.split(r"[\s,，;；]+", manual_domains)
        if item.strip()
    ]
    domains: List[str] = []
    seen = set()
    invalid_count = 0
    duplicate_count = 0

    for item in raw_items:
        hostname = _extract_hostname_from_input(item)
        normalized = _normalize_domain(hostname or "")
        if not normalized:
            invalid_count += 1
            continue
        if normalized in seen:
            duplicate_count += 1
            continue
        seen.add(normalized)
        domains.append(normalized)

    if not domains:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="未解析到有效域名，请检查输入内容"
        )
    if len(domains) > _MAX_MANUAL_DOMAIN_COUNT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"手动输入域名最多支持 {_MAX_MANUAL_DOMAIN_COUNT} 条"
        )

    return domains, {
        "raw_count": len(raw_items),
        "valid_count": len(domains),
        "invalid_count": invalid_count,
        "duplicate_count": duplicate_count,
    }


def _parse_similarity_threshold(use_custom_threshold: str, threshold: Optional[str]) -> Tuple[Optional[float], dict]:
    use_custom = str(use_custom_threshold or "false").strip().lower() == "true"
    if not use_custom:
        return None, {"use_custom_threshold": False, "threshold_percent": None}
    if threshold is None or str(threshold).strip() == "":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="threshold is required when useCustomThreshold is true",
        )
    try:
        threshold_percent = float(str(threshold).strip())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="threshold must be a number between 0 and 100",
        ) from exc
    if threshold_percent < 0 or threshold_percent > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="threshold must be between 0 and 100",
        )
    return threshold_percent / 100, {
        "use_custom_threshold": True,
        "threshold_percent": threshold_percent,
    }


def _parse_history_similarity_min_score(value: Optional[str]) -> Tuple[float, int]:
    if value is None or str(value).strip() == "":
        return 0.55, 55
    try:
        threshold_percent = float(str(value).strip())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="minScore must be a number between 0 and 100",
        ) from exc
    if threshold_percent < 0 or threshold_percent > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="minScore must be between 0 and 100",
        )
    return threshold_percent / 100, int(round(threshold_percent))


DOMAIN_DETECTION_PREVIEW_CATEGORIES = {
    "impersonation",
    "dga",
    "history_similarity",
}


def _resolve_full_whitelist_path() -> str:
    return os.path.abspath(os.path.expanduser(IMPERSONATION_FULL_WHITELIST_PATH))


def _load_full_whitelist_domains():
    whitelist_path = _resolve_full_whitelist_path()
    if not os.path.isfile(whitelist_path):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"系统全量白名单不存在：{whitelist_path}",
        )
    with open(whitelist_path, "rb") as file_handle:
        file_content = file_handle.read()
    return read_official_domains_from_file(
        file_content,
        os.path.basename(whitelist_path) or "full_whitelist.csv",
    )


def _resolve_model_record(
    db,
    model: Optional[str],
    model_category: str,
    created_by_user_id: Optional[int] = None,
):
    model_record = None
    if model:
        try:
            model_record = db.query(Model).filter(Model.id == int(model)).first()
        except ValueError:
            model_record = db.query(Model).filter(Model.name == model).first()

    if model_record is None:
        if model_category == "impersonation":
            model_record = _get_impersonation_model_record(db)
        elif model_category == "dga":
            model_record = _get_dga_model_record(db)
        elif model_category == "history_similarity":
            model_record = _get_history_similarity_model_record(db)

    if not model_record or model_record.model_category != model_category:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No active {model_category} model configured",
        )

    if created_by_user_id is not None:
        with engine.connect() as conn:
            user_model_result = conn.execute(
                text("""
                    SELECT um.id
                    FROM user_models um
                    WHERE um.user_id = :user_id
                      AND um.model_id = :model_id
                      AND um.is_active = 1
                """),
                {"user_id": created_by_user_id, "model_id": model_record.id},
            ).first()
        if not user_model_result:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"您没有权限使用模型 {model_record.name}",
            )

    return model_record


def _excel_statistics_dict(excel_file: io.BytesIO) -> dict:
    statistics_dict = {}
    excel_file.seek(0)
    stats_df = pd.read_excel(excel_file, sheet_name="统计信息")
    for _, row in stats_df.iterrows():
        statistics_dict[row["统计项"]] = row["数值"]
    return statistics_dict


def _excel_rows(excel_file: io.BytesIO, sheet_name: str) -> list:
    try:
        excel_file.seek(0)
        return pd.read_excel(excel_file, sheet_name=sheet_name).to_dict("records")
    except Exception:
        return []


def _parse_detection_preview_payload(
    *,
    task_type: str,
    excel_content: bytes,
    statistics: dict,
    extra_data: Optional[dict] = None,
) -> dict:
    extra_data = extra_data or {}
    excel_file = io.BytesIO(excel_content)
    statistics_dict = _excel_statistics_dict(excel_file)
    if not statistics_dict:
        statistics_dict = statistics or {}

    if task_type == "impersonation":
        results_list = _normalize_impersonation_result_rows(
            _excel_rows(excel_file, "检测结果")
        )
        phishing_list = _excel_rows(excel_file, "仿冒域名列表")
        if not phishing_list:
            phishing_list = _excel_rows(excel_file, "钓鱼域名列表")
        if phishing_list:
            phishing_list = _normalize_impersonation_result_rows(phishing_list)
        else:
            phishing_list = [
                row for row in results_list
                if row.get("仿冒域名") or row.get("钓鱼域名")
            ]
        return _json_safe_value({
            "ok": True,
            "task_type": task_type,
            "statistics": statistics_dict,
            "results": results_list,
            "phishing_domains": phishing_list,
            "total_count": len(results_list),
            "phishing_count": len(phishing_list),
            "official_domain_count": extra_data.get("official_domain_count"),
        })

    if task_type == "dga":
        results_list = _excel_rows(excel_file, "预测结果")
        dga_list = _excel_rows(excel_file, "DGA域名列表")
        if not dga_list:
            dga_list = [
                row for row in results_list
                if row.get("预测标签") == 1 or row.get("预测结果") == "DGA-like"
            ]
        return _json_safe_value({
            "ok": True,
            "task_type": task_type,
            "statistics": statistics_dict,
            "results": results_list,
            "dga_domains": dga_list,
            "total_count": len(results_list),
            "dga_count": len(dga_list),
            "dga_detection": extra_data.get("dga_detection") or {},
        })

    if task_type == "history_similarity":
        results_list = _excel_rows(excel_file, "预测结果")
        history_list = _dedupe_history_similarity_rows(
            _excel_rows(excel_file, "历史相似域名列表")
        )
        if not history_list:
            history_list = _dedupe_history_similarity_rows([
                row for row in results_list
                if row.get("预测标签") == 1 or row.get("预测结果") == "历史高度相似"
            ])
        return _json_safe_value({
            "ok": True,
            "task_type": task_type,
            "statistics": statistics_dict,
            "results": results_list,
            "history_similarity_domains": history_list,
            "total_count": len(results_list),
            "history_similarity_count": len(history_list),
            "history_similarity_detection": extra_data.get("history_similarity_detection") or {},
        })

    results_list = _excel_rows(excel_file, "预测结果")
    malicious_list = _excel_rows(excel_file, "恶意域名列表")
    if not malicious_list:
        malicious_list = [
            row for row in results_list
            if row.get("预测标签") == 1 or row.get("预测结果") == "恶意"
        ]
    return _json_safe_value({
        "ok": True,
        "task_type": task_type,
        "statistics": statistics_dict,
        "results": results_list,
        "malicious_domains": malicious_list,
        "total_count": len(results_list),
        "malicious_count": len(malicious_list),
    })


def _parse_apt_template_nrd_score_threshold(value: Optional[str]) -> Tuple[float, int]:
    if value is None or str(value).strip() == "":
        return 0.90, 90
    try:
        threshold_percent = float(str(value).strip())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scoreThreshold must be a number between 0 and 100",
        ) from exc
    if threshold_percent < 0 or threshold_percent > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scoreThreshold must be between 0 and 100",
        )
    return threshold_percent / 100, int(round(threshold_percent))


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


def _parse_detection_date_range_payload(detection_date_range: str) -> List[str]:
    try:
        date_range_parsed = json.loads(detection_date_range)
    except json.JSONDecodeError as exc:
        logger.error("日期范围JSON解析失败: %s, 原始数据: %s", exc, detection_date_range)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid detectionDateRange format",
        ) from exc
    if not isinstance(date_range_parsed, list) or len(date_range_parsed) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="detectionDateRange must be a JSON array with start and end date",
        )
    try:
        start_date = _parse_date_string(str(date_range_parsed[0]))
        end_date = _parse_date_string(str(date_range_parsed[1]))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid detectionDateRange date value",
        ) from exc
    if start_date > end_date:
        start_date, end_date = end_date, start_date
        date_range_parsed = [start_date.isoformat(), end_date.isoformat()]
    _validate_new_domain_date_range(start_date, end_date)
    return [str(date_range_parsed[0]), str(date_range_parsed[1])]


@router.get("/api/new-domain-data/availability")
async def check_new_domain_data_availability(
    startDate: str = Query(...),
    endDate: str = Query(...),
):
    """检查所选日期范围内是否存在可用的新注册域名数据。"""
    try:
        start_date = _parse_date_string(str(startDate))
        end_date = _parse_date_string(str(endDate))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="日期格式无效",
        ) from exc
    if start_date > end_date:
        start_date, end_date = end_date, start_date
    _validate_new_domain_date_range(start_date, end_date)
    availability = _inspect_daily_domain_availability(start_date, end_date)
    message = (
        f"所选范围内有 {len(availability['availableDates'])} 天可用数据"
        if availability["available"]
        else "所选日期范围内暂无可用的新注册域名数据"
    )
    return {
        "ok": True,
        "startDate": start_date.isoformat(),
        "endDate": end_date.isoformat(),
        "message": message,
        **availability,
    }


@router.post("/api/manual-domain-detection/preview")
async def preview_manual_domain_detection(
    request: Request,
    model: str = Form(...),
    modelCategory: str = Form(...),
    manualDomains: str = Form(...),
):
    """手动输入域名的同步检测预览，不创建任务、不触发预警推送。"""
    model_category = str(modelCategory or "").strip()
    if model_category not in DOMAIN_DETECTION_PREVIEW_CATEGORIES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="modelCategory must be impersonation, dga or history_similarity",
        )

    domains, manual_stats = _parse_manual_domains(manualDomains or "")
    created_by_user_id = _extract_user_id(request)
    db = SessionLocal()
    try:
        model_record = _resolve_model_record(
            db,
            model,
            model_category,
            created_by_user_id,
        )
    finally:
        db.close()

    model_path_to_use = model_record.model_path or None
    extra_data = {
        "manual_domain_stats": manual_stats,
        "model": {
            "id": model_record.id,
            "name": model_record.name,
            "category": model_category,
        },
    }

    try:
        if model_category == "impersonation":
            official_domains = _load_full_whitelist_domains()
            excel_content, statistics = impersonation_predict_from_domains(
                official_domains,
                domains,
                similarity_threshold=None,
            )
            extra_data["official_domain_count"] = len(official_domains)
            payload = _parse_detection_preview_payload(
                task_type="impersonation",
                excel_content=excel_content,
                statistics=statistics,
                extra_data=extra_data,
            )
        elif model_category == "dga":
            excel_content, statistics, dga_meta = dga_predict_from_domains(
                domains,
                "manual_preview",
                model_path_to_use,
                candidate_threshold=0.90,
            )
            extra_data["dga_detection"] = dga_meta
            payload = _parse_detection_preview_payload(
                task_type="dga",
                excel_content=excel_content,
                statistics=statistics,
                extra_data=extra_data,
            )
        else:
            excel_content, statistics, history_meta, _alert_rows = history_similarity_predict_from_domains(
                domains,
                "manual_preview",
                model_path_to_use,
                min_score=0.55,
                top_k=10,
                suspicious_only=False,
            )
            extra_data["history_similarity_detection"] = history_meta
            payload = _parse_detection_preview_payload(
                task_type="history_similarity",
                excel_content=excel_content,
                statistics=statistics,
                extra_data=extra_data,
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("手动输入域名同步检测失败: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"手动检测失败: {str(exc)}",
        ) from exc

    payload["mode"] = "manualPreview"
    payload["manual_domain_stats"] = manual_stats
    payload["model"] = extra_data["model"]
    return JSONResponse(status_code=status.HTTP_200_OK, content=payload)


@router.post("/api/impersonation-unified-tasks")
async def create_impersonation_unified_task(
    request: Request,
    model: Optional[str] = Form(None),
    dataSource: str = Form(...),
    file: Optional[UploadFile] = File(None),
    dateRange: Optional[str] = Form(None),
):
    """统一页面使用的仿冒检测任务：默认加载系统全量白名单。"""
    try:
        created_by_user_id: Optional[int] = _extract_user_id(request)
        uploaded_by_header = request.headers.get("X-User-Name") or request.headers.get("X-User")

        if dataSource not in ["upload", "newDomain"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="dataSource must be 'upload' or 'newDomain'",
            )
        if dataSource == "upload" and file is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="file is required")
        if dataSource == "newDomain" and (not dateRange or dateRange.strip() == ""):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="dateRange is required")

        whitelist_path = _resolve_full_whitelist_path()
        if not os.path.isfile(whitelist_path):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"系统全量白名单不存在：{whitelist_path}",
            )

        date_range_parsed = None
        if dataSource == "newDomain":
            date_range_parsed = _parse_detection_date_range_payload(dateRange or "")
            start_date = _parse_date_string(date_range_parsed[0])
            end_date = _parse_date_string(date_range_parsed[1])
            availability = _inspect_daily_domain_availability(start_date, end_date)
            if not availability["available"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "message": "所选日期范围内暂无可用的新注册域名数据，请重新选择日期",
                        **availability,
                    },
                )

        uploaded_file_meta = None
        if file is not None:
            file_ext = file.filename.split(".")[-1].lower() if file.filename else ""
            allowed_extensions = ["csv", "txt", "xlsx"]
            if file_ext not in allowed_extensions:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File type not allowed. Only {', '.join(allowed_extensions)} are supported",
                )
            file_content = await file.read()
            file_size = len(file_content)
            max_size = 5 * 1024 * 1024
            if file_size > max_size:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File size exceeds maximum allowed size of {max_size / 1024 / 1024}MB",
                )
            file_key = upload_file_content_to_minio(
                file_content,
                file.filename or "unknown",
                file.content_type,
            )
            uploaded_file_meta = {
                "bucket": MINIO_BUCKET,
                "object_key": file_key,
                "filename": file.filename or "unknown",
                "content_type": file.content_type,
                "size": file_size,
            }

        db = SessionLocal()
        try:
            model_record = _resolve_model_record(
                db,
                model,
                "impersonation",
                created_by_user_id,
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
                        "source": "impersonation_detection",
                        "role": "detection_domains",
                        "original_filename": uploaded_file_meta["filename"],
                    },
                )
                db.add(file_record)
                db.flush()

            extra_data = {
                "detectionSource": dataSource,
                "dateRange": date_range_parsed,
                "official_file_path": whitelist_path,
                "official_file_filename": os.path.basename(whitelist_path) or "full_whitelist.csv",
                "official_domain_resolution_status": "full_whitelist",
                "official_domain_resolution_pending": False,
                "official_domain_resolution_method": "full_whitelist",
                "official_domain_resolution_message": "已使用系统全量官方白名单",
                "threshold_policy": "adaptive",
                "similarity_threshold": None,
                "threshold_percent": None,
            }
            if uploaded_file_meta:
                extra_data["detection_file_bucket"] = uploaded_file_meta["bucket"]
                extra_data["detection_file_object_key"] = uploaded_file_meta["object_key"]
                extra_data["detection_file_filename"] = uploaded_file_meta["filename"]
                extra_data["detection_file_id"] = file_record.id if file_record else None

            task_id = f"IMP{int(datetime.utcnow().timestamp())}{uuid.uuid4().hex[:6]}"
            task = Task(
                task_id=task_id,
                task_type="impersonation",
                model_id=model_record.id,
                file_id=file_record.id if file_record else None,
                extra=extra_data,
                status="pending",
                created_by=created_by_user_id,
            )
            db.add(task)
            db.commit()
            db.refresh(task)

            try:
                dispatch_impersonation_task(task.task_id)
            except Exception as exc:
                logger.exception("enqueue unified impersonation task failed: %s", exc)
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
                content={"ok": True, "task_id": task.task_id, "status": "pending"},
            )
        except HTTPException:
            db.rollback()
            raise
        except Exception as exc:
            db.rollback()
            logger.exception("Failed to create unified impersonation task: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create impersonation task",
            ) from exc
        finally:
            db.close()
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error in create_impersonation_unified_task: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        ) from exc


@router.post("/api/tasks")
async def create_detection_task(
    request: Request,
    model: str = Form(...),
    dataSource: str = Form(...),
    withAttribution: str = Form("false"),
    file: Optional[UploadFile] = File(None),
    dateRange: Optional[str] = Form(None),
    manualDomains: Optional[str] = Form(None),
):
    """
    创建恶意性检测任务
    
    参数:
    - model: 检测模型ID
    - dataSource: 数据来源 ('upload'、'newDomain' 或 'manualInput')
    - withAttribution: 是否包含归因分析 ('true' 或 'false')
    - file: 上传的文件（当 dataSource 为 'upload' 时必填）
    - dateRange: 日期范围JSON字符串（当 dataSource 为 'newDomain' 时必填）
    - manualDomains: 用户手动输入的域名或 URL（当 dataSource 为 'manualInput' 时必填）
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
        if dataSource not in ["upload", "newDomain", "manualInput"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="dataSource must be 'upload', 'newDomain' or 'manualInput'"
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
        date_range_parsed = None
        if dataSource == "newDomain":
            date_range_parsed = _parse_detection_date_range_payload(dateRange or "")
            start_date = _parse_date_string(date_range_parsed[0])
            end_date = _parse_date_string(date_range_parsed[1])
            availability = _inspect_daily_domain_availability(start_date, end_date)
            if not availability["available"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "message": "所选日期范围内暂无可用的新注册域名数据，请重新选择日期",
                        **availability,
                    },
                )

        manual_domain_list = None
        manual_domain_stats = None
        if dataSource == "manualInput":
            manual_domain_list, manual_domain_stats = _parse_manual_domains(manualDomains or "")
        
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
        if dateRange:
            try:
                date_range_parsed = date_range_parsed or json.loads(dateRange)
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
        if manual_domain_list is not None:
            extra_data["manual_domains"] = manual_domain_list
            extra_data["manual_domain_stats"] = manual_domain_stats
        
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


@router.post("/api/dga-tasks")
async def create_dga_task(
    request: Request,
    model: Optional[str] = Form(None),
    dataSource: str = Form(...),
    file: Optional[UploadFile] = File(None),
    dateRange: Optional[str] = Form(None),
    manualDomains: Optional[str] = Form(None),
):
    """创建DGA域名检测任务。"""
    try:
        created_by_user_id: Optional[int] = _extract_user_id(request)
        uploaded_by_header = request.headers.get("X-User-Name") or request.headers.get("X-User")

        if dataSource not in ["upload", "newDomain", "manualInput"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="dataSource must be 'upload', 'newDomain' or 'manualInput'",
            )
        if dataSource == "upload" and file is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="file is required")
        if dataSource == "newDomain" and (not dateRange or dateRange.strip() == ""):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="dateRange is required")

        date_range_parsed = None
        if dataSource == "newDomain":
            date_range_parsed = _parse_detection_date_range_payload(dateRange or "")
            start_date = _parse_date_string(date_range_parsed[0])
            end_date = _parse_date_string(date_range_parsed[1])
            availability = _inspect_daily_domain_availability(start_date, end_date)
            if not availability["available"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "message": "所选日期范围内暂无可用的新注册域名数据，请重新选择日期",
                        **availability,
                    },
                )

        manual_domain_list = None
        manual_domain_stats = None
        if dataSource == "manualInput":
            manual_domain_list, manual_domain_stats = _parse_manual_domains(manualDomains or "")

        uploaded_file_meta = None
        if file is not None:
            file_ext = file.filename.split(".")[-1].lower() if file.filename else ""
            allowed_extensions = ["csv", "txt", "xlsx"]
            if file_ext not in allowed_extensions:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File type not allowed. Only {', '.join(allowed_extensions)} are supported",
                )
            file_content = await file.read()
            file_size = len(file_content)
            max_size = 5 * 1024 * 1024
            if file_size > max_size:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File size exceeds maximum allowed size of {max_size / 1024 / 1024}MB",
                )
            file_key = upload_file_content_to_minio(
                file_content,
                file.filename or "unknown",
                file.content_type,
            )
            uploaded_file_meta = {
                "bucket": MINIO_BUCKET,
                "object_key": file_key,
                "filename": file.filename or "unknown",
                "content_type": file.content_type,
                "size": file_size,
            }

        extra_data = {
            "dataSource": dataSource,
            "dateRange": date_range_parsed,
            "candidate_threshold": 0.90,
        }
        if uploaded_file_meta:
            extra_data["file_bucket"] = uploaded_file_meta["bucket"]
            extra_data["file_object_key"] = uploaded_file_meta["object_key"]
        if manual_domain_list is not None:
            extra_data["manual_domains"] = manual_domain_list
            extra_data["manual_domain_stats"] = manual_domain_stats

        task_id = f"DGA{int(datetime.utcnow().timestamp())}{uuid.uuid4().hex[:6]}"
        db = SessionLocal()
        try:
            model_record = None
            if model:
                try:
                    model_record = db.query(Model).filter(Model.id == int(model)).first()
                except ValueError:
                    model_record = db.query(Model).filter(Model.name == model).first()
            if model_record is None:
                model_record = _get_dga_model_record(db)
            if not model_record or model_record.model_category != "dga":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No active DGA model configured",
                )

            if created_by_user_id is not None:
                with engine.connect() as conn:
                    user_model_result = conn.execute(
                        text("""
                            SELECT um.id
                            FROM user_models um
                            WHERE um.user_id = :user_id
                              AND um.model_id = :model_id
                              AND um.is_active = 1
                        """),
                        {"user_id": created_by_user_id, "model_id": model_record.id},
                    ).first()
                if not user_model_result:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"您没有权限使用模型 {model_record.name}",
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
                        "source": "dga_detection",
                        "original_filename": uploaded_file_meta["filename"],
                    },
                )
                db.add(file_record)
                db.flush()

            task = Task(
                task_id=task_id,
                task_type="dga",
                model_id=model_record.id,
                file_id=file_record.id if file_record else None,
                extra=extra_data,
                status="pending",
                created_by=created_by_user_id,
            )
            db.add(task)
            db.commit()
            db.refresh(task)

            try:
                dispatch_dga_task(task.task_id)
            except Exception as exc:
                logger.exception("enqueue dga task failed: %s", exc)
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
                content={"ok": True, "task_id": task.task_id, "status": "pending"},
            )
        except HTTPException:
            db.rollback()
            raise
        except Exception as exc:
            db.rollback()
            logger.exception("Failed to create dga task: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create DGA task",
            ) from exc
        finally:
            db.close()
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error in create_dga_task: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        ) from exc


@router.post("/api/history-similarity-tasks")
async def create_history_similarity_task(
    request: Request,
    model: Optional[str] = Form(None),
    dataSource: str = Form(...),
    file: Optional[UploadFile] = File(None),
    dateRange: Optional[str] = Form(None),
    manualDomains: Optional[str] = Form(None),
    minScore: Optional[str] = Form(None),
):
    """创建历史高度相似检测任务。"""
    try:
        created_by_user_id: Optional[int] = _extract_user_id(request)
        uploaded_by_header = request.headers.get("X-User-Name") or request.headers.get("X-User")

        if dataSource not in ["upload", "newDomain", "manualInput"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="dataSource must be 'upload', 'newDomain' or 'manualInput'",
            )
        if dataSource == "upload" and file is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="file is required")
        if dataSource == "newDomain" and (not dateRange or dateRange.strip() == ""):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="dateRange is required")

        min_score, min_score_percent = _parse_history_similarity_min_score(minScore)

        date_range_parsed = None
        if dataSource == "newDomain":
            date_range_parsed = _parse_detection_date_range_payload(dateRange or "")
            start_date = _parse_date_string(date_range_parsed[0])
            end_date = _parse_date_string(date_range_parsed[1])
            availability = _inspect_daily_domain_availability(start_date, end_date)
            if not availability["available"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "message": "所选日期范围内暂无可用的新注册域名数据，请重新选择日期",
                        **availability,
                    },
                )

        manual_domain_list = None
        manual_domain_stats = None
        if dataSource == "manualInput":
            manual_domain_list, manual_domain_stats = _parse_manual_domains(manualDomains or "")

        uploaded_file_meta = None
        if file is not None:
            file_ext = file.filename.split(".")[-1].lower() if file.filename else ""
            allowed_extensions = ["csv", "txt", "xlsx"]
            if file_ext not in allowed_extensions:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File type not allowed. Only {', '.join(allowed_extensions)} are supported",
                )
            file_content = await file.read()
            file_size = len(file_content)
            max_size = 5 * 1024 * 1024
            if file_size > max_size:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File size exceeds maximum allowed size of {max_size / 1024 / 1024}MB",
                )
            file_key = upload_file_content_to_minio(
                file_content,
                file.filename or "unknown",
                file.content_type,
            )
            uploaded_file_meta = {
                "bucket": MINIO_BUCKET,
                "object_key": file_key,
                "filename": file.filename or "unknown",
                "content_type": file.content_type,
                "size": file_size,
            }

        extra_data = {
            "dataSource": dataSource,
            "dateRange": date_range_parsed,
            "min_score": min_score,
            "min_score_percent": min_score_percent,
            "top_k": 10,
        }
        if uploaded_file_meta:
            extra_data["file_bucket"] = uploaded_file_meta["bucket"]
            extra_data["file_object_key"] = uploaded_file_meta["object_key"]
        if manual_domain_list is not None:
            extra_data["manual_domains"] = manual_domain_list
            extra_data["manual_domain_stats"] = manual_domain_stats

        task_id = f"HIS{int(datetime.utcnow().timestamp())}{uuid.uuid4().hex[:6]}"
        db = SessionLocal()
        try:
            model_record = None
            if model:
                try:
                    model_record = db.query(Model).filter(Model.id == int(model)).first()
                except ValueError:
                    model_record = db.query(Model).filter(Model.name == model).first()
            if model_record is None:
                model_record = _get_history_similarity_model_record(db)
            if not model_record or model_record.model_category != "history_similarity":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No active history similarity model configured",
                )

            if created_by_user_id is not None:
                with engine.connect() as conn:
                    user_model_result = conn.execute(
                        text("""
                            SELECT um.id
                            FROM user_models um
                            WHERE um.user_id = :user_id
                              AND um.model_id = :model_id
                              AND um.is_active = 1
                        """),
                        {"user_id": created_by_user_id, "model_id": model_record.id},
                    ).first()
                if not user_model_result:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"您没有权限使用模型 {model_record.name}",
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
                        "source": "history_similarity_detection",
                        "original_filename": uploaded_file_meta["filename"],
                    },
                )
                db.add(file_record)
                db.flush()

            task = Task(
                task_id=task_id,
                task_type="history_similarity",
                model_id=model_record.id,
                file_id=file_record.id if file_record else None,
                extra=extra_data,
                status="pending",
                created_by=created_by_user_id,
            )
            db.add(task)
            db.commit()
            db.refresh(task)

            try:
                dispatch_history_similarity_task(task.task_id)
            except Exception as exc:
                logger.exception("enqueue history similarity task failed: %s", exc)
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
                content={"ok": True, "task_id": task.task_id, "status": "pending"},
            )
        except HTTPException:
            db.rollback()
            raise
        except Exception as exc:
            db.rollback()
            logger.exception("Failed to create history similarity task: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create history similarity task",
            ) from exc
        finally:
            db.close()
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error in create_history_similarity_task: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        ) from exc


@router.post("/api/apt-template-nrd-tasks")
async def create_apt_template_nrd_task(
    request: Request,
    model: Optional[str] = Form(None),
    dataSource: str = Form(...),
    file: Optional[UploadFile] = File(None),
    dateRange: Optional[str] = Form(None),
    manualDomains: Optional[str] = Form(None),
    scoreThreshold: Optional[str] = Form(None),
):
    """创建模板化APT域名检测任务。"""
    try:
        created_by_user_id: Optional[int] = _extract_user_id(request)
        uploaded_by_header = request.headers.get("X-User-Name") or request.headers.get("X-User")

        if dataSource not in ["upload", "newDomain", "manualInput"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="dataSource must be 'upload', 'newDomain' or 'manualInput'",
            )
        if dataSource == "upload" and file is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="file is required")
        if dataSource == "newDomain" and (not dateRange or dateRange.strip() == ""):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="dateRange is required")

        score_threshold, score_threshold_percent = _parse_apt_template_nrd_score_threshold(scoreThreshold)

        date_range_parsed = None
        if dataSource == "newDomain":
            date_range_parsed = _parse_detection_date_range_payload(dateRange or "")
            start_date = _parse_date_string(date_range_parsed[0])
            end_date = _parse_date_string(date_range_parsed[1])
            availability = _inspect_daily_domain_availability(start_date, end_date)
            if not availability["available"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "message": "所选日期范围内暂无可用的新注册域名数据，请重新选择日期",
                        **availability,
                    },
                )

        manual_domain_list = None
        manual_domain_stats = None
        if dataSource == "manualInput":
            manual_domain_list, manual_domain_stats = _parse_manual_domains(manualDomains or "")

        uploaded_file_meta = None
        if file is not None:
            file_ext = file.filename.split(".")[-1].lower() if file.filename else ""
            allowed_extensions = ["csv", "txt", "xlsx"]
            if file_ext not in allowed_extensions:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File type not allowed. Only {', '.join(allowed_extensions)} are supported",
                )
            file_content = await file.read()
            file_size = len(file_content)
            max_size = 5 * 1024 * 1024
            if file_size > max_size:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File size exceeds maximum allowed size of {max_size / 1024 / 1024}MB",
                )
            file_key = upload_file_content_to_minio(
                file_content,
                file.filename or "unknown",
                file.content_type,
            )
            uploaded_file_meta = {
                "bucket": MINIO_BUCKET,
                "object_key": file_key,
                "filename": file.filename or "unknown",
                "content_type": file.content_type,
                "size": file_size,
            }

        extra_data = {
            "dataSource": dataSource,
            "dateRange": date_range_parsed,
            "score_threshold": score_threshold,
            "score_threshold_percent": score_threshold_percent,
        }
        if uploaded_file_meta:
            extra_data["file_bucket"] = uploaded_file_meta["bucket"]
            extra_data["file_object_key"] = uploaded_file_meta["object_key"]
        if manual_domain_list is not None:
            extra_data["manual_domains"] = manual_domain_list
            extra_data["manual_domain_stats"] = manual_domain_stats

        task_id = f"APT{int(datetime.utcnow().timestamp())}{uuid.uuid4().hex[:6]}"
        db = SessionLocal()
        try:
            model_record = None
            if model:
                try:
                    model_record = db.query(Model).filter(Model.id == int(model)).first()
                except ValueError:
                    model_record = db.query(Model).filter(Model.name == model).first()
            if model_record is None:
                model_record = _get_apt_template_nrd_model_record(db)
            if not model_record or model_record.model_category != "apt_template_nrd":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No active APT template NRD model configured",
                )

            if created_by_user_id is not None:
                with engine.connect() as conn:
                    user_model_result = conn.execute(
                        text("""
                            SELECT um.id
                            FROM user_models um
                            WHERE um.user_id = :user_id
                              AND um.model_id = :model_id
                              AND um.is_active = 1
                        """),
                        {"user_id": created_by_user_id, "model_id": model_record.id},
                    ).first()
                if not user_model_result:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"您没有权限使用模型 {model_record.name}",
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
                        "source": "apt_template_nrd_detection",
                        "original_filename": uploaded_file_meta["filename"],
                    },
                )
                db.add(file_record)
                db.flush()

            task = Task(
                task_id=task_id,
                task_type="apt_template_nrd",
                model_id=model_record.id,
                file_id=file_record.id if file_record else None,
                extra=extra_data,
                status="pending",
                created_by=created_by_user_id,
            )
            db.add(task)
            db.commit()
            db.refresh(task)

            try:
                dispatch_apt_template_nrd_task(task.task_id)
            except Exception as exc:
                logger.exception("enqueue apt template nrd task failed: %s", exc)
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
                content={"ok": True, "task_id": task.task_id, "status": "pending"},
            )
        except HTTPException:
            db.rollback()
            raise
        except Exception as exc:
            db.rollback()
            logger.exception("Failed to create apt template nrd task: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create APT template NRD task",
            ) from exc
        finally:
            db.close()
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error in create_apt_template_nrd_task: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        ) from exc


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
        # 避免 tasks.extra 这类大 JSON 字段参与 MySQL 排序。归因结果会让 extra 变大，
        # 先只按轻量字段取分页 ID，再回查详情。
        task_id_rows = (
            db.query(Task.id)
            .filter(Task.created_by == user_id)
            .order_by(Task.created_at.desc())
            .offset((page - 1) * pageSize)
            .limit(pageSize)
            .all()
        )
        ordered_task_ids = [row[0] for row in task_id_rows]
        if not ordered_task_ids:
            return {"items": [], "total": total}

        records = (
            db.query(Task, Model, StoredFile)
            .join(Model, Model.id == Task.model_id)
            .outerjoin(StoredFile, StoredFile.id == Task.file_id)
            .filter(Task.id.in_(ordered_task_ids))
            .all()
        )
        order_index = {task_id: index for index, task_id in enumerate(ordered_task_ids)}
        records.sort(key=lambda record: order_index.get(record[0].id, 0))
        items = []
        for task, model, stored_file in records:
            extra_data = _normalize_extra(task.extra)
            task_type_label = TASK_TYPE_LABEL_MAP.get(task.task_type, task.task_type)
            status_label = STATUS_LABEL_MAP.get(task.status, task.status)
            progress = STATUS_PROGRESS_MAP.get(task.status, 0)
            raw_progress = extra_data.get("progress")
            if isinstance(raw_progress, (int, float)):
                progress = max(0, min(100, int(raw_progress)))
            if (
                task.task_type == "impersonation"
                and extra_data.get("official_domain_resolution_status") == "pending"
            ):
                status_label = "等待官方域名解析"
                progress = 0
            
            # 对于仿冒域名检测任务，使用 detectionSource；其他检测任务使用 dataSource
            data_source_type = ""
            if task.task_type == "impersonation":
                data_source_type = extra_data.get("detectionSource", "")
            else:
                data_source_type = extra_data.get("dataSource", "")
            
            data_source_label = DATA_SOURCE_LABEL_MAP.get(data_source_type, "上传文件")
            data_source_payload = {"type": data_source_label}
            if task.task_type == "impersonation" and extra_data.get("queryName"):
                data_source_payload["queryName"] = extra_data.get("queryName")
            
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
            elif data_source_type == "manualInput":
                manual_stats = extra_data.get("manual_domain_stats") or {}
                data_source_payload["domainCount"] = manual_stats.get("valid_count") or len(extra_data.get("manual_domains") or [])
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
            if task.task_type == "apt_template_nrd":
                try:
                    results_df = pd.read_excel(excel_file, sheet_name='预测结果')
                except Exception:
                    results_df = pd.DataFrame()
                excel_file.seek(0)
                stats_df = pd.read_excel(excel_file, sheet_name='统计信息')
                apt_list = []
                try:
                    excel_file.seek(0)
                    apt_df = pd.read_excel(excel_file, sheet_name='模板化APT域名列表')
                    apt_list = apt_df.to_dict('records')
                except Exception:
                    try:
                        excel_file.seek(0)
                        apt_df = pd.read_excel(excel_file, sheet_name='APT模板命中域名列表')
                        apt_list = apt_df.to_dict('records')
                    except Exception:
                        pass

                results_list = results_df.to_dict('records')
                statistics_dict = {}
                for _, row in stats_df.iterrows():
                    statistics_dict[row['统计项']] = row['数值']
                if not apt_list:
                    apt_list = [
                        row for row in results_list
                        if row.get('预测标签') == 1
                        or row.get('预测结果') == '模板化APT命中'
                        or row.get('预测结果') == 'APT模板命中'
                        or str(row.get('risk_level') or '').lower() == 'high'
                    ]

                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content=_json_safe_value({
                        "ok": True,
                        "task_id": task.task_id,
                        "task_type": task.task_type,
                        "statistics": statistics_dict,
                        "results": results_list,
                        "apt_template_nrd_domains": apt_list,
                        "result_file_key": result_key,
                        "result_filename": extra_data.get("result_filename") or f"{task.task_id}_result.xlsx",
                        "total_count": len(results_list),
                        "apt_template_nrd_count": len(apt_list),
                        "apt_template_nrd_detection": extra_data.get("apt_template_nrd_detection") or {},
                    })
                )
            if task.task_type == "dga":
                try:
                    results_df = pd.read_excel(excel_file, sheet_name='预测结果')
                except Exception:
                    results_df = pd.DataFrame()
                excel_file.seek(0)
                stats_df = pd.read_excel(excel_file, sheet_name='统计信息')
                dga_list = []
                try:
                    excel_file.seek(0)
                    dga_df = pd.read_excel(excel_file, sheet_name='DGA域名列表')
                    dga_list = dga_df.to_dict('records')
                except Exception:
                    pass

                results_list = results_df.to_dict('records')
                statistics_dict = {}
                for _, row in stats_df.iterrows():
                    statistics_dict[row['统计项']] = row['数值']
                if not dga_list:
                    dga_list = [
                        row for row in results_list
                        if row.get('预测标签') == 1 or row.get('预测结果') == 'DGA-like'
                    ]

                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content=_json_safe_value({
                        "ok": True,
                        "task_id": task.task_id,
                        "task_type": task.task_type,
                        "statistics": statistics_dict,
                        "results": results_list,
                        "dga_domains": dga_list,
                        "result_file_key": result_key,
                        "result_filename": extra_data.get("result_filename") or f"{task.task_id}_result.xlsx",
                        "total_count": len(results_list),
                        "dga_count": len(dga_list),
                        "dga_detection": extra_data.get("dga_detection") or {},
                    })
                )
            if task.task_type == "history_similarity":
                try:
                    results_df = pd.read_excel(excel_file, sheet_name='预测结果')
                except Exception:
                    results_df = pd.DataFrame()
                excel_file.seek(0)
                stats_df = pd.read_excel(excel_file, sheet_name='统计信息')
                history_list = []
                try:
                    excel_file.seek(0)
                    history_df = pd.read_excel(excel_file, sheet_name='历史相似域名列表')
                    history_list = history_df.to_dict('records')
                except Exception:
                    pass

                results_list = results_df.to_dict('records')
                history_list = _dedupe_history_similarity_rows(history_list)
                statistics_dict = {}
                for _, row in stats_df.iterrows():
                    statistics_dict[row['统计项']] = row['数值']
                if not history_list:
                    history_list = _dedupe_history_similarity_rows([
                        row for row in results_list
                        if row.get('预测标签') == 1 or row.get('预测结果') == '历史高度相似'
                    ])

                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content=_json_safe_value({
                        "ok": True,
                        "task_id": task.task_id,
                        "task_type": task.task_type,
                        "statistics": statistics_dict,
                        "results": results_list,
                        "history_similarity_domains": history_list,
                        "result_file_key": result_key,
                        "result_filename": extra_data.get("result_filename") or f"{task.task_id}_result.xlsx",
                        "total_count": len(results_list),
                        "history_similarity_count": len(history_list),
                        "history_similarity_detection": extra_data.get("history_similarity_detection") or {},
                    })
                )
            if task.task_type == "impersonation":
                # 仿冒域名检测结果
                try:
                    results_df = pd.read_excel(excel_file, sheet_name='检测结果')
                except Exception:
                    # 如果没有检测结果工作表，创建一个空的DataFrame
                    results_df = pd.DataFrame(columns=["钓鱼域名", "官方域名", "公司名称", "相似度", "匹配类型"])

                # 读取统计信息表
                stats_df = pd.read_excel(excel_file, sheet_name='统计信息')

                # 读取钓鱼域名列表（如果存在）
                phishing_list = []
                try:
                    try:
                        phishing_df = pd.read_excel(excel_file, sheet_name='仿冒域名列表')
                    except Exception:
                        excel_file.seek(0)
                        phishing_df = pd.read_excel(excel_file, sheet_name='钓鱼域名列表')
                    phishing_list = phishing_df.to_dict('records')
                except Exception:
                    # 如果没有钓鱼域名列表工作表，从结果中筛选
                    pass

                # 将DataFrame转换为字典列表
                results_list = _normalize_impersonation_result_rows(results_df.to_dict('records'))
                for item in results_list:
                    if "二分类置信度" not in item and "恶意概率" in item:
                        item["二分类置信度"] = item.get("恶意概率")
                for item in results_list:
                    if "官方域名" not in item and "目标域名" in item:
                        item["官方域名"] = item.get("目标域名")

                # 将统计信息转换为字典
                statistics_dict = {}
                for _, row in stats_df.iterrows():
                    statistics_dict[row['统计项']] = row['数值']

                official_domain_rows = _normalize_official_domain_rows(extra_data.get("official_domains") or [])
                if not official_domain_rows and extra_data.get("official_file_object_key"):
                    try:
                        official_file_content = download_file_from_minio(
                            extra_data.get("official_file_object_key"),
                            extra_data.get("official_file_bucket") or MINIO_BUCKET,
                        )
                        official_domain_rows = _normalize_official_domain_rows(
                            read_official_domains_from_file(
                                official_file_content,
                                extra_data.get("official_file_filename") or "official_domains",
                            )
                        )
                    except Exception:
                        logger.exception("读取任务官方域名列表失败 task_id=%s", task.task_id)

                # 如果没有钓鱼域名列表，从结果中筛选
                if not phishing_list:
                    phishing_list = [
                        r for r in results_list
                        if r.get('仿冒域名') or r.get('钓鱼域名')
                    ]
                else:
                    phishing_list = _normalize_impersonation_result_rows(phishing_list)

                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content=_json_safe_value({
                        "ok": True,
                        "task_id": task.task_id,
                        "task_type": task.task_type,
                        "statistics": statistics_dict,
                        "results": results_list,
                        "phishing_domains": phishing_list,
                        "official_domains": official_domain_rows,
                        "result_file_key": result_key,
                        "result_filename": extra_data.get("result_filename") or f"{task.task_id}_result.xlsx",
                        "word_report_file_key": extra_data.get("word_report_file_key"),
                        "word_report_filename": extra_data.get("word_report_filename"),
                        "total_count": len(results_list),
                        "phishing_count": len(phishing_list),
                        "official_domain_count": len(official_domain_rows),
                    })
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
                else:
                    for item in malicious_list:
                        if "二分类置信度" not in item and "恶意概率" in item:
                            item["二分类置信度"] = item.get("恶意概率")

                attribution_index = _build_attribution_index(extra_data)
                results_list = _attach_attribution_fields(results_list, attribution_index)
                malicious_list = _attach_attribution_fields(malicious_list, attribution_index)

                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content=_json_safe_value({
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
                        "attribution_enabled": bool(extra_data.get("attribution_enabled")),
                        "attribution_results": extra_data.get("attribution_results") or [],
                    })
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
        media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        is_word_report_download = False
        if task.task_type == "impersonation" and extra_data.get("word_report_file_key"):
            result_key = extra_data.get("word_report_file_key")
            result_bucket = extra_data.get("word_report_bucket") or RESULTS_BUCKET
            filename = extra_data.get("word_report_filename") or f"{task.task_id}_prediction_report.docx"
            media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            is_word_report_download = True
        try:
            file_bytes = download_file_from_minio(result_key, result_bucket)
        except Exception as exc:
            logger.exception("下载结果文件失败: %s", exc)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to fetch result file")
        if task.task_type == "history_similarity" and not is_word_report_download:
            try:
                file_bytes = _dedupe_history_similarity_sheet(file_bytes)
            except Exception:
                logger.exception("历史高度相似结果Sheet去重失败 task_id=%s", task.task_id)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to deduplicate history similarity sheet",
                )
        if task.task_type == "impersonation" and not is_word_report_download:
            official_domain_rows = _normalize_official_domain_rows(extra_data.get("official_domains") or [])
            if not official_domain_rows and extra_data.get("official_file_object_key"):
                try:
                    official_file_content = download_file_from_minio(
                        extra_data.get("official_file_object_key"),
                        extra_data.get("official_file_bucket") or MINIO_BUCKET,
                    )
                    official_domain_rows = _normalize_official_domain_rows(
                        read_official_domains_from_file(
                            official_file_content,
                            extra_data.get("official_file_filename") or "official_domains",
                        )
                    )
                except Exception:
                    logger.exception("下载时读取任务官方域名列表失败 task_id=%s", task.task_id)
            try:
                file_bytes = _replace_impersonation_official_sheet(file_bytes, official_domain_rows)
            except Exception:
                logger.exception("替换仿冒检测官方域名Sheet失败 task_id=%s", task.task_id)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to build official domain sheet",
                )
        response = StreamingResponse(
            io.BytesIO(file_bytes),
            media_type=media_type,
        )
        response.headers["Content-Disposition"] = f"attachment; filename*=utf-8''{quote(filename)}"
        return response
    finally:
        db.close()


@router.post("/api/impersonation-tasks")
async def create_impersonation_task(
    request: Request,
    queryName: Optional[str] = Form(None),
    detectionDateRange: str = Form(...),
    useCustomThreshold: str = Form("false"),
    threshold: Optional[str] = Form(None),
    officialFile: Optional[UploadFile] = File(None),
):
    """
    创建仿冒域名检测任务
    
    参数:
    - queryName: 事件名或单位名（首选，使用 DeepSeek 解析相关官方域名）
    - officialFile: 官方域名文件（当事件名未解析出官方域名时可使用）
    - detectionDateRange: 新注册域名日期范围JSON字符串
    - useCustomThreshold: 是否使用自定义阈值
    - threshold: 自定义阈值（0-100）
    """
    try:
        logger.info("收到仿冒域名检测任务创建请求")
        created_by_user_id: Optional[int] = _extract_user_id(request)
        uploaded_by_header = request.headers.get("X-User-Name") or request.headers.get("X-User")
        logger.info(f"用户ID: {created_by_user_id}, 上传者: {uploaded_by_header}")

        query_name = (queryName or "").strip()
        if not query_name and officialFile is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="queryName or officialFile is required"
            )
        if not detectionDateRange or detectionDateRange.strip() == "":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="detectionDateRange is required"
            )
        date_range_parsed = _parse_detection_date_range_payload(detectionDateRange)
        start_date = _parse_date_string(date_range_parsed[0])
        end_date = _parse_date_string(date_range_parsed[1])
        availability = _inspect_daily_domain_availability(start_date, end_date)
        if not availability["available"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": "所选日期范围内暂无可用的新注册域名数据，请重新选择日期",
                    **availability,
                },
            )
        similarity_threshold, threshold_meta = _parse_similarity_threshold(useCustomThreshold, threshold)
        official_domains = []
        official_domain_resolution_error = None
        if query_name:
            try:
                official_domains = resolve_official_domains(query_name)
                logger.info(
                    "DeepSeek解析官方域名完成 query=%s count=%s",
                    query_name,
                    len(official_domains),
                )
            except OfficialDomainResolutionError as exc:
                official_domain_resolution_error = str(exc)
                logger.warning(
                    "DeepSeek解析官方域名失败 query=%s error=%s",
                    query_name,
                    official_domain_resolution_error,
                )
                if officialFile is None:
                    status_code = (
                        status.HTTP_500_INTERNAL_SERVER_ERROR
                        if isinstance(exc, OfficialDomainResolverConfigError)
                        else status.HTTP_502_BAD_GATEWAY
                    )
                    raise HTTPException(
                        status_code=status_code,
                        detail=official_domain_resolution_error,
                    ) from exc
        official_domain_resolution_status = "resolved" if official_domains else "pending"
        official_file_meta = None
        if officialFile is not None:
            file_ext = officialFile.filename.split(".")[-1].lower() if officialFile.filename else ""
            allowed_extensions = ["csv", "txt", "xlsx"]
            if file_ext not in allowed_extensions:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Official file type not allowed. Only {', '.join(allowed_extensions)} are supported"
                )

            official_file_content = await officialFile.read()
            official_file_size = len(official_file_content)
            max_size = 5 * 1024 * 1024
            if official_file_size > max_size:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Official file size exceeds maximum allowed size of {max_size / 1024 / 1024}MB"
                )

            official_file_key = upload_file_content_to_minio(
                official_file_content,
                officialFile.filename or "unknown",
                officialFile.content_type,
            )
            official_file_meta = {
                "bucket": MINIO_BUCKET,
                "object_key": official_file_key,
                "filename": officialFile.filename or "unknown",
                "content_type": officialFile.content_type,
                "size": official_file_size,
            }
            if not official_domains:
                official_domain_resolution_status = "file_uploaded"

        if not official_domains and official_file_meta is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="未从事件名或单位名解析到有效官方域名，请调整输入或上传官方域名文件",
            )
        
        # 生成任务ID
        task_id = f"T{int(datetime.utcnow().timestamp())}"
        
        # 保存任务到数据库
        db = SessionLocal()
        try:
            logger.info(f"查找仿冒检测模型，配置名: {IMPERSONATION_MODEL_NAME}")
            model_record = _get_impersonation_model_record(db)
            if not model_record:
                logger.error("数据库中不存在可用的 active impersonation 模型")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="No active impersonation model configured"
                )
            logger.info(f"找到模型记录: id={model_record.id}, name={model_record.name}")
            
            # 构建extra字段
            extra_data = {
                "detectionSource": "newDomain",
                "queryName": query_name,
                "dateRange": date_range_parsed,
                "official_domains": official_domains,
                "official_domain_resolution_status": official_domain_resolution_status,
                "official_domain_resolution_pending": False,
                "official_domain_resolution_method": "deepseek" if official_domains else "file",
                "official_domain_count": len(official_domains),
                "threshold_policy": "custom" if similarity_threshold is not None else "adaptive",
                "similarity_threshold": similarity_threshold,
                "threshold_percent": threshold_meta["threshold_percent"],
            }
            if official_domain_resolution_error:
                extra_data["official_domain_resolution_error"] = official_domain_resolution_error
            file_record = None
            if official_file_meta:
                file_record = StoredFile(
                    bucket=official_file_meta["bucket"],
                    object_key=official_file_meta["object_key"],
                    filename=official_file_meta["filename"],
                    content_type=official_file_meta["content_type"],
                    size=official_file_meta["size"],
                    uploaded_by=uploaded_by_header,
                    metadata_json={
                        "source": "impersonation_detection",
                        "role": "official_domains",
                        "original_filename": official_file_meta["filename"],
                    },
                )
                db.add(file_record)
                db.flush()
                extra_data["official_file_bucket"] = official_file_meta["bucket"]
                extra_data["official_file_object_key"] = official_file_meta["object_key"]
                extra_data["official_file_filename"] = official_file_meta["filename"]
            if official_domains:
                extra_data["official_domain_resolution_message"] = (
                    f"DeepSeek已解析到 {len(official_domains)} 个官方域名"
                )
            elif not official_domains and official_file_meta is not None:
                extra_data["official_domain_resolution_message"] = "已使用上传的官方域名文件"
            
            # 创建任务
            task = Task(
                task_id=task_id,
                task_type="impersonation",
                model_id=model_record.id,
                file_id=file_record.id if file_record else None,
                extra=extra_data,
                status="pending",
                created_by=created_by_user_id,
            )
            db.add(task)
            db.commit()
            db.refresh(task)
            
            if official_domains or official_file_meta is not None:
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
                    "status": "pending",
                    "officialDomainStatus": official_domain_resolution_status,
                    "officialDomainCount": len(official_domains),
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
