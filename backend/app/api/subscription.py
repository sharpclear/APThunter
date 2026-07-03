from fastapi import APIRouter, File, Form, UploadFile, HTTPException, status, Request, Query, Header
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Tuple
import logging
import json
import sys
import os
import io
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import text
import threading
import time

# 北京时间时区（UTC+8）
BEIJING_TZ = timezone(timedelta(hours=8))

def _load_local_dotenv_if_present():
    """
    本地直接启动后端服务时，常见问题是没有 export SMTP_* 环境变量。
    这里尝试从项目根目录/后端目录的 .env 加载（如果存在）。
    不记录任何敏感信息到日志。
    """
    try:
        from dotenv import load_dotenv  # python-dotenv
    except Exception:
        return

    try:
        api_dir = os.path.dirname(os.path.abspath(__file__))  # backend/app/api
        backend_dir = os.path.abspath(os.path.join(api_dir, "..", ".."))  # backend/app
        backend_root = os.path.abspath(os.path.join(api_dir, "..", "..", ".."))  # backend
        project_root = os.path.abspath(os.path.join(api_dir, "..", "..", "..", ".."))  # apthunter

        # 允许通过环境变量显式指定 dotenv 路径（最优先）
        explicit = os.getenv("DOTENV_PATH")

        # 同时尝试 cwd（你本地命令行启动时最可能放置的位置）
        cwd = os.getcwd()

        candidates = []
        if explicit:
            candidates.append(explicit)
        candidates.extend(
            [
                os.path.join(cwd, ".env"),
                os.path.join(project_root, ".env"),
                os.path.join(backend_root, ".env"),
                os.path.join(backend_dir, ".env"),
            ]
        )

        for p in candidates:
            if os.path.exists(p):
                load_dotenv(p, override=False)
                break
    except Exception:
        return


_load_local_dotenv_if_present()


def beijing_now() -> datetime:
    """获取当前北京时间"""
    return datetime.now(BEIJING_TZ)


def beijing_today() -> datetime.date:
    """获取当前北京日期"""
    return beijing_now().date()


def beijing_datetime_to_naive(dt: datetime) -> datetime:
    """将带时区的北京时间转换为不带时区的datetime（用于数据库存储）"""
    if dt.tzinfo is not None:
        # 转换为北京时间（如果还不是）
        if dt.tzinfo != BEIJING_TZ:
            dt = dt.astimezone(BEIJING_TZ)
        # 去掉时区信息
        return dt.replace(tzinfo=None)
    return dt

# 添加models目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'models'))
# 从 entities / main / db / core 导入必要的依赖
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
if MODELS_DIR not in sys.path:
    sys.path.insert(0, MODELS_DIR)

from app.entities import AlertFile, Task, Model, StoredFile, User
from app.infra.minio_client import minio_client
from app.db.session import SessionLocal, engine
from app.db.base import Base
from app.core.config import MINIO_BUCKET, IMPERSONATION_MODEL_NAME, IMPERSONATION_FULL_WHITELIST_PATH
from sqlalchemy import Column, BigInteger, String, DateTime, ForeignKey, Enum as SqlEnum, Integer, JSON, text, Boolean
from app.services.notification.alert_notifier import build_alert_data_dict, dispatch_alert_notifications
from app.services.domain_monitor import register_monitor_targets
from app.services.apt_template_nrd_report import (
    build_apt_template_nrd_result_json,
    build_apt_template_nrd_result_payload,
    generate_apt_template_nrd_pdf_report,
)
from app.services.history_similarity_report import (
    build_history_similarity_result_json,
    build_history_similarity_result_payload,
    generate_history_similarity_pdf_report,
)
from app.services.actor_matcher import (
    AlertResultStorageError,
    build_alert_result_json,
    create_alert_file_mapping,
    match_domain_to_actors_v2_infra,
    save_alert_result_json_to_minio,
)
# 导入检测相关函数
from app.api.detection import (
    _collect_daily_domains,
    _parse_date_string,
    upload_file_content_to_minio,
    download_file_from_minio,
    RESULTS_BUCKET,
)
from malicious_detection_daily import predict_from_domains, predict_from_domains_subscription
from impersonation_detector import (
    read_official_domains_from_file,
    predict_from_domains as phishing_predict_from_domains,
    predict_from_domains_with_report as phishing_predict_from_domains_with_report,
)
from history_similarity_detection import (
    alert_rows_to_score_records as history_alert_rows_to_score_records,
    predict_from_domains as history_similarity_predict_from_domains,
)
from dga_domain_detection import predict_from_domains as dga_predict_from_domains
from apt_template_nrd_matcher import (
    alert_rows_to_score_records as apt_template_nrd_alert_rows_to_score_records,
    predict_from_domains as apt_template_nrd_predict_from_domains,
)

logger = logging.getLogger("uvicorn.error")

# 数据延迟配置：数据文件延迟多少天到达（默认1天，即今天的数据明天才能获取）
DATA_DELAY_DAYS = int(os.getenv("DATA_DELAY_DAYS", "1"))


def _resolve_full_whitelist_path() -> str:
    return os.path.abspath(os.path.expanduser(IMPERSONATION_FULL_WHITELIST_PATH))


def _load_full_whitelist_file() -> Tuple[bytes, str, str]:
    whitelist_path = _resolve_full_whitelist_path()
    if not os.path.isfile(whitelist_path):
        raise FileNotFoundError(
            f"系统全量白名单不存在，请保存为: {whitelist_path}"
        )
    filename = os.path.basename(whitelist_path) or "full_whitelist.csv"
    file_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if file_ext not in {"csv", "txt", "xlsx"}:
        raise ValueError("系统全量白名单文件类型必须是 csv, txt 或 xlsx")
    with open(whitelist_path, "rb") as file_handle:
        content = file_handle.read()
    if not content.strip():
        raise ValueError(f"系统全量白名单为空: {whitelist_path}")
    return content, filename, whitelist_path

# 定义 Subscription 和 Alert 模型（因为 main.py 中已删除）
class Subscription(Base):
    __tablename__ = "subscriptions"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    subscription_id = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(BigInteger, ForeignKey("users.id"), nullable=False, index=True)
    model_id = Column(BigInteger, ForeignKey("models.id"), nullable=False, index=True)
    frequency = Column(SqlEnum("daily", "weekly", "monthly", name="frequency_enum"), nullable=False, server_default="weekly")
    threshold = Column(Integer, nullable=True)
    official_file_id = Column(BigInteger, ForeignKey("files.id"), nullable=True, index=True)
    is_active = Column(Boolean, nullable=False, server_default=text("1"), index=True)
    next_run_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"), onupdate=lambda: beijing_now().replace(tzinfo=None))


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), unique=True, nullable=False, index=True)
    subscription_id = Column(String(64), ForeignKey("subscriptions.subscription_id"), nullable=False, index=True)
    task_id = Column(String(64), ForeignKey("tasks.task_id"), nullable=False, index=True)
    user_id = Column(BigInteger, ForeignKey("users.id"), nullable=False, index=True)
    model_id = Column(BigInteger, ForeignKey("models.id"), nullable=False, index=True)
    model_name = Column(String(255), nullable=False)
    task_type = Column(
        SqlEnum(
            "malicious",
            "impersonation",
            "malicious_ip",
            "dga",
            "history_similarity",
            "apt_template_nrd",
            name="task_type_enum",
        ),
        nullable=False,
    )
    detected_count = Column(Integer, nullable=False, server_default=text("0"))
    high_risk_count = Column(Integer, nullable=False, server_default=text("0"))
    threshold = Column(Integer, nullable=True)
    status = Column(SqlEnum("pending", "processed", name="alert_status_enum"), nullable=False, server_default="pending", index=True)
    feishu_notified = Column(Boolean, nullable=False, server_default=text("0"), default=False)
    feishu_notified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"), index=True)
    updated_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"), onupdate=lambda: beijing_now().replace(tzinfo=None))


router = APIRouter()

# APScheduler 调度器（全局单例）
scheduler = None
scheduler_lock = threading.Lock()


def _extract_user_id(request: Request) -> Optional[int]:
    """从请求头提取用户ID"""
    user_id_header = request.headers.get("X-User-Id")
    if not user_id_header:
        return None
    try:
        return int(user_id_header)
    except ValueError:
        logger.warning("Invalid X-User-Id header value: %s", user_id_header)
        return None


def _require_user_id(request: Request) -> int:
    """要求必须有用户ID，否则抛出401错误"""
    user_id = _extract_user_id(request)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-User-Id header",
        )
    return user_id


def _normalize_extra(extra_value):
    """规范化extra字段（JSON字符串或字典）"""
    if not extra_value:
        return {}
    if isinstance(extra_value, str):
        try:
            return json.loads(extra_value)
        except json.JSONDecodeError:
            logger.warning("Failed to parse extra JSON")
            return {}
    return dict(extra_value) if isinstance(extra_value, dict) else {}


def _extract_high_risk_snapshot_from_result_json(result_payload) -> tuple[list[str], list[dict]]:
    """
    从 MinIO 的完整预警 JSON 中提取轻量快照。
    """
    high_risk_domains = []
    snapshot = []
    for item in (result_payload or {}).get("high_risk_domains") or []:
        if not isinstance(item, dict):
            continue
        domain_name = str(item.get("domain") or "").strip()
        if not domain_name:
            continue
        high_risk_domains.append(domain_name)
        snapshot.append(
            {
                "domain": domain_name,
                "risk_score": item.get("risk_score"),
                "risk_level": item.get("risk_level"),
            }
        )
    return high_risk_domains, snapshot


def _calculate_next_run_at(frequency: str, from_date: Optional[datetime] = None) -> datetime:
    """
    计算下次执行时间（统一在早上9点执行）
    
    无论订阅频率如何，都统一在早上9点（北京时间）执行
    
    参数:
        frequency: 订阅频率（daily/weekly/monthly）
        from_date: 基准时间，如果为None则使用当前北京时间
    
    返回:
        下次执行时间（早上9点，北京时间）
    """
    if from_date is None:
        from_date = beijing_now()
    else:
        # 如果传入的from_date没有时区信息，假设是北京时间
        if from_date.tzinfo is None:
            from_date = from_date.replace(tzinfo=BEIJING_TZ)
        # 如果有时区信息，转换为北京时间
        elif from_date.tzinfo != BEIJING_TZ:
            from_date = from_date.astimezone(BEIJING_TZ)
    
    # 计算下一个早上9点（北京时间）
    # 统一在早上9点执行，无论订阅时间是什么时候
    target_time = from_date.replace(hour=9, minute=0, second=0, microsecond=0)
    
    # 判断是否已经过了今天9点（包括正好9:00:00的情况，因为已经执行过了）
    if from_date >= target_time:
        # 如果已经过了或正好是今天9点，设置为明天9点
        next_9am = target_time + timedelta(days=1)
    else:
        # 如果还没到今天9点，设置为今天9点
        next_9am = target_time
    
    # 根据频率计算执行时间
    if frequency == "daily":
        # 每天：下一个9点（如果今天9点已过，就是明天9点）
        # 注意：对于daily，如果next_9am是今天9点，但当前时间已经过了9点，应该返回明天9点
        # 这个逻辑已经在上面处理了，所以直接返回next_9am即可
        return next_9am
    elif frequency == "weekly":
        # 每周：下一个9点，然后加7天
        return next_9am + timedelta(weeks=1)
    elif frequency == "monthly":
        # 每月：下一个9点，然后加30天
        return next_9am + timedelta(days=30)
    else:
        # 默认：每周
        return next_9am + timedelta(weeks=1)


def _get_date_range_for_frequency(frequency: str, last_checked_date: Optional[datetime.date] = None) -> List[str]:
    """
    根据频率计算日期范围（前x天，x为订阅周期）
    考虑数据延迟：数据文件延迟DATA_DELAY_DAYS天到达
    
    策略：
    1. 如果提供了last_checked_date，从上次检测的日期+1开始检测（增量检测，避免重复）
    2. 如果没有last_checked_date，检测前x天的数据（首次检测或全量检测）
    3. 结束日期：排除今天及最近DATA_DELAY_DAYS天（因为数据还没到或可能还没到）
    
    例如（DATA_DELAY_DAYS=1，「今天」指北京日历日）：
    - 今天 1 月 9 日：end_date = 1 月 8 日（只读到「昨天」的 zip，与源站 T+1 发布节奏一致）
    - daily 首次：start_date = end_date → 只检测 1 月 8 日
    - daily 增量（last_checked_date=1 月 7 日）：start_date=1 月 8 日 → 仍只检测 1 月 8 日
    - 若同一天再次调度且 last_checked 已等于 end_date，则 start_date > end_date，返回空范围
    """
    today = beijing_today()
    # 结束日期：排除今天及最近DATA_DELAY_DAYS天（因为数据还没到或可能还没到）
    end_date = today - timedelta(days=DATA_DELAY_DAYS)
    
    if last_checked_date:
        # 增量检测：从上次检测的日期+1开始，到end_date结束
        start_date = last_checked_date + timedelta(days=1)
        # 确保不超过end_date
        if start_date > end_date:
            # 没有新数据需要检测
            return []
        
        # 根据频率限制最大检测范围（避免一次性检测太多数据）
        if frequency == "daily":
            # daily：只检测1天（即end_date这一天）
            # 如果start_date < end_date，说明有遗漏，从start_date开始检测到end_date
            # 但为了保持daily的特性，只检测end_date这一天
            if start_date < end_date:
                # 有遗漏的数据，但daily只检测最新的一天
                start_date = end_date
        elif frequency == "weekly":
            # weekly：最多检测7天，从start_date到end_date
            max_start = end_date - timedelta(days=6)
            if start_date < max_start:
                # 如果遗漏太多，只检测最近7天
                start_date = max_start
        elif frequency == "monthly":
            # monthly：最多检测30天，从start_date到end_date
            max_start = end_date - timedelta(days=29)
            if start_date < max_start:
                # 如果遗漏太多，只检测最近30天
                start_date = max_start
    else:
        # 首次检测或全量检测：检测前x天的数据
        if frequency == "daily":
            # 前1天：检测前1天的数据
            start_date = end_date - timedelta(days=0)  # 只检测end_date这一天
        elif frequency == "weekly":
            # 前7天：从7天前到前1天
            start_date = end_date - timedelta(days=6)  # 7天范围：end_date往前推6天
        elif frequency == "monthly":
            # 前30天：从30天前到前1天
            start_date = end_date - timedelta(days=29)  # 30天范围：end_date往前推29天
        else:
            # 默认前7天
            start_date = end_date - timedelta(days=6)
    
    # 确保start_date <= end_date
    if start_date > end_date:
        return []
    
    return [start_date.isoformat(), end_date.isoformat()]


def _collect_daily_domains_for_subscription(date_range: List[str]) -> Tuple[List[str], List[str]]:
    """
    为订阅场景收集每日域名数据（不会因为没有数据而抛出异常）
    返回: (域名列表, 缺失日期列表)
    """
    if not isinstance(date_range, list) or len(date_range) < 2:
        logger.warning(f"日期范围参数无效: {date_range}")
        return [], []
    
    try:
        start_date = _parse_date_string(str(date_range[0]))
        end_date = _parse_date_string(str(date_range[1]))
    except Exception as e:
        logger.warning(f"日期范围解析失败: {date_range}, 错误: {e}")
        return [], []
    
    if start_date > end_date:
        start_date, end_date = end_date, start_date
    
    domains_set = set()
    missing_dates = []
    current = start_date
    
    # 获取 DAILY_DATA_DIR（从 detection.py 导入的常量）
    DAILY_DATA_DIR = os.path.abspath(
        os.getenv("DAILY_DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "daily_data"))
    )
    
    while current <= end_date:
        month_folder = os.path.join(DAILY_DATA_DIR, current.strftime("%Y-%m"))
        zip_name = f"{current.strftime('%Y-%m-%d')}-domain.zip"
        zip_path = os.path.join(month_folder, zip_name)
        
        if not os.path.exists(zip_path):
            missing_dates.append(current.isoformat())
            logger.debug(f"日期 {current.isoformat()} 的数据文件不存在: {zip_path}")
            current += timedelta(days=1)
            continue
        
        try:
            import zipfile
            with zipfile.ZipFile(zip_path, "r") as zf:
                if "dailyupdate.txt" not in zf.namelist():
                    missing_dates.append(current.isoformat())
                    logger.debug(f"日期 {current.isoformat()} 的zip文件中没有 dailyupdate.txt")
                    current += timedelta(days=1)
                    continue
                
                with zf.open("dailyupdate.txt") as file_handle:
                    content = file_handle.read().decode("utf-8", errors="ignore")
                    for line in content.splitlines():
                        domain = line.strip()
                        if domain:
                            domains_set.add(domain)
        except Exception as exc:
            logger.warning(f"读取日期 {current.isoformat()} 的数据失败: {exc}, 文件: {zip_path}")
            missing_dates.append(current.isoformat())
        
        current += timedelta(days=1)
    
    domains = list(domains_set)
    
    if missing_dates:
        logger.info(f"日期范围内有 {len(missing_dates)} 天没有数据，已跳过: {missing_dates[:5]}{'...' if len(missing_dates) > 5 else ''}")
    
    if domains:
        logger.info(f"收集到 {len(domains)} 个域名，来自 {len(date_range)} 天中的 {len(date_range) - len(missing_dates)} 天")
    else:
        logger.warning(f"日期范围内没有收集到任何域名数据，缺失日期: {missing_dates}")
    
    return domains, missing_dates


def _clean_optional_text(value) -> str:
    if value is None:
        return ""
    try:
        import pandas as pd

        if pd.isna(value):
            return ""
    except Exception:
        pass
    text_value = str(value).strip()
    return "" if text_value.lower() == "nan" else text_value


def _impersonation_item_is_medium_or_high(item: dict) -> bool:
    risk_level = _clean_optional_text(item.get("risk_level")).lower()
    if risk_level in {"高", "高危", "high", "中", "中危", "medium", "middle"}:
        return True
    if risk_level in {"低", "低危", "low", "忽略", "ignore"}:
        return False
    score_text = _clean_optional_text(
        item.get("final_risk_score") or item.get("similarity") or item.get("llm_score")
    )
    try:
        return float(score_text) >= 0.65
    except (TypeError, ValueError):
        return False


def _model_category_to_subscription_type(model_category: Optional[str]) -> str:
    if model_category == "impersonation":
        return "phishing"
    if model_category == "history_similarity":
        return "history_similarity"
    if model_category == "dga":
        return "dga"
    if model_category == "apt_template_nrd":
        return "apt_template_nrd"
    return "malicious"


def _task_type_to_subscription_type(task_type: Optional[str]) -> str:
    if task_type == "impersonation":
        return "phishing"
    if task_type == "history_similarity":
        return "history_similarity"
    if task_type == "dga":
        return "dga"
    if task_type == "apt_template_nrd":
        return "apt_template_nrd"
    return "malicious"


def _extract_impersonation_alert_items(rows) -> List[dict]:
    """
    从仿冒检测结果 DataFrame 提取飞书/邮件附件预警明细。
    兼容列：仿冒域名、钓鱼域名、官方域名/目标域名、公司名称、单位类型、相似度、匹配类型、风险等级、最终风险分、命中原因、LLM研判标签、LLM研判分数、研判原因、LLM处置结果。
    """
    keep_dispositions = {"保留人工复核", "保留高危告警"}
    items: List[dict] = []
    seen = set()
    try:
        iterable = rows.to_dict("records")
    except Exception:
        return items

    for row in iterable:
        if not isinstance(row, dict):
            continue
        impersonation_domain = _clean_optional_text(
            row.get("仿冒域名") or row.get("钓鱼域名") or row.get("candidate_domain")
        )
        if not impersonation_domain:
            continue
        official_domain = _clean_optional_text(
            row.get("官方域名") or row.get("目标域名") or row.get("matched_target_domain")
        )
        official_unit_name = _clean_optional_text(
            row.get("公司名称")
            or row.get("单位名称")
            or row.get("官方域名单位名称")
            or row.get("matched_target_name")
        )
        official_unit_type = _clean_optional_text(
            row.get("单位类型")
            or row.get("官方域名单位类型")
            or row.get("matched_target_type")
            or row.get("target_type")
            or row.get("target_tier")
        )
        official_unit_subtype = _clean_optional_text(
            row.get("单位小类")
            or row.get("单位子类型")
            or row.get("官方域名单位小类")
            or row.get("matched_target_subtype")
            or row.get("target_subtype_label")
            or row.get("target_subtype")
        )
        similarity = _clean_optional_text(row.get("相似度") or row.get("final_score"))
        match_type = _clean_optional_text(row.get("匹配类型") or row.get("all_categories") or row.get("main_category"))
        risk_level = _clean_optional_text(row.get("风险等级") or row.get("risk_level"))
        final_risk_score = _clean_optional_text(row.get("最终风险分") or row.get("相似度") or row.get("final_score"))
        hit_reason = _clean_optional_text(row.get("命中原因") or row.get("reason"))
        llm_label = _clean_optional_text(row.get("LLM研判标签"))
        llm_score = _clean_optional_text(row.get("LLM研判分数"))
        llm_reason = _clean_optional_text(row.get("研判原因"))
        llm_disposition = _clean_optional_text(row.get("LLM处置结果") or row.get("LLM处置建议"))
        if llm_disposition and llm_disposition not in keep_dispositions:
            continue
        llm_key_features = _clean_optional_text(row.get("关键特征"))
        dedupe_key = (
            impersonation_domain.lower(),
            official_domain.lower(),
            official_unit_name.lower(),
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        items.append(
            {
                "official_domain": official_domain,
                "official_unit_name": official_unit_name,
                "official_unit_type": official_unit_type,
                "official_unit_subtype": official_unit_subtype,
                "impersonation_domain": impersonation_domain,
                "phishing_domain": impersonation_domain,
                "similarity": similarity,
                "match_type": match_type,
                "risk_level": risk_level,
                "final_risk_score": final_risk_score,
                "hit_reason": hit_reason,
                "llm_label": llm_label,
                "llm_score": llm_score,
                "llm_reason": llm_reason,
                "llm_disposition": llm_disposition,
                "llm_key_features": llm_key_features,
            }
        )
    return items


def _safe_optional_float(value) -> Optional[float]:
    text_value = _clean_optional_text(value)
    if not text_value:
        return None
    try:
        return float(text_value)
    except (TypeError, ValueError):
        return None


def _extract_dga_alert_items(rows) -> List[dict]:
    """
    从 DGA 检测结果 DataFrame 提取订阅预警明细。
    兼容旧版 DGA-like 字段，同时优先使用新版高置信 DGA 与家族识别字段。
    """
    items: List[dict] = []
    seen = set()
    try:
        iterable = rows.to_dict("records")
    except Exception:
        return items

    for row in iterable:
        if not isinstance(row, dict):
            continue
        domain = _clean_optional_text(row.get("域名") or row.get("domain"))
        if not domain:
            continue
        result_text = _clean_optional_text(row.get("预测结果"))
        label_text = _clean_optional_text(row.get("预测标签"))
        is_dga = result_text in {"高置信DGA", "DGA-like"} or label_text == "1"
        if not is_dga:
            continue
        domain_key = domain.lower()
        if domain_key in seen:
            continue
        seen.add(domain_key)
        score = _safe_optional_float(row.get("DGA_score") or row.get("dga_score"))
        family = _clean_optional_text(row.get("DGA家族") or row.get("predicted_family"))
        family_confidence = _safe_optional_float(row.get("家族置信度") or row.get("family_confidence"))
        family_status = _clean_optional_text(row.get("家族归因状态") or row.get("family_attribution_status"))
        reason = _clean_optional_text(row.get("命中方式") or row.get("命中原因") or row.get("reason"))
        items.append(
            {
                "domain": domain,
                "dga_score": score,
                "label": result_text or "高置信DGA",
                "family": family,
                "family_confidence": family_confidence,
                "family_attribution_status": family_status,
                "reason": reason or "达到DGA高置信检测口径",
                "raw": dict(row),
            }
        )
    return items


def _extract_apt_template_nrd_alert_items(rows) -> List[dict]:
    """
    从模板化APT域名检测结果 DataFrame 提取订阅预警明细。
    兼容列：域名、score、risk_level、风险等级、匹配模板、reason、命中原因。
    """
    items: List[dict] = []
    seen = set()
    try:
        iterable = rows.to_dict("records")
    except Exception:
        return items

    for row in iterable:
        if not isinstance(row, dict):
            continue
        domain = _clean_optional_text(row.get("域名") or row.get("domain"))
        if not domain:
            continue
        domain_key = domain.lower()
        if domain_key in seen:
            continue
        score = _safe_optional_float(row.get("score") or row.get("risk_score"))
        label_text = _clean_optional_text(row.get("预测标签"))
        result_text = _clean_optional_text(row.get("预测结果"))
        if label_text not in {"1", "1.0"} and result_text not in {"模板化APT命中", "APT模板命中"} and not (score is not None and score > 0):
            continue
        seen.add(domain_key)
        items.append(
            {
                "domain": domain,
                "score": score,
                "risk_score": score,
                "risk_level": _clean_optional_text(row.get("risk_level") or row.get("风险等级")),
                "matched_template": _clean_optional_text(row.get("匹配模板") or row.get("matched_template")),
                "reason": _clean_optional_text(row.get("reason") or row.get("命中原因")) or "命中模板化APT域名模板",
                "raw": dict(row),
            }
        )
    return items


def _build_alert_attachment_excel(
    *,
    task_type: str,
    high_risk_domains: List[str],
    phishing_alert_items: List[dict],
    dga_alert_items: Optional[List[dict]] = None,
    apt_template_nrd_alert_items: Optional[List[dict]] = None,
) -> bytes:
    """
    生成预警邮件附件 Excel。仿冒订阅按产品要求输出固定六列。
    """
    import pandas as pd

    rows = []
    if task_type == "impersonation":
        columns = ["疑似仿冒域名", "目标域名", "单位名称", "单位类型", "风险等级", "最终风险分", "LLM研判标签", "LLM研判分数", "研判原因", "LLM处置结果", "命中原因"]
        if phishing_alert_items:
            for item in phishing_alert_items:
                rows.append(
                    {
                        "疑似仿冒域名": item.get("impersonation_domain") or item.get("phishing_domain", ""),
                        "目标域名": item.get("official_domain", ""),
                        "单位名称": item.get("official_unit_name", ""),
                        "单位类型": item.get("official_unit_type", ""),
                        "风险等级": item.get("risk_level", ""),
                        "最终风险分": item.get("final_risk_score", ""),
                        "LLM研判标签": item.get("llm_label", ""),
                        "LLM研判分数": item.get("llm_score", ""),
                        "研判原因": item.get("llm_reason", ""),
                        "LLM处置结果": item.get("llm_disposition", ""),
                        "命中原因": item.get("hit_reason", ""),
                    }
                )
    elif task_type == "history_similarity":
        columns = ["高风险域名", "风险等级", "最终风险分", "命中原因"]
        for domain in high_risk_domains:
            rows.append(
                {
                    "高风险域名": domain,
                    "风险等级": "",
                    "最终风险分": "",
                    "命中原因": "与历史APT域名高度相似",
                }
            )
    elif task_type == "dga":
        columns = ["DGA域名", "DGA_score", "预测结果", "DGA家族", "家族置信度", "家族归因状态", "命中原因"]
        for item in dga_alert_items or []:
            score = item.get("dga_score")
            family_confidence = item.get("family_confidence")
            rows.append(
                {
                    "DGA域名": item.get("domain", ""),
                    "DGA_score": "" if score is None else f"{float(score):.6f}",
                    "预测结果": item.get("label") or "高置信DGA",
                    "DGA家族": item.get("family") or "",
                    "家族置信度": "" if family_confidence is None else f"{float(family_confidence):.6f}",
                    "家族归因状态": item.get("family_attribution_status") or "",
                    "命中原因": item.get("reason") or "达到DGA高置信检测口径",
                }
            )
        if not rows:
            for domain in high_risk_domains:
                rows.append(
                    {
                        "DGA域名": domain,
                        "DGA_score": "",
                        "预测结果": "高置信DGA",
                        "DGA家族": "",
                        "家族置信度": "",
                        "家族归因状态": "",
                        "命中原因": "达到DGA高置信检测口径",
                    }
                )
    elif task_type == "apt_template_nrd":
        columns = ["模板化APT域名", "风险分", "风险等级", "匹配模板", "命中原因"]
        for item in apt_template_nrd_alert_items or []:
            score = item.get("score")
            rows.append(
                {
                    "模板化APT域名": item.get("domain", ""),
                    "风险分": "" if score is None else f"{float(score):.6f}",
                    "风险等级": item.get("risk_level", ""),
                    "匹配模板": item.get("matched_template", ""),
                    "命中原因": item.get("reason") or "命中模板化APT域名模板",
                }
            )
        if not rows:
            for domain in high_risk_domains:
                rows.append(
                    {
                        "模板化APT域名": domain,
                        "风险分": "",
                        "风险等级": "",
                        "匹配模板": "",
                        "命中原因": "命中模板化APT域名模板",
                    }
                )
    else:
        columns = ["高风险域名", "风险等级", "最终风险分", "命中原因"]
        for domain in high_risk_domains:
            rows.append(
                {
                    "高风险域名": domain,
                    "风险等级": "",
                    "最终风险分": "",
                    "命中原因": "",
                }
            )

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        pd.DataFrame(rows, columns=columns).to_excel(writer, sheet_name="预警域名", index=False)
    return output.getvalue()


def execute_subscription(subscription_id: str):
    """执行订阅任务"""
    db = SessionLocal()
    try:
        subscription = db.query(Subscription).filter(
            Subscription.subscription_id == subscription_id,
            Subscription.is_active == True
        ).first()
        
        if not subscription:
            logger.warning(f"订阅 {subscription_id} 不存在或已取消")
            return
        
        # 检查是否到了执行时间
        now = beijing_now()
        # 如果next_run_at没有时区信息，假设是北京时间
        next_run_at = subscription.next_run_at
        if next_run_at.tzinfo is None:
            next_run_at = next_run_at.replace(tzinfo=BEIJING_TZ)
        elif next_run_at.tzinfo != BEIJING_TZ:
            next_run_at = next_run_at.astimezone(BEIJING_TZ)
        
        if next_run_at > now:
            logger.info(f"订阅 {subscription_id} 还未到执行时间，下次执行时间: {subscription.next_run_at}, 当前时间: {now}")
            return
        
        logger.info(f"开始执行订阅任务: {subscription_id}, 下次执行时间: {subscription.next_run_at}, 当前时间: {now}")
        
        # 获取模型信息
        model = db.query(Model).filter(Model.id == subscription.model_id).first()
        if not model:
            logger.error(f"模型 {subscription.model_id} 不存在，更新下次执行时间后跳过")
            subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(subscription.frequency))
            db.commit()
            return
        
        # 获取用户信息
        user = db.query(User).filter(User.id == subscription.user_id).first()
        if not user:
            logger.error(f"用户 {subscription.user_id} 不存在，更新下次执行时间后跳过")
            subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(subscription.frequency))
            db.commit()
            return
        
        # 获取上次检测的最后日期（从最近的Task记录中获取）
        last_checked_date = None
        last_task = db.query(Task).filter(
            Task.created_by == subscription.user_id,
            Task.model_id == subscription.model_id
        ).order_by(Task.created_at.desc()).first()
        
        if last_task and last_task.extra:
            task_extra = _normalize_extra(last_task.extra)
            # 检查是否是订阅任务
            if task_extra.get("subscription_id") == subscription_id:
                date_range_str = task_extra.get("dateRange")
                if date_range_str and isinstance(date_range_str, list) and len(date_range_str) >= 2:
                    try:
                        # 获取上次检测的结束日期
                        last_checked_date = _parse_date_string(date_range_str[1])
                        logger.info(f"订阅 {subscription_id} 上次检测到: {last_checked_date}")
                    except Exception as e:
                        logger.warning(f"解析上次检测日期失败: {date_range_str}, 错误: {e}")
        
        # 计算日期范围（考虑数据延迟和上次检测日期）
        date_range = _get_date_range_for_frequency(subscription.frequency, last_checked_date)
        
        # 如果没有新数据需要检测，更新下次执行时间并返回
        if not date_range:
            logger.info(f"订阅 {subscription_id} 没有新数据需要检测（上次检测日期: {last_checked_date}）")
            subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(subscription.frequency))
            db.commit()
            return
        
        # 解析日期范围的结束日期，用于更新last_checked_date
        try:
            date_range_end = _parse_date_string(date_range[1])
        except Exception as e:
            logger.warning(f"解析日期范围结束日期失败: {date_range[1]}, 错误: {e}")
            date_range_end = None
        
        # 生成任务ID
        task_id = f"T{int(beijing_now().timestamp())}"
        # 仅恶意订阅：逐条预测结果（含恶意概率），供预警按阈值筛选
        results_malicious_subscription = None
        results_history_similarity_subscription = None
        results_dga_subscription = None
        word_report_content = None
        results_apt_template_nrd_subscription = None

        # 根据模型类型执行不同的检测
        if model.model_category == "impersonation":
            # 仿冒域名检测
            official_file = None
            official_file_content = None
            official_filename = ""
            official_source = "full_whitelist"
            official_whitelist_path = ""

            if subscription.official_file_id:
                official_source = "uploaded_file"
                official_file = db.query(StoredFile).filter(StoredFile.id == subscription.official_file_id).first()
                if not official_file:
                    logger.error(f"官方文件 {subscription.official_file_id} 不存在，更新下次执行时间后跳过")
                    subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(subscription.frequency))
                    db.commit()
                    return

                # 下载官方文件
                official_file_content = download_file_from_minio(
                    official_file.object_key,
                    official_file.bucket
                )
                official_filename = official_file.filename or "unknown"
            else:
                try:
                    official_file_content, official_filename, official_whitelist_path = _load_full_whitelist_file()
                    logger.info(
                        "订阅 %s 未绑定官方文件，使用系统全量白名单: %s",
                        subscription_id,
                        official_whitelist_path,
                    )
                except Exception as exc:
                    logger.error(f"订阅 {subscription_id} 无法加载系统全量白名单，更新下次执行时间后跳过: {exc}")
                    subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(subscription.frequency))
                    db.commit()
                    return
            
            # 收集每日域名（使用订阅专用函数，不会因为没有数据而报错）
            detection_domains, missing_dates = _collect_daily_domains_for_subscription(date_range)
            if not detection_domains:
                logger.warning(f"订阅 {subscription_id} 在日期范围内没有可用的域名数据，缺失日期: {missing_dates}")
                # 更新下次执行时间，即使没有数据也继续
                subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(subscription.frequency))
                db.commit()
                return
            
            # 读取官方域名
            official_domains = read_official_domains_from_file(
                official_file_content,
                official_filename
            )
            
            # 执行检测
            # 将阈值从0-100转换为0-1（相似度阈值范围）
            similarity_threshold = subscription.threshold / 100.0 if subscription.threshold is not None else None
            
            excel_content, statistics, word_report_content = phishing_predict_from_domains_with_report(
                official_domains,
                detection_domains,
                similarity_threshold=similarity_threshold
            )
            
            # 创建任务记录
            task = Task(
                task_id=task_id,
                task_type="impersonation",
                model_id=model.id,
                file_id=official_file.id if official_file else None,
                extra={
                    "detectionSource": "newDomain",
                    "dateRange": date_range,
                    "subscription_id": subscription_id,
                    "official_source": official_source,
                    "official_whitelist_path": official_whitelist_path,
                },
                status="processing",
                created_by=subscription.user_id,
            )
            db.add(task)
            db.flush()
            
        elif model.model_category == "history_similarity":
            domains, missing_dates = _collect_daily_domains_for_subscription(date_range)
            if not domains:
                logger.warning(f"订阅 {subscription_id} 在日期范围内没有可用的域名数据，缺失日期: {missing_dates}")
                subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(subscription.frequency))
                db.commit()
                return

            source_label = f"subscription_{subscription_id}"
            min_score = float(subscription.threshold) / 100.0 if subscription.threshold is not None else 0.65
            excel_content, statistics, history_meta, history_alert_rows = history_similarity_predict_from_domains(
                domains,
                source_label,
                model.model_path,
                min_score=min_score,
                top_k=10,
                suspicious_only=True,
            )
            results_history_similarity_subscription = history_alert_rows_to_score_records(history_alert_rows)

            task = Task(
                task_id=task_id,
                task_type="history_similarity",
                model_id=model.id,
                file_id=None,
                extra={
                    "dataSource": "newDomain",
                    "dateRange": date_range,
                    "subscription_id": subscription_id,
                    "min_score": min_score,
                    "min_score_percent": int(round(min_score * 100)),
                    "top_k": 10,
                    "history_similarity_detection": history_meta,
                    "history_similarity_alert_rows": results_history_similarity_subscription,
                },
                status="processing",
                created_by=subscription.user_id,
            )
            db.add(task)
            db.flush()

        elif model.model_category == "dga":
            domains, missing_dates = _collect_daily_domains_for_subscription(date_range)
            if not domains:
                logger.warning(f"订阅 {subscription_id} 在日期范围内没有可用的域名数据，缺失日期: {missing_dates}")
                subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(subscription.frequency))
                db.commit()
                return

            source_label = f"subscription_{subscription_id}"
            candidate_threshold = (
                float(subscription.threshold) / 100.0
                if subscription.threshold is not None
                else 0.90
            )
            excel_content, statistics, dga_meta = dga_predict_from_domains(
                domains,
                source_label,
                model.model_path,
                candidate_threshold=candidate_threshold,
            )

            task = Task(
                task_id=task_id,
                task_type="dga",
                model_id=model.id,
                file_id=None,
                extra={
                    "dataSource": "newDomain",
                    "dateRange": date_range,
                    "subscription_id": subscription_id,
                    "candidate_threshold": candidate_threshold,
                    "dga_detection": dga_meta,
                },
                status="processing",
                created_by=subscription.user_id,
            )
            db.add(task)
            db.flush()

        elif model.model_category == "apt_template_nrd":
            domains, missing_dates = _collect_daily_domains_for_subscription(date_range)
            if not domains:
                logger.warning(f"订阅 {subscription_id} 在日期范围内没有可用的域名数据，缺失日期: {missing_dates}")
                subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(subscription.frequency))
                db.commit()
                return

            source_label = f"subscription_{subscription_id}"
            score_threshold = (
                float(subscription.threshold) / 100.0
                if subscription.threshold is not None
                else 0.90
            )
            excel_content, statistics, apt_meta, apt_alert_rows = apt_template_nrd_predict_from_domains(
                domains,
                source_label,
                model.model_path,
                score_threshold=score_threshold,
                high_risk_only=False,
            )
            results_apt_template_nrd_subscription = apt_template_nrd_alert_rows_to_score_records(apt_alert_rows)

            task = Task(
                task_id=task_id,
                task_type="apt_template_nrd",
                model_id=model.id,
                file_id=None,
                extra={
                    "dataSource": "newDomain",
                    "dateRange": date_range,
                    "subscription_id": subscription_id,
                    "score_threshold": score_threshold,
                    "score_threshold_percent": int(round(score_threshold * 100)),
                    "apt_template_nrd_detection": apt_meta,
                    "apt_template_nrd_alert_rows": results_apt_template_nrd_subscription,
                },
                status="processing",
                created_by=subscription.user_id,
            )
            db.add(task)
            db.flush()

        else:
            # 恶意性检测
            domains, missing_dates = _collect_daily_domains_for_subscription(date_range)
            if not domains:
                logger.warning(f"订阅 {subscription_id} 在日期范围内没有可用的域名数据，缺失日期: {missing_dates}")
                # 更新下次执行时间，即使没有数据也继续
                subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(subscription.frequency))
                db.commit()
                return
            
            source_label = f"subscription_{subscription_id}"
            # 与非订阅一致：标签由 model.predict 决定；恶意概率写入结果；预警再按订阅阈值/100 筛选
            excel_content, statistics, results_malicious_subscription = predict_from_domains_subscription(
                domains,
                source_label,
                model.model_path,
                malicious_only=True,
            )
            
            # 创建任务记录
            task = Task(
                task_id=task_id,
                task_type="malicious",
                model_id=model.id,
                file_id=None,
                extra={
                    "dataSource": "newDomain",
                    "dateRange": date_range,
                    "subscription_id": subscription_id,
                },
                status="processing",
                created_by=subscription.user_id,
            )
            db.add(task)
            db.flush()
        
        # 上传结果文件。报告型检测以 PDF 报告作为主结果文件，
        # 同时保存 JSON 辅助结果给在线查看接口使用。
        result_content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        result_file_id = None
        result_data_file_id = None
        result_data_key = None
        result_data_filename = None
        result_data_content_type = None
        word_report_key = None
        word_report_filename = None
        if model.model_category == "history_similarity":
            timestamp = beijing_now().strftime("%Y%m%d_%H%M%S")
            result_filename = f"history_apt_similarity_report_{task_id}_{timestamp}.pdf"
            result_data_filename = f"history_apt_similarity_result_{task_id}_{timestamp}.json"
            result_payload = build_history_similarity_result_payload(
                excel_content,
                task_id=task_id,
                history_meta=task.extra.get("history_similarity_detection") or {},
            )
            report_content = generate_history_similarity_pdf_report(
                result_payload,
                task_id=task_id,
                model_name=(
                    str(model.name or "")
                    .replace("历史高度相似检测", "历史APT域名相似性检测")
                    .replace("历史高度相似", "历史APT域名相似")
                ),
                data_source="newDomain",
                min_score=float(task.extra.get("min_score") or 0.65),
                top_k=int(task.extra.get("top_k") or 10),
                date_range=date_range,
                generated_at=beijing_now().replace(tzinfo=None),
            )
            result_key = upload_file_content_to_minio(
                report_content,
                result_filename,
                content_type="application/pdf",
                bucket=RESULTS_BUCKET,
            )
            result_payload["result_file_key"] = result_key
            result_payload["result_filename"] = result_filename
            result_data_content = build_history_similarity_result_json(result_payload)
            result_data_key = upload_file_content_to_minio(
                result_data_content,
                result_data_filename,
                content_type="application/json",
                bucket=RESULTS_BUCKET,
            )
            result_content_type = "application/pdf"
            result_data_content_type = "application/json"

            report_file_record = StoredFile(
                bucket=RESULTS_BUCKET,
                object_key=result_key,
                filename=result_filename,
                content_type=result_content_type,
                size=len(report_content),
                uploaded_by=str(subscription.user_id),
                metadata_json={
                    "source": "history_similarity_pdf_report",
                    "task_id": task_id,
                    "task_type": "history_similarity",
                    "subscription_id": subscription_id,
                },
            )
            db.add(report_file_record)
            db.flush()
            result_file_id = report_file_record.id
            result_data_file_record = StoredFile(
                bucket=RESULTS_BUCKET,
                object_key=result_data_key,
                filename=result_data_filename,
                content_type=result_data_content_type,
                size=len(result_data_content),
                uploaded_by=str(subscription.user_id),
                metadata_json={
                    "source": "history_similarity_result_json",
                    "task_id": task_id,
                    "task_type": "history_similarity",
                    "subscription_id": subscription_id,
                },
            )
            db.add(result_data_file_record)
            db.flush()
            result_data_file_id = result_data_file_record.id
        elif model.model_category == "apt_template_nrd":
            timestamp = beijing_now().strftime("%Y%m%d_%H%M%S")
            result_filename = f"apt_template_nrd_report_{task_id}_{timestamp}.pdf"
            result_data_filename = f"apt_template_nrd_result_{task_id}_{timestamp}.json"
            result_payload = build_apt_template_nrd_result_payload(
                excel_content,
                task_id=task_id,
                apt_meta=task.extra.get("apt_template_nrd_detection") or {},
            )
            report_content = generate_apt_template_nrd_pdf_report(
                result_payload,
                task_id=task_id,
                model_name=str(model.name or "").replace("APT模板新注册域名检测", "模板化APT域名检测"),
                data_source="newDomain",
                score_threshold=float(task.extra.get("score_threshold") or 0.90),
                date_range=date_range,
                generated_at=beijing_now().replace(tzinfo=None),
            )
            result_key = upload_file_content_to_minio(
                report_content,
                result_filename,
                content_type="application/pdf",
                bucket=RESULTS_BUCKET,
            )
            result_payload["result_file_key"] = result_key
            result_payload["result_filename"] = result_filename
            result_data_content = build_apt_template_nrd_result_json(result_payload)
            result_data_key = upload_file_content_to_minio(
                result_data_content,
                result_data_filename,
                content_type="application/json",
                bucket=RESULTS_BUCKET,
            )
            result_content_type = "application/pdf"
            result_data_content_type = "application/json"

            report_file_record = StoredFile(
                bucket=RESULTS_BUCKET,
                object_key=result_key,
                filename=result_filename,
                content_type=result_content_type,
                size=len(report_content),
                uploaded_by=str(subscription.user_id),
                metadata_json={
                    "source": "apt_template_nrd_pdf_report",
                    "task_id": task_id,
                    "task_type": "apt_template_nrd",
                    "subscription_id": subscription_id,
                },
            )
            db.add(report_file_record)
            db.flush()
            result_file_id = report_file_record.id
            result_data_file_record = StoredFile(
                bucket=RESULTS_BUCKET,
                object_key=result_data_key,
                filename=result_data_filename,
                content_type=result_data_content_type,
                size=len(result_data_content),
                uploaded_by=str(subscription.user_id),
                metadata_json={
                    "source": "apt_template_nrd_result_json",
                    "task_id": task_id,
                    "task_type": "apt_template_nrd",
                    "subscription_id": subscription_id,
                },
            )
            db.add(result_data_file_record)
            db.flush()
            result_data_file_id = result_data_file_record.id
        else:
            result_filename = f"result_{task_id}_{beijing_now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            result_key = upload_file_content_to_minio(
                excel_content,
                result_filename,
                content_type=result_content_type,
                bucket=RESULTS_BUCKET
            )
            if model.model_category == "impersonation" and word_report_content:
                word_report_filename = f"prediction_report_{task_id}_{beijing_now().strftime('%Y%m%d_%H%M%S')}.docx"
                word_report_key = upload_file_content_to_minio(
                    word_report_content,
                    word_report_filename,
                    content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    bucket=RESULTS_BUCKET,
                )
        
        # 更新任务extra
        result_extra = {
            "result_file_key": result_key,
            "result_bucket": RESULTS_BUCKET,
            "result_filename": result_filename,
            "result_content_type": result_content_type,
            "statistics": statistics,
            "completed_at": beijing_now().isoformat(),
        }
        if word_report_key:
            result_extra.update({
                "word_report_file_key": word_report_key,
                "word_report_bucket": RESULTS_BUCKET,
                "word_report_filename": word_report_filename,
            })
        if result_file_id is not None:
            result_extra["result_file_id"] = result_file_id
        if result_data_key:
            result_extra.update({
                "result_data_file_id": result_data_file_id,
                "result_data_file_key": result_data_key,
                "result_data_bucket": RESULTS_BUCKET,
                "result_data_filename": result_data_filename,
                "result_data_content_type": result_data_content_type,
            })
        task.extra = {**(task.extra or {}), **result_extra}
        db.commit()
        db.refresh(task)

        # 检查是否需要创建预警
        high_risk_count = 0
        high_risk_domains = []
        phishing_alert_items = []
        dga_alert_items = []
        apt_template_nrd_alert_items = []
        
        # 从Excel结果中提取高风险域名列表
        try:
            import pandas as pd
            excel_file = io.BytesIO(excel_content)
            
            if model.model_category == "impersonation":
                # 仿冒检测：从统计信息中获取仿冒域名数量
                high_risk_count = (
                    statistics.get("impersonation", 0)
                    or statistics.get("phishing", 0)
                    or statistics.get("仿冒域名数", 0)
                    or statistics.get("仿冒域名数量", 0)
                    or statistics.get("钓鱼域名数量", 0)
                    or statistics.get("检测到的仿冒域名数量", 0)
                    or statistics.get("检测到的钓鱼域名数量", 0)
                )

                # 从Excel中提取仿冒域名列表（提取所有，不限制数量）
                try:
                    results_df = pd.read_excel(excel_file, sheet_name='检测结果')
                    domain_column = "仿冒域名" if "仿冒域名" in results_df.columns else "钓鱼域名"
                    phishing_rows = results_df[results_df[domain_column].notna()]
                    phishing_alert_items = _extract_impersonation_alert_items(phishing_rows)
                except Exception as e:
                    logger.warning(f"从Excel提取仿冒域名列表失败: {e}")
                    try:
                        # 尝试从仿冒域名列表工作表读取，兼容旧的钓鱼域名列表工作表
                        excel_file.seek(0)
                        try:
                            phishing_df = pd.read_excel(excel_file, sheet_name='仿冒域名列表')
                        except Exception:
                            excel_file.seek(0)
                            phishing_df = pd.read_excel(excel_file, sheet_name='钓鱼域名列表')
                        if '仿冒域名' in phishing_df.columns or '钓鱼域名' in phishing_df.columns:
                            phishing_alert_items = _extract_impersonation_alert_items(phishing_df)
                        else:
                            high_risk_domains = []
                    except:
                        pass
                high_risk_domains = []
                seen_impersonation_domains = set()
                phishing_alert_items = [
                    item for item in phishing_alert_items
                    if _impersonation_item_is_medium_or_high(item)
                ]
                for item in phishing_alert_items:
                    domain = _clean_optional_text(item.get("impersonation_domain") or item.get("phishing_domain"))
                    domain_key = domain.lower()
                    if domain and domain_key not in seen_impersonation_domains:
                        seen_impersonation_domains.add(domain_key)
                        high_risk_domains.append(domain)
                high_risk_count = len(high_risk_domains)
            elif model.model_category == "history_similarity":
                high_risk_domains = []
                seen = set()
                for item in results_history_similarity_subscription or []:
                    d = item.get("domain") or item.get("域名")
                    if not d:
                        continue
                    d = str(d).strip()
                    d_key = d.lower()
                    if d and d_key not in seen:
                        seen.add(d_key)
                        high_risk_domains.append(d)
                high_risk_count = len(high_risk_domains)
            elif model.model_category == "dga":
                dga_alert_items = []
                try:
                    excel_file.seek(0)
                    dga_df = pd.read_excel(excel_file, sheet_name="DGA域名列表")
                    dga_alert_items = _extract_dga_alert_items(dga_df)
                except Exception:
                    try:
                        excel_file.seek(0)
                        results_df = pd.read_excel(excel_file, sheet_name="预测结果")
                        dga_alert_items = _extract_dga_alert_items(results_df)
                    except Exception as dga_extract_error:
                        logger.warning(f"从DGA结果中提取预警域名失败: {dga_extract_error}")

                high_risk_domains = []
                seen = set()
                results_dga_subscription = []
                for item in dga_alert_items:
                    d = item.get("domain")
                    if not d:
                        continue
                    d = str(d).strip()
                    d_key = d.lower()
                    if d and d_key not in seen:
                        seen.add(d_key)
                        high_risk_domains.append(d)
                    results_dga_subscription.append(
                        {
                            "domain": d,
                            "score": item.get("dga_score"),
                            "dga_score": item.get("dga_score"),
                            "label": item.get("label") or "高置信DGA",
                            "family": item.get("family"),
                            "family_confidence": item.get("family_confidence"),
                            "family_attribution_status": item.get("family_attribution_status"),
                            "reason": item.get("reason") or "达到DGA高置信检测口径",
                            "raw": item.get("raw") or {},
                        }
                    )
                high_risk_count = len(high_risk_domains)
            elif model.model_category == "apt_template_nrd":
                apt_template_nrd_alert_items = []
                for item in results_apt_template_nrd_subscription or []:
                    if isinstance(item, dict):
                        apt_template_nrd_alert_items.append(item)
                if not apt_template_nrd_alert_items:
                    try:
                        excel_file.seek(0)
                        try:
                            apt_df = pd.read_excel(excel_file, sheet_name="模板化APT域名列表")
                        except Exception:
                            excel_file.seek(0)
                            apt_df = pd.read_excel(excel_file, sheet_name="APT模板命中域名列表")
                        apt_template_nrd_alert_items = _extract_apt_template_nrd_alert_items(apt_df)
                    except Exception:
                        try:
                            excel_file.seek(0)
                            results_df = pd.read_excel(excel_file, sheet_name="预测结果")
                            apt_template_nrd_alert_items = _extract_apt_template_nrd_alert_items(results_df)
                        except Exception as apt_extract_error:
                            logger.warning(f"从模板化APT域名检测结果中提取预警域名失败: {apt_extract_error}")

                high_risk_domains = []
                seen = set()
                normalized_records = []
                for item in apt_template_nrd_alert_items:
                    d = item.get("domain") or item.get("域名")
                    if not d:
                        continue
                    d = str(d).strip()
                    d_key = d.lower()
                    if d and d_key not in seen:
                        seen.add(d_key)
                        high_risk_domains.append(d)
                    normalized_records.append(
                        {
                            "domain": d,
                            "score": item.get("score") or item.get("risk_score"),
                            "risk_score": item.get("risk_score") or item.get("score"),
                            "risk_level": item.get("risk_level"),
                            "matched_template": item.get("matched_template"),
                            "reason": item.get("reason") or "命中模板化APT域名模板",
                            "raw": item.get("raw") or {},
                        }
                    )
                results_apt_template_nrd_subscription = normalized_records
                apt_template_nrd_alert_items = normalized_records
                high_risk_count = len(high_risk_domains)
            else:
                # 恶意订阅预警：
                # - 默认策略：model.predict 判为恶意的结果全部预警
                # - 自定义阈值：预测标签为恶意且恶意概率 > 阈值/100
                cutoff = (
                    float(subscription.threshold) / 100.0
                    if subscription.threshold is not None
                    else None
                )
                high_risk_domains = []
                high_risk_count = 0
                if results_malicious_subscription:
                    seen = set()
                    for r in results_malicious_subscription:
                        if int(r.get("预测标签", 0)) != 1:
                            continue
                        if cutoff is not None:
                            prob = float(r.get("恶意概率", 0.0))
                            if prob <= cutoff:
                                continue
                        d = r.get("域名") or r.get("domain")
                        if not d:
                            continue
                        d = str(d).strip()
                        if d and d not in seen:
                            seen.add(d)
                            high_risk_domains.append(d)
                    high_risk_count = len(high_risk_domains)
        except Exception as e:
            logger.warning(f"解析Excel结果文件失败: {e}")
        
        # 计算总数
        total_count = statistics.get("total", 0) or statistics.get("总域名数", 0) or statistics.get("检测域名总数", 0) or statistics.get("总数量", 0)
        
        # 仿冒：原逻辑；恶意/历史相似：存在高风险结果时触发预警
        if model.model_category == "impersonation":
            trigger_alert = high_risk_count > 0 and len(high_risk_domains) > 0
        else:
            trigger_alert = len(high_risk_domains) > 0

        if trigger_alert:
            alert_id = f"A{int(beijing_now().timestamp())}"
            
            # 计算高风险比例（用于记录，但不作为发送邮件的条件）
            if total_count > 0:
                risk_ratio = (high_risk_count / total_count) * 100
            else:
                risk_ratio = 0
            
            # 创建预警记录（alerts 表不含 high_risk_domains）
            alert = Alert(
                alert_id=alert_id,
                subscription_id=subscription_id,
                task_id=task_id,
                user_id=subscription.user_id,
                model_id=model.id,
                model_name=model.name,
                task_type=task.task_type,
                detected_count=total_count,
                high_risk_count=high_risk_count,
                threshold=subscription.threshold,
                status="pending",
            )
            db.add(alert)
            db.flush()
            db.flush()

            # 新流程：组织关联匹配 -> 组装 JSON -> 上传 MinIO+写 files -> 写 alert_files
            match_results_by_domain = {}
            for domain in high_risk_domains:
                domain_name = str(domain or "").strip()
                if not domain_name:
                    continue
                try:
                    match_results_by_domain[domain_name.lower()] = match_domain_to_actors_v2_infra(
                        domain_name,
                        [],
                        db=db,
                    )
                except Exception:
                    logger.exception("组织匹配失败，已按空匹配继续 domain=%s alert_id=%s", domain_name, alert_id)
                    match_results_by_domain[domain_name.lower()] = {"domain_name": domain_name}

            if task.task_type == "history_similarity":
                risk_score_records = results_history_similarity_subscription
            elif task.task_type == "dga":
                risk_score_records = results_dga_subscription
            elif task.task_type == "apt_template_nrd":
                risk_score_records = results_apt_template_nrd_subscription
            else:
                risk_score_records = results_malicious_subscription

            alert_result_json = build_alert_result_json(
                alert_row=alert,
                subscription_row=subscription,
                task_row=task,
                high_risk_domains=high_risk_domains,
                match_results=match_results_by_domain,
                results_malicious_subscription=risk_score_records,
                impersonation_matches=phishing_alert_items,
                detected_count=total_count,
                high_risk_count=high_risk_count,
                alert_time=alert.created_at or beijing_now(),
            )

            archive_bucket = None
            archive_object_key = None
            try:
                stored_file = save_alert_result_json_to_minio(
                    db,
                    alert_id=alert_id,
                    subscription_id=subscription_id,
                    task_id=task_id,
                    user_id=subscription.user_id,
                    model_id=model.id,
                    task_type=task.task_type,
                    alert_time=alert.created_at or beijing_now(),
                    json_data=alert_result_json,
                )
                archive_bucket = stored_file.bucket
                archive_object_key = stored_file.object_key
                create_alert_file_mapping(
                    db,
                    alert_id=alert_id,
                    subscription_id=subscription_id,
                    task_id=task_id,
                    user_id=subscription.user_id,
                    model_id=model.id,
                    task_type=task.task_type,
                    frequency=subscription.frequency,
                    file_id=stored_file.id,
                    domain_count=high_risk_count,
                    alert_date=(alert.created_at or beijing_now()).date(),
                    file_role="full_result",
                    file_format="json",
                )
            except Exception as archive_error:
                if isinstance(archive_error, AlertResultStorageError):
                    archive_bucket = archive_bucket or archive_error.bucket
                    archive_object_key = archive_object_key or archive_error.object_key
                db.rollback()

                # files 成功但 alert_files 失败时，补偿删除 MinIO 文件，避免孤儿对象
                if archive_bucket and archive_object_key:
                    try:
                        minio_client.remove_object(archive_bucket, archive_object_key)
                    except Exception:
                        logger.exception(
                            "预警归档回滚时删除 MinIO 对象失败 alert_id=%s subscription_id=%s task_id=%s bucket=%s object_key=%s",
                            alert_id,
                            subscription_id,
                            task_id,
                            archive_bucket,
                            archive_object_key,
                        )

                # 归档失败后明确标记 task 状态，避免出现“completed 但归档失败”的语义不一致
                try:
                    failed_task = db.query(Task).filter(Task.task_id == task_id).first()
                    if failed_task:
                        failed_extra = dict(failed_task.extra or {})
                        failed_extra["archive_failed"] = True
                        failed_extra["archive_error"] = str(archive_error)
                        if archive_bucket:
                            failed_extra["archive_bucket"] = archive_bucket
                        if archive_object_key:
                            failed_extra["archive_object_key"] = archive_object_key
                        failed_extra["archive_failed_at"] = beijing_now().isoformat()
                        failed_task.extra = failed_extra
                        failed_task.status = "failed"
                        db.commit()
                except Exception:
                    db.rollback()
                    logger.exception(
                        "归档失败后更新 task 状态失败 subscription_id=%s task_id=%s",
                        subscription_id,
                        task_id,
                    )

                logger.exception(
                    "预警结果归档失败（JSON->MinIO->files->alert_files） alert_id=%s subscription_id=%s task_id=%s bucket=%s object_key=%s",
                    alert_id,
                    subscription_id,
                    task_id,
                    archive_bucket,
                    archive_object_key,
                )
                raise

            task.status = "completed"
            db.commit()
            db.refresh(alert)

            if task.task_type in {"malicious", "impersonation"}:
                try:
                    monitor_risk_records = (
                        phishing_alert_items
                        if task.task_type == "impersonation"
                        else risk_score_records
                    )
                    monitor_summary = register_monitor_targets(
                        db,
                        user_id=subscription.user_id,
                        domains=high_risk_domains,
                        source_type="subscription_alert",
                        task_id=task_id,
                        task_type=task.task_type,
                        model_id=model.id,
                        subscription_id=subscription_id,
                        alert_id=alert_id,
                        risk_records=monitor_risk_records,
                        detected_at=alert.created_at or beijing_now().replace(tzinfo=None),
                    )
                    db.commit()
                    logger.info(
                        "订阅预警域名已注册持续监控 alert_id=%s subscription_id=%s summary=%s",
                        alert_id,
                        subscription_id,
                        monitor_summary,
                    )
                except Exception:
                    db.rollback()
                    logger.exception(
                        "订阅预警域名注册持续监控失败（不影响预警主流程） alert_id=%s subscription_id=%s",
                        alert_id,
                        subscription_id,
                    )
            
            logger.info(f"创建预警: {alert_id}, {high_risk_count} 个高风险域名，高风险比例: {risk_ratio:.2f}%")
            
            # 生成预警邮件 Excel 附件
            attachment_content = None
            try:
                attachment_content = _build_alert_attachment_excel(
                    task_type=task.task_type,
                    high_risk_domains=high_risk_domains,
                    phishing_alert_items=phishing_alert_items,
                    dga_alert_items=dga_alert_items,
                    apt_template_nrd_alert_items=apt_template_nrd_alert_items,
                )
            except Exception as e:
                logger.warning(f"生成预警Excel附件失败: {e}")
            
            # 预警通知：仅在预警记录已提交后调用（与「检测任务完成」无关）
            alert_data = build_alert_data_dict(
                alert_id=alert_id,
                model_name=model.name,
                task_type=task.task_type,
                detected_count=total_count,
                high_risk_count=high_risk_count,
                threshold=subscription.threshold,
                created_at=alert.created_at.isoformat() if alert.created_at else beijing_now().isoformat(),
                high_risk_domains=high_risk_domains,
                match_results_by_domain=match_results_by_domain,
                impersonation_matches=phishing_alert_items,
                history_similarity_records=(
                    results_history_similarity_subscription
                    if task.task_type == "history_similarity"
                    else []
                ),
                dga_records=(
                    results_dga_subscription
                    if task.task_type == "dga"
                    else []
                ),
                apt_template_nrd_records=(
                    results_apt_template_nrd_subscription
                    if task.task_type == "apt_template_nrd"
                    else []
                ),
            )
            try:
                dispatch_alert_notifications(
                    db,
                    alert_row=alert,
                    alert_data=alert_data,
                    domains_attachment_content=attachment_content,
                    user_id=subscription.user_id,
                )
            except Exception:
                logger.exception("预警通知分发异常（已吞掉，不影响订阅主流程）")
        else:
            logger.info(
                f"订阅 {subscription_id} 本次检测未满足预警条件（仿冒按相似度规则；恶意订阅默认预警所有模型判恶意结果，启用自定义阈值时需恶意概率>阈值/100），跳过预警"
            )

            task.status = "completed"
        
        # 更新订阅的下次执行时间
        subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(subscription.frequency))
        
        # 记录本次检测的日期范围（已在Task.extra中记录，这里只是日志）
        if date_range:
            logger.info(f"订阅 {subscription_id} 本次检测日期范围: {date_range[0]} 到 {date_range[1]}")
        
        db.commit()
        
        logger.info(f"订阅任务 {subscription_id} 执行完成，下次执行时间: {subscription.next_run_at}")
        
    except Exception as e:
        logger.exception(f"执行订阅任务失败: {subscription_id}, 错误: {e}")
        try:
            db.rollback()
        except Exception:
            pass
        # 即使发生异常，也更新下次执行时间，避免订阅卡住
        try:
            subscription = db.query(Subscription).filter(
                Subscription.subscription_id == subscription_id
            ).first()
            if subscription:
                subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(subscription.frequency))
                db.commit()
                logger.info(f"订阅 {subscription_id} 因异常更新下次执行时间: {subscription.next_run_at}")
            else:
                db.rollback()
        except Exception as update_error:
            logger.exception(f"更新订阅 {subscription_id} 的下次执行时间失败: {update_error}")
            db.rollback()
    finally:
        db.close()


def run_subscription_scheduler():
    """运行订阅调度器（定期检查并执行订阅任务）"""
    db = SessionLocal()
    try:
        # 查询所有需要执行的活跃订阅
        now = beijing_now()
        logger.info(f"调度器检查时间（北京时间）: {now.isoformat()}")
        
        # 查询需要执行的订阅，处理时区问题
        subscriptions = db.query(Subscription).filter(
            Subscription.is_active == True
        ).all()
        
        # 过滤出需要执行的订阅（考虑时区）
        subscriptions_to_run = []
        for sub in subscriptions:
            next_run_at = sub.next_run_at
            if next_run_at.tzinfo is None:
                next_run_at = next_run_at.replace(tzinfo=BEIJING_TZ)
            elif next_run_at.tzinfo != BEIJING_TZ:
                next_run_at = next_run_at.astimezone(BEIJING_TZ)
            if next_run_at <= now:
                subscriptions_to_run.append(sub)
        
        subscriptions = subscriptions_to_run
        
        logger.info(f"找到 {len(subscriptions)} 个需要执行的订阅")
        
        if len(subscriptions) > 0:
            for subscription in subscriptions:
                logger.info(f"准备执行订阅: {subscription.subscription_id}, 下次执行时间: {subscription.next_run_at}, 当前时间: {now}")
        
        for subscription in subscriptions:
            try:
                execute_subscription(subscription.subscription_id)
            except Exception as e:
                logger.exception(f"执行订阅 {subscription.subscription_id} 时出错: {e}")
    except Exception as e:
        logger.exception(f"调度器执行失败: {e}")
    finally:
        db.close()


def init_scheduler():
    """初始化APScheduler调度器"""
    global scheduler
    with scheduler_lock:
        if scheduler is not None:
            return scheduler
        
        scheduler = BackgroundScheduler(timezone=BEIJING_TZ)
        # 每天9:00执行一次（主要执行时间，北京时间）
        scheduler.add_job(
            run_subscription_scheduler,
            trigger=CronTrigger(hour=9, minute=0, timezone=BEIJING_TZ),
            id='subscription_scheduler_daily',
            replace_existing=True,
        )
        # 每小时检查一次需要执行的订阅（作为备用，防止错过）
        scheduler.add_job(
            run_subscription_scheduler,
            trigger=IntervalTrigger(hours=1),
            id='subscription_scheduler_hourly',
            replace_existing=True,
        )
        monitor_interval_minutes = int(os.getenv("DOMAIN_MONITOR_SCHEDULER_INTERVAL_MINUTES", "60"))
        if monitor_interval_minutes > 0:
            from app.services.domain_monitor import dispatch_due_monitor_targets

            scheduler.add_job(
                dispatch_due_monitor_targets,
                trigger=IntervalTrigger(minutes=monitor_interval_minutes),
                id="domain_monitor_scheduler_interval",
                replace_existing=True,
            )
        scheduler.start()
        logger.info("订阅调度器已启动（每天9:00执行 + 每小时检查 + 域名持续监控检查）")
        return scheduler


# API路由

@router.post("/api/subscriptions")
async def create_subscription(
    request: Request,
    modelId: int = Form(...),
    frequency: str = Form(...),
    threshold: Optional[int] = Form(None),
    useCustomThreshold: Optional[bool] = Form(False),
    officialFile: Optional[UploadFile] = File(None),
):
    """创建订阅"""
    user_id = _require_user_id(request)
    db = SessionLocal()
    try:
        # 验证模型
        model = db.query(Model).filter(Model.id == modelId).first()
        if not model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="模型不存在"
            )
        
        # 验证用户是否有权限使用该模型
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
                {"user_id": user_id, "model_id": modelId}
            ).first()
            
            if not user_model_result:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="您没有权限使用该模型"
                )
        
        # 验证频率
        if frequency not in ["daily", "weekly", "monthly"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="频率必须是 daily, weekly 或 monthly"
            )
        
        # 验证阈值。threshold=None 表示使用模型默认策略：
        # - 恶意检测：模型判为恶意的结果全部预警
        # - 仿冒检测：使用普通仿冒检测的自适应相似度阈值
        if useCustomThreshold and threshold is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="启用自定义阈值时必须提供阈值"
            )
        resolved_threshold = threshold if useCustomThreshold else None
        if resolved_threshold is not None and not (0 <= resolved_threshold <= 100):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="阈值必须在0-100之间"
            )
        
        # 处理官方文件（仅仿冒检测需要）
        official_file_id = None
        if model.model_category == "impersonation":
            if officialFile:
                # 验证文件类型
                file_ext = officialFile.filename.split(".")[-1].lower() if officialFile.filename else ""
                if file_ext not in ["csv", "txt", "xlsx"]:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="文件类型必须是 csv, txt 或 xlsx"
                    )

                # 读取并上传文件
                file_content = await officialFile.read()
                file_size = len(file_content)
                max_size = 5 * 1024 * 1024  # 5MB
                if file_size > max_size:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"文件大小不能超过 {max_size / 1024 / 1024}MB"
                    )

                file_key = upload_file_content_to_minio(
                    file_content,
                    officialFile.filename or "unknown",
                    officialFile.content_type
                )

                uploaded_by = request.headers.get("X-User-Name") or request.headers.get("X-User")
                official_file = StoredFile(
                    bucket=MINIO_BUCKET,
                    object_key=file_key,
                    filename=officialFile.filename,
                    content_type=officialFile.content_type,
                    size=file_size,
                    uploaded_by=uploaded_by,
                    metadata_json={"source": "subscription", "role": "official"},
                )
                db.add(official_file)
                db.flush()
                official_file_id = official_file.id
            else:
                try:
                    _load_full_whitelist_file()
                except Exception as exc:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"未上传官方域名文件，且系统全量白名单不可用: {exc}"
                    )
        
        # 创建订阅
        subscription_id = f"S{int(beijing_now().timestamp())}"
        next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(frequency))
        
        subscription = Subscription(
            subscription_id=subscription_id,
            user_id=user_id,
            model_id=modelId,
            frequency=frequency,
            threshold=resolved_threshold,
            official_file_id=official_file_id,
            is_active=True,
            next_run_at=next_run_at,
        )
        db.add(subscription)
        db.commit()
        db.refresh(subscription)
        
        # 确保调度器已启动
        init_scheduler()
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "ok": True,
                "subscription_id": subscription_id,
                "next_run_at": subscription.next_run_at.isoformat(),
            }
        )
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"创建订阅失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="创建订阅失败"
        )
    finally:
        db.close()


@router.get("/api/subscriptions")
async def list_subscriptions(
    request: Request,
    page: int = Query(1, ge=1),
    pageSize: int = Query(100, ge=1, le=500),
):
    """获取订阅列表"""
    user_id = _require_user_id(request)
    db = SessionLocal()
    try:
        # 统计该用户的所有订阅（已删除的订阅不会出现在查询结果中）
        total = db.query(Subscription).filter(
            Subscription.user_id == user_id
        ).count()
        
        subscriptions = (
            db.query(Subscription, Model)
            .join(Model, Model.id == Subscription.model_id)
            .filter(Subscription.user_id == user_id)
            .order_by(Subscription.created_at.desc())
            .offset((page - 1) * pageSize)
            .limit(pageSize)
            .all()
        )
        
        items = []
        for subscription, model in subscriptions:
            official_file_name = None
            if subscription.official_file_id:
                official_file = db.query(StoredFile).filter(
                    StoredFile.id == subscription.official_file_id
                ).first()
                if official_file:
                    official_file_name = official_file.filename
            elif model.model_category == "impersonation":
                official_file_name = f"系统全量白名单 ({os.path.basename(_resolve_full_whitelist_path())})"
            
            items.append({
                "id": subscription.subscription_id,
                "modelId": subscription.model_id,
                "modelName": model.name,
                "type": _model_category_to_subscription_type(model.model_category),
                "frequency": subscription.frequency,
                "createdAt": subscription.created_at.isoformat() if subscription.created_at else "",
                "nextRunAt": subscription.next_run_at.isoformat() if subscription.next_run_at else "",
                "range": "week",  # 固定为week
                "threshold": subscription.threshold,
                "officialFileName": official_file_name,
            })
        
        return {"items": items, "total": total}
    finally:
        db.close()


@router.put("/api/subscriptions/{subscription_id}")
async def update_subscription(
    subscription_id: str,
    request: Request,
    frequency: Optional[str] = Form(None),
    threshold: Optional[int] = Form(None),
    useCustomThreshold: Optional[bool] = Form(None),
):
    """更新订阅"""
    user_id = _require_user_id(request)
    db = SessionLocal()
    try:
        subscription = db.query(Subscription).filter(
            Subscription.subscription_id == subscription_id,
            Subscription.user_id == user_id
        ).first()
        
        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="订阅不存在"
            )
        
        if frequency is not None:
            if frequency not in ["daily", "weekly", "monthly"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="频率必须是 daily, weekly 或 monthly"
                )
            subscription.frequency = frequency
            # 重新计算下次执行时间
            subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(frequency))
        
        if useCustomThreshold is not None:
            if useCustomThreshold:
                if threshold is None:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="启用自定义阈值时必须提供阈值"
                    )
                if not (0 <= threshold <= 100):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="阈值必须在0-100之间"
                    )
                subscription.threshold = threshold
            else:
                subscription.threshold = None
        elif threshold is not None:
            if not (0 <= threshold <= 100):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="阈值必须在0-100之间"
                )
            subscription.threshold = threshold
        
        db.commit()
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"ok": True}
        )
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"更新订阅失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="更新订阅失败"
        )
    finally:
        db.close()


@router.delete("/api/subscriptions/{subscription_id}")
async def delete_subscription(subscription_id: str, request: Request):
    """取消订阅（物理删除）"""
    user_id = _require_user_id(request)
    db = SessionLocal()
    try:
        subscription = db.query(Subscription).filter(
            Subscription.subscription_id == subscription_id,
            Subscription.user_id == user_id
        ).first()
        
        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="订阅不存在"
            )
        
        # 物理删除订阅记录（由于外键约束设置了 ON DELETE CASCADE，关联的预警记录也会被自动删除）
        db.delete(subscription)
        db.commit()
        
        logger.info(f"用户 {user_id} 删除了订阅 {subscription_id}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"ok": True}
        )
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"取消订阅失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="取消订阅失败"
        )
    finally:
        db.close()


@router.get("/api/alerts")
async def list_alerts(
    request: Request,
    page: int = Query(1, ge=1),
    pageSize: int = Query(5, ge=1, le=100),
):
    """获取预警历史列表"""
    user_id = _require_user_id(request)
    db = SessionLocal()
    try:
        total = db.query(Alert).filter(Alert.user_id == user_id).count()
        
        alerts = (
            db.query(Alert)
            .filter(Alert.user_id == user_id)
            .order_by(Alert.created_at.desc())
            .offset((page - 1) * pageSize)
            .limit(pageSize)
            .all()
        )

        alert_ids = [a.alert_id for a in alerts]
        alert_file_map = {}
        if alert_ids:
            alert_file_rows = (
                db.query(AlertFile, StoredFile)
                .join(StoredFile, StoredFile.id == AlertFile.file_id)
                .filter(
                    AlertFile.alert_id.in_(alert_ids),
                    AlertFile.file_role == "full_result",
                    AlertFile.file_format == "json",
                )
                .order_by(AlertFile.created_at.desc())
                .all()
            )
            for alert_file, stored_file in alert_file_rows:
                if alert_file.alert_id in alert_file_map:
                    continue
                alert_file_map[alert_file.alert_id] = (alert_file, stored_file)

        items = []
        for alert in alerts:
            high_risk_domains = []
            snapshot = []
            mapping_row = alert_file_map.get(alert.alert_id)
            if mapping_row:
                _, stored_file = mapping_row
                try:
                    file_bytes = download_file_from_minio(stored_file.object_key, stored_file.bucket)
                    result_payload = json.loads(file_bytes.decode("utf-8"))
                    high_risk_domains, snapshot = _extract_high_risk_snapshot_from_result_json(result_payload)
                except Exception:
                    logger.warning(
                        "预警列表读取 MinIO 快照失败 alert_id=%s file_id=%s",
                        alert.alert_id,
                        stored_file.id,
                    )

            items.append({
                "id": alert.alert_id,
                "time": alert.created_at.isoformat() if alert.created_at else "",
                "modelName": alert.model_name,
                "type": _task_type_to_subscription_type(alert.task_type),
                "detectedCount": alert.detected_count,
                # 兼容旧前端：继续返回字符串列表。
                "highRiskDomains": high_risk_domains,
                # 新前端可直接使用轻量快照（含可选风险分）。
                "highRiskDomainSnapshot": snapshot,
                "status": "已处理" if alert.status == "processed" else "未处理",
            })
        
        return {"items": items, "total": total}
    finally:
        db.close()


@router.get("/api/alerts/{alert_id}")
async def get_alert_detail(alert_id: str, request: Request):
    """获取预警完整详情（摘要 + 结果文件元信息 + MinIO JSON 内容）"""
    user_id = _require_user_id(request)
    db = SessionLocal()
    try:
        alert = (
            db.query(Alert)
            .filter(
                Alert.alert_id == alert_id,
                Alert.user_id == user_id,
            )
            .first()
        )
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="预警不存在",
            )

        alert_file = (
            db.query(AlertFile)
            .filter(
                AlertFile.alert_id == alert_id,
                AlertFile.file_role == "full_result",
                AlertFile.file_format == "json",
            )
            .order_by(AlertFile.created_at.desc())
            .first()
        )
        if not alert_file:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="未找到该预警对应的完整结果文件索引（alert_files）",
            )

        stored_file = db.query(StoredFile).filter(StoredFile.id == alert_file.file_id).first()
        if not stored_file:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="结果文件元信息不存在（files 记录缺失）",
            )

        try:
            file_bytes = download_file_from_minio(stored_file.object_key, stored_file.bucket)
        except Exception:
            logger.exception(
                "读取预警结果文件失败 alert_id=%s file_id=%s bucket=%s object_key=%s",
                alert_id,
                stored_file.id,
                stored_file.bucket,
                stored_file.object_key,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="结果文件不存在或无法读取（MinIO）",
            )

        try:
            result_json = json.loads(file_bytes.decode("utf-8"))
        except Exception:
            logger.exception(
                "解析预警结果 JSON 失败 alert_id=%s file_id=%s",
                alert_id,
                stored_file.id,
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="结果文件格式错误，无法解析为 JSON",
            )

        return {
            "alert_summary": {
                "alertId": alert.alert_id,
                "subscriptionId": alert.subscription_id,
                "taskId": alert.task_id,
                "userId": alert.user_id,
                "modelId": alert.model_id,
                "modelName": alert.model_name,
                "taskType": alert.task_type,
                "detectedCount": alert.detected_count,
                "highRiskCount": alert.high_risk_count,
                "threshold": alert.threshold,
                "status": alert.status,
                "createdAt": alert.created_at.isoformat() if alert.created_at else None,
                "updatedAt": alert.updated_at.isoformat() if alert.updated_at else None,
            },
            "result_file": {
                "alertFileId": alert_file.id,
                "fileId": stored_file.id,
                "bucket": stored_file.bucket,
                "objectKey": stored_file.object_key,
                "filename": stored_file.filename,
                "contentType": stored_file.content_type,
                "size": stored_file.size,
                "fileRole": alert_file.file_role,
                "fileFormat": alert_file.file_format,
                "domainCount": alert_file.domain_count,
                "alertDate": alert_file.alert_date.isoformat() if alert_file.alert_date else None,
                "uploadedAt": stored_file.uploaded_at.isoformat() if stored_file.uploaded_at else None,
            },
            "result": result_json,
        }
    finally:
        db.close()


@router.put("/api/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    request: Request,
    status: str = Form(...),
):
    """更新预警状态"""
    user_id = _require_user_id(request)
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(
            Alert.alert_id == alert_id,
            Alert.user_id == user_id
        ).first()
        
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="预警不存在"
            )
        
        if status not in ["pending", "processed"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="状态必须是 pending 或 processed"
            )
        
        alert.status = status
        db.commit()
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"ok": True}
        )
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"更新预警状态失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="更新预警状态失败"
        )
    finally:
        db.close()


@router.get("/api/subscriptions/models")
async def get_subscribable_models(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """获取可订阅的模型列表（与"我的模型"列表一致）"""
    # 使用与 models.py 中相同的逻辑获取用户模型
    from app.api.models import get_current_user_id
    
    user_id = get_current_user_id(request, authorization)
    username = None
    
    # 如果有有效的用户ID，获取用户名
    if user_id:
        with engine.connect() as conn:
            user_query = text("SELECT username FROM users WHERE id = :user_id LIMIT 1")
            user_row = conn.execute(user_query, {"user_id": user_id}).mappings().first()
            if user_row:
                username = user_row["username"]
    
    if user_id and username:
        # 已认证用户：从user_models表查询
        query = text("""
            SELECT 
                m.id, m.name, m.model_category, m.description
            FROM user_models um
            INNER JOIN models m ON um.model_id = m.id
            WHERE um.user_id = :user_id
              AND m.status = 'active'
              AND um.is_active = 1
            ORDER BY 
                CASE um.source 
                    WHEN 'official' THEN 1 
                    WHEN 'custom' THEN 2 
                    WHEN 'market' THEN 3 
                END,
                um.acquired_at DESC
        """)
        params = {"user_id": user_id}
    else:
        # 未认证或token过期：只返回官方模型
        query = text("""
            SELECT 
                m.id, m.name, m.model_category, m.description
            FROM models m
            WHERE m.status = 'active' AND m.model_type = 'official'
            ORDER BY m.created_at DESC
        """)
        params = {}
    
    with engine.connect() as conn:
        rows = conn.execute(query, params).mappings().all()
    
    models = []
    for row in rows:
        model_category = row["model_category"]
        models.append({
            "id": row["id"],
            "name": row["name"],
            "type": _model_category_to_subscription_type(model_category),
            "description": row["description"] or "",
        })
    
    return {"code": 0, "message": "ok", "data": models}


@router.post("/api/subscriptions/trigger")
async def trigger_subscriptions(request: Request):
    """手动触发订阅检查（用于测试或外部调用）"""
    user_id = _extract_user_id(request)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="需要认证"
        )
    
    try:
        run_subscription_scheduler()
        logger.info(f"用户 {user_id} 手动触发了订阅检查")
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"ok": True, "message": "订阅检查已触发"}
        )
    except Exception as e:
        logger.exception(f"手动触发订阅检查失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="触发订阅检查失败"
        )


def check_missed_subscriptions():
    """检查并执行错过的订阅（服务启动时调用）"""
    db = SessionLocal()
    try:
        now = beijing_now()
        # 查找所有 next_run_at 在过去24小时内的活跃订阅
        all_subscriptions = db.query(Subscription).filter(
            Subscription.is_active == True
        ).all()
        
        # 过滤出错过的订阅（考虑时区）
        missed = []
        for sub in all_subscriptions:
            next_run_at = sub.next_run_at
            if next_run_at.tzinfo is None:
                next_run_at = next_run_at.replace(tzinfo=BEIJING_TZ)
            elif next_run_at.tzinfo != BEIJING_TZ:
                next_run_at = next_run_at.astimezone(BEIJING_TZ)
            
            if next_run_at <= now and next_run_at >= now - timedelta(days=1):
                missed.append(sub)
        
        if missed:
            logger.info(f"发现 {len(missed)} 个错过的订阅，开始执行...")
            for sub in missed:
                try:
                    execute_subscription(sub.subscription_id)
                except Exception as e:
                    logger.exception(f"执行错过的订阅 {sub.subscription_id} 失败: {e}")
        else:
            logger.info("没有错过的订阅需要执行")
    except Exception as e:
        logger.exception(f"检查错过的订阅失败: {e}")
    finally:
        db.close()
