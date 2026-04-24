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
        project_root = os.path.abspath(os.path.join(api_dir, "..", "..", "..", ".."))  # atdv-pro

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
from app.entities import Task, Model, StoredFile, User
from app.infra.minio_client import minio_client
from app.db.session import SessionLocal, engine
from app.db.base import Base
from app.core.config import MINIO_BUCKET, IMPERSONATION_MODEL_NAME
from sqlalchemy import Column, BigInteger, String, DateTime, ForeignKey, Enum as SqlEnum, Integer, JSON, text, Boolean
from app.services.notification.alert_notifier import build_alert_data_dict, dispatch_alert_notifications
# 导入检测相关函数
from app.api.detection import (
    _collect_daily_domains,
    _parse_date_string,
    upload_file_content_to_minio,
    download_file_from_minio,
    RESULTS_BUCKET,
)
from malicious_detection_daily import predict_from_domains, predict_from_domains_subscription
from phishing_detector import (
    read_official_domains_from_file,
    predict_from_domains as phishing_predict_from_domains,
)

logger = logging.getLogger("uvicorn.error")

# 数据延迟配置：数据文件延迟多少天到达（默认1天，即今天的数据明天才能获取）
DATA_DELAY_DAYS = int(os.getenv("DATA_DELAY_DAYS", "1"))

# 定义 Subscription 和 Alert 模型（因为 main.py 中已删除）
class Subscription(Base):
    __tablename__ = "subscriptions"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    subscription_id = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(BigInteger, ForeignKey("users.id"), nullable=False, index=True)
    model_id = Column(BigInteger, ForeignKey("models.id"), nullable=False, index=True)
    frequency = Column(SqlEnum("daily", "weekly", "monthly", name="frequency_enum"), nullable=False, server_default="weekly")
    threshold = Column(Integer, nullable=False, server_default=text("60"))
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
    task_type = Column(SqlEnum("malicious", "impersonation", name="task_type_enum"), nullable=False)
    detected_count = Column(Integer, nullable=False, server_default=text("0"))
    high_risk_count = Column(Integer, nullable=False, server_default=text("0"))
    threshold = Column(Integer, nullable=False)
    status = Column(SqlEnum("pending", "processed", name="alert_status_enum"), nullable=False, server_default="pending", index=True)
    feishu_notified = Column(Boolean, nullable=False, server_default=text("0"), default=False)
    feishu_notified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"), index=True)
    updated_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"), onupdate=lambda: beijing_now().replace(tzinfo=None))


class AlertDetail(Base):
    """预警详情表，存储 high_risk_domains 等大字段，与 alerts 一对一关联"""
    __tablename__ = "alert_details"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), ForeignKey("alerts.alert_id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    high_risk_domains = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
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

        # 根据模型类型执行不同的检测
        if model.model_category == "impersonation":
            # 仿冒域名检测
            if not subscription.official_file_id:
                logger.error(f"订阅 {subscription_id} 缺少官方文件，更新下次执行时间后跳过")
                subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(subscription.frequency))
                db.commit()
                return
            
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
                official_file.filename or "unknown"
            )
            
            # 执行检测
            # 将阈值从0-100转换为0-1（相似度阈值范围）
            similarity_threshold = subscription.threshold / 100.0 if subscription.threshold is not None else None
            
            excel_content, statistics = phishing_predict_from_domains(
                official_domains,
                detection_domains,
                similarity_threshold=similarity_threshold
            )
            
            # 创建任务记录
            task = Task(
                task_id=task_id,
                task_type="impersonation",
                model_id=model.id,
                file_id=official_file.id,
                extra={
                    "detectionSource": "newDomain",
                    "dateRange": date_range,
                    "subscription_id": subscription_id,
                },
                status="completed",
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
                status="completed",
                created_by=subscription.user_id,
            )
            db.add(task)
            db.flush()
        
        # 上传结果文件
        result_filename = f"result_{task_id}_{beijing_now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        result_key = upload_file_content_to_minio(
            excel_content,
            result_filename,
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            bucket=RESULTS_BUCKET
        )
        
        # 更新任务extra
        task.extra.update({
            "result_file_key": result_key,
            "result_bucket": RESULTS_BUCKET,
            "result_filename": result_filename,
            "statistics": statistics,
            "completed_at": beijing_now().isoformat(),
        })
        db.commit()
        db.refresh(task)
        
        # 检查是否需要创建预警
        high_risk_count = 0
        high_risk_domains = []
        
        # 从Excel结果中提取高风险域名列表
        try:
            import pandas as pd
            excel_file = io.BytesIO(excel_content)
            
            if model.model_category == "impersonation":
                # 仿冒检测：从统计信息中获取钓鱼域名数量
                high_risk_count = statistics.get("phishing", 0) or statistics.get("钓鱼域名数量", 0) or statistics.get("检测到的钓鱼域名数量", 0)
                
                # 从Excel中提取钓鱼域名列表（提取所有，不限制数量）
                try:
                    results_df = pd.read_excel(excel_file, sheet_name='检测结果')
                    # 筛选出有钓鱼域名的行
                    phishing_rows = results_df[results_df['钓鱼域名'].notna()]
                    high_risk_domains = phishing_rows['钓鱼域名'].dropna().unique().tolist()
                except Exception as e:
                    logger.warning(f"从Excel提取钓鱼域名列表失败: {e}")
                    try:
                        # 尝试从钓鱼域名列表工作表读取
                        phishing_df = pd.read_excel(excel_file, sheet_name='钓鱼域名列表')
                        if '钓鱼域名' in phishing_df.columns:
                            high_risk_domains = phishing_df['钓鱼域名'].dropna().unique().tolist()
                        else:
                            high_risk_domains = []
                    except:
                        pass
            else:
                # 恶意订阅预警：备选 = model.predict 为恶意；触发对象 = 恶意概率 > 订阅阈值/100（严格大于）
                th_raw = subscription.threshold if subscription.threshold is not None else 0
                cutoff = float(th_raw) / 100.0
                high_risk_domains = []
                high_risk_count = 0
                if results_malicious_subscription:
                    seen = set()
                    for r in results_malicious_subscription:
                        if int(r.get("预测标签", 0)) != 1:
                            continue
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
        
        # 仿冒：原逻辑；恶意订阅：仅当存在「predict 恶意且恶意概率 > 阈值/100」的样本时触发预警
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
            # 创建预警详情（high_risk_domains 存入 alert_details 表）
            alert_detail = AlertDetail(
                alert_id=alert_id,
                high_risk_domains=high_risk_domains,
            )
            db.add(alert_detail)
            db.commit()
            db.refresh(alert)
            
            logger.info(f"创建预警: {alert_id}, {high_risk_count} 个高风险域名，高风险比例: {risk_ratio:.2f}%")
            
            # 生成CSV文件内容
            csv_content = None
            try:
                import csv
                csv_buffer = io.StringIO()
                domain_type = '恶意域名' if task.task_type == 'malicious' else '仿冒域名'
                writer = csv.writer(csv_buffer)
                writer.writerow(['序号', domain_type])  # CSV表头
                for i, domain in enumerate(high_risk_domains, 1):
                    writer.writerow([i, domain])
                csv_content = csv_buffer.getvalue().encode('utf-8-sig')  # 使用utf-8-sig以支持Excel正确显示中文
                csv_buffer.close()
            except Exception as e:
                logger.warning(f"生成CSV文件失败: {e}")
            
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
            )
            try:
                dispatch_alert_notifications(
                    db,
                    alert_row=alert,
                    alert_data=alert_data,
                    domains_csv_content=csv_content,
                    user_id=subscription.user_id,
                )
            except Exception:
                logger.exception("预警通知分发异常（已吞掉，不影响订阅主流程）")
        else:
            logger.info(
                f"订阅 {subscription_id} 本次检测未满足预警条件（仿冒按原规则；恶意订阅需 predict 恶意且恶意概率>阈值/100），跳过预警"
            )
        
        # 更新订阅的下次执行时间
        subscription.next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(subscription.frequency))
        
        # 记录本次检测的日期范围（已在Task.extra中记录，这里只是日志）
        if date_range:
            logger.info(f"订阅 {subscription_id} 本次检测日期范围: {date_range[0]} 到 {date_range[1]}")
        
        db.commit()
        
        logger.info(f"订阅任务 {subscription_id} 执行完成，下次执行时间: {subscription.next_run_at}")
        
    except Exception as e:
        logger.exception(f"执行订阅任务失败: {subscription_id}, 错误: {e}")
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
        scheduler.start()
        logger.info("订阅调度器已启动（每天9:00执行 + 每小时检查）")
        return scheduler


# API路由

@router.post("/api/subscriptions")
async def create_subscription(
    request: Request,
    modelId: int = Form(...),
    frequency: str = Form(...),
    threshold: int = Form(60),
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
        
        # 验证阈值
        if not (0 <= threshold <= 100):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="阈值必须在0-100之间"
            )
        
        # 处理官方文件（仅仿冒检测需要）
        official_file_id = None
        if model.model_category == "impersonation":
            if not officialFile:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="仿冒检测订阅需要上传官方域名文件"
                )
            
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
        
        # 创建订阅
        subscription_id = f"S{int(beijing_now().timestamp())}"
        next_run_at = beijing_datetime_to_naive(_calculate_next_run_at(frequency))
        
        subscription = Subscription(
            subscription_id=subscription_id,
            user_id=user_id,
            model_id=modelId,
            frequency=frequency,
            threshold=threshold,
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
            
            items.append({
                "id": subscription.subscription_id,
                "modelId": subscription.model_id,
                "modelName": model.name,
                "type": "phishing" if model.model_category == "impersonation" else "malicious",
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
        
        if threshold is not None:
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
        
        # 批量查询 alert_details 中的 high_risk_domains（避免 N+1）
        alert_ids = [a.alert_id for a in alerts]
        details_map = {}
        if alert_ids:
            details_list = db.query(AlertDetail).filter(AlertDetail.alert_id.in_(alert_ids)).all()
            details_map = {d.alert_id: d for d in details_list}
        
        items = []
        for alert in alerts:
            high_risk_domains = []
            detail = details_map.get(alert.alert_id)
            if detail and detail.high_risk_domains:
                if isinstance(detail.high_risk_domains, list):
                    high_risk_domains = detail.high_risk_domains
                elif isinstance(detail.high_risk_domains, str):
                    try:
                        high_risk_domains = json.loads(detail.high_risk_domains)
                    except Exception:
                        high_risk_domains = []
            
            items.append({
                "id": alert.alert_id,
                "time": alert.created_at.isoformat() if alert.created_at else "",
                "modelName": alert.model_name,
                "type": "phishing" if alert.task_type == "impersonation" else "malicious",
                "detectedCount": alert.detected_count,
                "highRiskDomains": high_risk_domains,
                "status": "已处理" if alert.status == "processed" else "未处理",
            })
        
        return {"items": items, "total": total}
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
            "type": "phishing" if model_category == "impersonation" else "malicious",
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