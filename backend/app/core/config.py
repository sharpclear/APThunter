import os

# 配置通过环境变量设置
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "123456789")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "uploads")

MYSQL_URL = os.getenv(
    "MYSQL_URL",
    "mysql+pymysql://apthunter:4CyUhr2zu6!@localhost:3306/apthunter_new",
)
IMPERSONATION_MODEL_NAME = os.getenv(
    "IMPERSONATION_MODEL_NAME", "impersonation_detector"
)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)

# ---------- 预警通知（邮件 / 飞书）----------
# 邮件：未设置 ALERT_EMAIL_ENABLED 时默认开启（与历史行为一致）；显式 false 则不发邮件
def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


ALERT_EMAIL_ENABLED = _env_bool("ALERT_EMAIL_ENABLED", True)

# 飞书自定义机器人：https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot
FEISHU_ENABLE_PUSH = _env_bool("FEISHU_ENABLE_PUSH", False)
FEISHU_WEBHOOK_URL = (os.getenv("FEISHU_WEBHOOK_URL") or "").strip()
FEISHU_BOT_SECRET = (os.getenv("FEISHU_BOT_SECRET") or "").strip()
FEISHU_PUSH_ONLY_ON_ALERT = _env_bool("FEISHU_PUSH_ONLY_ON_ALERT", True)
# 可选：逗号分隔 channels，例如 email,feishu（用于与 ALERT_*_ENABLED 组合理解；当前逻辑以各 ENABLED 为准）
ALERT_NOTIFY_CHANNELS = os.getenv("ALERT_NOTIFY_CHANNELS", "")

# ---------- 展示/态势感知模块整合开关 ----------
# 默认开启，便于在 APTHunter3 副本中直接验证整合效果。
# 生产环境可通过 DISPLAY_INTEGRATION_ENABLED=false 快速关闭。
DISPLAY_INTEGRATION_ENABLED = _env_bool("DISPLAY_INTEGRATION_ENABLED", True)

# 预警详情页外链（前端路由为 /detection/alert，history 模式无 #）
APP_PUBLIC_BASE_URL = (os.getenv("APP_PUBLIC_BASE_URL") or "").strip().rstrip("/")

# HTTP
FEISHU_HTTP_TIMEOUT_SEC = float(os.getenv("FEISHU_HTTP_TIMEOUT_SEC", "10"))
FEISHU_HTTP_RETRIES = int(os.getenv("FEISHU_HTTP_RETRIES", "3"))
