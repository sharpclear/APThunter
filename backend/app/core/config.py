import os

def _load_local_dotenv_if_present():
    """
    本地直接启动后端服务时，尽早从 .env 读取配置。
    必须在本模块读取任何 os.getenv 之前执行，避免导入顺序导致配置默认值被提前固化。
    """
    try:
        from dotenv import load_dotenv  # python-dotenv
    except Exception:
        return
    try:
        config_dir = os.path.dirname(os.path.abspath(__file__))  # backend/app/core
        app_dir = os.path.abspath(os.path.join(config_dir, ".."))  # backend/app
        backend_root = os.path.abspath(os.path.join(config_dir, "..", ".."))  # backend
        project_root = os.path.abspath(os.path.join(config_dir, "..", "..", ".."))  # apthunter
        cwd = os.getcwd()
        explicit = os.getenv("DOTENV_PATH")
        candidates = []
        if explicit:
            candidates.append(explicit)
        candidates.extend(
            [
                os.path.join(cwd, ".env"),
                os.path.join(project_root, ".env"),
                os.path.join(backend_root, ".env"),
                os.path.join(app_dir, ".env"),
            ]
        )
        for path in candidates:
            if os.path.exists(path):
                load_dotenv(path, override=False)
                break
    except Exception:
        return
_load_local_dotenv_if_present()

# 配置通过环境变量设置
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "123456789")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "uploads")
ALERT_RESULT_BUCKET = os.getenv("ALERT_RESULT_BUCKET", "apthunter-alert-results")

MYSQL_URL = os.getenv(
    "MYSQL_URL",
    "mysql+pymysql://apthunter:4CyUhr2zu6!@localhost:3306/apthunter_new",
)
IMPERSONATION_MODEL_NAME = os.getenv(
    "IMPERSONATION_MODEL_NAME", "impersonation_detector"
)
IMPERSONATION_FULL_WHITELIST_PATH = os.getenv(
    "IMPERSONATION_FULL_WHITELIST_PATH",
    os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "data",
            "official_domains",
            "full_whitelist.csv",
        )
    ),
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


# ---------- 基于历史图谱的域名 APT 归因 ----------
# 图谱目录必须包含 graph_nodes.csv 和 graph_edges.csv。候选域名只做只读匹配，
# 历史图谱的替换/更新由管理员在该目录中人工完成。
APT_ATTRIBUTION_GRAPH_DIR = os.path.abspath(
    os.path.expanduser(
        os.getenv(
            "APT_ATTRIBUTION_GRAPH_DIR",
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "data",
                "apt_attribution",
                "historical_graph",
            ),
        )
    )
)
APT_ATTRIBUTION_REALTIME_ALLOWED = _env_bool(
    "APT_ATTRIBUTION_REALTIME_ALLOWED",
    True,
)
APT_ATTRIBUTION_DNS_ENABLED = _env_bool("APT_ATTRIBUTION_DNS_ENABLED", True)
APT_ATTRIBUTION_DNS_RECORDS_ENABLED = _env_bool(
    "APT_ATTRIBUTION_DNS_RECORDS_ENABLED",
    True,
)
APT_ATTRIBUTION_RDAP_ENABLED = _env_bool("APT_ATTRIBUTION_RDAP_ENABLED", True)
APT_ATTRIBUTION_TLS_ENABLED = _env_bool("APT_ATTRIBUTION_TLS_ENABLED", True)
APT_ATTRIBUTION_CT_ENABLED = _env_bool("APT_ATTRIBUTION_CT_ENABLED", True)
APT_ATTRIBUTION_IPINTEL_ENABLED = _env_bool(
    "APT_ATTRIBUTION_IPINTEL_ENABLED",
    True,
)
APT_ATTRIBUTION_WEB_ENABLED = _env_bool("APT_ATTRIBUTION_WEB_ENABLED", True)
APT_ATTRIBUTION_REQUEST_TIMEOUT_SEC = float(
    os.getenv("APT_ATTRIBUTION_REQUEST_TIMEOUT_SEC", "12")
)
APT_ATTRIBUTION_REQUEST_RETRIES = int(
    os.getenv("APT_ATTRIBUTION_REQUEST_RETRIES", "1")
)
APT_ATTRIBUTION_MAX_WORKERS = int(os.getenv("APT_ATTRIBUTION_MAX_WORKERS", "4"))
APT_ATTRIBUTION_API_MAX_DOMAINS = int(
    os.getenv("APT_ATTRIBUTION_API_MAX_DOMAINS", "100")
)
APT_ATTRIBUTION_CERTIFICATE_LIMIT = int(
    os.getenv("APT_ATTRIBUTION_CERTIFICATE_LIMIT", "10")
)
APT_ATTRIBUTION_DNS_TRANSPORT = (
    os.getenv("APT_ATTRIBUTION_DNS_TRANSPORT", "auto").strip().lower()
)
APT_ATTRIBUTION_DOH_ENDPOINT = (
    os.getenv(
        "APT_ATTRIBUTION_DOH_ENDPOINT",
        "https://cloudflare-dns.com/dns-query",
    ).strip()
)
APT_ATTRIBUTION_CT_RATE_LIMIT_SEC = float(
    os.getenv("APT_ATTRIBUTION_CT_RATE_LIMIT_SEC", "0.5")
)
APT_ATTRIBUTION_HISTORICAL_MAX_HOPS = int(
    os.getenv("APT_ATTRIBUTION_HISTORICAL_MAX_HOPS", "4")
)
APT_ATTRIBUTION_HISTORICAL_MAX_PATHS = int(
    os.getenv("APT_ATTRIBUTION_HISTORICAL_MAX_PATHS", "20")
)


ALERT_EMAIL_ENABLED = _env_bool("ALERT_EMAIL_ENABLED", True)

# 飞书自定义机器人：https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot
FEISHU_ENABLE_PUSH = _env_bool("FEISHU_ENABLE_PUSH", False)
FEISHU_WEBHOOK_URL = (os.getenv("FEISHU_WEBHOOK_URL") or "").strip()
FEISHU_BOT_SECRET = (os.getenv("FEISHU_BOT_SECRET") or "").strip()
FEISHU_PUSH_ONLY_ON_ALERT = _env_bool("FEISHU_PUSH_ONLY_ON_ALERT", True)
FEISHU_PUSH_IMPERSONATION_ALERTS = _env_bool(
    "FEISHU_PUSH_IMPERSONATION_ALERTS", False
)
# 可选：逗号分隔 channels，例如 email,feishu（用于与 ALERT_*_ENABLED 组合理解；当前逻辑以各 ENABLED 为准）
ALERT_NOTIFY_CHANNELS = os.getenv("ALERT_NOTIFY_CHANNELS", "")

# 预警详情页外链（前端路由为 /detection/alert，history 模式无 #）
APP_PUBLIC_BASE_URL = (os.getenv("APP_PUBLIC_BASE_URL") or "").strip().rstrip("/")

# HTTP
FEISHU_HTTP_TIMEOUT_SEC = float(os.getenv("FEISHU_HTTP_TIMEOUT_SEC", "10"))
FEISHU_HTTP_RETRIES = int(os.getenv("FEISHU_HTTP_RETRIES", "3"))
