from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class AlertProfile:
    task_type: str
    type_label: str
    domain_label: str
    attachment_prefix: str
    default_reason: str


ALERT_PROFILES: Dict[str, AlertProfile] = {
    "malicious": AlertProfile(
        task_type="malicious",
        type_label="恶意性检测",
        domain_label="恶意域名",
        attachment_prefix="malicious",
        default_reason="模型判定为恶意",
    ),
    "malicious_ip": AlertProfile(
        task_type="malicious_ip",
        type_label="恶意IP检测",
        domain_label="恶意IP",
        attachment_prefix="malicious_ip",
        default_reason="模型判定为恶意",
    ),
    "impersonation": AlertProfile(
        task_type="impersonation",
        type_label="仿冒域名检测",
        domain_label="仿冒域名",
        attachment_prefix="phishing",
        default_reason="命中仿冒检测规则",
    ),
    "history_similarity": AlertProfile(
        task_type="history_similarity",
        type_label="历史APT域名相似性检测",
        domain_label="历史APT相似域名",
        attachment_prefix="history_similarity",
        default_reason="与历史APT域名高度相似",
    ),
    "dga": AlertProfile(
        task_type="dga",
        type_label="DGA域名检测",
        domain_label="高置信DGA域名",
        attachment_prefix="dga",
        default_reason="达到DGA高置信检测口径",
    ),
    "apt_template_nrd": AlertProfile(
        task_type="apt_template_nrd",
        type_label="模板化APT域名检测",
        domain_label="模板化APT域名",
        attachment_prefix="apt_template_nrd",
        default_reason="命中模板化APT域名模板",
    ),
}

DEFAULT_ALERT_PROFILE = ALERT_PROFILES["malicious"]


def normalize_task_type(task_type: Optional[str]) -> str:
    value = str(task_type or "").strip()
    return value if value in ALERT_PROFILES else DEFAULT_ALERT_PROFILE.task_type


def get_alert_profile(task_type: Optional[str]) -> AlertProfile:
    return ALERT_PROFILES.get(normalize_task_type(task_type), DEFAULT_ALERT_PROFILE)
