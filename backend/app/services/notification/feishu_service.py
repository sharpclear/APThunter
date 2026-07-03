"""
飞书自定义机器人 Webhook 客户端（消息体字段遵循官方文档，不臆造字段）。
https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from collections import Counter
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from app.core.config import (
    FEISHU_BOT_SECRET,
    FEISHU_ENABLE_PUSH,
    FEISHU_HTTP_RETRIES,
    FEISHU_HTTP_TIMEOUT_SEC,
    FEISHU_WEBHOOK_URL,
)
from app.services.notification.alert_profiles import get_alert_profile

logger = logging.getLogger("uvicorn.error")

# 飞书单条请求体上限约 20KB
_MAX_BODY_BYTES = 20 * 1024

# 可重试：网络/超时/服务端临时错误/部分业务限流
_RETRIABLE_HTTP_STATUS = {429, 500, 502, 503, 504}
_RETRIABLE_CODES = {11232}  # 限流等（以响应 JSON code 为准）


def _webhook_log_id(url: str) -> str:
    """日志中不输出完整 webhook，仅 host + hook id 尾部若干字符。"""
    try:
        p = urlparse(url)
        path = (p.path or "").strip("/")
        parts = path.split("/")
        tail = parts[-1] if parts else ""
        tail_show = tail[-6:] if len(tail) > 6 else tail
        return f"{p.netloc}/...{tail_show}"
    except Exception:
        return "(invalid-url)"


def gen_feishu_sign(timestamp: str, secret: str) -> str:
    """
    签名校验：将 timestamp + '\\n' + 密钥 作为 HMAC-SHA256 的密钥，对空消息计算摘要再 Base64。
    与飞书文档 Java 示例一致（非文档中易混淆的 Python 片段）。
    """
    string_to_sign = f"{timestamp}\n{secret}"
    sign = hmac.new(string_to_sign.encode("utf-8"), b"", hashlib.sha256).digest()
    return base64.b64encode(sign).decode("utf-8")


def _maybe_wrap_with_sign(body: Dict[str, Any]) -> Dict[str, Any]:
    if not FEISHU_BOT_SECRET:
        return body
    ts = str(int(time.time()))
    sign = gen_feishu_sign(ts, FEISHU_BOT_SECRET)
    out = {"timestamp": ts, "sign": sign}
    out.update(body)
    return out


def _parse_response(resp: requests.Response) -> tuple[Optional[int], str]:
    try:
        data = resp.json()
        code = data.get("code")
        msg = str(data.get("msg", ""))
        return (int(code) if code is not None else None, msg)
    except Exception:
        return (None, resp.text[:500] if resp.text else "")


def _should_retry(
    exc: Optional[BaseException],
    resp: Optional[requests.Response],
    code: Optional[int],
) -> bool:
    if exc is not None:
        if isinstance(exc, (requests.Timeout, requests.ConnectionError)):
            return True
        return False
    if resp is None:
        return False
    if resp.status_code in _RETRIABLE_HTTP_STATUS:
        return True
    if code is not None and code in _RETRIABLE_CODES:
        return True
    return False


def _should_not_retry_code(code: Optional[int]) -> bool:
    if code is None:
        return False
    # 参数错误、签名校验失败、关键词、IP 等不应盲重试
    fatal = {9499, 19021, 19022, 19024}
    return code in fatal


def send_webhook_raw(body: Dict[str, Any]) -> bool:
    """
    发送原始 JSON 体（已含 msg_type / content）。失败返回 False，不抛异常到业务层。
    """
    if not FEISHU_ENABLE_PUSH or not FEISHU_WEBHOOK_URL:
        return False

    rid = _webhook_log_id(FEISHU_WEBHOOK_URL)
    payload = _maybe_wrap_with_sign(body)
    raw = json.dumps(payload, ensure_ascii=False)
    if len(raw.encode("utf-8")) > _MAX_BODY_BYTES:
        logger.warning("飞书消息体超过 20KB 上限，已跳过发送: webhook=%s", rid)
        return False

    attempts = max(1, int(FEISHU_HTTP_RETRIES))
    last_err: Optional[str] = None

    for attempt in range(attempts):
        try:
            resp = requests.post(
                FEISHU_WEBHOOK_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=FEISHU_HTTP_TIMEOUT_SEC,
            )
            code, msg = _parse_response(resp)
            if resp.status_code == 200 and code == 0:
                logger.info("飞书 webhook 发送成功: webhook=%s", rid)
                return True

            if _should_not_retry_code(code):
                logger.warning(
                    "飞书 webhook 返回不可重试错误: webhook=%s http=%s code=%s msg=%s",
                    rid,
                    resp.status_code,
                    code,
                    msg,
                )
                return False

            last_err = f"http={resp.status_code} code={code} msg={msg}"
            if attempt < attempts - 1 and _should_retry(None, resp, code):
                logger.warning(
                    "飞书 webhook 将重试 attempt=%s/%s webhook=%s %s",
                    attempt + 1,
                    attempts,
                    rid,
                    last_err,
                )
                time.sleep(0.5 * (2**attempt))
                continue
            logger.warning("飞书 webhook 失败: webhook=%s %s", rid, last_err)
            return False

        except (requests.Timeout, requests.ConnectionError) as e:
            last_err = type(e).__name__
            if attempt < attempts - 1:
                logger.warning(
                    "飞书 webhook 网络异常将重试 attempt=%s/%s webhook=%s err=%s",
                    attempt + 1,
                    attempts,
                    rid,
                    last_err,
                )
                time.sleep(0.5 * (2**attempt))
                continue
            logger.warning("飞书 webhook 最终失败: webhook=%s err=%s", rid, last_err)
            return False
        except Exception as e:
            logger.exception("飞书 webhook 未预期异常: webhook=%s err=%s", rid, e)
            return False

    return False


def send_text(text: str) -> bool:
    """发送文本消息：msg_type=text。"""
    body: Dict[str, Any] = {
        "msg_type": "text",
        "content": {"text": text},
    }
    return send_webhook_raw(body)


def send_post(title: str, zh_cn_lines: List[List[Dict[str, Any]]]) -> bool:
    """
    发送富文本：msg_type=post，content.post.zh_cn。
    zh_cn_lines: 段落列表，每段为官方文档中的节点数组。
    """
    return send_webhook_raw(_build_post_body(title, zh_cn_lines))


def _build_post_body(title: str, zh_cn_lines: List[List[Dict[str, Any]]]) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "msg_type": "post",
        "content": {
            "post": {
                "zh_cn": {
                    "title": title,
                    "content": zh_cn_lines,
                }
            }
        },
    }
    return body


def _body_size_bytes(body: Dict[str, Any]) -> int:
    return len(json.dumps(_maybe_wrap_with_sign(body), ensure_ascii=False).encode("utf-8"))


def send_alert_notification(
    *,
    alert_id: str,
    task_id: str,
    subscription_id: str,
    model_name: str,
    task_type: str,
    detected_count: int,
    high_risk_count: int,
    threshold: Optional[int],
    created_at: str,
    high_risk_domains: List[str],
    detail_page_url: str,
    risk_summary: str,
    suspected_association_text: Optional[str] = None,
    impersonation_matches: Optional[List[Dict[str, Any]]] = None,
    phishing_matches: Optional[List[Dict[str, Any]]] = None,
    history_similarity_records: Optional[List[Dict[str, Any]]] = None,
    dga_records: Optional[List[Dict[str, Any]]] = None,
    apt_template_nrd_records: Optional[List[Dict[str, Any]]] = None,
) -> bool:
    """
    仅用于「已确认创建预警记录」后的展示型推送，不在此函数内做任何预警判定。
    """
    alert_profile = get_alert_profile(task_type)
    title = f"【域名检测预警】{model_name}"

    lines: List[List[Dict[str, Any]]] = [
        [{"tag": "text", "text": f"预警ID：{alert_id}  |  任务ID：{task_id}  |  订阅ID：{subscription_id}\n"}],
        [{"tag": "text", "text": f"检测类型：{alert_profile.type_label}\n"}],
        [{"tag": "text", "text": f"检测时间：{created_at}\n"}],
        [
            {
                "tag": "text",
                "text": (
                    f"检测总数：{detected_count}  |  "
                    f"{alert_profile.domain_label}数量：{high_risk_count}\n"
                ),
            }
        ],
    ]
    summary_text = str(risk_summary or "").strip() or _format_threshold_policy(threshold)
    lines.append([{"tag": "text", "text": f"预警策略：{summary_text}\n"}])

    if task_type == "impersonation":
        return _send_impersonation_alert_posts(
            title,
            lines,
            impersonation_matches or phishing_matches or [],
        )
    if task_type == "history_similarity":
        return send_post(
            title,
            lines
            + _build_history_similarity_alert_lines(
                detected_count=detected_count,
                high_risk_count=high_risk_count,
                records=history_similarity_records or [],
                fallback_domains=high_risk_domains,
            ),
        )
    if task_type == "dga":
        return send_post(
            title,
            lines
            + _build_dga_alert_lines(
                detected_count=detected_count,
                high_risk_count=high_risk_count,
                records=dga_records or [],
                fallback_domains=high_risk_domains,
            ),
        )
    if task_type == "apt_template_nrd":
        return send_post(
            title,
            lines
            + _build_apt_template_nrd_alert_lines(
                detected_count=detected_count,
                high_risk_count=high_risk_count,
                records=apt_template_nrd_records or [],
                fallback_domains=high_risk_domains,
            ),
        )

    return send_post(
        title,
        lines
        + _build_malicious_alert_lines(
            detected_count=detected_count,
            high_risk_count=high_risk_count,
            high_risk_domains=high_risk_domains,
            suspected_association_text=suspected_association_text,
        ),
    )


def _format_threshold_policy(threshold: Optional[int]) -> str:
    if threshold is None:
        return "默认阈值策略"
    return f"自定义阈值：{threshold}"


def _build_malicious_alert_lines(
    *,
    detected_count: int,
    high_risk_count: int,
    high_risk_domains: List[str],
    suspected_association_text: Optional[str],
) -> List[List[Dict[str, Any]]]:
    preview_domains = []
    seen = set()
    for domain in high_risk_domains or []:
        domain_text = _safe_text(domain)
        if not domain_text:
            continue
        domain_key = domain_text.lower()
        if domain_key in seen:
            continue
        seen.add(domain_key)
        preview_domains.append(domain_text)
        if len(preview_domains) >= 20:
            break

    detail_lines = [
        f"检测结果：命中恶意域名 {high_risk_count} 个 / 检测总数 {detected_count} 个",
        "恶意域名列表：",
    ]
    if preview_domains:
        detail_lines.extend(f"{index}. {domain}" for index, domain in enumerate(preview_domains, start=1))
    else:
        detail_lines.append("未能提取恶意域名明细，请查看预警详情文件。")

    lines = [[{"tag": "text", "text": "\n".join(detail_lines) + "\n"}]]
    if suspected_association_text and suspected_association_text.strip():
        lines.append(
            [
                {
                    "tag": "text",
                    "text": f"域名关联组织：\n{suspected_association_text.strip()}\n",
                }
            ]
        )
    return lines


def _format_similarity_score(value: Any) -> str:
    try:
        return f"{float(value):.4f}"
    except (TypeError, ValueError):
        return "未知"


def _format_dga_score(value: Any) -> str:
    try:
        return f"{float(value):.6f}"
    except (TypeError, ValueError):
        return "未知"


def _coerce_dga_score(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_score(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _build_dga_alert_lines(
    *,
    detected_count: int,
    high_risk_count: int,
    records: List[Dict[str, Any]],
    fallback_domains: List[str],
) -> List[List[Dict[str, Any]]]:
    normalized_records: List[Dict[str, Any]] = []
    seen = set()
    for item in records or []:
        if not isinstance(item, dict):
            continue
        raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
        domain = _safe_text(item.get("domain") or item.get("域名") or raw.get("域名"))
        if not domain:
            continue
        domain_key = domain.lower()
        if domain_key in seen:
            continue
        seen.add(domain_key)
        dga_score = item.get("dga_score", item.get("score", raw.get("DGA_score")))
        normalized_records.append(
            {
                "domain": domain,
                "dga_score": dga_score,
                "_score_value": _coerce_dga_score(dga_score),
                "label": _safe_text(item.get("label") or raw.get("预测结果"), "高置信DGA"),
                "family": _safe_text(item.get("family") or raw.get("DGA家族")),
                "family_confidence": item.get("family_confidence", raw.get("家族置信度")),
                "family_attribution_status": _safe_text(
                    item.get("family_attribution_status") or raw.get("家族归因状态")
                ),
                "reason": _safe_text(item.get("reason"), "达到DGA高置信检测口径"),
            }
        )

    if not normalized_records:
        for domain in fallback_domains or []:
            domain_text = _safe_text(domain)
            if domain_text:
                normalized_records.append(
                    {
                        "domain": domain_text,
                        "dga_score": None,
                        "_score_value": None,
                        "label": "高置信DGA",
                        "family": "",
                        "family_confidence": None,
                        "family_attribution_status": "",
                        "reason": "达到DGA高置信检测口径",
                    }
                )

    normalized_records.sort(
        key=lambda item: (
            item.get("_score_value") is None,
            -(item.get("_score_value") or 0.0),
            str(item.get("domain") or "").lower(),
        )
    )
    preview_records = normalized_records[:30]

    detail_lines = [
        f"检测结果：命中高置信DGA域名 {high_risk_count} 个 / 检测总数 {detected_count} 个",
        "DGA明细（按DGA_score降序，仅展示前30个）：",
    ]
    for index, item in enumerate(preview_records, start=1):
        family_line = ""
        if item.get("family"):
            family_line = (
                f"   DGA家族：{item.get('family', '')}"
                f"  家族置信度：{_format_dga_score(item.get('family_confidence'))}"
                f"  状态：{item.get('family_attribution_status', '')}\n"
            )
        detail_lines.append(
            f"{index}. 域名：{item.get('domain', '')}\n"
            f"   DGA_score：{_format_dga_score(item.get('dga_score'))}\n"
            f"   预测结果：{item.get('label', '高置信DGA')}\n"
            f"{family_line}"
            f"   命中原因：{item.get('reason', '')}"
        )
    if len(normalized_records) > len(preview_records):
        detail_lines.append(
            f"仅展示评分排名前30的DGA域名，其余 {len(normalized_records) - len(preview_records)} 个请查看预警附件或结果文件。"
        )

    return [[{"tag": "text", "text": "\n".join(detail_lines) + "\n"}]]


def _build_apt_template_nrd_alert_lines(
    *,
    detected_count: int,
    high_risk_count: int,
    records: List[Dict[str, Any]],
    fallback_domains: List[str],
) -> List[List[Dict[str, Any]]]:
    normalized_records: List[Dict[str, Any]] = []
    seen = set()
    for item in records or []:
        if not isinstance(item, dict):
            continue
        raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
        domain = _safe_text(item.get("domain") or item.get("域名") or raw.get("域名"))
        if not domain:
            continue
        domain_key = domain.lower()
        if domain_key in seen:
            continue
        seen.add(domain_key)
        score = item.get("score", item.get("risk_score", raw.get("score")))
        normalized_records.append(
            {
                "domain": domain,
                "score": score,
                "_score_value": _coerce_score(score),
                "risk_level": _safe_text(item.get("risk_level") or raw.get("risk_level") or raw.get("风险等级"), "高"),
                "matched_template": _safe_text(item.get("matched_template") or raw.get("匹配模板")),
                "reason": _safe_text(item.get("reason") or raw.get("reason") or raw.get("命中原因"), "命中模板化APT域名模板"),
            }
        )

    if not normalized_records:
        for domain in fallback_domains or []:
            domain_text = _safe_text(domain)
            if domain_text:
                normalized_records.append(
                    {
                        "domain": domain_text,
                        "score": None,
                        "_score_value": None,
                        "risk_level": "高",
                        "matched_template": "",
                        "reason": "命中模板化APT域名模板",
                    }
                )

    normalized_records.sort(
        key=lambda item: (
            item.get("_score_value") is None,
            -(item.get("_score_value") or 0.0),
            str(item.get("domain") or "").lower(),
        )
    )
    preview_records = normalized_records[:30]

    detail_lines = [
        f"检测结果：命中模板化APT域名 {high_risk_count} 个 / 检测总数 {detected_count} 个",
        "模板化APT域名明细（按风险分降序，仅展示前30个）：",
    ]
    for index, item in enumerate(preview_records, start=1):
        detail_lines.append(
            f"{index}. 域名：{item.get('domain', '')}\n"
            f"   风险分：{_format_similarity_score(item.get('score'))}\n"
            f"   风险等级：{item.get('risk_level', '')}\n"
            f"   匹配模板：{item.get('matched_template', '') or '未知'}\n"
            f"   命中原因：{item.get('reason', '')}"
        )
    if len(normalized_records) > len(preview_records):
        detail_lines.append(
            f"仅展示评分排名前30的模板化APT域名，其余 {len(normalized_records) - len(preview_records)} 个请查看预警附件或结果文件。"
        )

    return [[{"tag": "text", "text": "\n".join(detail_lines) + "\n"}]]


def _build_history_similarity_alert_lines(
    *,
    detected_count: int,
    high_risk_count: int,
    records: List[Dict[str, Any]],
    fallback_domains: List[str],
) -> List[List[Dict[str, Any]]]:
    normalized_records: List[Dict[str, Any]] = []
    seen = set()
    for item in records or []:
        if not isinstance(item, dict):
            continue
        domain = _safe_text(item.get("domain") or item.get("域名"))
        if not domain:
            continue
        domain_key = domain.lower()
        if domain_key in seen:
            continue
        seen.add(domain_key)
        raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
        matched_positive = (
            item.get("matched_positive")
            or item.get("匹配历史恶意域名")
            or raw.get("匹配历史恶意域名")
            or ""
        )
        normalized_records.append(
            {
                "domain": domain,
                "score": item.get("history_similarity_score", item.get("score")),
                "matched_positive": _safe_text(matched_positive),
            }
        )

    if not normalized_records:
        for domain in fallback_domains or []:
            domain_text = _safe_text(domain)
            if domain_text:
                normalized_records.append(
                    {
                        "domain": domain_text,
                        "score": None,
                        "matched_positive": "",
                    }
                )

    detail_lines = [
        f"检测结果：命中历史APT相似域名 {high_risk_count} 个 / 检测总数 {detected_count} 个",
        "检测明细：",
    ]
    for index, item in enumerate(normalized_records, start=1):
        matched_positive = item.get("matched_positive") or "未知"
        detail_lines.append(
            f"{index}. 域名：{item.get('domain', '')}\n"
            f"   评分：{_format_similarity_score(item.get('score'))}\n"
            f"   匹配历史APT域名：{matched_positive}"
        )

    return [[{"tag": "text", "text": "\n".join(detail_lines) + "\n"}]]


def _safe_text(value: Any, default: str = "") -> str:
    text = str(value or "").strip()
    return text if text else default


_IMPERSONATION_PUSH_MIN_SCORE = 0.65
_REGIONAL_SECOND_LEVEL_LABELS = {
    "ac",
    "co",
    "com",
    "edu",
    "go",
    "gov",
    "ne",
    "net",
    "or",
    "org",
}
_PRIMARY_TLD_LABELS = {"com", "org", "net", "edu", "gov"}

_MATCH_TYPE_LABELS = {
    "brand_combo": "品牌组合",
    "service_entry": "业务入口仿冒",
    "prefix_suffix": "前后缀仿冒",
    "typo": "拼写变体",
    "confusable": "视觉混淆",
    "hyphenation": "连字符变体",
    "tld_replace": "后缀替换",
    "subdomain_deception": "子域名欺骗",
    "template_reuse": "历史模板复用",
    "pinyin_abbr": "拼音缩写",
    "other_suspicious": "其他可疑",
}

_RISK_LEVEL_LABELS = {
    "high": "高",
    "medium": "中",
    "low": "低",
    "ignore": "忽略",
}

_TARGET_TYPE_LABELS = {
    "gov": "政府",
    "government": "政府",
    "政府": "政府",
    "edu": "教育",
    "education": "教育",
    "教育": "教育",
    "finance": "金融",
    "financial": "金融",
    "金融": "金融",
    "brand": "品牌",
    "品牌": "品牌",
    "cloud": "云服务",
    "云服务": "云服务",
    "ecommerce": "电商",
    "e-commerce": "电商",
    "电商": "电商",
    "media": "媒体",
    "媒体": "媒体",
    "other": "其他",
    "其他": "其他",
}

_TARGET_SUBTYPE_LABELS = {
    "email": "邮箱服务",
    "social": "社交平台",
    "internet_company": "互联网公司",
    "developer": "开发者平台",
    "cloud_service": "云服务",
    "payment": "支付平台",
    "crypto": "加密货币",
    "banking": "银行金融",
    "financial_institution": "金融机构",
    "ecommerce": "电商零售",
    "game": "游戏娱乐",
    "travel": "旅游出行",
    "government": "政府机构",
    "education": "教育机构",
    "media": "媒体资讯",
    "other_brand": "其他品牌",
    "other": "其他",
}

_UNIT_TYPE_ORDER = {
    "政府": 0,
    "金融": 1,
    "教育": 2,
}
_OTHER_UNIT_TYPE_ORDER = {
    "云服务": 100,
    "电商": 101,
    "媒体": 102,
    "其他": 190,
    "未知": 200,
}
_BRAND_SUBTYPE_UNIT_TYPES = {"品牌", "云服务", "电商", "媒体", "其他"}

_RISK_LEVEL_RANKS = {
    "high": 3,
    "高": 3,
    "高危": 3,
    "medium": 2,
    "middle": 2,
    "中": 2,
    "中危": 2,
    "low": 1,
    "低": 1,
    "低危": 1,
    "ignore": 0,
    "忽略": 0,
}


def _parse_float(value: Any, default: float = 0.0) -> float:
    text = _safe_text(value, "")
    if not text:
        return default
    try:
        return float(text)
    except (TypeError, ValueError):
        return default


def _normalize_v1_label(value: Any, labels: Dict[str, str]) -> str:
    text = _safe_text(value, "")
    return labels.get(text, labels.get(text.lower(), text))


def _normalize_multi_v1_labels(value: Any, labels: Dict[str, str]) -> str:
    text = _safe_text(value, "")
    if not text:
        return ""
    parts = [
        part.strip()
        for part in re.split(r"[|\\/,，、;；]+", text)
        if part and part.strip()
    ]
    if not parts:
        return _normalize_v1_label(text, labels)
    translated = [_normalize_v1_label(part, labels) for part in parts]
    return "\\".join(dict.fromkeys(item for item in translated if item))


def _normalize_target_subtype(value: Any) -> str:
    text = _safe_text(value, "")
    return _TARGET_SUBTYPE_LABELS.get(text, _TARGET_SUBTYPE_LABELS.get(text.lower(), text))


def _impersonation_domain(item: Dict[str, Any]) -> str:
    return _safe_text(item.get("impersonation_domain") or item.get("phishing_domain"), "")


def _impersonation_score(item: Dict[str, Any]) -> float:
    return _parse_float(
        item.get("final_risk_score") or item.get("similarity") or item.get("llm_score"),
        0.0,
    )


def _impersonation_risk_rank(item: Dict[str, Any]) -> int:
    raw_level = _safe_text(item.get("risk_level"), "")
    normalized = raw_level.strip().lower()
    if raw_level in _RISK_LEVEL_RANKS:
        return _RISK_LEVEL_RANKS[raw_level]
    if normalized in _RISK_LEVEL_RANKS:
        return _RISK_LEVEL_RANKS[normalized]

    score = _impersonation_score(item)
    if score >= 0.85:
        return 3
    if score >= _IMPERSONATION_PUSH_MIN_SCORE:
        return 2
    if score > 0:
        return 1
    return 0


def _is_medium_or_high_impersonation_match(item: Dict[str, Any]) -> bool:
    raw_level = _safe_text(item.get("risk_level"), "")
    rank = _impersonation_risk_rank(item)
    if raw_level:
        return rank >= 2
    return _impersonation_score(item) >= _IMPERSONATION_PUSH_MIN_SCORE


def _impersonation_match_priority(item: Dict[str, Any]) -> tuple[int, float, int]:
    return (
        _impersonation_risk_rank(item),
        _impersonation_score(item),
        1 if _safe_text(item.get("official_domain"), "") else 0,
    )


def _official_domain_labels(domain: Any) -> List[str]:
    text = _safe_text(domain, "").lower().strip(".")
    if not text:
        return []
    if "://" in text:
        text = urlparse(text).netloc or text
    text = text.split("/", 1)[0].split(":", 1)[0].strip(".")
    if text.startswith("www."):
        text = text[4:]
    return [part for part in text.split(".") if part]


def _is_country_code_label(label: str) -> bool:
    return len(label) == 2 and label.isalpha()


def _is_regional_second_level_domain(labels: List[str]) -> bool:
    return (
        len(labels) >= 3
        and labels[-2] in _REGIONAL_SECOND_LEVEL_LABELS
        and _is_country_code_label(labels[-1])
    )


def _official_domain_brand_key(domain: Any) -> str:
    labels = _official_domain_labels(domain)
    if not labels:
        return ""
    if _is_regional_second_level_domain(labels):
        return labels[-3]
    if len(labels) >= 2:
        return labels[-2]
    return labels[0]


def _official_domain_canonical_priority(item: Dict[str, Any]) -> tuple[int, int, int, int, int]:
    labels = _official_domain_labels(item.get("official_domain"))
    if not labels:
        return (0, 0, 0, 0, 0)

    regional_second_level = _is_regional_second_level_domain(labels)
    primary_tld = labels[-1] in _PRIMARY_TLD_LABELS
    domain_length = len(".".join(labels))
    return (
        1 if len(labels) == 2 else 0,
        0 if regional_second_level else 1,
        1 if primary_tld else 0,
        -len(labels),
        -domain_length,
    )


def _select_best_impersonation_match(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    severity_best = max(items, key=_impersonation_match_priority)
    brand_key = _official_domain_brand_key(severity_best.get("official_domain"))
    same_brand_items = [
        item
        for item in items
        if brand_key and _official_domain_brand_key(item.get("official_domain")) == brand_key
    ]
    candidate_items = same_brand_items or items
    return max(
        candidate_items,
        key=lambda item: (
            _official_domain_canonical_priority(item),
            _impersonation_match_priority(item),
        ),
    )


def _filter_impersonation_matches(
    phishing_matches: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    keep_dispositions = {"保留人工复核", "保留高危告警"}
    matches_by_domain: Dict[str, List[Dict[str, Any]]] = {}

    for idx, item in enumerate(phishing_matches):
        if not isinstance(item, dict):
            continue
        disposition = str(item.get("llm_disposition") or "").strip()
        if disposition and disposition not in keep_dispositions:
            continue
        if not _is_medium_or_high_impersonation_match(item):
            continue

        domain = _impersonation_domain(item).lower()
        dedupe_key = domain or f"__missing_impersonation_domain_{idx}"
        matches_by_domain.setdefault(dedupe_key, []).append(item)

    selected_matches = [
        _select_best_impersonation_match(items)
        for items in matches_by_domain.values()
        if items
    ]
    return sorted(selected_matches, key=_impersonation_match_priority, reverse=True)


def _chinese_ordinal(value: int) -> str:
    numerals = "零一二三四五六七八九"
    if value <= 0:
        return str(value)
    if value < 10:
        return numerals[value]
    if value == 10:
        return "十"
    if value < 20:
        return "十" + numerals[value % 10]
    if value < 100:
        tens, ones = divmod(value, 10)
        return numerals[tens] + "十" + (numerals[ones] if ones else "")
    return str(value)


def _unit_type_label(item: Dict[str, Any]) -> str:
    return _normalize_v1_label(item.get("official_unit_type"), _TARGET_TYPE_LABELS) or "未知"


def _unit_subtype_label(item: Dict[str, Any]) -> str:
    return (
        _normalize_target_subtype(item.get("official_unit_subtype"))
        or _normalize_target_subtype(item.get("matched_target_subtype"))
        or _normalize_target_subtype(item.get("target_subtype"))
        or "其他"
    )


def _unit_group_label(item: Dict[str, Any]) -> str:
    unit_type = _unit_type_label(item)
    if unit_type in _UNIT_TYPE_ORDER:
        return unit_type
    if unit_type in _BRAND_SUBTYPE_UNIT_TYPES:
        subtype = _unit_subtype_label(item)
        if subtype and subtype not in {"未知", "其他"}:
            return f"品牌-{subtype}"
        if unit_type not in {"品牌", "其他"}:
            return f"品牌-{unit_type}"
        return "品牌-其他"
    return unit_type or "未知"


def _unit_group_sort_key(label: str, count: int) -> tuple[int, int, str]:
    if label in _UNIT_TYPE_ORDER:
        return (_UNIT_TYPE_ORDER[label], 0, label)
    if label.startswith("品牌-"):
        return (3, -count, label)
    return (_OTHER_UNIT_TYPE_ORDER.get(label, 150), 0, label)


def _group_impersonation_matches(
    phishing_matches: List[Dict[str, Any]],
) -> List[tuple[str, List[Dict[str, Any]]]]:
    counts = Counter(_unit_group_label(item) for item in phishing_matches)
    ordered_labels = sorted(counts, key=lambda label: _unit_group_sort_key(label, counts[label]))
    groups: List[tuple[str, List[Dict[str, Any]]]] = []
    for label in ordered_labels:
        groups.append((
            label,
            [item for item in phishing_matches if _unit_group_label(item) == label],
        ))
    return groups


def _build_impersonation_grouped_detail_lines(
    phishing_matches: List[Dict[str, Any]],
) -> List[List[Dict[str, Any]]]:
    lines: List[List[Dict[str, Any]]] = []
    for group_idx, (unit_group, items) in enumerate(
        _group_impersonation_matches(phishing_matches),
        start=1,
    ):
        lines.append([{"tag": "text", "text": f"{_chinese_ordinal(group_idx)}、单位类型：{unit_group}\n"}])
        for item_idx, item in enumerate(items, start=1):
            lines.append(_build_impersonation_match_line(item_idx, item))
    return lines


def _build_impersonation_alert_lines(
    phishing_matches: List[Dict[str, Any]],
) -> List[List[Dict[str, Any]]]:
    phishing_matches = _filter_impersonation_matches(phishing_matches)
    if not phishing_matches:
        return [[{"tag": "text", "text": "仿冒检测结果：未发现中高风险仿冒域名，低风险结果已过滤。\n"}]]

    lines: List[List[Dict[str, Any]]] = [
        [{"tag": "text", "text": f"仿冒域名数量：{len(phishing_matches)}\n"}],
    ]
    lines.extend(_build_impersonation_grouped_detail_lines(phishing_matches))
    return lines


def _build_impersonation_match_line(idx: int, item: Dict[str, Any]) -> List[Dict[str, Any]]:
    official_unit_name = _safe_text(item.get("official_unit_name"), "未知单位")
    official_domain = _safe_text(item.get("official_domain"), "未知官方域名")
    impersonation_domain = _safe_text(_impersonation_domain(item), "未知仿冒域名")
    match_type = _normalize_multi_v1_labels(item.get("match_type"), _MATCH_TYPE_LABELS) or "未知"
    risk_level = _normalize_v1_label(item.get("risk_level"), _RISK_LEVEL_LABELS) or "未知"
    return [
        {
            "tag": "text",
            "text": (
                f"{idx}. 仿冒域名：{impersonation_domain}\n"
                f"   官方域名：{official_domain}\n"
                f"   官方单位名称：{official_unit_name}\n"
                f"   匹配类型：{match_type}\n"
                f"   风险等级：{risk_level}\n"
            ),
        }
    ]


def _send_impersonation_alert_posts(
    title: str,
    header_lines: List[List[Dict[str, Any]]],
    phishing_matches: List[Dict[str, Any]],
) -> bool:
    filtered_matches = _filter_impersonation_matches(phishing_matches)
    if not filtered_matches:
        logger.info("仿冒检测飞书推送无中高风险明细，跳过发送")
        return True

    intro_lines = [
        [{"tag": "text", "text": f"仿冒域名数量：{len(filtered_matches)}\n"}],
    ]
    chunks: List[List[List[Dict[str, Any]]]] = []
    current = header_lines + intro_lines

    for item_line in _build_impersonation_grouped_detail_lines(filtered_matches):
        candidate = current + [item_line]
        if len(current) > len(header_lines) + len(intro_lines) and _body_size_bytes(_build_post_body(title, candidate)) > _MAX_BODY_BYTES:
            chunks.append(current)
            current = header_lines + intro_lines + [item_line]
        else:
            current = candidate
    chunks.append(current)

    ok = True
    for chunk in chunks:
        ok = send_post(title, chunk) and ok
    return ok
