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
import time
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
    phishing_matches: Optional[List[Dict[str, Any]]] = None,
    history_similarity_records: Optional[List[Dict[str, Any]]] = None,
) -> bool:
    """
    仅用于「已确认创建预警记录」后的展示型推送，不在此函数内做任何预警判定。
    """
    if task_type == "impersonation":
        type_label = "仿冒域名检测"
    elif task_type == "history_similarity":
        type_label = "历史高度相似检测"
    else:
        type_label = "恶意性检测"

    title = f"【域名检测预警】{model_name}"

    lines: List[List[Dict[str, Any]]] = [
        [{"tag": "text", "text": f"预警ID：{alert_id}  |  任务ID：{task_id}  |  订阅ID：{subscription_id}\n"}],
        [{"tag": "text", "text": f"检测类型：{type_label}\n"}],
    ]
    if task_type == "impersonation":
        return _send_impersonation_alert_posts(title, lines, phishing_matches or [])
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

    if suspected_association_text and suspected_association_text.strip():
        lines.append(
            [
                {
                    "tag": "text",
                    "text": f"域名关联组织：\n{suspected_association_text}\n",
                }
            ]
        )

    '''if detail_page_url:
        lines.append(
            [
                {"tag": "text", "text": "结果详情："},
                {"tag": "a", "text": "打开预警页", "href": detail_page_url},
                {"tag": "text", "text": "\n"},
            ]
        )
    else:
        lines.append(
            [{"tag": "text", "text": "结果详情：未配置 APP_PUBLIC_BASE_URL，无法生成外链。\n"}]
        )'''


    return send_post(title, lines)


def _format_similarity_score(value: Any) -> str:
    try:
        return f"{float(value):.4f}"
    except (TypeError, ValueError):
        return "未知"


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
        f"检测结果：命中历史高度相似域名 {high_risk_count} 个 / 检测总数 {detected_count} 个",
        "检测明细：",
    ]
    for index, item in enumerate(normalized_records, start=1):
        matched_positive = item.get("matched_positive") or "未知"
        detail_lines.append(
            f"{index}. 域名：{item.get('domain', '')}\n"
            f"   评分：{_format_similarity_score(item.get('score'))}\n"
            f"   匹配历史恶意域名：{matched_positive}"
        )

    return [[{"tag": "text", "text": "\n".join(detail_lines) + "\n"}]]


def _safe_text(value: Any, default: str = "") -> str:
    text = str(value or "").strip()
    return text if text else default


def _filter_impersonation_matches(
    phishing_matches: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    keep_dispositions = {"保留人工复核", "保留高危告警"}
    return [
        item for item in phishing_matches
        if str(item.get("llm_disposition") or "").strip() in keep_dispositions
    ]


def _build_impersonation_alert_lines(
    phishing_matches: List[Dict[str, Any]],
) -> List[List[Dict[str, Any]]]:
    phishing_matches = _filter_impersonation_matches(phishing_matches)
    if not phishing_matches:
        return [[{"tag": "text", "text": "仿冒检测结果：未能提取仿冒明细，请查看预警详情文件。\n"}]]

    lines: List[List[Dict[str, Any]]] = [
        [{"tag": "text", "text": f"仿冒域名数量：{len(phishing_matches)}\n"}],
        [{"tag": "text", "text": "仿冒明细：\n"}],
    ]

    for idx, item in enumerate(phishing_matches, start=1):
        official_unit_name = _safe_text(item.get("official_unit_name"), "未知单位")
        official_domain = _safe_text(item.get("official_domain"), "未知官方域名")
        phishing_domain = _safe_text(item.get("phishing_domain"), "未知仿冒域名")
        llm_score = _safe_text(item.get("llm_score"), "未知")
        llm_reason = _safe_text(item.get("llm_reason"), "")
        llm_disposition = _safe_text(item.get("llm_disposition"), "")
        llm_reason_line = f"   LLM研判原因：{llm_reason}\n" if llm_reason else ""
        llm_disposition_line = f"   LLM处置结果：{llm_disposition}\n" if llm_disposition else ""
        lines.append(
            [
                {
                    "tag": "text",
                    "text": (
                        f"{idx}. 官方域名：{official_domain}\n"
                        f"   官方域名单位名称：{official_unit_name}\n"
                        f"   检测出的仿冒域名：{phishing_domain}\n"
                        f"   LLM风险分：{llm_score}\n"
                        f"{llm_disposition_line}"
                        f"{llm_reason_line}"
                    ),
                }
            ]
        )

    return lines


def _build_impersonation_match_line(idx: int, item: Dict[str, Any]) -> List[Dict[str, Any]]:
    official_unit_name = _safe_text(item.get("official_unit_name"), "未知单位")
    official_domain = _safe_text(item.get("official_domain"), "未知官方域名")
    phishing_domain = _safe_text(item.get("phishing_domain"), "未知仿冒域名")
    llm_score = _safe_text(item.get("llm_score"), "未知")
    llm_reason = _safe_text(item.get("llm_reason"), "")
    llm_disposition = _safe_text(item.get("llm_disposition"), "")
    llm_reason_line = f"   LLM研判原因：{llm_reason}\n" if llm_reason else ""
    llm_disposition_line = f"   LLM处置结果：{llm_disposition}\n" if llm_disposition else ""
    return [
        {
            "tag": "text",
            "text": (
                f"{idx}. 官方域名：{official_domain}\n"
                f"   官方域名单位名称：{official_unit_name}\n"
                f"   检测出的仿冒域名：{phishing_domain}\n"
                f"   LLM风险分：{llm_score}\n"
                f"{llm_disposition_line}"
                f"{llm_reason_line}"
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
        return send_post(
            title,
            header_lines + [[{"tag": "text", "text": "仿冒检测结果：未能提取仿冒明细，请查看预警详情文件。\n"}]],
        )

    intro_lines = [
        [{"tag": "text", "text": f"仿冒域名数量：{len(filtered_matches)}\n"}],
        [{"tag": "text", "text": "仿冒明细：\n"}],
    ]
    chunks: List[List[List[Dict[str, Any]]]] = []
    current = header_lines + intro_lines

    for idx, item in enumerate(filtered_matches, start=1):
        item_line = _build_impersonation_match_line(idx, item)
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
