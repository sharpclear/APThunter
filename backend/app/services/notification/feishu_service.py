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
    return send_webhook_raw(body)


def send_alert_notification(
    *,
    alert_id: str,
    task_id: str,
    subscription_id: str,
    model_name: str,
    task_type: str,
    detected_count: int,
    high_risk_count: int,
    threshold: int,
    created_at: str,
    high_risk_domains: List[str],
    detail_page_url: str,
    risk_summary: str,
) -> bool:
    """
    仅用于「已确认创建预警记录」后的展示型推送，不在此函数内做任何预警判定。
    """
    domain_label = "恶意域名" if task_type == "malicious" else "仿冒/钓鱼域名"
    type_label = "恶意性检测" if task_type == "malicious" else "仿冒域名检测"

    preview_lines: List[str] = []
    for d in high_risk_domains[:40]:
        preview_lines.append(f"• {str(d)[:300]}")
    domains_blob = "\n".join(preview_lines)
    if len(high_risk_domains) > 40:
        domains_blob += f"\n… 共 {len(high_risk_domains)} 条（完整列表见平台预警详情）"

    title = f"【域名检测预警】{model_name}"

    lines: List[List[Dict[str, Any]]] = [
        [{"tag": "text", "text": f"预警ID：{alert_id}  |  任务ID：{task_id}  |  订阅ID：{subscription_id}\n"}],
        [{"tag": "text", "text": f"检测类型：{type_label}\n"}],
    ]
    if domains_blob.strip():
        lines.append([{"tag": "text", "text": f"{domain_label}预览：\n{domains_blob}\n"}])

    if detail_page_url:
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
        )

    lines.append(
        [
            {
                "tag": "text",
                "text": "备注：该消息由平台预警机制自动推送（飞书）。\n",
            }
        ]
    )

    return send_post(title, lines)
