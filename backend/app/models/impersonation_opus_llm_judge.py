"""Claude Opus review for impersonation-domain candidates."""

from __future__ import annotations

import json
import os
import time
from typing import Any

import requests


ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
MODEL_NAME = "claude-opus-4-8"

ALLOWED_LABELS = {
    "likely_impersonation",
    "suspicious_impersonation",
    "unlikely_impersonation",
    "uncertain",
}
KEEP_RECOMMENDATIONS = {"保留高危告警", "保留人工复核"}

SYSTEM_PROMPT = """你是一个网络安全分析助手，任务是对疑似仿冒/仿冒域名候选进行二次研判。

重要限制：
- 只能基于用户提供的候选域名、官方域名、单位名称、算法分数、匹配类型、风险等级和命中原因判断。
- 不要假设你拥有 DNS、WHOIS、证书、网页内容、流量日志、搜索结果或威胁情报。
- 结论不能写成“确认钓鱼”，只能写成“疑似仿冒/钓鱼倾向”或“不具有明显仿冒特征”。
- 不要把 DGA、C2、失陷合法域名、Fast Flux、DNS 隧道和仿冒钓鱼混为一谈。

判断重点：
1. 候选域名是否明显借用了官方域名的品牌词、机构词、缩写或易混淆变体。
2. 是否组合 login、auth、secure、verify、mail、sso、account、support 等账号/认证/服务风险词。
3. 是否存在连字符、数字混排、异常长 SLD、可疑后缀、官方后缀替换等结构异常。
4. 短词和通用词要谨慎，必须有强风险上下文或明确目标指示才判为可疑。
5. 若候选域名更像普通业务词、无关品牌、可读通用域名或证据不足，应判为 unlikely_impersonation 或 uncertain。

输出要求：
- 只输出合法 JSON。
- JSON 顶层格式必须是 {"results": [...]}。
- results 中每个对象必须包含：
  domain, official_domain, impersonation_likelihood, label, reason, key_features, disposition
- impersonation_likelihood 是 0 到 1 的小数。
- label 只能是 likely_impersonation、suspicious_impersonation、unlikely_impersonation、uncertain。
- reason 不超过 80 个中文字符，说明 LLM 研判原因。
- key_features 是字符串数组，元素可包括 brand_token、confusable_brand、login_context、mail_context、auth_context、suffix_change、suspicious_tld、hyphen_or_digit、long_sld、short_token_risk、generic_word_only、insufficient_evidence。
- disposition 只能是：保留高危告警、保留人工复核、降低优先级、建议剔除。

处置口径：
- 强烈疑似仿冒/钓鱼，disposition 输出“保留高危告警”。
- 有明显仿冒/钓鱼倾向但证据不够强，disposition 输出“保留人工复核”。
- 仅凭现有证据难以判断，disposition 输出“降低优先级”。
- 无明显仿冒特征，disposition 输出“建议剔除”。

打分标准：
- 0.80 - 1.00：likely_impersonation，强烈疑似仿冒/钓鱼
- 0.55 - 0.79：suspicious_impersonation，有明显仿冒/钓鱼倾向
- 0.30 - 0.54：uncertain，仅凭现有证据难以判断
- 0.00 - 0.29：unlikely_impersonation，无明显仿冒特征
"""


def build_candidate_items(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    for item in candidates:
        items.append(
            {
                "domain": str(item.get("domain") or ""),
                "official_domain": str(item.get("official_domain") or ""),
                "company": str(item.get("company") or ""),
                "algorithm_score": safe_float(item.get("algorithm_score")),
                "match_type": str(item.get("match_type") or ""),
                "risk_level": str(item.get("risk_level") or ""),
                "evidence": str(item.get("evidence") or "")[:500],
            }
        )
    return items


def build_user_prompt(candidate_items: list[dict[str, Any]], batch_index: int) -> str:
    return (
        "请研判以下疑似仿冒域名候选。再次强调：只基于输入字段判断，不要编造 DNS、WHOIS、IP、证书、网页、搜索或威胁情报。\n"
        "请输出 JSON，格式为 {\"results\": [...]}，每个候选域名必须对应一个结果对象。\n"
        f"batch_index: {batch_index}\n"
        "candidates_json:\n"
        f"{json.dumps(candidate_items, ensure_ascii=False)}"
    )


def judge_batch(
    api_key: str,
    candidate_items: list[dict[str, Any]],
    batch_index: int,
    *,
    timeout_seconds: int,
    max_retries: int,
    retry_sleep_seconds: int,
    max_tokens: int,
) -> list[dict[str, Any]]:
    payload = {
        "model": os.getenv("ANTHROPIC_MODEL", MODEL_NAME),
        "max_tokens": max_tokens,
        "system": SYSTEM_PROMPT,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": build_user_prompt(candidate_items, batch_index),
                    }
                ],
            }
        ],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": os.getenv("ANTHROPIC_VERSION", ANTHROPIC_VERSION),
        "content-type": "application/json",
    }
    url = os.getenv("ANTHROPIC_API_URL", ANTHROPIC_API_URL)
    last_error: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=timeout_seconds)
            if response.status_code >= 400:
                raise RuntimeError(f"Anthropic API HTTP {response.status_code}: {response.text[:500]}")
            parsed = parse_json_object(extract_anthropic_text(response.json()))
            results = parsed.get("results", [])
            if not isinstance(results, list):
                raise ValueError("Anthropic JSON response field 'results' must be a list.")
            return normalize_llm_results(results, candidate_items)
        except Exception as exc:
            last_error = exc
            if attempt < max_retries:
                time.sleep(retry_sleep_seconds)
    raise RuntimeError(f"batch {batch_index} failed after {max_retries} attempts: {last_error}")


def extract_anthropic_text(data: dict[str, Any]) -> str:
    parts = []
    for item in data.get("content", []):
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(str(item.get("text", "")))
    text = "\n".join(parts).strip()
    if text:
        return text
    raise ValueError("Anthropic response does not contain text content.")


def parse_json_object(text: str) -> dict[str, Any]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise
        parsed = json.loads(text[start:end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("LLM response must be a JSON object.")
    return parsed


def normalize_llm_results(
    results: list[dict[str, Any]],
    candidate_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_domain = {str(result.get("domain", "")): result for result in results}
    normalized_rows = []

    for item in candidate_items:
        result = by_domain.get(item["domain"], {})
        score = safe_float(result.get("impersonation_likelihood", result.get("llm_score", 0.0)))
        label = str(result.get("label", result.get("llm_label", "uncertain")))
        if label not in ALLOWED_LABELS:
            label = label_from_score(score)

        key_features = result.get("key_features", [])
        if isinstance(key_features, list):
            key_features_text = ",".join(str(feature) for feature in key_features)
        else:
            key_features_text = str(key_features)

        disposition = normalize_disposition(result.get("disposition") or result.get("llm_disposition"), label)
        normalized_rows.append(
            {
                "domain": item["domain"],
                "official_domain": str(result.get("official_domain") or item["official_domain"]),
                "impersonation_likelihood": f"{score:.4f}",
                "label": label,
                "reason": str(result.get("reason", result.get("llm_reason", "")))[:160],
                "key_features": key_features_text,
                "disposition": disposition,
            }
        )
    return normalized_rows


def normalize_disposition(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if text in {"保留高危告警", "高危告警"}:
        return "保留高危告警"
    if text in {"保留人工复核", "人工复核"}:
        return "保留人工复核"
    if text in {"降低优先级", "降级"}:
        return "降低优先级"
    if text in {"建议剔除", "剔除"}:
        return "建议剔除"
    if label == "likely_impersonation":
        return "保留高危告警"
    if label == "suspicious_impersonation":
        return "保留人工复核"
    if label == "unlikely_impersonation":
        return "建议剔除"
    return "降低优先级"


def safe_float(value: Any) -> float:
    try:
        number = float(value)
    except Exception:
        number = 0.0
    return max(0.0, min(1.0, number))


def label_from_score(score: float) -> str:
    if score >= 0.80:
        return "likely_impersonation"
    if score >= 0.55:
        return "suspicious_impersonation"
    if score >= 0.30:
        return "uncertain"
    return "unlikely_impersonation"
