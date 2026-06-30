"""DeepSeek review for impersonation-domain candidates."""

from __future__ import annotations

import json
import os
import time
from typing import Any

import requests


DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"
MODEL_NAME = "deepseek-v4-flash"

ALLOWED_LABELS = {
    "likely_impersonation",
    "suspicious_impersonation",
    "unlikely_impersonation",
    "uncertain",
}

SYSTEM_PROMPT = """你是一个网络安全分析助手，任务是对疑似仿冒/仿冒域名候选进行二次研判。

重要限制：
- 只能基于用户提供的候选域名、官方域名、单位名称、算法分数、匹配类型和命中原因判断。
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
  domain, official_domain, impersonation_likelihood, label, reason, key_features
- impersonation_likelihood 是 0 到 1 的小数。
- label 只能是 likely_impersonation、suspicious_impersonation、unlikely_impersonation、uncertain。
- reason 不超过 50 个中文字符。
- key_features 是字符串数组，元素可包括 brand_token、confusable_brand、login_context、mail_context、auth_context、suffix_change、suspicious_tld、hyphen_or_digit、long_sld、short_token_risk、generic_word_only、insufficient_evidence。

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
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(candidate_items, batch_index)},
        ],
        "temperature": 0.0,
        "max_tokens": max_tokens,
        "stream": False,
        "response_format": {"type": "json_object"},
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    url = os.getenv("DEEPSEEK_API_URL", DEEPSEEK_API_URL)
    last_error: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=timeout_seconds)
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            results = parsed.get("results", [])
            if not isinstance(results, list):
                raise ValueError("DeepSeek JSON response field 'results' must be a list.")
            return normalize_llm_results(results, candidate_items)
        except Exception as exc:
            last_error = exc
            if attempt < max_retries:
                time.sleep(retry_sleep_seconds)
    raise RuntimeError(f"batch {batch_index} failed after {max_retries} attempts: {last_error}")


def normalize_llm_results(
    results: list[dict[str, Any]],
    candidate_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_domain = {str(result.get("domain", "")): result for result in results}
    normalized_rows = []

    for item in candidate_items:
        result = by_domain.get(item["domain"], {})
        score = safe_float(result.get("impersonation_likelihood", 0.0))
        label = str(result.get("label", "uncertain"))
        if label not in ALLOWED_LABELS:
            label = label_from_score(score)

        key_features = result.get("key_features", [])
        if isinstance(key_features, list):
            key_features_text = ",".join(str(feature) for feature in key_features)
        else:
            key_features_text = str(key_features)

        normalized_rows.append(
            {
                "domain": item["domain"],
                "official_domain": str(result.get("official_domain") or item["official_domain"]),
                "impersonation_likelihood": f"{score:.4f}",
                "label": label,
                "reason": str(result.get("reason", ""))[:100],
                "key_features": key_features_text,
            }
        )
    return normalized_rows


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
