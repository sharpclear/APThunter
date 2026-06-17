from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from typing import Any, List
from urllib.parse import urlsplit

import requests


DEFAULT_DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"
DEFAULT_DEEPSEEK_MODEL = "deepseek-v4-flash"
DEFAULT_MAX_DOMAINS = 20

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class OfficialDomainResolutionError(RuntimeError):
    pass


class OfficialDomainResolverConfigError(OfficialDomainResolutionError):
    pass


SYSTEM_PROMPT = """你是网络安全场景下的官方域名识别助手。

任务：根据用户输入的事件名、活动名、组织名、单位名或机构名，列出与其直接相关的一组官方域名，用作仿冒域名检测的官方域名基线。

必须遵守：
- 不要只返回主站。应尽量返回一系列高置信官方域名，包括主官网、重要二级域名、官方业务系统、门户、招生/招聘、邮箱、新闻、院系/部门、活动或会议相关官方域名。
- 对高校、政府、企业、赛事、会议、展会、专项行动等不同类型输入，优先覆盖该实体公开使用的多个官方域名或官方子域名。
- 同一注册域下的明确官方子域名可以分别返回，例如 portal.example.edu、mail.example.edu、news.example.edu。
- 只返回你有较高把握属于该事件/组织/单位的官方网站、官方子域名或官方业务域名。
- 不要返回社交媒体、百科、新闻报道、镜像站、第三方服务、应用商店、搜索结果、邮箱地址、URL路径或通配符。
- 目标是返回 5 到 20 个相关官方域名；确实只知道主站时才返回 1 个，但不要因为只想到主站就停止，应继续识别相关官方子域名和业务域名。
- 不确定时少返回，不要为了凑数量编造域名；但对明确属于同一单位或事件的官方子域名应尽量完整返回。
- 域名必须是可直接用于仿冒检测的主机名或注册域名，例如 example.com、sub.example.org。
- JSON 顶层只能是 {"results": [...]}。
- results 每项必须包含 organization、domain、confidence、reason。
- confidence 为 0 到 1 的小数；低于 0.60 的不要返回。
- reason 不超过 40 个中文字符。
"""


def resolve_official_domains(query_name: str) -> List[dict[str, Any]]:
    query = str(query_name or "").strip()
    if not query:
        return []

    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise OfficialDomainResolverConfigError("未配置 DEEPSEEK_API_KEY，无法通过 DeepSeek 解析官方域名")

    max_domains = _env_int("OFFICIAL_DOMAIN_RESOLVER_MAX_DOMAINS", DEFAULT_MAX_DOMAINS)
    max_domains = max(1, min(max_domains, 30))
    payload = {
        "model": os.getenv("DEEPSEEK_MODEL", DEFAULT_DEEPSEEK_MODEL),
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(query, max_domains)},
        ],
        "temperature": 0.0,
        "max_tokens": _env_int("OFFICIAL_DOMAIN_RESOLVER_MAX_TOKENS", 2048),
        "stream": False,
        "response_format": {"type": "json_object"},
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    response_json = _post_deepseek(payload, headers)
    try:
        content = str(response_json["choices"][0]["message"]["content"])
        parsed = _parse_json_object(content)
    except Exception as exc:
        raise OfficialDomainResolutionError(f"DeepSeek 官方域名解析响应格式无效：{exc}") from exc
    results = parsed.get("results") or []
    if not isinstance(results, list):
        raise OfficialDomainResolutionError("DeepSeek 官方域名解析结果格式无效：results 不是数组")
    return _normalize_results(results, query, max_domains)


def _build_user_prompt(query: str, max_domains: int) -> str:
    return (
        "请为下面的事件名或单位名识别一组相关官方域名，用于仿冒域名检测。\n"
        f"输入：{query}\n"
        f"目标返回 5 到 {max_domains} 个高置信官方域名或官方子域名；不要只返回主站。\n"
        "优先覆盖主官网、门户、邮箱、新闻、招生/招聘、业务系统、院系/部门、活动/会议等官方域名。\n"
        "如果只返回 1 个，请确保确实无法识别更多高置信官方域名。\n"
        "只输出 JSON：{\"results\":[{\"organization\":\"...\",\"domain\":\"example.com\","
        "\"confidence\":0.95,\"reason\":\"...\"}]}"
    )


def _post_deepseek(payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    url = os.getenv("DEEPSEEK_API_URL", DEFAULT_DEEPSEEK_API_URL).strip() or DEFAULT_DEEPSEEK_API_URL
    timeout_seconds = _env_int("OFFICIAL_DOMAIN_RESOLVER_TIMEOUT_SEC", 60)
    max_retries = max(1, _env_int("OFFICIAL_DOMAIN_RESOLVER_MAX_RETRIES", 2))
    retry_sleep_seconds = max(0, _env_int("OFFICIAL_DOMAIN_RESOLVER_RETRY_SLEEP_SEC", 2))
    last_error: Exception | None = None

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=timeout_seconds)
            if response.status_code >= 400:
                raise OfficialDomainResolutionError(
                    f"DeepSeek API HTTP {response.status_code}: {response.text[:500]}"
                )
            data = response.json()
            if not isinstance(data, dict):
                raise OfficialDomainResolutionError("DeepSeek API 响应不是 JSON 对象")
            return data
        except Exception as exc:
            last_error = exc
            if attempt < max_retries:
                time.sleep(retry_sleep_seconds)

    raise OfficialDomainResolutionError(f"DeepSeek 官方域名解析失败：{last_error}") from last_error


def _parse_json_object(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
        cleaned = re.sub(r"```$", "", cleaned).strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start < 0 or end <= start:
            raise
        parsed = json.loads(cleaned[start : end + 1])
    if not isinstance(parsed, dict):
        raise OfficialDomainResolutionError("DeepSeek 官方域名解析结果不是 JSON 对象")
    return parsed


def _normalize_results(results: list[Any], query: str, max_domains: int) -> List[dict[str, Any]]:
    domains: List[dict[str, Any]] = []
    seen = set()
    for item in results:
        if isinstance(item, str):
            organization = query
            raw_domain = item
            confidence = 1.0
            reason = ""
        elif isinstance(item, dict):
            organization = str(
                item.get("organization")
                or item.get("company")
                or item.get("单位名称")
                or item.get("公司名称")
                or query
            ).strip()
            raw_domain = str(
                item.get("domain")
                or item.get("官方域名")
                or item.get("域名")
                or item.get("host")
                or ""
            )
            confidence = _safe_float(item.get("confidence"), default=1.0)
            reason = str(item.get("reason") or item.get("evidence") or "").strip()
        else:
            continue

        if confidence < 0.6:
            continue
        domain = _normalize_domain(raw_domain)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        domains.append(
            {
                "单位名称": organization or query,
                "官方域名": domain,
                "confidence": round(confidence, 4),
                "source": "deepseek",
                "reason": reason[:80],
            }
        )
        if len(domains) >= max_domains:
            break
    return domains


def _normalize_domain(raw_value: str) -> str:
    host = _extract_hostname(raw_value)
    if not host:
        return ""
    if host.startswith("www."):
        host = host[4:]
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass
    try:
        ascii_domain = host.encode("idna").decode("ascii").lower().strip(".")
    except UnicodeError:
        return ""
    if len(ascii_domain) > 253 or "." not in ascii_domain:
        return ""
    labels = ascii_domain.split(".")
    if any(not label or not _DOMAIN_LABEL_RE.match(label) for label in labels):
        return ""
    return ascii_domain


def _extract_hostname(raw_value: str) -> str:
    candidate = str(raw_value or "").strip().strip("\"'`<>[](){}，。；;、")
    if not candidate:
        return ""
    candidate = candidate.replace("\\", "/")
    try:
        if "://" in candidate:
            host = urlsplit(candidate).hostname
        elif candidate.startswith("//"):
            host = urlsplit(f"http:{candidate}").hostname
        elif any(separator in candidate for separator in ["/", "?", "#"]):
            host = urlsplit(f"http://{candidate}").hostname
        elif ":" in candidate:
            host = urlsplit(f"//{candidate}").hostname
        else:
            host = candidate
    except ValueError:
        return ""
    return str(host or "").strip().strip(".").lower()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except Exception:
        number = default
    return max(0.0, min(1.0, number))


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default
