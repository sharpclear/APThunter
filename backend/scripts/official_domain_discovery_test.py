#!/usr/bin/env python3
"""
Search-augmented LLM test script for official domain discovery.

Current flow:
    1. DeepSeek generates search queries from the input event or organization.
    2. Tavily or SerpAPI searches the web with those AI-generated queries.
    3. The script extracts host/root_domain candidates from search result URLs.
    4. DeepSeek judges related official root domains from search-result evidence.
    5. The script runs site:{root_domain} expansion for related root domains.
    6. DeepSeek judges related official subdomains from expansion evidence.
    7. CSV is written under backend/scripts by default.

This script is intentionally independent and does not touch API routes, Celery,
database models, MySQL, MinIO, frontend pages, or existing detection tasks.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import requests
except ImportError:  # pragma: no cover - fallback for minimal environments
    requests = None


DEFAULT_DEEPSEEK_API_KEY = ""
DEFAULT_TAVILY_API_KEY = ""
DEFAULT_SERPAPI_API_KEY = ""

DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODEL = "deepseek-v4-flash"
TAVILY_API_URL = "https://api.tavily.com/search"
SERPAPI_API_URL = "https://serpapi.com/search.json"

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = SCRIPT_DIR

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
DEFAULT_HTTP_RETRIES = 3
DEFAULT_HTTP_RETRY_DELAY = 1.2
DEFAULT_MAX_RESULTS = 100
DEFAULT_SEARCH_QUERY_COUNT = 10
DEFAULT_PER_QUERY_LIMIT = 20
DEFAULT_SUBDOMAIN_RESULTS = 30

MULTI_LABEL_SUFFIXES = {
    "ac.cn",
    "com.cn",
    "edu.cn",
    "gov.cn",
    "mil.cn",
    "net.cn",
    "org.cn",
    "公司.cn",
    "网络.cn",
    "政务.cn",
    "com.hk",
    "edu.hk",
    "gov.hk",
    "net.hk",
    "org.hk",
    "com.mo",
    "edu.mo",
    "gov.mo",
    "net.mo",
    "org.mo",
    "com.tw",
    "edu.tw",
    "gov.tw",
    "net.tw",
    "org.tw",
    "co.uk",
    "ac.uk",
    "gov.uk",
    "org.uk",
}

IGNORED_ROOT_DOMAINS = {
    "baidu.com",
    "bing.com",
    "duckduckgo.com",
    "google.com",
    "sogou.com",
    "so.com",
    "sm.cn",
    "yahoo.com",
    "wikipedia.org",
    "zhihu.com",
    "weibo.com",
    "wechat.com",
    "qq.com",
}


@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str
    search_query: str
    provider: str


@dataclass
class CandidateDomain:
    domain: str
    root_domain: str
    result_type: str
    evidence: list[SearchResult] = field(default_factory=list)


class HttpJsonError(RuntimeError):
    pass


def normalize_domain(domain: str) -> str:
    domain = domain.strip().strip(".").lower()
    if not domain:
        return ""
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain


def get_root_domain(domain: str) -> str:
    domain = normalize_domain(domain)
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain

    suffix_2 = ".".join(labels[-2:])
    if suffix_2 in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_ignored_domain(domain: str) -> bool:
    root = get_root_domain(domain)
    return not root or root in IGNORED_ROOT_DOMAINS


def host_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    if host.startswith("www."):
        host = host[4:]
    return normalize_domain(host)


def mask_url_secrets(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    masked_pairs = []
    for key, value in query_pairs:
        if key.lower() in {"api_key", "apikey", "key", "token"}:
            masked_pairs.append((key, "***"))
        else:
            masked_pairs.append((key, value))
    masked_query = urllib.parse.urlencode(masked_pairs)
    return urllib.parse.urlunparse(parsed._replace(query=masked_query))


def should_retry_http_error(exc: Exception) -> bool:
    if requests is not None:
        request_exceptions = (
            requests.exceptions.SSLError,
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
        )
        if isinstance(exc, request_exceptions):
            return True
    return isinstance(exc, (urllib.error.URLError, TimeoutError, OSError))


def http_get_json(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 45,
    retries: int = DEFAULT_HTTP_RETRIES,
) -> dict[str, Any]:
    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)
    safe_url = mask_url_secrets(url)
    last_exc: Exception | None = None

    for attempt in range(1, retries + 1):
        try:
            if requests is not None:
                response = requests.get(url, headers=request_headers, timeout=timeout)
                response.raise_for_status()
                return response.json()

            request = urllib.request.Request(url, headers=request_headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                body = response.read().decode(charset, errors="replace")
                return json.loads(body)
        except Exception as exc:
            last_exc = exc
            if attempt >= retries or not should_retry_http_error(exc):
                break
            print(f"[warn] GET retry {attempt}/{retries}: {safe_url}: {exc}", file=sys.stderr)
            time.sleep(DEFAULT_HTTP_RETRY_DELAY * attempt)

    raise HttpJsonError(f"GET JSON failed after {retries} attempts: {safe_url}: {last_exc}") from last_exc


def http_post_json(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout: int = 60,
    retries: int = DEFAULT_HTTP_RETRIES,
) -> dict[str, Any]:
    request_headers = {"User-Agent": USER_AGENT}
    request_headers.update(headers)
    safe_url = mask_url_secrets(url)
    last_exc: Exception | None = None

    for attempt in range(1, retries + 1):
        try:
            if requests is not None:
                response = requests.post(url, headers=request_headers, json=payload, timeout=timeout)
                response.raise_for_status()
                return response.json()

            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            request = urllib.request.Request(url, data=data, headers=request_headers, method="POST")
            with urllib.request.urlopen(request, timeout=timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                body = response.read().decode(charset, errors="replace")
                return json.loads(body)
        except Exception as exc:
            last_exc = exc
            if attempt >= retries or not should_retry_http_error(exc):
                break
            print(f"[warn] POST retry {attempt}/{retries}: {safe_url}: {exc}", file=sys.stderr)
            time.sleep(DEFAULT_HTTP_RETRY_DELAY * attempt)

    raise HttpJsonError(f"POST JSON failed after {retries} attempts: {safe_url}: {last_exc}") from last_exc


def search_tavily(search_query: str, max_results: int, api_key: str) -> list[SearchResult]:
    payload = {
        "query": search_query,
        "search_depth": "basic",
        "max_results": max_results,
        "include_answer": False,
        "include_raw_content": False,
    }
    data = http_post_json(
        TAVILY_API_URL,
        {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        payload,
    )
    results = []
    for item in data.get("results", []):
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        results.append(
            SearchResult(
                title=str(item.get("title") or "").strip(),
                url=url,
                snippet=str(item.get("content") or "").strip(),
                search_query=search_query,
                provider="tavily",
            )
        )
    return results


def search_serpapi(search_query: str, max_results: int, api_key: str) -> list[SearchResult]:
    params = urllib.parse.urlencode(
        {
            "engine": "google",
            "q": search_query,
            "api_key": api_key,
            "num": max_results,
            "hl": "zh-cn",
            "gl": "cn",
        }
    )
    data = http_get_json(f"{SERPAPI_API_URL}?{params}")
    results = []
    for item in data.get("organic_results", []):
        url = str(item.get("link") or "").strip()
        if not url:
            continue
        results.append(
            SearchResult(
                title=str(item.get("title") or "").strip(),
                url=url,
                snippet=str(item.get("snippet") or "").strip(),
                search_query=search_query,
                provider="serpapi",
            )
        )
    return results


def run_search(search_query: str, provider: str, max_results: int, api_key: str) -> list[SearchResult]:
    if provider == "tavily":
        return search_tavily(search_query, max_results, api_key)
    if provider == "serpapi":
        return search_serpapi(search_query, max_results, api_key)
    raise ValueError(f"Unsupported search provider: {provider}")


def collect_search_results(
    search_queries: list[str],
    provider: str,
    search_api_key: str,
    max_results: int,
    delay: float,
) -> list[SearchResult]:
    results: list[SearchResult] = []
    seen_urls: set[str] = set()
    per_query_limit = max(1, min(DEFAULT_PER_QUERY_LIMIT, max_results))

    for search_query in search_queries:
        if len(results) >= max_results:
            break
        print(f"[search:{provider}] {search_query}")
        try:
            items = run_search(search_query, provider, per_query_limit, search_api_key)
        except (HttpJsonError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            print(f"[warn] search failed: {search_query}: {exc}", file=sys.stderr)
            continue

        for item in items:
            if len(results) >= max_results:
                break
            if item.url in seen_urls:
                continue
            seen_urls.add(item.url)
            results.append(item)

        if delay > 0:
            time.sleep(delay)

    return results


def add_evidence(candidate: CandidateDomain, evidence: SearchResult, max_items: int = 8) -> None:
    if any(item.url == evidence.url for item in candidate.evidence):
        return
    if len(candidate.evidence) < max_items:
        candidate.evidence.append(evidence)


def build_root_candidates(search_results: list[SearchResult]) -> dict[str, CandidateDomain]:
    candidates: dict[str, CandidateDomain] = {}
    for result in search_results:
        host = host_from_url(result.url)
        if not host or is_ignored_domain(host):
            continue
        root = get_root_domain(host)
        candidate = candidates.setdefault(
            root,
            CandidateDomain(domain=root, root_domain=root, result_type="root_domain"),
        )
        add_evidence(candidate, result)
    return candidates


def build_subdomain_candidates(root_domain: str, search_results: list[SearchResult]) -> dict[str, CandidateDomain]:
    candidates: dict[str, CandidateDomain] = {}
    for result in search_results:
        host = host_from_url(result.url)
        if not host or host == root_domain:
            continue
        if get_root_domain(host) != root_domain:
            continue
        candidate = candidates.setdefault(
            host,
            CandidateDomain(domain=host, root_domain=root_domain, result_type="subdomain"),
        )
        add_evidence(candidate, result)
    return candidates


def candidate_to_llm_row(candidate: CandidateDomain) -> dict[str, Any]:
    return {
        "domain": candidate.domain,
        "type": candidate.result_type,
        "root_domain": candidate.root_domain,
        "evidence": [
            {
                "title": item.title[:160],
                "url": item.url,
                "snippet": item.snippet[:260],
                "search_query": item.search_query,
            }
            for item in candidate.evidence[:5]
        ],
    }


def extract_json_from_llm_text(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.I)
        text = re.sub(r"\s*```$", "", text)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"(\{.*\}|\[.*\])", text, flags=re.S)
    if not match:
        raise ValueError("LLM response does not contain JSON")
    return json.loads(match.group(1))


def call_deepseek_json(system_prompt: str, user_payload: dict[str, Any], api_key: str) -> Any:
    payload = {
        "model": DEEPSEEK_MODEL,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": "请只返回严格 JSON，不要 Markdown，不要额外解释：\n"
                + json.dumps(user_payload, ensure_ascii=False),
            },
        ],
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    response = http_post_json(DEEPSEEK_API_URL, headers, payload)
    content = response["choices"][0]["message"]["content"]
    return extract_json_from_llm_text(content)


def normalize_llm_result_list(parsed: Any) -> list[dict[str, Any]]:
    if isinstance(parsed, dict):
        for key in ("results", "domains", "data"):
            if isinstance(parsed.get(key), list):
                parsed = parsed[key]
                break
    if not isinstance(parsed, list):
        raise ValueError("LLM response must be a JSON list or contain a list field")
    return [item for item in parsed if isinstance(item, dict)]


def normalize_llm_query_list(parsed: Any) -> list[str]:
    if isinstance(parsed, dict):
        for key in ("queries", "search_queries", "keywords", "data"):
            if isinstance(parsed.get(key), list):
                parsed = parsed[key]
                break
    if not isinstance(parsed, list):
        raise ValueError("LLM search query response must be a JSON list or contain a query list field")

    queries: list[str] = []
    seen: set[str] = set()
    for item in parsed:
        if isinstance(item, str):
            query_text = item.strip()
        elif isinstance(item, dict):
            query_text = str(item.get("query") or item.get("keyword") or "").strip()
        else:
            continue

        query_text = " ".join(query_text.split())
        if not query_text or query_text in seen:
            continue
        seen.add(query_text)
        queries.append(query_text)

    return queries


def generate_search_queries_with_llm(query: str, count: int, deepseek_api_key: str) -> list[str]:
    system_prompt = (
        "你是搜索策略生成助手。你的任务是根据用户输入的事件名或单位名，生成适合搜索 API "
        "召回官方网站、官方页面、主办方/主管单位页面和相关子域名页面的中文检索词。"
        "你只生成检索词，不判断域名，不编造域名。检索词应覆盖官方网站、官方发布、主管/主办/"
        "承办单位、常见简称、英文缩写或权威站点线索。"
    )
    user_payload = {
        "query": query,
        "query_count": count,
        "requirements": [
            "返回严格 JSON 数组，数组元素为字符串。",
            "每个字符串是一条可直接交给搜索 API 的检索词。",
            "不要固定套用同一模板，要根据 query 的类型生成。",
            "不要输出解释、评分或域名结论。",
            "可以包含必要的 site: 限定，但必须由你基于 query 判断是否适合。",
        ],
        "examples": [
            {
                "input": "四川大学",
                "output_style": ["四川大学 官方网站", "四川大学 scu 官方", "四川大学 机构设置 官网"],
            },
            {
                "input": "国家网络安全宣传周",
                "output_style": ["国家网络安全宣传周 官方网站", "国家网络安全宣传周 主办单位", "网络安全宣传周 官方发布"],
            },
        ],
    }
    parsed = call_deepseek_json(system_prompt, user_payload, deepseek_api_key)
    queries = normalize_llm_query_list(parsed)
    if not queries:
        raise ValueError("DeepSeek did not return any usable search queries")
    return queries[:count]


def judge_candidates_with_llm(
    query: str,
    candidates: dict[str, CandidateDomain],
    result_type: str,
    deepseek_api_key: str,
) -> list[dict[str, Any]]:
    if not candidates:
        return []

    system_prompt = (
        "你是搜索增强的官方域名识别助手。你不能凭空搜索或编造域名，只能基于用户给出的"
        "候选域名和搜索结果证据判断。判断目标是：候选域名是否为输入事件名或单位名相关的"
        "官方主域名或官方扩展子域名。不要把百科、新闻、社交媒体、搜索引擎、第三方黄页、"
        "广告页判断为相关官方域名。第一版不做可信度评分。"
    )
    user_payload = {
        "query": query,
        "candidate_type": result_type,
        "decision_rule": "仅当搜索证据支持该域名与 query 的官方身份、主办方、承办方、主管单位或直属单位相关时，related 才为 true。",
        "output_schema": [
            {
                "domain": "candidate domain",
                "type": result_type,
                "root_domain": "root domain",
                "related": True,
                "reason": "简短说明，必须引用搜索证据中的标题、摘要或URL信息",
            }
        ],
        "candidates": [candidate_to_llm_row(item) for item in candidates.values()],
    }
    parsed = call_deepseek_json(system_prompt, user_payload, deepseek_api_key)
    raw_results = normalize_llm_result_list(parsed)
    allowed = {domain: candidate for domain, candidate in candidates.items()}
    related_results: list[dict[str, Any]] = []

    for item in raw_results:
        domain = normalize_domain(str(item.get("domain") or ""))
        candidate = allowed.get(domain)
        if not candidate:
            continue
        if item.get("related") is not True:
            continue
        related_results.append(
            {
                "domain": candidate.domain,
                "type": candidate.result_type,
                "root_domain": candidate.root_domain,
                "reason": str(item.get("reason") or "").strip(),
                "evidence_urls": [evidence.url for evidence in candidate.evidence],
            }
        )

    return related_results


def expand_subdomains_for_roots(
    query: str,
    root_results: list[dict[str, Any]],
    provider: str,
    search_api_key: str,
    max_results_per_root: int,
    delay: float,
) -> dict[str, CandidateDomain]:
    candidates: dict[str, CandidateDomain] = {}
    for root_item in root_results:
        root = root_item["root_domain"]
        search_query = f"{query} site:{root}"
        print(f"[expand:{provider}] {search_query}")
        try:
            results = run_search(search_query, provider, max_results_per_root, search_api_key)
        except (HttpJsonError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            print(f"[warn] subdomain expansion failed: {root}: {exc}", file=sys.stderr)
            continue

        for domain, candidate in build_subdomain_candidates(root, results).items():
            existing = candidates.setdefault(domain, candidate)
            if existing is not candidate:
                for evidence in candidate.evidence:
                    add_evidence(existing, evidence)

        if delay > 0:
            time.sleep(delay)

    return candidates


def safe_filename_part(text: str, max_len: int = 40) -> str:
    text = re.sub(r"[^\w\u4e00-\u9fff.-]+", "_", text, flags=re.U).strip("_")
    return (text or "query")[:max_len]


def write_csv(
    query: str,
    results: list[dict[str, Any]],
    output_dir: Path,
    search_provider: str,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"official_domain_discovery_{safe_filename_part(query)}_{timestamp}.csv"
    output_path = output_dir / filename

    with output_path.open("w", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=[
                "query",
                "result_type",
                "domain",
                "root_domain",
                "evidence_urls",
                "llm_reason",
                "search_provider",
                "llm_model",
                "created_at",
            ],
        )
        writer.writeheader()
        created_at = dt.datetime.now().isoformat(timespec="seconds")
        for item in sorted(results, key=lambda x: (x["root_domain"], x["type"], x["domain"])):
            writer.writerow(
                {
                    "query": query,
                    "result_type": item["type"],
                    "domain": item["domain"],
                    "root_domain": item["root_domain"],
                    "evidence_urls": " | ".join(item.get("evidence_urls") or []),
                    "llm_reason": item.get("reason", ""),
                    "search_provider": search_provider,
                    "llm_model": DEEPSEEK_MODEL,
                    "created_at": created_at,
                }
            )

    return output_path


def get_search_api_key(provider: str, cli_key: str) -> str:
    if cli_key:
        return cli_key
    if provider == "tavily":
        return os.getenv("TAVILY_API_KEY") or DEFAULT_TAVILY_API_KEY
    if provider == "serpapi":
        return os.getenv("SERPAPI_API_KEY") or DEFAULT_SERPAPI_API_KEY
    return ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Search-augmented official root domain and subdomain discovery.")
    parser.add_argument("--query", required=True, help="事件名或单位名，例如：工业和信息化部")
    parser.add_argument("--max-results", type=int, default=DEFAULT_MAX_RESULTS, help="初始搜索结果最大读取数量，默认 100")
    parser.add_argument(
        "--search-provider",
        choices=("tavily", "serpapi"),
        default="tavily",
        help="搜索 API provider，默认 tavily",
    )
    parser.add_argument("--search-api-key", default="", help="搜索 API Key。Tavily 可用 TAVILY_API_KEY，SerpAPI 可用 SERPAPI_API_KEY")
    parser.add_argument("--deepseek-api-key", default="", help="DeepSeek API Key。也可使用环境变量 DEEPSEEK_API_KEY")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="CSV 输出目录，默认 backend/scripts")
    parser.add_argument("--delay", type=float, default=0.5, help="搜索 API 请求间隔秒数，默认 0.5")
    parser.add_argument("--subdomain-results", type=int, default=DEFAULT_SUBDOMAIN_RESULTS, help="每个 related root_domain 的 site 查询结果数，默认 30")
    parser.add_argument("--search-query-count", type=int, default=DEFAULT_SEARCH_QUERY_COUNT, help="DeepSeek 生成的初始检索词数量，默认 10")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    query = args.query.strip()
    if not query:
        print("[error] --query cannot be empty", file=sys.stderr)
        return 2

    deepseek_api_key = args.deepseek_api_key or os.getenv("DEEPSEEK_API_KEY") or DEFAULT_DEEPSEEK_API_KEY
    if not deepseek_api_key:
        print(
            "[error] DeepSeek API Key is required. Fill one of these locations:\n"
            "  1) export DEEPSEEK_API_KEY=\"your_deepseek_api_key\"\n"
            "  2) pass --deepseek-api-key \"your_deepseek_api_key\"\n"
            "  3) edit DEFAULT_DEEPSEEK_API_KEY at the top of this script for local testing only",
            file=sys.stderr,
        )
        return 2

    search_api_key = get_search_api_key(args.search_provider, args.search_api_key)
    if not search_api_key:
        env_name = "TAVILY_API_KEY" if args.search_provider == "tavily" else "SERPAPI_API_KEY"
        default_name = "DEFAULT_TAVILY_API_KEY" if args.search_provider == "tavily" else "DEFAULT_SERPAPI_API_KEY"
        print(
            f"[error] {args.search_provider} API Key is required. Fill one of these locations:\n"
            f"  1) export {env_name}=\"your_search_api_key\"\n"
            "  2) pass --search-api-key \"your_search_api_key\"\n"
            f"  3) edit {default_name} at the top of this script for local testing only",
            file=sys.stderr,
        )
        return 2

    print(f"[start] query={query} provider={args.search_provider}")
    try:
        search_queries = generate_search_queries_with_llm(
            query=query,
            count=max(1, args.search_query_count),
            deepseek_api_key=deepseek_api_key,
        )
    except (HttpJsonError, json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"[error] DeepSeek search query generation failed: {exc}", file=sys.stderr)
        print(
            "[hint] The script now needs DeepSeek before web search because search terms are AI-generated.",
            file=sys.stderr,
        )
        return 1
    print(f"[info] ai_search_queries={len(search_queries)}")
    for index, search_query in enumerate(search_queries, start=1):
        print(f"[query:{index}] {search_query}")

    search_results = collect_search_results(
        search_queries=search_queries,
        provider=args.search_provider,
        search_api_key=search_api_key,
        max_results=max(1, args.max_results),
        delay=max(0, args.delay),
    )
    print(f"[info] search_results={len(search_results)}")

    root_candidates = build_root_candidates(search_results)
    print(f"[info] root_candidates={len(root_candidates)}")
    try:
        root_results = judge_candidates_with_llm(
            query=query,
            candidates=root_candidates,
            result_type="root_domain",
            deepseek_api_key=deepseek_api_key,
        )
    except (HttpJsonError, json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"[error] DeepSeek root_domain judgment failed: {exc}", file=sys.stderr)
        print(
            "[hint] This is usually a network/TLS/API-key/API-quota issue. "
            "Retry once, or test connectivity with: curl https://api.deepseek.com/chat/completions",
            file=sys.stderr,
        )
        return 1
    print(f"[info] related_root_domains={len(root_results)}")

    subdomain_candidates = expand_subdomains_for_roots(
        query=query,
        root_results=root_results,
        provider=args.search_provider,
        search_api_key=search_api_key,
        max_results_per_root=max(1, args.subdomain_results),
        delay=max(0, args.delay),
    )
    print(f"[info] subdomain_candidates={len(subdomain_candidates)}")
    try:
        subdomain_results = judge_candidates_with_llm(
            query=query,
            candidates=subdomain_candidates,
            result_type="subdomain",
            deepseek_api_key=deepseek_api_key,
        )
    except (HttpJsonError, json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"[error] DeepSeek subdomain judgment failed: {exc}", file=sys.stderr)
        print("[hint] Root domain results were found, but subdomain LLM judgment failed.", file=sys.stderr)
        return 1
    print(f"[info] related_subdomains={len(subdomain_results)}")

    output_path = write_csv(
        query=query,
        results=root_results + subdomain_results,
        output_dir=Path(args.output_dir),
        search_provider=args.search_provider,
    )
    print(f"[done] CSV saved: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
