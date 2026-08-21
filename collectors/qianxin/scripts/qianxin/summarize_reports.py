from __future__ import annotations

import argparse
import copy
import difflib
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import time
import unicodedata
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlparse, urlsplit

try:
    from .parse_reports import PROJECT_ROOT, atomic_write_text, configure_console_encoding, project_relative
except ImportError:  # Allow direct execution: python scripts/qianxin/summarize_reports.py
    from parse_reports import (  # type: ignore[no-redef]
        PROJECT_ROOT,
        atomic_write_text,
        configure_console_encoding,
        project_relative,
    )


DEFAULT_INPUT_ROOT = PROJECT_ROOT / "data" / "parsed" / "merged"
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "data" / "summaries"
DEFAULT_MODEL = PROJECT_ROOT / "data" / "models" / "llm" / "Qwen3-4B-Q4_K_M.gguf"
DEFAULT_SERVER = PROJECT_ROOT / "tools" / "llama.cpp" / "b10278" / "llama-server.exe"
PROMPT_VERSION = "qianxin-ti-summary-v3-grounded-fuzzy"
SCHEMA_VERSION = 1
VALIDATOR_VERSION = "qianxin-validator-v2-evidence-ioc"
DIRECT_CONTEXT_RESERVE = 3200
CHUNK_CONTEXT_RESERVE = 2400
DEFAULT_MAX_DIRECT_CHARS = 30000
EXECUTIVE_SUMMARY_MAX_CHARS = 240
EMPTY_LIST_FIELDS = (
    "key_findings",
    "targets",
    "malware_tools",
    "vulnerabilities",
    "attack_chain",
    "timeline",
    "defensive_recommendations",
    "limitations",
)

URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
EMAIL_RE = re.compile(r"(?i)(?<![\w.+-])[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DOMAIN_RE = re.compile(
    r"(?i)(?<![@\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-])"
)
CVE_RE = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")
MITRE_RE = re.compile(r"(?i)\bT\d{4}(?:\.\d{3})?\b")
IOC_HEADING_RE = re.compile(
    r"(?i)^(?:iocs?|indicators?(?:\s+of\s+compromise)?|"
    r"compromise\s+indicators?|威胁指标|失陷指标|攻击指标|入侵指标|"
    r"网络指标|样本指标|附录\s*[:：-]?\s*iocs?)\b"
)
HASH_PATTERNS = {
    "sha256": re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])"),
    "sha1": re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])"),
    "md5": re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])"),
}
FILE_TLDS = {
    "7z", "apk", "bat", "bin", "cfg", "cmd", "css", "csv", "dll", "doc", "docx",
    "exe", "gif", "html", "ico", "ini", "jar", "jpeg", "jpg", "js", "json", "lnk",
    "log", "msi", "pdf", "php", "png", "ps1", "py", "rar", "sh", "svg", "sys", "tar",
    "txt", "vbs", "xls", "xlsx", "xml", "zip",
}
GENERIC_TLDS = {
    "app", "biz", "cloud", "com", "dev", "edu", "example", "google", "gov", "info",
    "int", "io", "me", "mil", "net", "online", "org", "site", "tech", "top", "tv", "xyz",
    "agency", "art", "club", "digital", "email", "icu", "international", "link", "live",
    "market", "network", "news", "ntt", "one", "pro", "run", "shop", "software", "solutions",
    "space", "store", "today", "uno", "website", "world", "xn--3e0b707e",
}
RECOMMENDATION_CUE_RE = re.compile(
    r"(?i)(\b(?:we\s+recommend|our\s+advice|advice\s+is|it\s+is\s+(?:recommended|advisable)|"
    r"(?:organizations?|users?|defenders?|administrators?|(?:security|IT)\s+teams?|"
    r"EDR(?:\s+policies)?|security\s+policies?)\b.{0,80}\b"
    r"(?:should|must|need\s+to|are\s+advised\s+to|is\s+required\s+to)|"
    r"recommendations?\s+(?:to|include)\s+(?:use|disable|enable|deploy|apply)|"
    r"(?:monitoring|detection|EDR)\b.{0,120}\b(?:is\s+essential|is\s+required)\s+to|"
    r"(?:this|that|the)\s+[a-z][a-z -]{1,50}\s+should\s+be\s+"
    r"(?:disabled|enabled|blocked|restricted|patched|updated)|"
    r"(?:safest|recommended)\s+remediation\s+path\b|"
    r"to\s+(?:counter|mitigate|reduce|address)\s+(?:this|that|the)?\s*(?:threat|risk|attack)\b)\b|"
    r"建议|应当|应该|请勿|切勿|务必|需要及时|可采取|"
    r"(?:^|\n|[。；;]\s*)(?:[-*•]\s*)?(?:请)?及时(?:安装|更新|升级|修复|打补丁|处置)|"
    r"рекоменду|следует\b|доцільно|необхідно|слід\s|"
    r"권고|권장|해야\s*합니다|필요합니다|주의해야|절대.+(?:안|않).+됩니다|"
    r"반드시.{0,80}(?:변경|설정|차단|비활성|활성|업데이트|패치)|"
    r"推奨|してください|ないでください|すべき|してはいけません|注意してください)"
)
RECOMMENDATION_IMPERATIVE_START_RE = re.compile(
    r"(?i)^\s*(?:[-*•]\s*)?(?:strengthen|educate|inspect|remove|review|verify|avoid|"
    r"disable|enable|update|patch|apply|restrict|ensure|harden|block|monitor|deploy|"
    r"enforce|hunt|do\s+not|never)\b"
)
NON_TOOL_NAME_RE = re.compile(
    r"(?i)(入侵套件|攻击组织|威胁组织|劫持|钓鱼|水坑|\bintrusion set\b|"
    r"(?:设备)?漏洞|(?:虚假|伪造).{0,12}(?:界面|页面)|"
    r"(?:HTTPS?|TLS).{0,8}(?:通信|通讯|连接)|GitHub\s*(?:仓库|repository)|"
    r"\bALGORIT_[A-Z0-9_]+\b|^\s*DECODE\s+SHELLCODE\s*$|"
    r"\bthreat actor\b|\bvulnerabilit(?:y|ies)\b|\bhijacking\b|\bphishing\b|\bwaterholing\b)"
)
NON_TOOL_ROLE_RE = re.compile(
    r"(?i)^\s*(?:攻击者|威胁行为者|攻击组织|威胁组织|threat actor|intrusion set|"
    r".{0,30}(?:算法|algorithm|hash constant|技术|technique)|"
    r".{0,20}(?:注入|社会工程|钓鱼).{0,10}攻击|"
    r"(?:恶意软件)?(?:活动|战役|campaign|operation))\s*$"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalized_indicator_text(text: str) -> str:
    value = (
        text.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
    )
    # PyMuPDF4LLM can render a visible URL as ``url](url)``. Prefer the link target
    # before the generic URL regex sees both halves as one value.
    value = re.sub(
        r"(?i)https?://[^\s\]]+\]\((https?://[^\s)]+)\)",
        r"\1",
        value,
    )
    value = re.sub(r"(?i)\[[^\]]*\]\((https?://[^\s)]+)\)", r"\1", value)
    return value


def clean_extracted_url(value: str) -> str | None:
    cleaned = value.strip().lstrip("`*_~[")
    if "](" in cleaned:
        cleaned = cleaned.rsplit("](", 1)[-1]
    # Markdown table cells are sometimes emitted without whitespace around
    # the separator, so the generic URL regex consumes the following column.
    cleaned = cleaned.split("|", 1)[0]
    cleaned = cleaned.rstrip(".,;:!?]}*`_~")
    while cleaned.endswith(")") and cleaned.count("(") < cleaned.count(")"):
        cleaned = cleaned[:-1]
    annotation = re.search(r"\([^)]*[\u3400-\u9fff\uac00-\ud7a3]", cleaned)
    if annotation:
        cleaned = cleaned[: annotation.start()]
    if re.search(r"(?i)\[(?:redacted|removed|hidden)", cleaned):
        return None
    if cleaned.count("(") > cleaned.count(")"):
        return None
    if not cleaned or len(cleaned) > 2048:
        return None
    try:
        parsed = urlsplit(cleaned)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    hostname = parsed.hostname.casefold().rstrip(".")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if hostname != "localhost":
            labels = hostname.split(".")
            if len(labels) < 2 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels
            ):
                return None
            tld = labels[-1]
            if len(tld) != 2 and tld not in GENERIC_TLDS:
                return None
    return cleaned


def indicator_classification(
    kind: str,
    value: str,
    page_numbers: set[int],
    reference_pages: set[int],
    explicit_observables: set[str],
) -> str:
    if page_numbers and page_numbers.issubset(reference_pages):
        return "reference"
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        if kind == "ipv4":
            address = ipaddress.ip_address(value)
        elif kind == "urls":
            host = urlsplit(value).hostname
            if host:
                address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        return "local"
    # Plain web links and domains in prose are often vendor articles, social
    # profiles, or documentation rather than attack infrastructure.  Only
    # promote them automatically when the report defangs them or places them
    # in an explicit IOC section; keep the rest for review as candidates.
    if kind in {"urls", "domains", "emails"} and value not in explicit_observables:
        return "candidate"
    return "observable"


def _indicator_map() -> dict[str, dict[str, set[int]]]:
    return {
        kind: defaultdict(set)
        for kind in ("cves", "mitre_techniques", "urls", "domains", "ipv4", "emails", "sha256", "sha1", "md5")
    }


def extract_indicators(pages: Sequence[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    found = _indicator_map()
    explicit_observables: dict[str, set[str]] = defaultdict(set)
    reference_pages: set[int] = set()
    in_references = False
    ioc_heading_level: int | None = None
    for page in pages:
        page_number = int(page["page_number"])
        raw_text = str(page.get("markdown") or "")
        text = normalized_indicator_text(raw_text)
        page_is_ioc = ioc_heading_level is not None
        for heading in re.finditer(r"(?im)^(#{1,6})\s*(.+?)\s*$", text):
            level = len(heading.group(1))
            title = heading.group(2).strip()
            if IOC_HEADING_RE.search(title):
                ioc_heading_level = level
                page_is_ioc = True
            elif ioc_heading_level is not None and level <= ioc_heading_level:
                ioc_heading_level = None
        if re.search(r"(?im)^#{1,6}\s*(?:references?|参考文献|参考资料|引用)\b", text):
            in_references = True
            ioc_heading_level = None
        if in_references:
            reference_pages.add(page_number)
        for value in CVE_RE.findall(text):
            found["cves"][value.upper()].add(page_number)
        for value in MITRE_RE.findall(text):
            found["mitre_techniques"][value.upper()].add(page_number)
        for value in URL_RE.findall(text):
            cleaned = clean_extracted_url(value)
            if cleaned:
                found["urls"][cleaned].add(page_number)
        for value in EMAIL_RE.findall(text):
            found["emails"][value.lower()].add(page_number)
        for value in IPV4_RE.findall(text):
            try:
                normalized = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            found["ipv4"][normalized].add(page_number)
        for value in DOMAIN_RE.findall(text):
            normalized = value.lower().rstrip(".")
            tld = normalized.rsplit(".", 1)[-1]
            if tld in FILE_TLDS or (len(tld) != 2 and tld not in GENERIC_TLDS):
                continue
            found["domains"][normalized].add(page_number)
        for kind, pattern in HASH_PATTERNS.items():
            for value in pattern.findall(text):
                found[kind][value.lower()].add(page_number)
        # Defanging is a strong provenance signal.  Mark web-like values on
        # such pages, and values inside explicit IOC sections, as observables.
        defanged_page = bool(re.search(r"(?i)hxxps?://|\[\.\]|\(\.\)", raw_text))
        if (page_is_ioc or defanged_page) and not in_references:
            for value in URL_RE.findall(text):
                cleaned = clean_extracted_url(value)
                if cleaned:
                    explicit_observables["urls"].add(cleaned)
                    host = urlsplit(cleaned).hostname
                    if host:
                        explicit_observables["domains"].add(host.casefold().rstrip("."))
            for value in DOMAIN_RE.findall(text):
                explicit_observables["domains"].add(value.casefold().rstrip("."))
            for value in EMAIL_RE.findall(text):
                explicit_observables["emails"].add(value.casefold())
    return {
        kind: [
            {
                "value": value,
                "evidence_pages": sorted(page_numbers),
                "classification": indicator_classification(
                    kind,
                    value,
                    page_numbers,
                    reference_pages,
                    explicit_observables[kind],
                ),
            }
            for value, page_numbers in sorted(values.items())
        ]
        for kind, values in found.items()
    }


def chunk_pages(pages: Sequence[dict[str, Any]], max_chars: int) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    current_parts: list[str] = []
    current_pages: list[int] = []
    current_length = 0
    for page in pages:
        page_number = int(page["page_number"])
        part = f"[PDF_PAGE {page_number}]\n{str(page.get('markdown') or '').strip()}"
        if current_parts and current_length + len(part) > max_chars:
            text = "\n\n".join(current_parts)
            chunks.append({"pages": current_pages, "text": text, "sha256": content_hash(text)})
            current_parts, current_pages, current_length = [], [], 0
        current_parts.append(part)
        current_pages.append(page_number)
        current_length += len(part)
    if current_parts:
        text = "\n\n".join(current_parts)
        chunks.append({"pages": current_pages, "text": text, "sha256": content_hash(text)})
    return chunks


def make_chunk(pages: Sequence[dict[str, Any]]) -> dict[str, Any]:
    text = "\n\n".join(
        f"[PDF_PAGE {int(page['page_number'])}]\n{str(page.get('markdown') or '').strip()}"
        for page in pages
    )
    return {
        "pages": [int(page["page_number"]) for page in pages],
        "text": text,
        "sha256": content_hash(text),
    }


def make_page_segment_chunk(page_number: int, text: str) -> dict[str, Any]:
    rendered = f"[PDF_PAGE {page_number}]\n{text.strip()}"
    return {
        "pages": [page_number],
        "text": rendered,
        "sha256": content_hash(rendered),
    }


def split_oversized_page(
    page: dict[str, Any],
    client: "LocalLlamaClient",
    context_size: int,
    max_chars: int = 0,
) -> list[dict[str, Any]]:
    """Split a single text-heavy page without losing its original PDF page number."""
    page_number = int(page["page_number"])
    remaining = str(page.get("markdown") or "").strip()
    token_limit = context_size - CHUNK_CONTEXT_RESERVE
    segments: list[dict[str, Any]] = []
    while remaining:
        whole = make_page_segment_chunk(page_number, remaining)
        whole_fits_chars = not max_chars or len(whole["text"]) <= max_chars
        if (
            whole_fits_chars
            and client.token_count(CHUNK_SYSTEM_PROMPT + "\n" + chunk_prompt(whole)) <= token_limit
        ):
            segments.append(whole)
            break

        low, high, best = 1, len(remaining), 0
        while low <= high:
            midpoint = (low + high) // 2
            candidate = make_page_segment_chunk(page_number, remaining[:midpoint])
            tokens = client.token_count(CHUNK_SYSTEM_PROMPT + "\n" + chunk_prompt(candidate))
            fits_chars = not max_chars or len(candidate["text"]) <= max_chars
            if fits_chars and tokens <= token_limit:
                best = midpoint
                low = midpoint + 1
            else:
                high = midpoint - 1
        if best < 1:
            raise ValueError(
                f"Page {page_number} cannot fit the model context even after text splitting"
            )

        split_at = best
        boundary = max(remaining.rfind("\n", 0, best), remaining.rfind(" ", 0, best))
        if boundary >= max(1, best // 2):
            split_at = boundary
        segment_text = remaining[:split_at].strip()
        if not segment_text:
            segment_text = remaining[:best]
            split_at = best
        segments.append(make_page_segment_chunk(page_number, segment_text))
        remaining = remaining[split_at:].strip()
    return segments


def fit_chunks_to_context(
    chunks: Sequence[dict[str, Any]],
    pages: Sequence[dict[str, Any]],
    client: "LocalLlamaClient",
    context_size: int,
) -> list[dict[str, Any]]:
    page_by_number = {int(page["page_number"]): page for page in pages}
    pending = list(chunks)
    fitted: list[dict[str, Any]] = []
    while pending:
        chunk = pending.pop(0)
        prompt_tokens = client.token_count(CHUNK_SYSTEM_PROMPT + "\n" + chunk_prompt(chunk))
        if prompt_tokens <= context_size - 700 or len(chunk["pages"]) == 1:
            fitted.append(chunk)
            continue
        midpoint = len(chunk["pages"]) // 2
        left = make_chunk([page_by_number[number] for number in chunk["pages"][:midpoint]])
        right = make_chunk([page_by_number[number] for number in chunk["pages"][midpoint:]])
        pending[0:0] = [left, right]
    return fitted


def pack_pages_for_context(
    pages: Sequence[dict[str, Any]],
    client: "LocalLlamaClient",
    context_size: int,
    max_chars: int,
) -> list[dict[str, Any]]:
    """Greedily pack pages, splitting an individually oversized page as a fallback."""
    chunks: list[dict[str, Any]] = []
    current: list[dict[str, Any]] = []
    for page in pages:
        single = make_chunk([page])
        single_too_many_chars = bool(max_chars and len(single["text"]) > max_chars)
        single_tokens = client.token_count(CHUNK_SYSTEM_PROMPT + "\n" + chunk_prompt(single))
        if single_too_many_chars or single_tokens > context_size - CHUNK_CONTEXT_RESERVE:
            if current:
                chunks.append(make_chunk(current))
                current = []
            chunks.extend(split_oversized_page(page, client, context_size, max_chars))
            continue
        candidate_pages = [*current, page]
        candidate = make_chunk(candidate_pages)
        too_many_chars = bool(max_chars and len(candidate["text"]) > max_chars)
        prompt_tokens = client.token_count(CHUNK_SYSTEM_PROMPT + "\n" + chunk_prompt(candidate))
        if current and (too_many_chars or prompt_tokens > context_size - CHUNK_CONTEXT_RESERVE):
            chunks.append(make_chunk(current))
            current = [page]
        else:
            current = candidate_pages
    if current:
        chunks.append(make_chunk(current))
    return chunks


def parse_json_response(text: str) -> dict[str, Any]:
    value = text.strip()
    if value.startswith("```"):
        value = re.sub(r"^```(?:json)?\s*", "", value, flags=re.IGNORECASE)
        value = re.sub(r"\s*```$", "", value)
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        start, end = value.find("{"), value.rfind("}")
        if start < 0 or end <= start:
            raise
        parsed = json.loads(value[start : end + 1])
    if not isinstance(parsed, dict):
        raise TypeError("Model response must be a JSON object")
    return parsed


class LocalLlamaClient:
    def __init__(self, base_url: str, *, timeout: int = 600) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Only a loopback HTTP endpoint is allowed; report text must remain local")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def wait_until_ready(self, seconds: int = 180) -> None:
        deadline = time.monotonic() + seconds
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                status = self._request("GET", "/health")
                if status.get("status") == "ok":
                    return
            except (OSError, ValueError, urllib.error.URLError) as exc:
                last_error = exc
            time.sleep(0.5)
        raise TimeoutError(f"Local llama server did not become ready: {last_error}")

    def context_size(self) -> int:
        props = self._request("GET", "/props")
        return int(props["default_generation_settings"]["n_ctx"])

    def token_count(self, text: str) -> int:
        response = self._request("POST", "/tokenize", {"content": text, "add_special": False})
        return len(response["tokens"])

    def chat_json(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int,
        schema: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        payload = {
            "model": "local-qwen3-4b",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "top_p": 0.9,
            "max_tokens": max_tokens,
            "response_format": (
                {
                    "type": "json_schema",
                    "json_schema": {"name": "threat_summary", "strict": True, "schema": schema},
                }
                if schema is not None
                else {"type": "json_object"}
            ),
        }
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                response = self._request("POST", "/v1/chat/completions", payload)
                content = response["choices"][0]["message"]["content"]
                return parse_json_response(content), response.get("timings", {})
            except (KeyError, TypeError, json.JSONDecodeError, urllib.error.URLError) as exc:
                last_error = exc
                payload["messages"].append(
                    {"role": "user", "content": "上一条输出无效。请重新输出单个、完整、可解析的 JSON 对象。"}
                )
                time.sleep(attempt + 1)
        raise RuntimeError(f"Model failed to return valid JSON: {last_error}")


class ReplayClient:
    """Re-run deterministic grounding and validation without invoking the model."""

    replay = True

    def __init__(self, output: dict[str, Any]) -> None:
        self.output = output

    def context_size(self) -> int:
        return 1_000_000

    def token_count(self, text: str) -> int:
        return 0

    def chat_json(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int,
        schema: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return copy.deepcopy(self.output), {}


def start_server(
    server_exe: Path,
    model_path: Path,
    port: int,
    context_size: int,
    threads: int,
) -> tuple[subprocess.Popen[bytes], Any, Any]:
    if not server_exe.is_file():
        raise FileNotFoundError(f"llama-server not found: {server_exe}")
    if not model_path.is_file():
        raise FileNotFoundError(f"GGUF model not found: {model_path}")
    log_root = PROJECT_ROOT / "logs"
    log_root.mkdir(parents=True, exist_ok=True)
    stdout_handle = (log_root / "llama-server.stdout.log").open("ab")
    stderr_handle = (log_root / "llama-server.stderr.log").open("ab")
    command = [
        str(server_exe), "-m", str(model_path), "--host", "127.0.0.1", "--port", str(port),
        "-c", str(context_size), "-t", str(threads), "-tb", str(max(threads, 12)),
        "--parallel", "1", "--reasoning", "off", "--no-webui",
    ]
    creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process = subprocess.Popen(
        command,
        cwd=PROJECT_ROOT,
        stdout=stdout_handle,
        stderr=stderr_handle,
        creationflags=creation_flags,
    )
    return process, stdout_handle, stderr_handle


def stop_server(process: subprocess.Popen[bytes], handles: Sequence[Any]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    for handle in handles:
        handle.close()


def _bounded_string(max_length: int) -> dict[str, Any]:
    return {"type": "string", "maxLength": max_length}


def _fact_schema(fields: dict[str, int]) -> dict[str, Any]:
    properties = {name: _bounded_string(length) for name, length in fields.items()}
    properties["evidence_quote"] = _bounded_string(180)
    properties["evidence_pages"] = {
        "type": "array", "items": {"type": "integer"}, "maxItems": 8
    }
    return {
        "type": "object",
        "properties": properties,
        "required": [*fields, "evidence_quote"],
        "additionalProperties": False,
    }


FACT_SCHEMAS = {
    "key_findings": _fact_schema({"finding": 240}),
    "targets": _fact_schema({"name": 120, "type": 30}),
    "attribution": _fact_schema({"actor": 120, "confidence": 16, "basis": 240}),
    "malware_tools": _fact_schema({"name": 100, "role": 180}),
    "vulnerabilities": _fact_schema({"cve": 24, "description": 180}),
    "attack_chain": _fact_schema({"stage": 60, "activity": 220}),
    "timeline": _fact_schema({"date": 40, "event": 220}),
    "defensive_recommendations": _fact_schema({"recommendation": 220, "rationale": 180}),
}


def _fact_array(field: str, max_items: int) -> dict[str, Any]:
    return {"type": "array", "items": FACT_SCHEMAS[field], "maxItems": max_items}


SUMMARY_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "report_title": _bounded_string(200),
        "executive_summary_zh": _bounded_string(240),
        "key_findings": _fact_array("key_findings", 3),
        "targets": _fact_array("targets", 2),
        "attribution": FACT_SCHEMAS["attribution"],
        "malware_tools": _fact_array("malware_tools", 2),
        "vulnerabilities": _fact_array("vulnerabilities", 1),
        "attack_chain": _fact_array("attack_chain", 2),
        "timeline": _fact_array("timeline", 1),
        "defensive_recommendations": _fact_array("defensive_recommendations", 1),
        "limitations": {"type": "array", "items": _bounded_string(160), "maxItems": 3},
    },
    "required": [
        "report_title", "executive_summary_zh", "key_findings", "targets", "attribution",
        "malware_tools", "vulnerabilities", "attack_chain", "timeline",
        "defensive_recommendations", "limitations",
    ],
    "additionalProperties": False,
}


CHUNK_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "chunk_summary_zh": _bounded_string(160),
        "key_findings": _fact_array("key_findings", 2),
        "targets": _fact_array("targets", 1),
        "attribution_evidence": {
            "type": "array", "items": FACT_SCHEMAS["attribution"], "maxItems": 1
        },
        "malware_tools": _fact_array("malware_tools", 2),
        "vulnerabilities": _fact_array("vulnerabilities", 1),
        "attack_chain": _fact_array("attack_chain", 2),
        "timeline": _fact_array("timeline", 1),
        "defensive_recommendations": _fact_array("defensive_recommendations", 1),
        "limitations": {"type": "array", "items": _bounded_string(160), "maxItems": 2},
    },
    "required": [
        "chunk_summary_zh", "key_findings", "targets", "attribution_evidence",
        "malware_tools", "vulnerabilities", "attack_chain", "timeline",
        "defensive_recommendations", "limitations",
    ],
    "additionalProperties": False,
}


CHUNK_SYSTEM_PROMPT = """你是严谨的网络威胁情报抽取器。只依据给定 PDF 原文，不使用外部知识，不补写防御建议。每条事实的 evidence_quote 必须逐字复制原文中连续的短句；不能提供原文短引的事实不要输出。只输出一个紧凑 JSON 对象。/no_think"""


def chunk_prompt(chunk: dict[str, Any]) -> str:
    return f"""从以下 PDF 片段抽取事实。JSON 必须使用这些键：
{{
  "chunk_summary_zh": "不超过80字的中文概括",
  "key_findings": [{{"finding": "事实", "evidence_quote": "逐字原文短引"}}],
  "targets": [{{"name": "目标", "type": "country|sector|organization|person|group", "evidence_quote": "逐字原文短引"}}],
  "attribution_evidence": [{{"actor": "攻击者", "basis": "归因依据", "confidence": "high|medium|low|unknown", "evidence_quote": "逐字原文短引"}}],
  "malware_tools": [{{"name": "名称", "role": "用途", "evidence_quote": "逐字原文短引"}}],
  "vulnerabilities": [{{"cve": "CVE编号或空字符串", "description": "用途", "evidence_quote": "逐字原文短引"}}],
  "attack_chain": [{{"stage": "阶段", "activity": "行为", "evidence_quote": "逐字原文短引"}}],
  "timeline": [{{"date": "日期", "event": "事件", "evidence_quote": "逐字原文短引"}}],
  "defensive_recommendations": [{{"recommendation": "仅限报告明确给出的建议", "evidence_quote": "逐字原文短引"}}],
  "limitations": []
}}
全部数组合计最多 10 个事实对象，只保留最重要内容。evidence_quote 使用报告原语言连续 6 至 24 个词（中文可为 12 至 60 字），不要翻译、拼接或省略。没有内容必须为 []。不要把攻击行为改写成防御建议。

PDF 片段：
{chunk['text']}"""


FINAL_SYSTEM_PROMPT = """你是严谨的高级网络威胁情报编辑。仅将给定的、已经由程序定位页码的事实笔记去重归并，不添加外部知识或新事实。必须原样保留每条事实的 evidence_quote 和 evidence_pages；不要自行编造防御建议。只输出一个紧凑 JSON 对象。/no_think"""


def final_prompt(source: dict[str, Any], notes: Sequence[dict[str, Any]], indicators: dict[str, Any]) -> str:
    compact_indicators = {
        "cves": indicators["cves"],
        "mitre_techniques": indicators["mitre_techniques"],
    }
    return f"""将事实笔记合并。JSON 必须使用这些键：
{{
  "report_title": "报告原文标题，无法确认则用 PDF 元数据标题",
  "executive_summary_zh": "2至4句中文摘要",
  "key_findings": [{{"finding": "关键发现", "evidence_quote": "原文短引", "evidence_pages": []}}],
  "targets": [{{"name": "目标", "type": "类型", "evidence_quote": "原文短引", "evidence_pages": []}}],
  "attribution": {{"actor": "攻击者", "confidence": "high|medium|low|unknown", "basis": "归因依据", "evidence_quote": "原文短引", "evidence_pages": []}},
  "malware_tools": [{{"name": "名称", "role": "用途", "evidence_quote": "原文短引", "evidence_pages": []}}],
  "vulnerabilities": [{{"cve": "CVE或空字符串", "description": "用途", "evidence_quote": "原文短引", "evidence_pages": []}}],
  "attack_chain": [{{"stage": "阶段", "activity": "行为", "evidence_quote": "原文短引", "evidence_pages": []}}],
  "timeline": [{{"date": "日期", "event": "事件", "evidence_quote": "原文短引", "evidence_pages": []}}],
  "defensive_recommendations": [{{"recommendation": "报告原有建议", "rationale": "理由", "evidence_quote": "原文短引", "evidence_pages": []}}],
  "limitations": ["局限"]
}}
全部数组合计最多 12 个事实对象。合并重复项但必须从输入笔记原样复制 evidence_quote 与 evidence_pages。不要把编号扩写成报告未说明的名称。没有明确归因时 actor 为空、confidence 为 unknown。没有内容必须为 []。

来源元数据：
{json.dumps({'file_name': source.get('file_name'), 'pdf_title': source.get('pdf_metadata', {}).get('title'), 'organization_directory': source.get('organization_directory')}, ensure_ascii=False)}

显式编号（只用于防漏）：
{json.dumps(compact_indicators, ensure_ascii=False)}

分块事实笔记：
{json.dumps(notes, ensure_ascii=False)}"""


DIRECT_SYSTEM_PROMPT = """你是严谨的网络威胁情报分析员。只依据给定 PDF 原文生成中文结构化摘要，不使用外部知识，不补写报告未提供的防御建议。每条事实的 evidence_quote 必须逐字复制原文中的连续短句；不能提供原文短引就不要输出。只输出一个紧凑 JSON 对象。/no_think"""


def direct_prompt(source: dict[str, Any], report_text: str) -> str:
    return f"""直接分析整份报告。输出：
{{
  "report_title": "原文标题",
  "executive_summary_zh": "2至4句中文摘要",
  "key_findings": [{{"finding": "发现", "evidence_quote": "逐字原文短引"}}],
  "targets": [{{"name": "目标", "type": "country|sector|organization|person|group", "evidence_quote": "逐字原文短引"}}],
  "attribution": {{"actor": "攻击者", "confidence": "high|medium|low|unknown", "basis": "归因依据", "evidence_quote": "逐字原文短引"}},
  "malware_tools": [{{"name": "名称", "role": "用途", "evidence_quote": "逐字原文短引"}}],
  "vulnerabilities": [{{"cve": "CVE或空字符串", "description": "用途", "evidence_quote": "逐字原文短引"}}],
  "attack_chain": [{{"stage": "阶段", "activity": "行为", "evidence_quote": "逐字原文短引"}}],
  "timeline": [{{"date": "日期", "event": "事件", "evidence_quote": "逐字原文短引"}}],
  "defensive_recommendations": [{{"recommendation": "仅限报告明确给出的建议", "rationale": "理由", "evidence_quote": "逐字原文短引"}}],
  "limitations": []
}}
全部数组合计最多 12 个事实对象。evidence_quote 使用报告原语言连续 6 至 16 个词（中文可为 12 至 40 字），不得翻译、拼接、省略。不要把攻击方法反向改写成建议。没有内容必须为 []；无明确归因时 actor 为空且 confidence 为 unknown。

来源元数据：
{json.dumps({'file_name': source.get('file_name'), 'pdf_title': source.get('pdf_metadata', {}).get('title')}, ensure_ascii=False)}

PDF 原文：
{report_text}"""


def normalize_summary(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["report_title"] = str(result.get("report_title") or "").strip()
    result["executive_summary_zh"] = str(result.get("executive_summary_zh") or "").strip()
    for field in EMPTY_LIST_FIELDS:
        if not isinstance(result.get(field), list):
            result[field] = []
    if not isinstance(result.get("attribution"), dict):
        result["attribution"] = {
            "actor": "", "confidence": "unknown", "basis": "", "evidence_pages": []
        }
    return result


def normalize_match_text(text: str) -> str:
    value = unicodedata.normalize("NFKC", text).casefold().replace("\u00ad", "")
    return re.sub(r"\s+", " ", value).strip()


def find_quote_pages(quote: str, normalized_pages: dict[int, str]) -> tuple[list[int], str]:
    exact = [page for page, text in normalized_pages.items() if quote and quote in text]
    if exact:
        return sorted(exact), "exact"
    if len(quote) < 40:
        return [], "none"

    character_scores: list[tuple[float, int]] = []
    for page, text in normalized_pages.items():
        longest = difflib.SequenceMatcher(None, quote, text, autojunk=False).find_longest_match().size
        character_scores.append((longest / len(quote), page))
    character_scores.sort(reverse=True)
    best_score, best_page = character_scores[0]
    second_score = character_scores[1][0] if len(character_scores) > 1 else 0.0
    if best_score >= 0.85 and best_score - second_score >= 0.15:
        return [best_page], "fuzzy_unique_characters"

    quote_tokens = re.findall(r"[a-z0-9]+", quote)
    if len(quote_tokens) >= 6:
        quote_counter = Counter(quote_tokens)
        token_scores: list[tuple[float, int]] = []
        for page, text in normalized_pages.items():
            page_counter = Counter(re.findall(r"[a-z0-9]+", text))
            overlap = sum(min(count, page_counter[token]) for token, count in quote_counter.items())
            token_scores.append((overlap / len(quote_tokens), page))
        token_scores.sort(reverse=True)
        best_score, best_page = token_scores[0]
        second_score = token_scores[1][0] if len(token_scores) > 1 else 0.0
        if (
            (best_score >= 0.95 and best_score - second_score >= 0.08)
            or (best_score >= 0.72 and best_score - second_score >= 0.15)
        ):
            return [best_page], "fuzzy_unique_tokens"

    cjk_characters = "".join(re.findall(r"[\u3400-\u9fff\uac00-\ud7a3]", quote))
    cjk_grams = [cjk_characters[index : index + 2] for index in range(len(cjk_characters) - 1)]
    if len(cjk_grams) >= 8:
        quote_counter = Counter(cjk_grams)
        gram_scores: list[tuple[float, int]] = []
        for page, text in normalized_pages.items():
            page_characters = "".join(re.findall(r"[\u3400-\u9fff\uac00-\ud7a3]", text))
            page_counter = Counter(
                page_characters[index : index + 2] for index in range(len(page_characters) - 1)
            )
            overlap = sum(min(count, page_counter[gram]) for gram, count in quote_counter.items())
            gram_scores.append((overlap / len(cjk_grams), page))
        gram_scores.sort(reverse=True)
        best_score, best_page = gram_scores[0]
        second_score = gram_scores[1][0] if len(gram_scores) > 1 else 0.0
        if best_score >= 0.85 and best_score - second_score >= 0.25:
            return [best_page], "fuzzy_unique_cjk_bigrams"
    return [], "none"


def ground_quotes(
    value: dict[str, Any],
    pages: Sequence[dict[str, Any]],
    *,
    allowed_pages: set[int] | None = None,
) -> list[dict[str, Any]]:
    normalized_pages = {
        int(page["page_number"]): normalize_match_text(str(page.get("markdown") or ""))
        for page in pages
        if allowed_pages is None or int(page["page_number"]) in allowed_pages
    }
    ungrounded: list[dict[str, Any]] = []
    list_fields = (
        "key_findings", "targets", "attribution_evidence", "malware_tools", "vulnerabilities",
        "attack_chain", "timeline", "defensive_recommendations",
    )
    for field in list_fields:
        grounded_items: list[dict[str, Any]] = []
        items = value.get(field, [])
        if not isinstance(items, list):
            value[field] = []
            continue
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            quote = normalize_match_text(str(item.get("evidence_quote") or ""))
            matches, match_method = find_quote_pages(quote, normalized_pages)
            if matches:
                item["evidence_pages"] = sorted(matches)
                item["evidence_match"] = match_method
                grounded_items.append(item)
            else:
                ungrounded.append(
                    {"path": f"$.{field}[{index}]", "evidence_quote": item.get("evidence_quote", "")}
                )
        value[field] = grounded_items

    attribution = value.get("attribution")
    if isinstance(attribution, dict):
        quote = normalize_match_text(str(attribution.get("evidence_quote") or ""))
        matches, match_method = find_quote_pages(quote, normalized_pages)
        if matches:
            attribution["evidence_pages"] = sorted(matches)
            attribution["evidence_match"] = match_method
        elif attribution.get("actor"):
            ungrounded.append({"path": "$.attribution", "evidence_quote": attribution.get("evidence_quote", "")})
            value["attribution"] = {
                "actor": "", "confidence": "unknown", "basis": "", "evidence_quote": "", "evidence_pages": []
            }
    return ungrounded


def filter_non_prescriptive_recommendations(summary: dict[str, Any]) -> list[dict[str, Any]]:
    removed: list[dict[str, Any]] = []
    kept: list[dict[str, Any]] = []
    for index, item in enumerate(summary.get("defensive_recommendations", [])):
        quote = str(item.get("evidence_quote") or "") if isinstance(item, dict) else ""
        if RECOMMENDATION_CUE_RE.search(quote) or RECOMMENDATION_IMPERATIVE_START_RE.search(quote):
            kept.append(item)
        else:
            removed.append({"path": f"$.defensive_recommendations[{index}]", "evidence_quote": quote})
    summary["defensive_recommendations"] = kept
    return removed


def filter_non_tool_names(summary: dict[str, Any]) -> list[dict[str, Any]]:
    removed: list[dict[str, Any]] = []
    kept: list[dict[str, Any]] = []
    actor = str(summary.get("attribution", {}).get("actor") or "")
    generic_actor_tokens = {"actor", "actors", "group", "organization", "threat"}

    def actor_alias_tokens(value: str) -> set[str]:
        return {
            token
            for token in re.findall(r"(?i)[a-z0-9][a-z0-9-]{2,}", value)
            if token.casefold() not in generic_actor_tokens
        }

    actor_tokens = {token.casefold() for token in actor_alias_tokens(actor)}
    for index, item in enumerate(summary.get("malware_tools", [])):
        name = str(item.get("name") or "") if isinstance(item, dict) else ""
        role = str(item.get("role") or "") if isinstance(item, dict) else ""
        evidence_quote = str(item.get("evidence_quote") or "") if isinstance(item, dict) else ""
        name_tokens = {token.casefold() for token in actor_alias_tokens(name)}
        is_actor_alias = bool(actor_tokens and name_tokens and name_tokens.issubset(actor_tokens))
        role_is_actor = bool(NON_TOOL_ROLE_RE.search(role))
        quote_identifies_actor = bool(
            name
            and re.search(
                rf"(?i)\b{re.escape(name)}\b\s*:\s*.{{0,100}}\b(?:hackers?|threat\s+actor|group)\b",
                evidence_quote,
            )
        )
        if NON_TOOL_NAME_RE.search(name) or is_actor_alias or role_is_actor or quote_identifies_actor:
            removed.append(
                {
                    "path": f"$.malware_tools[{index}]",
                    "name": name,
                    "reason": (
                        "actor_alias"
                        if is_actor_alias or role_is_actor or quote_identifies_actor
                        else "non_tool_name"
                    ),
                }
            )
        else:
            kept.append(item)
    summary["malware_tools"] = kept
    return removed


NO_VULNERABILITY_RE = re.compile(
    r"(?i)(未指定(?:具体)?(?:漏洞)?|"
    r"未(?:明确|提及|发现|识别|利用).{0,12}(?:漏洞|CVE)|"
    r"(?:没有|不存在).{0,12}(?:已知|具体|明确|任何)?.{0,8}(?:漏洞|CVE)|"
    r"无(?:(?:已知|具体|明确|任何|可利用).{0,8})?(?:漏洞|CVE)|"
    r"不涉及.{0,8}(?:漏洞|CVE)|"
    r"no\s+(?:(?:specific|explicit|known|identified)\s+)?(?:vulnerabilit(?:y|ies)|CVEs?)|"
    r"(?:vulnerabilit(?:y|ies)|CVEs?)\s+(?:was|were|is|are)?\s*(?:not|never)\s+"
    r"(?:identified|found|observed|mentioned|specified|exploited)|"
    r"not\s+(?:specified|mentioned|identified|found).{0,16}(?:vulnerabilit|CVE))"
)
VULNERABILITY_EVIDENCE_RE = re.compile(
    r"(?i)(CVE-\d{4}-\d{4,7}|\bvulnerabilit\w*\b|\bsecurity\s+flaw\b|\bzero[- ]day\b|"
    r"\b0[- ]day\b|漏洞|脆弱性|취약점|취약성|уязвим|вразлив)"
)


def filter_vulnerability_placeholders(summary: dict[str, Any]) -> list[dict[str, Any]]:
    removed: list[dict[str, Any]] = []
    kept: list[dict[str, Any]] = []
    for index, item in enumerate(summary.get("vulnerabilities", [])):
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cve") or "").strip().upper()
        description = str(item.get("description") or "").strip()
        evidence_quote = str(item.get("evidence_quote") or "").strip()
        invalid_cve = bool(cve and not CVE_RE.fullmatch(cve))
        negative_context = bool(NO_VULNERABILITY_RE.search(f"{description}\n{evidence_quote}"))
        placeholder = bool(not cve and not description and not evidence_quote)
        unsupported_type = bool(not cve and not VULNERABILITY_EVIDENCE_RE.search(evidence_quote))
        if invalid_cve or negative_context or placeholder or unsupported_type:
            reason = (
                "invalid_cve"
                if invalid_cve
                else (
                    "negated_vulnerability"
                    if negative_context
                    else ("empty_placeholder" if placeholder else "not_explicitly_a_vulnerability")
                )
            )
            removed.append(
                {
                    "path": f"$.vulnerabilities[{index}]",
                    "cve": cve,
                    "description": description,
                    "reason": reason,
                }
            )
        else:
            item["cve"] = cve
            kept.append(item)
    summary["vulnerabilities"] = kept
    return removed


def validate_evidence_pages(value: Any, page_count: int, path: str = "$") -> list[dict[str, Any]]:
    invalid: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "evidence_pages":
                if not isinstance(item, list):
                    invalid.append({"path": f"{path}.{key}", "value": item})
                    value[key] = []
                    continue
                cleaned: list[int] = []
                for page in item:
                    if isinstance(page, int) and not isinstance(page, bool) and 1 <= page <= page_count:
                        cleaned.append(page)
                    else:
                        invalid.append({"path": f"{path}.{key}", "value": page})
                value[key] = sorted(set(cleaned))
            else:
                invalid.extend(validate_evidence_pages(item, page_count, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            invalid.extend(validate_evidence_pages(item, page_count, f"{path}[{index}]"))
    return invalid


def unsupported_named_items(summary: dict[str, Any], pages: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    page_text = {int(page["page_number"]): str(page.get("markdown") or "").casefold() for page in pages}

    generic_name_tokens = {
        "access", "agent", "android", "apple", "backdoor", "client", "framework",
        "google", "linux", "loader", "malware", "microsoft", "payload", "remote",
        "script", "server", "service", "stealer", "system", "tool", "trojan", "windows",
    }

    def name_is_present(name: str, evidence: Sequence[int]) -> bool:
        compact_name = re.sub(r"[^a-z0-9\u3400-\u9fff\uac00-\ud7a3]", "", name.casefold())
        name_tokens = set(re.findall(r"[a-z0-9][a-z0-9._-]{3,}", name.casefold()))
        informative_tokens = name_tokens - generic_name_tokens
        for page in evidence:
            text = page_text.get(page, "")
            compact_text = re.sub(r"[^a-z0-9\u3400-\u9fff\uac00-\ud7a3]", "", text)
            if compact_name and compact_name in compact_text:
                return True
            page_tokens = set(re.findall(r"[a-z0-9][a-z0-9._-]{3,}", text))
            if informative_tokens and informative_tokens.intersection(page_tokens):
                return True
        return False

    unsupported: list[dict[str, Any]] = []
    for field, key in (("malware_tools", "name"), ("vulnerabilities", "cve")):
        for index, item in enumerate(summary.get(field, [])):
            if not isinstance(item, dict):
                continue
            name = str(item.get(key) or "").strip()
            evidence = item.get("evidence_pages") or []
            if name and evidence and not name_is_present(name, evidence):
                unsupported.append({"path": f"$.{field}[{index}].{key}", "value": name, "evidence_pages": evidence})
    return unsupported


def filter_unsupported_named_items(
    summary: dict[str, Any], pages: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    unsupported = unsupported_named_items(summary, pages)
    indexes: dict[str, set[int]] = defaultdict(set)
    for item in unsupported:
        match = re.match(r"^\$\.(malware_tools|vulnerabilities)\[(\d+)\]", str(item["path"]))
        if match:
            indexes[match.group(1)].add(int(match.group(2)))
    for field, removed_indexes in indexes.items():
        summary[field] = [
            item for index, item in enumerate(summary.get(field, [])) if index not in removed_indexes
        ]
    return unsupported


def remove_duplicate_tool_names(summary: dict[str, Any]) -> list[dict[str, Any]]:
    removed: list[dict[str, Any]] = []
    kept: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(summary.get("malware_tools", [])):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        key = re.sub(r"[^a-z0-9\u3400-\u9fff\uac00-\ud7a3]", "", name.casefold())
        if key and key in seen:
            removed.append(
                {
                    "path": f"$.malware_tools[{index}]",
                    "name": name,
                    "reason": "duplicate_normalized_name",
                }
            )
            continue
        if key:
            seen.add(key)
        kept.append(item)
    summary["malware_tools"] = kept
    return removed


def build_validated_executive_summary(summary: dict[str, Any]) -> str:
    candidates: list[tuple[str, list[int]]] = []
    for field in ("key_findings", "attack_chain"):
        for item in summary.get(field, []):
            if not isinstance(item, dict):
                continue
            text = str(item.get("evidence_quote") or "").strip()
            pages = item.get("evidence_pages") or []
            if text and pages:
                candidates.append((text, pages))
    unique: list[tuple[str, list[int]]] = []
    seen: set[str] = set()
    for text, pages in candidates:
        normalized = normalize_match_text(text)
        if normalized and normalized not in seen:
            seen.add(normalized)
            unique.append((text, pages))
        if len(unique) == 3:
            break
    if not unique:
        return "未从报告中提取到具有可定位原文证据的关键事实。"

    parts: list[str] = []
    current_length = 0
    for text, pages in unique:
        suffix = f"”{format_evidence(pages)}。"
        prefix = "“"
        rendered = f"{prefix}{text}{suffix}"
        if current_length + len(rendered) <= EXECUTIVE_SUMMARY_MAX_CHARS:
            parts.append(rendered)
            current_length += len(rendered)
            continue
        available = (
            EXECUTIVE_SUMMARY_MAX_CHARS
            - current_length
            - len(prefix)
            - len(suffix)
            - 1
        )
        if available >= 24:
            shortened = text[:available].rstrip()
            parts.append(f"{prefix}{shortened}…{suffix}")
        break
    return "".join(parts) or "未从报告中提取到具有可定位原文证据的关键事实。"


def lock_reduced_facts_to_notes(
    reduced: dict[str, Any], notes: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Make the reducer select grounded chunk facts instead of rewriting them."""
    removed: list[dict[str, Any]] = []
    fields = (
        "key_findings",
        "targets",
        "malware_tools",
        "vulnerabilities",
        "attack_chain",
        "timeline",
        "defensive_recommendations",
    )
    identity_fields = {
        "key_findings": "finding",
        "targets": "name",
        "malware_tools": "name",
        "vulnerabilities": "cve",
        "attack_chain": "activity",
        "timeline": "event",
        "defensive_recommendations": "recommendation",
    }
    indexes: dict[str, dict[str, list[dict[str, Any]]]] = {field: {} for field in fields}
    attribution_index: dict[str, dict[str, Any]] = {}
    for note in notes:
        if not isinstance(note, dict):
            continue
        for field in fields:
            for item in note.get(field, []):
                if not isinstance(item, dict):
                    continue
                key = normalize_match_text(str(item.get("evidence_quote") or ""))
                if key:
                    indexes[field].setdefault(key, []).append(copy.deepcopy(item))
        for item in note.get("attribution_evidence", []):
            if not isinstance(item, dict):
                continue
            key = normalize_match_text(str(item.get("evidence_quote") or ""))
            if key:
                attribution_index.setdefault(key, copy.deepcopy(item))

    for field in fields:
        selected: list[dict[str, Any]] = []
        seen: set[str] = set()
        for index, item in enumerate(reduced.get(field, [])):
            if not isinstance(item, dict):
                continue
            key = normalize_match_text(str(item.get("evidence_quote") or ""))
            candidates = indexes[field].get(key, [])
            identity_field = identity_fields[field]
            requested_identity = normalize_match_text(str(item.get(identity_field) or ""))
            original = next(
                (
                    candidate
                    for candidate in candidates
                    if normalize_match_text(str(candidate.get(identity_field) or ""))
                    == requested_identity
                ),
                candidates[0] if len(candidates) == 1 else None,
            )
            if original is None:
                removed.append(
                    {
                        "path": f"$.{field}[{index}]",
                        "reason": "not_selected_from_grounded_chunk_fact",
                        "evidence_quote": item.get("evidence_quote", ""),
                    }
                )
            else:
                selected_identity = normalize_match_text(str(original.get(identity_field) or ""))
                selection_key = f"{key}\0{selected_identity}"
                if selection_key in seen:
                    continue
                seen.add(selection_key)
                selected.append(copy.deepcopy(original))
        reduced[field] = selected

    attribution = reduced.get("attribution")
    if isinstance(attribution, dict):
        key = normalize_match_text(str(attribution.get("evidence_quote") or ""))
        original = attribution_index.get(key)
        if original is not None:
            reduced["attribution"] = {
                "actor": original.get("actor", ""),
                "confidence": original.get("confidence", "unknown"),
                "basis": original.get("basis", ""),
                "evidence_quote": original.get("evidence_quote", ""),
                "evidence_pages": copy.deepcopy(original.get("evidence_pages", [])),
                **(
                    {"evidence_match": original["evidence_match"]}
                    if original.get("evidence_match")
                    else {}
                ),
            }
        elif key:
            removed.append(
                {
                    "path": "$.attribution",
                    "reason": "not_selected_from_grounded_chunk_fact",
                    "evidence_quote": attribution.get("evidence_quote", ""),
                }
            )
            reduced["attribution"] = {
                "actor": "",
                "confidence": "unknown",
                "basis": "",
                "evidence_quote": "",
                "evidence_pages": [],
            }
    return removed


def format_evidence(pages: Any) -> str:
    if not isinstance(pages, list) or not pages:
        return ""
    return " [PDF p." + ", ".join(str(page) for page in pages) + "]"


def render_summary_markdown(document: dict[str, Any]) -> str:
    summary = document["summary"]
    source = document["source"]
    lines = [
        f"# {summary.get('report_title') or source.get('file_name')}",
        "",
        f"- 组织目录：{source.get('organization_directory', '')}",
        f"- 报告日期：{source.get('report_date', '')}",
        f"- 源 PDF：`{source.get('path', '')}`",
        "",
        "## 执行摘要",
        "",
        summary.get("executive_summary_zh", ""),
    ]
    sections = (
        ("关键发现", "key_findings", "finding"),
        ("攻击目标", "targets", "name"),
        ("恶意软件与工具", "malware_tools", "name"),
        ("漏洞", "vulnerabilities", "cve"),
        ("攻击链", "attack_chain", "activity"),
        ("时间线", "timeline", "event"),
        ("防御建议", "defensive_recommendations", "recommendation"),
    )
    attribution = summary.get("attribution", {})
    lines.extend(
        [
            "", "## 归因", "",
            f"- 攻击者：{attribution.get('actor') or '报告未明确'}",
            f"- 置信度：{attribution.get('confidence') or 'unknown'}",
            f"- 依据：{attribution.get('basis') or '无'}{format_evidence(attribution.get('evidence_pages'))}",
        ]
    )
    for title, field, key in sections:
        lines.extend(["", f"## {title}", ""])
        items = summary.get(field, [])
        if not items:
            lines.append("- 报告未明确。")
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            primary = str(item.get(key) or "").strip()
            if field == "vulnerabilities" and not primary:
                primary = str(item.get("description") or "").strip()
            details = [
                str(item.get(detail) or "").strip()
                for detail in ("type", "role", "description", "stage", "date", "rationale")
                if item.get(detail) and not (field == "vulnerabilities" and not item.get("cve") and detail == "description")
            ]
            suffix = f" — {'；'.join(details)}" if details else ""
            lines.append(f"- {primary}{suffix}{format_evidence(item.get('evidence_pages'))}")
    lines.extend(["", "## 确定性提取的指标", ""])
    observable_count = 0
    reference_count = 0
    for kind, items in document["indicators"].items():
        observable = [item for item in items if item.get("classification") == "observable"]
        references = [item for item in items if item.get("classification") == "reference"]
        observable_count += len(observable)
        reference_count += len(references)
        if observable:
            lines.append(
                f"- {kind}: "
                + "; ".join(f"{item['value']}{format_evidence(item['evidence_pages'])}" for item in observable)
            )
    if not observable_count:
        lines.append("- 未发现高置信度可观测指标。")
    if reference_count:
        lines.append(f"- 另有 {reference_count} 个值仅出现在参考文献页，已保留在 JSON 中但不作为 IOC 展示。")
    return "\n".join(lines).rstrip() + "\n"


def report_date(source: dict[str, Any]) -> str:
    match = re.match(r"(\d{4}-\d{2}-\d{2})", str(source.get("file_name") or ""))
    return match.group(1) if match else ""


def summarize_report(
    document_path: Path,
    output_root: Path,
    client: LocalLlamaClient,
    *,
    model_name: str,
    max_chunk_chars: int,
    max_direct_chars: int,
    overwrite: bool = False,
) -> dict[str, Any]:
    parsed = read_json(document_path)
    source = dict(parsed["source"])
    parsed_content_sha256 = content_hash(
        json.dumps(parsed.get("pages", []), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )
    source["report_date"] = report_date(source)
    sha8 = source["sha256"][:8]
    destination = output_root / source["organization_directory"] / sha8
    summary_path = destination / "summary.json"
    quality_path = destination / "quality.json"
    previous_quality = (
        read_json(quality_path)
        if getattr(client, "replay", False) and quality_path.exists()
        else None
    )
    if summary_path.exists() and quality_path.exists() and not overwrite:
        existing = read_json(summary_path)
        if (
            existing.get("source", {}).get("sha256") == source["sha256"]
            and existing.get("prompt_version") == PROMPT_VERSION
            and existing.get("model", {}).get("name") == model_name
            and quality_path.exists()
            and read_json(quality_path).get("validator_version") == VALIDATOR_VERSION
            and read_json(quality_path).get("parsed_content_sha256") == parsed_content_sha256
        ):
            quality = read_json(quality_path)
            quality["skipped_existing"] = True
            return quality

    pages = parsed["pages"]
    indicators = extract_indicators(pages)
    report_chunk = make_chunk(pages)
    direct_user_prompt = direct_prompt(source, report_chunk["text"])
    context_size = client.context_size()
    direct_tokens = client.token_count(DIRECT_SYSTEM_PROMPT + "\n" + direct_user_prompt)
    notes: list[dict[str, Any]] = []
    total_timings: Counter[str] = Counter()
    ungrounded: list[dict[str, Any]] = []
    dropped_reduce_rewrites: list[dict[str, Any]] = []
    if getattr(client, "replay", False) or (
        direct_tokens <= context_size - DIRECT_CONTEXT_RESERVE
        and (not max_direct_chars or len(report_chunk["text"]) <= max_direct_chars)
    ):
        inference_mode = "revalidated_raw" if getattr(client, "replay", False) else "direct"
        final_value, final_timings = client.chat_json(
            DIRECT_SYSTEM_PROMPT,
            direct_user_prompt,
            max_tokens=1600,
            schema=SUMMARY_JSON_SCHEMA,
        )
        raw_final_value = copy.deepcopy(final_value)
        replay_original_mode = (
            previous_quality.get("original_inference_mode", previous_quality.get("inference_mode"))
            if previous_quality is not None
            else None
        )
        if getattr(client, "replay", False) and replay_original_mode == "map_reduce":
            checkpoint_notes = [
                checkpoint["note"]
                for checkpoint_path in sorted((destination / "chunks").glob("chunk-*.json"))
                if isinstance((checkpoint := read_json(checkpoint_path)).get("note"), dict)
            ]
            if checkpoint_notes:
                dropped_reduce_rewrites.extend(
                    lock_reduced_facts_to_notes(final_value, checkpoint_notes)
                )
        ungrounded.extend(ground_quotes(final_value, pages))
        chunks = [report_chunk]
    else:
        inference_mode = "map_reduce"
        chunks = pack_pages_for_context(pages, client, context_size, max_chunk_chars)
        for index, chunk in enumerate(chunks, start=1):
            chunk_path = destination / "chunks" / f"chunk-{index:03}.json"
            checkpoint = read_json(chunk_path) if chunk_path.exists() and not overwrite else None
            if (
                checkpoint
                and checkpoint.get("input_sha256") == chunk["sha256"]
                and checkpoint.get("prompt_version") == PROMPT_VERSION
                and checkpoint.get("model") == model_name
            ):
                note = checkpoint["note"]
            else:
                note, timings = client.chat_json(
                    CHUNK_SYSTEM_PROMPT,
                    chunk_prompt(chunk),
                    max_tokens=900,
                    schema=CHUNK_JSON_SCHEMA,
                )
                dropped = ground_quotes(note, pages, allowed_pages=set(chunk["pages"]))
                ungrounded.extend(dropped)
                checkpoint = {
                    "schema_version": SCHEMA_VERSION,
                    "generated_at": utc_now(),
                    "prompt_version": PROMPT_VERSION,
                    "model": model_name,
                    "input_sha256": chunk["sha256"],
                    "source_pages": chunk["pages"],
                    "note": note,
                    "dropped_ungrounded": dropped,
                    "timings": timings,
                }
                write_json(chunk_path, checkpoint)
                for key, value in timings.items():
                    if isinstance(value, (int, float)):
                        total_timings[key] += value
            notes.append(note)
            print(f"  {sha8}: chunk {index}/{len(chunks)} pages {chunk['pages'][0]}-{chunk['pages'][-1]}")
        final_value, final_timings = client.chat_json(
            FINAL_SYSTEM_PROMPT,
            final_prompt(source, notes, indicators),
            max_tokens=1600,
            schema=SUMMARY_JSON_SCHEMA,
        )
        raw_final_value = copy.deepcopy(final_value)
        dropped_reduce_rewrites.extend(lock_reduced_facts_to_notes(final_value, notes))
        ungrounded.extend(ground_quotes(final_value, pages))
    for key, value in final_timings.items():
        if isinstance(value, (int, float)):
            total_timings[key] += value
    summary = normalize_summary(final_value)
    metadata_title = str(source.get("pdf_metadata", {}).get("title") or "").strip()
    if summary["report_title"].lower().endswith(".pdf"):
        first_heading = ""
        for page in pages[:3]:
            match = re.search(r"(?m)^#\s+(.+?)\s*$", str(page.get("markdown") or ""))
            if match:
                first_heading = match.group(1).strip()
                break
        if metadata_title or first_heading:
            summary["report_title"] = metadata_title or first_heading
    removed_non_prescriptive = filter_non_prescriptive_recommendations(summary)
    removed_non_tools = filter_non_tool_names(summary)
    removed_vulnerability_placeholders = filter_vulnerability_placeholders(summary)
    invalid_evidence = validate_evidence_pages(summary, len(pages))
    removed_unsupported = filter_unsupported_named_items(summary, pages)
    removed_duplicate_tools = remove_duplicate_tool_names(summary)
    unsupported = unsupported_named_items(summary, pages)
    summary["executive_summary_zh"] = build_validated_executive_summary(summary)
    warnings: list[str] = []
    if invalid_evidence:
        warnings.append("模型返回了越界或无效证据页码，已从结果中移除。")
    if unsupported:
        warnings.append("部分恶意软件或 CVE 名称未在其证据页精确匹配，建议人工复核。")
    if ungrounded:
        warnings.append(f"已剔除 {len(ungrounded)} 条无法在原文中精确定位短引的模型事实。")
    if removed_non_prescriptive:
        warnings.append(
            f"已剔除 {len(removed_non_prescriptive)} 条由攻击描述反写、缺少原文建议措辞的防御建议。"
        )
    if removed_non_tools:
        warnings.append(f"已从恶意软件/工具列表移除 {len(removed_non_tools)} 个明显的组织或入侵集名称。")
    if removed_vulnerability_placeholders:
        warnings.append(f"已移除 {len(removed_vulnerability_placeholders)} 个空白或格式无效的漏洞占位项。")
    if removed_unsupported:
        warnings.append(f"已移除 {len(removed_unsupported)} 个无法在证据页定位名称的工具或漏洞项。")
    if dropped_reduce_rewrites:
        warnings.append(
            f"已阻止 {len(dropped_reduce_rewrites)} 个未从分块事实原样选择的归并项。"
        )
    if removed_duplicate_tools:
        warnings.append(f"已合并 {len(removed_duplicate_tools)} 个重复工具名称。")
    if not summary["executive_summary_zh"]:
        warnings.append("模型未生成执行摘要。")

    generated_at = utc_now()
    result = {
        "schema_version": SCHEMA_VERSION,
        "validator_version": VALIDATOR_VERSION,
        "generated_at": generated_at,
        "prompt_version": PROMPT_VERSION,
        "model": {"name": model_name, "runtime": "llama.cpp", "local_only": True},
        "source": source,
        "summary": summary,
        "indicators": indicators,
    }
    quality = {
        "schema_version": SCHEMA_VERSION,
        "validator_version": VALIDATOR_VERSION,
        "generated_at": generated_at,
        "source_sha256": source["sha256"],
        "parsed_content_sha256": parsed_content_sha256,
        "status": (
            "needs_review"
            if invalid_evidence or unsupported or not summary["executive_summary_zh"]
            else (
                "ready_with_filtered_items"
                if (
                    ungrounded
                    or removed_non_prescriptive
                    or removed_non_tools
                    or removed_vulnerability_placeholders
                    or removed_unsupported
                    or dropped_reduce_rewrites
                    or removed_duplicate_tools
                )
                else "ready"
            )
        ),
        "page_count": len(pages),
        "chunk_count": len(chunks),
        "inference_mode": inference_mode,
        "context_size": context_size,
        "input_token_count": direct_tokens,
        "indicator_counts": {key: len(value) for key, value in indicators.items()},
        "invalid_evidence": invalid_evidence,
        "unsupported_named_items": unsupported,
        "dropped_ungrounded": ungrounded,
        "removed_non_prescriptive_recommendations": removed_non_prescriptive,
        "removed_non_tool_names": removed_non_tools,
        "removed_vulnerability_placeholders": removed_vulnerability_placeholders,
        "removed_unsupported_named_items": removed_unsupported,
        "dropped_reduce_rewrites": dropped_reduce_rewrites,
        "removed_duplicate_tool_names": removed_duplicate_tools,
        "executive_summary_source": "validated_evidence_quotes",
        "warnings": warnings,
        "timings": dict(total_timings),
        "outputs": {
            "json": project_relative(summary_path),
            "markdown": project_relative(destination / "summary.md"),
            "quality": project_relative(quality_path),
            "raw_model_output": project_relative(destination / "raw-model-output.json"),
        },
    }
    if previous_quality is not None:
        original_inference_mode = previous_quality.get(
            "original_inference_mode", previous_quality.get("inference_mode")
        )
        quality["original_inference_mode"] = original_inference_mode
        for field in ("context_size", "input_token_count", "chunk_count", "timings"):
            if field in previous_quality:
                quality[field] = previous_quality[field]
        if original_inference_mode == "map_reduce":
            checkpoint_count = len(list((destination / "chunks").glob("chunk-*.json")))
            if checkpoint_count:
                quality["chunk_count"] = checkpoint_count
    write_json(
        destination / "raw-model-output.json",
        {
            "schema_version": SCHEMA_VERSION,
            "validator_version": VALIDATOR_VERSION,
            "generated_at": generated_at,
            "prompt_version": PROMPT_VERSION,
            "model": model_name,
            "source_sha256": source["sha256"],
            "parsed_content_sha256": parsed_content_sha256,
            "output": raw_final_value,
        },
    )
    write_json(summary_path, result)
    atomic_write_text(destination / "summary.md", render_summary_markdown(result))
    write_json(quality_path, quality)
    return quality


def discover_documents(input_root: Path) -> list[Path]:
    return sorted(input_root.glob("*/*/document.json"))


def select_documents(paths: Iterable[Path], sha_prefixes: Sequence[str], limit: int | None) -> list[Path]:
    paths = list(paths)
    if sha_prefixes:
        prefixes = [prefix.lower() for prefix in sha_prefixes]
        selected = [path for path in paths if any(path.parent.name.lower().startswith(prefix) for prefix in prefixes)]
        missing = [prefix for prefix in prefixes if not any(path.parent.name.lower().startswith(prefix) for path in paths)]
        if missing:
            raise ValueError(f"No merged report matches SHA prefix(es): {', '.join(missing)}")
    else:
        selected = paths
    return selected[:limit] if limit is not None else selected


def write_batch_summary(output_root: Path) -> dict[str, Any]:
    qualities = [read_json(path) for path in sorted(output_root.glob("*/*/quality.json"))]
    status_counts = Counter(item["status"] for item in qualities)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "report_count": len(qualities),
        "status_counts": dict(sorted(status_counts.items())),
        "reports": qualities,
    }
    write_json(output_root / "batch-summary.json", summary)
    return summary


def load_active_failures(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    value = read_json(path)
    if not isinstance(value, list):
        return {}
    return {
        str(item["document"]): dict(item)
        for item in value
        if isinstance(item, dict) and item.get("document")
    }


def persist_active_failures(path: Path, failures: dict[str, dict[str, Any]]) -> None:
    if failures:
        write_json(path, [failures[key] for key in sorted(failures)])
    else:
        path.unlink(missing_ok=True)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate evidence-linked local-LLM threat summaries.")
    parser.add_argument("--input-root", type=Path, default=DEFAULT_INPUT_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--server-exe", type=Path, default=DEFAULT_SERVER)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--model-name", default="Qwen3-4B-Q4_K_M")
    parser.add_argument("--base-url", default="http://127.0.0.1:8091")
    parser.add_argument("--start-server", action="store_true")
    parser.add_argument(
        "--request-timeout",
        type=int,
        default=600,
        help="Timeout in seconds for each local model HTTP request (default: 600)",
    )
    parser.add_argument("--context-size", type=int, default=16384)
    parser.add_argument("--threads", type=int, default=6)
    parser.add_argument(
        "--max-chunk-chars",
        type=int,
        default=60000,
        help="Secondary character cap; real model token count remains the primary limit",
    )
    parser.add_argument(
        "--max-direct-chars",
        type=int,
        default=DEFAULT_MAX_DIRECT_CHARS,
        help="Route larger reports through checkpointed map-reduce (default: 30000)",
    )
    parser.add_argument("--sha", action="append", default=[])
    parser.add_argument("--limit", type=int)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument(
        "--revalidate-only",
        action="store_true",
        help="Reapply deterministic grounding to saved raw model output without starting a model",
    )
    parser.add_argument("--fail-fast", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    configure_console_encoding()
    args = build_argument_parser().parse_args(argv)
    if args.request_timeout < 1:
        raise SystemExit("--request-timeout must be at least 1 second")
    if args.max_direct_chars < 0:
        raise SystemExit("--max-direct-chars cannot be negative")
    documents = select_documents(discover_documents(args.input_root.resolve()), args.sha, args.limit)
    if not documents:
        raise FileNotFoundError(f"No merged document.json files found below {args.input_root}")
    client: LocalLlamaClient | ReplayClient = LocalLlamaClient(
        args.base_url, timeout=args.request_timeout
    )
    process: subprocess.Popen[bytes] | None = None
    handles: tuple[Any, Any] = (None, None)
    if args.start_server and not args.revalidate_only:
        process, *opened = start_server(
            args.server_exe.resolve(), args.model.resolve(), urlparse(args.base_url).port or 8091,
            args.context_size, args.threads,
        )
        handles = (opened[0], opened[1])
    try:
        if not args.revalidate_only:
            client.wait_until_ready()
        mode_message = "Raw-output revalidation" if args.revalidate_only else "Local model ready"
        print(f"{mode_message}; selected {len(documents)} reports.", flush=True)
        failure_path = args.output_root.resolve() / "failures.json"
        active_failures = load_active_failures(failure_path)
        current_run_failures: list[dict[str, Any]] = []
        for index, document_path in enumerate(documents, start=1):
            print(
                f"[{index}/{len(documents)}] {document_path.parent.parent.name}/{document_path.parent.name}",
                flush=True,
            )
            document_key = project_relative(document_path)
            try:
                active_client: LocalLlamaClient | ReplayClient = client
                force_overwrite = args.overwrite
                effective_model_name = args.model_name
                if args.revalidate_only:
                    raw_path = (
                        args.output_root.resolve()
                        / document_path.parent.parent.name
                        / document_path.parent.name
                        / "raw-model-output.json"
                    )
                    raw = read_json(raw_path)
                    if raw.get("prompt_version") != PROMPT_VERSION:
                        raise ValueError(f"Raw output prompt version does not match: {raw_path}")
                    raw_source_sha = str(raw.get("source_sha256") or "")
                    if raw_source_sha and raw_source_sha != document_path.parent.name:
                        parsed_source_sha = str(read_json(document_path).get("source", {}).get("sha256") or "")
                        if raw_source_sha != parsed_source_sha:
                            raise ValueError(f"Raw output source SHA does not match: {raw_path}")
                    raw_model = str(raw.get("model") or "").strip()
                    if not raw_model:
                        raise ValueError(f"Raw output model is missing: {raw_path}")
                    active_client = ReplayClient(raw["output"])
                    force_overwrite = True
                    effective_model_name = raw_model
                summarize_report(
                    document_path, args.output_root.resolve(), active_client,
                    model_name=effective_model_name, max_chunk_chars=args.max_chunk_chars,
                    max_direct_chars=args.max_direct_chars,
                    overwrite=force_overwrite,
                )
                active_failures.pop(document_key, None)
                persist_active_failures(failure_path, active_failures)
            except Exception as exc:
                previous_attempts = int(active_failures.get(document_key, {}).get("attempts") or 0)
                failure = {
                    "document": document_key,
                    "error": str(exc),
                    "updated_at": utc_now(),
                    "attempts": previous_attempts + 1,
                }
                active_failures[document_key] = failure
                current_run_failures.append(failure)
                persist_active_failures(failure_path, active_failures)
                print(f"  ERROR: {exc}", flush=True)
                if args.fail_fast:
                    raise
        batch = write_batch_summary(args.output_root.resolve())
        persist_active_failures(failure_path, active_failures)
        print(
            f"Summary complete: {batch['report_count']} existing outputs, "
            f"statuses={batch['status_counts']}, "
            f"current_failures={len(current_run_failures)}, active_failures={len(active_failures)}",
            flush=True,
        )
        return 1 if current_run_failures else 0
    finally:
        if process is not None:
            stop_server(process, handles)


if __name__ == "__main__":
    raise SystemExit(main())
