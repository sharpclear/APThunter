from __future__ import annotations

import hashlib
import json
import re
import time
import unicodedata
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

import httpx
from bs4 import BeautifulSoup

from .models import ModelEnrichment, OriginalSource, ReportRecord, THREAT_TYPES
from .storage import atomic_write_text


PROMPT_VERSION = "lazarus-event-enrichment-v1"
RETRYABLE_STATUSES = {429, 502, 503, 504}
FORBIDDEN_DISPLAY_PHRASES = (
    "需要人工复核",
    "需人工审核",
    "待审核",
    "待确认",
    "置信度不足",
    "低于阈值",
    "当前采集器",
    "未调用外部",
    "具体技术细节应由人工",
)


class EnrichmentError(RuntimeError):
    """A bounded model request or deterministic response check failed."""


class LazarusEnrichmentClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        timeout: float = 900,
        max_retries: int = 2,
        cache_root: Path | None = None,
        http_client: httpx.Client | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("enrichment API URL must use HTTP or HTTPS")
        if parsed.username or parsed.password:
            raise ValueError("enrichment API URL must not contain credentials")
        if not api_key.strip():
            raise ValueError("enrichment API key is required")
        if timeout <= 0 or max_retries < 0:
            raise ValueError("invalid enrichment timeout or retry count")
        self.endpoint = (
            base_url.rstrip("/") + "/api/v1/model/lazarus/enrich"
        )
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.cache_root = cache_root.resolve() if cache_root else None
        self._sleeper = sleeper
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            follow_redirects=False,
            timeout=httpx.Timeout(timeout),
            verify=True,
            trust_env=True,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def enrich(
        self, report: ReportRecord, original: OriginalSource | None
    ) -> ModelEnrichment:
        source_content = build_source_content(report, original)
        source_sha256 = hashlib.sha256(
            source_content.encode("utf-8")
        ).hexdigest()
        cached = self._read_cache(source_sha256, source_content)
        if cached is not None:
            return ModelEnrichment(**{**asdict(cached), "cached": True})
        payload = {
            "source_event_id": report.source_record_id,
            "source_url": report.lazarus_day_url,
            "report_title": report.title,
            "publisher": report.publisher,
            "source_sha256": source_sha256,
            "source_content": source_content,
        }
        value = self._request(payload)
        result = validate_enrichment_response(
            value,
            source_event_id=report.source_record_id,
            source_sha256=source_sha256,
            source_content=source_content,
        )
        self._write_cache(result)
        return result

    def _request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self._client.post(
                    self.endpoint,
                    headers={"X-API-Key": self.api_key},
                    json=dict(payload),
                )
            except httpx.RequestError as exc:
                last_error = exc
                if attempt < self.max_retries:
                    self._sleeper(min(8.0, 2**attempt))
                    continue
                break
            error_code = ""
            if response.status_code >= 400:
                try:
                    error_value = response.json()
                    error_code = str(
                        (error_value.get("detail") or {}).get("code") or ""
                    )
                except (TypeError, ValueError):
                    error_code = ""
            if error_code == "invalid_model_output":
                raise EnrichmentError(
                    "enrichment API rejected ungrounded model output"
                )
            if response.status_code in RETRYABLE_STATUSES and attempt < self.max_retries:
                self._sleeper(min(8.0, 2**attempt))
                continue
            if response.status_code != 200:
                raise EnrichmentError(
                    f"enrichment API returned HTTP {response.status_code}"
                )
            try:
                value = response.json()
            except ValueError as exc:
                raise EnrichmentError("enrichment API returned invalid JSON") from exc
            if not isinstance(value, Mapping):
                raise EnrichmentError("enrichment API response is not an object")
            return value
        error_name = type(last_error).__name__ if last_error else "request_failure"
        raise EnrichmentError(f"enrichment request failed: {error_name}")

    def _cache_path(self, source_sha256: str) -> Path | None:
        if self.cache_root is None:
            return None
        return self.cache_root / f"{source_sha256}.json"

    def _read_cache(
        self, source_sha256: str, source_content: str
    ) -> ModelEnrichment | None:
        path = self._cache_path(source_sha256)
        if path is None or not path.is_file():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return validate_enrichment_response(
                value,
                source_event_id=None,
                source_sha256=source_sha256,
                source_content=source_content,
            )
        except (OSError, UnicodeError, ValueError, EnrichmentError):
            return None

    def _write_cache(self, result: ModelEnrichment) -> None:
        path = self._cache_path(result.source_sha256)
        if path is None:
            return
        value = asdict(result)
        value["cached"] = False
        atomic_write_text(
            path,
            json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n",
        )


def build_source_content(
    report: ReportRecord, original: OriginalSource | None
) -> str:
    sections = [
        "[LAZARUS.DAY METADATA]",
        f"Title: {report.title}",
        f"Publisher: {report.publisher}",
        f"Summary: {report.summary}",
        f"Tags: {', '.join(report.tags)}",
        f"Related Actors: {', '.join(report.related_actors)}",
        "[LAZARUS.DAY PAGE]",
        _visible_text(report.raw_html, 18000),
    ]
    if original is not None and original.error is None:
        sections.extend(
            [
                "[ORIGINAL SOURCE METADATA]",
                f"Title: {original.title}",
                f"Summary: {original.summary}",
                "[ORIGINAL SOURCE PAGE]",
                _visible_text(original.raw_html or "", 28000),
            ]
        )
    value = "\n".join(section for section in sections if section).strip()
    return value[:50000]


def _visible_text(html: str, limit: int) -> str:
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    for node in soup(["script", "style", "noscript", "svg"]):
        node.decompose()
    return " ".join(soup.get_text(" ", strip=True).split())[:limit]


def _normalize(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"\s+", " ", normalized).strip()


def _grounded(quote: str, source_content: str) -> bool:
    normalized = _normalize(quote)
    return len(normalized) >= 4 and normalized in _normalize(source_content)


def _display_text(value: Any, field: str, maximum: int) -> str:
    text = " ".join(str(value or "").split())
    if not text or len(text) > maximum:
        raise EnrichmentError(f"{field} is empty or too long")
    if not re.search(r"[\u4e00-\u9fff]", text):
        raise EnrichmentError(f"{field} is not Chinese")
    if any(phrase in text for phrase in FORBIDDEN_DISPLAY_PHRASES):
        raise EnrichmentError(f"{field} contains an internal workflow phrase")
    return text


def validate_enrichment_response(
    value: Mapping[str, Any],
    *,
    source_event_id: str | None,
    source_sha256: str,
    source_content: str,
) -> ModelEnrichment:
    if source_event_id is not None and value.get("source_event_id") != source_event_id:
        raise EnrichmentError("source event identity mismatch")
    if value.get("source_sha256") != source_sha256:
        raise EnrichmentError("source content identity mismatch")
    if value.get("prompt_version") != PROMPT_VERSION:
        raise EnrichmentError("unsupported enrichment prompt version")
    title = _display_text(value.get("title_zh"), "title_zh", 500)
    description = _display_text(value.get("description_zh"), "description_zh", 2000)
    if description[-1] not in "。！？.!?":
        description += "。"
    threat_type = str(value.get("threat_type") or "")
    if threat_type not in THREAT_TYPES:
        raise EnrichmentError("threat_type is outside the controlled vocabulary")
    threat_quote = str(value.get("threat_type_evidence_quote") or "").strip()
    if not _grounded(threat_quote, source_content):
        raise EnrichmentError("threat evidence is not grounded")

    actors: list[dict[str, str]] = []
    actor_values = value.get("actor_mentions") or []
    if not isinstance(actor_values, list) or len(actor_values) > 10:
        raise EnrichmentError("actor_mentions is invalid")
    for item in actor_values:
        if not isinstance(item, Mapping):
            raise EnrichmentError("actor_mentions contains an invalid item")
        name = " ".join(str(item.get("name") or "").split())
        quote = str(item.get("evidence_quote") or "").strip()
        if (
            not name
            or len(name) > 160
            or not _grounded(quote, source_content)
            or _normalize(name) not in _normalize(quote)
        ):
            raise EnrichmentError("actor evidence is invalid or ungrounded")
        actors.append({"name": name, "evidence_quote": quote})

    facts: list[dict[str, str]] = []
    fact_values = value.get("factual_points") or []
    if not isinstance(fact_values, list) or not 1 <= len(fact_values) <= 8:
        raise EnrichmentError("factual_points is invalid")
    for item in fact_values:
        if not isinstance(item, Mapping):
            raise EnrichmentError("factual_points contains an invalid item")
        text_zh = _display_text(item.get("text_zh"), "factual_points", 500)
        quote = str(item.get("evidence_quote") or "").strip()
        if not _grounded(quote, source_content):
            raise EnrichmentError("factual point is not grounded")
        facts.append({"text_zh": text_zh, "evidence_quote": quote})

    confidence = value.get("confidence")
    if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise EnrichmentError("confidence is invalid")
    return ModelEnrichment(
        source_sha256=source_sha256,
        prompt_version=PROMPT_VERSION,
        title_zh=title,
        description_zh=description,
        threat_type=threat_type,
        threat_type_evidence_quote=threat_quote,
        actor_mentions=tuple(actors),
        factual_points=tuple(facts),
        confidence=round(float(confidence), 3),
        cached=bool(value.get("cached", False)),
    )
