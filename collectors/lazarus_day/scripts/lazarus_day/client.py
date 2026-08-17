from __future__ import annotations

import hashlib
import logging
import random
import time
import urllib.robotparser
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Callable
from urllib.parse import urlsplit

import httpx

from .models import FetchError, FetchResult, RobotsDeniedError


LOGGER = logging.getLogger(__name__)

RETRYABLE_STATUSES = {429, 502, 503, 504}
SAFE_RESPONSE_HEADERS = {
    "content-type",
    "etag",
    "last-modified",
    "retry-after",
}


class LazarusHttpClient:
    """Rate-limited HTTP client with robots enforcement and bounded retries."""

    def __init__(
        self,
        *,
        user_agent: str,
        request_delay: float = 1.0,
        timeout: float = 20.0,
        max_retries: int = 3,
        http_client: httpx.Client | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        if request_delay < 0:
            raise ValueError("request_delay must be non-negative")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        self.user_agent = user_agent
        self.request_delay = request_delay
        self.timeout = timeout
        self.max_retries = max_retries
        self._sleeper = sleeper
        self._jitter = jitter
        self._last_request_at: float | None = None
        self._robots: dict[str, urllib.robotparser.RobotFileParser | bool] = {}
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            headers={"User-Agent": user_agent, "Accept": "*/*"},
            follow_redirects=True,
            timeout=httpx.Timeout(timeout),
            verify=True,
            trust_env=True,
        )

    def __enter__(self) -> "LazarusHttpClient":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def ensure_allowed(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise FetchError(f"不支持的 URL：{url}")
        origin = f"{parts.scheme.lower()}://{parts.netloc.lower()}"
        policy = self._robots.get(origin)
        if policy is None:
            policy = self._load_robots(origin)
            self._robots[origin] = policy
        if policy is not True and not policy.can_fetch(self.user_agent, url):
            raise RobotsDeniedError(f"robots.txt 禁止访问：{url}")

    def get(self, url: str, *, enforce_robots: bool = True) -> FetchResult:
        if enforce_robots:
            self.ensure_allowed(url)
        response = self._request(url)
        now = datetime.now(timezone.utc).isoformat()
        content_type = response.headers.get("content-type", "")
        body = self._decode_body(response)
        safe_headers = {
            key.lower(): value
            for key, value in response.headers.items()
            if key.lower() in SAFE_RESPONSE_HEADERS
        }
        return FetchResult(
            requested_url=url,
            final_url=str(response.url),
            status_code=response.status_code,
            body=body,
            content_sha256=hashlib.sha256(response.content).hexdigest(),
            fetched_at=now,
            content_type=content_type,
            headers=safe_headers,
        )

    def _load_robots(
        self, origin: str
    ) -> urllib.robotparser.RobotFileParser | bool:
        robots_url = f"{origin}/robots.txt"
        LOGGER.debug("读取 robots.txt：%s", robots_url)
        response = self._request(robots_url, acceptable_statuses={404, 410})
        if response.status_code in {404, 410}:
            return True
        if response.status_code != 200:
            raise FetchError(
                f"无法可靠检查 robots.txt：{robots_url} "
                f"(HTTP {response.status_code})"
            )
        parser = urllib.robotparser.RobotFileParser()
        parser.set_url(robots_url)
        parser.parse(response.text.splitlines())
        return parser

    def _request(
        self,
        url: str,
        *,
        acceptable_statuses: set[int] | None = None,
    ) -> httpx.Response:
        acceptable_statuses = acceptable_statuses or set()
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._wait_for_rate_limit()
            try:
                response = self._client.get(url)
                self._last_request_at = time.monotonic()
            except httpx.RequestError as exc:
                self._last_request_at = time.monotonic()
                last_error = exc
                if attempt >= self.max_retries:
                    break
                delay = self._backoff_delay(attempt, None)
                LOGGER.warning(
                    "请求失败，将在 %.2f 秒后重试（%s）：%s",
                    delay,
                    type(exc).__name__,
                    url,
                )
                self._sleeper(delay)
                continue

            if (
                response.status_code in RETRYABLE_STATUSES
                and attempt < self.max_retries
            ):
                delay = self._backoff_delay(
                    attempt, response.headers.get("retry-after")
                )
                LOGGER.warning(
                    "HTTP %s，将在 %.2f 秒后重试：%s",
                    response.status_code,
                    delay,
                    url,
                )
                self._sleeper(delay)
                continue
            if (
                200 <= response.status_code < 400
                or response.status_code in acceptable_statuses
            ):
                return response
            raise FetchError(
                f"请求失败：{url} (HTTP {response.status_code}, "
                f"最终 URL {response.url})"
            )
        detail = f"{type(last_error).__name__}: {last_error}" if last_error else ""
        raise FetchError(f"请求重试耗尽：{url} {detail}".rstrip())

    def _wait_for_rate_limit(self) -> None:
        if self._last_request_at is None or self.request_delay <= 0:
            return
        elapsed = time.monotonic() - self._last_request_at
        remaining = self.request_delay - elapsed
        if remaining > 0:
            self._sleeper(remaining)

    def _backoff_delay(
        self, attempt: int, retry_after: str | None
    ) -> float:
        parsed = self._parse_retry_after(retry_after)
        if parsed is not None:
            return max(0.0, parsed)
        return min(60.0, (2**attempt) + self._jitter())

    @staticmethod
    def _parse_retry_after(value: str | None) -> float | None:
        if not value:
            return None
        value = value.strip()
        try:
            return float(value)
        except ValueError:
            pass
        try:
            retry_at = parsedate_to_datetime(value)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            return max(
                0.0,
                (retry_at - datetime.now(timezone.utc)).total_seconds(),
            )
        except (TypeError, ValueError, OverflowError):
            return None

    @staticmethod
    def _decode_body(response: httpx.Response) -> str:
        content_type = response.headers.get("content-type", "").lower()
        if any(
            marker in content_type
            for marker in ("text/", "xml", "json", "html", "rss")
        ):
            return response.text
        return ""
