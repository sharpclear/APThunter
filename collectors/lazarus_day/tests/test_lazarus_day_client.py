from __future__ import annotations

import httpx
import pytest

from scripts.lazarus_day.client import LazarusHttpClient
from scripts.lazarus_day.models import FetchError, RobotsDeniedError


USER_AGENT = "APTHunter-Research-Collector/1.0 (test)"


def test_429_retry_after_is_retried_with_finite_attempts() -> None:
    calls = 0
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "0"}, request=request)
        return httpx.Response(
            200,
            text="ok",
            headers={"Content-Type": "text/plain"},
            request=request,
        )

    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport)
    client = LazarusHttpClient(
        user_agent=USER_AGENT,
        request_delay=0,
        max_retries=2,
        http_client=http_client,
        sleeper=sleeps.append,
        jitter=lambda: 0,
    )
    result = client.get("https://example.test/report", enforce_robots=False)
    http_client.close()
    assert result.status_code == 200
    assert calls == 2
    assert sleeps == [0.0]


def test_network_error_is_not_silently_swallowed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = LazarusHttpClient(
        user_agent=USER_AGENT,
        request_delay=0,
        max_retries=1,
        http_client=http_client,
        sleeper=lambda _seconds: None,
        jitter=lambda: 0,
    )
    with pytest.raises(FetchError, match="重试耗尽"):
        client.get("https://example.test/report", enforce_robots=False)
    http_client.close()


def test_robots_denial_terminates_before_target_fetch() -> None:
    target_fetched = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal target_fetched
        if request.url.path == "/robots.txt":
            return httpx.Response(
                200,
                text="User-agent: *\nDisallow: /reports/\n",
                request=request,
            )
        target_fetched = True
        return httpx.Response(200, text="should not happen", request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = LazarusHttpClient(
        user_agent=USER_AGENT,
        request_delay=0,
        http_client=http_client,
    )
    with pytest.raises(RobotsDeniedError):
        client.get("https://example.test/reports/one")
    http_client.close()
    assert target_fetched is False
