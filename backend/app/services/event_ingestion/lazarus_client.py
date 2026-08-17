from __future__ import annotations

from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class LazarusClientError(RuntimeError):
    """Lazarus.day API 请求或契约错误。"""


class LazarusDayClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout_seconds: float = 30.0,
        session: requests.Session | None = None,
        source_label: str = "Lazarus.day",
    ) -> None:
        self.base_url = base_url.strip().rstrip("/")
        self.api_key = api_key.strip()
        self.timeout_seconds = float(timeout_seconds)
        self.source_label = source_label.strip() or "事件采集器"
        if not self.base_url:
            raise ValueError(f"{self.source_label} API URL 不能为空")
        if not self.api_key:
            raise ValueError(f"{self.source_label} API Key 未配置")

        self.session = session or requests.Session()
        if session is None:
            retry = Retry(
                total=2,
                connect=2,
                read=2,
                status=2,
                backoff_factor=0.5,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset({"GET", "POST"}),
                respect_retry_after_header=True,
            )
            self.session.mount("http://", HTTPAdapter(max_retries=retry))
            self.session.mount("https://", HTTPAdapter(max_retries=retry))

    @property
    def _headers(self) -> dict[str, str]:
        return {"X-API-Key": self.api_key, "Accept": "application/json"}

    def _json(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        headers = dict(self._headers)
        headers.update(kwargs.pop("headers", {}) or {})
        try:
            response = self.session.request(
                method,
                f"{self.base_url}{path}",
                headers=headers,
                timeout=self.timeout_seconds,
                **kwargs,
            )
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise LazarusClientError(
                f"{self.source_label} API 请求失败: {method} {path}"
            ) from exc
        if not isinstance(payload, dict):
            raise LazarusClientError(f"{self.source_label} API 返回的不是 JSON 对象")
        return payload

    def ready(self) -> dict[str, Any]:
        return self._json("GET", "/readyz")

    def create_incremental_run(self, idempotency_key: str) -> dict[str, Any]:
        if not idempotency_key.strip():
            raise ValueError("幂等键不能为空")
        return self._json(
            "POST",
            "/api/v1/runs",
            headers={"Idempotency-Key": idempotency_key.strip()},
            json={"mode": "incremental"},
        )

    def get_run(self, run_id: str) -> dict[str, Any]:
        return self._json("GET", f"/api/v1/runs/{run_id}")

    def list_events(
        self,
        *,
        cursor: str | None,
        limit: int,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": int(limit)}
        if cursor:
            params["cursor"] = cursor
        payload = self._json("GET", "/api/v1/events", params=params)
        items = payload.get("items")
        next_cursor = payload.get("next_cursor")
        has_more = payload.get("has_more")
        if (
            not isinstance(items, list)
            or not all(isinstance(item, dict) for item in items)
            or not isinstance(next_cursor, str)
            or not isinstance(has_more, bool)
        ):
            raise LazarusClientError(
                f"{self.source_label} 变更流的 items、next_cursor 或 has_more 无效"
            )
        return payload
