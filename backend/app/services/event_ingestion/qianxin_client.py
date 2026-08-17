from __future__ import annotations

import requests

from app.services.event_ingestion.lazarus_client import LazarusDayClient


class QianxinClient(LazarusDayClient):
    """Qianxin report/event API client using the shared cursor contract."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout_seconds: float = 30.0,
        session: requests.Session | None = None,
    ) -> None:
        super().__init__(
            base_url,
            api_key,
            timeout_seconds=timeout_seconds,
            session=session,
            source_label="Qianxin",
        )
