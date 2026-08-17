from __future__ import annotations

from sqlalchemy.engine import Engine

from app.services.event_ingestion.lazarus_sync import LazarusEventSyncService
from app.services.event_ingestion.qianxin_client import QianxinClient


SOURCE = "qianxin"


class QianxinEventSyncService(LazarusEventSyncService):
    def __init__(
        self,
        engine: Engine,
        client: QianxinClient,
        *,
        page_limit: int = 100,
        max_pages: int = 20,
        auto_import: bool = False,
    ) -> None:
        super().__init__(
            engine,
            client,
            page_limit=page_limit,
            max_pages=max_pages,
            auto_import=auto_import,
            source=SOURCE,
            source_label="Qianxin",
            lock_name="apthunter:qianxin-event-sync",
        )
