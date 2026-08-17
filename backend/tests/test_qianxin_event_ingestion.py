from __future__ import annotations

import pytest

from app.services.event_ingestion.lazarus_adapter import (
    build_event_candidates,
    validate_lazarus_variant,
)
from app.services.event_ingestion.qianxin_client import QianxinClient
from app.services.event_ingestion.qianxin_sync import QianxinEventSyncService


def _event(*, source: str = "qianxin") -> dict:
    return {
        "source": source,
        "source_event_id": "a" * 64,
        "version": 2,
        "quality_status": "needs_review",
        "review_required": True,
        "title": "APT28 发起鱼叉式钓鱼攻击",
        "structured_event": {
            "variants": [
                {
                    "event_key": "b" * 64,
                    "event_date": "2026-08-12",
                    "date_precision": "publication_date",
                    "title": "APT28 发起鱼叉式钓鱼攻击",
                    "description": "攻击者通过钓鱼邮件投递恶意附件。",
                    "link": "http://192.168.21.181:8787/api/v1/reports/"
                    + "a" * 64
                    + "/pdf",
                    "event_type": "normal",
                    "threat_type": "钓鱼攻击",
                    "releasing_product": "奇安信威胁情报中心",
                    "organization_id": 40,
                    "organization_name": "APT28",
                    "severity": 4,
                    "confidence": 0.72,
                    "review_status": "needs_review",
                    "evidence": [
                        {
                            "url": "http://192.168.21.181:8787/api/v1/reports/"
                            + "a" * 64
                            + "/pdf",
                            "source_level": "B",
                            "evidence_quote": "The campaign used spearphishing.",
                            "evidence_pages": [2],
                        }
                    ],
                }
            ]
        },
    }


def test_qianxin_candidate_keeps_source_identity_separate() -> None:
    qianxin = build_event_candidates(_event(), source="qianxin")[0]
    lazarus = build_event_candidates(
        _event(source="lazarus.day"),
        source="lazarus.day",
    )[0]

    assert qianxin.source == "qianxin"
    assert qianxin.source_identity_hash != lazarus.source_identity_hash
    assert qianxin.payload["source_metadata"]["source"] == "qianxin"


def test_qianxin_source_mismatch_is_rejected() -> None:
    with pytest.raises(ValueError, match="事件来源不匹配"):
        build_event_candidates(_event(source="lazarus.day"), source="qianxin")


def test_qianxin_review_candidate_cannot_auto_import() -> None:
    candidate = build_event_candidates(_event(), source="qianxin")[0]

    errors, _ = validate_lazarus_variant(candidate, {"APT28"})

    assert "来源质量状态不是可自动导入的 accepted" in errors
    assert "variant 尚未接受" in errors
    assert "置信度低于 0.75" in errors


class _Response:
    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return {"items": [], "next_cursor": "opaque.next", "has_more": False}


class _Session:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def request(self, method: str, url: str, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return _Response()


def test_qianxin_client_uses_api_key_and_event_cursor() -> None:
    session = _Session()
    client = QianxinClient(
        "http://192.168.21.181:8787/",
        "secret",
        session=session,  # type: ignore[arg-type]
    )

    payload = client.list_events(cursor="opaque.current", limit=100)

    assert payload["next_cursor"] == "opaque.next"
    assert session.calls[0]["url"].endswith("/api/v1/events")
    assert session.calls[0]["headers"]["X-API-Key"] == "secret"
    assert session.calls[0]["params"]["cursor"] == "opaque.current"


def test_qianxin_sync_service_is_safe_by_default() -> None:
    service = QianxinEventSyncService(object(), object())  # type: ignore[arg-type]

    assert service.source == "qianxin"
    assert service.lock_name == "apthunter:qianxin-event-sync"
    assert service.auto_import is False
