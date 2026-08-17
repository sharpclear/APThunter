from __future__ import annotations

from datetime import date

import pytest

from app.services.event_ingestion.lazarus_adapter import (
    build_lazarus_candidates,
    canonicalize_url,
    validate_lazarus_variant,
)
from app.services.event_ingestion.lazarus_client import (
    LazarusClientError,
    LazarusDayClient,
)
from app.services.event_ingestion.lazarus_sync import LazarusEventSyncService


def _accepted_event() -> dict:
    return {
        "source": "lazarus.day",
        "source_event_id": "report-42",
        "version": 3,
        "quality_status": "accepted",
        "review_required": False,
        "title": "Lazarus activity",
        "structured_event": {
            "variants": [
                {
                    "event_key": "a" * 64,
                    "event_date": "2026-08-01",
                    "date_precision": "publication_date",
                    "title": "Lazarus 针对软件供应链发起攻击",
                    "description": "安全厂商披露了 Lazarus 的软件供应链攻击活动。",
                    "threat_type": "供应链攻击",
                    "organization_id": 7,
                    "organization_name": "Lazarus Group",
                    "releasing_product": "Example Security Lab",
                    "link": "https://example.com/report/42?utm_source=test",
                    "confidence": 0.91,
                    "review_status": "accepted",
                    "review_reasons": [],
                    "evidence": [
                        {
                            "url": "https://example.com/report/42",
                            "source_level": "B",
                        }
                    ],
                }
            ]
        },
    }


def test_canonicalize_url_removes_tracking_and_fragment() -> None:
    value = canonicalize_url("HTTPS://Example.COM/path/?utm_source=x&id=7#section")
    assert value == "https://example.com/path?id=7"


def test_build_and_validate_accepted_variant() -> None:
    candidate = build_lazarus_candidates(_accepted_event())[0]

    errors, clean = validate_lazarus_variant(
        candidate,
        {"Lazarus Group", "Hidden Cobra"},
        today=date(2026, 8, 14),
    )

    assert errors == []
    assert candidate.source_version == 3
    assert candidate.source_identity_hash != candidate.payload_sha256
    assert clean["link"] == "https://example.com/report/42"
    assert clean["event_type"] == "major"
    assert clean["severity"] == 5


def test_review_required_event_cannot_be_auto_imported() -> None:
    event = _accepted_event()
    event["quality_status"] = "accepted_with_review"
    event["review_required"] = True
    variant = event["structured_event"]["variants"][0]
    variant["organization_name"] = "Unknown Actor"
    variant["evidence"] = [{"url": "https://example.com", "source_level": "D"}]

    candidate = build_lazarus_candidates(event)[0]
    errors, _ = validate_lazarus_variant(
        candidate,
        {"Lazarus Group"},
        today=date(2026, 8, 14),
    )

    assert "来源质量状态不是可自动导入的 accepted" in errors
    assert "组织 ID 与名称不一致" in errors
    assert "证据数量或来源等级不足" in errors


class _Response:
    def __init__(self, payload: object, status_code: int = 200) -> None:
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError("HTTP error")

    def json(self) -> object:
        return self.payload


class _Session:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.calls: list[dict] = []

    def request(self, method: str, url: str, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.response


def test_client_passes_opaque_cursor_and_api_key() -> None:
    session = _Session(
        _Response({"items": [], "next_cursor": "opaque.next", "has_more": False})
    )
    client = LazarusDayClient(
        "http://collector:8788/",
        "secret",
        session=session,  # type: ignore[arg-type]
    )

    payload = client.list_events(cursor="opaque.current", limit=100)

    assert payload["next_cursor"] == "opaque.next"
    assert session.calls[0]["params"] == {
        "limit": 100,
        "cursor": "opaque.current",
    }
    assert session.calls[0]["headers"]["X-API-Key"] == "secret"


def test_client_rejects_invalid_event_feed_contract() -> None:
    client = LazarusDayClient(
        "http://collector:8788",
        "secret",
        session=_Session(_Response({"items": {}})),  # type: ignore[arg-type]
    )

    with pytest.raises(LazarusClientError):
        client.list_events(cursor=None, limit=10)


class _MappingResult:
    def __init__(self, row: dict | None) -> None:
        self.row = row

    def mappings(self):
        return self

    def first(self):
        return self.row


class _CandidateConnection:
    def __init__(self, existing_candidate: dict | None) -> None:
        self.existing_candidate = existing_candidate

    def execute(self, *_args, **_kwargs):
        return _MappingResult(self.existing_candidate)


def test_managed_event_can_resume_after_a_review_version(monkeypatch) -> None:
    candidate = build_lazarus_candidates(_accepted_event())[0]
    service = LazarusEventSyncService(object(), object())  # type: ignore[arg-type]
    connection = _CandidateConnection(
        {
            "source_version": 2,
            "payload_sha256": "older-payload",
            "decision": "needs_review",
            "apt_event_id": 9,
            "event_managed": 1,
        }
    )
    stored: dict = {}
    updated: dict = {}
    monkeypatch.setattr(
        service,
        "_load_organization",
        lambda *_: {"id": 7, "name": "Lazarus Group", "alias": "[]", "region": "东亚"},
    )
    monkeypatch.setattr(
        service,
        "_find_duplicate",
        lambda *_: {
            "id": 9,
            "organization_id": 7,
            "event_date": date(2026, 8, 1),
            "region": "东亚",
        },
    )
    monkeypatch.setattr(
        service,
        "_update_event",
        lambda _connection, event_id, clean: updated.update(
            {"event_id": event_id, "clean": clean}
        ),
    )
    monkeypatch.setattr(
        service,
        "_store_candidate",
        lambda *_args, **kwargs: stored.update(kwargs),
    )

    result = service._process_candidate(connection, candidate)  # type: ignore[arg-type]

    assert result["counter"] == "events_updated"
    assert updated["event_id"] == 9
    assert stored["decision"] == "auto_imported"
    assert stored["event_managed"] is True


def test_legacy_duplicate_is_linked_but_not_managed(monkeypatch) -> None:
    candidate = build_lazarus_candidates(_accepted_event())[0]
    service = LazarusEventSyncService(object(), object())  # type: ignore[arg-type]
    connection = _CandidateConnection(None)
    stored: dict = {}
    monkeypatch.setattr(service, "_load_organization", lambda *_: None)
    monkeypatch.setattr(
        service,
        "_find_duplicate",
        lambda *_: {
            "id": 21,
            "organization_id": 7,
            "event_date": date(2026, 8, 1),
            "region": "东亚",
        },
    )
    monkeypatch.setattr(
        service,
        "_store_candidate",
        lambda *_args, **kwargs: stored.update(kwargs),
    )

    result = service._process_candidate(connection, candidate)  # type: ignore[arg-type]

    assert result["counter"] == "duplicates_linked"
    assert stored["apt_event_id"] == 21
    assert stored["event_managed"] is False
