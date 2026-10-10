from datetime import datetime, timezone

from app.tasks.lazarus_event_tasks import _collection_idempotency_key


def test_collection_idempotency_key_uses_six_hour_shanghai_slot() -> None:
    assert (
        _collection_idempotency_key(
            datetime(2026, 9, 16, 2, 59, tzinfo=timezone.utc)
        )
        == "apthunter-lazarus-20260916-06"
    )
    assert (
        _collection_idempotency_key(
            datetime(2026, 9, 16, 4, 1, tzinfo=timezone.utc)
        )
        == "apthunter-lazarus-20260916-12"
    )
