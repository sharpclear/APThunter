"""Backfill Chinese display copy for already-imported collector events.

The script is deliberately side-effect free unless ``--apply`` is supplied.
It only updates title/description display fields and their stored candidate
payloads; it does not run collectors, create events, or invoke notifications.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from sqlalchemy import text

from app.core.config import QIANXIN_API_KEY, QIANXIN_API_URL
from app.db.session import engine


CHINESE_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")
SUPPORTED_SOURCES = ("qianxin", "lazarus.day")


def _needs_translation(title: str, description: str) -> bool:
    return not CHINESE_RE.search(title) or not CHINESE_RE.search(description)


def _chunks(items: list[dict[str, Any]], size: int) -> Iterable[list[dict[str, Any]]]:
    for offset in range(0, len(items), size):
        yield items[offset : offset + size]


def _request_translation(items: list[dict[str, Any]], retries: int) -> list[dict[str, str]]:
    if not QIANXIN_API_URL or not QIANXIN_API_KEY:
        raise RuntimeError("QIANXIN_API_URL and QIANXIN_API_KEY must be configured")
    body = json.dumps(
        {
            "items": [
                {
                    "source_event_id": str(item["event_id"]),
                    "title": item["title"],
                    "description": item["description"],
                }
                for item in items
            ]
        },
        ensure_ascii=False,
    ).encode("utf-8")
    request = urllib.request.Request(
        QIANXIN_API_URL.rstrip("/") + "/api/v1/model/events/translate",
        data=body,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "X-API-Key": QIANXIN_API_KEY,
        },
        method="POST",
    )
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=1200) as response:
                value = json.loads(response.read().decode("utf-8"))
            translated = value.get("items")
            if not isinstance(translated, list):
                raise ValueError("translation response does not contain items")
            return translated
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:1000]
            except OSError:
                detail = ""
            last_error = RuntimeError(
                f"translation API returned HTTP {exc.code}: {detail or exc.reason}"
            )
            if attempt < retries:
                time.sleep(min(10 * attempt, 30))
        except (OSError, ValueError, urllib.error.URLError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(min(10 * attempt, 30))
    raise RuntimeError(f"translation request failed: {last_error}") from last_error


def _request_with_fallback(
    items: list[dict[str, Any]], retries: int
) -> list[dict[str, str]]:
    try:
        return _request_translation(items, retries)
    except RuntimeError as exc:
        if len(items) == 1:
            item = items[0]
            raise RuntimeError(
                f"event {item['event_id']} translation failed: {exc}"
            ) from exc
        midpoint = len(items) // 2
        return [
            *_request_with_fallback(items[:midpoint], retries),
            *_request_with_fallback(items[midpoint:], retries),
        ]


def _load_pending() -> list[dict[str, Any]]:
    statement = text(
        """
        SELECT ae.id AS event_id, ae.title, ae.description,
               c.id AS candidate_id, c.source, c.payload
        FROM apt_events ae
        JOIN apt_event_candidates c
          ON c.apt_event_id = ae.id AND c.event_managed = 1
        WHERE c.source IN ('qianxin', 'lazarus.day')
        ORDER BY ae.event_date, ae.id
        """
    )
    with engine.connect() as connection:
        rows = [dict(row._mapping) for row in connection.execute(statement)]
    result: list[dict[str, Any]] = []
    for row in rows:
        row["title"] = str(row.get("title") or "").strip()
        row["description"] = str(row.get("description") or "").strip()
        if _needs_translation(row["title"], row["description"]):
            result.append(row)
    return result


def _translated_payload(payload: Any, title: str, description: str) -> tuple[str, str]:
    if isinstance(payload, str):
        value = json.loads(payload)
    elif isinstance(payload, dict):
        value = dict(payload)
    else:
        raise ValueError("candidate payload is not a JSON object")
    value["title"] = title
    value["description"] = description
    apt_event = value.get("apt_event")
    if isinstance(apt_event, dict):
        apt_event["title"] = title
        apt_event["description"] = description
    structured = value.get("structured_event")
    if isinstance(structured, dict):
        variants = structured.get("variants")
        if isinstance(variants, list):
            for variant in variants:
                if isinstance(variant, dict):
                    variant["title"] = title
                    variant["description"] = description
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _source_fingerprint(item: dict[str, Any]) -> str:
    material = f"{item['title']}\0{item['description']}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _load_checkpoint(path: Path, pending: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    pending_by_id = {str(item["event_id"]): item for item in pending}
    valid: dict[str, dict[str, str]] = {}
    for event_id, value in raw.items():
        source = pending_by_id.get(str(event_id))
        if source is None or not isinstance(value, dict):
            continue
        if value.get("source_fingerprint") != _source_fingerprint(source):
            continue
        title_zh = str(value.get("title_zh") or "").strip()
        description_zh = str(value.get("description_zh") or "").strip()
        if not _needs_translation(title_zh, description_zh):
            valid[str(event_id)] = {
                "source_fingerprint": value["source_fingerprint"],
                "title_zh": title_zh,
                "description_zh": description_zh,
            }
    return valid


def _write_checkpoint(path: Path, values: dict[str, dict[str, str]]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(values, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )
    temporary.replace(path)


def _apply(translations: list[dict[str, Any]]) -> None:
    event_update = text(
        "UPDATE apt_events SET title=:title, description=:description WHERE id=:event_id"
    )
    candidate_update = text(
        """
        UPDATE apt_event_candidates
        SET payload=:payload, payload_sha256=:payload_sha256
        WHERE id=:candidate_id AND apt_event_id=:event_id AND event_managed=1
        """
    )
    with engine.begin() as connection:
        for item in translations:
            payload, payload_sha256 = _translated_payload(
                item["payload"], item["title_zh"], item["description_zh"]
            )
            connection.execute(
                event_update,
                {
                    "event_id": item["event_id"],
                    "title": item["title_zh"],
                    "description": item["description_zh"],
                },
            )
            connection.execute(
                candidate_update,
                {
                    "candidate_id": item["candidate_id"],
                    "event_id": item["event_id"],
                    "payload": payload,
                    "payload_sha256": payload_sha256,
                },
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--batch-size", type=int, default=8, choices=range(1, 11))
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=Path("/tmp/apt-event-translation-checkpoint.json"),
    )
    args = parser.parse_args()

    pending = _load_pending()
    print(json.dumps({"pending": len(pending), "apply": args.apply}, ensure_ascii=False))
    if not args.apply or not pending:
        return 0

    checkpoint = _load_checkpoint(args.checkpoint, pending)
    completed_by_id: dict[str, dict[str, Any]] = {}
    for source in pending:
        saved = checkpoint.get(str(source["event_id"]))
        if saved is not None:
            completed_by_id[str(source["event_id"])] = {
                **source,
                "title_zh": saved["title_zh"],
                "description_zh": saved["description_zh"],
            }
    remaining = [
        item for item in pending if str(item["event_id"]) not in completed_by_id
    ]
    print(
        json.dumps(
            {"checkpointed": len(completed_by_id), "remaining_model_calls": len(remaining)},
            ensure_ascii=False,
        )
    )
    for batch_number, batch in enumerate(_chunks(remaining, args.batch_size), start=1):
        translated = _request_with_fallback(batch, args.retries)
        by_id = {str(item["source_event_id"]): item for item in translated}
        for source in batch:
            value = by_id.get(str(source["event_id"]))
            if value is None:
                raise RuntimeError(f"event {source['event_id']} was not translated")
            title_zh = str(value.get("title_zh") or "").strip()
            description_zh = str(value.get("description_zh") or "").strip()
            if _needs_translation(title_zh, description_zh):
                raise RuntimeError(f"event {source['event_id']} is still not Chinese")
            event_id = str(source["event_id"])
            completed_by_id[event_id] = {
                **source,
                "title_zh": title_zh,
                "description_zh": description_zh,
            }
            checkpoint[event_id] = {
                "source_fingerprint": _source_fingerprint(source),
                "title_zh": title_zh,
                "description_zh": description_zh,
            }
        _write_checkpoint(args.checkpoint, checkpoint)
        print(
            json.dumps(
                {"batch": batch_number, "translated": len(completed_by_id), "total": len(pending)},
                ensure_ascii=False,
            ),
            flush=True,
        )

    completed = [completed_by_id[str(item["event_id"])] for item in pending]
    _apply(completed)
    remaining = len(_load_pending())
    if remaining == 0:
        args.checkpoint.unlink(missing_ok=True)
    print(
        json.dumps(
            {"updated": len(completed), "remaining": remaining, "notifications": 0},
            ensure_ascii=False,
        )
    )
    return 0 if remaining == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
