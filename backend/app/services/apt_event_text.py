"""Helpers for repairing legacy APT event text encoding."""

from __future__ import annotations

import csv
import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

logger = logging.getLogger(__name__)

_CJK_RE = re.compile(r"[\u3400-\u9fff\uf900-\ufaff]")
_HIGH_LATIN_RE = re.compile(r"[\u00a0-\u00ff]")
_MOJIBAKE_MARKER_RE = re.compile(r"[\ufffd]|[ÃÂâ][\u0080-\uffff]|[\u0590-\u05ff]")


def _seed_csv_candidates() -> list[Path]:
    candidates: list[Path] = []
    explicit_path = os.getenv("APTHUNTER_APT_EVENTS_CSV")
    if explicit_path:
        candidates.append(Path(explicit_path))

    backend_root = Path(__file__).resolve().parents[2]
    candidates.append(backend_root / "db" / "init" / "apt_events.csv")
    return candidates


def _looks_mojibake(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False

    if _MOJIBAKE_MARKER_RE.search(value):
        return True

    cjk_count = len(_CJK_RE.findall(value))
    high_latin_count = len(_HIGH_LATIN_RE.findall(value))
    return high_latin_count >= 3 and high_latin_count > cjk_count


@lru_cache(maxsize=1)
def _load_seed_events() -> dict[int, dict[str, str]]:
    for path in _seed_csv_candidates():
        if not path.exists():
            continue

        try:
            with path.open("r", encoding="utf-8-sig", newline="") as file:
                rows = csv.DictReader(file)
                seed_events: dict[int, dict[str, str]] = {}
                for row in rows:
                    try:
                        event_id = int((row.get("id") or "").strip())
                    except ValueError:
                        continue

                    seed_events[event_id] = {
                        "title": (row.get("title") or "").strip(),
                        "description": (row.get("description") or "").strip(),
                        "threatType": (row.get("threat_type") or "").strip(),
                        "releasingProduct": (row.get("releasing_product") or "").strip(),
                    }
                return seed_events
        except Exception as exc:
            logger.warning("Failed to load APT event seed data from %s: %s", path, exc)

    logger.warning("APT event seed data file was not found")
    return {}


def normalize_apt_event_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Repair known seed event text only when the stored value is corrupted."""
    normalized = dict(record)
    raw_id = normalized.get("id")

    try:
        event_id = int(str(raw_id).removeprefix("event-"))
    except (TypeError, ValueError):
        return normalized

    seed_event = _load_seed_events().get(event_id)
    if not seed_event:
        return normalized

    for field in ("title", "description", "threatType", "releasingProduct"):
        if _looks_mojibake(normalized.get(field)) and seed_event.get(field):
            normalized[field] = seed_event[field]

    return normalized
