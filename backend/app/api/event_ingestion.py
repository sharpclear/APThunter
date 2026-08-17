import json
import logging
import os
from datetime import date, datetime
from decimal import Decimal
from typing import Any

import jwt
from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import text

from app.db.session import engine
from app.tasks.lazarus_event_tasks import (
    sync_lazarus_events_job,
    trigger_lazarus_collection_job,
)
from app.tasks.qianxin_event_tasks import (
    sync_qianxin_events_job,
    trigger_qianxin_collection_job,
)

logger = logging.getLogger("uvicorn.error")
router = APIRouter(prefix="/api/event-ingestion", tags=["event-ingestion"])

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
DECISIONS = {"auto_imported", "duplicate", "needs_review", "rejected"}


def _require_user(request: Request) -> int:
    user_id_header = request.headers.get("X-User-Id")
    if user_id_header:
        try:
            return int(user_id_header)
        except ValueError:
            pass
    token = request.headers.get("Authorization")
    if token and token.lower().startswith("bearer "):
        token = token.split(" ", 1)[1]
    if not token:
        token = request.query_params.get("token") or request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未登录")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload["sub"])
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="登录状态无效",
        ) from exc


def _plain(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return str(value)


def _payload(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None
    return None


def _source_status(source: str) -> dict[str, Any]:
    with engine.connect() as connection:
        sync_state = (
            connection.execute(
                text(
                    """
                SELECT source, cursor_value, last_attempt_at, last_success_at,
                       last_error, updated_at
                FROM apt_event_sync_state
                WHERE source = :source
                """
                ),
                {"source": source},
            )
            .mappings()
            .first()
        )
        latest_run = (
            connection.execute(
                text(
                    """
                SELECT * FROM apt_event_import_runs
                WHERE source = :source
                ORDER BY id DESC LIMIT 1
                """
                ),
                {"source": source},
            )
            .mappings()
            .first()
        )
        decisions = (
            connection.execute(
                text(
                    """
                SELECT decision, COUNT(*) AS count
                FROM apt_event_candidates
                WHERE source = :source
                GROUP BY decision
                """
                ),
                {"source": source},
            )
            .mappings()
            .all()
        )
    return {
        "source": source,
        "syncState": _plain(dict(sync_state)) if sync_state else None,
        "latestRun": _plain(dict(latest_run)) if latest_run else None,
        "candidateCounts": {
            str(row["decision"]): int(row["count"]) for row in decisions
        },
    }


def _source_candidates(
    source: str,
    *,
    page: int,
    page_size: int,
    decision: str | None,
) -> dict[str, Any]:
    if decision and decision not in DECISIONS:
        raise HTTPException(status_code=422, detail="无效的候选状态")
    where = "source = :source"
    params: dict[str, Any] = {
        "source": source,
        "limit": page_size,
        "offset": (page - 1) * page_size,
    }
    if decision:
        where += " AND decision = :decision"
        params["decision"] = decision
    with engine.connect() as connection:
        total = int(
            connection.execute(
                text(f"SELECT COUNT(*) FROM apt_event_candidates WHERE {where}"),
                params,
            ).scalar()
            or 0
        )
        rows = (
            connection.execute(
                text(
                    f"""
                SELECT id, source_record_id, variant_key, source_version,
                       quality_status, review_required, decision,
                       decision_reason, payload, apt_event_id, event_managed,
                       first_seen_at, updated_at
                FROM apt_event_candidates
                WHERE {where}
                ORDER BY updated_at DESC, id DESC
                LIMIT :limit OFFSET :offset
                """
                ),
                params,
            )
            .mappings()
            .all()
        )
    items = []
    for row in rows:
        item = _plain(dict(row))
        item["payload"] = _payload(row.get("payload"))
        items.append(item)
    return {"items": items, "total": total, "page": page, "pageSize": page_size}


@router.get("/lazarus/status")
def get_lazarus_status(request: Request):
    _require_user(request)
    return _source_status("lazarus.day")


@router.get("/lazarus/candidates")
def list_lazarus_candidates(
    request: Request,
    page: int = Query(1, ge=1),
    pageSize: int = Query(20, ge=1, le=100),
    decision: str | None = Query(None),
):
    _require_user(request)
    return _source_candidates(
        "lazarus.day",
        page=page,
        page_size=pageSize,
        decision=decision,
    )


@router.post("/lazarus/trigger")
def trigger_lazarus_collection(request: Request):
    _require_user(request)
    task = trigger_lazarus_collection_job.delay()
    return {"taskId": task.id, "status": "queued"}


@router.post("/lazarus/sync")
def sync_lazarus_events(request: Request):
    _require_user(request)
    task = sync_lazarus_events_job.delay("manual")
    return {"taskId": task.id, "status": "queued"}


@router.get("/qianxin/status")
def get_qianxin_status(request: Request):
    _require_user(request)
    return _source_status("qianxin")


@router.get("/qianxin/candidates")
def list_qianxin_candidates(
    request: Request,
    page: int = Query(1, ge=1),
    pageSize: int = Query(20, ge=1, le=100),
    decision: str | None = Query(None),
):
    _require_user(request)
    return _source_candidates(
        "qianxin",
        page=page,
        page_size=pageSize,
        decision=decision,
    )


@router.post("/qianxin/trigger")
def trigger_qianxin_collection(request: Request):
    _require_user(request)
    task = trigger_qianxin_collection_job.delay()
    return {"taskId": task.id, "status": "queued"}


@router.post("/qianxin/sync")
def sync_qianxin_events(request: Request):
    _require_user(request)
    task = sync_qianxin_events_job.delay("manual")
    return {"taskId": task.id, "status": "queued"}
