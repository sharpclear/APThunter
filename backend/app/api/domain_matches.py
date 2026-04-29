import logging
from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.actor_matcher import (
    get_match_detail,
    get_matches_by_alert_id,
    search_matches,
    update_match_status,
)

router = APIRouter()
logger = logging.getLogger("uvicorn.error")


class _OrmSchema(BaseModel):
    model_config = {"from_attributes": True}


class AlertDomainMatchResponse(_OrmSchema):
    id: int
    alert_id: int
    task_id: Optional[int] = None
    domain_id: Optional[int] = None
    domain_name: str
    malicious_score: Optional[float] = None
    risk_level: Optional[str] = None
    matched_organization_id: Optional[int] = None
    matched_organization_name: Optional[str] = None
    actor_score: Optional[float] = None
    actor_confidence: Optional[str] = None
    reason_summary: Optional[str] = None
    evidence_json: Optional[Any] = None
    top_candidates_json: Optional[Any] = None
    enrichment_snapshot_json: Optional[Any] = None
    model_id: Optional[int] = None
    model_version: Optional[str] = None
    actor_profile_version: Optional[str] = None
    match_method: str
    status: str
    created_at: datetime
    updated_at: datetime


class AlertDomainMatchListResponse(BaseModel):
    items: List[AlertDomainMatchResponse]
    total: int


class AlertDomainMatchDetailResponse(BaseModel):
    item: AlertDomainMatchResponse


class AlertDomainMatchStatusUpdateResponse(BaseModel):
    ok: bool
    item: AlertDomainMatchResponse


class MatchStatusUpdateRequest(BaseModel):
    status: str


def _extract_user_id(request: Request) -> Optional[int]:
    user_id_header = request.headers.get("X-User-Id")
    if not user_id_header:
        return None
    try:
        return int(user_id_header)
    except ValueError:
        logger.warning("Invalid X-User-Id header value: %s", user_id_header)
        return None


def _require_user_id(request: Request) -> int:
    user_id = _extract_user_id(request)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-User-Id header",
        )
    return user_id


def _to_match_schema(row) -> AlertDomainMatchResponse:
    if hasattr(AlertDomainMatchResponse, "model_validate"):
        return AlertDomainMatchResponse.model_validate(row)
    return AlertDomainMatchResponse.from_orm(row)


def _ensure_alert_belongs_to_user(db: Session, alert_id: int, user_id: int) -> None:
    exists = db.execute(
        text(
            """
            SELECT 1
            FROM alerts
            WHERE id = :alert_id
              AND user_id = :user_id
            LIMIT 1
            """
        ),
        {"alert_id": alert_id, "user_id": user_id},
    ).first()
    if not exists:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")


def _ensure_match_belongs_to_user(db: Session, match_id: int, user_id: int) -> None:
    exists = db.execute(
        text(
            """
            SELECT 1
            FROM alert_domain_matches adm
            INNER JOIN alerts a ON a.id = adm.alert_id
            WHERE adm.id = :match_id
              AND a.user_id = :user_id
            LIMIT 1
            """
        ),
        {"match_id": match_id, "user_id": user_id},
    ).first()
    if not exists:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Match not found")


@router.get("/api/alerts/{alert_id}/domain-matches", response_model=AlertDomainMatchListResponse, deprecated=True)
async def get_alert_domain_matches(
    alert_id: int,
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    user_id = _require_user_id(request)
    try:
        _ensure_alert_belongs_to_user(db, alert_id, user_id)
        rows = get_matches_by_alert_id(db, alert_id=alert_id, skip=skip, limit=limit)
        return AlertDomainMatchListResponse(
            items=[_to_match_schema(row) for row in rows], total=len(rows)
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to get domain matches for alert_id=%s", alert_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch domain matches",
        )


@router.get("/api/domain-matches/{match_id}", response_model=AlertDomainMatchDetailResponse, deprecated=True)
async def get_domain_match_detail(match_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = _require_user_id(request)
    try:
        _ensure_match_belongs_to_user(db, match_id, user_id)
        row = get_match_detail(db, match_id=match_id)
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Match not found")
        return AlertDomainMatchDetailResponse(item=_to_match_schema(row))
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to get domain match detail match_id=%s", match_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch match detail",
        )


@router.get("/api/domain-matches", response_model=AlertDomainMatchListResponse, deprecated=True)
async def search_domain_matches(
    request: Request,
    domain_name: Optional[str] = Query(None),
    matched_organization_name: Optional[str] = Query(None),
    actor_confidence: Optional[str] = Query(None),
    status_value: Optional[str] = Query(None, alias="status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    user_id = _require_user_id(request)
    try:
        # 先按筛选条件查询，再在用户可见范围内过滤，避免跨用户数据暴露
        rows = search_matches(
            db,
            domain_name=domain_name,
            matched_organization_name=matched_organization_name,
            actor_confidence=actor_confidence,
            status=status_value,
            skip=skip,
            limit=limit,
        )
        if not rows:
            return AlertDomainMatchListResponse(items=[], total=0)

        allowed_alert_ids = {
            int(row["id"])
            for row in db.execute(
                text("SELECT id FROM alerts WHERE user_id = :user_id"),
                {"user_id": user_id},
            ).mappings()
        }
        filtered = [row for row in rows if int(row.alert_id) in allowed_alert_ids]
        return AlertDomainMatchListResponse(
            items=[_to_match_schema(row) for row in filtered], total=len(filtered)
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to search domain matches")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to search domain matches",
        )


@router.patch(
    "/api/domain-matches/{match_id}/status",
    response_model=AlertDomainMatchStatusUpdateResponse,
    deprecated=True,
)
async def patch_domain_match_status(
    match_id: int,
    payload: MatchStatusUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    user_id = _require_user_id(request)
    try:
        _ensure_match_belongs_to_user(db, match_id, user_id)
        row = update_match_status(db, match_id=match_id, status=payload.status)
        db.commit()
        db.refresh(row)
        return AlertDomainMatchStatusUpdateResponse(
            ok=True,
            item=_to_match_schema(row),
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        logger.exception("Failed to update domain match status match_id=%s", match_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update match status",
        )
