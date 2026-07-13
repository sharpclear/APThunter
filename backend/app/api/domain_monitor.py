import logging
import os
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Optional

import jwt
from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import or_

from app.db.session import SessionLocal
from app.entities import DomainMonitorSnapshot, DomainMonitorSource, DomainMonitorTarget
from app.services.domain_monitor import DOMAIN_MONITOR_LEASE_MINUTES, dispatch_due_monitor_targets, mark_target_due_now

logger = logging.getLogger("uvicorn.error")

router = APIRouter(prefix="/api/domain-monitor", tags=["domain-monitor"])
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")


def _extract_user_id(request: Request) -> Optional[int]:
    user_id_header = request.headers.get("X-User-Id")
    if user_id_header:
        try:
            return int(user_id_header)
        except ValueError:
            logger.warning("Invalid X-User-Id header value: %s", user_id_header)

    token = request.headers.get("Authorization")
    if token and token.lower().startswith("bearer "):
        token = token.split(" ", 1)[1]
    if not token:
        token = request.query_params.get("token") or request.cookies.get("token")
    if not token:
        return None

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        return int(user_id) if user_id else None
    except jwt.ExpiredSignatureError:
        logger.warning("Domain monitor token expired")
        return None
    except Exception as exc:
        logger.warning("Domain monitor token decode failed: %s", exc)
        return None


def _require_user_id(request: Request) -> int:
    user_id = _extract_user_id(request)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication token",
        )
    return user_id


def _plain(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(v) for v in value]
    return str(value)


def _target_item(db, target: DomainMonitorTarget) -> dict:
    latest_snapshot = (
        db.query(DomainMonitorSnapshot)
        .filter(DomainMonitorSnapshot.target_id == target.id)
        .order_by(DomainMonitorSnapshot.collected_at.desc(), DomainMonitorSnapshot.id.desc())
        .first()
    )
    source_count = (
        db.query(DomainMonitorSource)
        .filter(DomainMonitorSource.target_id == target.id)
        .count()
    )
    return {
        "id": target.id,
        "domain": target.domain,
        "normalizedDomain": target.normalized_domain,
        "isActive": bool(target.is_active),
        "status": target.status,
        "monitorIntervalHours": target.monitor_interval_hours,
        "nextCheckAt": target.next_check_at.isoformat() if target.next_check_at else None,
        "lastCheckedAt": target.last_checked_at.isoformat() if target.last_checked_at else None,
        "consecutiveFailures": target.consecutive_failures,
        "lastError": target.last_error,
        "sourceCount": source_count,
        "createdAt": target.created_at.isoformat() if target.created_at else None,
        "updatedAt": target.updated_at.isoformat() if target.updated_at else None,
        "latestSnapshot": _plain(
            {
                "id": latest_snapshot.id,
                "status": latest_snapshot.status,
                "collectedAt": latest_snapshot.collected_at,
                "changedFields": latest_snapshot.changed_fields,
                "errorMessage": latest_snapshot.error_message,
            }
        ) if latest_snapshot else None,
    }


@router.get("/targets")
async def list_monitor_targets(
    request: Request,
    page: int = Query(1, ge=1),
    pageSize: int = Query(20, ge=1, le=100),
    activeOnly: bool = Query(False),
    domain: Optional[str] = Query(None),
):
    user_id = _require_user_id(request)
    db = SessionLocal()
    try:
        query = db.query(DomainMonitorTarget).filter(DomainMonitorTarget.user_id == user_id)
        if activeOnly:
            query = query.filter(DomainMonitorTarget.is_active == True)
        if domain:
            keyword = f"%{domain.strip().lower()}%"
            query = query.filter(
                or_(
                    DomainMonitorTarget.domain.like(keyword),
                    DomainMonitorTarget.normalized_domain.like(keyword),
                )
            )
        total = query.count()
        targets = (
            query.order_by(DomainMonitorTarget.created_at.desc(), DomainMonitorTarget.id.desc())
            .offset((page - 1) * pageSize)
            .limit(pageSize)
            .all()
        )
        return {
            "items": [_plain(_target_item(db, target)) for target in targets],
            "total": total,
        }
    finally:
        db.close()


@router.get("/targets/{target_id}/snapshots")
async def list_monitor_snapshots(
    target_id: int,
    request: Request,
    page: int = Query(1, ge=1),
    pageSize: int = Query(10, ge=1, le=100),
):
    user_id = _require_user_id(request)
    db = SessionLocal()
    try:
        target = (
            db.query(DomainMonitorTarget)
            .filter(
                DomainMonitorTarget.id == int(target_id),
                DomainMonitorTarget.user_id == user_id,
            )
            .first()
        )
        if not target:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="监控目标不存在")

        query = db.query(DomainMonitorSnapshot).filter(DomainMonitorSnapshot.target_id == target.id)
        total = query.count()
        snapshots = (
            query.order_by(DomainMonitorSnapshot.collected_at.desc(), DomainMonitorSnapshot.id.desc())
            .offset((page - 1) * pageSize)
            .limit(pageSize)
            .all()
        )
        return {
            "target": _plain(_target_item(db, target)),
            "items": [
                _plain(
                    {
                        "id": item.id,
                        "status": item.status,
                        "collectedAt": item.collected_at,
                        "whois": item.whois_snapshot,
                        "dns": item.dns_snapshot,
                        "certificate": item.certificate_snapshot,
                        "web": item.web_snapshot,
                        "changedFields": item.changed_fields,
                        "rawLookupErrors": item.raw_lookup_errors,
                        "errorMessage": item.error_message,
                        "createdAt": item.created_at,
                    }
                )
                for item in snapshots
            ],
            "total": total,
        }
    finally:
        db.close()


@router.post("/targets/{target_id}/trigger")
async def trigger_monitor_target(target_id: int, request: Request):
    user_id = _require_user_id(request)
    db = SessionLocal()
    try:
        target = mark_target_due_now(db, target_id=int(target_id), user_id=user_id)
        target.status = "checking"
        target.next_check_at = datetime.now().replace(microsecond=0) + timedelta(
            minutes=max(5, DOMAIN_MONITOR_LEASE_MINUTES)
        )
        db.commit()
        from app.services.task_dispatcher import dispatch_domain_monitor_snapshot_task

        target_id_value = int(target.id)
        try:
            dispatch_domain_monitor_snapshot_task(target_id_value)
        except Exception as exc:
            failed_target = (
                db.query(DomainMonitorTarget)
                .filter(DomainMonitorTarget.id == target_id_value)
                .first()
            )
            if failed_target:
                failed_target.status = "failed"
                failed_target.last_error = f"入队失败: {exc}"
                failed_target.next_check_at = datetime.now().replace(microsecond=0) + timedelta(hours=1)
                db.commit()
            raise
        return {"ok": True, "targetId": target_id_value}
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        logger.exception("手动触发域名监控失败 target_id=%s", target_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="触发监控失败") from exc
    finally:
        db.close()


@router.post("/trigger-due")
async def trigger_due_monitor_targets(request: Request, limit: int = Query(20, ge=1, le=100)):
    _require_user_id(request)
    try:
        return {"ok": True, "summary": dispatch_due_monitor_targets(limit=limit)}
    except Exception as exc:
        logger.exception("手动触发到期域名监控失败")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="触发到期监控失败") from exc
