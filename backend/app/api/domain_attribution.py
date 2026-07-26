from __future__ import annotations

from typing import List

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from starlette.concurrency import run_in_threadpool

from app.core import config
from app.models.apt_attribution.common import normalize_domain
from app.services.domain_apt_attribution import (
    AttributionConfigurationError,
    RealtimeAttributionDisabledError,
    attribute_domains,
    enabled_live_providers,
)


router = APIRouter(prefix="/api/domain-attribution", tags=["域名APT归因"])


class DomainAttributionRequest(BaseModel):
    domains: List[str] = Field(..., min_length=1)
    realtime_enrichment: bool = False
    include_infrastructure: bool = True

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, values: List[str]) -> List[str]:
        normalized: List[str] = []
        seen = set()
        invalid: List[str] = []
        for value in values:
            domain = normalize_domain(value)
            if not domain:
                invalid.append(str(value))
                continue
            if domain not in seen:
                seen.add(domain)
                normalized.append(domain)
        if invalid:
            preview = "、".join(invalid[:5])
            raise ValueError(f"包含无效域名：{preview}")
        if not normalized:
            raise ValueError("至少提供一个有效域名")
        if len(normalized) > max(1, config.APT_ATTRIBUTION_API_MAX_DOMAINS):
            raise ValueError(
                f"单次最多归因 {config.APT_ATTRIBUTION_API_MAX_DOMAINS} 个域名"
            )
        return normalized


def _require_user(request: Request) -> None:
    user_id = request.headers.get("X-User-Id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="缺少用户身份信息",
        )
    try:
        int(user_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户身份信息无效",
        ) from exc


@router.post("")
async def attribute_domain_request(
    payload: DomainAttributionRequest,
    request: Request,
):
    """对一个或多个域名执行只读历史图谱归因。"""
    _require_user(request)
    try:
        results = await run_in_threadpool(
            attribute_domains,
            payload.domains,
            realtime_enrichment=payload.realtime_enrichment,
            include_infrastructure=payload.include_infrastructure,
        )
    except AttributionConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"历史图谱不可用：{exc}",
        ) from exc
    except RealtimeAttributionDisabledError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    return {
        "ok": True,
        "count": len(results),
        "realtime_enrichment": payload.realtime_enrichment,
        "live_providers": (
            sorted(enabled_live_providers())
            if payload.realtime_enrichment
            else []
        ),
        "results": results,
    }
