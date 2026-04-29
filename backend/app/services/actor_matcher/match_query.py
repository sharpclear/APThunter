from typing import List, Optional

from app.entities import AlertDomainMatch

ALLOWED_MATCH_STATUS = {
    "pending",
    "confirmed",
    "false_positive",
    "ignored",
    "monitoring",
}


def get_matches_by_alert_id(
    db, alert_id: int, skip: int = 0, limit: int = 100
) -> List[AlertDomainMatch]:
    return (
        db.query(AlertDomainMatch)
        .filter(AlertDomainMatch.alert_id == alert_id)
        .order_by(
            AlertDomainMatch.actor_score.is_(None),
            AlertDomainMatch.actor_score.desc(),
            AlertDomainMatch.created_at.desc(),
        )
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_match_detail(db, match_id: int) -> Optional[AlertDomainMatch]:
    return (
        db.query(AlertDomainMatch)
        .filter(AlertDomainMatch.id == match_id)
        .first()
    )


def search_matches(
    db,
    domain_name: Optional[str] = None,
    matched_organization_name: Optional[str] = None,
    actor_confidence: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
) -> List[AlertDomainMatch]:
    query = db.query(AlertDomainMatch)

    if domain_name:
        query = query.filter(AlertDomainMatch.domain_name.like(f"%{domain_name.strip()}%"))
    if matched_organization_name:
        query = query.filter(
            AlertDomainMatch.matched_organization_name.like(
                f"%{matched_organization_name.strip()}%"
            )
        )
    if actor_confidence:
        query = query.filter(AlertDomainMatch.actor_confidence == actor_confidence.strip())
    if status:
        query = query.filter(AlertDomainMatch.status == status.strip())

    return (
        query.order_by(
            AlertDomainMatch.actor_score.is_(None),
            AlertDomainMatch.actor_score.desc(),
            AlertDomainMatch.created_at.desc(),
        )
        .offset(skip)
        .limit(limit)
        .all()
    )


def update_match_status(db, match_id: int, status: str) -> AlertDomainMatch:
    normalized = str(status or "").strip().lower()
    if normalized not in ALLOWED_MATCH_STATUS:
        raise ValueError(
            "invalid status, allowed values: pending, confirmed, false_positive, ignored, monitoring"
        )

    row = (
        db.query(AlertDomainMatch)
        .filter(AlertDomainMatch.id == match_id)
        .first()
    )
    if not row:
        raise ValueError(f"match_id not found: {match_id}")

    row.status = normalized
    db.flush()
    return row
