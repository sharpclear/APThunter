from datetime import datetime

from sqlalchemy import BigInteger, Column, DateTime, Integer, JSON, Numeric, String, Text, text

from app.db.base import Base


class AlertDomainMatch(Base):
    __tablename__ = "alert_domain_matches"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    alert_id = Column(BigInteger, nullable=False, index=True)
    task_id = Column(BigInteger, nullable=True, index=True)
    domain_id = Column(Integer, nullable=True, index=True)
    domain_name = Column(String(255), nullable=False, index=True)
    malicious_score = Column(Numeric(6, 4), nullable=True)
    risk_level = Column(String(32), nullable=True)
    matched_organization_id = Column(Integer, nullable=True, index=True)
    matched_organization_name = Column(String(255), nullable=True)
    actor_score = Column(Numeric(6, 4), nullable=True, index=True)
    actor_confidence = Column(String(32), nullable=True)
    reason_summary = Column(Text, nullable=True)
    evidence_json = Column(JSON, nullable=True)
    top_candidates_json = Column(JSON, nullable=True)
    enrichment_snapshot_json = Column(JSON, nullable=True)
    model_id = Column(BigInteger, nullable=True, index=True)
    model_version = Column(String(64), nullable=True)
    actor_profile_version = Column(String(64), nullable=True)
    match_method = Column(String(64), nullable=False, server_default="rule_v1")
    status = Column(String(32), nullable=False, index=True, server_default="pending")
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"), index=True)
    updated_at = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=datetime.utcnow,
    )
