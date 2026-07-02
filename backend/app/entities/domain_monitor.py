from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, JSON, Numeric, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.mysql import BIGINT as MysqlBigInteger

from app.db.base import Base


UnsignedBigInteger = MysqlBigInteger(unsigned=True)


class DomainMonitorTarget(Base):
    __tablename__ = "domain_monitor_targets"
    __table_args__ = (
        UniqueConstraint("user_id", "normalized_domain", name="uniq_domain_monitor_user_domain"),
        Index("idx_domain_monitor_due", "is_active", "next_check_at"),
    )

    id = Column(UnsignedBigInteger, primary_key=True, autoincrement=True)
    user_id = Column(UnsignedBigInteger, ForeignKey("users.id"), nullable=False, index=True)
    domain = Column(String(255), nullable=False)
    normalized_domain = Column(String(255), nullable=False, index=True)
    is_active = Column(Boolean, nullable=False, server_default=text("1"))
    monitor_interval_hours = Column(Integer, nullable=False, server_default=text("24"))
    next_check_at = Column(DateTime, nullable=False)
    last_checked_at = Column(DateTime, nullable=True)
    status = Column(String(32), nullable=False, server_default="pending", index=True)
    consecutive_failures = Column(Integer, nullable=False, server_default=text("0"))
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=text("CURRENT_TIMESTAMP"),
    )


class DomainMonitorSource(Base):
    __tablename__ = "domain_monitor_sources"
    __table_args__ = (
        Index("idx_domain_monitor_source_target", "target_id"),
        Index("idx_domain_monitor_source_type", "source_type"),
        Index("idx_domain_monitor_source_task", "task_id"),
        Index("idx_domain_monitor_source_alert", "alert_id"),
        Index("idx_domain_monitor_source_subscription", "subscription_id"),
        Index("idx_domain_monitor_source_model", "model_id"),
    )

    id = Column(UnsignedBigInteger, primary_key=True, autoincrement=True)
    target_id = Column(UnsignedBigInteger, ForeignKey("domain_monitor_targets.id"), nullable=False)
    source_type = Column(String(32), nullable=False)
    task_id = Column(String(64), nullable=True)
    task_type = Column(String(64), nullable=True)
    model_id = Column(UnsignedBigInteger, nullable=True)
    subscription_id = Column(String(64), nullable=True)
    alert_id = Column(String(64), nullable=True)
    risk_score = Column(Numeric(10, 6), nullable=True)
    risk_level = Column(String(32), nullable=True)
    risk_record = Column(JSON, nullable=True)
    detected_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))


class DomainMonitorSnapshot(Base):
    __tablename__ = "domain_monitor_snapshots"
    __table_args__ = (
        Index("idx_domain_monitor_snapshot_target", "target_id"),
        Index("idx_domain_monitor_snapshot_collected", "target_id", "collected_at"),
        Index("idx_domain_monitor_snapshot_status", "status"),
    )

    id = Column(UnsignedBigInteger, primary_key=True, autoincrement=True)
    target_id = Column(UnsignedBigInteger, ForeignKey("domain_monitor_targets.id"), nullable=False)
    status = Column(String(32), nullable=False, server_default="success")
    collected_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    whois_snapshot = Column(JSON, nullable=True)
    dns_snapshot = Column(JSON, nullable=True)
    certificate_snapshot = Column(JSON, nullable=True)
    web_snapshot = Column(JSON, nullable=True)
    changed_fields = Column(JSON, nullable=True)
    raw_lookup_errors = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
