from sqlalchemy import BigInteger, Column, Date, DateTime, Enum as SqlEnum, ForeignKey, Integer, String, text

from app.db.base import Base


class AlertFile(Base):
    __tablename__ = "alert_files"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), ForeignKey("alerts.alert_id"), nullable=False, index=True)
    subscription_id = Column(String(64), nullable=False, index=True)
    task_id = Column(String(64), nullable=False, index=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    model_id = Column(BigInteger, nullable=False, index=True)
    task_type = Column(
        SqlEnum("malicious", "impersonation", name="alert_files_task_type_enum"),
        nullable=False,
    )
    frequency = Column(
        SqlEnum("daily", "weekly", "monthly", name="alert_files_frequency_enum"),
        nullable=False,
    )
    file_id = Column(Integer, ForeignKey("files.id"), nullable=False, index=True)
    file_role = Column(
        SqlEnum("full_result", "report", name="alert_files_file_role_enum"),
        nullable=False,
        server_default="full_result",
    )
    file_format = Column(
        SqlEnum("json", name="alert_files_file_format_enum"),
        nullable=False,
        server_default="json",
    )
    domain_count = Column(Integer, nullable=False, server_default=text("0"))
    alert_date = Column(Date, nullable=False, index=True)
    created_at = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
