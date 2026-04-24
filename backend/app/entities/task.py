from datetime import datetime

from sqlalchemy import Column, DateTime, Enum as SqlEnum, ForeignKey, Integer, JSON, String, text

from app.db.base import Base


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(String(64), unique=True, index=True, nullable=False)
    task_type = Column(
        SqlEnum("malicious", "impersonation", name="task_type_enum"),
        nullable=False,
    )
    model_id = Column(Integer, ForeignKey("models.id"), nullable=False)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=True)
    extra = Column(JSON, nullable=True)
    status = Column(
        SqlEnum("pending", "processing", "completed", "failed", name="task_status_enum"),
        nullable=False,
        server_default="pending",
    )
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    updated_at = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=datetime.utcnow,
    )
