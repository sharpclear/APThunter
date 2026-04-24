from sqlalchemy import BigInteger, Column, DateTime, Integer, JSON, String, text

from app.db.base import Base


class StoredFile(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, autoincrement=True)
    bucket = Column(String(128), nullable=False)
    object_key = Column(String(512), nullable=False)
    filename = Column(String(255), nullable=True)
    content_type = Column(String(128), nullable=True)
    size = Column(BigInteger, nullable=True)
    uploaded_by = Column(String(64), nullable=True)
    uploaded_at = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    metadata_json = Column("metadata", JSON, nullable=True)
