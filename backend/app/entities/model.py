from sqlalchemy import BigInteger, Column, DateTime, Enum as SqlEnum, Integer, String, Text, text

from app.db.base import Base


class Model(Base):
    __tablename__ = "models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    version = Column(String(64), nullable=True)
    description = Column(Text, nullable=True)
    model_path = Column(String(500), nullable=True)
    file_size = Column(BigInteger, nullable=True)
    model_type = Column(
        SqlEnum("official", "custom", "market", name="model_type_enum"),
        nullable=True,
        server_default="custom",
    )
    is_public = Column(Integer, nullable=True, server_default=text("0"))
    created_by = Column(String(64), nullable=True)
    status = Column(
        SqlEnum("active", "inactive", name="model_status_enum"),
        nullable=False,
        server_default="active",
    )
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    model_category = Column(
        SqlEnum("malicious", "impersonation", name="model_category_enum"), nullable=True
    )
