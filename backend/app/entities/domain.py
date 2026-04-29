from sqlalchemy import Column, Date, DateTime, ForeignKey, Integer, String, text

from app.db.base import Base


class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_name = Column(String(255), nullable=False, unique=True, index=True)
    is_malicious = Column(Integer, nullable=True, server_default=text("0"))
    first_seen = Column(Date, nullable=True)
    last_seen = Column(Date, nullable=True)
    organization_id = Column(Integer, ForeignKey("apt_organizations.id"), nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
