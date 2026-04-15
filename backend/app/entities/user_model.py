from sqlalchemy import Column, DateTime, ForeignKey, Integer, text

from app.db.base import Base


class UserModel(Base):
    __tablename__ = "user_models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    model_id = Column(Integer, ForeignKey("models.id"), nullable=False)
    acquired_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    is_active = Column(Integer, nullable=True, server_default=text("1"))
