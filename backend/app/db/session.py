from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import MYSQL_URL

engine = create_engine(MYSQL_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
