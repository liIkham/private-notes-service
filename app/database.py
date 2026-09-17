from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings


POSTGRES_INTEGER_MAX = 2_147_483_647


class Base(DeclarativeBase):
    pass


engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    hide_parameters=True,
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
