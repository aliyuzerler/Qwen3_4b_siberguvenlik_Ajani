"""SQLAlchemy async motor ve oturum yönetimi (Faz 01 altyapısı).

ORM modelleri Faz 03'te eklenecektir; bu fazda yalnızca altyapı bulunur:
- init_engine(): ayarlardan gelen URL ile async motor kurar
- get_session(): istek başına taze AsyncSession üreten FastAPI dependency
- dispose_engine(): kapanışta motoru düzgün kapatır
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Tüm ORM modellerinin taban sınıfı (Faz 03'te doldurulur)."""


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def init_engine(database_url: str) -> AsyncEngine:
    """Uygulama yaşam döngüsü başında motoru kurar."""
    global _engine, _sessionmaker
    _engine = create_async_engine(database_url, pool_pre_ping=True)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("DB motoru başlatılmadı: önce init_engine() çağrılmalıdır.")
    return _engine


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: istek başına taze oturum."""
    if _sessionmaker is None:
        raise RuntimeError("DB motoru başlatılmadı: önce init_engine() çağrılmalıdır.")
    async with _sessionmaker() as session:
        yield session


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
