"""SQLAlchemy async motor ve oturum yönetimi (Faz 01 altyapısı).

ORM modelleri Faz 03'te eklenecektir; bu fazda yalnızca altyapı bulunur:
- init_engine(): ayarlardan gelen URL ile async motor kurar
- get_session(): istek başına taze AsyncSession üreten FastAPI dependency
- dispose_engine(): kapanışta motoru düzgün kapatır
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy import event
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


def register_sqlite_fk_pragma(engine: AsyncEngine) -> None:
    """SQLite'ta FK kısıtlarını etkinleştir (PG'de varsayılan davranış).

    Gerekçe: analyses.events_id FK ON DELETE CASCADE (Faz 04 retention
    sözleşmesi) sqlite dev/test ortamında da PG ile AYNI semantiği taşımalı.
    SQLite'ta foreign_keys pragma bağlantı başına KAPALI başlar; aiosqlite
    sürücüsü için connect olayında açılır (prod PG'de no-op).
    Test fixture'ları kendi motorunu kurduğunda da çağrılmalıdır.
    """

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def init_engine(database_url: str) -> AsyncEngine:
    """Uygulama yaşam döngüsü başında motoru kurar."""
    global _engine, _sessionmaker
    _engine = create_async_engine(database_url, pool_pre_ping=True)
    if database_url.startswith("sqlite"):
        register_sqlite_fk_pragma(_engine)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("DB motoru başlatılmadı: önce init_engine() çağrılmalıdır.")
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Aktif oturum fabrikasını döndürür (worker döngüsü/deposu kullanır)."""
    if _sessionmaker is None:
        raise RuntimeError("DB motoru başlatılmadı: önce init_engine() çağrılmalıdır.")
    return _sessionmaker


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
