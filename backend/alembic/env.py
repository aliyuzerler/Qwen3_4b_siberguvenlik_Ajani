"""Alembic migration ortamı (async motor ile).

- Migration URL'i Settings.database_url üzerinden alınır; secret alembic.ini'ye yazılmaz.
- ORM modelleri Faz 03'te eklendiğinde aşağıdaki import açılacak ve
  target_metadata otomatik doldurulacaktır.
- İlk tablolar Faz 03'te gelecektir; bu fazda yalnızca altyapı kuruludur.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context
from app.core.config import get_settings
from app.core.db import Base

# Faz 03'te: from app import models  # noqa: F401  (modelleri Base'e kaydeder)
target_metadata = Base.metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# URL'i .env/settings üzerinden ata (secret dosyaya yazılmaz)
config.set_main_option("sqlalchemy.url", get_settings().database_url)


def run_migrations_offline() -> None:
    """Offline mod: SQL betiği üretimi (bağlantı gerektirmez)."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def _run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    """Online mod: doğrudan veritabanına uygula (async engine)."""
    asyncio.run(_run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
