#!/usr/bin/env python3
"""Staging test-alert besleyici (Faz 10).

Gerçek Wazuh bulunmayan staging'de uçtan uca akışı (ingest → normalizasyon →
idempotent saklama → panel → AI analizi) doğrulamak için SENTETİK alert'leri
ÜRETİM İNGEST YOLUYLA besler:

    parse_alert_hit → normalize → redaction → EventRepository (idempotent)

Özellikler:
- Zaman damgaları ŞİMDİ'dir: worker ilk penceresi (WORKER_INITIAL_WINDOW_SECONDS)
  kaçsa da yakalanır; gerçek Wazuh gecikme senaryosunu taklit eder.
- Veri tamamen sentetiktir; örnek değerler (AGENTS.md §3): IP'ler RFC 5737
  dokümantasyon aralığından, kullanıcı adları örnek etiketlerdir.
- Idempotent: aynı alert_id tekrar koşumda YENİ satır üretmez (duplicate).
- Bu script gerçek Wazuh YOKKEN kullanılır; gerçek kurulumda GEREKMEZ ve
  üretim veritabanına karşı KOŞULMAZ (sentez veri bulaşmasın).

Kullanım (backend dizininden veya DATABASE_URL env ile):
    DATABASE_URL=postgresql+asyncpg://… python3 ../scripts/seed_staging_events.py
    # sandbox smoke örneği:
    DATABASE_URL=sqlite+aiosqlite:////tmp/ajant.db python3 scripts/seed_staging_events.py

Çıktı: tek satır JSON — {"fetched", "stored", "duplicate", "failed", "ok"}
Exit kodları: 0 başarı, 1 hata.
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from importlib import resources
from pathlib import Path


def _ensure_backend_on_path() -> None:
    """backend/ paketini sys.path'e ekler (script repo dışından da koşulabilir).

    Adaylar: betiğin kardeşi backend/, veya çalışma dizini. İlk bulanan kazanır;
    `app` zaten importlanabiliyorsa dokunulmaz.
    """
    try:
        import app  # noqa: F401

        return
    except ModuleNotFoundError:
        pass
    candidates = [
        Path(__file__).resolve().parent.parent / "backend",
        Path.cwd(),
    ]
    for candidate in candidates:
        if (candidate / "app" / "__init__.py").is_file():
            sys.path.insert(0, str(candidate))
            return


_ensure_backend_on_path()


def build_fresh_hits(*, minutes_ago_start: float = 10.0, step_seconds: float = 1.0) -> list[dict]:
    """Fixture alert'lerini ŞİMDİ'ye denk getirilmiş zamanlarla hit zarfına sarar.

    Fixture sırası timestamp DESC'tir; en eskiden başlayarak artan aralıklarla
    yeniden damgalanır (gerçek Wazuh akışındaki sıra gibi).
    """
    raw = (
        resources.files("app.services.wazuh.fixtures")
        .joinpath("sample_alerts.json")
        .read_text(encoding="utf-8")
    )
    alerts = json.loads(raw).get("alerts")
    if not isinstance(alerts, list) or not alerts:
        raise RuntimeError("Fixture okunamadı/boş — paket bozuk olabilir.")

    base = datetime.now(UTC) - timedelta(minutes=minutes_ago_start)
    hits: list[dict] = []
    for index, alert in enumerate(reversed(alerts)):
        item = copy.deepcopy(alert)
        stamp = base + timedelta(seconds=index * step_seconds)
        # Wazuh Indexer biçimi: '2026-10-26T09:15:00.000+0000' (parsing.py uyumlu)
        item["timestamp"] = stamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
        hits.append({"_id": str(item.get("id")), "_source": item})
    return hits


async def seed(database_url: str) -> dict[str, int]:
    """Sentetik alert'leri üretim ingest yoluyla besler (şema ÖNCEDEN uygulanmış
    olmalıdır: compose başlangıcında `alembic upgrade head` bunu yapar; script
    tek başına koşulacaksa önce `python -m alembic upgrade head` çalıştırın)."""
    # Lazy import: backend paketi sys.path'te olmalı (script backend kökünde koşar)
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.services.normalization.redaction import RedactionPolicy
    from app.services.normalization.repository import EventRepository
    from app.services.wazuh.mock_source import MockWazuhAlertSource
    from app.services.wazuh.models import AlertQuery
    from app.workers.ingest import run_ingest_cycle

    engine = create_async_engine(database_url)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        source = MockWazuhAlertSource(hits=build_fresh_hits())
        # EventRepository kendi oturumlarını sessionmaker'dan açar (istek başına
        # taze oturum disiplini — repository.py). Tek yazar döngüyle aynı yol.
        repo = EventRepository(maker)
        result = await run_ingest_cycle(
            source,
            repo,
            RedactionPolicy(),
            query=AlertQuery(since=None, limit=100),
            store_raw=False,
            max_pages=5,
        )
        return {
            "fetched": result.fetched,
            "stored": result.stored,
            "duplicate": result.duplicate,
            "variant": result.variant,
            "failed": result.failed,
        }
    finally:
        await engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(description="Staging sentetik alert besleyici")
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL", ""),
        help="DATABASE_URL (env alternatifi)",
    )
    args = parser.parse_args()
    if not args.database_url:
        print("HATA: DATABASE_URL gerekli (--database-url veya env).", file=sys.stderr)
        return 1

    try:
        result = asyncio.run(seed(args.database_url))
    except Exception as exc:  # noqa: BLE001 — operasyon scripti: açık hata, temiz exit
        print(f"HATA: besleme başarısız: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    result["ok"] = 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
