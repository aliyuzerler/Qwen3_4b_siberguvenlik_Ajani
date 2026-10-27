"""rate_limit_counters tablosu (Faz 08 — paylaşımlı rate limit deposu).

Neden: bellek içi fren (Faz 05) tek proses içindir. Çok prosesli uvicorn
veya çok düğümlü dağıtımda sayaçların PAYLAŞILMASI gerekir (phases/08:
"rate limit ve DoS dayanıklılığı"). Redis gibi yeni bir servis eklemek
yerine mevcut DB kullanılır:

- Satır anahtarı (key, window_start): sabit pencere kovası.
- check() atomik UPSERT ile hit_count'u artırır (ON CONFLICT DO UPDATE;
  PostgreSQL ve SQLite'ın modern sürümleri destekler — aiosqlite/asyncpg).
- Tablo SADECE fren sayaçları içerir: güvenlik kararı değil, telemetri
  bile değildir; silinebilir (cleanup) — audit_log append-only kuralına
  aykırı DEĞİLDİR (audit_log'dan farklı olarak bu tablo iz taşırmaz,
  yalnızca pencere sayacıdır).
- Anahtar kardinalitesi IP/kullanıcı sayısıyla sınırlıdır; cleanup eski
  kovaları siler (append-only İSTİSNASI bilinçli ve belgelenmiştir).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.event import UTCDateTime

# Anahtar biçimi: "login:<ip>" | "refresh:<ip>" | "remediation:<username>"
# — IP 64 karakterle kırpılır (audit ile aynı kural); tavana pad eklenir.
KEY_LENGTH = 160


class RateLimitCounter(Base):
    """Sabit pencere hız freni kovası (paylaşımlı depo)."""

    __tablename__ = "rate_limit_counters"

    key: Mapped[str] = mapped_column(String(KEY_LENGTH), primary_key=True)
    # Pencere başlangıcı (UTC, pencere uzunluğuna hizalı — floor).
    window_start: Mapped[datetime] = mapped_column(UTCDateTime(), primary_key=True)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # cleanup DELETE'i bu kolonla tarar (tarama maliyeti: eski kovalar).
    __table_args__ = (
        Index("ix_rate_limit_counters_window_start", "window_start"),
    )

    def __repr__(self) -> str:  # pragma: no cover — debug kolaylığı
        return (
            f"RateLimitCounter(key={self.key!r}, window_start={self.window_start!s}, "
            f"hit_count={self.hit_count!s})"
        )
