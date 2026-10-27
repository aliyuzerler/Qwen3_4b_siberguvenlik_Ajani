"""audit_log tablosu ORM modeli (Faz 05) — append-only denetim izi.

Gereksinimler (phases/05-security-dashboard.md, AGENTS.md §4):
- "Yönetim panelinde ... audit logging uygula" → kimlik doğrulama olayları
  (giriş başarılı/başarısız/frenlendi, refresh, bootstrap) kaydedilir.
- Append-only: kodda bu tabloya UPDATE/DELETE YOKTUR — ajant kendi audit
  kayıtlarını değiştiremez/silemez (AGENTS.md §4). Retention bu fazda
  audit'e uygulanmaz (kalıcı iz istenir); Faz 08'de politikayla netleşir.
- Parola/token değeri ASLA kaydedilmez: yalnızca aktör (kullanıcı adı veya
  'anonymous'), eylem, kaynak, küçük yapısal detay (JSON), istemci IP ve
  request ID saklanır.

Erişim yetkileri (belgelenmiş; compose'da uygulanan kullanıcı):
- Uygulama DB kullanıcısı: SELECT/INSERT (audit_log). UPDATE/DELETE yok.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.event import FlexibleJSON, UTCDateTime


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AuditLog(Base):
    """Tek denetim kaydı (append-only)."""

    __tablename__ = "audit_log"
    __table_args__ = (
        # Olay adı whitelist'i kod tarafında sabitlerle korunur; CHECK yalnızca
        # son savunma hattıdır (biçim: alan.alan[.alan] — nokta ile ayrılmış).
        # Serbest metin kasıtlı DEĞİLDİR: yazan tek kod services/security/audit
        # içindeki sabit eylem adlarıdır.
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=_utcnow, index=True
    )
    # Aktör: giriş başarısızsa denenen kullanıcı adı; çözülemeyen istekte
    # 'anonymous'. Kullanıcı silinse bile iz kalır (FK YOK — kasıtlı).
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    detail: Mapped[dict[str, object] | None] = mapped_column(FlexibleJSON, nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # İleride dışa aktarım/uyarı için serbest satır arama alanı (kısa metin;
    # parola/token ASLA buraya yazılmaz — yazan kod bunu zorunlu kılar).
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover — debug kolaylığı
        return (
            f"AuditLog(id={self.id!s}, actor={self.actor!r}, "
            f"action={self.action!r}, created_at={self.created_at.isoformat()})"
        )
