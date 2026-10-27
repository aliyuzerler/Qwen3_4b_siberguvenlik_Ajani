"""rate_limit_counters tablosu — paylaşımlı rate limit deposu (Faz 08)

Revision ID: 0006_hardening
Revises: 0005_remediation
Create Date: 2026-10-27

İçerik:
- rate_limit_counters (sabit pencere hız freni kovası): çok prosesli /
  çok düğümlü dağıtımda brute-force freninin prosesler arası geçerli olması
  için (phases/08: "rate limit ve DoS dayanıklılığı").
  - Birleşik PK (key, window_start): aynı anahtar+pencere tek satır.
  - ix_rate_limit_counters_window_start: cleanup DELETE'i bu indeksle tarar.

Bu tablo İZ DEĞİLDİR (audit_log append-only'den farklı): yalnızca pencere
sayacıdır; eski kovalar cleanup ile SİLİNİR — bilinçli ve belgelenmiştir
(app/services/security/db_rate_limit.py modül docstring).

Geri dönüş (downgrade): tablo düşürülür; RATE_LIMIT_BACKEND=memory kalırsa
uygulama etkilenmez. database modunda tablo yoksa fren DB hatası verir
(fail-closed) → downgrade öncesi backend=memory'ye dönün (docs/deployment.md).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0006_hardening"
down_revision: str = "0005_remediation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_counters",
        sa.Column("key", sa.String(length=160), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hit_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("key", "window_start"),
    )
    op.create_index(
        "ix_rate_limit_counters_window_start",
        "rate_limit_counters",
        ["window_start"],
    )


def downgrade() -> None:
    op.drop_index("ix_rate_limit_counters_window_start", table_name="rate_limit_counters")
    op.drop_table("rate_limit_counters")
