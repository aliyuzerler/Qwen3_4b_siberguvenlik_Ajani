"""Audit log okuma endpoint'i (Faz 05) — yalnızca admin.

GET /audit — append-only denetim izinin PANEL GÖRÜNÜMÜ:
- Yalnızca admin rolü: kısıt router düzeyinde dependency olarak TANIM
  ANINDA bağlanır (fonksiyon gövdesine değil) — koruma atlama hatası
  yapılamaz; viewer/analyst 403 alır.
- Salt okunur: listeleme + sayfalama; güncelleme/silme ucu YOKTUR (model
  de yalnızca INSERT ile yaşar — append-only sözleşme şema seviyesinde).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.api.v1.deps import CurrentUser, SessionDep, require_role
from app.api.v1.schemas import AuditEntry, AuditListResponse
from app.models.audit import AuditLog
from app.models.user import ROLE_ADMIN

router = APIRouter(
    tags=["audit"],
    dependencies=[Depends(require_role(ROLE_ADMIN))],
)

MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 25


@router.get("/audit", response_model=AuditListResponse)
async def list_audit(
    session: SessionDep,
    current_user: CurrentUser,
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
) -> AuditListResponse:
    """Denetim kayıtları (en yeni önce, sayfalı) — yalnızca admin."""
    _ = current_user

    total: int = (
        await session.scalars(select(func.count()).select_from(AuditLog))
    ).one()
    pages = (total + page_size - 1) // page_size
    rows = (
        (
            await session.execute(
                select(AuditLog)
                .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return AuditListResponse(
        items=[
            AuditEntry(
                id=str(entry.id),
                created_at=entry.created_at,
                actor=entry.actor,
                action=entry.action,
                resource=entry.resource,
                detail=entry.detail,
                client_ip=entry.client_ip,
                request_id=entry.request_id,
            )
            for entry in rows
        ],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )
