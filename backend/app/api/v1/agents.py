"""Agent/server listesi endpoint'i (Faz 05).

GET /agents — events tablosundan türetilen agent envanteri:
- agent_id/agent_name/manager kırılımında olay sayısı + ilk/son görülme
- Bilinçli kapsam notu: Wazuh Server API'den canlı agent listesi OKUNMAZ
  (Faz 02 mimari kararı: alert kaynağı Indexer; Server API kapsam dışı).
  Buradaki liste "panelin gördüğü olaylara göre" envanterdir; canlı
  bağlantı durumu /ready wazuh bileşeniyle raporlanır.

Erişim: kimlik zorunlu (viewer+).
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter
from sqlalchemy import func, select

from app.api.v1.deps import CurrentUser, SessionDep
from app.api.v1.schemas import AgentListResponse, AgentRow
from app.models.event import Event

router = APIRouter(tags=["agents"])

MAX_AGENTS = 500


@router.get("/agents", response_model=AgentListResponse)
async def list_agents(
    session: SessionDep, current_user: CurrentUser
) -> AgentListResponse:
    """Olaylardan türetilmiş agent envanteri (son görülme sıralı)."""
    _ = current_user

    rows = (
        await session.execute(
            select(
                Event.agent_id,
                Event.agent_name,
                Event.manager,
                func.count().label("event_count"),
                func.min(Event.timestamp).label("first_seen"),
                func.max(Event.timestamp).label("last_seen"),
            )
            .group_by(Event.agent_id, Event.agent_name, Event.manager)
            .order_by(func.max(Event.timestamp).desc())
            .limit(MAX_AGENTS)
        )
    ).all()

    items = [
        AgentRow(
            agent_id=agent_id,
            agent_name=agent_name,
            manager=manager,
            event_count=int(count),
            first_seen=first_seen if isinstance(first_seen, datetime) else None,
            last_seen=last_seen if isinstance(last_seen, datetime) else None,
        )
        for agent_id, agent_name, manager, count, first_seen, last_seen in rows
    ]
    return AgentListResponse(items=items, total=len(items))
