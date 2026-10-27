"""API v1 router birleşimi (Faz 05: auth + panel uçları; Faz 07: remediation; Faz 08: users)."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    agents,
    audit_api,
    auth,
    correlations,
    events,
    health,
    overview,
    remediation,
    settings_api,
    users,
)

api_v1_router = APIRouter()
# Sıra anlamlıdır: health en sonda değil ama public uçlar önce listelenir.
api_v1_router.include_router(health.router)
api_v1_router.include_router(auth.router)
# Faz 08: "me" literal ucu {user_id} desenli uçlardan ÖNCE kaydedilir
# (users.py docstring: route sırası).
api_v1_router.include_router(users.self_router)
api_v1_router.include_router(events.router)
api_v1_router.include_router(correlations.router)
api_v1_router.include_router(remediation.router)
api_v1_router.include_router(overview.router)
api_v1_router.include_router(agents.router)
api_v1_router.include_router(audit_api.router)
api_v1_router.include_router(settings_api.router)
api_v1_router.include_router(users.router)
