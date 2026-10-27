"""API v1 router birleşimi (Faz 05: auth + panel uçları eklendi)."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import agents, audit_api, auth, events, health, overview, settings_api

api_v1_router = APIRouter()
# Sıra anlamlıdır: health en sonda değil ama public uçlar önce listelenir.
api_v1_router.include_router(health.router)
api_v1_router.include_router(auth.router)
api_v1_router.include_router(events.router)
api_v1_router.include_router(overview.router)
api_v1_router.include_router(agents.router)
api_v1_router.include_router(audit_api.router)
api_v1_router.include_router(settings_api.router)
