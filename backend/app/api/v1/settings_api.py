"""Ayarlar görüntüleme endpoint'i (Faz 05) — yalnızca admin.

GET /settings — panelin AYAR GÖRÜNÜMÜ:
- Yalnızca admin (router düzeyi dependency — atlama hatası yok).
- Secret değeri DÖNMEZ: jwt_secret, indexer parolası, bootstrap parolası
  şemada bile tanımlı değildir (schemas.SettingsResponse docstring).
- Bu fazda ayar GÜNCELLEME ucunun YOKTUR: .env + yeniden başlatma tek
  değişim yoludur (değişmez yapılandırma → yetki/tutarsızlık riski düşük;
  Faz 08 değerlendirir).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.api.v1.deps import CurrentUser, require_role
from app.api.v1.schemas import (
    ModelInfo,
    NotificationSettings,
    RedactionSettings,
    SettingsResponse,
    WorkerSettings,
)
from app.core.config import Settings
from app.models.user import ROLE_ADMIN

router = APIRouter(
    tags=["settings"],
    dependencies=[Depends(require_role(ROLE_ADMIN))],
)


@router.get("/settings", response_model=SettingsResponse)
async def get_settings_view(
    request: Request, current_user: CurrentUser
) -> SettingsResponse:
    """Güvenli ayar görüntüsü (secret yok; admin yetkili).

    Ayarlar request.app.state.settings'ten okunur: uygulama örneği kendi
    doğrulanmış Settings'ini taşır (testler izole Settings geçebilir;
    modül düzeyi get_settings() önbelleği BYPASS edilir).
    """
    _ = current_user
    settings: Settings = request.app.state.settings
    return SettingsResponse(
        app_env=settings.app_env,
        policy_mode=settings.policy_mode,
        model=ModelInfo(
            model_tag=settings.ollama_model_tag,
            model_quantization=settings.ollama_model_quantization,
            analysis_enabled=settings.analysis_enabled,
            policy_mode=settings.policy_mode,
        ),
        ollama_base_url=settings.ollama_base_url,
        retention_days=settings.retention_days,
        redaction=RedactionSettings(
            enabled=settings.redaction_enabled,
            ip_mode=settings.redact_ip_mode,
            email_mode=settings.redact_email_mode,
            secret_patterns=settings.redact_secret_patterns,
        ),
        worker=WorkerSettings(
            loop_enabled=settings.worker_loop_enabled,
            interval_seconds=settings.worker_interval_seconds,
            concurrency=settings.worker_concurrency,
            batch_size=settings.analysis_batch_size,
        ),
        notifications=NotificationSettings(),
    )
