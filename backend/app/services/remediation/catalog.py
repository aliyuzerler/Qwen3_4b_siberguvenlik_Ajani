"""Müdahale aksiyon kataloğu (Faz 07).

Gereksinimler (phases/07-remediation-guardrails.md):
- "Tipli action enum; serbest shell komutu yok" → her aksiyonun tipi,
  parametre şeması ve hedef kapsamı AÇIKÇA tanımlıdır. Kullanıcı/model
  girdisinde `command` benzeri serbest metin alanı TOPLUCA yasaktır
  (tüm param modelleri extra="forbid"; bilinmeyen alan şemayı düşürür).
- "Allowlist" → aksiyon YALNIZCA bu katalogda tanımlıysa önerilebilir.
  Katalog kod kaynağıdır (correlation_rules kalıbı); DB'de yalnızca
  operatör `enabled` anahtarı yaşar (0005 migration).
- "Kritik sistem erişimini kesebilecek firewall/SSH işlemlerini varsayılan
  olarak engelle" → default_blocked=True aksiyonlar (firewall/SSH/hesap)
  iki bağımsız kapı olmadan asla önerilemez/uygulanamaz:
      1) REMEDIATION_ALLOW_BLOCKED_ACTIONS=true (env; prod'da config reddeder)
      2) admin PATCH ile aksiyon enabled=true (audit'li)
- "Eylem öncesi ... risk açıklaması" → her tanım risk_explanation ve
  rollback_note (TR) taşır; öneri satırına anlık kopyalanır (kanıt paketi).

Model eylem BAŞLATAMAZ (AGENTS.md §4): kataloğa erişen tek kod yolu
API'deki insan uçlarıdır (analyst+); analysis/worker paketleri bu modülü
İÇERMEZ (test_remediation_security kaynak taramasıyla kalıcı garanti).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# --- Tipli aksiyon enum (serbest metin DEĞİL) -------------------------------

ACTION_NOTIFY_ADMIN = "notify_admin"
ACTION_RESTART_WAZUH_AGENT = "restart_wazuh_agent"
ACTION_RUN_ANTIVIRUS_SCAN = "run_antivirus_scan"
ACTION_BLOCK_SRC_IP = "block_src_ip"
ACTION_ISOLATE_HOST = "isolate_host"
ACTION_LOCK_USER_ACCOUNT = "lock_user_account"

ActionType = Literal[
    "notify_admin",
    "restart_wazuh_agent",
    "run_antivirus_scan",
    "block_src_ip",
    "isolate_host",
    "lock_user_account",
]

ALL_ACTION_TYPES: tuple[str, ...] = (
    ACTION_NOTIFY_ADMIN,
    ACTION_RESTART_WAZUH_AGENT,
    ACTION_RUN_ANTIVIRUS_SCAN,
    ACTION_BLOCK_SRC_IP,
    ACTION_ISOLATE_HOST,
    ACTION_LOCK_USER_ACCOUNT,
)

RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"

# --- Hedef kapsam kuralları (deterministik; motor uygular) ------------------
#
# "yanlış hedef" reddi: parametre değeri, önerinin kanıt paketinde
# (bağlı olaylardan sunucu tarafında üretilen) MAKUL biçimde bulunmalıdır.
SCOPE_AGENT_ID = "agent_id"  # agent_id en az bir bağlı olayda geçmeli
SCOPE_SRC_IP = "src_ip"  # ip değeri en az bir bağlı olayın src_ip'si olmalı
SCOPE_ANY_EVENT = "any_event"  # hedef doğrulaması yok; ≥1 bağlı olay yeterli


# --- Tip parametre şemaları (extra=forbid → serbest alan sızamaz) -----------


class NotifyAdminParams(BaseModel):
    """Bilgilendirme: sistem değişikliği YAPMAZ (bildirim içeriği sabit şablon)."""

    model_config = ConfigDict(extra="forbid")

    note: str | None = Field(default=None, max_length=300)


class AgentTargetParams(BaseModel):
    """agent_id hedefli aksiyonlar (restart/tarama/izolasyon) için tip param."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")


class BlockSrcIpParams(BaseModel):
    """IP engelleme (FIREWALL — default_blocked). Serbest komut yok: tek alan."""

    model_config = ConfigDict(extra="forbid")

    ip: str = Field(min_length=7, max_length=45)

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        import ipaddress

        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"Geçersiz IP adresi: {value!r}") from exc
        return value


class LockUserParams(BaseModel):
    """Hesap kilidi (SSH/HESAP — default_blocked). Kullanıcı adı kısıtlı karakter seti."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    """Bir müdahale aksiyonunun tam tanımı (allowlist kaydı)."""

    key: str
    title: str  # TR panel adı
    description: str  # TR kısa açıklama
    risk_level: str  # low | medium | high
    default_blocked: bool  # firewall/SSH/hesap → True (varsayılan ENGELLİ)
    param_model: type[BaseModel]
    target_scope: str  # SCOPE_* sabiti
    risk_explanation: str  # TR risk metni (öneriye kopyalanır)
    rollback_note: str  # TR geri alma/mitigation notu
    execution_plan: str  # dry-run çıktısında "ne yapılacaktı" açıklaması
    blocked_reason: str = field(default="")
    blocked_detail: str = field(default="")

    def validate_params(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Tip doğrulaması; dönen değer normalize edilmiş param sözlüğüdür.

        - extra="forbid": `command`, `args`, `shell` gibi serbest alanlar
          (modelden gelse bile) ValidationError ile reddedilir.
        """
        validated = self.param_model.model_validate(raw)
        return validated.model_dump(mode="json", exclude_none=True)


# --- Katalog (kod kaynaklı; sıralama panel/enum kararlılığı için) -----------

_ACTION_DEFINITIONS: tuple[ActionDefinition, ...] = (
    ActionDefinition(
        key=ACTION_NOTIFY_ADMIN,
        title="Yöneticiyi bilgilendir",
        description=(
            "Seçili olay(lar) için sabit şablonlu bilgilendirme kaydı oluşturur; "
            "sistemde hiçbir değişiklik yapmaz."
        ),
        risk_level=RISK_LOW,
        default_blocked=False,
        param_model=NotifyAdminParams,
        target_scope=SCOPE_ANY_EVENT,
        risk_explanation=(
            "Düşük risk: yalnızca panel/bildirim akışında kayıt üretilir; "
            "sunucu, ağ veya hesap üzerinde hiçbir değişiklik yapılmaz."
        ),
        rollback_note="Geri alma gerekmez; bilgilendirme kaydı panelde arşivlenir.",
        execution_plan=(
            "Gerçek ortamda e-posta/webhook bildirimi gönderilecektir "
            "(bildirim entegrasyonu Faz 08+); dry-run yalnızca planı kaydeder."
        ),
    ),
    ActionDefinition(
        key=ACTION_RESTART_WAZUH_AGENT,
        title="Wazuh ajanını yeniden başlat",
        description=(
            "Hedef sunucudaki Wazuh ajan servisini yeniden başlatır; "
            "telemetri akışını geri kazanmak için kullanılır."
        ),
        risk_level=RISK_MEDIUM,
        default_blocked=False,
        param_model=AgentTargetParams,
        target_scope=SCOPE_AGENT_ID,
        risk_explanation=(
            "Orta risk: hedef sunucuda kısa süreli telemetri kesintisi olur; "
            "yanlış hedef seçilirse başka bir sunucunun ajanı etkilenir. "
            "Hedef kapsamı doğrulaması agent_id'yi kanıt olaylarına bağlar."
        ),
        rollback_note=(
            "Ajan yeniden başlatma idempotenttir; ajan başlamazsa "
            "'systemctl status wazuh-agent' ile hata incelenir ve servis "
            "eski durumuna getirilir (bkz. docs/remediation-runbook.md §2)."
        ),
        execution_plan=(
            "Gerçek ortamda Wazuh API/ajan yönetim kanalı üzerinden restart "
            "komutu gönderilecektir; dry-run yalnızca planı kaydeder."
        ),
    ),
    ActionDefinition(
        key=ACTION_RUN_ANTIVIRUS_SCAN,
        title="Tam antivirüs taraması başlat",
        description=(
            "Hedef sunucuda tam sistem taraması başlatır; "
            "şüpheli aktivite sonrası doğrulama adımıdır."
        ),
        risk_level=RISK_MEDIUM,
        default_blocked=False,
        param_model=AgentTargetParams,
        target_scope=SCOPE_AGENT_ID,
        risk_explanation=(
            "Orta risk: tarama sırasında hedefte CPU/G/IO yükü artar; "
            "yanlış hedef, gereksiz yük üretir. Hedef kapsamı doğrulaması "
            "agent_id'yi kanıt olaylarına bağlar."
        ),
        rollback_note=(
            "Tarama durdurulabilir (hedefteki ajan arayüzünden); sonuçlar "
            "yalnızca rapor üretir, sistem değişikliği yapmaz."
        ),
        execution_plan=(
            "Gerçek ortamda hedefteki EDR/AV entegrasyonuna tarama isteği "
            "gönderilecektir; dry-run yalnızca planı kaydeder."
        ),
    ),
    ActionDefinition(
        key=ACTION_BLOCK_SRC_IP,
        title="Kaynak IP'yi engelle (firewall)",
        description=(
            "Firewall kuralıyla kaynak IP'yi engeller. KRİTİK: panel/Wazuh "
            "iletişimini veya meşru kullanıcı erişimini kesebilir."
        ),
        risk_level=RISK_HIGH,
        default_blocked=True,
        param_model=BlockSrcIpParams,
        target_scope=SCOPE_SRC_IP,
        blocked_reason="default_blocked",
        blocked_detail=(
            "Firewall işlemi kritik erişimi kesebilir (panel/Wazuh/meşru "
            "kullanıcı trafiği). Varsayılan ENGELLİ; yalnızca "
            "REMEDIATION_ALLOW_BLOCKED_ACTIONS=true VE admin enable ile açılır."
        ),
        risk_explanation=(
            "YÜKSEK risk: yanlış IP engellenirse meşru erişim veya "
            "güvenlik altyapısının iletişimi kesilir; maskelenmiş/güvenilir "
            "olmayan kaynak IP'si hatalı bloğa yol açabilir."
        ),
        rollback_note=(
            "Firewall kuralı ters adımla kaldırılır (bkz. "
            "docs/remediation-runbook.md §3); kural ID'si yürütme kaydında saklanır."
        ),
        execution_plan=(
            "Gerçek ortamda firewall yönetim kanalına kural ekleme isteği "
            "gönderilecektir; dry-run yalnızca planı kaydeder, kural EKLENMEZ."
        ),
    ),
    ActionDefinition(
        key=ACTION_ISOLATE_HOST,
        title="Sunucuyu izole et",
        description=(
            "Hedef sunucunun ajan-ana iletişimi dışındaki ağ erişimini keser. "
            "KRİTİK: sunucunun tüm servislerini etkiler."
        ),
        risk_level=RISK_HIGH,
        default_blocked=True,
        param_model=AgentTargetParams,
        target_scope=SCOPE_AGENT_ID,
        blocked_reason="default_blocked",
        blocked_detail=(
            "Sunucu izolasyonu kritik erişimi kesebilir (üretim servisleri, "
            "uzaktan erişim). Varsayılan ENGELLİ; yalnızca "
            "REMEDIATION_ALLOW_BLOCKED_ACTIONS=true VE admin enable ile açılır."
        ),
        risk_explanation=(
            "YÜKSEK risk: hedef sunucudaki üretim servisleri ve uzaktan "
            "yönetim erişimi kesilir; yanlış hedef seçimi hizmet kesintisi üretir."
        ),
        rollback_note=(
            "İzolasyon kuralı kaldırılarak ağ erişimi geri verilir "
            "(bkz. docs/remediation-runbook.md §3); adımlar runbook'tadır."
        ),
        execution_plan=(
            "Gerçek ortamda NAC/firewall üzerinden izolasyon kuralı "
            "uygulanacaktır; dry-run yalnızca planı kaydeder."
        ),
    ),
    ActionDefinition(
        key=ACTION_LOCK_USER_ACCOUNT,
        title="Kullanıcı hesabını kilitle",
        description=(
            "SSH/hesap yönetimi üzerinden kullanıcı hesabını kilitleyerek "
            "girişi engeller. KRİTİK: meşru kullanıcıyı kilitleyebilir."
        ),
        risk_level=RISK_HIGH,
        default_blocked=True,
        param_model=LockUserParams,
        target_scope=SCOPE_ANY_EVENT,
        blocked_reason="default_blocked",
        blocked_detail=(
            "Hesap kilidi SSH/oturum erişimini keser (kritik erişim). "
            "Varsayılan ENGELLİ; yalnızca REMEDIATION_ALLOW_BLOCKED_ACTIONS=true "
            "VE admin enable ile açılır."
        ),
        risk_explanation=(
            "YÜKSEK risk: yanlış kullanıcı adı kilitlenirse meşru yönetici "
            "veya servis hesabının erişimi kesilir; kilitli servis hesabı "
            "uygulama kesintisi üretir."
        ),
        rollback_note=(
            "Hesap kilidi 'passwd -u <user>' / dizin servisi ters adımıyla "
            "açılır (bkz. docs/remediation-runbook.md §3)."
        ),
        execution_plan=(
            "Gerçek ortamda kimlik/SSH yönetim kanalına hesap kilidi isteği "
            "gönderilecektir; dry-run yalnızca planı kaydeder."
        ),
    ),
)

_CATALOG: dict[str, ActionDefinition] = {d.key: d for d in _ACTION_DEFINITIONS}


def get_action_definition(action_type: str) -> ActionDefinition | None:
    """Allowlist araması: tanımsız aksiyon → None (policy reddi)."""
    return _CATALOG.get(action_type)


def list_action_definitions() -> list[ActionDefinition]:
    """Katalog sıralı (enum sırası) kopyasını döndürür."""
    return list(_ACTION_DEFINITIONS)


__all__ = [
    "ACTION_BLOCK_SRC_IP",
    "ACTION_ISOLATE_HOST",
    "ACTION_LOCK_USER_ACCOUNT",
    "ACTION_NOTIFY_ADMIN",
    "ACTION_RESTART_WAZUH_AGENT",
    "ACTION_RUN_ANTIVIRUS_SCAN",
    "ALL_ACTION_TYPES",
    "ActionDefinition",
    "ActionType",
    "RISK_HIGH",
    "RISK_LOW",
    "RISK_MEDIUM",
    "SCOPE_AGENT_ID",
    "SCOPE_ANY_EVENT",
    "SCOPE_SRC_IP",
    "get_action_definition",
    "list_action_definitions",
]
