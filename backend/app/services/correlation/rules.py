"""Korelasyon kural kataloğu (Faz 06) — basit ve açıklanabilir kurallar.

Faz gereksinimi: "İlk etapta bilinen örnek senaryolar için basit ve
açıklanabilir kurallarla başla; gereksiz ML/anomali algoritması ekleme."
→ Katalog KOD içinde sürümlenmiş veri olarak yaşar; eşik/pencere/filtre
parametreleri doğrulanmış (Pydantic) ve DB'ye yansıtılır (operatör
enabled anahtarı + audit).

Kural türleri (kind):
- burst   : aynı grup anahtarında window_seconds içinde >= threshold eşleşen
            event → tespit (örn. başarısız login patlaması).
- sequence: aynı grup anahtarında önce first- filtresine uyan bir event,
            ardından window_seconds içinde then- filtresine uyan bir event
            → çift tespit (örn. başarılı giriş sonrası şüpheli değişiklik).

Sürüm disiplini: tanım değişirse version ARTIRILIR (startup senkronu
değişimi audit'ler); mevcut tespit kayıtları kendi rule_version'larını
taşır — geçmiş, hangi tanımla üretildiğini göstermeye devam eder.

GRUP ANAHTARI ve None (eksik alan) politikası: group_by listesindeki
alanlardan HERHANGİ biri None ise event o kural için ELİMİNE edilir
(None==None sahte gruplaşması yapılamaz; "eksik alan" senaryosu).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

GROUP_FIELDS = ("agent_id", "agent_name", "src_ip", "rule_id")
GroupField = Literal["agent_id", "agent_name", "src_ip", "rule_id"]

# Parametre tavanları (açıklanabilirlik + kaynak koruması)
MAX_WINDOW_SECONDS = 86_400.0
MAX_THRESHOLD = 10_000
MAX_RULE_ID_FILTERS = 64
MAX_GROUP_FILTERS = 32


class CorrelationParams(BaseModel):
    """Doğrulanmış kural parametreleri (DB'de JSON olarak saklanır).

    match_*  : birinci aşama filtresi (burst: tespit olayları; sequence:
               "ilk" olay — örn. başarılı giriş).
    then_*   : yalnızca kind=sequence için ikinci aşama filtresi.
    group_by : grup anahtarı alanları (örn. ["agent_id"]; tekrar kuralı
               için ["agent_id", "rule_id"]).
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["burst", "sequence"]
    window_seconds: float = Field(gt=0, le=MAX_WINDOW_SECONDS)
    threshold: int = Field(default=2, ge=2, le=MAX_THRESHOLD)
    group_by: list[GroupField] = Field(min_length=1, max_length=4)
    match_rule_ids: list[str] = Field(default_factory=list, max_length=MAX_RULE_ID_FILTERS)
    match_rule_groups: list[str] = Field(
        default_factory=list, max_length=MAX_GROUP_FILTERS
    )
    match_min_level: int = Field(default=0, ge=0, le=15)
    then_rule_ids: list[str] = Field(default_factory=list, max_length=MAX_RULE_ID_FILTERS)
    then_rule_groups: list[str] = Field(
        default_factory=list, max_length=MAX_GROUP_FILTERS
    )
    then_min_level: int = Field(default=0, ge=0, le=15)

    @model_validator(mode="after")
    def _validate_filters(self) -> CorrelationParams:
        if self.kind == "sequence":
            first_has_filter = bool(self.match_rule_ids or self.match_rule_groups)
            then_has_filter = bool(self.then_rule_ids or self.then_rule_groups)
            if not (first_has_filter and then_has_filter):
                raise ValueError(
                    "sequence kuralı için hem match_* (ilk olay) hem then_* "
                    "(ikinci olay) filtrelerinden en az biri dolu olmalıdır."
                )
            # Ayrıklık zorunlusu: aynı event iki aşamaya da uyarsa motor
            # tüm olayları "ikinci" havuzuna taşır ve tespit HİÇ üretemez
            # (sessiz false-negative tuzağı). Tanım hatalıysa başlangıçta reddet.
            id_overlap = set(self.match_rule_ids) & set(self.then_rule_ids)
            group_overlap = set(self.match_rule_groups) & set(self.then_rule_groups)
            if id_overlap or group_overlap:
                raise ValueError(
                    "sequence kuralında match_* ve then_* filtreleri KESİŞMEMELİDIR "
                    f"(rule_ids kesişimi: {sorted(id_overlap)}, "
                    f"rule_groups kesişimi: {sorted(group_overlap)}). Aynı event "
                    "iki aşamaya da uyarsa tespit hiç üretilemez."
                )
        return self

    def to_storage(self) -> dict[str, object]:
        """DB params sütunu için sözlük (JSON-uyumlu; tuple yok)."""
        return self.model_dump(mode="json")


class CorrelationRuleDef:
    """Koddaki tek kural tanımı (sürümlenmiş, donuk)."""

    __slots__ = ("key", "name", "description", "version", "params", "enabled")

    def __init__(
        self,
        *,
        key: str,
        name: str,
        description: str,
        version: int,
        params: CorrelationParams,
        enabled: bool = True,
    ) -> None:
        if not key or len(key) > 64 or not key.replace("_", "").isalnum():
            raise ValueError(f"Geçersiz kural anahtarı: {key!r}")
        if version < 1:
            raise ValueError("Kural sürümü en az 1 olmalıdır.")
        self.key = key
        self.name = name
        self.description = description
        self.version = version
        self.params = params
        self.enabled = enabled

    def __repr__(self) -> str:  # pragma: no cover — debug kolaylığı
        return f"CorrelationRuleDef(key={self.key!r}, version={self.version})"


def _failed_login_burst() -> CorrelationRuleDef:
    """Kural 1: aynı agent'ta kısa sürede çok sayıda başarısız giriş."""
    return CorrelationRuleDef(
        key="failed_login_burst",
        name="Başarısız giriş patlaması",
        description=(
            "Aynı agent üzerinde 5 dakika içinde 5 veya daha fazla başarısız "
            "kimlik doğrulama olayı (authentication_failed grubu). Kaba kuvvet "
            "denemesi göstergesidir; doğrulama: eşleşen olayların kaynak IP'si "
            "ve hedef hesapları panelde incelenmelidir."
        ),
        version=1,
        params=CorrelationParams(
            kind="burst",
            window_seconds=300.0,
            threshold=5,
            group_by=["agent_id"],
            match_rule_groups=["authentication_failed"],
        ),
    )


def _suspicious_change_after_login() -> CorrelationRuleDef:
    """Kural 2: başarılı giriş sonrası aynı agent'ta yapılandırma/hesap değişikliği."""
    return CorrelationRuleDef(
        key="suspicious_change_after_login",
        name="Giriş sonrası şüpheli değişiklik",
        description=(
            "Aynı agent'ta başarılı bir kimlik doğrulamayı (authentication_success) "
            "10 dakika içinde kullanıcı/kurulum değişikliği (adduser, "
            "account_changed, config_change grupları veya Wazuh 550/553/554/591 "
            "kuralları) izler. Yetki sürüklenmesi göstergesidir; çift sıralı "
            "olarak raporlanır (giriş + değişiklik)."
        ),
        version=1,
        params=CorrelationParams(
            kind="sequence",
            window_seconds=600.0,
            threshold=2,
            group_by=["agent_id"],
            match_rule_groups=["authentication_success"],
            then_rule_ids=["550", "553", "554", "591"],
            then_rule_groups=["adduser", "account_changed", "config_change"],
        ),
    )


def _repeated_alert() -> CorrelationRuleDef:
    """Kural 3: aynı agent + aynı kural tekrarı (near-duplicate tekrar sinyali)."""
    return CorrelationRuleDef(
        key="repeated_alert",
        name="Tekrarlayan uyarı (aynı kural)",
        description=(
            "Aynı agent üzerinde aynı Wazuh kuralı 10 dakika içinde 3 veya daha "
            "fazla kez tetiklenir. Aynı uyarının tekrarını tek tespitte "
            "yoğunlaştırır (gürültü azaltma); hit_count ve kanıt bağlantıları "
            "tekrar sayısını izlenebilir kılar."
        ),
        version=1,
        params=CorrelationParams(
            kind="burst",
            window_seconds=600.0,
            threshold=3,
            group_by=["agent_id", "rule_id"],
        ),
    )


def build_default_catalog() -> tuple[CorrelationRuleDef, ...]:
    """Varsayılan katalog (deterministik sıra: key'e göre alfabetik)."""
    catalog = (_failed_login_burst(), _suspicious_change_after_login(), _repeated_alert())
    return tuple(sorted(catalog, key=lambda rule: rule.key))


def params_from_storage(raw: object) -> CorrelationParams:
    """DB params sütununu doğrulayarak modele çevirir (bozuk satır reddedilir)."""
    if not isinstance(raw, dict):
        raise ValueError("correlation_rules.params JSON nesnesi olmalıdır.")
    return CorrelationParams.model_validate(raw)


__all__ = [
    "GROUP_FIELDS",
    "CorrelationParams",
    "CorrelationRuleDef",
    "build_default_catalog",
    "params_from_storage",
]
