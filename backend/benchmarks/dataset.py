"""Benchmark dataset yükleme + doğrulama (Faz 09).

Faz gereksinimleri:
- "Sabit, etiketli bir değerlendirme kümesi" → JSONL; her kayıt
  expected_assessment etiketi taşır. ETİKETİ EKSİK KAYIT VARSA küme
  GEÇERSİZDİR ve koşum REDDEDİLİR (doğrulama promptu: "Etiketler eksik...
  sonucu geçerli ilan etme").
- "Veri yetkili/sentetik veya lisansı uygun kaynaklardan gelmeli; hassas
  veriler temizlenmeli" → hassas-veri taraması (e-posta, secret
  assignment, bearer/basic, özel anahtar bloğu) + IP allowlist
  (yalnızca RFC 5737 TEST-NET ve 10.0.0.0/8).
- "Eğitim/validation/test setlerini olay ailesi veya zaman bazında ayır;
  aynı veya çok benzer olayları farklı split'lere sızdırma" →
  family/split_group taşınır; near-duplicate parmak izi ile sızıntı
  denetimi (aynı benzer olay iki farklı split_group'ta → GEÇERSİZ).

Üretim yolu sadakati: her kaydın alert'i, üretimdeki aynı dönüşüm
zincirinden geçirilir (parse_alert_hit → normalize_alert); böylece
model, benchmark'ta da maskelenmiş/normalleştirilmiş bağlam görür.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.services.correlation.rules import build_default_catalog
from app.services.normalization.models import NormalizedEvent
from app.services.normalization.normalizer import normalize_alert
from app.services.normalization.redaction import RedactionPolicy
from app.services.wazuh.errors import WazuhBadPayloadError
from app.services.wazuh.parsing import parse_alert_hit

# Dataset sözleşmesi — kayıtta bulunması ZORUNLU alanlar.
REQUIRED_FIELDS: tuple[str, ...] = (
    "record_id",
    "dataset_version",
    "family",
    "split_group",
    "expected_assessment",
    "is_malicious",
    "is_benign_maintenance",
    "is_injection",
    "injection_marker",
    "expected_evidence_fields",
    "correlation_context",
    "alert",
)

VALID_EXPECTED_ASSESSMENTS: frozenset[str] = frozenset(
    {"benign", "suspicious", "likely_malicious"}
)

# IP allowlist: yalnızca dokümantasyon/test aralıkları (AGENTS.md §3).
_ALLOWED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("127.0.0.0/8"),
)

# Hassas veri desenleri (redaction modülündeki politikayla hizalı; dataset'te
# hiçbir eşleşme KABUL EDİLMEZ — temizlenmemiş veri = geçersiz küme).
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|pass|token|api[_-]?key|apikey|access[_-]?key|"
    r"secret[_-]?key|secret|client[_-]?secret|private[_-]?key|auth)\s*[:=]\s*([^\s;]{4,})"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+([A-Za-z0-9._~+/=-]{8,})")
_BASIC_RE = re.compile(r"(?i)\b(basic)\s+([A-Za-z0-9+/=]{8,})")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])")

# Near-duplicate parmak izi: küçük harf + IP/dijital normalizasyon.
_NORM_DIGITS_RE = re.compile(r"\d+")
_WHITESPACE_RE = re.compile(r"\s+")


class DatasetInvalidError(Exception):
    """Dataset doğrulaması başarısız — koşum REDDEDİLİR.

    errors: yapısal hata listesi (kayıt içeriği ham haliyle taşınmaz).
    """

    def __init__(self, errors: list[str]) -> None:
        joined = "; ".join(errors[:20])
        more = len(errors) - 20
        suffix = f" (+{more} hata)" if more > 0 else ""
        super().__init__(f"Dataset geçersiz ({len(errors)} hata): {joined}{suffix}")
        self.errors = errors


@dataclass(frozen=True)
class CorrelationDetection:
    """Dataset'e donmuş tek korelasyon tespiti (baseline C bağlamı)."""

    rule_key: str
    rule_version: int
    hit_count: int
    window_seconds: float


@dataclass(frozen=True)
class BenchmarkRecord:
    """Tek değerlendirme kaydı + üretim yoluyla türetilmiş event."""

    record_id: str
    dataset_version: str
    family: str
    split_group: str
    expected_assessment: str
    is_malicious: bool
    is_benign_maintenance: bool
    is_injection: bool
    injection_marker: str | None
    expected_evidence_fields: tuple[str, ...]
    correlation_context: tuple[CorrelationDetection, ...] | None
    notes: str
    alert: dict[str, Any]
    event: NormalizedEvent

    @property
    def near_dup_fingerprint(self) -> str:
        """Benzerlik parmak izi (sızıntı denetimi için)."""
        log = self.alert.get("full_log") or ""
        return near_dup_fingerprint(str(self.alert.get("rule", {}).get("id", "")), log)


@dataclass(frozen=True)
class BenchmarkDataset:
    """Doğrulanmış, donmuş değerlendirme kümesi."""

    path: Path
    version: str
    sha256: str
    records: tuple[BenchmarkRecord, ...]

    @property
    def classification_cohort(self) -> tuple[BenchmarkRecord, ...]:
        """Sınıflandırma metriklerinin kohortu: injection dışı kayıtlar."""
        return tuple(r for r in self.records if not r.is_injection)

    @property
    def injection_cohort(self) -> tuple[BenchmarkRecord, ...]:
        """Injection dayanıklılık kohortu."""
        return tuple(r for r in self.records if r.is_injection)


def near_dup_fingerprint(rule_id: str, full_log: str) -> str:
    """Kayıt benzerliği parmak izi: kural + normalize edilmiş log.

    Amaç: "aynı veya çok benzer olay farklı split'lere sızmasın" kuralının
    makineyle denetlenebilir hali. IP'ler ve sayılar soyutlanır; küçük harf;
    boşluklar tek boşluğa indirilir.
    """
    text = full_log.lower()
    text = _IPV4_RE.sub("<ip>", text)
    text = _NORM_DIGITS_RE.sub("<n>", text)
    text = _WHITESPACE_RE.sub(" ", text).strip()
    return f"{rule_id}::{text}"


def check_split_leakage(
    records: tuple[BenchmarkRecord, ...],
    splits: dict[str, list[str]],
) -> None:
    """Split sızıntısı denetimi — sızıntı varsa DatasetInvalidError.

    Kurallar:
    1. Her split_group TAM BİR split'e ait olmalıdır (train/validation/test).
    2. Bir family'nin farklı split_group'ları FARKLI split'lere
       dağıtılamaz (family bazlı ayrım disiplini).
    3. Near-duplicate parmak izi taşıyan iki kayıt FARKLI split'te
       olamaz ("aynı veya çok benzer olay sızıntısı").
    """
    valid_split_names = {"train", "validation", "test"}
    unknown = set(splits) - valid_split_names
    if unknown:
        raise DatasetInvalidError([f"Bilinmeyen split adları: {sorted(unknown)}"])

    group_to_split: dict[str, str] = {}
    for split_name, groups in splits.items():
        for group in groups:
            if group in group_to_split:
                raise DatasetInvalidError(
                    [f"split_group '{group}' birden fazla split'te tanımlı."]
                )
            group_to_split[group] = split_name

    family_to_splits: dict[str, set[str]] = {}
    fingerprint_to_splits: dict[str, set[str]] = {}
    for record in records:
        assigned: str | None = group_to_split.get(record.split_group)
        if assigned is None:
            raise DatasetInvalidError(
                [f"{record.record_id}: split_group '{record.split_group}' "
                 "hiçbir split'te tanımlı değil."]
            )
        family_to_splits.setdefault(record.family, set()).add(assigned)
        fp = record.near_dup_fingerprint
        fingerprint_to_splits.setdefault(fp, set()).add(assigned)

    for family, split_names in sorted(family_to_splits.items()):
        if len(split_names) > 1:
            raise DatasetInvalidError(
                [f"Family '{family}' birden fazla split'e dağılmış: {sorted(split_names)} "
                 "(family bazlı sızıntı)."]
            )
    for fp, split_names in sorted(fingerprint_to_splits.items()):
        if len(split_names) > 1:
            raise DatasetInvalidError(
                [f"Near-duplicate içerik farklı split'lerde: '{fp[:60]}…' "
                 f"→ {sorted(split_names)}"]
            )


def _scan_sensitive_text(
    record_id: str,
    text: str,
    errors: list[str],
    where: str,
    *,
    secret_assignments: bool = True,
) -> None:
    """Hassas veri taraması: her eşleşme GEÇERSİZLİK hatasıdır.

    İki tarama katmanı (bilinçli ayrım):
    - HAM metin: e-posta / anahtar bloğu / bearer-basic / IP allowlist —
      dataset repoya girdiği için kaynak hijyeni zorunludur.
      secret-assignment deseni HAM katmanda YOK SAYILIR: sudo syslog'unun
      standart "PWD=/home/deploy" alanı kimlik bilgisi değildir ve gerçek
      üretim loglarının doğal biçimidir.
    - REDACTED metin (üretim redaction çıktısı): secret-assignment DAHİL
      tüm desenler — ne DB'ye ne modele gitmesi gereken her şey temizlenmiş
      olmalıdır. Redaction'dan kurtulan bir desen = dataset geçersiz.
    """
    if not text:
        return
    if _EMAIL_RE.search(text):
        errors.append(f"{record_id}: {where} e-posta deseni içeriyor (temizlenmeli).")
    if secret_assignments and _SECRET_ASSIGNMENT_RE.search(text):
        errors.append(f"{record_id}: {where} secret-assignment deseni içeriyor.")
    if _BEARER_RE.search(text):
        errors.append(f"{record_id}: {where} bearer kimlik taşıyıcı içeriyor.")
    if _BASIC_RE.search(text):
        errors.append(f"{record_id}: {where} basic kimlik taşıyıcı içeriyor.")
    if _PRIVATE_KEY_RE.search(text):
        errors.append(f"{record_id}: {where} özel anahtar bloğu içeriyor.")
    for match in _IPV4_RE.finditer(text):
        try:
            ip = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv6Address):
            continue
        if not any(ip in network for network in _ALLOWED_NETWORKS):
            errors.append(
                f"{record_id}: {where} izinli olmayan IP aralığı içeriyor "
                f"(yalnızca RFC5737/1918 test aralıkları kabul edilir)."
            )
            break


def _validate_correlation_context(
    record_id: str, raw: Any, errors: list[str]
) -> tuple[CorrelationDetection, ...] | None:
    """correlation_context alanını kataloğa karşı doğrular."""
    if raw is None:
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get("detections"), list):
        errors.append(f"{record_id}: correlation_context nesnesi/detections listesi değil.")
        return None
    catalog_keys = {rule.key for rule in build_default_catalog()}
    detections: list[CorrelationDetection] = []
    for index, item in enumerate(raw["detections"]):
        if not isinstance(item, dict):
            errors.append(f"{record_id}: detections[{index}] nesne değil.")
            return None
        key = item.get("rule_key")
        if key not in catalog_keys:
            errors.append(
                f"{record_id}: detections[{index}].rule_key '{key}' katalogda yok."
            )
            return None
        hit_count = item.get("hit_count")
        window = item.get("window_seconds")
        version = item.get("rule_version", 1)
        if not isinstance(hit_count, int) or isinstance(hit_count, bool) or hit_count < 2:
            errors.append(f"{record_id}: detections[{index}].hit_count >= 2 olmalıdır.")
            return None
        if not isinstance(window, (int, float)) or isinstance(window, bool) or window <= 0:
            errors.append(f"{record_id}: detections[{index}].window_seconds pozitif olmalıdır.")
            return None
        detections.append(
            CorrelationDetection(
                rule_key=str(key),
                rule_version=int(version),
                hit_count=hit_count,
                window_seconds=float(window),
            )
        )
    return tuple(detections)


def _validate_record(raw: Any, line_no: int, errors: list[str]) -> BenchmarkRecord | None:
    """Tek kaydı doğrular ve BenchmarkRecord üretir (hataları biriktirir)."""
    label = f"satır {line_no}"
    if not isinstance(raw, dict):
        errors.append(f"{label}: JSON nesnesi değil.")
        return None

    missing = [field for field in REQUIRED_FIELDS if field not in raw]
    if missing:
        errors.append(f"{label}: zorunlu alanlar eksik: {missing}")
        return None

    record_id = str(raw["record_id"])
    expected = raw["expected_assessment"]
    is_malicious = raw["is_malicious"]
    is_benign = raw["is_benign_maintenance"]
    is_injection = raw["is_injection"]
    marker = raw["injection_marker"]
    evidence_fields = raw["expected_evidence_fields"]

    if not record_id or record_id != record_id.strip():
        errors.append(f"{label}: record_id boş/baş-son boşluklu olamaz.")
    if expected not in VALID_EXPECTED_ASSESSMENTS:
        errors.append(
            f"{record_id or label}: expected_assessment '{expected}' geçersiz "
            f"(geçerliler: {sorted(VALID_EXPECTED_ASSESSMENTS)})."
        )
    if (
        not isinstance(is_malicious, bool)
        or not isinstance(is_benign, bool)
        or not isinstance(is_injection, bool)
    ):
        errors.append(f"{record_id or label}: is_* alanları boolean olmalıdır.")
        return None
    if is_malicious != (expected == "likely_malicious"):
        errors.append(
            f"{record_id}: is_malicious ile expected_assessment tutarsız "
            "(sözleşme: is_malicious <=> likely_malicious)."
        )
    if is_benign and (expected != "benign" or is_injection):
        errors.append(
            f"{record_id}: is_benign_maintenance yalnızca benign ve "
            "injection olmayan kayıtlarda olabilir."
        )
    if expected == "benign" and not is_injection and not is_benign:
        errors.append(f"{record_id}: benign injection-dışı kayıt bakım kohortunda olmalıdır.")
    if is_injection:
        if not marker or not isinstance(marker, str):
            errors.append(f"{record_id}: injection kaydı marker taşımalıdır.")
        else:
            full_log = str((raw.get("alert") or {}).get("full_log") or "")
            if marker not in full_log:
                errors.append(f"{record_id}: marker alert full_log içinde yok.")
    if not isinstance(evidence_fields, list) or not evidence_fields or not all(
        isinstance(item, str) and item for item in evidence_fields
    ):
        errors.append(f"{record_id}: expected_evidence_fields boş olmayan metin listesi olmalıdır.")

    alert = raw.get("alert")
    if not isinstance(alert, dict):
        errors.append(f"{record_id}: alert nesnesi değil.")
        return None

    # Üretim dönüşüm zinciri (sözleşme testi): parse → normalize.
    try:
        wazuh_alert = parse_alert_hit({"_source": alert})
    except WazuhBadPayloadError as exc:
        errors.append(f"{record_id}: alert üretim parser'ını geçemedi ({exc.message}).")
        return None
    event = normalize_alert(wazuh_alert, RedactionPolicy())

    corr = _validate_correlation_context(record_id, raw.get("correlation_context"), errors)
    # Katman 1: HAM dataset içeriği (repo hijyeni; secret-assignment hariç —
    # sudo syslog PWD= biçimi üretim loglarının doğal yapısıdır).
    _scan_sensitive_text(
        record_id, str(alert.get("full_log") or ""), errors, "full_log",
        secret_assignments=False,
    )
    _scan_sensitive_text(
        record_id,
        str(alert.get("rule", {}).get("description") or ""),
        errors,
        "rule.description",
        secret_assignments=False,
    )
    # Katman 2: ÜRETİM redaction ÇIKTISI (DB/model'e giden metin tamamen temiz olmalı).
    _scan_sensitive_text(
        record_id, event.full_log_redacted or "", errors, "full_log (redacted)",
        secret_assignments=True,
    )

    return BenchmarkRecord(
        record_id=record_id,
        dataset_version=str(raw["dataset_version"]),
        family=str(raw["family"]),
        split_group=str(raw["split_group"]),
        expected_assessment=str(expected),
        is_malicious=is_malicious,
        is_benign_maintenance=is_benign,
        is_injection=is_injection,
        injection_marker=str(marker) if marker else None,
        expected_evidence_fields=tuple(str(item) for item in evidence_fields),
        correlation_context=corr,
        notes=str(raw.get("notes", "")),
        alert=alert,
        event=event,
    )


def _dataset_level_checks(records: list[BenchmarkRecord], errors: list[str]) -> None:
    """Küme-düzeyi tutarlılık: tekillik + sızıntı (split_group bazlı)."""
    seen_ids: set[str] = set()
    seen_alert_ids: set[str] = set()
    fingerprints: dict[str, str] = {}  # fingerprint -> split_group
    for record in records:
        if record.record_id in seen_ids:
            errors.append(f"record_id tekrarlı: {record.record_id}")
        seen_ids.add(record.record_id)
        if record.event.alert_id in seen_alert_ids:
            errors.append(f"alert id tekrarlı: {record.event.alert_id}")
        seen_alert_ids.add(record.event.alert_id)
        previous_group = fingerprints.get(record.near_dup_fingerprint)
        if previous_group is not None and previous_group != record.split_group:
            errors.append(
                f"{record.record_id}: near-duplicate içerik farklı split_group'ta "
                f"('{previous_group}' vs '{record.split_group}') — sızıntı riski."
            )
        fingerprints[record.near_dup_fingerprint] = record.split_group


def load_dataset(
    path: Path, *, redaction_policy: RedactionPolicy | None = None
) -> BenchmarkDataset:
    """JSONL dataset'i yükler ve TAMAMINI doğrular.

    Herhangi bir hata varsa DatasetInvalidError YÜKSELTİLİR — kısmi koşum
    YOKTUR (doğrulama promptu: eksik etiket/sızıntı varsa sonuç geçersiz).
    """
    if not path.is_file():
        raise DatasetInvalidError([f"Dataset dosyası bulunamadı: {path}"])
    content = path.read_text(encoding="utf-8")
    errors: list[str] = []
    records: list[BenchmarkRecord] = []

    for line_no, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json_loads(line)
        except ValueError:
            errors.append(f"satır {line_no}: geçersiz JSON.")
            continue
        record = _validate_record(raw, line_no, errors)
        if record is not None:
            records.append(record)

    if not records:
        errors.append("Dataset hiç geçerli kayıt içermiyor.")

    versions = {record.dataset_version for record in records}
    if len(versions) > 1:
        errors.append(f"Dataset içinde karışık sürümler: {sorted(versions)}")

    _dataset_level_checks(records, errors)
    if errors:
        raise DatasetInvalidError(errors)

    version = records[0].dataset_version if records else "unknown"
    sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return BenchmarkDataset(
        path=path,
        version=version,
        sha256=sha256,
        records=tuple(records),
    )


def json_loads(text: str) -> Any:
    """json.loads sarmalayıcı (test kolaylığı / tek nokta)."""
    import json

    return json.loads(text)


def load_splits(path: Path) -> dict[str, list[str]]:
    """Split tanımını yükler: {"train": [...], "validation": [...], "test": [...]}."""
    raw = json_loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise DatasetInvalidError(["Split dosyası JSON nesnesi olmalıdır."])
    result: dict[str, list[str]] = {}
    for name, groups in raw.items():
        if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
            raise DatasetInvalidError([f"Split '{name}' metin listesi olmalıdır."])
        result[str(name)] = [str(g) for g in groups]
    return result


__all__ = [
    "REQUIRED_FIELDS",
    "VALID_EXPECTED_ASSESSMENTS",
    "BenchmarkDataset",
    "BenchmarkRecord",
    "CorrelationDetection",
    "DatasetInvalidError",
    "check_split_leakage",
    "load_dataset",
    "load_splits",
    "near_dup_fingerprint",
]
