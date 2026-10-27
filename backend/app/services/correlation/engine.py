"""Korelasyon motoru (Faz 06) — deterministik, saf (pure) değerlendirme.

Gereksinimler (phases/06):
- "Ortak agent, IP, kullanıcı, süreç ve alert ID gibi mevcut kanıt
  alanlarıyla ilişki" → group_by alanları agent_id/agent_name/src_ip/rule_id;
  kanıt (evidence) agent adları, IP'ler, eşleşen kural ID'leri ve alert_id
  listesini taşır.
- "Her korelasyon için hangi olayların ve hangi kuralın eşleştiğini göster"
  → tespit, eşleşen event ID'lerini (zaman sırasıyla) ve kural anahtarını/
  sürümünü taşır; repository bu listeyi correlation_events bağlantısı olarak
  yazar.
- "Duplicate/near-duplicate yönetimi" → dedup_key = sha256(rule | grup |
  pencere başlangıcı): aynı olay kümesi yeniden taranırsa aynı anahtar
  üretilir; repository yeni satır yazmak yerine hit_count artırır.
- "Kural çıktısı ve LLM yorumu ayrı" → motor YALNIZCA kural çıktısı üretir;
  LLM alanı yoktur (analyses tablosu olay başına ayrı kalır).

Zaman sırası bozuk girdi: event'ler grup içinda (timestamp, alert_id)
sırasına konur — ingestion sırası sonuç değiştirmez (belirlenimci).

Algoritma (açıklanabilir, ML yok):
- burst: grup içi kayan pencere; eşik sağlandığında küme emit edilir ve
  gösterici kümenin sonuna atlanır (üst üste binen kümeler yok).
- sequence: her "ilk" olay için zaman sırasında tüketilmemiş İLK uygun
  "ikinci" olay çiftlenir; her ikinci olay en fazla bir kez tüketilir.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime

from app.models.event import Event
from app.services.correlation.rules import CorrelationParams, CorrelationRuleDef

__all__ = ["CorrelationDetection", "EngineRun", "CorrelationEngine"]


@dataclass(frozen=True)
class CorrelationDetection:
    """Tek kural tespiti (DB'ye yazılmadan önceki saf sonuç)."""

    rule_key: str
    rule_version: int
    dedup_key: str
    window_start: datetime
    window_end: datetime
    event_ids: tuple[str, ...]  # eşleşen events.id (UUID string, zaman sırasıyla)
    event_count: int
    max_rule_level: int
    evidence: dict[str, object]

    def latency_seconds(self, *, now: datetime) -> float:
        """event→tespit gecikmesi: son eşleşen olaydan tespit anına (saniye).

        Ölçüm sözleşmesi (phases/06 doğrulama): now, döngünün çalıştırılma
        zamanıdır; gerçek dağıtımda created_at ile aynı anı temsil eder.
        """
        return max(0.0, (now - self.window_end).total_seconds())


@dataclass
class EngineRun:
    """Tek değerlendirme turunun ölçülebilir sonucu (AGENTS.md §7)."""

    detections: list[CorrelationDetection] = field(default_factory=list)
    events_scanned: int = 0
    rules_evaluated: int = 0
    skipped_missing_group: int = 0  # filtre geçti ama grup alanı eksik olan event


def _matches(
    event: Event,
    *,
    rule_ids: frozenset[str],
    rule_groups: frozenset[str],
    min_level: int,
) -> bool:
    """Filtre koşulu: ID listesi VEYA grup kesişimi VEYA alt seviye (hepsi opsiyonel)."""
    if min_level and event.rule_level < min_level:
        return False
    if rule_ids and event.rule_id not in rule_ids:
        return False
    if rule_groups:
        groups = event.rule_groups or []
        if not rule_groups.intersection(groups):
            return False
    return True


def _group_value(event: Event, group_by: Sequence[str]) -> tuple[object, ...] | None:
    """Grup anahtarı; bileşenlerden biri eksikse (None) event elenir."""
    values: list[object] = []
    for field_name in group_by:
        value = getattr(event, field_name, None)
        if value is None:
            return None
        values.append(value)
    return tuple(values)


def _dedup_key(rule_key: str, group_value: tuple[object, ...], window_start: datetime) -> str:
    """Tekrar-tespiti anahtarı: aynı kural+grup+pencere başlangıcı aynı anahtar.

    Pencere başlangıcı, kümeyi açan İLK event'in UTC zamanıdır; lookback
    penceresi kaydıkça kümenin ilk eventi değişmedikçe anahtar kararlıdır
    (sınır durumu: ilk event lookback dışına düşerse devam için yeni tespit
    satırı açılabilir — belgelenmiş bilinen kısıt).
    """
    parts = [rule_key, *map(str, group_value), window_start.isoformat()]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _sorted_events(events: Sequence[Event]) -> list[Event]:
    """(timestamp, alert_id) sıralı kopya — belirlenimci ve çakışmaya dayanıklı."""
    return sorted(events, key=lambda e: (e.timestamp, e.alert_id))


def _evidence(
    params: CorrelationParams,
    group_value: tuple[object, ...],
    events: Sequence[Event],
    *,
    first: Sequence[Event] | None = None,
    then: Sequence[Event] | None = None,
) -> dict[str, object]:
    """Yapılandırılmış kanıt sözlüğü (panel/API'de görüntülenir)."""
    evidence: dict[str, object] = {
        "group_fields": list(params.group_by),
        "group_value": dict(zip(params.group_by, map(str, group_value), strict=True)),
        "agent_names": sorted({e.agent_name for e in events if e.agent_name}),
        "src_ips": sorted({e.src_ip for e in events if e.src_ip}),
        "matched_rule_ids": sorted({e.rule_id for e in events}),
        "alert_ids": [e.alert_id for e in events],  # zaman sırasıyla
    }
    if first is not None:
        evidence["first_alert_ids"] = [e.alert_id for e in first]
    if then is not None:
        evidence["then_alert_ids"] = [e.alert_id for e in then]
    return evidence


def _emit(
    rule: CorrelationRuleDef,
    group_value: tuple[object, ...],
    cluster: Sequence[Event],
    *,
    first: Sequence[Event] | None = None,
    then: Sequence[Event] | None = None,
) -> CorrelationDetection:
    window_start = cluster[0].timestamp
    window_end = cluster[-1].timestamp
    return CorrelationDetection(
        rule_key=rule.key,
        rule_version=rule.version,
        dedup_key=_dedup_key(rule.key, group_value, window_start),
        window_start=window_start,
        window_end=window_end,
        event_ids=tuple(str(e.id) for e in cluster),
        event_count=len(cluster),
        max_rule_level=max(e.rule_level for e in cluster),
        evidence=_evidence(
            rule.params, group_value, cluster, first=first, then=then
        ),
    )


class CorrelationEngine:
    """Kural kataloğunu event listesine uygular; saf fonksiyon (DB yok)."""

    def evaluate(
        self, events: Sequence[Event], rules: Sequence[CorrelationRuleDef]
    ) -> EngineRun:
        run = EngineRun(events_scanned=len(events), rules_evaluated=len(rules))
        # Deterministik kural sırası: key'e göre (çift tespitte sonuç sırası kararlı).
        for rule in sorted(rules, key=lambda r: r.key):
            params = rule.params
            match_rule_ids = frozenset(params.match_rule_ids)
            match_rule_groups = frozenset(params.match_rule_groups)
            then_rule_ids = frozenset(params.then_rule_ids)
            then_rule_groups = frozenset(params.then_rule_groups)

            eligible: list[Event] = []
            for event in events:
                if not _matches(
                    event,
                    rule_ids=match_rule_ids,
                    rule_groups=match_rule_groups,
                    min_level=params.match_min_level,
                ):
                    continue
                if _group_value(event, params.group_by) is None:
                    run.skipped_missing_group += 1
                    continue
                eligible.append(event)
            if params.kind == "sequence":
                # sequence: then- olayları da havuza girer (aynı filtre-çifti mantığı).
                for event in events:
                    if not _matches(
                        event,
                        rule_ids=then_rule_ids,
                        rule_groups=then_rule_groups,
                        min_level=params.then_min_level,
                    ):
                        continue
                    if _group_value(event, params.group_by) is None:
                        run.skipped_missing_group += 1
                        continue
                    eligible.append(event)

            if not eligible:
                continue

            groups: dict[tuple[object, ...], list[Event]] = {}
            for event in eligible:
                key = _group_value(event, params.group_by)
                if key is None:  # pragma: no cover — yukarıda elendi
                    continue
                groups.setdefault(key, []).append(event)

            for group_value, group_events in sorted(
                groups.items(), key=lambda item: tuple(map(str, item[0]))
            ):
                ordered = _sorted_events(group_events)
                if params.kind == "burst":
                    run.detections.extend(
                        self._evaluate_burst(rule, group_value, ordered)
                    )
                else:
                    run.detections.extend(
                        self._evaluate_sequence(rule, group_value, ordered)
                    )
        return run

    def _evaluate_burst(
        self,
        rule: CorrelationRuleDef,
        group_value: tuple[object, ...],
        ordered: list[Event],
    ) -> list[CorrelationDetection]:
        """Kayan pencere + eşik; üst üste binmeyen kümeler (belirlenimci)."""
        params = rule.params
        window = params.window_seconds
        detections: list[CorrelationDetection] = []
        i, n = 0, len(ordered)
        while i < n:
            anchor = ordered[i].timestamp
            j = i
            while j < n and (ordered[j].timestamp - anchor).total_seconds() <= window:
                j += 1
            cluster = ordered[i:j]
            if len(cluster) >= params.threshold:
                detections.append(_emit(rule, group_value, cluster))
                i = j  # kümenin sonuna atla: aynı olaylar ikinci kez raporlanmaz
            else:
                i += 1
        return detections

    def _evaluate_sequence(
        self,
        rule: CorrelationRuleDef,
        group_value: tuple[object, ...],
        ordered: list[Event],
    ) -> list[CorrelationDetection]:
        """İlk→ikinci çiftleme; her ikinci olay en fazla bir kez tüketilir."""
        params = rule.params
        window = params.window_seconds
        then_rule_ids = frozenset(params.then_rule_ids)
        then_rule_groups = frozenset(params.then_rule_groups)

        first_events: list[Event] = []
        then_events: list[Event] = []
        for event in ordered:
            if _matches(
                event,
                rule_ids=then_rule_ids,
                rule_groups=then_rule_groups,
                min_level=params.then_min_level,
            ):
                then_events.append(event)
            else:
                first_events.append(event)

        detections: list[CorrelationDetection] = []
        consumed: set[int] = set()
        for first in first_events:
            for k, candidate in enumerate(then_events):
                if k in consumed:
                    continue
                delta = (candidate.timestamp - first.timestamp).total_seconds()
                if delta <= 0:
                    continue  # ikinci olay ilk olaydan ÖNCE gelmiş → çift değil
                if delta > window:
                    break  # sıralı: gerisi daha uzak
                detections.append(
                    _emit(
                        rule,
                        group_value,
                        [first, candidate],
                        first=[first],
                        then=[candidate],
                    )
                )
                consumed.add(k)
                break
        return detections
