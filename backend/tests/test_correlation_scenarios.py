"""Etiketli sentetik senaryo suite (Faz 06 bağımsız doğrulama gereksinimi).

phases/06 doğrulama promptu karşılığı:
- Senaryolar: normal bakım, başarısız login burst, başarılı login sonrası
  şüpheli değişiklik, duplicate event, farklı sunuculardaki benzer olay,
  zaman sırası bozuk olay ve eksik alan.
- precision / recall / false-positive rate / event→tespit latency hesaplanır.
- Her eşleşmede kanıt (alert_ids/evidence) ve kural ID/sürümü gösterilir.
- Sentetik kayıtlar AÇIKÇA etiketlidir (fixture meta.synthetic=true + senaryo
  başına benign/malicious label + SENTETİK ibaresi) — gerçek saldırı verisi
  gibi sunulamaz (AGENTS.md §7: test verisi sentetik ve işaretli olmalı).

Sentetiklik kanıtı: tests/fixtures/correlation_scenarios.json meta bloğu;
test fixture etiketini doğrular (etiketsiz fixture suite'i dolduramaz).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

import app.models  # noqa: F401  # metadata kaydı
from app.core.db import Base, register_sqlite_fk_pragma
from app.models.correlation import Correlation, CorrelationEvent
from app.services.correlation.repository import CorrelationRepository
from app.services.normalization.models import NormalizedEvent
from app.services.normalization.repository import EventRepository
from app.workers.correlation import run_correlation_cycle

SCENARIO_PATH = Path(__file__).parent / "fixtures" / "correlation_scenarios.json"
# Tüm senaryo olayları 06:00-10:00 aralığında; döngü zamanı sabittir:
NOW = datetime(2026, 10, 26, 11, 0, 0, tzinfo=UTC)
LOOKBACK_SECONDS = 8 * 3600.0


def load_scenarios() -> dict[str, Any]:
    data = json.loads(SCENARIO_PATH.read_text(encoding="utf-8"))
    meta = data["meta"]
    assert meta["synthetic"] is True, "fixture SENTETİK etiketli olmalıdır"
    assert "GERCEK SALDIRI VERISI DEGIL" in meta["license"].upper().replace("İ", "I")
    for scenario in data["scenarios"]:
        assert scenario["label"] in {"benign", "malicious"}, (
            f"{scenario['id']}: her senaryo benign/malicious ETİKETLİ olmalıdır"
        )
        assert "SENTETIK" in scenario["description"].upper()
    return data


@dataclass
class ScenarioOutcome:
    scenario_id: str
    label: str
    predicted: set[str] = field(default_factory=set)
    expected: set[str] = field(default_factory=set)
    detections: int = 0
    max_latency_seconds: float = 0.0


def _to_normalized(alert: dict[str, Any]) -> NormalizedEvent:
    """Fixture alert satırını sürümlenmiş event modeline çevirir."""
    return NormalizedEvent(
        alert_id=alert["alert_id"],
        timestamp=datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00")),
        rule_id=alert["rule_id"],
        rule_level=alert["rule_level"],
        rule_description=alert["rule_description"],
        rule_groups=list(alert["rule_groups"]),
        agent_id=alert.get("agent_id"),
        agent_name=alert.get("agent_name"),
        src_ip=alert.get("src_ip"),
        full_log_redacted=alert.get("full_log"),
        manager="wazuh-manager-synth",
        location="/var/log/synth.log",
        decoder="sshd",
    )


async def _fresh_sessionmaker(tmp_path: Path, name: str) -> tuple[async_sessionmaker, AsyncEngine]:
    """Senaryo başına İZOLE sqlite DB (çapraz kirlenme yok)."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/{name}.db")
    register_sqlite_fk_pragma(engine)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    return async_sessionmaker(engine, expire_on_commit=False), engine


async def _correlation_rows(maker: Any) -> list[Correlation]:
    async with maker() as session:
        return list((await session.scalars(select(Correlation))).all())


class TestLabeledSyntheticScenarios:
    @pytest.mark.asyncio
    async def test_all_scenarios_against_labels(self, tmp_path: Any) -> None:
        data = load_scenarios()
        outcomes: list[ScenarioOutcome] = []

        for scenario in data["scenarios"]:
            maker, engine = await _fresh_sessionmaker(
                tmp_path, f"scenario-{scenario['id']}"
            )
            try:
                await CorrelationRepository(maker).sync_rule_catalog(
                    __import__(
                        "app.services.correlation.rules",
                        fromlist=["build_default_catalog"],
                    ).build_default_catalog()
                )
                repo = EventRepository(maker)
                expected = {
                    key for key, want in scenario["expected"].items() if want
                }
                duplicate_delivery = scenario["id"] == "duplicate_event"
                latest_window_end = NOW

                for _round in range(2 if duplicate_delivery else 1):
                    for alert in scenario["alerts"]:
                        await repo.store_event(_to_normalized(alert))
                    result = await run_correlation_cycle(
                        maker,
                        lookback_seconds=LOOKBACK_SECONDS,
                        max_events=10_000,
                        now=NOW,
                    )
                    latest_window_end = max(
                        latest_window_end, NOW - timedelta(seconds=result.max_latency_seconds)
                    )

                rows = await _correlation_rows(maker)
                predicted = {row.rule_key for row in rows}
                outcome = ScenarioOutcome(
                    scenario_id=scenario["id"],
                    label=scenario["label"],
                    predicted=predicted,
                    expected=expected,
                    detections=len(rows),
                    max_latency_seconds=(
                        (NOW - max(row.window_end for row in rows)).total_seconds()
                        if rows
                        else 0.0
                    ),
                )
                outcomes.append(outcome)

                # --- Senaryoya özel davranış doğrulamaları -------------------
                if scenario["id"] == "normal_bakim":
                    assert rows == [], "normal bakım tespit ÜRETMEMELİ"
                elif scenario["id"] == "duplicate_event":
                    # Tekrar teslimat YENİ SATIR ÜRETMEZ; hit_count artar ve
                    # duplicate event'ler bağlantılara ÇOĞALTILARAK eklenmez.
                    per_key: dict[str, int] = {}
                    for row in rows:
                        per_key[row.rule_key] = per_key.get(row.rule_key, 0) + 1
                    assert all(count == 1 for count in per_key.values()), (
                        "duplicate event tek korelasyon satırı üretmeli"
                    )
                    async with maker() as session:
                        hit_counts = (
                            await session.scalars(select(Correlation.hit_count))
                        ).all()
                        link_rows = (
                            await session.execute(
                                select(
                                    CorrelationEvent.correlation_id,
                                    func.count(),
                                ).group_by(CorrelationEvent.correlation_id)
                            )
                        ).all()
                    assert all(count == 2 for count in hit_counts), (
                        "ikinci turda hit_count artmalı (yeni satır değil)"
                    )
                    for _cid, link_count in link_rows:
                        assert link_count == 5, (
                            "duplicate alert bağlantıyı çoğaltmamalı (5 unique event)"
                        )
                elif scenario["id"] == "farkli_sunucular":
                    burst_rows = [
                        row for row in rows if row.rule_key == "failed_login_burst"
                    ]
                    assert len(burst_rows) == 2, (
                        "farklı sunuculardaki benzer olay AYRI tespit olmalı"
                    )
                    group_values = {
                        row.evidence["group_value"]["agent_id"] for row in burst_rows
                    }
                    assert group_values == {"105", "106"}
                elif scenario["id"] == "zaman_sirasi_bozuk":
                    assert rows, "zaman sırası bozuk olsa da tespit üretilmeli"
                    # Motor zamanı sıraladı: pencere başlangıcı EN ESKİ olay:
                    earliest = min(
                        datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00"))
                        for a in scenario["alerts"]
                    )
                    assert all(
                        row.window_start == earliest for row in rows
                    ), "motor zaman sırasına sokmalı (ingest sırası değil)"
                elif scenario["id"] == "eksik_alan":
                    assert rows == [], "eksik grup alanı sahte gruplama üretmemeli"

                # --- Her eşleşmede kanıt + kural ID gösterimi ----------------
                for row in rows:
                    assert row.rule_version >= 1
                    assert row.evidence.get("alert_ids"), (
                        f"{scenario['id']}: kanıt alert_ids boş olamaz"
                    )
                    assert row.evidence.get("matched_rule_ids"), (
                        f"{scenario['id']}: eşleşen kural ID'leri gösterilmeli"
                    )
                    assert 0 <= row.max_rule_level <= 15
                    async with maker() as session:
                        links = (
                            await session.execute(
                                select(func.count())
                                .select_from(CorrelationEvent)
                                .where(
                                    CorrelationEvent.correlation_id == row.id
                                )
                            )
                        ).scalar_one()
                    assert links == row.event_count, (
                        "kanıt bağlantı sayısı event_count ile tutarlı olmalı"
                    )
                    # event→tespit gecikmesi ölçülebilir aralıkta:
                    latency = (NOW - row.window_end).total_seconds()
                    assert 0 <= latency <= LOOKBACK_SECONDS
            finally:
                await engine.dispose()

        # --- Suite geneli metrikler (phases/06 doğrulama ölçütü) ----------
        all_rules = set(data["meta"]["rules_under_test"])
        tp = fp = fn = tn = 0
        for outcome in outcomes:
            tp += len(outcome.predicted & outcome.expected)
            fp += len(outcome.predicted - outcome.expected)
            fn += len(outcome.expected - outcome.predicted)
            tn += len(all_rules - outcome.predicted - outcome.expected)
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 1.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        max_latency = max(o.max_latency_seconds for o in outcomes)

        print("\n--- Faz 06 sentetik senaryo metrikleri ---")
        for outcome in outcomes:
            print(
                f"  {outcome.scenario_id:35s} [{outcome.label:9s}] "
                f"tahmin={sorted(outcome.predicted) or '{}'} "
                f"beklenen={sorted(outcome.expected) or '{}'}"
            )
        print(f"  TP={tp} FP={fp} FN={fn} TN={tn}")
        print(f"  precision={precision:.4f} recall={recall:.4f} FPR={fpr:.4f}")
        print(f"  max event→tespit latency={max_latency:.1f}s")

        # Deterministik kurallar + etiketli suite → kusursuz sınıflandırma:
        assert precision == 1.0, "yanlış pozitif VAR (etiketlere göre)"
        assert recall == 1.0, "kaçırılan tespit VAR (etiketlere göre)"
        assert fpr == 0.0, "false-positive rate sıfır olmalı"
        assert tp > 0 and tn > 0, "suite hem tespit hem temiz senaryo içermeli"
