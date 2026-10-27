"""Korelasyon motoru birim testleri (Faz 06) — saf, deterministik.

Sentetik Event nesneleriyle (DB yok) her kural türü için: eşik/pencere
sınırları, grup ayrımı, zaman sırası bozukluğu, eksik alan ve filtreler.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from app.models.event import Event
from app.services.correlation.engine import CorrelationEngine
from app.services.correlation.rules import CorrelationParams, CorrelationRuleDef

BASE_TS = datetime(2026, 10, 26, 12, 0, 0, tzinfo=UTC)

_FAILED_LOGIN_BURST = CorrelationParams(
    kind="burst",
    window_seconds=300.0,
    threshold=5,
    group_by=["agent_id"],
    match_rule_groups=["authentication_failed"],
)
_REPEATED_ALERT = CorrelationParams(
    kind="burst",
    window_seconds=600.0,
    threshold=3,
    group_by=["agent_id", "rule_id"],
)
_SEQUENCE = CorrelationParams(
    kind="sequence",
    window_seconds=600.0,
    threshold=2,
    group_by=["agent_id"],
    match_rule_groups=["authentication_success"],
    then_rule_ids=["554"],
    then_rule_groups=["adduser"],
)


def burst_rule(**overrides: Any) -> CorrelationRuleDef:
    values: dict[str, Any] = {
        "key": "failed_login_burst",
        "name": "Başarısız giriş patlaması",
        "description": "sentetik test kuralı",
        "version": 1,
        "params": _FAILED_LOGIN_BURST,
    }
    values.update(overrides)
    return CorrelationRuleDef(**values)


def repeated_rule(**overrides: Any) -> CorrelationRuleDef:
    values: dict[str, Any] = {
        "key": "repeated_alert",
        "name": "Tekrarlayan uyarı",
        "description": "sentetik test kuralı",
        "version": 1,
        "params": _REPEATED_ALERT,
    }
    values.update(overrides)
    return CorrelationRuleDef(**values)


def sequence_rule(**overrides: Any) -> CorrelationRuleDef:
    values: dict[str, Any] = {
        "key": "suspicious_change_after_login",
        "name": "Giriş sonrası şüpheli değişiklik",
        "description": "sentetik test kuralı",
        "version": 1,
        "params": _SEQUENCE,
    }
    values.update(overrides)
    return CorrelationRuleDef(**values)


_SEQ = 0


def make_event(**overrides: Any) -> Event:
    """SENTETİK Event ORM nesnesi (DB kaydı yok; motor girdisi)."""
    global _SEQ
    _SEQ += 1
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "alert_id": f"1792974900.{_SEQ:06d}",
        "timestamp": BASE_TS,
        "rule_id": "5710",
        "rule_level": 10,
        "rule_description": "sshd: Brute force trying to get access to the system.",
        "rule_groups": ["syslog", "sshd", "authentication_failed"],
        "agent_id": "001",
        "agent_name": "web-server-01",
        "src_ip": "203.0.113.7",
    }
    values.update(overrides)
    return Event(**values)


def failed_login(offset_seconds: float, **overrides: Any) -> Event:
    ts = BASE_TS + timedelta(seconds=offset_seconds)
    return make_event(timestamp=ts, **overrides)


class TestBurstRule:
    def test_threshold_reached_emits_single_detection(self) -> None:
        events = [failed_login(i * 30) for i in range(5)]  # 0..120s, eşik 5
        run = CorrelationEngine().evaluate(events, [burst_rule()])
        assert len(run.detections) == 1
        detection = run.detections[0]
        assert detection.rule_key == "failed_login_burst"
        assert detection.rule_version == 1
        assert detection.event_count == 5
        assert detection.window_start == BASE_TS
        assert detection.window_end == BASE_TS + timedelta(seconds=120)
        # Kanıt: zaman sıralı alert_id listesi + grup alanı/değeri
        assert detection.evidence["group_value"] == {"agent_id": "001"}
        assert detection.evidence["alert_ids"] == [e.alert_id for e in events]
        assert detection.evidence["matched_rule_ids"] == ["5710"]
        assert "web-server-01" in detection.evidence["agent_names"]
        assert "203.0.113.7" in detection.evidence["src_ips"]
        assert detection.max_rule_level == 10

    def test_below_threshold_no_detection(self) -> None:
        events = [failed_login(i * 30) for i in range(4)]  # eşik 5 → altında
        run = CorrelationEngine().evaluate(events, [burst_rule()])
        assert run.detections == []

    def test_window_boundary_inclusive(self) -> None:
        # 5. olay tam pencere sınırında (300s) → dahil (<= sözleşmesi)
        events = [failed_login(i * 75) for i in range(5)]  # 0,75,150,225,300
        run = CorrelationEngine().evaluate(events, [burst_rule()])
        assert len(run.detections) == 1
        assert run.detections[0].event_count == 5

    def test_event_outside_window_breaks_cluster(self) -> None:
        # 4 olay 100 sn arayla (0..300), 5. olay 400 sn → pencere dışı kalır
        events = [failed_login(i * 100) for i in range(5)]
        run = CorrelationEngine().evaluate(events, [burst_rule()])
        # Kayan pencere: [0..300) 4 olay → eşik altı; [100..400] 4 olay → altı...
        # Yalnızca 100..400 aralığı 4 olay içerir; hiçbir küme 5'e ulaşmaz.
        assert run.detections == []

    def test_two_agents_same_window_two_detections(self) -> None:
        events = [failed_login(i * 30, agent_id="001") for i in range(5)]
        events += [failed_login(i * 30, agent_id="002", agent_name="db-01") for i in range(5)]
        run = CorrelationEngine().evaluate(events, [burst_rule()])
        assert len(run.detections) == 2  # farklı sunuculardaki benzer olay BİRLEŞMEZ
        group_values = {d.evidence["group_value"]["agent_id"] for d in run.detections}
        assert group_values == {"001", "002"}
        for detection in run.detections:
            assert detection.event_count == 5

    def test_out_of_order_input_same_result(self) -> None:
        ordered = [failed_login(i * 30) for i in range(5)]
        shuffled = [ordered[i] for i in (3, 0, 4, 1, 2)]
        run_ordered = CorrelationEngine().evaluate(ordered, [burst_rule()])
        run_shuffled = CorrelationEngine().evaluate(shuffled, [burst_rule()])
        assert len(run_ordered.detections) == 1
        assert len(run_shuffled.detections) == 1
        a, b = run_ordered.detections[0], run_shuffled.detections[0]
        assert a.dedup_key == b.dedup_key  # zaman sırası bozuk olsa da aynı tespit
        assert a.window_start == b.window_start
        assert a.event_ids == b.event_ids

    def test_overlapping_clusters_do_not_duplicate(self) -> None:
        # İki ayrı burst (0..120s ve 400..520s): kayan pencere küme 1'i
        # emit ettikten sonra gösterici kümenin sonuna atlar → aynı olaylar
        # ikinci kez raporlanmaz; toplam 2 tespit, her biri 5 olay.
        events = [failed_login(i * 30) for i in range(5)]
        events += [failed_login(400 + i * 30) for i in range(5)]
        run = CorrelationEngine().evaluate(events, [burst_rule()])
        assert len(run.detections) == 2
        assert all(d.event_count == 5 for d in run.detections)
        assert len({d.dedup_key for d in run.detections}) == 2
        # Üst üste binme yok: her event tam bir tespitte görünür.
        all_linked = [eid for d in run.detections for eid in d.event_ids]
        assert len(all_linked) == len(set(all_linked))

    def test_missing_group_field_skipped_not_grouped(self) -> None:
        # agent_id eksik: None==None sahte gruplaşması YASAK
        events = [failed_login(i * 30, agent_id=None) for i in range(6)]
        run = CorrelationEngine().evaluate(events, [burst_rule()])
        assert run.detections == []
        assert run.skipped_missing_group == 6

    def test_rule_groups_filter_excludes_other_events(self) -> None:
        events = [failed_login(i * 30) for i in range(5)]
        noise = [
            failed_login(
                i * 30,
                rule_id="31151",
                rule_groups=["syslog", "authentication_success"],
                rule_level=3,
            )
            for i in range(5)
        ]
        run = CorrelationEngine().evaluate(events + noise, [burst_rule()])
        assert len(run.detections) == 1
        assert run.detections[0].event_count == 5

    def test_rule_ids_filter(self) -> None:
        rule = burst_rule(
            params=CorrelationParams(
                kind="burst",
                window_seconds=300.0,
                threshold=3,
                group_by=["agent_id"],
                match_rule_ids=["5710"],
            )
        )
        events = [failed_login(i * 30) for i in range(3)]
        other = [failed_login(300 + i, rule_id="9999") for i in range(3)]
        run = CorrelationEngine().evaluate(events + other, [rule])
        assert len(run.detections) == 1
        assert run.detections[0].event_count == 3

    def test_min_level_filter(self) -> None:
        rule = burst_rule(
            params=CorrelationParams(
                kind="burst",
                window_seconds=300.0,
                threshold=3,
                group_by=["agent_id"],
                match_rule_groups=["authentication_failed"],
                match_min_level=10,
            )
        )
        events = [failed_login(i * 30) for i in range(3)]
        low = [failed_login(300 + i, rule_level=5) for i in range(3)]
        run = CorrelationEngine().evaluate(events + low, [rule])
        assert len(run.detections) == 1
        assert run.detections[0].event_count == 3


class TestRepeatedAlertRule:
    def test_same_agent_same_rule_three_times(self) -> None:
        events = [failed_login(i * 60) for i in range(3)]
        run = CorrelationEngine().evaluate(events, [repeated_rule()])
        assert len(run.detections) == 1
        assert run.detections[0].evidence["group_value"] == {
            "agent_id": "001",
            "rule_id": "5710",
        }

    def test_different_rules_same_agent_separate(self) -> None:
        events = [failed_login(i * 60) for i in range(3)]
        events += [
            failed_login(i * 60, rule_id="31151", rule_groups=["authentication_failed"])
            for i in range(3)
        ]
        run = CorrelationEngine().evaluate(events, [repeated_rule()])
        assert len(run.detections) == 2  # (agent, rule) çiftine göre grup

    def test_different_agents_same_rule_separate(self) -> None:
        events = [failed_login(i * 60, agent_id="001") for i in range(3)]
        events += [failed_login(i * 60, agent_id="002") for i in range(3)]
        run = CorrelationEngine().evaluate(events, [repeated_rule()])
        assert len(run.detections) == 2


class TestSequenceRule:
    def test_login_then_change_within_window(self) -> None:
        login = make_event(
            rule_id="5715",
            rule_groups=["syslog", "sshd", "authentication_success"],
            rule_level=3,
            rule_description="sshd: authentication success",
        )
        change = make_event(
            timestamp=BASE_TS + timedelta(seconds=120),
            rule_id="554",
            rule_groups=["adduser", "system_audit"],
            rule_level=8,
            rule_description="User added to system",
        )
        run = CorrelationEngine().evaluate([change, login], [sequence_rule()])
        assert len(run.detections) == 1
        detection = run.detections[0]
        assert detection.event_count == 2
        assert detection.window_start == login.timestamp
        assert detection.evidence["first_alert_ids"] == [login.alert_id]
        assert detection.evidence["then_alert_ids"] == [change.alert_id]
        assert detection.max_rule_level == 8  # ORİJİNAL seviyelerin maksimumu

    def test_change_before_login_no_detection(self) -> None:
        login = make_event(
            rule_id="5715",
            rule_groups=["authentication_success"],
            rule_level=3,
        )
        change = make_event(
            timestamp=BASE_TS - timedelta(seconds=60),
            rule_id="554",
            rule_groups=["adduser"],
            rule_level=8,
        )
        run = CorrelationEngine().evaluate([login, change], [sequence_rule()])
        assert run.detections == []

    def test_change_after_window_no_detection(self) -> None:
        login = make_event(
            rule_id="5715",
            rule_groups=["authentication_success"],
            rule_level=3,
        )
        change = make_event(
            timestamp=BASE_TS + timedelta(seconds=601),
            rule_id="554",
            rule_groups=["adduser"],
            rule_level=8,
        )
        run = CorrelationEngine().evaluate([login, change], [sequence_rule()])
        assert run.detections == []

    def test_change_on_other_agent_no_detection(self) -> None:
        login = make_event(
            rule_id="5715",
            rule_groups=["authentication_success"],
            rule_level=3,
        )
        change = make_event(
            timestamp=BASE_TS + timedelta(seconds=60),
            rule_id="554",
            rule_groups=["adduser"],
            rule_level=8,
            agent_id="002",
            agent_name="db-01",
        )
        run = CorrelationEngine().evaluate([login, change], [sequence_rule()])
        assert run.detections == []

    def test_two_logins_one_change_single_pair(self) -> None:
        logins = [
            make_event(
                rule_id="5715",
                rule_groups=["authentication_success"],
                rule_level=3,
                timestamp=BASE_TS + timedelta(seconds=i * 10),
            )
            for i in range(2)
        ]
        change = make_event(
            timestamp=BASE_TS + timedelta(seconds=30),
            rule_id="554",
            rule_groups=["adduser"],
            rule_level=8,
        )
        run = CorrelationEngine().evaluate([*logins, change], [sequence_rule()])
        assert len(run.detections) == 1  # tek değişiklik tek çift; çoğaltılmaz
        assert run.detections[0].evidence["first_alert_ids"] == [logins[0].alert_id]

    def test_two_changes_two_logins_two_pairs(self) -> None:
        logins = [
            make_event(
                rule_id="5715",
                rule_groups=["authentication_success"],
                rule_level=3,
                timestamp=BASE_TS + timedelta(seconds=i * 100),
            )
            for i in range(2)
        ]
        changes = [
            make_event(
                timestamp=BASE_TS + timedelta(seconds=50 + i * 100),
                rule_id="554",
                rule_groups=["adduser"],
                rule_level=8,
            )
            for i in range(2)
        ]
        run = CorrelationEngine().evaluate([*logins, *changes], [sequence_rule()])
        assert len(run.detections) == 2

    def test_missing_agent_fields_skipped(self) -> None:
        login = make_event(
            rule_id="5715",
            rule_groups=["authentication_success"],
            rule_level=3,
            agent_id=None,
        )
        change = make_event(
            timestamp=BASE_TS + timedelta(seconds=60),
            rule_id="554",
            rule_groups=["adduser"],
            rule_level=8,
            agent_id=None,
        )
        run = CorrelationEngine().evaluate([login, change], [sequence_rule()])
        assert run.detections == []
        assert run.skipped_missing_group == 2


class TestEngineGeneral:
    def test_disabled_rules_not_passed_by_caller_contract(self) -> None:
        # Motor, kendisine verilen kuralları çalıştırır; enabled filtresi
        # çağıranın (döngünün DB okumasının) sorumluluğudur — burada yalnızca
        # boş kural listesinin boş sonuç verdiği doğrulanır.
        events = [failed_login(i * 30) for i in range(5)]
        run = CorrelationEngine().evaluate(events, [])
        assert run.detections == []
        assert run.rules_evaluated == 0

    def test_detections_sorted_by_rule_key(self) -> None:
        events = [failed_login(i * 30) for i in range(5)]
        run = CorrelationEngine().evaluate(events, [burst_rule(), repeated_rule()])
        keys = [d.rule_key for d in run.detections]
        assert keys == sorted(keys)

    def test_latency_seconds_monotonic(self) -> None:
        events = [failed_login(i * 30) for i in range(5)]
        run = CorrelationEngine().evaluate(events, [burst_rule()])
        detection = run.detections[0]
        later = BASE_TS + timedelta(seconds=130)
        assert detection.latency_seconds(now=later) > 0
        assert detection.latency_seconds(now=BASE_TS) == 0  # geleceğe negatif yok
