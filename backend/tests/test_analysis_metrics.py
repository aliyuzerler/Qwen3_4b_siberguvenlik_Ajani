"""AnalysisMetrics testleri (Faz 04 ölçüm kabulü).

"Başarıyı varsayma; ölçüm sonucu ver": schema geçerlilik oranı,
hata oranı, p50/p95 latency hesapları.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.services.analysis.metrics import AnalysisMetrics, _nearest_rank_percentile
from app.services.analysis.models import parse_model_analysis
from tests.conftest import make_valid_model_output
from tests.test_analysis_prompt import make_context

CONTEXT = make_context()


def _metadata(duration_ms: int, retries: int = 0):  # type: ignore[no-untyped-def]
    from app.services.analysis.analyzer import AnalysisMetadata

    return AnalysisMetadata(
        model_tag="qwen3:4b",
        model_quantization="Q4_K_M",
        prompt_template_version="v1",
        prompt_chars=100,
        context_chars=50,
        context_truncated=False,
        duration_ms=duration_ms,
        retries_used=retries,
        finished_at=datetime.now(UTC),
    )


def _completed(duration_ms: int):  # type: ignore[no-untyped-def]
    from app.services.analysis.analyzer import AnalysisOutcome

    analysis = parse_model_analysis(make_valid_model_output(CONTEXT.alert_id), max_chars=6000)
    return AnalysisOutcome.completed(CONTEXT.event_id, analysis, _metadata(duration_ms))


def _failed(duration_ms: int, retries: int = 1):  # type: ignore[no-untyped-def]
    from app.services.analysis.analyzer import AnalysisOutcome

    return AnalysisOutcome.failed(
        CONTEXT.event_id, "schema_violation", "şema ihlali", _metadata(duration_ms, retries)
    )


class TestPercentile:
    def test_nearest_rank_math(self) -> None:
        assert _nearest_rank_percentile([], 50) == 0
        assert _nearest_rank_percentile([10], 50) == 10
        assert _nearest_rank_percentile([10, 20, 30, 40], 50) == 20
        assert _nearest_rank_percentile([10, 20, 30, 40], 95) == 40
        assert _nearest_rank_percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95) == 10


class TestSnapshot:
    def test_empty_snapshot(self) -> None:
        snapshot = AnalysisMetrics().snapshot()
        assert snapshot.total == 0
        assert snapshot.schema_valid_rate == 0.0
        assert snapshot.error_rate == 0.0
        assert snapshot.p50_ms == 0 and snapshot.p95_ms == 0

    def test_validity_and_error_rate(self) -> None:
        metrics = AnalysisMetrics()
        metrics.record(_completed(100))
        metrics.record(_completed(200))
        metrics.record(_failed(300, retries=2))
        snapshot = metrics.snapshot()
        assert snapshot.total == 3
        assert snapshot.completed == 2 and snapshot.failed == 1
        assert abs(snapshot.schema_valid_rate - 2 / 3) < 1e-6
        assert abs(snapshot.error_rate - 1 / 3) < 1e-6
        assert snapshot.retries_total == 2

    def test_p50_p95_latency(self) -> None:
        metrics = AnalysisMetrics()
        for duration in [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]:
            metrics.record(_completed(duration))
        snapshot = metrics.snapshot()
        assert snapshot.p50_ms == 50
        assert snapshot.p95_ms == 100

    def test_as_dict_serializable(self) -> None:
        metrics = AnalysisMetrics()
        metrics.record(_completed(42))
        data = metrics.snapshot().as_dict()
        assert data["total"] == 1
        assert isinstance(data["p50_ms"], int)
