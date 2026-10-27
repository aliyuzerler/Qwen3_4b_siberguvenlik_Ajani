"""Benchmark koşum orkestrasyonu (Faz 09) — provenance + CSV/JSON çıktı.

Doğrulama promptu gereksinimleri:
- "Benchmark'ı sabit sürümde çalıştır ve sonuçları CSV/JSON olarak kaydet"
  → her koşum kendi klasörüne report.json + metrics.csv + predictions.jsonl
  yazar.
- "Seed, model tag/quantization, prompt sürümü, dataset sürümü ve donanımı
  raporla" → RunProvenance bu künyenin TAMAMINI taşır (dataset sha256,
  git commit, python/platform/RSS dahil).
- "Etiketler eksik veya veri sızıntısı varsa sonucu geçerli ilan etme"
  → runner'a dataset yalnızca load_dataset doğrulamasından geçerek girer;
  --splits verilmişse check_split_leakage da zorunludur.

Koşum determinizmi: kayıt sırası record_id'ye göre sabittir; seed
provenance'a yazılır (gelecekteki stokastik bileşenler için künye
sözleşmesi). LLM baselines'da tek deneme ölçülür (retry yok — latency
temizliği; sapma docs'ta belgeli).

Bellek: koşum süreci ru_maxrss (KB) başlangıç/bitiş; gerçek model belleği
yalnızca kullanıcı makinesinde `ollama ps` ile ölçülebilir (CLI --probe-
ollama-ps; sandbox'ta None).
"""

from __future__ import annotations

import asyncio
import csv
import json
import platform
import resource
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.services.analysis.client import OllamaClient
from app.services.analysis.errors import OllamaError
from app.services.analysis.prompt import build_context_payload
from benchmarks.baselines import (
    BASELINE_QWEN_PROMPT_ONLY,
    BASELINE_RULES_CORR_QWEN,
    BASELINE_RULES_ONLY,
    BASELINE_VERSIONS,
    LlmBaseline,
    RulesOnlyBaseline,
    context_from_record,
)
from benchmarks.dataset import BenchmarkDataset, BenchmarkRecord, check_split_leakage
from benchmarks.metrics import (
    RecordEvaluation,
    compute_metrics,
    count_unsupported_anchors,
    ground_value,
)
from benchmarks.mock_client import MockOllamaClient

BASELINES: tuple[str, ...] = (
    BASELINE_RULES_ONLY,
    BASELINE_QWEN_PROMPT_ONLY,
    BASELINE_RULES_CORR_QWEN,
)

RUN_STATUS_COMPLETED = "completed"
RUN_STATUS_ABORTED = "aborted_infrastructure"


@dataclass(frozen=True)
class LlmRunConfig:
    """LLM baseline koşum parametreleri (CLI'dan gelir)."""

    provider: str  # "mock" | "ollama"
    base_url: str = "http://127.0.0.1:11434"
    model_tag: str = "qwen3:4b"
    quantization: str | None = None
    temperature: float = 0.2
    num_predict: int = 512
    timeout_seconds: float = 120.0
    max_context_chars: int = 4000
    max_output_chars: int = 6000


@dataclass(frozen=True)
class RunResult:
    """Tek koşumun çıktısı."""

    run_id: str
    run_dir: Path
    status: str
    report: dict[str, Any]


def _git_commit() -> str | None:
    """Kısa commit hash'i (backend kökü = repo alt dizini)."""
    try:
        result = subprocess.run(  # noqa: S603 — sabit argüman, kullanıcı girdisi yok
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (result.stdout or "").strip()
    return output or None


def _total_ram_kb() -> int | None:
    """/proc/meminfo MemTotal (Linux dışında None)."""
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                fields = line.split()
                return int(fields[1])
    except OSError:
        return None
    return None


def _peak_rss_kb() -> int:
    """Sürecin tepe RSS'i (KB; Linux)."""
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


def _probe_ollama_ps() -> dict[str, Any] | None:
    """`ollama ps --json` çıktısından model belleği (varsa).

    Sandbox'ta ollama yoktur → None. Başarısızlık sessiz None'dır: bellek
    ölçümü opsiyoneldir ve kullanıcı makinesi dokümantasyonunda ayrıca
    anlatılır.
    """
    try:
        result = subprocess.run(  # noqa: S603 — sabit argüman, kullanıcı girdisi yok
            ["ollama", "ps", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        entries = json.loads(result.stdout or "[]")
    except ValueError:
        return None
    if not isinstance(entries, list):
        return None
    return {
        "models": [
            {
                "name": entry.get("name"),
                "size_bytes": entry.get("size"),
                "size_vram_bytes": entry.get("size_vram"),
            }
            for entry in entries
            if isinstance(entry, dict)
        ]
    }


def _build_client(config: LlmRunConfig) -> OllamaClient:
    """Provider'a göre istemci üretir (mock yalnızca doğrulama içindir)."""
    if config.provider == "mock":
        return MockOllamaClient()
    from app.services.analysis.client import build_ollama_client

    return build_ollama_client(config.base_url, timeout_seconds=config.timeout_seconds)


def _evidence_and_claims(
    prediction: Any, context_json: str, leaf_values: frozenset[str]
) -> tuple[int, int, int, int]:
    """(evidence_total, evidence_grounded, anchors_total, anchors_unsupported)."""
    analysis = prediction.analysis
    if analysis is None:
        return 0, 0, 0, 0

    evidence_total = 0
    evidence_grounded = 0
    claims: list[str] = [analysis.summary, *analysis.alternative_explanations]
    for item in analysis.evidence:
        evidence_total += 1
        if ground_value(item.value, context_json, leaf_values):
            evidence_grounded += 1
        claims.append(item.value)

    anchors_total, anchors_unsupported = count_unsupported_anchors(claims, context_json)
    return evidence_total, evidence_grounded, anchors_total, anchors_unsupported


async def run_benchmark(
    *,
    baseline: str,
    dataset: BenchmarkDataset,
    llm: LlmRunConfig,
    seed: int,
    out_dir: Path,
    splits: dict[str, list[str]] | None = None,
    limit: int | None = None,
    probe_ollama_ps: bool = False,
) -> RunResult:
    """Tek baseline'ın tam koşumu: tahmin → skor → rapor dosyaları.

    Altyapı hatası (OllamaError): koşum ABORT olur, bugüne kadarki
    tahminler + aborted raporu YAZILIR ve RunResult.status ile bildirilir
    (CLI çıkış kodu 3). Kısmi sonuçlar 'geçerli koşum' SAYILMAZ.
    """
    if baseline not in BASELINES:
        raise ValueError(f"Bilinmeyen baseline: {baseline} (geçerliler: {BASELINES})")
    if splits is not None:
        check_split_leakage(dataset.records, splits)

    records: tuple[BenchmarkRecord, ...] = dataset.records
    if limit is not None and limit > 0:
        records = records[:limit]

    started_at = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{baseline}-{dataset.version}-{started_at}-{uuid.uuid4().hex[:6]}"
    run_dir = out_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    rss_start = _peak_rss_kb()
    monotonic_start = time.monotonic()

    predictor: RulesOnlyBaseline | LlmBaseline
    if baseline == BASELINE_RULES_ONLY:
        predictor = RulesOnlyBaseline()
    else:
        predictor = LlmBaseline(
            _build_client(llm),
            include_correlation=(baseline == BASELINE_RULES_CORR_QWEN),
            model_tag=llm.model_tag,
            temperature=llm.temperature,
            num_predict=llm.num_predict,
            timeout_seconds=llm.timeout_seconds,
            max_context_chars=llm.max_context_chars,
            max_output_chars=llm.max_output_chars,
        )

    evaluations: dict[str, RecordEvaluation] = {}
    prediction_rows: list[dict[str, Any]] = []
    status = RUN_STATUS_COMPLETED
    abort_error: str | None = None

    for record in records:
        context = context_from_record(record)
        context_json, truncated = build_context_payload(
            context, max_log_chars=llm.max_context_chars
        )
        leaf_values = _leaf_values_cached(context_json)
        started = time.perf_counter()
        try:
            prediction = await predictor.predict(record)
        except OllamaError as exc:
            status = RUN_STATUS_ABORTED
            abort_error = exc.message
            break
        duration_ms = int((time.perf_counter() - started) * 1000)

        ev_total, ev_grounded, anchors_total, anchors_unsupported = _evidence_and_claims(
            prediction, context_json, leaf_values
        )
        raw_output = prediction.raw_output or ""
        marker = record.injection_marker
        marker_in_output = bool(marker and marker in raw_output)

        evaluation = RecordEvaluation(
            record_id=record.record_id,
            family=record.family,
            split_group=record.split_group,
            expected_assessment=record.expected_assessment,
            is_injection=record.is_injection,
            is_benign_maintenance=record.is_benign_maintenance,
            predicted_assessment=(
                prediction.analysis.assessment.value
                if prediction.analysis is not None
                else None
            ),
            schema_valid=prediction.schema_valid,
            error_code=prediction.error_code,
            confidence=(
                prediction.analysis.confidence if prediction.analysis is not None else None
            ),
            evidence_total=ev_total,
            evidence_grounded=ev_grounded,
            anchors_total=anchors_total,
            anchors_unsupported=anchors_unsupported,
            marker_in_output=marker_in_output,
            duration_ms=duration_ms,
            prompt_chars=prediction.prompt_chars,
            context_truncated=truncated or prediction.context_truncated,
        )
        evaluations[record.record_id] = evaluation
        prediction_rows.append(_prediction_row(record, evaluation, raw_output))

    report = _build_report(
        baseline=baseline,
        dataset=dataset,
        llm=llm,
        seed=seed,
        records=records,
        evaluations=evaluations,
        run_id=run_id,
        status=status,
        abort_error=abort_error,
        rss_start=rss_start,
        elapsed_s=time.monotonic() - monotonic_start,
        probe=(_probe_ollama_ps() if probe_ollama_ps else None),
    )

    _write_outputs(run_dir=run_dir, report=report, prediction_rows=prediction_rows)
    return RunResult(run_id=run_id, run_dir=run_dir, status=status, report=report)


_LEAF_CACHE: dict[str, frozenset[str]] = {}


def _leaf_values_cached(context_json: str) -> frozenset[str]:
    """Bağlam → yaprak değer kümesi (koşum içi küçük önbellek)."""
    cached = _LEAF_CACHE.get(context_json)
    if cached is None:
        from benchmarks.metrics import _leaf_values_from_context

        cached = _leaf_values_from_context(context_json)
        _LEAF_CACHE[context_json] = cached
    return cached


def _prediction_row(
    record: BenchmarkRecord,
    evaluation: RecordEvaluation,
    raw_output: str,
) -> dict[str, Any]:
    del raw_output  # ham model çıktısı diske YAZILMAZ (log hijyeni, AGENTS.md §6)
    return {
        "record_id": evaluation.record_id,
        "family": evaluation.family,
        "split_group": evaluation.split_group,
        "expected_assessment": evaluation.expected_assessment,
        "predicted_assessment": evaluation.predicted_assessment,
        "schema_valid": evaluation.schema_valid,
        "error_code": evaluation.error_code,
        "confidence": evaluation.confidence,
        "evidence_total": evaluation.evidence_total,
        "evidence_grounded": evaluation.evidence_grounded,
        "anchors_total": evaluation.anchors_total,
        "anchors_unsupported": evaluation.anchors_unsupported,
        "marker_in_output": evaluation.marker_in_output,
        "injection_resilient": evaluation.injection_resilient,
        "duration_ms": evaluation.duration_ms,
        "prompt_chars": evaluation.prompt_chars,
        "context_truncated": evaluation.context_truncated,
    }


def _build_report(
    *,
    baseline: str,
    dataset: BenchmarkDataset,
    llm: LlmRunConfig,
    seed: int,
    records: tuple[BenchmarkRecord, ...],
    evaluations: dict[str, RecordEvaluation],
    run_id: str,
    status: str,
    abort_error: str | None,
    rss_start: int,
    elapsed_s: float,
    probe: dict[str, Any] | None,
) -> dict[str, Any]:
    is_llm = baseline in (BASELINE_QWEN_PROMPT_ONLY, BASELINE_RULES_CORR_QWEN)
    effective_provider = llm.provider if is_llm else "none"
    metrics = compute_metrics(records, evaluations)
    rss_end = _peak_rss_kb()
    report: dict[str, Any] = {
        "run_id": run_id,
        "run_status": status,
        "abort_error": abort_error,
        "baseline": baseline,
        "baseline_version": BASELINE_VERSIONS[baseline],
        "results_valid_as_model_evidence": effective_provider != "mock",
        "results_interpretation": _interpretation(effective_provider),
        "provenance": {
            "seed": seed,
            "llm_provider": effective_provider,
            "model_tag": llm.model_tag if is_llm else None,
            "model_quantization": llm.quantization if is_llm else None,
            "prompt_template_version": BASELINE_VERSIONS[baseline],
            "generation_config": (
                {
                    "temperature": llm.temperature,
                    "num_predict": llm.num_predict,
                    "timeout_seconds": llm.timeout_seconds,
                    "max_context_chars": llm.max_context_chars,
                    "max_output_chars": llm.max_output_chars,
                }
                if is_llm
                else None
            ),
            "dataset_version": dataset.version,
            "dataset_sha256": dataset.sha256,
            "dataset_path": str(dataset.path),
            "records_requested": len(records),
            "records_evaluated": len(evaluations),
            "started_at_utc": run_id,
            "finished_at_utc": datetime.now(UTC).isoformat(),
            "git_commit": _git_commit(),
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
            "cpu_count": _cpu_count(),
            "total_ram_kb": _total_ram_kb(),
            "peak_rss_kb_start": rss_start,
            "peak_rss_kb_end": rss_end,
            "wall_seconds": round(elapsed_s, 3),
            "ollama_ps": probe,
        },
        "metrics": metrics.as_dict(),
    }
    return report


def _interpretation(provider: str) -> str:
    """Raporun yorum satırı (kötüye kullanım önleme: mock = kanıt değil)."""
    if provider == "mock":
        return (
            "MOCK istemci koşumu: yalnızca altyapı doğrulaması; model kalitesi "
            "kanıtı DEĞİLDİR (Faz 09 sözleşmesi)."
        )
    if provider == "none":
        return "Kural-eşiği baseline'ı deterministiktir; LLM kullanılmamıştır."
    return "Gerçek Ollama koşumu; fine-tuning karar girdisi."


def _cpu_count() -> int | None:
    import os

    return os.cpu_count()


def _flatten_metrics(prefix: str, value: Any, rows: list[tuple[str, Any]]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _flatten_metrics(f"{prefix}.{key}", item, rows)
    elif isinstance(value, list):
        rows.append((prefix, json.dumps(value, ensure_ascii=False)))
    else:
        rows.append((prefix, value))


def _write_outputs(
    *, run_dir: Path, report: dict[str, Any], prediction_rows: list[dict[str, Any]]
) -> None:
    (run_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with (run_dir / "metrics.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["metric", "value"])
        rows: list[tuple[str, Any]] = []
        _flatten_metrics("metrics", report["metrics"], rows)
        for metric, value in rows:
            writer.writerow([metric, value])
    with (run_dir / "predictions.jsonl").open("w", encoding="utf-8") as handle:
        for row in prediction_rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def run_benchmark_sync(**kwargs: Any) -> RunResult:
    """CLI için senkron sarmalayıcı."""
    return asyncio.run(run_benchmark(**kwargs))


__all__ = [
    "BASELINES",
    "LlmRunConfig",
    "RUN_STATUS_ABORTED",
    "RUN_STATUS_COMPLETED",
    "RunResult",
    "run_benchmark",
    "run_benchmark_sync",
]
