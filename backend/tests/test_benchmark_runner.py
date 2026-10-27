"""Faz 09 — runner uçtan uca testleri (mock yol + abort + CLI reddi).

Kapsam: çıktı dosyalarının oluşumu, provenance künyesi, limit koşumu,
mock sağlayıcının kanıt-değil işaretlemesi, altyapı kesintisinde kısmi
kayıt + aborted durumu, geçersiz dataset'te CLI red düzeyi.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from benchmarks.dataset import DatasetInvalidError, load_dataset
from benchmarks.run_benchmark import main as cli_main
from benchmarks.runner import (
    RUN_STATUS_ABORTED,
    LlmRunConfig,
    run_benchmark_sync,
)

DATASET_PATH = Path("benchmarks/datasets/holdout-v1.jsonl")


def _llm_config(provider: str = "mock", **overrides: Any) -> LlmRunConfig:
    values: dict[str, Any] = {
        "provider": provider,
        "base_url": "http://127.0.0.1:9",
        "model_tag": "qwen3:4b",
        "quantization": "Q4_K_M",
        "temperature": 0.2,
        "num_predict": 512,
        "timeout_seconds": 5.0,
        "max_context_chars": 4000,
        "max_output_chars": 6000,
    }
    values.update(overrides)
    return LlmRunConfig(**values)


def test_rules_only_end_to_end_outputs(tmp_path: Path) -> None:
    dataset = load_dataset(DATASET_PATH)
    result = run_benchmark_sync(
        baseline="rules_only",
        dataset=dataset,
        llm=_llm_config(),
        seed=42,
        out_dir=tmp_path,
        limit=6,
    )
    assert result.status == "completed"
    assert (result.run_dir / "report.json").is_file()
    assert (result.run_dir / "metrics.csv").is_file()
    assert (result.run_dir / "predictions.jsonl").is_file()

    report = json.loads((result.run_dir / "report.json").read_text(encoding="utf-8"))
    provenance = report["provenance"]
    # Doğrulama promptu künyesi: seed, dataset sürümü+sha, prompt sürümü
    assert provenance["seed"] == 42
    assert provenance["dataset_version"] == "holdout-v1"
    assert len(provenance["dataset_sha256"]) == 64
    assert provenance["prompt_template_version"] == "rules-only-v1"
    assert provenance["llm_provider"] == "none"
    assert provenance["model_tag"] is None
    assert provenance["platform"]
    assert provenance["python_version"]
    assert report["results_valid_as_model_evidence"] is True

    metrics = report["metrics"]
    assert metrics["totals"]["total_records"] == 6
    assert metrics["totals"]["evaluated_records"] == 6
    assert metrics["totals"]["schema_valid_rate"] == 1.0
    assert metrics["evidence"]["item_correctness_rate"] == 1.0

    # CSV: metric,value başlığı + satırlar
    csv_lines = (result.run_dir / "metrics.csv").read_text(encoding="utf-8").splitlines()
    assert csv_lines[0] == "metric,value"
    assert len(csv_lines) > 5

    # predictions.jsonl: satır başına kayıt
    prediction_text = (result.run_dir / "predictions.jsonl").read_text(encoding="utf-8")
    prediction_lines = prediction_text.splitlines()
    assert len(prediction_lines) == 6
    first = json.loads(prediction_lines[0])
    assert {"record_id", "expected_assessment", "predicted_assessment",
            "schema_valid"} <= set(first)


def test_mock_llm_run_marked_as_not_evidence(tmp_path: Path) -> None:
    dataset = load_dataset(DATASET_PATH)
    result = run_benchmark_sync(
        baseline="qwen_prompt_only",
        dataset=dataset,
        llm=_llm_config("mock"),
        seed=7,
        out_dir=tmp_path,
        limit=8,
    )
    report = result.report
    assert report["results_valid_as_model_evidence"] is False
    assert "MOCK" in report["results_interpretation"]
    assert report["provenance"]["model_tag"] == "qwen3:4b"
    assert report["provenance"]["generation_config"] is not None
    # Mock deterministik → tüm çıktılar şema geçerli
    assert report["metrics"]["totals"]["schema_valid_rate"] == 1.0
    # İlk 8 kayıtta injection kaydı yok
    assert report["metrics"]["injection_resilience"]["evaluated"] == 0


def test_mock_correlation_baseline_changes_outcome(tmp_path: Path) -> None:
    """Baseline C: korelasyon bloğu mock kararını değiştirir (hattın kanıtı)."""
    dataset = load_dataset(DATASET_PATH)
    result = run_benchmark_sync(
        baseline="rules_corr_qwen",
        dataset=dataset,
        llm=_llm_config("mock"),
        seed=7,
        out_dir=tmp_path,
    )
    metrics = result.report["metrics"]
    # backup repeated (L3, hit 6) benign→suspicious: maintenance FPR > 0 olmalı
    assert metrics["benign_maintenance"]["false_alarms"] >= 1
    assert metrics["totals"]["schema_valid_rate"] == 1.0
    # Injection kohortu tam koşumda ölçülür (mock marker yansıtmaz)
    assert metrics["injection_resilience"]["evaluated"] == 8
    assert metrics["injection_resilience"]["resilience_rate"] == 1.0


def test_infrastructure_abort_writes_partial_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.analysis.errors import OllamaUnavailableError

    def _failing_client(config: LlmRunConfig) -> Any:
        class _Client:
            async def generate(self, **kwargs: Any) -> str:
                del kwargs
                raise OllamaUnavailableError("bağlantı yok (test)")

            async def check_health(self) -> None:
                return None

            async def ensure_model(self, model_tag: str) -> None:
                del model_tag

            async def aclose(self) -> None:
                return None

        return _Client()

    monkeypatch.setattr("benchmarks.runner._build_client", _failing_client)
    dataset = load_dataset(DATASET_PATH)
    result = run_benchmark_sync(
        baseline="qwen_prompt_only",
        dataset=dataset,
        llm=_llm_config("ollama"),
        seed=1,
        out_dir=tmp_path,
    )
    assert result.status == RUN_STATUS_ABORTED
    report = json.loads((result.run_dir / "report.json").read_text(encoding="utf-8"))
    assert report["run_status"] == RUN_STATUS_ABORTED
    assert report["abort_error"] == "bağlantı yok (test)"
    assert report["metrics"]["totals"]["evaluated_records"] == 0


def test_cli_rejects_invalid_dataset(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"record_id": "x"}\n', encoding="utf-8")  # zorunlu alanlar eksik
    exit_code = cli_main(
        [
            "run",
            "--baseline",
            "rules_only",
            "--dataset",
            str(bad),
            "--out",
            str(tmp_path / "out"),
        ]
    )
    assert exit_code == 2
    assert "DATASET GECERSIZ" in capsys.readouterr().out
    with pytest.raises(DatasetInvalidError):
        load_dataset(bad)


def test_cli_validate_real_dataset(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli_main(["validate", "--dataset", str(DATASET_PATH)])
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "dataset GECERLI" in output
    assert "sha256:" in output


def test_unknown_baseline_rejected(tmp_path: Path) -> None:
    dataset = load_dataset(DATASET_PATH)
    with pytest.raises(ValueError):
        run_benchmark_sync(
            baseline="bilinmeyen",
            dataset=dataset,
            llm=_llm_config(),
            seed=1,
            out_dir=tmp_path / "unknown-baseline",
        )
