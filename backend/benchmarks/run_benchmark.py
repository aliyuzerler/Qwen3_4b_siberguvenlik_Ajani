"""Benchmark CLI (Faz 09).

Kullanım:
    # Dataset doğrulama (etiket/sızıntı/hassas veri denetimi — koşum öncesi zorunlu)
    python -m benchmarks.run_benchmark validate \
        --dataset benchmarks/datasets/holdout-v1.jsonl

    # rules_only (deterministik; sandbox'ta GERÇEK çalışır)
    python -m benchmarks.run_benchmark run --baseline rules_only \
        --dataset benchmarks/datasets/holdout-v1.jsonl --out benchmarks/results

    # LLM baseline'ları — sandbox'ta hat doğrulaması (mock; KANIT DEĞİL)
    python -m benchmarks.run_benchmark run --baseline qwen_prompt_only \
        --dataset benchmarks/datasets/holdout-v1.jsonl --out benchmarks/results --llm mock

    # LLM baseline'ları — kullanıcı makinesinde GERÇEK Ollama koşumu
    python -m benchmarks.run_benchmark run --baseline rules_corr_qwen \
        --dataset benchmarks/datasets/holdout-v1.jsonl --out benchmarks/results \
        --llm ollama --base-url http://127.0.0.1:11434 --probe-ollama-ps

    # Ollama sağlık/kurulu model yoklaması
    python -m benchmarks.run_benchmark check --model-tag qwen3:4b

Çıkış kodları: 0 başarı · 2 dataset geçersiz · 3 altyapı kesintisi
(aborted_infrastructure) · 1 beklenmedik hata/yanlış kullanım.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

from benchmarks.dataset import DatasetInvalidError, load_dataset, load_splits
from benchmarks.runner import BASELINES, LlmRunConfig, run_benchmark_sync

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DATASET_INVALID = 2
EXIT_ABORTED = 3


def _add_dataset_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--dataset",
        type=Path,
        required=True,
        help="Değerlendirme kümesi (JSONL) yolu",
    )
    parser.add_argument(
        "--splits",
        type=Path,
        default=None,
        help="Opsiyonel split tanımı (train/validation/test) — sızıntı denetimi",
    )


def _add_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--baseline",
        choices=list(BASELINES),
        required=True,
        help="Karşılaştırma kolu: rules_only | qwen_prompt_only | rules_corr_qwen",
    )
    parser.add_argument("--out", type=Path, required=True, help="Sonuç kök klasörü")
    parser.add_argument(
        "--llm",
        choices=["mock", "ollama"],
        default="mock",
        help="LLM baseline sağlayıcısı (rules_only için yok sayılır); "
        "mock çıktısı MODEL KANITI DEĞİLDİR",
    )
    parser.add_argument("--seed", type=int, default=42, help="Künyeye yazılan tohum")
    parser.add_argument(
        "--limit", type=int, default=None, help="Koşuma dahil edilecek ilk N kayıt (test)"
    )
    _add_llm_config_args(parser)


def _add_llm_config_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-url", default="http://127.0.0.1:11434", help="Ollama adresi")
    parser.add_argument("--model-tag", default="qwen3:4b", help="Model tag (sabit: qwen3:4b)")
    parser.add_argument("--quantization", default="Q4_K_M", help="Quantization künyesi")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--num-predict", type=int, default=512)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--max-context-chars", type=int, default=4000)
    parser.add_argument("--max-output-chars", type=int, default=6000)
    parser.add_argument(
        "--probe-ollama-ps",
        action="store_true",
        help="Koşum sonunda `ollama ps --json` ile model belleği kaydet",
    )


def _build_llm_config(args: argparse.Namespace) -> LlmRunConfig:
    return LlmRunConfig(
        provider=args.llm,
        base_url=args.base_url,
        model_tag=args.model_tag,
        quantization=args.quantization,
        temperature=args.temperature,
        num_predict=args.num_predict,
        timeout_seconds=args.timeout_seconds,
        max_context_chars=args.max_context_chars,
        max_output_chars=args.max_output_chars,
    )


def _load_validated(dataset_path: Path, splits_path: Path | None) -> Any:
    dataset = load_dataset(dataset_path)
    if splits_path is not None:
        check_with(dataset, load_splits(splits_path))
    return dataset


def check_with(dataset: Any, splits: dict[str, list[str]]) -> None:
    from benchmarks.dataset import check_split_leakage

    check_split_leakage(dataset.records, splits)


def cmd_validate(args: argparse.Namespace) -> int:
    dataset = load_dataset(args.dataset)
    if args.splits is not None:
        check_with(dataset, load_splits(args.splits))
    counts = {
        "total": len(dataset.records),
        "classification_cohort": len(dataset.classification_cohort),
        "injection_cohort": len(dataset.injection_cohort),
    }
    print("dataset GECERLI")
    print(f"surum: {dataset.version}")
    print(f"sha256: {dataset.sha256}")
    for key, value in counts.items():
        print(f"{key}: {value}")
    return EXIT_OK


def cmd_run(args: argparse.Namespace) -> int:
    dataset = load_dataset(args.dataset)
    if args.splits is not None:
        check_with(dataset, load_splits(args.splits))

    result = run_benchmark_sync(
        baseline=args.baseline,
        dataset=dataset,
        llm=_build_llm_config(args),
        seed=args.seed,
        out_dir=args.out,
        limit=args.limit,
        probe_ollama_ps=args.probe_ollama_ps,
    )
    metrics = result.report["metrics"]
    print(f"run_id: {result.run_id}")
    print(f"status: {result.status}")
    print(f"dir: {result.run_dir}")
    print(
        "schema_valid_rate={schema_valid_rate} macro_f1={macro_f1} "
        "fpr={fpr} fpr_maintenance={fpr_maintenance}".format(
            schema_valid_rate=metrics["totals"]["schema_valid_rate"],
            macro_f1=metrics["classification"]["macro_f1"],
            fpr=metrics["binary_alarm"]["fpr"],
            fpr_maintenance=metrics["benign_maintenance"]["fpr_maintenance"],
        )
    )
    print(
        "p50_ms={p50} p95_ms={p95} evidence_ok={evidence} injection={injection}".format(
            p50=metrics["latency"]["p50_ms"],
            p95=metrics["latency"]["p95_ms"],
            evidence=metrics["evidence"]["item_correctness_rate"],
            injection=metrics["injection_resilience"]["resilience_rate"],
        )
    )
    if not result.report["results_valid_as_model_evidence"]:
        print("UYARI: mock koşum — model kalitesi kanıtı DEĞİLDİR (altyapı doğrulaması).")
    if result.status == "aborted_infrastructure":
        print(f"HATA: koşum altyapı hatasıyla kesildi: {result.report['abort_error']}")
        return EXIT_ABORTED
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    from app.services.analysis.client import build_ollama_client
    from app.services.analysis.errors import AnalysisError

    async def _check() -> None:
        client = build_ollama_client(args.base_url, timeout_seconds=10.0)
        try:
            await client.check_health()
            print(f"ollama ERISILEBILIR: {args.base_url}")
            await client.ensure_model(args.model_tag)
            print(f"model KURULU: {args.model_tag}")
        finally:
            await client.aclose()

    try:
        asyncio.run(_check())
    except AnalysisError as exc:
        print(f"HATA: {exc.message}")
        return EXIT_ABORTED
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="benchmarks",
        description="Faz 09 model benchmark altyapısı",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Dataset doğrulama")
    _add_dataset_args(validate_parser)

    run_parser = subparsers.add_parser("run", help="Tek baseline koşumu")
    _add_dataset_args(run_parser)
    _add_run_args(run_parser)

    check_parser = subparsers.add_parser("check", help="Ollama sağlık/model yoklaması")
    check_parser.add_argument("--base-url", default="http://127.0.0.1:11434")
    check_parser.add_argument("--model-tag", default="qwen3:4b")

    args = parser.parse_args(argv)

    try:
        if args.command == "validate":
            return cmd_validate(args)
        if args.command == "run":
            return cmd_run(args)
        return cmd_check(args)
    except DatasetInvalidError as exc:
        print("DATASET GECERSIZ — koşum yapılmadı (phases/09 kuralı).")
        for error in exc.errors:
            print(f"  - {error}")
        return EXIT_DATASET_INVALID
    except KeyboardInterrupt:  # pragma: no cover
        print("İptal edildi.")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
