"""EventAnalyzer — Ollama/Qwen3 4B analiz motoru (Faz 04).

Gereksinimler (phases/04, AGENTS.md §5, §8):
- Timeout: her üretim denemesi asyncio.timeout ile sınırlıdır; istemci
  httpx zaman aşımı ikinci savunma hattıdır.
- Sınırlı retry: retryable hatalarda (aktarım + model çıktı) üstel backoff
  ile en fazla analysis_max_retries kadar TEKRAR (ilk çağrı + max_retries).
  Deneme dışına çıkılmaz.
- Cancellation: dışarıdan task.cancel() gelirse CancelledError sızdırılır
  (yutulmaz); temiz iptal mümkündür.
- Concurrency sınırı: asyncio.Semaphore(worker_concurrency) — CPU modunda
  tek modeli aşırı yüklememek için.
- Geçersiz çıktı için güvenli fallback: model çıktısı sınırlı tekrara
  rağmen geçersizse AnalysisOutcome.failed (analysis_failed) döndürülür —
  HATA YÜKSELTİLMEZ. Altyapı hatalarında ise hata yükseltilir ve döngü
  durur (satır yazılmaz); iki ailenin ayrımı errors.py'de belgelenmiştir.
- "Orijinal Wazuh severity değiştirilmesin": analyzer events verisini
  YALNIZCA okur; ModelAnalysis içinde severity alanı bile yoktur.
- "Başlangıçta sadece analiz; tool calling/shell execution yok": istemci
  yalnızca /api/generate çağırır; çıktı yalnızca veridir, yürütme yolu
  yoktur (recommended_next_steps enum whitelist — models.py).

Ölçülebilirlik (AGENTS.md §7): her sonuç, süre/retries/prompt boyutu
metadata'sı taşır; AnalysisMetrics'e kaydedilir (geçerlilik oranı,
p50/p95 latency, hata oranı raporu Faz 09'a temel).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from app.services.analysis.client import OllamaClient
from app.services.analysis.errors import (
    OUTPUT_ERROR_SCHEMA_VIOLATION,
    AnalysisOutputError,
    OllamaError,
    OllamaUnavailableError,
)
from app.services.analysis.models import ModelAnalysis, parse_model_analysis
from app.services.analysis.prompt import (
    PROMPT_TEMPLATE_VERSION,
    AnalysisContext,
    BuiltPrompt,
    build_analysis_prompt,
)

AsyncSleep = Callable[[float], Awaitable[None]]


async def _default_sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


@dataclass(frozen=True)
class AnalysisMetadata:
    """Her analiz denemesinin izlenebilirlik künyesi (AGENTS.md §5, §6)."""

    model_tag: str
    model_quantization: str
    prompt_template_version: str
    prompt_chars: int
    context_chars: int
    context_truncated: bool
    duration_ms: int  # son denemenin süresi (toplam değil; bilinçli seçim)
    retries_used: int  # ekstra deneme sayısı (0 = ilk denemede tamam)
    finished_at: datetime


@dataclass(frozen=True)
class AnalysisOutcome:
    """Tek event'in analiz sonucu — YA completed YA analysis_failed.

    status="analysis_failed" güvenli fallback'tir: model çıktısı doğrulanamadı;
    analyses tablosuna bu durumla YAZILIR (AGENTS.md §5) ve panelde
    gösterilir (Faz 05). Hata mesajı yapısal bilgidir; log içeriği/credential
    taşımaz.
    """

    event_id: str  # analiz edilen olay (analyses.event_id FK)
    status: str  # "completed" | "analysis_failed"
    analysis: ModelAnalysis | None
    error_code: str | None
    error_message: str | None
    metadata: AnalysisMetadata

    @classmethod
    def completed(
        cls,
        event_id: str,
        analysis: ModelAnalysis,
        metadata: AnalysisMetadata,
    ) -> AnalysisOutcome:
        return cls(
            event_id=event_id,
            status="completed",
            analysis=analysis,
            error_code=None,
            error_message=None,
            metadata=metadata,
        )

    @classmethod
    def failed(
        cls, event_id: str, error_code: str, error_message: str, metadata: AnalysisMetadata
    ) -> AnalysisOutcome:
        return cls(
            event_id=event_id,
            status="analysis_failed",
            analysis=None,
            error_code=error_code,
            error_message=error_message,
            metadata=metadata,
        )


class EventAnalyzer:
    """Ollama modeli üzerinden tek event analizi yapar (kullanım: worker döngüsü)."""

    def __init__(
        self,
        client: OllamaClient,
        *,
        model_tag: str,
        model_quantization: str,
        temperature: float,
        num_predict: int,
        timeout_seconds: float,
        max_retries: int,
        backoff_base_seconds: float,
        max_context_chars: int,
        max_output_chars: int,
        concurrency: int,
        sleep: AsyncSleep | None = None,
    ) -> None:
        if concurrency < 1:
            raise ValueError("concurrency en az 1 olmalıdır.")
        if max_retries < 0:
            raise ValueError("max_retries negatif olamaz.")
        self._client = client
        self._model_tag = model_tag
        self._model_quantization = model_quantization
        self._temperature = temperature
        self._num_predict = num_predict
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._backoff_base = backoff_base_seconds
        self._max_context_chars = max_context_chars
        self._max_output_chars = max_output_chars
        self._semaphore = asyncio.Semaphore(concurrency)
        self._sleep: AsyncSleep = sleep or _default_sleep

    async def analyze(self, context: AnalysisContext) -> AnalysisOutcome:
        """Tek olayı analiz eder.

        - Altyapı hatası (retry tükendi) → AnalysisError YÜKSELİR; döngü
          durur, analyses tablosuna satır YAZILMAZ.
        - Model çıktısı geçersiz (retry tükendi) → analysis_failed OUTCOME
          döner (güvenli fallback, AGENTS.md §5).
        - Dış iptal → CancelledError aynen yükselir.
        """
        async with self._semaphore:
            return await self._analyze_with_retry(context)

    async def _analyze_with_retry(self, context: AnalysisContext) -> AnalysisOutcome:
        prompt = build_analysis_prompt(context, max_log_chars=self._max_context_chars)
        prompt_chars = len(prompt.system) + len(prompt.user)

        for attempt in range(self._max_retries + 1):
            started = time.monotonic()
            try:
                raw = await self._generate_with_timeout(prompt.system, prompt.user)
            except OllamaError as exc:
                # Aktarım ailesi: retryable ise sınırlı tekrar; tükenirse YÜKSELT
                # (döngü durur, satır YAZILMAZ — errors.py kuralı).
                if exc.retryable and attempt < self._max_retries:
                    await self._sleep(self._backoff_seconds(attempt))
                    continue
                raise
            duration_ms = int((time.monotonic() - started) * 1000)

            try:
                analysis = parse_model_analysis(raw, max_chars=self._max_output_chars)
                self._check_traceability(analysis, context)
            except AnalysisOutputError as exc:
                # Model ÇIKTI ailesi: sınırlı tekrar; tükenirse güvenli fallback.
                if attempt < self._max_retries:
                    await self._sleep(self._backoff_seconds(attempt))
                    continue
                return AnalysisOutcome.failed(
                    context.event_id,
                    error_code=exc.error_code,
                    error_message=exc.message,
                    metadata=self._metadata(prompt, prompt_chars, duration_ms, attempt),
                )

            metadata = self._metadata(prompt, prompt_chars, duration_ms, attempt)
            return AnalysisOutcome.completed(context.event_id, analysis, metadata)

        # Döngü garantisi: her yol ya döndürür ya yükseltir.
        raise AssertionError("erişilemez")  # pragma: no cover  # noqa: S101

    @staticmethod
    def _check_traceability(analysis: ModelAnalysis, context: AnalysisContext) -> None:
        """İzlenebilirlik zoru (AGENTS.md §5): sonucun ilişkilendirildiği
        alert ID'ler analiz edilen olayı KAPSAMALIDIR. Uyuşmazlık şema
        ihlalidir → retry → analysis_failed."""
        if context.alert_id not in analysis.alert_ids:
            raise AnalysisOutputError(
                "Model çıktısındaki alert_ids analiz edilen olayı içermiyor "
                "(izlenebilirlik ihlali).",
                error_code=OUTPUT_ERROR_SCHEMA_VIOLATION,
            )

    async def _generate_with_timeout(self, system: str, user: str) -> str:
        """Tek üretim denemesi; süre aşımı retryable OllamaUnavailableError'a
        çevrilir.

        Dış iptal (task.cancel) bilinçli olarak YUTULMAZ: asyncio.timeout
        yalnızca kendi deadline'ı aşılırsa TimeoutError üretir; dışarıdan
        gelen CancelledError olduğu gibi yükselir (cancellation testi).
        """
        try:
            async with asyncio.timeout(self._timeout_seconds):
                return await self._client.generate(
                    system_prompt=system,
                    user_prompt=user,
                    model_tag=self._model_tag,
                    temperature=self._temperature,
                    num_predict=self._num_predict,
                    timeout_seconds=self._timeout_seconds,
                )
        except TimeoutError as exc:
            raise OllamaUnavailableError(
                f"Analiz denemesi {self._timeout_seconds}s zaman aşımına uğradı."
            ) from exc

    def _backoff_seconds(self, attempt: int) -> float:
        # Üstel backoff (jitter'sız; test determinizmi için — Faz 02'den farkı dokümante)
        return self._backoff_base * (2**attempt)

    def _metadata(
        self, prompt: BuiltPrompt, prompt_chars: int, duration_ms: int, attempt: int
    ) -> AnalysisMetadata:
        return AnalysisMetadata(
            model_tag=self._model_tag,
            model_quantization=self._model_quantization,
            prompt_template_version=PROMPT_TEMPLATE_VERSION,
            prompt_chars=prompt_chars,
            context_chars=prompt.context_chars,
            context_truncated=prompt.truncated,
            duration_ms=duration_ms,
            retries_used=attempt,
            finished_at=datetime.now(UTC),
        )


__all__ = [
    "AnalysisMetadata",
    "AnalysisOutcome",
    "EventAnalyzer",
]
