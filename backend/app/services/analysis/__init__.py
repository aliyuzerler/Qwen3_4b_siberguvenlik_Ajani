"""Analiz paketi (Faz 04) — Ollama/Qwen3 4B, katı şema, güvenli fallback.

Model erişim disiplini: yalnızca /api/generate + sağlık yoklamaları;
araç çağrısı/shell yok (phases/04). Mock istemci yalnızca testlerdedir —
config'te analiz için "mock modu" YOKTUR (sahte AI değerlendirmesi üretilemez).
"""

from __future__ import annotations

from app.services.analysis.analyzer import AnalysisMetadata, AnalysisOutcome, EventAnalyzer
from app.services.analysis.client import HttpOllamaClient, OllamaClient, build_ollama_client
from app.services.analysis.errors import (
    AnalysisError,
    AnalysisOutputError,
    OllamaBadPayloadError,
    OllamaError,
    OllamaModelMissingError,
    OllamaRequestError,
    OllamaUnavailableError,
)
from app.services.analysis.metrics import AnalysisMetrics, MetricsSnapshot
from app.services.analysis.models import Assessment, ModelAnalysis, RecommendedStep
from app.services.analysis.prompt import PROMPT_TEMPLATE_VERSION, AnalysisContext

__all__ = [
    "AnalysisContext",
    "AnalysisError",
    "AnalysisMetadata",
    "AnalysisMetrics",
    "AnalysisOutcome",
    "AnalysisOutputError",
    "Assessment",
    "EventAnalyzer",
    "HttpOllamaClient",
    "MetricsSnapshot",
    "ModelAnalysis",
    "OllamaBadPayloadError",
    "OllamaClient",
    "OllamaError",
    "OllamaModelMissingError",
    "OllamaRequestError",
    "OllamaUnavailableError",
    "PROMPT_TEMPLATE_VERSION",
    "RecommendedStep",
    "build_ollama_client",
]
