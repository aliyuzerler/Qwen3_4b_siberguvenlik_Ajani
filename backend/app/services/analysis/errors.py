"""Analiz katmanı tipli hata hiyerarşisi (Faz 04).

Kurallar (phases/04-qwen-analysis.md, AGENTS.md §4, §7 — Faz 02/03 ile aynı disiplin):
- Hata mesajları anlaşılır ve Türkçedir; credential/token ASLA içermez.
- Hata mesajları güvenilmeyen log içeriğini ham haliyle TAŞIMAZ
  (yalnızca yapısal bilgi: alan adı, uzunluk, durum kodu).
- Retry edilebilirlik hatanın türünden okunur (retryable özelliği).

İki ayrı hata ailesi vardır ve kaderleri farklıdır:
- Ollama/altyapı hataları  → döngü durur, event analizsiz kalır (sonraki
  döngüde tekrar denenir); analyses tablosu HİÇ yazılmaz.
- Model ÇIKTI hataları     → sınırlı tekrar denenir, tükenince güvenli
  fallback: status=analysis_failed satırı YAZILIR (AGENTS.md §5).
"""

from __future__ import annotations


class AnalysisError(Exception):
    """Tüm analiz katmanı hatalarının tabanı."""

    retryable: bool = False

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


# --- Ollama / altyapı hataları (döngü durur, satır yazılmaz) ---------------


class OllamaError(AnalysisError):
    """Ollama iletişim hatalarının tabanı (aktarım ailesi).

    Analyzer bu aileyi yakalar: retryable ise sınırlı tekrar; tükenirse
    hata yükseltilir ve döngü durur (analyses tablosuna satır YAZILMAZ).
    """


class OllamaUnavailableError(OllamaError):
    """Ollama erişilemez: bağlantı kurulamadı, zaman aşımı, HTTP 5xx.

    Geçici kabul edilir; sınırlı retry sonrası tükenirse döngü iptal olur.
    """

    retryable = True


class OllamaModelMissingError(AnalysisError):
    """Model Ollama'da yüklü değil (HTTP 404 / tags listesinde yok).

    Tekrar denemesiz: kurulum talimatı mesajda açıkça verilir
    (phases/04: "model yoksa açık hata/kurulum talimatı ver").
    """

    retryable = False


class OllamaRequestError(AnalysisError):
    """Beklenmeyen istek hatası (4xx vb.). Tekrar denemesiz."""

    retryable = False


class OllamaBadPayloadError(AnalysisError):
    """Ollama 2xx döndü ama zarf kullanılamaz: bozuk UTF-8, geçersiz zarf
    JSON'u, `response` alanı yok/str değil.

    Aktarım düzeyi bozulma sayılır: sınırlı retry denenir, tükenirse
    döngü iptal olur (event'e analysis_failed YAZILMAZ — model suçlu değil).
    """

    retryable = True


# --- Model ÇIKTI hataları (sınırlı retry → analysis_failed satırı) ----------


class AnalysisOutputError(AnalysisError):
    """Model çıktısı geçersiz: JSON parse edilemedi veya şema ihlali.

    retryable=True: AGENTS.md §5 — "Geçersiz çıktı için sınırlı tekrar dene;
    ardından analysis_failed olarak kaydet." Tükenince analyzer hata
    YÜKSELTMEZ, güvenli fallback outcome döndürür.
    """

    retryable = True

    def __init__(self, message: str, *, error_code: str) -> None:
        super().__init__(message)
        self.error_code = error_code


# Sabit hata kodları (analyses.error_code sütununa yazılır; panelde gösterilir)
OUTPUT_ERROR_INVALID_JSON = "invalid_json"
OUTPUT_ERROR_SCHEMA_VIOLATION = "schema_violation"
OUTPUT_ERROR_TOO_LONG = "output_too_long"
