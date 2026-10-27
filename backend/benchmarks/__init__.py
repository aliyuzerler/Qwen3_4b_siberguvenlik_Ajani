"""Faz 09 benchmark paketi — model değerlendirme altyapısı.

Modüller:
- dataset.py     : donmuş holdout kümesinin yüklenmesi + doğrulanması
- metrics.py     : precision/recall/F1/FPR, JSON-valid, evidence, latency...
- baselines.py   : rules_only / qwen_prompt_only / rules_corr_qwen
- mock_client.py : deterministik sözleşme-doğrulama istemcisi (KANIT DEĞİL)
- runner.py      : koşum orkestrasyonu + provenance + CSV/JSON çıktı
- run_benchmark.py / __main__.py : CLI

Kural (phases/09): benchmark altyapısı ÜRETİM kodunu DEĞİŞTİRMEZ;
sadece app.services.* arayüzlerini kullanır (mock-first disiplini).
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.9.0"
