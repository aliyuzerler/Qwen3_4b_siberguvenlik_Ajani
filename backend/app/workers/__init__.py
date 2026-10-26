"""Arka plan iş katmanı.

Modüller:
- Faz 03: ingest.py — fetch → normalize → idempotent saklama döngüsü
  (zamanlanmış döngü Faz 04'te etkinleşir)
- Faz 04 (planlı): queue.py (DB tabanlı idempotent görev tablosu),
  analysis_worker.py (Ollama/Qwen3 4B çağrısı, timeout, concurrency sınırı)
"""
