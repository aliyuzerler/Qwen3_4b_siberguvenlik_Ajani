# ajant — Wazuh + Qwen3 4B Security Agent

Savunma odaklı güvenlik olayı analiz ajanı: Wazuh alarmlarını toplayıp, yerel
**Qwen3 4B** (Ollama) modeliyle açıklayan/önceliklendiren ve güvenli bir web
panelinde sunan sistem.

> İlk sürüm **yalnızca gözlem (observe-only)** modundadır. Model hiçbir komut
> çalıştıramaz; tüm çıktılar katı JSON şemasıyla doğrulanır (Faz 04'te eklenir).

## Doküman haritası

| Dosya | İçerik |
|---|---|
| `AGENTS.md` | Geliştirme ve güvenlik kuralları |
| `architecture.md` | Önerilen mimari ve veri akışı |
| `acceptance-matrix.md` | Faz kabul ölçütleri |
| `docs/phase-00-discovery.md` | Keşif raporu (onaylı teknoloji kararları) |
| `docs/phase-01-verification.md` | Faz 01 doğrulama raporu |
| `phases/`, `skills/`, `training/` | Starter pack belgeleri |

## Faz durumu

- [x] **Faz 00** — Keşif ve tasarım
- [x] **Faz 01** — Proje iskeleti (backend + panel iskeleti + migration altyapısı)
- [ ] Faz 02 — Wazuh bağlantısı (mock adapter + sentetik fixture)
- [ ] Faz 03 — Normalizasyon, redaction ve depolama
- [ ] Faz 04 — Ollama/Qwen3 4B analiz worker'ı
- [ ] Faz 05 — Güvenlik paneli (6 ekran, Türkçe)
- [ ] Faz 06+ — Korelasyon, müdahale hazırlığı, hardening, benchmark, dağıtım

## Yerel kurulum (backend)

```bash
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements-lock.txt
pip install -e ".[dev]"
cp .env.example .env        # ZORUNLU alanları doldurun: JWT_SECRET, DATABASE_URL
uvicorn app.main:create_app --factory --reload
```

Uygulama zorunlu config doğrulanmadan başlamaz; eksik secret açık ve anlaşılır
hata mesajıyla bildirilir (sahte varsayılanla sessiz telafi yoktur).

## Test / lint / tip kontrolü

```bash
pytest -q          # birim + entegrasyon testleri (sqlite + mock)
ruff check .       # lint (güvenlik kuralları dahil)
mypy app           # tip kontrolü
```

## Panel (frontend)

```bash
cd frontend
npm install
npm run dev        # http://localhost:3000 — Faz 05'e kadar yer tutucu sayfa
```

## Docker Compose

```bash
cp backend/.env.example backend/.env   # değerleri düzenleyin
docker compose up --build
```

Not: Ollama compose içinde koşmaz; kullanıcı makinesindeki Ollama'ya
`host.docker.internal:11434` üzerinden bağlanılır. Donanım notu: 2 GB VRAM'li
GPU model yüklemeye yetersizdir; Qwen3 4B CPU modunda çalışır (32 GB RAM yeterli).

## Güvenlik notları

- `POLICY_MODE` varsayılanı `observe_only` — Faz 07'ye kadar hiçbir otomatik
  müdahale yolu yoktur.
- `.env` asla repoya eklenmez; `.env.example` yalnızca sahte örnek değerler içerir.
- Loglar JSON yapılandırılmıştır; password/token/secret alanları otomatik maskelenir.
- Wazuh adapter (Faz 02) yalnızca salt okunur, en az ayrıcalıklı hesapla çalışır.
