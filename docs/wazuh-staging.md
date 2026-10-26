# Wazuh bağlantı talimatı (staging) — Faz 02

Bu belge, ajant backend'i gerçek bir Wazuh kurulumuna **salt okunur** modda
bağlamak için hazırlanmıştır. Mock-first geliştirme tamamlandığı için bu
adımlar **sahada** yapılır; sandbox'ta doğrulanamaz.

## 0. Neden Indexer? (kanıt)

Wazuh Server API (port 55000) **alert okuma endpoint'i içermez**. Resmi API
spec'i incelendiğinde (wazuh/wazuh `api/api/spec/spec.yaml`) alert/olay ile
ilgili tek uç nokta `POST /events`'tir — bu bir **ingest (yazma)** uç noktasıdır
ve ajant bunu ASLA kullanmaz. Alert'ler Wazuh tarafından **Wazuh Indexer'a**
(OpenSearch tabanlı, port 9200) `wazuh-alerts-*` indeksine yazılır ve resmi
erişim yolu bu indeks üzerinde aramadır (Wazuh dashboard da aynısını yapar).

Bu yüzden ajant alert kaynağı **Wazuh Indexer REST API**'dir:

- Uç nokta: `POST /wazuh-alerts-*/_search` (OKUMA; OpenSearch'te `_search`
  gövdeli POST ile de salt sorgudur, indeks mutasyonu yapmaz)
- Bağlantı kontrolü: `GET /` (kök, küme bilgisi)
- Kimlik: HTTP Basic (indexer iç kullanıcısı)

## 1. Salt okunur servis hesabı oluştur (en az ayrıcalık)

Wazuh dashboard'da (admin girişiyle):

1. **Dashboard menüsü → Indexer management → Security → Internal users**
   → *Create internal user*. Örnek kullanıcı adı: `ajant-readonly`.
   Parolayı parola yöneticisinde sakla; **backend `.env` dışına yazma**.
2. **Security → Roles** → *Create role*:
   - Role adı: `ajant_readonly`
   - **Index permissions**: Index: `wazuh-alerts*` → izin: **read**
     (yalnızca okuma; `write`, `manage`, `crud` VERİLMEZ)
3. **Roles → Role mappings** (veya rolün *Mapped users* sekmesi):
   `ajant_readonly` rolünü `ajant-readonly` kullanıcısına eşle.

> Kural (AGENTS.md §4): Wazuh API'si salt okunur, en az ayrıcalıklı servis
> hesabıyla kullanılır. Bu hesapla dashboard'a veya Server API'ye erişim
> gerekmez; yalnızca indexer okuma yetkisi yeterlidir.

## 2. Backend yapılandırması

`backend/.env` (repoda YOK, `.gitignore` içinde):

```bash
WAZUH_SOURCE_MODE=indexer
WAZUH_INDEXER_URL=https://<indexer-host>:9200
WAZUH_INDEXER_USER=ajant-readonly
WAZUH_INDEXER_PASSWORD=<gerçek-parola>
WAZUH_INDEX_PATTERN=wazuh-alerts-*
WAZUH_VERIFY_TLS=true
```

`WAZUH_VERIFY_TLS=false` YALNIZCA staging'de self-signed sertifika ile
geçicidir; prod'da asla kullanma (kabul matrisi güvenlik maddesi).

## 3. Doğrulama (staging'de sırayla)

```bash
# 1) Bağlantı + kimlik (salt okunur hesapla):
curl -sk -u ajant-readonly:'<parola>' https://<indexer-host>:9200/ | head

# 2) Alert arama yetkisi (read izni kanıtı):
curl -sk -u ajant-readonly:'<parola>' \
  -H 'Content-Type: application/json' \
  -X POST "https://<indexer-host>:9200/wazuh-alerts-*/_search" \
  -d '{"size":1,"sort":[{"timestamp":{"order":"desc"}}],"track_total_hits":true}' | head

# 3) Yazma ENGELLENMELİ (beklenen: 403 forbidden):
curl -sk -u ajant-readonly:'<parola>' \
  -X PUT "https://<indexer-host>:9200/wazuh-alerts-*/_settings" \
  -d '{}' | head

# 4) Uygulama tarafı:
cd backend && uvicorn app.main:create_app --factory --port 8000
curl -s http://localhost:8000/api/v1/ready   # → components.wazuh: "up"
```

4. adımda `wazuh: "down"` görürsen `.env` değerlerini ve 401/403 nedenini
kontrol et; backend logları `wazuh_request` olayını method/path/status ile
yazar (credential içermez).

## 4. Sürüm notu

Hem 4.x hem 5.x indexer'ında `wazuh-alerts-*` şeması bu adapter'ın
kullandığı alanları içerir (`id`, `timestamp`, `rule.id`, `rule.level`,
`rule.description`, `agent.*`, `data.srcip`). Adapter, zorunlu alan eksikse
`WazuhBadPayloadError` ile açıkça başarısız olur — uydurma alan yok
(phases/02-wazuh-integration.md kuralı). Gerçek kurulumda sürüm farkı
görürsen `docs/phase-02-verification.md` "kalan riskler" bölümüne not düş.
