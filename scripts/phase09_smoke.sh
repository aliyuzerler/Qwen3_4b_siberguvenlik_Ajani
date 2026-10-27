#!/usr/bin/env bash
# Faz 09 smoke testi: benchmark hattının uçtan uca doğrulaması (Ollama'sız).
#
# Evre 1: donmuş dataset doğrulaması (etiket/sızıntı/hassas veri taraması).
# Evre 2: rules_only baseline — GERÇEK koşum (deterministik, LLM yok).
# Evre 3: mock LLM baseline'ları (B ve C) — ALTYAPI doğrulaması;
#         raporun "kanıt değildir" işaretlemesi zorunludur.
# Evre 4: negatif yollar — geçersiz dataset CLI red (exit 2);
#         erişilemez Ollama → aborted_infrastructure (exit 3).
# Evre 5: çıktı dosya sözleşmesi (report.json / metrics.csv / predictions.jsonl).
#
# Tüm veri SENTETİKTİR (RFC 5737/1918); parola/secret YOKTUR.
set -euo pipefail
cd /home/z/my-project/ajant/backend

DATASET="benchmarks/datasets/holdout-v1.jsonl"
EXPECTED_SHA="7f0c687390eda4de2403b303618d5e0a1b931d96316ac90bac3c0db445683bc3"
OUT="benchmarks/results_smoke"
pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "PASS: $1 ($3)";
  else fail=$((fail+1)); echo "FAIL: $1 (beklenen $2, gelen $3)"; fi
}
metric() { # report_path joktaş
  python - "$1" "$2" <<'PYEOF'
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
node = report
for key in sys.argv[2].split("."):
    node = node[key]
print(node)
PYEOF
}

rm -rf "$OUT"; mkdir -p "$OUT"

# ==================== EVRE 1: dataset doğrulama ==============================
echo "== EVRE 1: dataset doğrulama"
VALID_OUT=$(python -m benchmarks.run_benchmark validate --dataset "$DATASET")
check "dataset geçerli" "0" "$?"
echo "$VALID_OUT" | grep -q "sha256: $EXPECTED_SHA"
check "dataset sha256 donmuş" "0" "$?"
echo "$VALID_OUT" | grep -q "total: 48"
check "kayıt sayısı 48" "0" "$?"

# ==================== EVRE 2: rules_only (GERÇEK) ============================
echo "== EVRE 2: rules_only gerçek koşum"
RULES_DIR=$(python -m benchmarks.run_benchmark run --baseline rules_only \
  --dataset "$DATASET" --out "$OUT" | tee /tmp/ajant09_rules.log | grep '^dir: ' | cut -d' ' -f2)
check "rules_only tamamlanır" "completed" "$(metric "$RULES_DIR/report.json" run_status)"
check "rules_only schema-valid" "1.0" "$(metric "$RULES_DIR/report.json" metrics.totals.schema_valid_rate)"
check "rules_only kanıt-geçerli" "True" "$(metric "$RULES_DIR/report.json" results_valid_as_model_evidence)"
check "rules_only LLM yok" "none" "$(metric "$RULES_DIR/report.json" provenance.llm_provider)"
check "rules_only evidence köklü" "1.0" "$(metric "$RULES_DIR/report.json" metrics.evidence.item_correctness_rate)"

# ==================== EVRE 3: mock baseline'lar (B ve C) =====================
echo "== EVRE 3: mock LLM baseline'ları (altyapı doğrulaması)"
B_DIR=$(python -m benchmarks.run_benchmark run --baseline qwen_prompt_only \
  --dataset "$DATASET" --out "$OUT" --llm mock | tee /tmp/ajant09_b.log | grep '^dir: ' | cut -d' ' -f2)
check "mock B tamamlanır" "completed" "$(metric "$B_DIR/report.json" run_status)"
check "mock B şema-geçerli" "1.0" "$(metric "$B_DIR/report.json" metrics.totals.schema_valid_rate)"
check "mock B kanıt-DEĞİL işareti" "False" "$(metric "$B_DIR/report.json" results_valid_as_model_evidence)"
grep -q "UYARI: mock koşum" /tmp/ajant09_b.log
check "mock B CLI uyarısı" "0" "$?"

C_DIR=$(python -m benchmarks.run_benchmark run --baseline rules_corr_qwen \
  --dataset "$DATASET" --out "$OUT" --llm mock | tee /tmp/ajant09_c.log | grep '^dir: ' | cut -d' ' -f2)
check "mock C tamamlanır" "completed" "$(metric "$C_DIR/report.json" run_status)"
check "mock C injection dayanıklılığı" "1.0" "$(metric "$C_DIR/report.json" metrics.injection_resilience.resilience_rate)"
MAINT_FP=$(metric "$C_DIR/report.json" metrics.benign_maintenance.false_alarms)
if [ "$MAINT_FP" -ge 1 ]; then
  check "mock C korelasyon gürültü takası görünür" "0" "0"
else
  check "mock C korelasyon gürültü takası görünür" ">=1" "$MAINT_FP"
fi

# ==================== EVRE 4: negatif yollar =================================
echo "== EVRE 4: negatif yollar"
printf '{"record_id": "eksik-etiket"}\n' > "$OUT/invalid.jsonl"
set +e
python -m benchmarks.run_benchmark run --baseline rules_only \
  --dataset "$OUT/invalid.jsonl" --out "$OUT/never" > /tmp/ajant09_neg1.log 2>&1
NEG1=$?
set -e
check "geçersiz dataset exit 2" "2" "$NEG1"
grep -q "DATASET GECERSIZ" /tmp/ajant09_neg1.log
check "geçersiz dataset mesajı" "0" "$?"

set +e
python -m benchmarks.run_benchmark run --baseline qwen_prompt_only \
  --dataset "$DATASET" --out "$OUT/abort" --llm ollama \
  --base-url http://127.0.0.1:9 --timeout-seconds 2 > /tmp/ajant09_neg2.log 2>&1
NEG2=$?
set -e
check "erişilemez Ollama exit 3" "3" "$NEG2"
grep -q "aborted_infrastructure" /tmp/ajant09_neg2.log
check "aborted durumu raporlanır" "0" "$?"

# ==================== EVRE 5: çıktı sözleşmesi ===============================
echo "== EVRE 5: çıktı dosya sözleşmesi"
for FILE in report.json metrics.csv predictions.jsonl; do
  [ -f "$RULES_DIR/$FILE" ]
  check "rules_only $FILE var" "0" "$?"
done
ROWS=$(wc -l < "$RULES_DIR/predictions.jsonl")
check "predictions satır sayısı 48" "48" "$ROWS"
CSV_HEADER=$(head -1 "$RULES_DIR/metrics.csv")
check "CSV başlığı" "metric,value" "$CSV_HEADER"
python -c "import json; json.load(open('$RULES_DIR/report.json', encoding='utf-8'))"
check "report.json geçerli JSON" "0" "$?"

echo ""
echo "SONUÇ: $pass PASS, $fail FAIL"
[ "$fail" -eq 0 ] || exit 1
