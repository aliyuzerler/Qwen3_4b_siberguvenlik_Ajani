"""Hassas alan maskeleme politikası (Faz 03).

Gereksinim (phases/03-normalization-and-storage.md):
- "Parola, token, e-posta/IP gibi hassas alanlar için yapılandırılabilir
  redaction politikası; IP maskeleme ürün gereksinimine göre ayarlanabilir."

Tasarım:
- Saf fonksiyonlardır; DB ve ağa bağımlılığı yoktur → birim testi kolaydır.
- Girdi güvenilmeyen veridir (AGENTS.md §4): desenler doğrusal çalışır,
  geri izleme (backtracking) düşük tutulur; rastgele uzun girdide patlamaz.
- Maskeleme SAKLANAN değerlere uygulanır; kanonik rule_level int'i asla
  değişmez (orijinal severity korunur — Faz 02 sözleşmesi).

IP maskeleme modları (ürün gereksinimine göre ayarlanabilir):
- none     → değer aynen saklanır (analitik değer tam)
- masked   → host bitleri sıfırlanır: IPv4 → /24, IPv6 → /64 (alt ağ korunur)
- redacted → değer tamamen "[ip]" maskesiyle değiştirilir
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

IP_MASK = "[ip]"
EMAIL_MASK_LOCAL = "***"
# full_log güvenlik sınırı: sınırsız metin depolamak DoS yüzeyidir.
# Normalizer'da uygulanır; burada tek kaynağı burasıdır.
MAX_FULL_LOG_CHARS = 8192

IpMode = Literal["none", "masked", "redacted"]
EmailMode = Literal["none", "masked"]

# E-posta: basit, doğrusal desen (iç içe niceleyici yok → geri izleme yok).
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Secret desenleri: anahtar=değer biçimli assignment'lar ve taşıyıcı başlıklar.
# Değer tarafı [^\s;]+ (boşluk/noktalı virgül dışı) → doğrusal, hızlı.
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|pass|token|api[_-]?key|apikey|access[_-]?key|"
    r"secret[_-]?key|secret|client[_-]?secret|private[_-]?key|auth)\s*[:=]\s*([^\s;]{4,})"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+([A-Za-z0-9._~+/=-]{8,})")
_BASIC_RE = re.compile(r"(?i)\b(basic)\s+([A-Za-z0-9+/=]{8,})")
# Özel anahtar blokları: BEGIN/END arasında her şey maskelenir (non-greedy, doğrusal).
_PRIVATE_KEY_RE = re.compile(
    r"(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{0,20000}?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)


@dataclass(frozen=True)
class RedactionPolicy:
    """Yapılandırılabilir maskeleme politikası (Settings.redaction_policy)."""

    enabled: bool = True
    ip_mode: IpMode = "masked"
    email_mode: EmailMode = "masked"
    secret_patterns: bool = True


def _secret_assignment_repl(match: re.Match[str]) -> str:
    key = match.group(1)
    return f"{key}=***"


def redact_text(text: str, policy: RedactionPolicy) -> str:
    """Serbest metindeki secret assignment, taşıyıcı başlık ve e-postaları maskeler.

    full_log ve rule_description gibi güvenilmeyen/metin türevi alanlar için
    kullanılır. Politika devre dışıysa metin aynen döner (test/analiz modu).
    """
    if not text:
        return text
    result = text
    if policy.enabled and policy.secret_patterns:
        result = _PRIVATE_KEY_RE.sub("[private-key]", result)
        result = _BEARER_RE.sub(r"\1 ***", result)
        result = _BASIC_RE.sub(r"\1 ***", result)
        result = _SECRET_ASSIGNMENT_RE.sub(_secret_assignment_repl, result)
    if policy.enabled and policy.email_mode == "masked":
        result = _EMAIL_RE.sub(_email_repl, result)
    return result


def _email_repl(match: re.Match[str]) -> str:
    value = match.group(0)
    _local, at, domain = value.rpartition("@")
    if not at:
        return value
    return f"{EMAIL_MASK_LOCAL}@{domain}"


def mask_ip(value: str, policy: RedactionPolicy) -> str:
    """Tek IP değerini politikaya göre maskeleyip döner.

    Geçersiz IP değerleri (örn. hostname, bozuk veri) değiştirilmez; maskeleme
    yanlış pozitif üretmemek için yalnızca gerçek IP sözdizimine uygulanır.
    redacted modunda geçersiz değerler de maskeye dönüşür (IP sızıntısı sıfır).
    """
    if not value:
        return value
    if not policy.enabled or policy.ip_mode == "none":
        return value
    if policy.ip_mode == "redacted":
        return IP_MASK
    # masked modu: host bitlerini sıfırla (IPv4 /24, IPv6 /64).
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return value  # IP değil → dokunma (hostname olabilir)
    prefix = 24 if addr.version == 4 else 64
    network = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
    return str(network.network_address)


def redact_src_ip(value: str | None, policy: RedactionPolicy) -> str | None:
    """src_ip alanına politikayı uygular (None koruyarak)."""
    if value is None:
        return None
    return mask_ip(value, policy)
