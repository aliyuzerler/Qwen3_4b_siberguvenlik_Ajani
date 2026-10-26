"""Redaction politika testleri (Faz 03).

Kapsam (phases/03): "Parola, token, e-posta/IP gibi hassas alanlar için
yapılandırılabilir redaction politikası; IP maskeleme ürün gereksinimine
göre ayarlanabilir."

Tüm değerler SENTETİKTİR (örnek token'lar geçersiz biçimli dizelerdir).
"""

from __future__ import annotations

from app.services.normalization.redaction import (
    IP_MASK,
    MAX_FULL_LOG_CHARS,
    RedactionPolicy,
    mask_ip,
    redact_src_ip,
    redact_text,
)

POLICY = RedactionPolicy()  # varsayılan: enabled, ip=masked, email=masked, secrets
DISABLED = RedactionPolicy(enabled=False)


class TestSecretPatterns:
    def test_password_assignment_masked(self) -> None:
        out = redact_text("auth failed: password=SuperSecret123 retry", POLICY)
        assert "SuperSecret123" not in out
        assert "password=***" in out

    def test_token_and_api_key_masked(self) -> None:
        out = redact_text("token=abcdef123456 api_key=zzzz9999 yml", POLICY)
        assert "abcdef123456" not in out
        assert "zzzz9999" not in out
        assert "token=***" in out and "api_key=***" in out

    def test_colon_separator_masked(self) -> None:
        out = redact_text("Authorization: Basic dXNlcjpwYXNzd29yZA==", POLICY)
        assert "dXNlcjpwYXNzd29yZA==" not in out
        assert "Basic ***" in out

    def test_bearer_masked(self) -> None:
        out = redact_text("GET /api HTTP/1.1 Authorization: Bearer eyJhbGciOiJI.abc.def", POLICY)
        assert "eyJhbGciOiJI" not in out
        assert "Bearer ***" in out

    def test_private_key_block_masked(self) -> None:
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabcdef\n"
            "-----END RSA PRIVATE KEY-----\nafter"
        )
        out = redact_text(text, POLICY)
        assert "MIIEowIBAAKCAQEA" not in out
        assert "[private-key]" in out
        assert out.endswith("after")

    def test_normal_text_untouched(self) -> None:
        text = "Failed password for root from 203.0.113.7 port 51422 ssh2"
        assert redact_text(text, POLICY) == text  # assignment deseni değildir

    def test_secret_patterns_disabled(self) -> None:
        policy = RedactionPolicy(secret_patterns=False)
        text = "password=SuperSecret123"
        assert redact_text(text, policy) == text


class TestEmailMasking:
    def test_email_local_part_masked(self) -> None:
        out = redact_text("user john.doe@example.com logged in", POLICY)
        assert "john.doe" not in out
        assert "***@example.com" in out

    def test_email_mode_none_keeps_value(self) -> None:
        policy = RedactionPolicy(email_mode="none")
        text = "user john.doe@example.com"
        assert redact_text(text, policy) == text

    def test_disabled_keeps_email(self) -> None:
        text = "mail: john.doe@example.com"
        assert redact_text(text, DISABLED) == text


class TestIpMasking:
    def test_ipv4_masked_zeroes_host_bits(self) -> None:
        assert mask_ip("203.0.113.7", POLICY) == "203.0.113.0"

    def test_ipv6_masked_zeroes_host_bits(self) -> None:
        assert mask_ip("2001:db8:abcd:0012:0001:0002:0003:0004", POLICY) == "2001:db8:abcd:12::"

    def test_ip_mode_none_keeps_full_value(self) -> None:
        policy = RedactionPolicy(ip_mode="none")
        assert mask_ip("203.0.113.7", policy) == "203.0.113.7"

    def test_ip_mode_redacted_replaces_whole_value(self) -> None:
        policy = RedactionPolicy(ip_mode="redacted")
        assert mask_ip("203.0.113.7", policy) == IP_MASK

    def test_invalid_ip_untouched_in_masked_mode(self) -> None:
        # hostname/bozuk değer: maskeleme yanlış pozitif üretmez
        assert mask_ip("not-an-ip", POLICY) == "not-an-ip"

    def test_invalid_ip_replaced_in_redacted_mode(self) -> None:
        policy = RedactionPolicy(ip_mode="redacted")
        assert mask_ip("not-an-ip", policy) == IP_MASK

    def test_redact_src_ip_none_preserved(self) -> None:
        assert redact_src_ip(None, POLICY) is None

    def test_redact_src_ip_applies_policy(self) -> None:
        assert redact_src_ip("198.51.100.99", POLICY) == "198.51.100.0"

    def test_disabled_policy_keeps_ip(self) -> None:
        assert mask_ip("203.0.113.7", DISABLED) == "203.0.113.7"


class TestLimits:
    def test_max_full_log_chars_constant(self) -> None:
        # Sınırsız metin depolama DoS yüzeyidir; sabit belgelenmiştir.
        assert 1024 <= MAX_FULL_LOG_CHARS <= 65536

    def test_large_input_processed_linearly(self) -> None:
        # Geri izleme (backtracking) koruması: büyük girdi patlamamalı.
        big = "x" * 200_000 + " password=abc123 " + "y" * 200_000
        out = redact_text(big, POLICY)
        assert "abc123" not in out
        assert len(out) > MAX_FULL_LOG_CHARS // 2  # metin yapısı korunur
