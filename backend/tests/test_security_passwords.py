"""argon2id parola servisi testleri (Faz 05).

Kapsam: hash biçimi (argon2id öneki), doğrulama (doğru/yanlış/bozuk hash),
tuz benzersizliği (aynı parola → farklı hash), parola değeri hash içinde
düz metin olarak görünmez.
"""

from __future__ import annotations

from app.services.security.passwords import (
    ARGON2ID_PREFIX,
    hash_password,
    verify_password,
)


class TestPasswordHashing:
    def test_hash_uses_argon2id_format(self) -> None:
        h = hash_password("güçlü-parola-1")
        assert h.startswith(ARGON2ID_PREFIX)

    def test_verify_correct_password(self) -> None:
        h = hash_password("güçlü-parola-1")
        assert verify_password(h, "güçlü-parola-1") is True

    def test_verify_wrong_password(self) -> None:
        h = hash_password("güçlü-parola-1")
        assert verify_password(h, "yanlış-parola") is False

    def test_verify_malformed_hash_returns_false_not_crash(self) -> None:
        assert verify_password("bozuk-hash", "herhangi") is False
        assert verify_password("", "herhangi") is False

    def test_same_password_produces_unique_hashes(self) -> None:
        # Rastgele tuz: aynı parola iki kez hash'lenirse hash'ler farklıdır.
        h1 = hash_password("aynı-parola")
        h2 = hash_password("aynı-parola")
        assert h1 != h2
        # İkisi de doğru parolayı doğrular.
        assert verify_password(h1, "aynı-parola")
        assert verify_password(h2, "aynı-parola")

    def test_plain_password_never_appears_in_hash(self) -> None:
        secret = "cok-gizli-parola-Xy7719"
        h = hash_password(secret)
        assert secret not in h
