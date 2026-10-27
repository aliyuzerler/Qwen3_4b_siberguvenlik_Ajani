"""argon2id parola karma/doğrulama (Faz 05).

- AGENTS.md §4 güvenli oturum yönetimi: parolalar düz metin saklanmaz.
- argon2id OWASP önerisiyle uyumlu parametreler (argon2-cffi PasswordHasher
  varsayılları: time_cost=3, memory_cost=64MiB, parallelism=4).
- verify_password her sonucu False döndürür; hata türü çağırana sızmaz
  (timing/information side-channel yüzeyi küçültülür).
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()

# argon2id tanıtıcı öneki (testler hash biçimini bununla doğrular)
ARGON2ID_PREFIX = "$argon2id$"


def hash_password(password: str) -> str:
    """Parolayı argon2id ile hash'ler (rastgele tuz otomatik üretilir)."""
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Parolayı saklanan hash ile doğrular; her hatada False döner.

    Bilinmeyen/bozuk hash biçimi (InvalidHashError) dahil tüm hatalar
    False'a indirgenir — çağıran taraf yalnızca başarı/başarısızlık görür.
    """
    try:
        _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return True


def needs_rehash(password_hash: str) -> bool:
    """Hash parametreleri güncel politikadan eskiyse True döner (Faz 08 notu).

    Bu fazda çağrılmaz; giriş başarılı olduktan sonra sessiz yükseltme
    (transparent rehash) Faz 08 sertleştirmesine bırakılmıştır.
    """
    return _hasher.check_needs_rehash(password_hash)
