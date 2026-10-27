"""JWT token servisi testleri (Faz 05).

Kapsam: access/refresh üretimi, doğrulama roundtrip, tip ayrımı
(refresh ile API erişimi reddi), yanlış imza, süresi dolmuş token,
bozuk payload tipleri, alg confusion kapalılığı.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt as pyjwt
import pytest

from app.services.security.tokens import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH,
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
)

SECRET = "test-sadece-sahte-secret-0123456789abcdef-0123456789abcdef"  # noqa: S105
ALG = "HS256"


def _issue_access(**overrides: object) -> str:
    values: dict[str, object] = {
        "secret": SECRET,
        "algorithm": ALG,
        "subject": "11111111-1111-1111-1111-111111111111",
        "username": "admin",
        "role": "admin",
        "ttl_minutes": 5,
    }
    values.update(overrides)
    return create_access_token(**values)  # type: ignore[arg-type]


class TestTokenRoundtrip:
    def test_access_token_decodes_with_claims(self) -> None:
        token = _issue_access()
        claims = decode_token(token, secret=SECRET, algorithm=ALG, expected_type=TOKEN_TYPE_ACCESS)
        assert claims.username == "admin"
        assert claims.role == "admin"
        assert claims.token_type == TOKEN_TYPE_ACCESS
        assert claims.subject == "11111111-1111-1111-1111-111111111111"
        assert claims.expires_at > datetime.now(UTC)

    def test_refresh_token_has_refresh_type(self) -> None:
        token = create_refresh_token(
            secret=SECRET, algorithm=ALG, subject="u", username="a", role="viewer", ttl_minutes=60
        )
        claims = decode_token(token, secret=SECRET, algorithm=ALG, expected_type=TOKEN_TYPE_REFRESH)
        assert claims.token_type == TOKEN_TYPE_REFRESH


class TestTokenRejection:
    def test_refresh_token_cannot_be_used_as_access(self) -> None:
        refresh = create_refresh_token(
            secret=SECRET, algorithm=ALG, subject="u", username="a", role="viewer", ttl_minutes=60
        )
        with pytest.raises(TokenError):
            decode_token(
                refresh, secret=SECRET, algorithm=ALG, expected_type=TOKEN_TYPE_ACCESS
            )

    def test_access_token_cannot_be_used_as_refresh(self) -> None:
        access = _issue_access()
        with pytest.raises(TokenError):
            decode_token(
                access, secret=SECRET, algorithm=ALG, expected_type=TOKEN_TYPE_REFRESH
            )

    def test_wrong_signature_rejected(self) -> None:
        token = _issue_access()
        with pytest.raises(TokenError):
            decode_token(
                token,
                secret="bambaşka-secret" * 4,
                algorithm=ALG,
                expected_type=TOKEN_TYPE_ACCESS,
            )

    def test_expired_token_rejected(self) -> None:
        now = datetime.now(UTC) - timedelta(minutes=10)
        payload = {
            "sub": "u",
            "username": "a",
            "role": "viewer",
            "typ": TOKEN_TYPE_ACCESS,
            "iat": now,
            "exp": now + timedelta(minutes=1),
        }
        token = pyjwt.encode(payload, SECRET, algorithm=ALG)
        with pytest.raises(TokenError):
            decode_token(token, secret=SECRET, algorithm=ALG, expected_type=TOKEN_TYPE_ACCESS)

    def test_garbage_token_rejected(self) -> None:
        with pytest.raises(TokenError):
            decode_token(
                "bu-token-değil", secret=SECRET, algorithm=ALG, expected_type=TOKEN_TYPE_ACCESS
            )

    def test_alg_confusion_rejected(self) -> None:
        """none algoritmasıyla imzalanan token reddedilir (alg confusion)."""
        payload = {
            "sub": "u",
            "username": "a",
            "role": "admin",
            "typ": TOKEN_TYPE_ACCESS,
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        }
        token = pyjwt.encode(payload, key="", algorithm="none")
        with pytest.raises(TokenError):
            decode_token(token, secret=SECRET, algorithm=ALG, expected_type=TOKEN_TYPE_ACCESS)

    def test_missing_subject_rejected(self) -> None:
        payload = {
            "username": "a",
            "role": "admin",
            "typ": TOKEN_TYPE_ACCESS,
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        }
        token = pyjwt.encode(payload, SECRET, algorithm=ALG)
        with pytest.raises(TokenError):
            decode_token(token, secret=SECRET, algorithm=ALG, expected_type=TOKEN_TYPE_ACCESS)

    def test_nonstring_role_rejected(self) -> None:
        payload = {
            "sub": "u",
            "username": "a",
            "role": 123,
            "typ": TOKEN_TYPE_ACCESS,
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        }
        token = pyjwt.encode(payload, SECRET, algorithm=ALG)
        with pytest.raises(TokenError):
            decode_token(token, secret=SECRET, algorithm=ALG, expected_type=TOKEN_TYPE_ACCESS)
