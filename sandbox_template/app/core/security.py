from datetime import UTC, datetime, timedelta

import jwt
from pwdlib import PasswordHash

from app.config import settings

_password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return _password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return _password_hash.verify(password, hashed_password)


def create_access_token(subject: str, expires_minutes: int | None = None) -> str:
    minutes = expires_minutes or settings.access_token_expire_minutes
    expires = datetime.now(UTC) + timedelta(minutes=minutes)
    return str(
        jwt.encode(
            {"sub": subject, "exp": expires},
            settings.secret_key,
            algorithm=settings.algorithm,
        )
    )


def decode_access_token(token: str) -> dict:
    return dict(jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm]))
