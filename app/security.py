import secrets
from datetime import datetime, timedelta, timezone

import jwt
from jwt import PyJWTError
from pwdlib import PasswordHash

from app.config import settings
from app.database import POSTGRES_INTEGER_MAX


password_hasher = PasswordHash.recommended()
DUMMY_PASSWORD_HASH = password_hasher.hash(secrets.token_urlsafe(32))


class InvalidAccessTokenError(Exception):
    pass


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return password_hasher.verify(plain_password, password_hash)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def create_access_token(
    user_id: int,
    *,
    expires_delta: timedelta | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    lifetime = (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.access_token_expire_minutes)
    )
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + lifetime,
    }
    return jwt.encode(
        payload,
        settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> int:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "exp"]},
        )
    except PyJWTError as exc:
        raise InvalidAccessTokenError from exc

    subject = payload.get("sub")
    if (
        not isinstance(subject, str)
        or not subject.isascii()
        or not subject.isdigit()
    ):
        raise InvalidAccessTokenError

    user_id = int(subject)
    if (
        user_id <= 0
        or user_id > POSTGRES_INTEGER_MAX
        or str(user_id) != subject
    ):
        raise InvalidAccessTokenError
    return user_id
