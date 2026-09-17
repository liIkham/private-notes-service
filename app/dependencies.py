from collections.abc import Generator
import secrets
from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models.user import User, UserRole
from app.security import InvalidAccessTokenError, decode_access_token


CSRF_TOKEN_LENGTH = 43


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session


def _unauthenticated_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    db: Annotated[Session, Depends(get_db)],
    access_token: Annotated[
        str | None,
        Cookie(alias=settings.access_token_cookie_name),
    ] = None,
) -> User:
    if access_token is None:
        raise _unauthenticated_exception()

    try:
        user_id = decode_access_token(access_token)
    except InvalidAccessTokenError as exc:
        raise _unauthenticated_exception() from exc

    user = db.get(User, user_id)
    if user is None:
        raise _unauthenticated_exception()
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    return user


def require_admin(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


def require_csrf(
    csrf_cookie: Annotated[
        str | None,
        Cookie(alias=settings.csrf_cookie_name),
    ] = None,
    csrf_header: Annotated[
        str | None,
        Header(alias=settings.csrf_header_name),
    ] = None,
) -> None:
    if (
        csrf_cookie is None
        or csrf_header is None
        or len(csrf_cookie) != CSRF_TOKEN_LENGTH
        or len(csrf_header) != CSRF_TOKEN_LENGTH
        or not csrf_cookie.isascii()
        or not csrf_header.isascii()
        or not all(character.isalnum() or character in "-_" for character in csrf_cookie)
        or not all(character.isalnum() or character in "-_" for character in csrf_header)
        or not secrets.compare_digest(csrf_cookie, csrf_header)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token",
        )
