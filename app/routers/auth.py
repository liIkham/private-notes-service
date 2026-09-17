from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.config import settings
from app.dependencies import get_current_user, get_db, require_csrf
from app.models.user import User
from app.schemas.auth import CsrfTokenRead, UserLogin, UserRegister
from app.schemas.user import UserRead
from app.security import create_access_token, generate_csrf_token
from app.services.auth import (
    InactiveUserError,
    InvalidCredentialsError,
    UsernameAlreadyExistsError,
    authenticate_user,
    register_user,
)


router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/csrf", response_model=CsrfTokenRead)
def csrf(response: Response) -> CsrfTokenRead:
    token = generate_csrf_token()
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    return CsrfTokenRead(csrf_token=token)


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(
    registration: UserRegister,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(require_csrf)],
) -> UserRead:
    try:
        user = register_user(db, registration.username, registration.password)
    except UsernameAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username is already registered",
        ) from exc

    return UserRead.model_validate(user)


@router.post("/login", response_model=UserRead)
def login(
    credentials: UserLogin,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(require_csrf)],
) -> UserRead:
    try:
        user = authenticate_user(db, credentials.username, credentials.password)
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except InactiveUserError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        ) from exc

    response.set_cookie(
        key=settings.access_token_cookie_name,
        value=create_access_token(user.id),
        max_age=settings.access_token_expire_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    return UserRead.model_validate(user)


@router.get("/me", response_model=UserRead)
def me(current_user: Annotated[User, Depends(get_current_user)]) -> UserRead:
    return UserRead.model_validate(current_user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    _: Annotated[None, Depends(require_csrf)],
) -> None:
    response.delete_cookie(
        key=settings.access_token_cookie_name,
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    response.delete_cookie(
        key=settings.csrf_cookie_name,
        path="/",
        secure=settings.cookie_secure,
        httponly=False,
        samesite="lax",
    )
