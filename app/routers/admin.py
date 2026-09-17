from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy.orm import Session

from app.database import POSTGRES_INTEGER_MAX
from app.dependencies import get_db, require_admin, require_csrf
from app.models.user import User
from app.schemas.note import AdminNoteRead
from app.schemas.user import AdminUserUpdate, UserRead
from app.services.notes import NoteNotFoundError, get_all_notes, get_note_for_admin
from app.services.users import (
    AdminSelfLockoutError,
    UserNotFoundError,
    get_all_users,
    get_user,
    update_user,
)


router = APIRouter(prefix="/api/admin", tags=["admin"])
ResourceId = Annotated[int, Path(gt=0, le=POSTGRES_INTEGER_MAX)]


@router.get("/users", response_model=list[UserRead])
def list_users(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
) -> list[UserRead]:
    return [UserRead.model_validate(user) for user in get_all_users(db)]


@router.get("/users/{user_id}", response_model=UserRead)
def read_user(
    user_id: ResourceId,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
) -> UserRead:
    try:
        user = get_user(db, user_id=user_id)
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        ) from exc
    return UserRead.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserRead)
def patch_user(
    user_id: ResourceId,
    user_data: AdminUserUpdate,
    db: Annotated[Session, Depends(get_db)],
    current_admin: Annotated[User, Depends(require_admin)],
    _: Annotated[None, Depends(require_csrf)],
) -> UserRead:
    try:
        user = update_user(
            db,
            user_id=user_id,
            acting_admin_id=current_admin.id,
            role=user_data.role if "role" in user_data.model_fields_set else None,
            is_active=(
                user_data.is_active
                if "is_active" in user_data.model_fields_set
                else None
            ),
        )
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        ) from exc
    except AdminSelfLockoutError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Admin cannot deactivate or demote own account",
        ) from exc
    return UserRead.model_validate(user)


@router.get("/notes", response_model=list[AdminNoteRead])
def list_notes(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
) -> list[AdminNoteRead]:
    return [AdminNoteRead.model_validate(note) for note in get_all_notes(db)]


@router.get("/notes/{note_id}", response_model=AdminNoteRead)
def read_note(
    note_id: ResourceId,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
) -> AdminNoteRead:
    try:
        note = get_note_for_admin(db, note_id=note_id)
    except NoteNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found",
        ) from exc
    return AdminNoteRead.model_validate(note)
