from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy.orm import Session

from app.database import POSTGRES_INTEGER_MAX
from app.dependencies import get_current_user, get_db, require_csrf
from app.models.user import User
from app.schemas.note import NoteCreate, NoteRead, NoteUpdate
from app.services.notes import (
    NoteNotFoundError,
    create_note,
    delete_user_note,
    get_user_note,
    get_user_notes,
    update_user_note,
)


router = APIRouter(prefix="/api/notes", tags=["notes"])
NoteId = Annotated[int, Path(gt=0, le=POSTGRES_INTEGER_MAX)]


def _not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Note not found",
    )


@router.post("", response_model=NoteRead, status_code=status.HTTP_201_CREATED)
def create(
    note_data: NoteCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    _: Annotated[None, Depends(require_csrf)],
) -> NoteRead:
    note = create_note(
        db,
        owner_id=current_user.id,
        title=note_data.title,
        content=note_data.content,
    )
    return NoteRead.model_validate(note)


@router.get("", response_model=list[NoteRead])
def list_notes(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[NoteRead]:
    return [
        NoteRead.model_validate(note)
        for note in get_user_notes(db, owner_id=current_user.id)
    ]


@router.get("/{note_id}", response_model=NoteRead)
def read_note(
    note_id: NoteId,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> NoteRead:
    try:
        note = get_user_note(db, note_id=note_id, owner_id=current_user.id)
    except NoteNotFoundError as exc:
        raise _not_found() from exc
    return NoteRead.model_validate(note)


@router.patch("/{note_id}", response_model=NoteRead)
def update_note(
    note_id: NoteId,
    note_data: NoteUpdate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    _: Annotated[None, Depends(require_csrf)],
) -> NoteRead:
    try:
        note = update_user_note(
            db,
            note_id=note_id,
            owner_id=current_user.id,
            title=note_data.title if "title" in note_data.model_fields_set else None,
            content=(
                note_data.content if "content" in note_data.model_fields_set else None
            ),
        )
    except NoteNotFoundError as exc:
        raise _not_found() from exc
    return NoteRead.model_validate(note)


@router.delete("/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_note(
    note_id: NoteId,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    _: Annotated[None, Depends(require_csrf)],
) -> None:
    try:
        delete_user_note(db, note_id=note_id, owner_id=current_user.id)
    except NoteNotFoundError as exc:
        raise _not_found() from exc
