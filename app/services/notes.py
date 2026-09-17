from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.note import Note


class NoteNotFoundError(Exception):
    pass


def create_note(db: Session, *, owner_id: int, title: str, content: str) -> Note:
    note = Note(owner_id=owner_id, title=title, content=content)
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


def get_user_notes(db: Session, *, owner_id: int) -> Sequence[Note]:
    return db.scalars(
        select(Note)
        .where(Note.owner_id == owner_id)
        .order_by(Note.created_at.desc(), Note.id.desc())
    ).all()


def get_all_notes(db: Session) -> Sequence[Note]:
    return db.scalars(
        select(Note).order_by(Note.created_at.desc(), Note.id.desc())
    ).all()


def get_user_note(db: Session, *, note_id: int, owner_id: int) -> Note:
    note = db.scalar(
        select(Note).where(
            Note.id == note_id,
            Note.owner_id == owner_id,
        )
    )
    if note is None:
        raise NoteNotFoundError
    return note


def get_note_for_admin(db: Session, *, note_id: int) -> Note:
    note = db.get(Note, note_id)
    if note is None:
        raise NoteNotFoundError
    return note


def update_user_note(
    db: Session,
    *,
    note_id: int,
    owner_id: int,
    title: str | None = None,
    content: str | None = None,
) -> Note:
    note = get_user_note(db, note_id=note_id, owner_id=owner_id)
    if title is not None:
        note.title = title
    if content is not None:
        note.content = content
    db.commit()
    db.refresh(note)
    return note


def delete_user_note(db: Session, *, note_id: int, owner_id: int) -> None:
    note = get_user_note(db, note_id=note_id, owner_id=owner_id)
    db.delete(note)
    db.commit()
