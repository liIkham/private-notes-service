from sqlalchemy import inspect

from app.models.note import Note
from app.schemas.note import NoteRead


def test_note_metadata_contains_expected_constraints() -> None:
    table = Note.__table__

    assert set(table.columns.keys()) == {
        "id",
        "owner_id",
        "title",
        "content",
        "created_at",
        "updated_at",
    }
    assert table.c.owner_id.nullable is False
    assert table.c.title.type.length == 200
    assert table.c.created_at.type.timezone is True
    assert table.c.updated_at.type.timezone is True

    foreign_keys = list(table.c.owner_id.foreign_keys)
    assert len(foreign_keys) == 1
    assert foreign_keys[0].target_fullname == "users.id"
    assert foreign_keys[0].constraint.name == "fk_notes_owner_id_users"
    assert any(
        index.name == "ix_notes_owner_id" and index.columns.keys() == ["owner_id"]
        for index in table.indexes
    )


def test_note_read_does_not_expose_owner_id() -> None:
    assert "owner_id" not in NoteRead.model_fields


def test_note_table_is_registered_in_shared_metadata() -> None:
    mapper = inspect(Note)

    assert mapper.local_table.metadata is Note.metadata
    assert "notes" in Note.metadata.tables
