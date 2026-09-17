from datetime import datetime
from typing import Annotated, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    StringConstraints,
    model_validator,
)


def reject_nul_character(value: str) -> str:
    if "\x00" in value:
        raise ValueError("NUL characters are not allowed")
    return value


NoteTitle = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=200),
    AfterValidator(reject_nul_character),
]
NoteContent = Annotated[
    str,
    StringConstraints(max_length=100_000),
    AfterValidator(reject_nul_character),
]


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: NoteTitle
    content: NoteContent


class NoteUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: NoteTitle | None = None
    content: NoteContent | None = None

    @model_validator(mode="after")
    def require_an_actual_change(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided")
        if any(getattr(self, field_name) is None for field_name in self.model_fields_set):
            raise ValueError("Note fields cannot be null")
        return self


class NoteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    content: str
    created_at: datetime
    updated_at: datetime


class AdminNoteRead(NoteRead):
    owner_id: int
