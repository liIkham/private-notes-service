from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.normalization import normalize_username


class CsrfTokenRead(BaseModel):
    csrf_token: str


class UsernamePasswordInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        min_length=3,
        max_length=64,
        pattern=r"^[a-z0-9_-]+$",
    )
    password: str = Field(min_length=8, max_length=128)

    @field_validator("username", mode="before")
    @classmethod
    def normalize_username_value(cls, value: object) -> object:
        if isinstance(value, str):
            return normalize_username(value)
        return value


class UserRegister(UsernamePasswordInput):
    """Public registration input."""


class UserLogin(UsernamePasswordInput):
    """Password login input."""
