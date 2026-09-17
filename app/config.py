from typing import Literal

from typing import Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Private Notes Service"
    app_env: str = "development"
    database_url: str = "postgresql+psycopg://notes:notes@localhost:5432/notes"
    jwt_secret_key: SecretStr = Field(min_length=32)
    jwt_algorithm: Literal["HS256"] = "HS256"
    access_token_expire_minutes: int = Field(default=30, gt=0)
    access_token_cookie_name: str = "access_token"
    csrf_cookie_name: str = "csrf_token"
    csrf_header_name: str = "X-CSRF-Token"
    cookie_secure: bool = False

    @model_validator(mode="after")
    def validate_security_settings(self) -> Self:
        secret = self.jwt_secret_key.get_secret_value()
        if secret in {
            "replace-with-a-random-secret-at-least-32-characters",
            "change-me-change-me-change-me-change-me",
        }:
            raise ValueError("JWT_SECRET_KEY must not use a public placeholder")
        if self.app_env.casefold() == "production" and not self.cookie_secure:
            raise ValueError("COOKIE_SECURE must be true in production")
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        hide_input_in_errors=True,
    )


settings = Settings()
