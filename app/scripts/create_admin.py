import sys
from getpass import getpass

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.user import User, UserRole
from app.schemas.auth import UsernamePasswordInput
from app.security import hash_password
from app.services.auth import (
    UsernameAlreadyExistsError,
    is_username_unique_violation,
)


def create_admin(db: Session, username: str, password: str) -> User:
    """Validate credentials and create one explicitly requested administrator."""
    credentials = UsernamePasswordInput.model_validate(
        {"username": username, "password": password}
    )

    existing_user_id = db.scalar(
        select(User.id).where(User.username == credentials.username)
    )
    if existing_user_id is not None:
        raise UsernameAlreadyExistsError

    admin = User(
        username=credentials.username,
        password_hash=hash_password(credentials.password),
        role=UserRole.ADMIN,
        is_active=True,
    )
    db.add(admin)

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if is_username_unique_violation(exc):
            raise UsernameAlreadyExistsError from exc
        raise
    except SQLAlchemyError:
        db.rollback()
        raise

    db.refresh(admin)
    return admin


def main() -> int:
    try:
        username = input("Username: ")
        password = getpass("Password: ")
        repeated_password = getpass("Repeat password: ")
    except (EOFError, KeyboardInterrupt):
        print("\nAdministrator creation cancelled", file=sys.stderr)
        return 1

    if password != repeated_password:
        print("Passwords do not match", file=sys.stderr)
        return 1

    try:
        with SessionLocal() as db:
            admin = create_admin(db, username, password)
    except ValidationError:
        print(
            "Invalid credentials: username must use 3-64 ASCII characters "
            "(a-z, 0-9, _ or -), and password must contain 8-128 characters",
            file=sys.stderr,
        )
        return 1
    except UsernameAlreadyExistsError:
        print("User already exists", file=sys.stderr)
        return 1
    except SQLAlchemyError:
        print("Database error while creating administrator", file=sys.stderr)
        return 1

    print(f"Administrator '{admin.username}' created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
