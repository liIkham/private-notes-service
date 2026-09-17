from pathlib import Path

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.exception_handlers import validation_exception_handler
from app.routers.admin import router as admin_router
from app.routers.auth import router as auth_router
from app.routers.health import router as health_router
from app.routers.notes import router as notes_router
from app.routers.pages import router as pages_router
from app.security_headers import add_security_headers


STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name)
    app.middleware("http")(add_security_headers)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(notes_router)
    app.include_router(admin_router)
    app.include_router(pages_router)
    return app


app = create_app()
