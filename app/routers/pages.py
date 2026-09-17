from pathlib import Path

from fastapi import APIRouter, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates


TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(include_in_schema=False)


def _page(request: Request, template_name: str, title: str) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name=template_name,
        context={"page_title": title},
    )


@router.get("/", response_class=HTMLResponse)
def root() -> RedirectResponse:
    return RedirectResponse(url="/notes", status_code=status.HTTP_302_FOUND)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    return _page(request, "login.html", "Вход")


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request) -> HTMLResponse:
    return _page(request, "register.html", "Регистрация")


@router.get("/notes", response_class=HTMLResponse)
def notes_page(request: Request) -> HTMLResponse:
    return _page(request, "notes.html", "Мои заметки")


@router.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request) -> HTMLResponse:
    return _page(request, "admin.html", "Админ-панель")
