from collections.abc import Awaitable, Callable

from fastapi import Request, Response


APPLICATION_CSP = (
    "default-src 'self'; "
    "base-uri 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'"
)

# FastAPI's built-in documentation renders an inline initializer and loads its
# assets from jsDelivr. Keep that exception confined to the documentation pages.
DOCUMENTATION_CSP = (
    "default-src 'self'; "
    "base-uri 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "object-src 'none'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net"
)

NO_STORE_PAGES = frozenset({"/", "/login", "/register", "/notes", "/admin"})


async def add_security_headers(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    response = await call_next(request)
    path = request.url.path

    response.headers["Content-Security-Policy"] = (
        DOCUMENTATION_CSP
        if path == "/docs" or path.startswith("/docs/") or path == "/redoc"
        else APPLICATION_CSP
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"

    if path.startswith("/api/") or path in NO_STORE_PAGES:
        response.headers["Cache-Control"] = "no-store"

    return response
