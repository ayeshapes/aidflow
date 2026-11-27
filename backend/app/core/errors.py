"""One error format for the whole API:

    {"error": {"code": "STRING", "message": "..."}}

Every kind of failure (our own errors, 404/405, validation 422, and unexpected
crashes 500) is routed through the handlers below.
"""
import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("aidflow")

# Default machine-readable code for each HTTP status.
STATUS_CODES = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    422: "VALIDATION_ERROR",
}


class AppError(Exception):
    """Raise this in our own code, e.g. AppError(409, "STOCK_TOO_LOW", "...").

    `headers` is for responses that need one, e.g. Retry-After on a 429.
    """

    def __init__(
        self, status_code: int, code: str, message: str, headers: dict[str, str] | None = None
    ):
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = headers


def error_response(status_code: int, code: str, message: str, headers=None) -> JSONResponse:
    body = {"error": {"code": code, "message": message}}
    return JSONResponse(status_code=status_code, content=body, headers=headers)


async def handle_app_error(request: Request, exc: AppError):
    return error_response(exc.status_code, exc.code, exc.message, headers=exc.headers)


async def handle_http_error(request: Request, exc: StarletteHTTPException):
    # Covers HTTPException raised by us or FastAPI, plus unknown routes (404).
    code = STATUS_CODES.get(exc.status_code, "HTTP_ERROR")
    return error_response(exc.status_code, code, str(exc.detail), headers=exc.headers)


async def handle_validation_error(request: Request, exc: RequestValidationError):
    # Only field name + problem are returned, never the submitted values.
    problems = [
        f"{'.'.join(str(part) for part in err['loc'])}: {err['msg']}"
        for err in exc.errors()[:3]
    ]
    return error_response(422, "VALIDATION_ERROR", "Validation failed: " + "; ".join(problems))


async def handle_unexpected_error(request: Request, exc: Exception):
    # Full details go to the server log only. The client gets a generic message.
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return error_response(500, "INTERNAL_ERROR", "Internal server error")


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, handle_app_error)
    app.add_exception_handler(StarletteHTTPException, handle_http_error)
    app.add_exception_handler(RequestValidationError, handle_validation_error)
    app.add_exception_handler(Exception, handle_unexpected_error)
