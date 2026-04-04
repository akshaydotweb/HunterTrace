"""Middleware for logging, tracing, and error handling."""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from huntertrace.service.validators import InputValidator


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware to add request IDs to all requests."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add request ID to request and response."""
        request_id = str(uuid.uuid4())[:8]
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for structured logging."""

    def __init__(self, app):
        super().__init__(app)
        self.logger = logging.getLogger("huntertrace.service")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log request and response."""
        start_time = time.time()
        request_id = getattr(request.state, "request_id", "unknown")

        # Log request
        try:
            body = await request.body()
            self.logger.info(
                "Request",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "content_length": len(body),
                },
            )
        except Exception:
            pass

        # Call endpoint
        response = await call_next(request)

        # Log response
        duration_ms = (time.time() - start_time) * 1000
        self.logger.info(
            "Response",
            extra={
                "request_id": request_id,
                "status": response.status_code,
                "duration_ms": round(duration_ms, 2),
            },
        )

        return response


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Middleware for consistent error handling."""

    def __init__(self, app):
        super().__init__(app)
        self.logger = logging.getLogger("huntertrace.service")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Handle errors consistently."""
        request_id = getattr(request.state, "request_id", "unknown")

        try:
            response = await call_next(request)
            return response
        except ValueError as e:
            # Validation errors
            self.logger.warning(
                f"Validation error: {str(e)}",
                extra={"request_id": request_id},
            )
            return JSONResponse(
                status_code=400,
                content={
                    "error_code": "validation_error",
                    "message": str(e),
                    "request_id": request_id,
                    "details": [],
                },
            )
        except Exception as e:
            # Unexpected errors
            self.logger.error(
                f"Unexpected error: {str(e)}",
                extra={"request_id": request_id},
                exc_info=True,
            )
            return JSONResponse(
                status_code=500,
                content={
                    "error_code": "internal_error",
                    "message": "Internal server error",
                    "request_id": request_id,
                    "details": [],
                },
            )


def configure_logging(log_level: str = "INFO") -> None:
    """Configure structured logging for the service."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Reduce verbosity of external libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
