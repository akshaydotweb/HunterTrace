"""Main FastAPI application for HunterTrace Atlas service."""

from __future__ import annotations

import asyncio
import hmac
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request

from huntertrace.service.config import ServiceConfig
from huntertrace.service.middleware import (
    ErrorHandlingMiddleware,
    LoggingMiddleware,
    RequestIDMiddleware,
    configure_logging,
)
from huntertrace.service.orchestrator import PipelineOrchestrator
from huntertrace.service.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    AnalysisOptions,
    BatchRequest,
    BatchResponse,
    ErrorResponse,
    HealthResponse,
    MetadataResponse,
    VersionResponse,
)
from huntertrace.service.validators import InputValidator

logger = logging.getLogger("huntertrace.service")


class HunterTraceAPI:
    """HunterTrace Atlas FastAPI application."""

    def __init__(self, config: Optional[ServiceConfig] = None):
        """Initialize the API.

        Args:
            config: ServiceConfig instance (uses defaults if None)
        """
        self.config = config or ServiceConfig()
        self.app = FastAPI(
            title=self.config.title,
            description=self.config.description,
            version=self.config.version,
        )
        self.orchestrator = PipelineOrchestrator()
        self.start_time = time.time()
        # CRITICAL FIX #4: Thread pool for concurrent batch processing
        self.thread_pool = ThreadPoolExecutor(max_workers=4)

        # Configure logging
        configure_logging(self.config.log_level)

        # Add middleware
        self.app.add_middleware(ErrorHandlingMiddleware)
        self.app.add_middleware(LoggingMiddleware)
        self.app.add_middleware(RequestIDMiddleware)

        # Register endpoints
        self._register_endpoints()

    def _verify_api_key(self, authorization: Optional[str] = Header(None)) -> bool:
        """Verify API key if required with constant-time comparison.

        CRITICAL FIX #6: Uses hmac.compare_digest for constant-time comparison.
        """
        if not self.config.api_key_required:
            return True

        if not authorization:
            raise HTTPException(status_code=401, detail="Missing API key")

        # Extract bearer token
        try:
            scheme, token = authorization.split()
            if scheme.lower() != "bearer":
                raise HTTPException(status_code=401, detail="Invalid auth scheme")

            # CRITICAL FIX #6: Constant-time comparison prevents timing attacks
            valid = any(
                hmac.compare_digest(token, allowed_key)
                for allowed_key in self.config.allowed_api_keys
            )

            if not valid:
                raise HTTPException(status_code=403, detail="Invalid API key")
        except ValueError:
            raise HTTPException(status_code=401, detail="Malformed authorization header")

        return True

    def _register_endpoints(self) -> None:
        """Register all API endpoints."""

        @self.app.post("/analyze", response_model=AnalyzeResponse)
        async def analyze(
            request_data: AnalyzeRequest,
            request: Request,
            authorized: bool = Depends(self._verify_api_key),
        ) -> AnalyzeResponse:
            """Analyze a single email for origin attribution.

            Args:
                request_data: AnalyzeRequest with email content
                request: FastAPI Request object
                authorized: Authorization status from API key check

            Returns:
                AnalyzeResponse with attribution result and optional explainability

            Raises:
                HTTPException: If validation fails or analysis errors occur
            """
            request_id = getattr(request.state, "request_id", "unknown")

            try:
                # Validate request
                InputValidator.validate_request(request_data)

                # CRITICAL FIX #5: Enforce timeout using asyncio.wait_for
                try:
                    result = await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(
                            self.thread_pool,
                            lambda: self.orchestrator.run_full_analysis(
                                input_content=request_data.content,
                                input_type=request_data.input_type,
                                # CRITICAL FIX #8: Remove evaluation/adversarial from /analyze
                                options=AnalysisOptions(
                                    include_explainability=request_data.options.include_explainability if request_data.options else True,
                                    include_evaluation=False,  # Use separate endpoint
                                    include_adversarial=False,  # Use separate endpoint
                                ),
                            ),
                        ),
                        timeout=self.config.request_timeout_seconds,
                    )
                except asyncio.TimeoutError:
                    # CRITICAL FIX #3: Structured error with stage info
                    logger.error(f"Request timeout: {request_id}")
                    raise HTTPException(
                        status_code=408,
                        detail={
                            "error_code": "timeout_error",
                            "message": "Analysis exceeded timeout",
                            "request_id": request_id,
                            "details": [{"stage": "pipeline", "message": f"Timeout after {self.config.request_timeout_seconds}s"}],
                        },
                    )

                # Convert to response model
                return AnalyzeResponse(**result)

            except ValueError as e:
                # CRITICAL FIX #3: Structured error with field detail
                logger.warning(f"Validation error [{request_id}]: {str(e)}")
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error_code": "validation_error",
                        "message": "Input validation failed",
                        "request_id": request_id,
                        "details": [{"field": "content", "message": str(e), "code": "validation_error"}],
                    },
                )
            except HTTPException:
                raise
            except Exception as e:
                # CRITICAL FIX #3: Structured error with stage and error type
                logger.error(f"Analysis error [{request_id}]: {str(e)}", exc_info=True)
                raise HTTPException(
                    status_code=500,
                    detail={
                        "error_code": "pipeline_failure",
                        "message": "Internal analysis error",
                        "request_id": request_id,
                        "details": [{"stage": "pipeline", "message": "Unexpected error during analysis", "code": type(e).__name__}],
                    },
                )

        @self.app.post("/batch", response_model=BatchResponse)
        async def batch(
            request_data: BatchRequest,
            request: Request,
            authorized: bool = Depends(self._verify_api_key),
        ) -> BatchResponse:
            """Analyze multiple emails in a single batch request.

            Args:
                request_data: BatchRequest with list of emails
                request: FastAPI Request object
                authorized: Authorization status

            Returns:
                BatchResponse with list of results

            Raises:
                HTTPException: If batch size exceeds limit or other errors occur
            """
            request_id = getattr(request.state, "request_id", "unknown")

            if len(request_data.inputs) > self.config.max_batch_size:
                raise HTTPException(
                    status_code=400,
                    detail=f"Batch size exceeds maximum ({len(request_data.inputs)} > {self.config.max_batch_size})",
                )

            batch_start = time.time()

            # CRITICAL FIX #4: Concurrent batch processing using async/await
            async def process_item(item: AnalyzeRequest) -> AnalyzeResponse:
                """Process a single item with timeout."""
                try:
                    InputValidator.validate_request(item)

                    # Use thread pool executor for CPU-bound work
                    try:
                        result = await asyncio.wait_for(
                            asyncio.get_event_loop().run_in_executor(
                                self.thread_pool,
                                lambda: self.orchestrator.run_full_analysis(
                                    input_content=item.content,
                                    input_type=item.input_type,
                                    options=AnalysisOptions(
                                        include_explainability=item.options.include_explainability if item.options else True,
                                        include_evaluation=False,
                                        include_adversarial=False,
                                    ),
                                ),
                            ),
                            timeout=self.config.request_timeout_seconds,
                        )
                        return AnalyzeResponse(**result)
                    except asyncio.TimeoutError:
                        return AnalyzeResponse(
                            region=None,
                            confidence=0.0,
                            verdict="error",
                            consistency_score=0.0,
                            reasoning="Analysis timeout",
                            metadata=MetadataResponse(
                                processing_time_ms=0,
                                pipeline_version=PipelineOrchestrator.PIPELINE_VERSION,
                                deterministic_hash="",
                                input_size_bytes=len(item.content.encode("utf-8")),
                            ),
                        )
                except ValueError as e:
                    return AnalyzeResponse(
                        region=None,
                        confidence=0.0,
                        verdict="error",
                        consistency_score=0.0,
                        reasoning=f"Validation error: {str(e)}",
                        metadata=MetadataResponse(
                            processing_time_ms=0,
                            pipeline_version=PipelineOrchestrator.PIPELINE_VERSION,
                            deterministic_hash="",
                            input_size_bytes=len(item.content.encode("utf-8")),
                        ),
                    )
                except Exception as e:
                    logger.error(f"Batch item error: {str(e)}", exc_info=True)
                    return AnalyzeResponse(
                        region=None,
                        confidence=0.0,
                        verdict="error",
                        consistency_score=0.0,
                        reasoning=f"Processing error: {type(e).__name__}",
                        metadata=MetadataResponse(
                            processing_time_ms=0,
                            pipeline_version=PipelineOrchestrator.PIPELINE_VERSION,
                            deterministic_hash="",
                            input_size_bytes=len(item.content.encode("utf-8")),
                        ),
                    )

            # Process all items concurrently
            results = await asyncio.gather(
                *[process_item(item) for item in request_data.inputs]
            )

            batch_time_ms = (time.time() - batch_start) * 1000

            return BatchResponse(
                results=results,
                batch_processing_time_ms=batch_time_ms,
                batch_size=len(request_data.inputs),
            )

        @self.app.get("/health", response_model=HealthResponse)
        def health() -> HealthResponse:
            """Health check endpoint."""
            uptime = time.time() - self.start_time
            return HealthResponse(
                status="ok",
                version=self.config.version,
                uptime_seconds=uptime,
            )

        @self.app.get("/version", response_model=VersionResponse)
        def version() -> VersionResponse:
            """Get version information."""
            return VersionResponse(
                version=self.config.version,
                pipeline_version=PipelineOrchestrator.PIPELINE_VERSION,
                build_timestamp=datetime.utcnow().isoformat(),
                components={
                    "parsing": "1.0",
                    "signals": "1.0",
                    "correlation": "1.0",
                    "scoring": "1.0",
                    "explainability": "1.0",
                    "evaluation": "1.0",
                    "adversarial": "1.0",
                },
            )

        @self.app.get("/config")
        def get_config() -> dict:
            """Get service configuration (non-sensitive parts)."""
            return {
                "version": self.config.version,
                "max_batch_size": self.config.max_batch_size,
                "max_request_size_mb": self.config.max_request_size_mb,
                "request_timeout_seconds": self.config.request_timeout_seconds,
                "features": {
                    "explainability": self.config.enable_explainability,
                },
            }

        @self.app.options("/{path:path}")
        def options() -> dict:
            """Handle CORS preflight requests."""
            return {}

    def get_app(self) -> FastAPI:
        """Get the FastAPI application instance."""
        return self.app


def create_app(config: Optional[ServiceConfig] = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        config: Optional ServiceConfig

    Returns:
        Configured FastAPI application
    """
    api = HunterTraceAPI(config)
    return api.get_app()
