"""Pydantic schemas for API requests and responses."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class AnalysisOptions(BaseModel):
    """Configuration options for analysis request."""

    include_explainability: bool = True
    include_evaluation: bool = False
    include_adversarial: bool = False
    adversarial_samples_per_input: int = 1
    confidence_threshold: Optional[float] = None


class AnalyzeRequest(BaseModel):
    """Single email analysis request."""

    input_type: str = Field(
        ..., pattern="^(eml|raw)$", description="Email format: 'eml' or 'raw'"
    )
    content: str = Field(
        ..., min_length=1, max_length=10_000_000, description="Email content"
    )
    options: Optional[AnalysisOptions] = Field(
        default_factory=AnalysisOptions, description="Analysis options"
    )

    @field_validator("content")
    def validate_content_not_empty(cls, v):
        """Ensure content is not just whitespace."""
        if not v.strip():
            raise ValueError("content cannot be empty or whitespace-only")
        return v


class BatchRequest(BaseModel):
    """Batch analysis request."""

    inputs: List[AnalyzeRequest] = Field(
        ..., min_items=1, max_items=1000, description="List of emails to analyze"
    )


class MetadataResponse(BaseModel):
    """Metadata about the analysis."""

    processing_time_ms: float
    pipeline_version: str
    deterministic_hash: str
    input_size_bytes: int


class AnalyzeResponse(BaseModel):
    """Single email analysis response."""

    # Attribution result
    region: Optional[str] = None
    confidence: float
    verdict: str  # "attributed" | "inconclusive"
    consistency_score: float

    # Signal breakdown
    signals_used: List[Dict[str, Any]] = Field(default_factory=list)
    signals_rejected: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    reasoning: str = ""

    # Optional explainability
    explainability: Optional[Dict[str, Any]] = None

    # Optional evaluation
    evaluation: Optional[Dict[str, Any]] = None

    # Optional adversarial
    adversarial: Optional[Dict[str, Any]] = None

    # Metadata
    metadata: MetadataResponse


class BatchResponse(BaseModel):
    """Batch analysis response."""

    results: List[AnalyzeResponse]
    batch_processing_time_ms: float
    batch_size: int


class ErrorDetail(BaseModel):
    """Details about an error."""

    field: Optional[str] = None
    message: str
    code: str = "validation_error"


class ErrorResponse(BaseModel):
    """Standardized error response."""

    error_code: str
    message: str
    details: List[ErrorDetail] = Field(default_factory=list)
    request_id: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str
    uptime_seconds: float


class VersionResponse(BaseModel):
    """Version information."""

    version: str
    pipeline_version: str
    build_timestamp: str
    components: Dict[str, str]
