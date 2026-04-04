"""Service configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ServiceConfig:
    """Configuration for HunterTrace API service."""

    # Server settings
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    reload: bool = False

    # API settings
    title: str = "HunterTrace Atlas API"
    description: str = "Secure email origin attribution service"
    version: str = "1.0.0"

    # Request handling
    max_request_size_mb: int = 10
    request_timeout_seconds: float = 30.0
    max_batch_size: int = 1000

    # Analysis settings
    enable_explainability: bool = True
    enable_evaluation: bool = False
    enable_adversarial: bool = False
    adversarial_samples_per_input: int = 1

    # Logging
    log_level: str = "INFO"
    log_requests: bool = True
    mask_sensitive_data: bool = True

    # Security
    rate_limit_enabled: bool = False
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    api_key_required: bool = False
    allowed_api_keys: list[str] = field(default_factory=list)

    # Performance
    pipeline_cache_enabled: bool = False
    determinism_hash_enabled: bool = True

    @classmethod
    def from_env(cls) -> ServiceConfig:
        """Load configuration from environment variables."""
        import os

        return cls(
            host=os.getenv("HUNTERTRACE_HOST", "0.0.0.0"),
            port=int(os.getenv("HUNTERTRACE_PORT", 8000)),
            workers=int(os.getenv("HUNTERTRACE_WORKERS", 4)),
            reload=os.getenv("HUNTERTRACE_RELOAD", "false").lower() == "true",
            max_request_size_mb=int(os.getenv("HUNTERTRACE_MAX_REQUEST_MB", 10)),
            request_timeout_seconds=float(os.getenv("HUNTERTRACE_TIMEOUT_SECONDS", 30.0)),
            enable_explainability=os.getenv("HUNTERTRACE_ENABLE_EXPLAINABILITY", "true").lower()
            == "true",
            enable_evaluation=os.getenv("HUNTERTRACE_ENABLE_EVALUATION", "false").lower()
            == "true",
            enable_adversarial=os.getenv("HUNTERTRACE_ENABLE_ADVERSARIAL", "false").lower()
            == "true",
            log_level=os.getenv("HUNTERTRACE_LOG_LEVEL", "INFO"),
            log_requests=os.getenv("HUNTERTRACE_LOG_REQUESTS", "true").lower() == "true",
            api_key_required=os.getenv("HUNTERTRACE_API_KEY_REQUIRED", "false").lower()
            == "true",
            allowed_api_keys=os.getenv("HUNTERTRACE_API_KEYS", "").split(",")
            if os.getenv("HUNTERTRACE_API_KEYS")
            else [],
        )

    @classmethod
    def from_file(cls, path: str) -> ServiceConfig:
        """Load configuration from YAML file."""
        import yaml

        with open(path) as f:
            config_data = yaml.safe_load(f) or {}

        return cls(**config_data)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "host": self.host,
            "port": self.port,
            "workers": self.workers,
            "reload": self.reload,
            "title": self.title,
            "version": self.version,
            "max_request_size_mb": self.max_request_size_mb,
            "request_timeout_seconds": self.request_timeout_seconds,
            "max_batch_size": self.max_batch_size,
            "enable_explainability": self.enable_explainability,
            "enable_evaluation": self.enable_evaluation,
            "enable_adversarial": self.enable_adversarial,
            "log_level": self.log_level,
            "log_requests": self.log_requests,
            "mask_sensitive_data": self.mask_sensitive_data,
        }
