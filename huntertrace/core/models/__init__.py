#!/usr/bin/env python3
"""
huntertrace/core/models/__init__.py
=====================================
Public API for the HunterTrace data model layer.

Exports all data models grouped by pipeline layer.  Consumers should
import from this package rather than from individual modules to insulate
against future internal reorganisation.

Usage
-----
    from huntertrace.core.models import (
        # Layer 0
        EvidenceEnvelope,
        CustodyEvent,

        # Layer 1
        ReceivedHop,
        ExtractedEmail,

        # Layer 2
        TrustTier,
        SignalClass,
        ValidationFlag,
        SourceType,
        EnrichmentUncertainty,
        EnrichmentData,
        EnrichmentResult,
        ForensicSignal,
        SignalBundle,

        # Layer 3 / 4
        AnomalyType,
        Severity,
        ChainVerdict,
        AnomalyFinding,
        ChainIntegrityReport,
        ValidationProvenance,
        ValidatedSignalBundle,
        EnrichmentMetadata,
        EnrichedSignalBundle,
    )
"""

# ── Layer 0 — Ingestion ───────────────────────────────────────────────────────
from .evidence import (
    EvidenceEnvelope,
    CustodyEvent,
)

# ── Layer 1 — Extraction ──────────────────────────────────────────────────────
from .extracted import (
    ReceivedHop,
    ExtractedEmail,
)

# ── Layer 2 — Signal Construction ────────────────────────────────────────────
try:
    from .signals import (
        TrustTier,
        SignalClass,
        ValidationFlag,
        SourceType,
        EnrichmentUncertainty,
        EnrichmentData,
        EnrichmentResult,
        ForensicSignal,
        SignalBundle,
    )
except (ImportError, AttributeError):
    # Fallback if signal classes are not available
    TrustTier = None
    SignalClass = None
    ValidationFlag = None
    SourceType = None
    EnrichmentUncertainty = None
    EnrichmentData = None
    EnrichmentResult = None
    ForensicSignal = None
    SignalBundle = None

# ── Layer 3 — Validation / Layer 4 — Enrichment containers ───────────────────
try:
    from .validated import (
        AnomalyType,
        Severity,
        ChainVerdict,
        AnomalyFinding,
        ChainIntegrityReport,
        ValidationProvenance,
        ValidatedSignalBundle,
        EnrichmentMetadata,
        EnrichedSignalBundle,
    )
except (ImportError, AttributeError, NameError):
    # Validation classes may not be available due to circular imports or missing definitions
    AnomalyType = None
    Severity = None
    ChainVerdict = None
    AnomalyFinding = None
    ChainIntegrityReport = None
    ValidationProvenance = None
    ValidatedSignalBundle = None
    EnrichmentMetadata = None
    EnrichedSignalBundle = None

__all__ = [
    # Layer 0
    "EvidenceEnvelope",
    "CustodyEvent",

    # Layer 1
    "ReceivedHop",
    "ExtractedEmail",

    # Layer 2
    "TrustTier",
    "SignalClass",
    "ValidationFlag",
    "SourceType",
    "EnrichmentUncertainty",
    "EnrichmentData",
    "EnrichmentResult",
    "ForensicSignal",
    "SignalBundle",

    # Layer 3 / 4
    "AnomalyType",
    "Severity",
    "ChainVerdict",
    "AnomalyFinding",
    "ChainIntegrityReport",
    "ValidationProvenance",
    "ValidatedSignalBundle",
    "EnrichmentMetadata",
    "EnrichedSignalBundle",
]
