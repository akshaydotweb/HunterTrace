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
from .signal import (
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

# ── Layer 3 — Validation / Layer 4 — Enrichment containers ───────────────────
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
