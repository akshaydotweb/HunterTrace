#!/usr/bin/env python3
"""
huntertrace/core/models/evidence.py
=====================================
Layer 0 — Ingestion data models.

EvidenceEnvelope is the immutable chain-of-custody anchor for every
analysis run.  It is produced once at ingestion and referenced by every
downstream artifact via evidence_id.  It is frozen: no field may be
modified after construction.

Design constraints (per Phase 1 architecture spec):
  - Frozen dataclass (immutable after construction)
  - raw_bytes carried as bytes — never a str, never decoded here
  - sha256 computed externally and passed in; this model does NOT compute it
    (computing a hash is logic, not a data model responsibility)
  - All timestamps are ISO 8601 UTC strings; datetime objects are NOT used
    here to avoid tz-awareness ambiguity at the model boundary
  - No external dependencies
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
#  LAYER 0 — INGESTION
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class EvidenceEnvelope:
    """
    Immutable chain-of-custody wrapper produced at ingestion (Layer 0).

    Every downstream layer artifact references evidence_id to maintain
    an unbroken chain of custody from raw input to final verdict.

    Fields
    ------
    evidence_id : str
        UUID4 string assigned at ingestion.  Unique per analysis run.

    sha256 : str
        Lowercase hex SHA-256 digest of raw_bytes.  Computed by the
        ingestion layer before constructing this envelope; stored here
        for downstream verification.

    raw_bytes : bytes
        Verbatim content of the input email.  Never decoded, never
        modified.  Downstream layers operate on parsed copies; this
        field is the forensic reference copy.

    source_path : Optional[str]
        Original filesystem path of the input file, if applicable.
        Informational only — not used for any computation.
        None when email is supplied as a byte stream.

    source_type : str
        How the email was supplied: "file" | "stream" | "api" | "stdin".

    received_at : str
        ISO 8601 UTC timestamp at which this envelope was created.
        Format: "YYYY-MM-DDTHH:MM:SS.ffffffZ"

    analyst_id : Optional[str]
        Identifier of the analyst or automated process that initiated
        this analysis run.  Used for audit trail only.

    pipeline_version : str
        Version string of the HunterTrace pipeline that created this
        envelope.  Format: semver, e.g. "2.0.0".

    config_digest : str
        SHA-256 hex digest of the combined configuration files active
        during this run.  Enables exact reproduction of results by
        specifying the same config_digest.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    evidence_id:      str
    sha256:           str

    # ── Raw evidence (immutable forensic reference copy) ─────────────────────
    raw_bytes:        bytes

    # ── Provenance ────────────────────────────────────────────────────────────
    source_path:      Optional[str]
    source_type:      str           # "file" | "stream" | "api" | "stdin"
    received_at:      str           # ISO 8601 UTC

    # ── Audit trail ───────────────────────────────────────────────────────────
    analyst_id:       Optional[str]
    pipeline_version: str
    config_digest:    str


@dataclass(frozen=True)
class CustodyEvent:
    """
    Single entry in a ForensicReport's chain_of_custody list.

    One CustodyEvent is appended each time a layer transforms an artifact.
    The complete list forms an auditable record of every transformation
    applied to the evidence from ingestion to final output.

    Fields
    ------
    event_id : str
        UUID4 string unique to this custody event.

    timestamp : str
        ISO 8601 UTC timestamp at which this transformation occurred.

    layer : int
        Pipeline layer number (0–6) that produced this event.

    module : str
        Dotted module path of the code that performed the transformation.
        Example: "huntertrace.extraction.email_parser"

    action : str
        Short description of the transformation performed.
        Example: "parse_received_headers"

    input_artifact_id : str
        ID of the input artifact consumed (evidence_id or a layer-specific
        artifact UUID).

    output_artifact_id : str
        ID of the output artifact produced.

    input_sha256 : Optional[str]
        SHA-256 of the serialised input artifact, if computed.
        Enables detecting unexpected mutation between layers.

    output_sha256 : Optional[str]
        SHA-256 of the serialised output artifact, if computed.

    notes : Optional[str]
        Free-text analyst notes or automated warnings attached to
        this custody event.
    """

    event_id:           str
    timestamp:          str           # ISO 8601 UTC
    layer:              int           # 0–6
    module:             str
    action:             str
    input_artifact_id:  str
    output_artifact_id: str
    input_sha256:       Optional[str]
    output_sha256:      Optional[str]
    notes:              Optional[str]

