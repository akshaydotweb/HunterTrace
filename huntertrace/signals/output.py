"""Atlas audit-ready output assembly."""

from __future__ import annotations

from typing import List

from huntertrace.parsing import AtlasHeaderPipeline
from huntertrace.signals.builder import SignalBuilder
from huntertrace.signals.models import AtlasAuditResult, TechniqueApplication
from huntertrace.signals.quality import ObservabilityScorer

_LIMITATIONS = [
    "Cannot trace origin through VPN/Tor from headers alone.",
    "Cannot recover missing SMTP hops not present in visible headers.",
    "Attacker-controlled headers may be forged and cannot be fully verified without external logs.",
]


class AtlasSignalPipeline:
    """Compose parser + signal layer into an auditable Atlas output."""

    @staticmethod
    def from_eml(path: str) -> AtlasAuditResult:
        chain = AtlasHeaderPipeline.parse_eml_file(path)
        return AtlasSignalPipeline.from_chain(chain)

    @staticmethod
    def from_header_text(raw_email_or_headers: str) -> AtlasAuditResult:
        chain = AtlasHeaderPipeline.parse_header_string(raw_email_or_headers)
        return AtlasSignalPipeline.from_chain(chain)

    @staticmethod
    def from_chain(chain) -> AtlasAuditResult:
        signals_used, signals_rejected = SignalBuilder.build(chain)
        observability = ObservabilityScorer.score(chain, signals_used)
        techniques = AtlasSignalPipeline._techniques_for_chain(chain)

        confidence = AtlasSignalPipeline._confidence_from_observability(
            observability.score, anomaly_count=len(chain.anomalies)
        )
        verdict = AtlasSignalPipeline._verdict_from_chain(chain, observability.score)

        evidence_sources: List[str] = [f"Received[{hop.index}]" for hop in chain.hops]
        evidence_sources.extend(
            [
                "RFC 5321 (SMTP Received trace semantics)",
                "RFC 5322 (Internet Message Format and header folding)",
            ]
        )

        return AtlasAuditResult(
            region="undetermined",
            confidence=confidence,
            verdict=verdict,
            observability_score=observability.score,
            signals_used=signals_used,
            signals_rejected=signals_rejected,
            techniques_applied=techniques,
            evidence_sources=evidence_sources,
            limitations=list(_LIMITATIONS),
        )

    @staticmethod
    def _techniques_for_chain(chain) -> List[TechniqueApplication]:
        techniques: List[TechniqueApplication] = [
            TechniqueApplication(
                name="timestamp_monotonicity",
                technique="Temporal consistency analysis",
                evidence=[item for item in chain.anomalies if "TIMESTAMP" in item or "TEMPORAL" in item]
                or ["No timestamp anomaly detected"],
                result="anomaly" if any("TIMESTAMP" in item or "TEMPORAL" in item for item in chain.anomalies) else "pass",
                confidence_impact=-0.15
                if any("TIMESTAMP" in item or "TEMPORAL" in item for item in chain.anomalies)
                else 0.05,
            ),
            TechniqueApplication(
                name="hop_linkage_validation",
                technique="Hop-chain structural analysis",
                evidence=[item for item in chain.anomalies if "BROKEN_CHAIN" in item]
                or ["No broken chain anomaly detected"],
                result="anomaly" if any("BROKEN_CHAIN" in item for item in chain.anomalies) else "pass",
                confidence_impact=-0.2 if any("BROKEN_CHAIN" in item for item in chain.anomalies) else 0.05,
            ),
            TechniqueApplication(
                name="header_malformed_detection",
                technique="RFC-aware header parsing integrity check",
                evidence=[item for item in chain.anomalies if "MALFORMED" in item]
                or ["Malformed token checks are evaluated at hop level flags"],
                result="anomaly"
                if any("MALFORMED" in item for item in chain.anomalies)
                else "pass_or_unknown",
                confidence_impact=-0.1 if any("MALFORMED" in item for item in chain.anomalies) else 0.0,
            ),
        ]
        return techniques

    @staticmethod
    def _confidence_from_observability(observability_score: float, anomaly_count: int) -> float:
        penalty = min(0.35, anomaly_count * 0.03)
        return round(max(0.0, min(1.0, observability_score - penalty)), 4)

    @staticmethod
    def _verdict_from_chain(chain, observability_score: float) -> str:
        if not chain.hops:
            return "insufficient-evidence"
        if observability_score < 0.45:
            return "low-observability"
        if chain.anomalies:
            return "anomalous-header-chain"
        return "structurally-consistent-header-chain"

