"""Signal construction from parsed hop chains."""

from __future__ import annotations

from typing import List, Tuple

from huntertrace.parsing.models import HopChain, ValidationFlag
from huntertrace.signals.models import EvidenceSignal, RejectedSignal

_RESEARCH_REF = "RFC 5321 Received trace fields + RFC 5322 header format"


class SignalBuilder:
    """Build deterministic evidence signals from parsed hop chain artifacts."""

    @staticmethod
    def build(chain: HopChain) -> Tuple[List[EvidenceSignal], List[RejectedSignal]]:
        signals: List[EvidenceSignal] = []
        rejected: List[RejectedSignal] = []

        for hop in chain.hops:
            source = f"Received[{hop.index}]"
            raw_ref = hop.raw_header

            SignalBuilder._emit(
                signals=signals,
                rejected=rejected,
                name="hop_from_host",
                value=hop.from_host,
                source=source,
                extraction_method="Regex-based extraction from Received from-clause",
                raw_reference=raw_ref,
                confidence=SignalBuilder._confidence_for_hop(hop),
                validation_basis="Hostname token validation + structural checks",
                reason_if_missing="from_host missing or not extractable",
            )
            SignalBuilder._emit(
                signals=signals,
                rejected=rejected,
                name="hop_from_ip",
                value=hop.from_ip,
                source=source,
                extraction_method="IPv4/IPv6 extraction from Received from-segment",
                raw_reference=raw_ref,
                confidence=SignalBuilder._confidence_for_hop(hop),
                validation_basis="IP token parse + chain context",
                reason_if_missing="from_ip missing or not extractable",
            )
            SignalBuilder._emit(
                signals=signals,
                rejected=rejected,
                name="hop_by_host",
                value=hop.by_host,
                source=source,
                extraction_method="Regex-based extraction from Received by-clause",
                raw_reference=raw_ref,
                confidence=SignalBuilder._confidence_for_hop(hop),
                validation_basis="Hostname token validation + continuity checks",
                reason_if_missing="by_host missing or not extractable",
            )
            SignalBuilder._emit(
                signals=signals,
                rejected=rejected,
                name="hop_protocol",
                value=hop.protocol,
                source=source,
                extraction_method="Token extraction from Received with-clause",
                raw_reference=raw_ref,
                confidence=SignalBuilder._confidence_for_hop(hop),
                validation_basis="Protocol token parsing only",
                reason_if_missing="protocol missing in with-clause",
            )
            SignalBuilder._emit(
                signals=signals,
                rejected=rejected,
                name="hop_timestamp_utc",
                value=hop.timestamp.isoformat() if hop.timestamp else None,
                source=source,
                extraction_method="RFC datetime parse and UTC normalization",
                raw_reference=raw_ref,
                confidence=SignalBuilder._confidence_for_hop(hop),
                validation_basis="Temporal ordering + timestamp parse checks",
                reason_if_missing="timestamp missing or invalid",
            )

        signals.append(
            EvidenceSignal(
                name="hop_count",
                value=len(chain.hops),
                source="hop_chain",
                extraction_method="Count of parsed Received hops",
                raw_reference="derived",
                confidence_initial=1.0,
                validation_basis="Deterministic list cardinality",
                research_reference=_RESEARCH_REF,
            )
        )
        signals.append(
            EvidenceSignal(
                name="chain_completeness_score",
                value=chain.completeness_score,
                source="hop_chain",
                extraction_method="Deterministic completeness formula",
                raw_reference="derived",
                confidence_initial=1.0,
                validation_basis="Field coverage + anomaly penalty",
                research_reference=_RESEARCH_REF,
            )
        )
        signals.append(
            EvidenceSignal(
                name="chain_anomaly_count",
                value=len(chain.anomalies),
                source="hop_chain",
                extraction_method="Count of validation anomalies",
                raw_reference="derived",
                confidence_initial=1.0,
                validation_basis="Structural + temporal validator output",
                research_reference=_RESEARCH_REF,
            )
        )
        if chain.anomalies:
            signals.append(
                EvidenceSignal(
                    name="anomaly_types",
                    value=sorted(
                        {
                            item.split()[0]
                            for item in chain.anomalies
                            if item and item[0].isalpha()
                        }
                    ),
                    source="hop_chain",
                    extraction_method="Prefix extraction from anomaly records",
                    raw_reference="derived",
                    confidence_initial=0.8,
                    validation_basis="Validator anomaly text",
                    research_reference=_RESEARCH_REF,
                )
            )

        return signals, rejected

    @staticmethod
    def _emit(
        *,
        signals: List[EvidenceSignal],
        rejected: List[RejectedSignal],
        name: str,
        value,
        source: str,
        extraction_method: str,
        raw_reference: str,
        confidence: float,
        validation_basis: str,
        reason_if_missing: str,
    ) -> None:
        if value in (None, ""):
            rejected.append(
                RejectedSignal(
                    name=name,
                    source=source,
                    reason=reason_if_missing,
                    raw_reference=raw_reference,
                )
            )
            return

        signals.append(
            EvidenceSignal(
                name=name,
                value=value,
                source=source,
                extraction_method=extraction_method,
                raw_reference=raw_reference,
                confidence_initial=round(confidence, 4),
                validation_basis=validation_basis,
                research_reference=_RESEARCH_REF,
            )
        )

    @staticmethod
    def _confidence_for_hop(hop) -> float:
        penalty = 0.0
        if ValidationFlag.MALFORMED_HEADER in hop.validation_flags:
            penalty += 0.2
        if ValidationFlag.BROKEN_CHAIN in hop.validation_flags:
            penalty += 0.15
        if ValidationFlag.INVALID_TIMESTAMP in hop.validation_flags:
            penalty += 0.2
        if ValidationFlag.TEMPORAL_ANOMALY in hop.validation_flags:
            penalty += 0.1
        value = max(0.0, min(1.0, hop.parse_confidence - penalty))
        return value

