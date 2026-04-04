"""Observability scoring for Atlas signals."""

from __future__ import annotations

from typing import List

from huntertrace.parsing.models import ValidationFlag
from huntertrace.signals.models import EvidenceSignal, Observability


class ObservabilityScorer:
    """Compute deterministic observability score from chain and signal quality."""

    @staticmethod
    def score(chain, signals: List[EvidenceSignal]) -> Observability:
        hop_completeness = chain.completeness_score

        categories = set()
        for signal in signals:
            if signal.name.startswith("hop_from_"):
                categories.add("hosting")
            elif signal.name.startswith("hop_timestamp"):
                categories.add("temporal")
            elif signal.name.startswith("hop_protocol"):
                categories.add("transport")
            elif signal.name in {"hop_count", "chain_completeness_score", "chain_anomaly_count"}:
                categories.add("meta")
            else:
                categories.add("other")
        signal_diversity = min(1.0, len(categories) / 5.0) if signals else 0.0

        total_flags = sum(len(hop.validation_flags) for hop in chain.hops)
        severe_flags = sum(
            1
            for hop in chain.hops
            for flag in hop.validation_flags
            if flag in {ValidationFlag.BROKEN_CHAIN, ValidationFlag.INVALID_TIMESTAMP}
        )
        if total_flags == 0:
            signal_agreement = 1.0
        else:
            signal_agreement = max(0.0, 1.0 - (severe_flags / max(1.0, float(total_flags))))

        score = (0.45 * hop_completeness) + (0.25 * signal_diversity) + (0.30 * signal_agreement)
        return Observability(
            hop_completeness=round(hop_completeness, 4),
            signal_diversity=round(signal_diversity, 4),
            signal_agreement=round(signal_agreement, 4),
            score=round(max(0.0, min(1.0, score)), 4),
        )

