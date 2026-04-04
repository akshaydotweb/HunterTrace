"""Hop-chain reconstruction and completeness scoring."""

from __future__ import annotations

from typing import List

from huntertrace.parsing.models import Hop, HopChain
from huntertrace.parsing.received_parser import ReceivedParser
from huntertrace.parsing.validators import HopValidators


class HopChainBuilder:
    """Build validated bottom-up hop chains from top-down Received headers."""

    @staticmethod
    def build(received_headers: List[str]) -> HopChain:
        """Reconstruct chain (earliest visible first), validate, and score completeness."""

        # Received headers are observed top-down; reverse for earliest visible hop first.
        ordered_headers = list(reversed(received_headers))

        hops: List[Hop] = []
        for idx, raw_header in enumerate(ordered_headers):
            hop = ReceivedParser.parse_received(raw_header, index=idx)
            hops.append(hop)

        anomalies: List[str] = []
        anomalies.extend(HopValidators.validate_structural(hops))
        anomalies.extend(HopValidators.validate_temporal(hops))
        HopValidators.deduplicate_flags(hops)

        score = HopChainBuilder._completeness_score(hops, anomalies)
        return HopChain(hops=hops, anomalies=sorted(set(anomalies)), completeness_score=score)

    @staticmethod
    def _completeness_score(hops: List[Hop], anomalies: List[str]) -> float:
        if not hops:
            return 0.0

        field_total = len(hops) * 5.0
        extracted_fields = 0.0
        valid_hops = 0.0

        for hop in hops:
            extracted_fields += 1.0 if hop.from_host else 0.0
            extracted_fields += 1.0 if hop.from_ip else 0.0
            extracted_fields += 1.0 if hop.by_host else 0.0
            extracted_fields += 1.0 if hop.protocol else 0.0
            extracted_fields += 1.0 if hop.timestamp else 0.0
            if hop.parse_confidence >= 0.6:
                valid_hops += 1.0

        extraction_ratio = extracted_fields / field_total
        valid_ratio = valid_hops / len(hops)

        anomaly_penalty = min(0.5, len(anomalies) * 0.05)
        score = (0.6 * extraction_ratio) + (0.4 * valid_ratio) - anomaly_penalty

        if score < 0.0:
            return 0.0
        if score > 1.0:
            return 1.0
        return round(score, 4)

