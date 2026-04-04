"""Structural and temporal validation for reconstructed hop chains."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import List

from huntertrace.parsing.models import Hop, ValidationFlag
from huntertrace.parsing.utils import hostname_approx_equal


class HopValidators:
    """Apply deterministic chain integrity checks."""

    @staticmethod
    def validate_structural(hops: List[Hop]) -> List[str]:
        """Validate host linkage, duplicate hops, and suspicious structural patterns."""

        anomalies: List[str] = []

        for idx in range(len(hops) - 1):
            current = hops[idx]
            nxt = hops[idx + 1]
            if current.by_host and nxt.from_host:
                if not hostname_approx_equal(current.by_host, nxt.from_host):
                    current.validation_flags.append(ValidationFlag.BROKEN_CHAIN)
                    nxt.validation_flags.append(ValidationFlag.BROKEN_CHAIN)
                    anomalies.append(
                        f"BROKEN_CHAIN between hop {current.index} by={current.by_host} and "
                        f"hop {nxt.index} from={nxt.from_host}"
                    )
            else:
                current.validation_flags.append(ValidationFlag.MISSING_FIELDS)
                nxt.validation_flags.append(ValidationFlag.MISSING_FIELDS)
                anomalies.append(
                    f"MISSING_FIELDS for continuity check between hop {current.index} and hop {nxt.index}"
                )

        signature_counts = Counter(
            (
                hop.from_host or "",
                hop.from_ip or "",
                hop.by_host or "",
                hop.protocol or "",
                hop.timestamp.isoformat() if hop.timestamp else "",
            )
            for hop in hops
        )
        for signature, count in signature_counts.items():
            if count > 1:
                anomalies.append(f"POSSIBLE_INJECTION duplicate hop signature count={count}")
                for hop in hops:
                    hop_sig = (
                        hop.from_host or "",
                        hop.from_ip or "",
                        hop.by_host or "",
                        hop.protocol or "",
                        hop.timestamp.isoformat() if hop.timestamp else "",
                    )
                    if hop_sig == signature:
                        hop.validation_flags.append(ValidationFlag.POSSIBLE_INJECTION)

        host_counter = Counter((hop.from_host or "").lower() for hop in hops if hop.from_host)
        for host, count in host_counter.items():
            if count >= 3:
                anomalies.append(f"POSSIBLE_INJECTION repeated from_host={host} count={count}")
                for hop in hops:
                    if (hop.from_host or "").lower() == host:
                        hop.validation_flags.append(ValidationFlag.POSSIBLE_INJECTION)

        return anomalies

    @staticmethod
    def validate_temporal(hops: List[Hop], max_jump_hours: int = 72) -> List[str]:
        """Validate monotonic timestamp progression and unrealistic inter-hop deltas."""

        anomalies: List[str] = []
        max_jump = timedelta(hours=max_jump_hours)

        for idx in range(len(hops) - 1):
            current = hops[idx]
            nxt = hops[idx + 1]

            if current.timestamp is None or nxt.timestamp is None:
                if current.timestamp is None:
                    current.validation_flags.append(ValidationFlag.INVALID_TIMESTAMP)
                if nxt.timestamp is None:
                    nxt.validation_flags.append(ValidationFlag.INVALID_TIMESTAMP)
                continue

            delta = nxt.timestamp - current.timestamp
            if delta.total_seconds() < 0:
                current.validation_flags.append(ValidationFlag.INVALID_TIMESTAMP)
                nxt.validation_flags.append(ValidationFlag.INVALID_TIMESTAMP)
                anomalies.append(
                    f"INVALID_TIMESTAMP non-monotonic timestamps between hop {current.index} and hop {nxt.index}"
                )
            elif delta.total_seconds() == 0:
                current.validation_flags.append(ValidationFlag.TEMPORAL_ANOMALY)
                nxt.validation_flags.append(ValidationFlag.TEMPORAL_ANOMALY)
                anomalies.append(
                    f"TEMPORAL_ANOMALY identical timestamps between hop {current.index} and hop {nxt.index}"
                )
            elif delta > max_jump:
                current.validation_flags.append(ValidationFlag.TEMPORAL_ANOMALY)
                nxt.validation_flags.append(ValidationFlag.TEMPORAL_ANOMALY)
                anomalies.append(
                    f"TEMPORAL_ANOMALY unrealistic time jump {delta} between hop {current.index} and hop {nxt.index}"
                )

        return anomalies

    @staticmethod
    def deduplicate_flags(hops: List[Hop]) -> None:
        """Deduplicate validation flags while preserving deterministic order."""

        order = {flag: idx for idx, flag in enumerate(ValidationFlag)}
        for hop in hops:
            hop.validation_flags = sorted(set(hop.validation_flags), key=lambda item: order[item])
