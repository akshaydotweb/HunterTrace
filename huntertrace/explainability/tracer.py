"""Evidence tracer for linking signals to hops and raw headers."""

from __future__ import annotations

from typing import Dict, List, Optional

from huntertrace.analysis.models import Signal
from huntertrace.explainability.models import EvidenceLink
from huntertrace.parsing.models import HopChain


class EvidenceTracer:
    """Traces evidence from decisions through signals to raw headers."""

    def __init__(self, hop_chain: HopChain | None = None):
        """
        Initialize tracer with optional hop chain for full traceability.

        Args:
            hop_chain: HopChain for mapping signals to raw headers (optional)
        """
        self.hop_chain = hop_chain

    def trace_evidence(
        self,
        signals: List[Signal],
        hop_indices: Dict[str, List[int]] | None = None,
    ) -> List[EvidenceLink]:
        """
        Build evidence links from signals to hops.

        Args:
            signals: List of signals used in attribution
            hop_indices: Optional mapping of signal_id to hop indices

        Returns:
            List of EvidenceLink objects, sorted deterministically
        """
        links = []

        for signal in signals:
            # Skip signals without evidence hops
            if not signal.evidence:
                continue

            # Find corresponding hops
            signal_hop_indices = hop_indices.get(signal.signal_id, []) if hop_indices else []

            # If no explicit mapping, try to infer from signal evidence
            if not signal_hop_indices and self.hop_chain:
                signal_hop_indices = self._infer_hop_indices(signal)

            # Create links for each hop
            for hop_idx in signal_hop_indices:
                if self.hop_chain and 0 <= hop_idx < len(self.hop_chain.hops):
                    hop = self.hop_chain.hops[hop_idx]
                    link = EvidenceLink(
                        signal_id=signal.signal_id,
                        signal_name=signal.name,
                        hop_index=hop_idx,
                        hop_from_ip=hop.from_ip,
                        hop_from_host=hop.from_host,
                        raw_header_snippet=self._extract_snippet(hop.raw_header),
                        extracted_fields=self._extract_fields(hop),
                    )
                    links.append(link)

        # Sort deterministically by signal_id, then hop_index
        links.sort(key=lambda x: (x.signal_id, x.hop_index))
        return links

    def _infer_hop_indices(self, signal: Signal) -> List[int]:
        """
        Infer hop indices from signal evidence if hop chain available.

        This is a best-effort attempt to match signals to hops.
        """
        if not self.hop_chain or not signal.evidence:
            return []

        indices = []
        evidence_lower = signal.evidence.lower()

        for idx, hop in enumerate(self.hop_chain.hops):
            # Match by IP
            if hop.from_ip and hop.from_ip.lower() in evidence_lower:
                indices.append(idx)
                continue

            # Match by hostname
            if hop.from_host and hop.from_host.lower() in evidence_lower:
                indices.append(idx)
                continue

        return list(set(indices))  # Deduplicate

    def _extract_snippet(self, raw_header: str, max_length: int = 200) -> str:
        """Extract minimal snippet from raw header (no full dump)."""
        if not raw_header:
            return ""
        # Remove excessive whitespace and truncate
        snippet = " ".join(raw_header.split())
        if len(snippet) > max_length:
            snippet = snippet[: max_length - 3] + "..."
        return snippet

    def _extract_fields(self, hop) -> Dict:
        """Extract key fields from hop for evidence record."""
        fields = {}
        if hop.from_ip:
            fields["from_ip"] = hop.from_ip
        if hop.from_host:
            fields["from_host"] = hop.from_host
        if hop.by_host:
            fields["by_host"] = hop.by_host
        if hop.protocol:
            fields["protocol"] = hop.protocol
        if hop.timestamp:
            fields["timestamp"] = hop.timestamp.isoformat()
        fields["parse_confidence"] = round(hop.parse_confidence, 4)
        if hop.validation_flags:
            fields["validation_flags"] = [str(f.value) if hasattr(f, 'value') else str(f) for f in hop.validation_flags]
        return fields
