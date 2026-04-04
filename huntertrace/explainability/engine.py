"""Explainability engine for auditable attribution reasoning."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from huntertrace.analysis.models import (
    AttributionResult,
    CorrelationResult,
    Signal,
    SignalContribution,
)
from huntertrace.explainability.models import (
    Anomaly,
    Contribution,
    ExplainabilityResult,
    Limitation,
    RejectedSignal,
)
from huntertrace.explainability.tracer import EvidenceTracer
from huntertrace.parsing.models import HopChain


class ExplainabilityEngine:
    """
    Deterministic explainability engine for HunterTrace Atlas.

    Consumes:
    - signals (Signal Layer)
    - correlation results (CorrelationResult)
    - attribution results (AttributionResult)
    - hop_chain (parsing layer)

    Produces:
    - decision_trace: ordered reasoning steps
    - contributions: signal contribution breakdown
    - evidence_links: signal → hop → raw header traceability
    - anomalies: detected contradictions and patterns
    - limitations: analysis scope and reliability bounds
    - explanation: human-readable summary
    """

    def __init__(self, hop_chain: HopChain | None = None):
        """
        Initialize explainability engine.

        Args:
            hop_chain: Optional HopChain for full evidence traceability
        """
        self.hop_chain = hop_chain
        self.tracer = EvidenceTracer(hop_chain)

    def explain(
        self,
        signals: List[Signal],
        correlation: CorrelationResult,
        attribution: AttributionResult,
    ) -> ExplainabilityResult:
        """
        Produce complete explainability result for attribution decision.

        Args:
            signals: Processed signals from signal layer
            correlation: CorrelationResult from correlation engine
            attribution: AttributionResult from scoring engine

        Returns:
            ExplainabilityResult with full explainability breakdown
        """
        # Phase 1: Build decision trace
        decision_trace = self._build_decision_trace(
            signals, correlation, attribution
        )

        # Phase 2: Build contribution breakdown
        contributions = self._build_contributions(attribution, signals)

        # Phase 2b: Build rejected signals for audit trail
        rejected_signals = self._build_rejected_signals(attribution)

        # Phase 3: Build evidence traceability
        # Use set for O(1) lookup instead of O(n) search
        contrib_ids = {c.signal_id for c in contributions}
        evidence_links = self.tracer.trace_evidence(
            [s for s in signals if s.signal_id in contrib_ids]
        )

        # Phase 4: Extract anomalies
        anomalies = self._extract_anomalies(correlation, signals)

        # Phase 5: Extract limitations
        limitations = self._extract_limitations(attribution, correlation, signals)

        # Phase 5b: Generate human explanation
        explanation = self._generate_explanation(
            attribution, correlation, contributions, anomalies
        )

        return ExplainabilityResult(
            verdict=attribution.verdict,
            region=attribution.region,
            confidence=attribution.confidence,
            decision_trace=decision_trace,
            contributions=contributions,
            rejected_signals=rejected_signals,
            evidence_links=evidence_links,
            anomalies=anomalies,
            limitations=limitations,
            explanation=explanation,
        )

    def _build_decision_trace(
        self,
        signals: List[Signal],
        correlation: CorrelationResult,
        attribution: AttributionResult,
    ) -> List[str]:
        """PHASE 1: Build ordered decision reasoning steps."""
        trace = []

        # Parsing phase
        if self.hop_chain:
            trace.append(f"Parsed {len(self.hop_chain.hops)} hops from header chain")
            if self.hop_chain.anomalies:
                trace.append(
                    f"Detected {len(self.hop_chain.anomalies)} chain-level anomalies"
                )

        # Signal processing phase
        if signals:
            trace.append(f"Extracted {len(signals)} signals from headers")
        else:
            trace.append("No signals extracted from headers")

        # Correlation phase
        trace.append(f"Consistency score: {correlation.consistency_score:.1%}")

        if correlation.contradictions:
            trace.append(
                f"Detected {len(correlation.contradictions)} contradictions"
            )
            severity_count = self._count_by_severity(correlation.contradictions)
            for severity, count in sorted(severity_count.items()):
                trace.append(f"  - {count} {severity} severity")

        if correlation.anonymization.detected:
            trace.append(
                f"Anonymization patterns detected ({correlation.anonymization.strength} strength)"
            )

        # Scoring phase
        if attribution.signals_used:
            supporting = [
                s for s in attribution.signals_used if s.role == "supporting"
            ]
            conflicting = [
                s for s in attribution.signals_used if s.role == "conflicting"
            ]
            trace.append(
                f"Signal classification: {len(supporting)} supporting, {len(conflicting)} conflicting"
            )

        if attribution.signals_rejected:
            trace.append(f"{len(attribution.signals_rejected)} signals rejected/non-attributable")

        # Final decision
        trace.append(
            f"Final confidence: {attribution.confidence:.1%}, verdict: {attribution.verdict}"
        )

        if attribution.region:
            trace.append(f"Attribution decision: {attribution.region}")
        else:
            trace.append("Attribution decision: inconclusive (abstention triggered)")

        return trace

    def _build_contributions(
        self, attribution: AttributionResult, signals: List[Signal]
    ) -> List[Contribution]:
        """PHASE 2: Build contribution breakdown from signal contributions."""
        contributions = []

        for signal_contrib in attribution.signals_used:
            # Find original signal for group info
            original_signal = next(
                (s for s in signals if s.signal_id == signal_contrib.signal_id), None
            )
            group = original_signal.group if original_signal else signal_contrib.group

            net_effect = signal_contrib.contribution - signal_contrib.penalty

            contrib = Contribution(
                signal_id=signal_contrib.signal_id,
                signal_name=signal_contrib.name,
                role=signal_contrib.role,
                group=group,
                contribution_score=signal_contrib.contribution,
                penalty_score=signal_contrib.penalty,
                net_effect=net_effect,
            )
            contributions.append(contrib)

        # Sort by absolute impact (descending)
        contributions.sort(
            key=lambda x: abs(x.net_effect), reverse=True
        )

        # Compute normalized effects (relative impact within this decision)
        total_absolute_effect = sum(abs(c.net_effect) for c in contributions)
        if total_absolute_effect > 0:
            contributions = [
                Contribution(
                    signal_id=c.signal_id,
                    signal_name=c.signal_name,
                    role=c.role,
                    group=c.group,
                    contribution_score=c.contribution_score,
                    penalty_score=c.penalty_score,
                    net_effect=c.net_effect,
                    normalized_effect=c.net_effect / total_absolute_effect,
                )
                for c in contributions
            ]

        return contributions

    def _build_rejected_signals(
        self, attribution: AttributionResult
    ) -> List[RejectedSignal]:
        """Build list of rejected signals for audit trail."""
        rejected = []

        for rejected_detail in attribution.signals_rejected:
            rejected_signal = RejectedSignal(
                signal_id=rejected_detail.signal_id,
                signal_name=rejected_detail.name,
                reason=rejected_detail.reason,
            )
            rejected.append(rejected_signal)

        # Sort deterministically by signal_id
        rejected.sort(key=lambda x: x.signal_id)
        return rejected

    def _extract_anomalies(
        self, correlation: CorrelationResult, signals: List[Signal]
    ) -> List[Anomaly]:
        """PHASE 4: Extract anomalies from correlation and signals."""
        anomalies = []

        # Contradictions from correlation
        for contradiction in correlation.contradictions:
            anomaly = Anomaly(
                type="contradiction",
                severity=contradiction.severity,
                description=contradiction.reason,
                source="correlation",
            )
            anomalies.append(anomaly)

        # Anonymization patterns
        if correlation.anonymization.detected:
            indicators_text = ", ".join(correlation.anonymization.indicators[:3])
            if len(correlation.anonymization.indicators) > 3:
                indicators_text += f", and {len(correlation.anonymization.indicators) - 3} more"

            anomaly = Anomaly(
                type="anonymization",
                severity="high" if correlation.anonymization.strength == "high" else "medium",
                description=f"Anonymization patterns: {indicators_text}",
                source="correlation",
            )
            anomalies.append(anomaly)

        # Validation flags from signals
        signal_anomalies = set()
        for signal in signals:
            if signal.validation_flags:
                for flag in signal.validation_flags:
                    flag_str = str(flag.value) if hasattr(flag, 'value') else str(flag)
                    signal_anomalies.add(flag_str)

        for flag in sorted(signal_anomalies):
            anomaly = Anomaly(
                type=flag.lower(),
                severity="medium",
                description=f"Validation flag detected: {flag}",
                source="signal",
            )
            anomalies.append(anomaly)

        # Sort deterministically by severity (high first) then type
        severity_order = {"high": 0, "medium": 1, "low": 2}
        anomalies.sort(key=lambda x: (severity_order.get(x.severity, 3), x.type))

        return anomalies

    def _extract_limitations(
        self,
        attribution: AttributionResult,
        correlation: CorrelationResult,
        signals: List[Signal],
    ) -> List[Limitation]:
        """PHASE 5: Extract analysis limitations."""
        limitations = []

        # From attribution reasoning
        for limit_text in attribution.limitations:
            limitation = Limitation(
                category="evidence",
                description=limit_text,
                impact="medium",
            )
            limitations.append(limitation)

        # From correlation limitations
        for limit_text in correlation.limitations:
            limitation = Limitation(
                category="correlation",
                description=limit_text,
                impact="medium",
            )
            limitations.append(limitation)

        # Observability limitations
        if correlation.anonymization.detected:
            limitation = Limitation(
                category="observability",
                description="Anonymization reduces infrastructure observability",
                impact="high",
            )
            limitations.append(limitation)

        # Evidence quality
        if not signals or len(signals) < 3:
            limitation = Limitation(
                category="evidence",
                description="Limited signal diversity constrains attribution confidence",
                impact="high",
            )
            limitations.append(limitation)

        # Inconsistency
        if correlation.consistency_score < 0.5:
            limitation = Limitation(
                category="correlation",
                description="Low consistency score reflects internal contradictions",
                impact="high",
            )
            limitations.append(limitation)

        # Deduplicate and sort by impact (high first) then category
        seen = set()
        unique_limitations = []
        for limit in limitations:
            key = (limit.category, limit.description)
            if key not in seen:
                seen.add(key)
                unique_limitations.append(limit)

        impact_order = {"high": 0, "medium": 1, "low": 2}
        unique_limitations.sort(key=lambda x: (impact_order.get(x.impact, 3), x.category))
        return unique_limitations

    def _generate_explanation(
        self,
        attribution: AttributionResult,
        correlation: CorrelationResult,
        contributions: List[Contribution],
        anomalies: List[Anomaly],
    ) -> str:
        """PHASE 5b: Generate human-readable explanation."""

        # Summarize key findings with semantic meaning
        if not contributions:
            findings = "No supporting signals were identified"
            signal_groups_text = ""
        else:
            # Extract signal types and groups for semantic meaning
            signal_types = [c.signal_name for c in contributions[:3]]
            top_groups = set(c.group for c in contributions[:3] if c.group)

            if top_groups:
                group_names = sorted(top_groups)
                group_text = " and ".join(group_names)
                findings = f"identified {len(contributions)} signal contributions ({group_text} signal groups)"
            else:
                findings = f"identified {len(contributions)} signal contributions"

            signal_groups_text = f" ({', '.join(signal_types[:2])})"

        # Summarize signal agreement
        if contributions:
            supporting = [c for c in contributions if c.role == "supporting"]
            conflicting = [c for c in contributions if c.role == "conflicting"]

            if conflicting:
                agreement_pct = int(100 * len(supporting) / len(contributions))
                agreement_text = f"{len(supporting)}/{len(contributions)} signals ({agreement_pct}%) supported attribution"
            else:
                agreement_text = f"all {len(supporting)} signals aligned consistently"
        else:
            agreement_text = "no signals aligned with any region"

        # Anomaly impact - be specific about severity
        high_severity_anomalies = [a for a in anomalies if a.severity == "high"]
        med_severity_anomalies = [a for a in anomalies if a.severity == "medium"]

        if high_severity_anomalies:
            anomaly_count = len(high_severity_anomalies)
            anomaly_text = f"{anomaly_count} high-severity anomaly/anomalies significantly reduced confidence"
        elif med_severity_anomalies:
            anomaly_text = f"moderate anomalies detected, reducing confidence"
        elif anomalies:
            anomaly_text = f"minor anomalies detected"
        else:
            anomaly_text = "no significant anomalies detected"

        # Verdict and confidence
        verdict_text = {
            "attributed": f"attributed to {attribution.region}",
            "inconclusive": "inconclusive (insufficient evidence)",
        }.get(attribution.verdict, "unknown verdict")

        # Construct explanation with semantic detail
        explanation = (
            f"The email routing analysis {findings}. These signals {agreement_text}, "
            f"resulting in a consistency score of {correlation.consistency_score:.1%}. "
            f"{anomaly_text.capitalize()}. "
            f"Final decision: {verdict_text} with {attribution.confidence:.1%} confidence."
        )

        return explanation

    def _count_by_severity(self, contradictions) -> Dict[str, int]:
        """Count contradictions by severity."""
        counts = {}
        for contradiction in contradictions:
            severity = contradiction.severity.lower()
            counts[severity] = counts.get(severity, 0) + 1
        return counts
