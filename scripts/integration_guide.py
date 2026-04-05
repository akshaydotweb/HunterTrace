"""
Quick integration guide for adding calibration to existing analysis pipeline.

Minimal changes required - calibration is purely additive.
"""

# ============================================================================
# BEFORE (Current Analysis Pipeline)
# ============================================================================

"""
from huntertrace.parsing import HeaderParser, HopChainBuilder
from huntertrace.signals import SignalBuilder, ObservabilityScorer
from huntertrace.analysis import AtlasScoringEngine, CorrelationEngine
from huntertrace.explainability import ExplainabilityEngine

def analyze_email(email_content: str):
    # Parse
    hop_chain = HopChainBuilder.build(HeaderParser.parse(email_content))

    # Signals
    signals = SignalBuilder.build(hop_chain)
    observability = ObservabilityScorer.score(hop_chain, signals)

    # Correlation
    correlation = CorrelationEngine.correlate(signals)

    # Scoring
    result = AtlasScoringEngine.score(signals, correlation)

    # Explainability
    explanation = ExplainabilityEngine.explain(
        result, signals, hop_chain, correlation
    )

    return {
        "region": result.region,
        "confidence": result.confidence,
        "verdict": result.verdict,
        "explanation": explanation,
    }
"""

# ============================================================================
# AFTER (With Calibration - Add 4 Lines!)
# ============================================================================

"""
from huntertrace.parsing import HeaderParser, HopChainBuilder
from huntertrace.signals import SignalBuilder, ObservabilityScorer
from huntertrace.analysis import AtlasScoringEngine, CorrelationEngine
from huntertrace.calibration import CalibrationEngine  # NEW
from huntertrace.explainability import ExplainabilityEngine

def analyze_email(email_content: str):
    # Parse
    hop_chain = HopChainBuilder.build(HeaderParser.parse(email_content))

    # Signals
    signals = SignalBuilder.build(hop_chain)
    observability = ObservabilityScorer.score(hop_chain, signals)

    # Correlation
    correlation = CorrelationEngine.correlate(signals)

    # Scoring
    result = AtlasScoringEngine.score(signals, correlation)

    # CALIBRATION (NEW - 4 lines)
    calibrated = CalibrationEngine.calibrate(
        candidate_region=result.region,
        base_confidence=result.confidence,
        correlation_result=correlation,
        observability=observability,
        hop_count=len(hop_chain.hops),
        routing_complexity=_calc_routing_complexity(signals),
        anomaly_count=len(hop_chain.anomalies),
    )

    # Explainability (unchanged)
    explanation = ExplainabilityEngine.explain(
        result, signals, hop_chain, correlation
    )

    return {
        "region": calibrated.final_region,  # Changed
        "confidence": calibrated.calibrated_confidence,  # Changed
        "verdict": calibrated.verdict,  # Changed
        "calibration_adjustments": calibrated.adjustments_applied,  # New
        "calibration_reasoning": calibrated.reasoning,  # New
        "explanation": explanation,
    }

def _calc_routing_complexity(signals):
    # Simple heuristic: measure geographic diversity
    regions = set()
    for signal in signals:
        if signal.candidate_region and signal.candidate_region not in ("internal", "local"):
            regions.add(signal.candidate_region)
    return min(1.0, (len(regions) - 1) / 10.0)
"""

# ============================================================================
# KEY CHANGES
# ============================================================================
"""
1. Import CalibrationEngine from huntertrace.calibration
2. After AtlasScoringEngine.score(), call CalibrationEngine.calibrate()
3. Use calibrated output instead of raw scoring result
4. Optional: Add calibration adjustments/reasoning to response

That's it! No other changes needed.
"""

# ============================================================================
# FOR API/SERVICE INTEGRATION
# ============================================================================

"""
# In huntertrace/service/orchestrator.py

from huntertrace.calibration import CalibrationEngine

class Orchestrator:
    def run_full_analysis(self, ...):
        # ... existing pipeline ...

        # After scoring
        result = AtlasScoringEngine.score(signals, correlation)

        # ADD: Calibration step
        calibrated = CalibrationEngine.calibrate(
            candidate_region=result.region,
            base_confidence=result.confidence,
            correlation_result=correlation,
            observability=observability,
            hop_count=len(hop_chain.hops),
            routing_complexity=self._calc_routing_complexity(hop_chain, signals),
            anomaly_count=len(hop_chain.anomalies),
        )

        # Use calibrated output for response
        return {
            ...
            "region": calibrated.final_region,
            "confidence": calibrated.calibrated_confidence,
            "verdict": calibrated.verdict,
            "calibration": {
                "adjustments": calibrated.adjustments_applied,
                "reasoning": calibrated.reasoning,
            }
            ...
        }
"""

# ============================================================================
# MINIMAL EXAMPLE
# ============================================================================

def minimal_integration_example():
    """Minimum code to integrate calibration."""
    from huntertrace.analysis import AtlasScoringEngine, CorrelationResult
    from huntertrace.calibration import CalibrationEngine

    # Assume you have:
    signals = []  # from signal builder
    correlation = CorrelationResult(...)  # from correlation engine
    observability = None  # optional

    # Original pipeline
    base_result = AtlasScoringEngine.score(signals, correlation)

    # ADD CALIBRATION (1 call)
    calibrated = CalibrationEngine.calibrate(
        candidate_region=base_result.region,
        base_confidence=base_result.confidence,
        correlation_result=correlation,
        observability=observability,
    )

    # Use calibrated output
    return calibrated.final_region, calibrated.calibrated_confidence


if __name__ == "__main__":
    print("Integration examples shown in comments above")
    print("See CALIBRATION_LAYER.md for full documentation")
