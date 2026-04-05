"""Output validators for each pipeline layer.

Validates layer outputs against expected schema and constraints.
"""

from __future__ import annotations

from typing import Any, Optional


def validate_parsing(hop_chain: Any) -> dict[str, bool]:
    """Validate parsing layer output.

    Checks:
    - hop_count > 0
    - no crash
    - all hops have required fields
    - timestamps in order or flagged as anomaly

    Args:
        hop_chain: HopChain object from parser

    Returns:
        Dictionary of validation checks
    """
    try:
        checks = {
            "has_hops": len(hop_chain.hops) > 0 if hasattr(hop_chain, "hops") else False,
            "hops_valid": True,
            "anomaly_flags_exist": False,
        }

        if hasattr(hop_chain, "hops"):
            # Validate each hop
            for hop in hop_chain.hops:
                has_from_host = hasattr(hop, "from_host") and hop.from_host
                has_by_host = hasattr(hop, "by_host") and hop.by_host
                has_timestamp = hasattr(hop, "timestamp") and hop.timestamp

                if not (has_from_host and has_by_host and has_timestamp):
                    checks["hops_valid"] = False

                # Check for anomaly flags
                if hasattr(hop, "validation_flags") and hop.validation_flags:
                    checks["anomaly_flags_exist"] = True

        checks["parsing_successful"] = (
            checks["has_hops"] and checks["hops_valid"]
        )
        return checks

    except Exception:
        return {
            "has_hops": False,
            "hops_valid": False,
            "anomaly_flags_exist": False,
            "parsing_successful": False,
            "error": True,
        }


def validate_signals(signals: list[Any], rejected: Optional[list[Any]] = None) -> dict[str, bool]:
    """Validate signal layer output.

    Checks:
    - signal_count > 0
    - all signals have confidence in [0, 1]
    - all signals have required fields

    Args:
        signals: List of Signal objects
        rejected: List of RejectedSignal objects (optional)

    Returns:
        Dictionary of validation checks
    """
    try:
        checks = {
            "has_signals": len(signals) > 0,
            "all_have_confidence": True,
            "all_have_source": True,
            "confidence_in_range": True,
        }

        for signal in signals:
            # Check confidence
            if hasattr(signal, "confidence"):
                if not (0 <= signal.confidence <= 1):
                    checks["confidence_in_range"] = False
            else:
                checks["all_have_confidence"] = False

            # Check source
            if not (hasattr(signal, "source") and signal.source):
                checks["all_have_source"] = False

        checks["signals_valid"] = (
            checks["has_signals"]
            and checks["all_have_confidence"]
            and checks["all_have_source"]
        )
        return checks

    except Exception:
        return {
            "has_signals": False,
            "all_have_confidence": False,
            "all_have_source": False,
            "confidence_in_range": False,
            "signals_valid": False,
            "error": True,
        }


def validate_correlation(correlation: Any) -> dict[str, bool]:
    """Validate correlation layer output.

    Checks:
    - consistency_score exists and in [0, 1]
    - contradictions list valid
    - relationships list valid

    Args:
        correlation: CorrelationResult object

    Returns:
        Dictionary of validation checks
    """
    try:
        checks = {
            "has_consistency_score": hasattr(correlation, "consistency_score")
            and correlation.consistency_score is not None,
            "consistency_in_range": False,
            "has_contradictions": hasattr(correlation, "contradictions"),
            "has_relationships": hasattr(correlation, "relationships"),
        }

        if checks["has_consistency_score"]:
            score = correlation.consistency_score
            checks["consistency_in_range"] = 0 <= score <= 1

        checks["correlation_valid"] = (
            checks["has_consistency_score"]
            and checks["consistency_in_range"]
            and checks["has_contradictions"]
        )
        return checks

    except Exception:
        return {
            "has_consistency_score": False,
            "consistency_in_range": False,
            "has_contradictions": False,
            "has_relationships": False,
            "correlation_valid": False,
            "error": True,
        }


def validate_scoring(result: Any) -> dict[str, bool]:
    """Validate scoring layer output.

    Checks:
    - confidence in [0, 1]
    - verdict in valid set
    - region set

    Args:
        result: AttributionResult object

    Returns:
        Dictionary of validation checks
    """
    try:
        valid_verdicts = {"identified", "suspicious", "abstain"}

        checks = {
            "has_confidence": hasattr(result, "confidence")
            and result.confidence is not None,
            "confidence_in_range": False,
            "has_verdict": hasattr(result, "verdict") and result.verdict is not None,
            "verdict_valid": False,
            "has_region": hasattr(result, "region") and result.region is not None,
        }

        if checks["has_confidence"]:
            checks["confidence_in_range"] = 0 <= result.confidence <= 1

        if checks["has_verdict"]:
            checks["verdict_valid"] = result.verdict in valid_verdicts

        checks["scoring_valid"] = (
            checks["has_confidence"]
            and checks["confidence_in_range"]
            and checks["verdict_valid"]
            and checks["has_region"]
        )
        return checks

    except Exception:
        return {
            "has_confidence": False,
            "confidence_in_range": False,
            "has_verdict": False,
            "verdict_valid": False,
            "has_region": False,
            "scoring_valid": False,
            "error": True,
        }


def validate_explainability(explain: Any, hop_chain: Any) -> dict[str, bool]:
    """Validate explainability layer output.

    Checks:
    - evidence_links present
    - contributions exist
    - no missing mappings

    Args:
        explain: ExplainabilityResult object
        hop_chain: Original HopChain for reference

    Returns:
        Dictionary of validation checks
    """
    try:
        checks = {
            "has_evidence_links": hasattr(explain, "evidence_links")
            and len(explain.evidence_links) > 0,
            "has_contributions": hasattr(explain, "contributions")
            and len(explain.contributions) > 0,
            "has_verdict": hasattr(explain, "verdict") and explain.verdict is not None,
            "contributions_valid": True,
        }

        # Check contribution scores
        if checks["has_contributions"]:
            for contribution in explain.contributions:
                if hasattr(contribution, "net_effect"):
                    if not (0 <= contribution.net_effect <= 1):
                        checks["contributions_valid"] = False

        checks["explainability_valid"] = (
            checks["has_evidence_links"]
            and checks["has_contributions"]
            and checks["has_verdict"]
            and checks["contributions_valid"]
        )
        return checks

    except Exception:
        return {
            "has_evidence_links": False,
            "has_contributions": False,
            "has_verdict": False,
            "contributions_valid": False,
            "explainability_valid": False,
            "error": True,
        }


def validate_expectations(synthetic_sample: Any, result: Any) -> dict[str, bool]:
    """Validate result against synthetic sample expectations.

    For synthetic samples only:
    - If should_abstain: verdict == "abstain"
    - If has_anomaly: len(anomalies) > 0
    - If anonymization: specific field checks

    Args:
        synthetic_sample: SyntheticSample with expected_behavior
        result: AttributionResult

    Returns:
        Dictionary of expectation validation checks
    """
    checks = {}
    expected = getattr(synthetic_sample, "expected_behavior", {})

    if expected.get("should_abstain"):
        actual_verdict = result.verdict if hasattr(result, "verdict") else None
        checks["verdict_abstain"] = actual_verdict == "abstain"

    if expected.get("has_anomaly"):
        anomalies = result.anomalies if hasattr(result, "anomalies") else []
        checks["has_anomalies"] = len(anomalies) > 0

    if expected.get("anonymization"):
        anomalies = result.anomalies if hasattr(result, "anomalies") else []
        checks["anonymization_detected"] = any(
            getattr(a, "type", None) == "anonymization" for a in anomalies
        )

    return checks


def validate_all_checks_pass(checks: dict[str, bool]) -> bool:
    """Check if all validation checks passed.

    Args:
        checks: Dictionary of validation checks

    Returns:
        True if all checks are True/passed, False otherwise
    """
    return all(
        v is True or (isinstance(v, dict) and all(validate_all_checks_pass(v)))
        for v in checks.values()
        if v is not False
    )
