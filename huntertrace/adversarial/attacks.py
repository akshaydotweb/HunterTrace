"""Attack library and orchestration."""

from enum import Enum
from typing import Dict, List, Optional, Tuple

from huntertrace.adversarial.models import AdversarialSample, AttackSeverity, AttackType


class AttackLibraryConfig:
    """Configuration for attack library."""

    ATTACK_DESCRIPTIONS: Dict[str, str] = {
        AttackType.HEADER_INJECTION.value: "Duplicate or inject fake Received headers to confuse hop analysis",
        AttackType.TIMESTAMP_SPOOFING.value: "Create identical or non-monotonic timestamps to break temporal verification",
        AttackType.HOP_CHAIN_BREAK.value: "Remove intermediate hops to obscure email routing path",
        AttackType.RELAY_MIMICRY.value: "Replace relay hosts with common provider patterns (Gmail, Outlook, etc.)",
        AttackType.INFRASTRUCTURE_CONFLICT.value: "Inject contradictory IP/host patterns to break consistency checks",
        AttackType.HEADER_OBFUSCATION.value: "Apply malformed but parseable header variations to evade analysis",
    }

    ATTACK_IMPACT: Dict[str, Dict[str, float]] = {
        AttackType.HEADER_INJECTION.value: {
            "hop_analysis_disruption": 0.8,
            "confidence_reduction": 0.3,
            "false_attribution_risk": 0.4,
        },
        AttackType.TIMESTAMP_SPOOFING.value: {
            "hop_analysis_disruption": 0.5,
            "confidence_reduction": 0.6,
            "false_attribution_risk": 0.3,
        },
        AttackType.HOP_CHAIN_BREAK.value: {
            "hop_analysis_disruption": 0.9,
            "confidence_reduction": 0.4,
            "false_attribution_risk": 0.5,
        },
        AttackType.RELAY_MIMICRY.value: {
            "hop_analysis_disruption": 0.6,
            "confidence_reduction": 0.5,
            "false_attribution_risk": 0.7,
        },
        AttackType.INFRASTRUCTURE_CONFLICT.value: {
            "hop_analysis_disruption": 0.7,
            "confidence_reduction": 0.7,
            "false_attribution_risk": 0.4,
        },
        AttackType.HEADER_OBFUSCATION.value: {
            "hop_analysis_disruption": 0.3,
            "confidence_reduction": 0.2,
            "false_attribution_risk": 0.2,
        },
    }


class AttackLibrary:
    """Centralized attack library and composition tool."""

    @staticmethod
    def get_all_attacks() -> List[str]:
        """Return list of all available attacks."""
        return [t.value for t in AttackType]

    @staticmethod
    def get_attack_description(attack_type: str) -> str:
        """Get human-readable description of attack."""
        return AttackLibraryConfig.ATTACK_DESCRIPTIONS.get(
            attack_type, "Unknown attack type"
        )

    @staticmethod
    def get_attack_impact(attack_type: str) -> Dict[str, float]:
        """Get expected impact metrics for attack."""
        return AttackLibraryConfig.ATTACK_IMPACT.get(attack_type, {})

    @staticmethod
    def get_attacks_by_category(category: str) -> List[str]:
        """Get attacks by category."""
        categories = {
            "routing": [
                AttackType.HEADER_INJECTION.value,
                AttackType.HOP_CHAIN_BREAK.value,
            ],
            "temporal": [AttackType.TIMESTAMP_SPOOFING.value],
            "identity": [
                AttackType.RELAY_MIMICRY.value,
                AttackType.INFRASTRUCTURE_CONFLICT.value,
            ],
            "obfuscation": [AttackType.HEADER_OBFUSCATION.value],
        }
        return categories.get(category, [])

    @staticmethod
    def get_severity_from_impact(baseline_confidence: float) -> str:
        """Recommend severity based on baseline confidence."""
        if baseline_confidence > 0.8:
            return AttackSeverity.HIGH.value
        elif baseline_confidence > 0.5:
            return AttackSeverity.MEDIUM.value
        else:
            return AttackSeverity.LOW.value
