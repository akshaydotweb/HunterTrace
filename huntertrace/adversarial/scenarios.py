"""Adversarial scenario definitions and composition."""

from dataclasses import dataclass
from typing import Dict, List, Optional

from huntertrace.adversarial.models import AttackSeverity, AttackType


@dataclass
class Scenario:
    """Definition of an adversarial attack scenario."""

    name: str
    description: str
    attack_sequence: List[str]  # Ordered list of attack types
    severity_level: str  # low/medium/high
    target_properties: Optional[Dict[str, str]] = None  # e.g., region, features to target

    def to_dict(self) -> Dict:
        """Serialize to dict."""
        return {
            "name": self.name,
            "description": self.description,
            "attack_sequence": self.attack_sequence,
            "severity_level": self.severity_level,
            "target_properties": self.target_properties or {},
        }


class ScenarioLibrary:
    """Library of predefined attack scenarios."""

    SCENARIOS: Dict[str, Scenario] = {
        "vpn_like_chain": Scenario(
            name="VPN-Like Routing Chain",
            description="Mimics relay chain through VPN/proxy infrastructure by combining header injection with relay mimicry",
            attack_sequence=[
                AttackType.HEADER_INJECTION.value,
                AttackType.RELAY_MIMICRY.value,
            ],
            severity_level=AttackSeverity.MEDIUM.value,
            target_properties={"feature": "hop_consistency"},
        ),
        "spoofed_enterprise": Scenario(
            name="Spoofed Enterprise Identity",
            description="Attempts to impersonate enterprise by injecting corporate infrastructure patterns",
            attack_sequence=[
                AttackType.RELAY_MIMICRY.value,
                AttackType.INFRASTRUCTURE_CONFLICT.value,
            ],
            severity_level=AttackSeverity.HIGH.value,
            target_properties={"feature": "infrastructure_consistency"},
        ),
        "partial_chain_attack": Scenario(
            name="Partial Chain Destruction",
            description="Breaks hop chain continuity while maintaining parser validity",
            attack_sequence=[
                AttackType.HOP_CHAIN_BREAK.value,
                AttackType.HEADER_OBFUSCATION.value,
            ],
            severity_level=AttackSeverity.MEDIUM.value,
            target_properties={"feature": "hop_validation"},
        ),
        "mixed_infrastructure_attack": Scenario(
            name="Mixed Infrastructure Confusion",
            description="Combines conflicting signals about infrastructure and identity",
            attack_sequence=[
                AttackType.INFRASTRUCTURE_CONFLICT.value,
                AttackType.RELAY_MIMICRY.value,
                AttackType.HEADER_INJECTION.value,
            ],
            severity_level=AttackSeverity.HIGH.value,
            target_properties={"feature": "multi_signal_consistency"},
        ),
        "temporal_deception": Scenario(
            name="Temporal Anomaly",
            description="Breaks temporal sequencing of email hops",
            attack_sequence=[AttackType.TIMESTAMP_SPOOFING.value],
            severity_level=AttackSeverity.MEDIUM.value,
            target_properties={"feature": "temporal_consistency"},
        ),
        "advanced_obfuscation": Scenario(
            name="Advanced Obfuscation",
            description="Combines multiple obfuscation techniques to evade parsing",
            attack_sequence=[
                AttackType.HEADER_OBFUSCATION.value,
                AttackType.HEADER_INJECTION.value,
            ],
            severity_level=AttackSeverity.LOW.value,
            target_properties={"feature": "header_parsing_robustness"},
        ),
        "full_exploitation": Scenario(
            name="Full Pipeline Exploitation",
            description="Comprehensive attack combining all techniques",
            attack_sequence=[
                AttackType.HEADER_INJECTION.value,
                AttackType.TIMESTAMP_SPOOFING.value,
                AttackType.HOP_CHAIN_BREAK.value,
                AttackType.RELAY_MIMICRY.value,
                AttackType.INFRASTRUCTURE_CONFLICT.value,
            ],
            severity_level=AttackSeverity.HIGH.value,
            target_properties={"feature": "overall_robustness"},
        ),
    }

    @staticmethod
    def get_scenario(name: str) -> Optional[Scenario]:
        """Get scenario by name."""
        return ScenarioLibrary.SCENARIOS.get(name)

    @staticmethod
    def list_scenarios() -> List[str]:
        """List all available scenario names."""
        return list(ScenarioLibrary.SCENARIOS.keys())

    @staticmethod
    def filter_by_severity(severity: str) -> List[Scenario]:
        """Get all scenarios of given severity."""
        return [
            s for s in ScenarioLibrary.SCENARIOS.values()
            if s.severity_level == severity
        ]

    @staticmethod
    def filter_by_target(target_property: str) -> List[Scenario]:
        """Get scenarios targeting specific property."""
        return [
            s for s in ScenarioLibrary.SCENARIOS.values()
            if s.target_properties and target_property in s.target_properties
        ]

    @staticmethod
    def custom_scenario(
        name: str,
        attack_sequence: List[str],
        severity: str = AttackSeverity.MEDIUM.value,
        description: str = "",
    ) -> Scenario:
        """Create custom scenario from attack sequence."""
        return Scenario(
            name=name,
            description=description or f"Custom scenario: {', '.join(attack_sequence)}",
            attack_sequence=attack_sequence,
            severity_level=severity,
        )

    @staticmethod
    def multi_attack(
        base_scenario: Scenario,
        additional_attacks: List[str],
        combined_name: str = "",
    ) -> Scenario:
        """Compose new scenario by adding attacks to existing one."""
        combined_sequence = base_scenario.attack_sequence + additional_attacks
        name = combined_name or f"{base_scenario.name} + Extended"

        # Determine combined severity (highest component severity)
        severity_order = {
            AttackSeverity.LOW.value: 0,
            AttackSeverity.MEDIUM.value: 1,
            AttackSeverity.HIGH.value: 2,
        }
        base_severity = severity_order.get(base_scenario.severity_level, 1)
        additional_max = max(
            (severity_order.get(
                AttackSeverity.MEDIUM.value, 1
            ) for _ in additional_attacks),
            default=1,
        )
        combined_severity_level = (
            AttackSeverity.HIGH.value
            if max(base_severity, additional_max) == 2
            else AttackSeverity.MEDIUM.value
        )

        return Scenario(
            name=name,
            description=f"Composite of: {base_scenario.name} + {len(additional_attacks)} additional attack(s)",
            attack_sequence=combined_sequence,
            severity_level=combined_severity_level,
        )
