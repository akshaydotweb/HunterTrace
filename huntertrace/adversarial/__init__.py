"""Phase 7: Comprehensive adversarial testing framework for HunterTrace Atlas.

This module implements deterministic adversarial testing designed to:
- Generate realistic attacker behavior patterns
- Measure pipeline robustness against deception
- Quantify failure modes (false attribution, overconfidence, instability)
- Integrate seamlessly with evaluation and explainability layers
- Maintain reproducibility through seeded determinism
"""

from huntertrace.adversarial.attacks import AttackLibrary, AttackSeverity, AttackType
from huntertrace.adversarial.evaluator import AdversarialEvaluator, AdversarialRunConfig
from huntertrace.adversarial.generator import AdversarialGenerator, AdversarialSample, MutationTrace
from huntertrace.adversarial.metrics import (
    FailureCase,
    RobustnessAnalyzer,
    RobustnessMetrics,
    RobustnessReport,
)
from huntertrace.adversarial.scenarios import Scenario, ScenarioLibrary

__all__ = [
    "AdversarialGenerator",
    "AdversarialSample",
    "MutationTrace",
    "AttackLibrary",
    "AttackType",
    "AttackSeverity",
    "Scenario",
    "ScenarioLibrary",
    "AdversarialEvaluator",
    "AdversarialRunConfig",
    "RobustnessMetrics",
    "RobustnessAnalyzer",
    "FailureCase",
    "RobustnessReport",
]

