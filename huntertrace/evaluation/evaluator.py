"""Main evaluation orchestrator."""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from huntertrace.analysis.models import AttributionResult, CorrelationResult, ScoringConfig, Signal
from huntertrace.analysis.scoring import AtlasScoringEngine
from huntertrace.evaluation.adversarial import AdversarialGenerator, RobustnessAnalyzer, RobustnessMetrics
from huntertrace.evaluation.calibration import CalibrationAnalyzer, CalibrationMetrics, PredictionForCalibration
from huntertrace.evaluation.cost import CostAnalyzer, CostConfig, CostMetrics
from huntertrace.evaluation.datasets import EvaluationSample
from huntertrace.evaluation.metrics import Metrics, PredictionRecord, compute_metrics
from huntertrace.evaluation.statistics import BootstrapAnalyzer, MetricCI


@dataclass
class ErrorCase:
    """Single error case for detailed analysis."""

    sample_id: str
    input_path: str
    predicted_region: Optional[str]
    ground_truth_region: Optional[str]
    predicted_confidence: float
    predicted_verdict: str
    error_type: str  # "false_attribution", "overconfident_incorrect", "unnecessary_abstention"
    correlation_summary: Optional[Dict[str, Any]] = None
    reasoning: Optional[str] = None


@dataclass
class StratifiedMetrics:
    """Metrics for a specific stratum."""

    stratum_name: str
    stratum_filter: str  # Description of filter
    metrics: Metrics
    sample_count: int


@dataclass
class ThresholdAnalysis:
    """Analysis of performance across confidence thresholds."""

    threshold: float
    accuracy: float
    false_attribution_rate: float
    abstention_rate: float
    coverage_rate: float


@dataclass
class EvaluationContext:
    """Accumulated evaluation results."""

    overall_metrics: Metrics
    calibration_metrics: CalibrationMetrics
    stratified_metrics: List[StratifiedMetrics] = field(default_factory=list)
    threshold_analysis: List[ThresholdAnalysis] = field(default_factory=list)
    error_cases: List[ErrorCase] = field(default_factory=list)
    predictions: List[PredictionRecord] = field(default_factory=list)

    # Statistical significance (new)
    metric_confidence_intervals: Dict[str, MetricCI] = field(default_factory=dict)

    # Cost-sensitive evaluation (new)
    cost_metrics: Optional[CostMetrics] = None

    # Adversarial robustness (new)
    robustness_metrics: Optional[RobustnessMetrics] = None


class AtlasEvaluator:
    """Evaluate AtlasScoringEngine on datasets."""

    def __init__(
        self,
        scoring_config: Optional[ScoringConfig] = None,
        signal_extractor: Optional[Callable[[str], Tuple[List[Signal], CorrelationResult]]] = None,
        bootstrap_iterations: int = 1000,
        cost_config: Optional[CostConfig] = None,
        enable_adversarial: bool = False,
        adversarial_samples_per_input: int = 1,
    ):
        """
        Initialize evaluator.

        Args:
            scoring_config: ScoringConfig for scoring engine
            signal_extractor: Function that takes input_path and returns (signals, correlation)
                            If None, will attempt to use huntertrace.analysis.analyzer
            bootstrap_iterations: Number of bootstrap iterations for CI (default 1000)
            cost_config: CostConfig for cost-sensitive evaluation
            enable_adversarial: Whether to generate and evaluate adversarial samples
            adversarial_samples_per_input: Number of adversarial samples per input
        """
        self.scoring_config = scoring_config or ScoringConfig()
        self.signal_extractor = signal_extractor
        self.bootstrap_iterations = bootstrap_iterations
        self.cost_config = cost_config or CostConfig()
        self.enable_adversarial = enable_adversarial
        self.adversarial_samples_per_input = adversarial_samples_per_input

    def evaluate(
        self,
        samples: List[EvaluationSample],
        error_sample_limit: int = 10,
    ) -> EvaluationContext:
        """
        Evaluate pipeline on samples.

        Args:
            samples: EvaluationSample objects
            error_sample_limit: Max error cases to collect

        Returns:
            EvaluationContext with full results
        """
        if not samples:
            raise ValueError("No samples provided")

        # Extract signal extractor
        signal_extractor = self.signal_extractor
        if signal_extractor is None:
            signal_extractor = self._default_signal_extractor()

        # Collect predictions
        predictions = []
        all_calibration_preds = []
        error_cases = []

        for i, sample in enumerate(samples):
            try:
                signals, correlation = signal_extractor(sample.input_path)
                result = AtlasScoringEngine.score(signals, correlation, self.scoring_config)

                # Create prediction record
                pred = PredictionRecord(
                    sample_id=f"sample_{i}",
                    predicted_region=result.region,
                    predicted_verdict=result.verdict,
                    predicted_confidence=result.confidence,
                    ground_truth_region=sample.ground_truth_region,
                )
                predictions.append(pred)

                # Collect for calibration
                cal_pred = PredictionForCalibration(
                    confidence=result.confidence,
                    is_correct=pred.is_correct,
                )
                all_calibration_preds.append(cal_pred)

                # Collect errors
                if not pred.is_correct and len(error_cases) < error_sample_limit:
                    error_type = self._classify_error(pred, result)
                    error_case = ErrorCase(
                        sample_id=f"sample_{i}",
                        input_path=sample.input_path,
                        predicted_region=result.region,
                        ground_truth_region=sample.ground_truth_region,
                        predicted_confidence=result.confidence,
                        predicted_verdict=result.verdict,
                        error_type=error_type,
                        correlation_summary={
                            "consistency_score": round(result.consistency_score, 4),
                            "contradictions": len(result.anomalies),
                        },
                        reasoning=result.reasoning[:200] if result.reasoning else None,
                    )
                    error_cases.append(error_case)

            except Exception as e:
                # Record error as incorrect/inconclusive
                pred = PredictionRecord(
                    sample_id=f"sample_{i}",
                    predicted_region=None,
                    predicted_verdict="inconclusive",
                    predicted_confidence=0.0,
                    ground_truth_region=sample.ground_truth_region,
                )
                predictions.append(pred)
                cal_pred = PredictionForCalibration(confidence=0.0, is_correct=False)
                all_calibration_preds.append(cal_pred)

        # Compute metrics
        overall_metrics = compute_metrics(predictions)

        # Compute calibration metrics
        calibration_metrics = CalibrationAnalyzer.compute_ece(all_calibration_preds)

        # Compute stratified metrics
        stratified = self._compute_stratified_metrics(samples, predictions)

        # Compute threshold analysis
        threshold_analysis = self._compute_threshold_analysis(predictions)

        # Compute bootstrap confidence intervals (NEW)
        metric_confidence_intervals = {}
        if self.bootstrap_iterations > 0 and predictions:
            metric_confidence_intervals["accuracy"] = BootstrapAnalyzer.bootstrap_accuracy_ci(
                predictions, n_bootstrap=self.bootstrap_iterations, seed=42
            )
            metric_confidence_intervals["false_attribution_rate"] = (
                BootstrapAnalyzer.bootstrap_far_ci(
                    predictions, n_bootstrap=self.bootstrap_iterations, seed=42
                )
            )
            metric_confidence_intervals["precision"] = BootstrapAnalyzer.bootstrap_precision_ci(
                predictions, n_bootstrap=self.bootstrap_iterations, seed=42
            )
            metric_confidence_intervals["recall"] = BootstrapAnalyzer.bootstrap_recall_ci(
                predictions, n_bootstrap=self.bootstrap_iterations, seed=42
            )
            metric_confidence_intervals["f1_score"] = BootstrapAnalyzer.bootstrap_f1_ci(
                predictions, n_bootstrap=self.bootstrap_iterations, seed=42
            )

        # Compute cost metrics (NEW)
        cost_metrics = None
        if predictions:
            cost_metrics = CostAnalyzer.compute_cost_metrics(predictions, self.cost_config)

        # Compute adversarial robustness (NEW)
        robustness_metrics = None
        if self.enable_adversarial and predictions:
            robustness_metrics = self._compute_adversarial_robustness(
                samples, predictions, error_sample_limit
            )

        # Create context
        context = EvaluationContext(
            overall_metrics=overall_metrics,
            calibration_metrics=calibration_metrics,
            stratified_metrics=stratified,
            threshold_analysis=threshold_analysis,
            error_cases=error_cases,
            predictions=predictions,
            metric_confidence_intervals=metric_confidence_intervals,
            cost_metrics=cost_metrics,
            robustness_metrics=robustness_metrics,
        )

        return context

    def _classify_error(self, pred: PredictionRecord, result: AttributionResult) -> str:
        """Classify type of error."""
        if pred.is_abstained:
            if pred.ground_truth_region is not None:
                return "unnecessary_abstention"
        else:
            if pred.predicted_confidence > 0.6 and not pred.is_correct:
                return "overconfident_incorrect"
            else:
                return "false_attribution"
        return "false_attribution"

    def _compute_stratified_metrics(
        self,
        samples: List[EvaluationSample],
        predictions: List[PredictionRecord],
    ) -> List[StratifiedMetrics]:
        """Compute stratified metrics by sample characteristics."""
        strata = []

        # Stratum 1: Clean signals (high consistency score)
        clean_preds = []
        clean_count = 0
        for i, (sample, pred) in enumerate(zip(samples, predictions)):
            consistency_score = sample.metadata.get("consistency_score", 0.5)
            if consistency_score > 0.7:
                clean_preds.append(pred)
                clean_count += 1

        if clean_preds:
            metrics = compute_metrics(clean_preds)
            strata.append(StratifiedMetrics(
                stratum_name="clean_signals",
                stratum_filter="consistency_score > 0.7",
                metrics=metrics,
                sample_count=len(clean_preds),
            ))

        # Stratum 2: Conflicting signals
        conflicting_preds = []
        for i, (sample, pred) in enumerate(zip(samples, predictions)):
            has_anomalies = len(sample.metadata.get("anomalies", [])) > 0
            if has_anomalies:
                conflicting_preds.append(pred)

        if conflicting_preds:
            metrics = compute_metrics(conflicting_preds)
            strata.append(StratifiedMetrics(
                stratum_name="conflicting_signals",
                stratum_filter="anomalies present",
                metrics=metrics,
                sample_count=len(conflicting_preds),
            ))

        # Stratum 3: Low observability
        low_obs_preds = []
        for i, (sample, pred) in enumerate(zip(samples, predictions)):
            signal_count = sample.metadata.get("signal_count", 0)
            if signal_count < 5:
                low_obs_preds.append(pred)

        if low_obs_preds:
            metrics = compute_metrics(low_obs_preds)
            strata.append(StratifiedMetrics(
                stratum_name="low_observability",
                stratum_filter="signal_count < 5",
                metrics=metrics,
                sample_count=len(low_obs_preds),
            ))

        return strata

    def _compute_threshold_analysis(
        self,
        predictions: List[PredictionRecord],
    ) -> List[ThresholdAnalysis]:
        """Compute performance across confidence thresholds."""
        thresholds = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
        analysis = []

        for threshold in thresholds:
            # Filter predictions by threshold
            filtered = []
            for pred in predictions:
                if pred.predicted_verdict == "inconclusive":
                    # Abstained predictions always pass threshold
                    filtered.append(pred)
                elif pred.predicted_confidence >= threshold:
                    filtered.append(pred)
                else:
                    # Below threshold - treat as abstention
                    modified_pred = PredictionRecord(
                        sample_id=pred.sample_id,
                        predicted_region=None,
                        predicted_verdict="inconclusive",
                        predicted_confidence=pred.predicted_confidence,
                        ground_truth_region=pred.ground_truth_region,
                    )
                    filtered.append(modified_pred)

            metrics = compute_metrics(filtered)
            analysis.append(ThresholdAnalysis(
                threshold=threshold,
                accuracy=metrics.accuracy,
                false_attribution_rate=metrics.false_attribution_rate,
                abstention_rate=metrics.abstention_rate,
                coverage_rate=metrics.coverage_rate,
            ))

        return analysis

    def _compute_adversarial_robustness(
        self,
        samples: List[EvaluationSample],
        predictions: List[PredictionRecord],
        error_sample_limit: int,
    ) -> Optional[RobustnessMetrics]:
        """Compute adversarial robustness metrics."""
        if not samples or not predictions:
            return None

        signal_extractor = self.signal_extractor
        if signal_extractor is None:
            signal_extractor = self._default_signal_extractor()

        adversarial_results = []

        # Generate and evaluate adversarial samples
        for sample in samples[:error_sample_limit]:  # Limit to reduce computation
            try:
                # Generate adversarial variants
                adv_samples = AdversarialGenerator.generate_adversarial_variants(
                    sample.input_path, seed=42
                )

                for adv_sample in adv_samples:
                    try:
                        # Evaluate adversarial variant
                        signals, correlation = signal_extractor(adv_sample.adversarial_path)
                        result = AtlasScoringEngine.score(
                            signals, correlation, self.scoring_config
                        )

                        # Create prediction record for adversarial sample
                        pred = PredictionRecord(
                            sample_id=f"{adv_sample.attack_type}_0",
                            predicted_region=result.region,
                            predicted_verdict=result.verdict,
                            predicted_confidence=result.confidence,
                            ground_truth_region=sample.ground_truth_region,
                        )
                        adversarial_results.append((adv_sample.attack_type, [pred]))
                    except Exception:
                        # Skip failed adversarial evaluations
                        continue
            except Exception:
                # Skip if adversarial generation fails
                continue

        if not adversarial_results:
            return None

        # Compute robustness metrics
        return RobustnessAnalyzer.compute_robustness_metrics(
            predictions, adversarial_results
        )

    def _default_signal_extractor(self) -> Callable[[str], Tuple[List[Signal], CorrelationResult]]:
        """Get default signal extractor from huntertrace.analysis.analyzer."""
        try:
            from huntertrace.analysis.analyzer import Analyzer

            def extractor(input_path: str) -> Tuple[List[Signal], CorrelationResult]:
                analyzer = Analyzer()
                result = analyzer.analyze(input_path)
                return result.signals, result.correlation

            return extractor
        except ImportError:
            raise RuntimeError("Could not import Analyzer - provide signal_extractor manually")
