"""Test runner for layer-wise and full pipeline testing.

Orchestrates execution of tests across all pipeline layers.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional, Union

from huntertrace.parsing import AtlasHeaderPipeline
from huntertrace.signals import SignalBuilder
from huntertrace.analysis import AtlasCorrelationEngine, AtlasScoringEngine, Signal, ScoringConfig
from huntertrace.explainability import ExplainabilityEngine

from huntertrace.testing.metrics import TestResult
from huntertrace.testing.validators import (
    validate_parsing,
    validate_signals,
    validate_correlation,
    validate_scoring,
    validate_explainability,
    validate_expectations,
)


class TestRunner:
    """Execute tests on samples."""

    @staticmethod
    def run_parsing(samples: list[Union[Any, Any]]) -> list[TestResult]:
        """Run parsing layer on all samples.

        Args:
            samples: List of SyntheticSample or DatasetSample objects

        Returns:
            List of TestResult objects
        """
        results = []

        for i, sample in enumerate(samples):
            result_id = f"parse_{i}_{getattr(sample, 'category', 'unknown')}"
            start_time = time.time()

            try:
                # Get content
                content = (
                    sample.content
                    if hasattr(sample, "content")
                    else sample.path
                )

                # Parse
                hop_chain = AtlasHeaderPipeline.parse_header_string(content)

                # Validate
                validated_checks = validate_parsing(hop_chain)

                passed = validated_checks.get("parsing_successful", False)

                # Serialize output
                try:
                    output_dict = {
                        "hops": len(hop_chain.hops) if hasattr(hop_chain, "hops") else 0,
                        "completeness_score": (
                            hop_chain.completeness_score
                            if hasattr(hop_chain, "completeness_score")
                            else None
                        ),
                        "anomalies": [
                            str(f)
                            for h in (hop_chain.hops if hasattr(hop_chain, "hops") else [])
                            for f in (h.validation_flags if hasattr(h, "validation_flags") else [])
                        ],
                    }
                except Exception:
                    output_dict = {"hops": 0}

                results.append(
                    TestResult(
                        sample_id=result_id,
                        stage="parsing",
                        passed=passed,
                        duration_ms=(time.time() - start_time) * 1000,
                        output={"output": output_dict, "hop_chain": hop_chain},
                        validated_checks=validated_checks,
                    )
                )

            except Exception as e:
                results.append(
                    TestResult(
                        sample_id=result_id,
                        stage="parsing",
                        passed=False,
                        error=str(e),
                        duration_ms=(time.time() - start_time) * 1000,
                        validated_checks={
                            "parsing_successful": False,
                            "error": True,
                        },
                    )
                )

        return results

    @staticmethod
    def run_signals(hop_chains: list[Any]) -> tuple[list[TestResult], list[Any]]:
        """Run signals layer on parsed hop chains.

        Args:
            hop_chains: List of HopChain objects from parsing

        Returns:
            Tuple of (TestResult list, enriched_signals list)
        """
        results = []
        all_enriched_signals = []

        for i, hop_chain in enumerate(hop_chains):
            result_id = f"signals_{i}"
            start_time = time.time()

            try:
                # Extract signals
                signals, rejected = SignalBuilder.build(hop_chain)

                # Enrich signals using same logic as orchestrator
                enriched_signals = TestRunner._enrich_signals(signals)
                all_enriched_signals.append(enriched_signals)

                # Validate enriched signals (not raw signals)
                validated_checks = validate_signals(enriched_signals, rejected)
                passed = validated_checks.get("signals_valid", False)

                # Serialize output
                try:
                    output_dict = {
                        "signal_count": len(signals),
                        "rejected_count": len(rejected),
                        "avg_confidence": (
                            sum(getattr(s, "confidence", 0) for s in enriched_signals) / len(enriched_signals)
                            if enriched_signals
                            else 0
                        ),
                    }
                except Exception:
                    output_dict = {"signal_count": len(signals)}

                results.append(
                    TestResult(
                        sample_id=result_id,
                        stage="signals",
                        passed=passed,
                        duration_ms=(time.time() - start_time) * 1000,
                        output={"output": output_dict, "signals": enriched_signals},
                        validated_checks=validated_checks,
                    )
                )

            except Exception as e:
                results.append(
                    TestResult(
                        sample_id=result_id,
                        stage="signals",
                        passed=False,
                        error=str(e),
                        duration_ms=(time.time() - start_time) * 1000,
                        validated_checks={
                            "signals_valid": False,
                            "error": True,
                        },
                    )
                )
                all_enriched_signals.append([])

        return results, all_enriched_signals

    @staticmethod
    def _enrich_signals(signals: list[Any]) -> list[Signal]:
        """Enrich signals with region and group hints (copied from orchestrator)."""
        enriched = []
        for signal in signals:
            signal_id = getattr(signal, "signal_id", f"{signal.source}::{signal.name}")

            # Extract region hint from signal
            candidate_region = TestRunner._extract_region_hint(signal)

            # Extract group hint from signal name
            group = TestRunner._extract_group_hint(signal)

            # Base confidence with heuristic reduction
            base_confidence = getattr(signal, "confidence_initial", 0.5)
            if candidate_region is not None:
                enrichment_confidence = base_confidence * 0.8  # 20% reduction for heuristic
            else:
                enrichment_confidence = base_confidence

            enriched.append(
                Signal(
                    signal_id=signal_id,
                    name=signal.name,
                    value=signal.value,
                    source=signal.source,
                    validation_flags=getattr(signal, "validation_flags", ()),
                    confidence=enrichment_confidence,
                    evidence=getattr(signal, "evidence", ""),
                    candidate_region=candidate_region,
                    group=group,
                )
            )

        return enriched

    @staticmethod
    def _extract_region_hint(signal) -> Optional[str]:
        """Extract region hint from signal (copied from orchestrator)."""
        value_str = str(signal.value).lower()

        tld_map = {
            "uk": "UK",
            "de": "DE",
            "fr": "FR",
            "it": "IT",
            "es": "ES",
            "ru": "RU",
            "br": "BR",
            "au": "AU",
            "ca": "CA",
            "com": "US",
            "net": "US",
            "org": "US",
            "gov": "US",
            "edu": "US",
        }

        if "." in value_str and not all(c.isdigit() or c == "." for c in value_str.split(".")[-1]):
            parts = value_str.split(".")
            tld = parts[-1]

            if tld in tld_map:
                return tld_map[tld]

        if any(x in value_str for x in [".uk", ".gb", "london"]):
            return "UK"
        elif any(x in value_str for x in [".de", "berlin"]):
            return "DE"
        elif any(x in value_str for x in [".fr", "paris"]):
            return "FR"
        elif any(x in value_str for x in [".jp", "tokyo"]):
            return "JP"
        elif any(x in value_str for x in [".cn", "beijing"]):
            return "CN"

        return None

    @staticmethod
    def _extract_group_hint(signal) -> Optional[str]:
        """Extract group hint from signal name (copied from orchestrator)."""
        name = signal.name
        if name.startswith("hop_timestamp") or name in ["hop_count", "chain_completeness_score"]:
            return "temporal"
        elif name.startswith("hop_from") or name.startswith("hop_by") or name == "hop_protocol":
            return "infrastructure"
        elif name in ["chain_anomaly_count", "anomaly_types"]:
            return "structure"
        else:
            return "quality"

    @staticmethod
    def run_correlation(signals_list: list[list[Any]]) -> tuple[list[TestResult], list[Any]]:
        """Run correlation layer.

        Args:
            signals_list: List of Signal lists

        Returns:
            Tuple of (TestResult list, CorrelationResult list)
        """
        results = []
        all_correlations = []

        for i, signals in enumerate(signals_list):
            result_id = f"correlation_{i}"
            start_time = time.time()

            try:
                # Correlate
                correlation = AtlasCorrelationEngine.correlate(signals)

                all_correlations.append(correlation)

                # Validate
                validated_checks = validate_correlation(correlation)
                passed = validated_checks.get("correlation_valid", False)

                # Serialize output
                try:
                    output_dict = {
                        "consistency_score": (
                            correlation.consistency_score
                            if hasattr(correlation, "consistency_score")
                            else None
                        ),
                        "contradiction_count": (
                            len(correlation.contradictions)
                            if hasattr(correlation, "contradictions")
                            else 0
                        ),
                        "relationship_count": (
                            len(correlation.relationships)
                            if hasattr(correlation, "relationships")
                            else 0
                        ),
                    }
                except Exception:
                    output_dict = {"consistency_score": None}

                results.append(
                    TestResult(
                        sample_id=result_id,
                        stage="correlation",
                        passed=passed,
                        duration_ms=(time.time() - start_time) * 1000,
                        output={"output": output_dict, "correlation": correlation},
                        validated_checks=validated_checks,
                    )
                )

            except Exception as e:
                results.append(
                    TestResult(
                        sample_id=result_id,
                        stage="correlation",
                        passed=False,
                        error=str(e),
                        duration_ms=(time.time() - start_time) * 1000,
                        validated_checks={
                            "correlation_valid": False,
                            "error": True,
                        },
                    )
                )
                all_correlations.append(None)

        return results, all_correlations

    @staticmethod
    def run_scoring(
        signals_list: list[list[Any]],
        correlations: list[Any],
        config: Optional[ScoringConfig] = None,
    ) -> tuple[list[TestResult], list[Any]]:
        """Run scoring layer.

        Args:
            signals_list: List of Signal lists
            correlations: List of CorrelationResult objects
            config: Optional ScoringConfig

        Returns:
            Tuple of (TestResult list, AttributionResult list)
        """
        results = []
        all_results = []

        if config is None:
            config = ScoringConfig()

        for i, (signals, correlation) in enumerate(zip(signals_list, correlations)):
            result_id = f"scoring_{i}"
            start_time = time.time()

            try:
                if correlation is None:
                    raise ValueError("Missing correlation result")

                # Score
                attribution = AtlasScoringEngine.score(signals, correlation, config)

                all_results.append(attribution)

                # Validate
                validated_checks = validate_scoring(attribution)
                passed = validated_checks.get("scoring_valid", False)

                # Serialize output
                try:
                    output_dict = {
                        "region": attribution.region if hasattr(attribution, "region") else None,
                        "confidence": (
                            attribution.confidence
                            if hasattr(attribution, "confidence")
                            else None
                        ),
                        "verdict": attribution.verdict if hasattr(attribution, "verdict") else None,
                        "anomalies": (
                            [str(a) for a in attribution.anomalies]
                            if hasattr(attribution, "anomalies")
                            else []
                        ),
                    }
                except Exception:
                    output_dict = {"region": None, "confidence": None}

                results.append(
                    TestResult(
                        sample_id=result_id,
                        stage="scoring",
                        passed=passed,
                        duration_ms=(time.time() - start_time) * 1000,
                        output={"output": output_dict, "attribution": attribution},
                        validated_checks=validated_checks,
                    )
                )

            except Exception as e:
                results.append(
                    TestResult(
                        sample_id=result_id,
                        stage="scoring",
                        passed=False,
                        error=str(e),
                        duration_ms=(time.time() - start_time) * 1000,
                        validated_checks={
                            "scoring_valid": False,
                            "error": True,
                        },
                    )
                )
                all_results.append(None)

        return results, all_results

    @staticmethod
    def run_explainability(
        attributions: list[Any],
        correlations: list[Any],
        signals_list: list[list[Any]],
        hop_chains: list[Any],
    ) -> list[TestResult]:
        """Run explainability layer (optional).

        Args:
            attributions: List of AttributionResult objects
            correlations: List of CorrelationResult objects
            signals_list: List of Signal lists
            hop_chains: List of HopChain objects

        Returns:
            List of TestResult objects
        """
        results = []

        for i, (attr, corr, signals, hop_chain) in enumerate(
            zip(attributions, correlations, signals_list, hop_chains)
        ):
            result_id = f"explainability_{i}"
            start_time = time.time()

            try:
                if attr is None or corr is None:
                    raise ValueError("Missing attribution or correlation")

                # Explain
                engine = ExplainabilityEngine(hop_chain)
                explanation = engine.explain(attr, corr, signals, hop_chain)

                # Validate
                validated_checks = validate_explainability(explanation, hop_chain)
                passed = validated_checks.get("explainability_valid", False)

                # Serialize output
                try:
                    output_dict = {
                        "verdict": (
                            explanation.verdict if hasattr(explanation, "verdict") else None
                        ),
                        "evidence_links": (
                            len(explanation.evidence_links)
                            if hasattr(explanation, "evidence_links")
                            else 0
                        ),
                        "contributions": (
                            len(explanation.contributions)
                            if hasattr(explanation, "contributions")
                            else 0
                        ),
                    }
                except Exception:
                    output_dict = {"verdict": None}

                results.append(
                    TestResult(
                        sample_id=result_id,
                        stage="explainability",
                        passed=passed,
                        duration_ms=(time.time() - start_time) * 1000,
                        output={"output": output_dict, "explanation": explanation},
                        validated_checks=validated_checks,
                    )
                )

            except Exception as e:
                results.append(
                    TestResult(
                        sample_id=result_id,
                        stage="explainability",
                        passed=False,
                        error=str(e),
                        duration_ms=(time.time() - start_time) * 1000,
                        validated_checks={
                            "explainability_valid": False,
                            "error": True,
                        },
                    )
                )

        return results

    @staticmethod
    def run_full_pipeline(
        samples: list[Union[Any, Any]],
        config: Optional[ScoringConfig] = None,
        enable_explainability: bool = True,
    ) -> list[TestResult]:
        """Run all layers end-to-end on samples.

        Args:
            samples: List of SyntheticSample or DatasetSample objects
            config: Optional ScoringConfig
            enable_explainability: Whether to run explainability layer

        Returns:
            List of TestResult objects for full pipeline
        """
        results = []

        # Run parsing
        parse_results = TestRunner.run_parsing(samples)
        hop_chains = [
            r.output.get("hop_chain") if r.passed else None for r in parse_results
        ]

        # Run signals
        valid_hop_chains = [h for h in hop_chains if h is not None]
        if valid_hop_chains:
            signal_results, signals_list = TestRunner.run_signals(valid_hop_chains)
        else:
            signal_results, signals_list = [], []

        # Run correlation
        if signals_list:
            corr_results, correlations = TestRunner.run_correlation(signals_list)
        else:
            corr_results, correlations = [], []

        # Run scoring
        if signals_list and correlations:
            score_results, attributions = TestRunner.run_scoring(signals_list, correlations, config)
        else:
            score_results, attributions = [], []

        # Run explainability (optional)
        explain_results = []
        if enable_explainability and attributions and signals_list:
            explain_results = TestRunner.run_explainability(
                attributions, correlations, signals_list, valid_hop_chains
            )

        # Combine all results into full pipeline results
        for i, sample in enumerate(samples):
            result_id = f"full_{i}_{getattr(sample, 'category', 'unknown')}"
            start_time_parse = parse_results[i].duration_ms if i < len(parse_results) else 0
            total_duration = start_time_parse

            # Check all stages passed
            parse_ok = parse_results[i].passed if i < len(parse_results) else False
            signal_ok = (
                signal_results[min(i, len(signal_results) - 1)].passed
                if signal_results
                else False
            )
            corr_ok = (
                corr_results[min(i, len(corr_results) - 1)].passed
                if corr_results
                else False
            )
            score_ok = (
                score_results[min(i, len(score_results) - 1)].passed
                if score_results
                else False
            )

            all_passed = parse_ok and signal_ok and corr_ok and score_ok

            # Get final output
            final_output = {}
            if score_ok and i < len(score_results):
                score_result = score_results[i]
                if "output" in score_result.output:
                    final_output = score_result.output["output"]

            # Check expectations (for synthetic samples)
            expectations = {}
            if hasattr(sample, "expected_behavior"):
                expectations = validate_expectations(sample, final_output)

            results.append(
                TestResult(
                    sample_id=result_id,
                    stage="full",
                    passed=all_passed and all(expectations.values()) if expectations else all_passed,
                    duration_ms=(
                        sum(
                            r.duration_ms
                            for r in parse_results + signal_results + corr_results + score_results + explain_results
                            if r is not None
                        ) / len(samples)
                        if samples
                        else 0
                    ),
                    output=final_output,
                    validated_checks={
                        "parse_ok": parse_ok,
                        "signal_ok": signal_ok,
                        "correlation_ok": corr_ok,
                        "scoring_ok": score_ok,
                        **expectations,
                    },
                )
            )

        return results
