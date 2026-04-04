"""Pipeline orchestration for HunterTrace Atlas service."""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict
from typing import Any, Dict, Optional

from huntertrace.analysis import (
    AtlasCorrelationEngine,
    AtlasScoringEngine,
    Signal,
    ScoringConfig,
)
from huntertrace.analysis.scoring import AttributionResult
from huntertrace.explainability.engine import ExplainabilityEngine
from huntertrace.explainability.formatter import FormatterFactory
from huntertrace.parsing import AtlasHeaderPipeline
from huntertrace.service.schemas import AnalysisOptions, MetadataResponse
from huntertrace.signals import SignalBuilder


class PipelineOrchestrator:
    """Orchestrates the full analysis pipeline."""

    PIPELINE_VERSION = "1.0.0"

    def __init__(self, config: Optional[ScoringConfig] = None):
        """Initialize orchestrator.

        Args:
            config: Optional ScoringConfig for customization
        """
        self.config = config or ScoringConfig()

    def run_pipeline(
        self,
        input_content: str,
        input_type: str,
    ) -> tuple[AttributionResult, Dict[str, Any]]:
        """Run core pipeline (parse → signals → correlate → score).

        Args:
            input_content: Email content (EML or raw headers)
            input_type: "eml" or "raw"

        Returns:
            Tuple of (AttributionResult, execution_stats)

        Raises:
            ValueError: If parsing or analysis fails
        """
        start_time = time.time()
        stats = {"stages": {}}

        try:
            # Stage 1: Parse
            stage_start = time.time()
            try:
                if input_type == "eml":
                    hop_chain = AtlasHeaderPipeline.parse_header_string(input_content)
                elif input_type == "raw":
                    hop_chain = AtlasHeaderPipeline.parse_header_string(input_content)
                else:
                    raise ValueError(f"Unknown input_type: {input_type}")
            except Exception as e:
                raise ValueError(f"Parsing failed: {str(e)}")

            stats["stages"]["parsing"] = time.time() - stage_start

            # Stage 2: Build signals
            stage_start = time.time()
            signals_raw, rejected = SignalBuilder.build(hop_chain)
            stats["stages"]["signal_building"] = time.time() - stage_start

            # Enrich signals with region and group hints
            enriched_signals = self._enrich_signals(signals_raw)
            stats["signals_count"] = len(enriched_signals)
            stats["rejected_count"] = len(rejected)

            # Stage 3: Correlate
            stage_start = time.time()
            correlation = AtlasCorrelationEngine.correlate(enriched_signals)
            stats["stages"]["correlation"] = time.time() - stage_start

            # Stage 4: Score
            stage_start = time.time()
            result = AtlasScoringEngine.score(enriched_signals, correlation, self.config)
            stats["stages"]["scoring"] = time.time() - stage_start

            stats["total_time"] = time.time() - start_time
            # CRITICAL FIX #1: Store hop_chain for explainability traceability
            stats["hop_chain"] = hop_chain
            stats["enriched_signals"] = enriched_signals
            stats["correlation"] = correlation

            return result, stats

        except Exception as e:
            raise ValueError(f"Pipeline execution failed: {str(e)}")

    def run_full_analysis(
        self,
        input_content: str,
        input_type: str,
        options: AnalysisOptions,
    ) -> Dict[str, Any]:
        """Run full analysis with optional explainability and evaluation.

        Args:
            input_content: Email content
            input_type: "eml" or "raw"
            options: Analysis options

        Returns:
            Dictionary with result, explainability, evaluation, etc.
        """
        analysis_start = time.time()

        # Run core pipeline
        attribution_result, exec_stats = self.run_pipeline(input_content, input_type)

        # CRITICAL FIX #2: Compute deterministic hash with full context
        deterministic_hash = self._compute_deterministic_hash(
            input_content=input_content,
            signals_used=[asdict(s) for s in attribution_result.signals_used],
            correlation=exec_stats.get("correlation"),
            result=attribution_result,
            config_version=str(self.config),
        )

        # Build base response
        response: Dict[str, Any] = {
            "region": attribution_result.region,
            "confidence": float(attribution_result.confidence),
            "verdict": attribution_result.verdict,
            "consistency_score": float(attribution_result.consistency_score),
            "signals_used": [asdict(s) for s in attribution_result.signals_used],
            "signals_rejected": [asdict(s) for s in attribution_result.signals_rejected],
            "anomalies": attribution_result.anomalies,
            "limitations": list(attribution_result.limitations),
            "reasoning": attribution_result.reasoning,
        }

        # Optionally add explainability
        if options.include_explainability:
            response["explainability"] = self._add_explainability(
                exec_stats, attribution_result
            )

        # Optionally add evaluation (stub for now)
        if options.include_evaluation:
            response["evaluation"] = None  # TODO: DESIGN: move to separate /evaluate endpoint

        # Optionally add adversarial testing (stub for now)
        if options.include_adversarial:
            response["adversarial"] = None  # TODO: DESIGN: move to separate /adversarial endpoint

        # Add metadata
        response["metadata"] = {
            "processing_time_ms": (time.time() - analysis_start) * 1000,
            "pipeline_version": self.PIPELINE_VERSION,
            "deterministic_hash": deterministic_hash,
            "input_size_bytes": len(input_content.encode("utf-8")),
        }

        return response

    @staticmethod
    def _enrich_signals(signals: list) -> list[Signal]:
        """Enrich signals with region and group hints for scoring.

        CRITICAL FIX #7: Marks heuristic-based enrichments with lower confidence.
        """
        enriched = []
        for signal in signals:
            signal_id = getattr(signal, "signal_id", f"{signal.source}::{signal.name}")

            # Extract region hint from signal (HEURISTIC)
            candidate_region = PipelineOrchestrator._extract_region_hint(signal)

            # Extract group hint from signal name
            group = PipelineOrchestrator._extract_group_hint(signal)

            # CRITICAL FIX #7: Reduce confidence for heuristic-based enrichments
            base_confidence = getattr(signal, "confidence_initial", 0.5)
            if candidate_region is not None:
                # Confidence reduced for heuristic region extraction (TLD-based)
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
                    confidence=enrichment_confidence,  # Reduced for heuristics
                    evidence=getattr(signal, "evidence", ""),
                    candidate_region=candidate_region,
                    group=group,
                )
            )

        return enriched

    @staticmethod
    def _extract_region_hint(signal) -> Optional[str]:
        """Extract region hint from signal using hostname TLD heuristics."""
        value_str = str(signal.value).lower()

        # Extract TLD from hostnames
        if "." in value_str and not all(c.isdigit() or c == "." for c in value_str.split(".")[-1]):
            parts = value_str.split(".")
            tld = parts[-1]

            # TLD to region mapping
            tld_map = {
                "uk": "UK",
                "gb": "UK",
                "de": "DE",
                "fr": "FR",
                "jp": "JP",
                "cn": "CN",
                "in": "IN",
                "ir": "IR",
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

            if tld in tld_map:
                return tld_map[tld]

        # Hostname-based heuristics
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
        """Extract group hint from signal name."""
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
    def _add_explainability(exec_stats: Dict[str, Any], result: AttributionResult) -> Dict[str, Any]:
        """Add explainability layer to response with full traceability.

        CRITICAL FIX #1: Uses real hop_chain for evidence linking.
        """
        try:
            # Get hop_chain from exec_stats (now stored by run_pipeline)
            hop_chain = exec_stats.get("hop_chain")
            enriched_signals = exec_stats.get("enriched_signals", [])

            if hop_chain is None:
                raise ValueError("hop_chain not available for explainability")

            # Create explainability engine with REAL hop_chain
            engine = ExplainabilityEngine(hop_chain=hop_chain)

            # Create explainability result from attribution result
            explainability_result = engine.explain(
                signals=enriched_signals,
                correlation=exec_stats.get("correlation"),
                attribution=result,
            )

            # Convert to dictionary
            explainability_dict = explainability_result.to_dict() if hasattr(explainability_result, "to_dict") else {
                "verdict": result.verdict,
                "region": result.region,
                "confidence": float(result.confidence),
                "decision_trace": explainability_result.decision_trace if hasattr(explainability_result, "decision_trace") else [result.reasoning],
                "contributions": [asdict(s) for s in result.signals_used],
                "evidence_links": explainability_result.evidence_links if hasattr(explainability_result, "evidence_links") else [],
                "anomalies": explainability_result.anomalies if hasattr(explainability_result, "anomalies") else result.anomalies,
                "limitations": explainability_result.limitations if hasattr(explainability_result, "limitations") else list(result.limitations),
                "explanation": explainability_result.explanation if hasattr(explainability_result, "explanation") else result.reasoning,
            }

            return explainability_dict
        except Exception as e:
            # Graceful degradation - return basic explainability if full engine fails
            return {
                "verdict": result.verdict,
                "region": result.region,
                "confidence": float(result.confidence),
                "decision_trace": [result.reasoning] if result.reasoning else [],
                "contributions": [asdict(s) for s in result.signals_used],
                "evidence_links": [],
                "anomalies": result.anomalies,
                "limitations": list(result.limitations),
                "explanation": f"Explainability degraded due to: {str(e)}",
                "degradation_reason": str(e),
            }

    @staticmethod
    def _compute_deterministic_hash(
        input_content: str,
        signals_used: list,
        correlation: Any,
        result: AttributionResult,
        config_version: str,
    ) -> str:
        """Compute deterministic hash combining input, signals, correlation, and config.

        CRITICAL FIX #2: Includes full context for true reproducibility verification.

        Args:
            input_content: Original email content
            signals_used: Signals used in scoring
            correlation: CorrelationResult object
            result: AttributionResult
            config_version: String representation of config

        Returns:
            SHA256 hash (hex, first 16 chars)
        """
        import json

        # Build comprehensive hash input
        hash_components = {
            "input": hash(input_content),  # Hash content to detect changes
            "signals_count": len(signals_used),
            "signals_hash": hash(tuple(str(s) for s in signals_used)),
            "correlation_score": correlation.consistency_score if hasattr(correlation, "consistency_score") else 0.0,
            "correlation_contradictions": len(correlation.contradictions) if hasattr(correlation, "contradictions") else 0,
            "result_region": result.region,
            "result_confidence": result.confidence,
            "result_verdict": result.verdict,
            "config_version": config_version,
        }

        # Convert to JSON for consistent serialization
        combined_str = json.dumps(hash_components, sort_keys=True, default=str)
        combined_bytes = combined_str.encode("utf-8")

        # Compute SHA256 and return first 16 hex chars
        return hashlib.sha256(combined_bytes).hexdigest()[:16]
