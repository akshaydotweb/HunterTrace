from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import time
from contextlib import ExitStack, redirect_stdout, redirect_stderr, contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from .datasets import DatasetLoader, DatasetLoadResult, load_dataset
from .metrics import (
    AdversarialMetrics,
    ConfidenceMetrics,
    GlobalMetrics,
    PhaseMetrics,
    compute_adversarial_metrics,
    compute_confidence_metrics,
    compute_global_metrics,
    compute_phase_metrics,
)
from .phase_tests import (
    validate_calibration,
    validate_correlation,
    validate_enrichment,
    validate_explainability,
    validate_hops,
    validate_normalization,
    validate_parsing,
    validate_provenance,
    validate_scoring,
    validate_semantic,
    validate_signals,
)
from .reporting import build_report, build_summary_text, dump_json, to_jsonable
from .schema import AdversarialResult, EvaluationReport, SampleRunResult, ValidationSample
from .thresholds import DEFAULT_THRESHOLDS


class ValidationRunner:
    def __init__(
        self,
        pipeline_factory: Optional[Callable[[], Any]] = None,
        repeat_count: int = 2,
        skip_enrichment: bool = True,
        offline_requests: bool = True,
        code_version: str = "unknown",
    ) -> None:
        self.pipeline_factory = pipeline_factory or self._default_pipeline_factory
        self.repeat_count = max(1, int(repeat_count))
        self.skip_enrichment = skip_enrichment
        self.offline_requests = offline_requests
        self.code_version = code_version

    def run_single(self, sample: ValidationSample) -> SampleRunResult:
        start = time.perf_counter()
        result = self._run_pipeline(sample)
        repeat = self._run_pipeline(sample) if self.repeat_count > 1 else result
        raw_hash = self._hash_result(result)
        repeat_hash = self._hash_result(repeat)
        deterministic = raw_hash == repeat_hash
        phase_results = {
            "parsing": validate_parsing(sample, result),
            "hop_reconstruction": validate_hops(sample, result),
            "signals": validate_signals(sample, result),
            "normalization": validate_normalization(sample, result),
            "enrichment": validate_enrichment(sample, result),
            "provenance": validate_provenance(sample, result),
            "semantic": validate_semantic(sample, result),
            "correlation": validate_correlation(sample, result, repeated_result=repeat),
            "scoring": validate_scoring(sample, result),
            "calibration": validate_calibration(sample, result),
            "explainability": validate_explainability(sample, result),
        }
        bayes = getattr(result, "bayesian_attribution", None)
        confidence = float(getattr(bayes, "aci_adjusted_prob", 0.0) or 0.0)
        predicted_region = getattr(bayes, "primary_region", None) if bayes else None
        predicted_verdict = _predict_verdict(result)
        runtime_ms = (time.perf_counter() - start) * 1000.0
        return SampleRunResult(
            sample=sample,
            predicted_region=predicted_region,
            predicted_verdict=predicted_verdict,
            confidence=confidence,
            repeat_hash=repeat_hash,
            deterministic=deterministic,
            runtime_ms=runtime_ms,
            phase_results=phase_results,
            raw_result=result,
            raw_result_hash=raw_hash,
        )

    def run_dataset(self, dataset_path: str | Path, limit: Optional[int] = None, enable_adversarial: bool = False, bootstrap_iterations: int = 0) -> EvaluationReport:
        dataset = load_dataset(dataset_path, limit=limit)
        sample_results = [self.run_single(sample) for sample in dataset.samples]
        phase_metrics = compute_phase_metrics(sample_results)
        global_metrics = compute_global_metrics(sample_results)
        confidence_metrics = compute_confidence_metrics(sample_results)
        adversarial_results = []
        if enable_adversarial:
            for sample in dataset.samples:
                adversarial_results.extend(self.run_adversarial(sample))
        adversarial_metrics = compute_adversarial_metrics(adversarial_results)
        determinism = {
            "all_deterministic": all(item.deterministic for item in sample_results),
            "mismatched_samples": [item.sample.sample_id for item in sample_results if not item.deterministic],
            "hashes": {item.sample.sample_id: item.raw_result_hash for item in sample_results},
        }
        return build_report(
            dataset_name=dataset.dataset_name,
            sample_results=sample_results,
            phase_metrics=phase_metrics,
            global_metrics=global_metrics,
            confidence_metrics=confidence_metrics,
            adversarial_metrics=adversarial_metrics,
            determinism_check=determinism,
            code_version=self.code_version,
        )

    def run_adversarial(self, sample: ValidationSample) -> List[AdversarialResult]:
        baseline = self.run_single(sample)
        attacks = ["header_injection", "timestamp_spoof", "broken_chain", "mixed_infrastructure", "relay_mimicry"]
        results: List[AdversarialResult] = []
        for attack in attacks:
            attacked_sample = self._mutate_sample(sample, attack)
            attacked = self.run_single(attacked_sample)
            confidence_drop = max(0.0, baseline.confidence - attacked.confidence)
            far_increase = 1.0 if baseline.predicted_verdict == "attributed" and attacked.predicted_verdict != "attributed" else 0.0
            detected = attacked.predicted_verdict != "attributed" or attacked.confidence <= baseline.confidence
            robustness_score = max(0.0, 1.0 - confidence_drop - far_increase)
            results.append(
                AdversarialResult(
                    attack_type=attack,
                    baseline_confidence=baseline.confidence,
                    attacked_confidence=attacked.confidence,
                    confidence_drop=confidence_drop,
                    baseline_verdict=baseline.predicted_verdict,
                    attacked_verdict=attacked.predicted_verdict,
                    far_increase=far_increase,
                    detected=detected,
                    robustness_score=robustness_score,
                    notes=[f"sample={sample.sample_id}"],
                )
            )
        return results

    def export_report(self, report: EvaluationReport, path: str | Path) -> None:
        dump_json(report, path)

    def summarize(self, report: EvaluationReport) -> str:
        return build_summary_text(report)

    def _default_pipeline_factory(self) -> Any:
        from huntertrace.core.pipeline import CompletePipeline

        return CompletePipeline(verbose=False, skip_enrichment=self.skip_enrichment)

    def _run_pipeline(self, sample: ValidationSample) -> Any:
        pipeline = self.pipeline_factory()
        with self._offline_requests():
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                input_path = self._materialize(sample)
                try:
                    return pipeline.run(str(input_path))
                finally:
                    self._cleanup_materialized(sample, input_path)

    def _materialize(self, sample: ValidationSample) -> Path:
        if sample.input_path.startswith("synthetic://"):
            temp_dir = Path(tempfile.gettempdir()) / "huntertrace_validation"
            temp_dir.mkdir(parents=True, exist_ok=True)
            content = sample.metadata.get("eml_content", "")
            path = temp_dir / f"{sample.sample_id}.eml"
            path.write_text(content, encoding="utf-8")
            return path
        return sample.resolve_path()

    def _cleanup_materialized(self, sample: ValidationSample, path: Path) -> None:
        if sample.input_path.startswith("synthetic://") and path.exists():
            try:
                path.unlink()
            except OSError:
                pass

    @contextmanager
    def _offline_requests(self):
        if not self.offline_requests:
            yield
            return
        import requests

        class _OfflineResponse:
            status_code = 503
            text = ""
            content = b""

            def json(self) -> Dict[str, Any]:
                return {}

            def raise_for_status(self) -> None:
                raise requests.RequestException("offline validation")

        def _offline_get(*_args, **_kwargs):
            return _OfflineResponse()

        with ExitStack() as stack:
            modules = []
            for mod_name in (
                "huntertrace.core.pipeline",
                "huntertrace.enrichment.geolocation",
                "huntertrace.enrichment.hosting",
            ):
                try:
                    module = __import__(mod_name, fromlist=["requests"])
                    if hasattr(module, "requests"):
                        modules.append(module)
                except Exception:
                    continue
            originals = []
            for module in modules:
                originals.append((module, module.requests.get))
                module.requests.get = _offline_get
            try:
                yield
            finally:
                for module, original in originals:
                    module.requests.get = original

    def _hash_result(self, result: Any) -> str:
        payload = json.dumps(self._summarize_result(result), sort_keys=True, default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _summarize_result(self, result: Any) -> Dict[str, Any]:
        header = getattr(result, "header_analysis", None)
        bayes = getattr(result, "bayesian_attribution", None)
        geo = getattr(result, "geolocation_results", {}) or {}
        correlation = getattr(result, "correlation_analysis", None)
        return {
            "header": {
                "from": getattr(header, "email_from", None),
                "to": getattr(header, "email_to", None),
                "subject": getattr(header, "email_subject", None),
                "date": getattr(header, "email_date", None),
                "hop_count": getattr(header, "hop_count", None),
            },
            "hops": [
                {
                    "hop_number": getattr(hop, "hop_number", None),
                    "ip": getattr(hop, "ip", None),
                    "ipv6": getattr(hop, "ipv6", None),
                }
                for hop in list(getattr(header, "hops", []) or [])
            ],
            "geo": {
                ip: {
                    "country": getattr(item, "country", None),
                    "country_code": getattr(item, "country_code", None),
                    "city": getattr(item, "city", None),
                }
                for ip, item in sorted(geo.items(), key=lambda kv: str(kv[0]))
            },
            "bayes": {
                "primary_region": getattr(bayes, "primary_region", None),
                "aci_adjusted_prob": float(getattr(bayes, "aci_adjusted_prob", 0.0) or 0.0),
                "tier": getattr(bayes, "tier", None),
                "signals_used": list(getattr(bayes, "signals_used", []) or []),
                "reliability_mode": getattr(bayes, "reliability_mode", None),
            },
            "correlation": {
                "clusters": len(getattr(correlation, "clusters", []) or []),
                "patterns": len(getattr(correlation, "patterns", []) or []),
            },
        }

    def _mutate_sample(self, sample: ValidationSample, attack: str) -> ValidationSample:
        content = sample.metadata.get("eml_content")
        if not content and not sample.input_path.startswith("synthetic://"):
            content = Path(sample.input_path).read_text(encoding="utf-8", errors="ignore")
        content = content or ""
        if attack == "header_injection":
            mutated = "X-Validation-Attack: header-injection\n" + content
        elif attack == "timestamp_spoof":
            mutated = content.replace("+0530", "-0500").replace("+0000", "-0500")
        elif attack == "broken_chain":
            mutated = "\n".join(line for line in content.splitlines() if not line.startswith("Received:") or "sender" in line)
        elif attack == "mixed_infrastructure":
            mutated = content.replace("203.0.113.10", "198.51.100.23")
        else:
            mutated = content + "\nX-Relay-Mimicry: true\n"
        return ValidationSample(
            sample_id=f"{sample.sample_id}__{attack}",
            input_path=f"synthetic://{sample.sample_id}__{attack}.eml",
            expected_region=sample.expected_region,
            expected_verdict=sample.expected_verdict,
            scenario_type=sample.scenario_type,
            metadata={"synthetic": True, "eml_content": mutated, "attack_type": attack},
        )


def _predict_verdict(result: Any) -> str:
    bayes = getattr(result, "bayesian_attribution", None)
    if bayes and float(getattr(bayes, "aci_adjusted_prob", 0.0) or 0.0) >= 0.50:
        return "attributed"
    return "inconclusive"
