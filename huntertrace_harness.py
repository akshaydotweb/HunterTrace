#!/usr/bin/env python3
"""
HUNTERTRACE VALIDATION HARNESS
===============================
Runs HunterTrace on synthetic dataset and measures attribution accuracy.

Metrics:
  - Origin country accuracy (true label vs predicted)
  - Obfuscation detection (VPN, proxy, etc.)
  - Infrastructure classification accuracy
  - Per-scenario breakdown

Output: JSON report with confusion matrix and per-sample results.
"""
import sys
import subprocess
import tempfile
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict

@dataclass
class PredictionResult:
    """Result from HunterTrace analysis."""
    email_id: str
    huntertrace_output: str
    predicted_country: str = None
    predicted_obfuscation: str = None
    predicted_ip: str = None
    confidence: float = 0.0
    error_msg: str = None

@dataclass
class ValidationMetrics:
    """Validation metrics for a scenario."""
    scenario: str
    total_samples: int
    correct_country: int
    correct_obfuscation: int
    correct_infrastructure: int
    avg_confidence: float
    accuracy_country: float = 0.0
    accuracy_obfuscation: float = 0.0
    accuracy_infrastructure: float = 0.0

class HunterTraceValidator:
    """Validate HunterTrace on synthetic dataset."""
    def __init__(self, huntertrace_path: str = "huntertrace"):
        self.huntertrace_path = huntertrace_path
        self.results: List[Tuple[Dict, PredictionResult]] = []

    def run_huntertrace(self, raw_email_path: str, verbose: bool = False) -> str:
        """Execute HunterTrace on an email file."""
        try:
            cmd = [self.huntertrace_path, "analyze", raw_email_path]
            if verbose:
                cmd.append("--verbose")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout
        except FileNotFoundError:
            return "[ERROR] HunterTrace not found at {}".format(self.huntertrace_path)
        except subprocess.TimeoutExpired:
            return "[ERROR] HunterTrace timed out"
        except Exception as e:
            return f"[ERROR] {e}"

    def extract_predictions(self, huntertrace_output: str) -> Tuple[str, str, str, float]:
        """Extract predictions from HunterTrace output."""
        predicted_country = "UNKNOWN"
        predicted_obfuscation = "unknown"
        predicted_ip = None
        confidence = 0.0
        country_match = re.search(r"\\[ATTRIBUTION\\].*?Primary region\\s*:\\s*(\\w+)", huntertrace_output, re.DOTALL)
        if country_match:
            predicted_country = country_match.group(1)
        if "VPN_PROVIDER" in huntertrace_output:
            predicted_obfuscation = "vpn"
        elif "PROXY" in huntertrace_output:
            predicted_obfuscation = "proxy"
        elif "TOR" in huntertrace_output:
            predicted_obfuscation = "tor"
        else:
            predicted_obfuscation = "none"
        ip_match = re.search(r"\\[INFO\\] Unique IPs found:\\s*([\\d.]+)", huntertrace_output)
        if ip_match:
            predicted_ip = ip_match.group(1)
        conf_match = re.search(r"Confidence\\s*:\\s*([\\d.]+)%", huntertrace_output)
        if conf_match:
            confidence = float(conf_match.group(1)) / 100.0
        return predicted_country, predicted_obfuscation, predicted_ip, confidence

    def validate_sample(self, label: Dict[str, Any], raw_email: str, email_id: str) -> PredictionResult:
        """Validate a single email sample."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
            f.write(raw_email)
            temp_path = f.name
        try:
            output = self.run_huntertrace(temp_path)
            pred_country, pred_obf, pred_ip, conf = self.extract_predictions(output)
            return PredictionResult(
                email_id=email_id,
                huntertrace_output=output,
                predicted_country=pred_country,
                predicted_obfuscation=pred_obf,
                predicted_ip=pred_ip,
                confidence=conf,
                error_msg=None
            )
        except Exception as e:
            return PredictionResult(
                email_id=email_id,
                huntertrace_output="",
                predicted_country=None,
                predicted_obfuscation=None,
                predicted_ip=None,
                confidence=0.0,
                error_msg=str(e)
            )
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def validate_dataset(self, samples: List[Dict], sample_size: int = None) -> Dict[str, Any]:
        if sample_size:
            samples = samples[:sample_size]
        print(f"\n[*] Validating {len(samples)} samples against HunterTrace...")
        print("=" * 80)
        metrics_by_scenario = defaultdict(lambda: {
            'total': 0,
            'correct_country': 0,
            'correct_obfuscation': 0,
            'correct_infrastructure': 0,
            'confidences': [],
            'samples': [],
        })
        for i, sample in enumerate(samples):
            email_id = sample.get('email_id')
            raw_email = sample.get('raw_email')
            labels = sample.get('labels', {})
            pred = self.validate_sample(labels, raw_email, email_id)
            scenario = labels.get('scenario', 'unknown')
            metrics = metrics_by_scenario[scenario]
            metrics['total'] += 1
            metrics['samples'].append(email_id)
            if pred.predicted_country and pred.predicted_country.lower() == labels.get('true_origin_country', '').lower():
                metrics['correct_country'] += 1
            if pred.predicted_obfuscation and pred.predicted_obfuscation in labels.get('obfuscation_types', []):
                metrics['correct_obfuscation'] += 1
            metrics['confidences'].append(pred.confidence)
            self.results.append((labels, pred))
            if i % 10 == 0:
                print(f"  [{i}/{len(samples)}] Processing...")
        print(f"  [✓] Validation complete!")
        print("=" * 80)
        summary = {
            'total_samples': len(samples),
            'scenarios': {},
            'overall': {},
        }
        total_correct_country = 0
        total_correct_obfuscation = 0
        all_confidences = []
        for scenario, metrics in metrics_by_scenario.items():
            acc_country = metrics['correct_country'] / metrics['total'] if metrics['total'] else 0
            acc_obf = metrics['correct_obfuscation'] / metrics['total'] if metrics['total'] else 0
            avg_conf = sum(metrics['confidences']) / len(metrics['confidences']) if metrics['confidences'] else 0
            summary['scenarios'][scenario] = {
                'samples': metrics['samples'],
                'accuracy_country': round(acc_country * 100, 1),
                'accuracy_obfuscation': round(acc_obf * 100, 1),
                'avg_confidence': round(avg_conf, 3),
            }
            total_correct_country += metrics['correct_country']
            total_correct_obfuscation += metrics['correct_obfuscation']
            all_confidences.extend(metrics['confidences'])
        overall_acc_country = total_correct_country / len(samples) if samples else 0
        overall_acc_obf = total_correct_obfuscation / len(samples) if samples else 0
        overall_conf = sum(all_confidences) / len(all_confidences) if all_confidences else 0
        summary['overall'] = {
            'accuracy_country': round(overall_acc_country * 100, 1),
            'accuracy_obfuscation': round(overall_acc_obf * 100, 1),
            'avg_confidence': round(overall_conf, 3),
        }
        return summary

def print_validation_report(summary: Dict[str, Any]):
    print("\n" + "=" * 80)
    print("HUNTERTRACE VALIDATION REPORT")
    print("=" * 80)
    print(f"\nTotal Samples: {summary['total_samples']}")
    print(f"\nOVERALL ACCURACY:")
    print(f"  Country Attribution: {summary['overall']['accuracy_country']:.1f}%")
    print(f"  Obfuscation Detection: {summary['overall']['accuracy_obfuscation']:.1f}%")
    print(f"  Avg Confidence: {summary['overall']['avg_confidence']:.1%}")
    print(f"\nPER-SCENARIO BREAKDOWN:")
    for scenario, metrics in summary['scenarios'].items():
        print(f"\n  [{scenario.upper()}]")
        print(f"    Samples: {metrics['samples']}")
        print(f"    Country Accuracy: {metrics['accuracy_country']:.1f}%")
        print(f"    Obfuscation Accuracy: {metrics['accuracy_obfuscation']:.1f}%")
        print(f"    Avg Confidence: {metrics['avg_confidence']:.1%}")
    print("\n" + "=" * 80)

if __name__ == "__main__":
    from dataset_generator import load_dataset_jsonl
    dataset_file = sys.argv[1] if len(sys.argv) > 1 else "synthetic_phishing_dataset.jsonl"
    if not Path(dataset_file).exists():
        print(f"[ERROR] Dataset file not found: {dataset_file}")
        print(f"[*] Run dataset_generator.py first to create the dataset")
        sys.exit(1)
    print(f"[*] Loading dataset: {dataset_file}")
    samples = load_dataset_jsonl(dataset_file)
    print(f"[+] Loaded {len(samples)} samples")
    validator = HunterTraceValidator(huntertrace_path="huntertrace")
    summary = validator.validate_dataset(samples, sample_size=60)
    print_validation_report(summary)
    report_file = "validation_report.json"
    with open(report_file, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\n[+] Report saved: {report_file}")
