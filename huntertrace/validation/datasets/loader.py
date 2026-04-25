from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .schema import DatasetLoadResult
from ..schema import ValidationSample


class DatasetLoader:
    @staticmethod
    def load_jsonl(path: str | Path) -> DatasetLoadResult:
        p = Path(path)
        samples: List[ValidationSample] = []
        for idx, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
            if not raw.strip():
                continue
            item = json.loads(raw)
            samples.append(
                ValidationSample(
                    sample_id=str(item.get("sample_id") or f"sample_{idx}"),
                    input_path=str(item["input_path"]),
                    expected_region=item.get("expected_region"),
                    expected_verdict=item.get("expected_verdict"),
                    scenario_type=str(item.get("scenario_type", "unknown")),
                    metadata=dict(item.get("metadata") or {}),
                )
            )
        return DatasetLoadResult(samples=samples, dataset_name=p.stem, source="jsonl", metadata={"path": str(p)})

    @staticmethod
    def load_eml_folder(path: str | Path, labels_path: str | Path | None = None) -> DatasetLoadResult:
        base = Path(path)
        label_map = _load_label_map(labels_path or _auto_label_path(base))
        samples: List[ValidationSample] = []
        for eml in sorted(base.rglob("*.eml")):
            rel = eml.relative_to(base)
            scenario = rel.parts[0] if len(rel.parts) > 1 else "unknown"
            label = label_map.get(eml.name) or label_map.get(str(rel)) or label_map.get(eml.stem)
            samples.append(
                ValidationSample(
                    sample_id=eml.stem,
                    input_path=str(eml),
                    expected_region=(label or {}).get("expected_region"),
                    expected_verdict=(label or {}).get("expected_verdict"),
                    scenario_type=str((label or {}).get("scenario_type", scenario)),
                    metadata={"relative_path": str(rel)},
                )
            )
        return DatasetLoadResult(
            samples=samples,
            dataset_name=base.name,
            source="eml_folder",
            metadata={"path": str(base)},
            labels_path=str(labels_path) if labels_path else None,
        )

    @staticmethod
    def load_synthetic(count: int = 12, dataset_name: str = "synthetic") -> DatasetLoadResult:
        templates = _synthetic_templates()
        samples: List[ValidationSample] = []
        for idx in range(count):
            template = templates[idx % len(templates)]
            sample_id = f"{dataset_name}_{idx+1:04d}"
            content = _render_template(sample_id, template)
            samples.append(
                ValidationSample(
                    sample_id=sample_id,
                    input_path=f"synthetic://{sample_id}.eml",
                    expected_region=template["expected_region"],
                    expected_verdict=template["expected_verdict"],
                    scenario_type=template["scenario_type"],
                    metadata={"eml_content": content, "synthetic": True, "template": template["name"]},
                )
            )
        return DatasetLoadResult(samples=samples, dataset_name=dataset_name, source="synthetic")

    @staticmethod
    def load_dataset(path: str | Path, limit: Optional[int] = None) -> DatasetLoadResult:
        p = Path(path)
        if p.is_dir():
            result = DatasetLoader.load_eml_folder(p)
        elif p.suffix.lower() == ".jsonl":
            result = DatasetLoader.load_jsonl(p)
        elif p.suffix.lower() in {".json"}:
            payload = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                samples = [
                    ValidationSample(
                        sample_id=str(item.get("sample_id") or f"sample_{idx+1}"),
                        input_path=str(item["input_path"]),
                        expected_region=item.get("expected_region"),
                        expected_verdict=item.get("expected_verdict"),
                        scenario_type=str(item.get("scenario_type", "unknown")),
                        metadata=dict(item.get("metadata") or {}),
                    )
                    for idx, item in enumerate(payload)
                ]
                result = DatasetLoadResult(samples=samples, dataset_name=p.stem, source="json", metadata={"path": str(p)})
            else:
                result = DatasetLoadResult(samples=[], dataset_name=p.stem, source="json", metadata={"path": str(p)})
        else:
            result = DatasetLoadResult(samples=[], dataset_name=p.stem, source="unknown", metadata={"path": str(p)})
        if limit is not None:
            result.samples = result.samples[: int(limit)]
        return result


def load_dataset(path: str | Path, limit: Optional[int] = None) -> DatasetLoadResult:
    return DatasetLoader.load_dataset(path, limit=limit)


def _auto_label_path(base: Path) -> Optional[Path]:
    for candidate in ("labels.jsonl", "labels.json", "ground_truth.jsonl", "ground_truth.json"):
        p = base / candidate
        if p.exists():
            return p
    return None


def _load_label_map(path: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    if path is None or not path.exists():
        return {}
    if path.suffix.lower() == ".jsonl":
        mapping: Dict[str, Dict[str, Any]] = {}
        for raw in path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            item = json.loads(raw)
            key = str(item.get("sample_id") or item.get("file") or item.get("input_path") or "")
            if key:
                mapping[key] = dict(item)
        return mapping
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return {str(k): dict(v) for k, v in payload.items()}
    return {}


def _synthetic_templates() -> List[Dict[str, Any]]:
    return [
        {"name": "clean", "scenario_type": "clean", "expected_region": "India", "expected_verdict": "attributed"},
        {"name": "forwarded", "scenario_type": "forwarded", "expected_region": None, "expected_verdict": "inconclusive"},
        {"name": "mailing_list", "scenario_type": "mailing_list", "expected_region": None, "expected_verdict": "inconclusive"},
        {"name": "spoofed", "scenario_type": "spoofed", "expected_region": None, "expected_verdict": "inconclusive"},
        {"name": "vpn", "scenario_type": "anonymized", "expected_region": None, "expected_verdict": "inconclusive"},
        {"name": "malformed", "scenario_type": "malformed", "expected_region": None, "expected_verdict": "inconclusive"},
    ]


def _render_template(sample_id: str, template: Dict[str, Any]) -> str:
    subject = f"Validation {template['name']} {sample_id}"
    if template["scenario_type"] == "clean":
        date = "Tue, 02 Apr 2026 10:00:00 +0530"
        received = "Received: from sender.example.com (sender.example.com [203.0.113.10]) by mx.example.net with ESMTP; Tue, 02 Apr 2026 10:00:00 +0530"
    elif template["scenario_type"] == "spoofed":
        date = "Tue, 02 Apr 2026 10:00:00 -0500"
        received = "Received: from relay.example.com (relay.example.com [198.51.100.10]) by mx.example.net with ESMTP; Tue, 02 Apr 2026 15:00:00 +0000"
    else:
        date = "Tue, 02 Apr 2026 10:00:00 +0000"
        received = "Received: from mail.example.com (mail.example.com [198.51.100.10]) by mx.example.net with ESMTP; Tue, 02 Apr 2026 10:00:00 +0000"
    return (
        f"From: sender@example.com\n"
        f"To: recipient@example.com\n"
        f"Subject: {subject}\n"
        f"Date: {date}\n"
        f"{received}\n"
        f"\n"
        f"Validation body for {sample_id}\n"
    )
