"""Dataset loading and preparation for evaluation."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class EvaluationSample:
    """Single evaluation sample with ground truth and optional metadata."""

    input_path: str
    ground_truth_region: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate sample."""
        if not self.input_path:
            raise ValueError("input_path cannot be empty")
        if self.ground_truth_region is not None and not self.ground_truth_region.strip():
            raise ValueError("ground_truth_region must be valid string or None")


class DatasetLoader:
    """Load evaluation samples from various formats."""

    @staticmethod
    def load_jsonl(path: str | Path) -> List[EvaluationSample]:
        """
        Load samples from JSONL format.

        Expected format per line:
        {
            "input_path": "...",
            "ground_truth_region": "...",
            "metadata": {...}
        }
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"JSONL file not found: {path}")
        if not path.is_file():
            raise ValueError(f"Expected file, got directory: {path}")

        samples = []
        with open(path) as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    sample = DatasetLoader._parse_sample(obj, line_no)
                    samples.append(sample)
                except json.JSONDecodeError as e:
                    raise ValueError(f"Invalid JSON at line {line_no}: {e}")
                except Exception as e:
                    raise ValueError(f"Error parsing sample at line {line_no}: {e}")

        return samples

    @staticmethod
    def load_directory(
        directory: str | Path,
        labels_file: str = "labels.json",
        extension: str = ".eml",
    ) -> List[EvaluationSample]:
        """
        Load samples from directory of files + labels.json.

        Expected structure:
        - directory/
          - labels.json (mapping of filename -> ground_truth_region)
          - *.eml files (or other extension)
        """
        directory = Path(directory)
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")
        if not directory.is_dir():
            raise ValueError(f"Expected directory, got file: {directory}")

        labels_path = directory / labels_file
        if not labels_path.exists():
            raise FileNotFoundError(f"Labels file not found: {labels_path}")

        with open(labels_path) as f:
            labels = json.load(f)

        samples = []
        for filename, ground_truth in labels.items():
            file_path = directory / filename
            if not file_path.exists():
                # Skip missing files
                continue
            if not file_path.is_file():
                continue

            sample = EvaluationSample(
                input_path=str(file_path),
                ground_truth_region=ground_truth,
                metadata={"filename": filename, "source": "directory"},
            )
            samples.append(sample)

        return samples

    @staticmethod
    def _parse_sample(obj: Dict[str, Any], line_no: int) -> EvaluationSample:
        """Parse and validate sample object."""
        input_path = obj.get("input_path")
        if not input_path:
            raise ValueError(f"Missing 'input_path' at line {line_no}")

        ground_truth_region = obj.get("ground_truth_region")
        metadata = obj.get("metadata", {})

        if not isinstance(metadata, dict):
            raise ValueError(f"'metadata' must be dict at line {line_no}")

        return EvaluationSample(
            input_path=input_path,
            ground_truth_region=ground_truth_region,
            metadata=metadata,
        )


def load_dataset(
    path: str | Path,
    format: str = "auto",
) -> List[EvaluationSample]:
    """
    Load evaluation dataset.

    Args:
        path: Path to dataset (JSONL file or directory)
        format: "jsonl", "directory", or "auto" (detect)

    Returns:
        List of EvaluationSample objects
    """
    path = Path(path)

    if format == "auto":
        if path.is_file() and path.suffix == ".jsonl":
            format = "jsonl"
        elif path.is_dir():
            format = "directory"
        else:
            raise ValueError(f"Cannot auto-detect format for: {path}")

    if format == "jsonl":
        return DatasetLoader.load_jsonl(path)
    elif format == "directory":
        return DatasetLoader.load_directory(path)
    else:
        raise ValueError(f"Unknown format: {format}")
