from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..schema import ValidationSample


@dataclass
class DatasetLoadResult:
    samples: List[ValidationSample]
    dataset_name: str
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    labels_path: Optional[str] = None
