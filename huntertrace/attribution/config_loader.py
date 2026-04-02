#!/usr/bin/env python3
"""
Configuration loader for deterministic attribution scoring runtime.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

from huntertrace.attribution.scoring import ScoringConfig


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "scoring.yaml"


@dataclass(frozen=True)
class RuntimeConfig:
    scoring: ScoringConfig
    inference: Dict[str, Any]
    logging: Dict[str, Any]
    raw: Dict[str, Any]


def _to_scalar(value: str) -> Any:
    raw = value.strip()
    if not raw:
        return ""
    if raw.lower() in {"true", "false"}:
        return raw.lower() == "true"
    if raw.lower() in {"null", "none"}:
        return None
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    try:
        if any(ch in raw for ch in (".", "e", "E")):
            return float(raw)
        return int(raw)
    except Exception:
        return raw


def _simple_yaml_load(text: str) -> Dict[str, Any]:
    """
    Minimal YAML mapping loader for key/value + nested dictionaries.
    Deterministic and dependency-free.
    """
    root: Dict[str, Any] = {}
    stack: List[tuple[int, MutableMapping[str, Any]]] = [(-1, root)]

    for original_line in text.splitlines():
        line = original_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip(" "))
        if ":" not in line:
            continue

        key_raw, value_raw = line.strip().split(":", 1)
        key = key_raw.strip()
        value = value_raw.strip()

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()

        current = stack[-1][1]
        if value == "":
            child: Dict[str, Any] = {}
            current[key] = child
            stack.append((indent, child))
        else:
            current[key] = _to_scalar(value)

    return root


def _load_raw_config(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}

    content = path.read_text(encoding="utf-8")
    if not content.strip():
        return {}

    if path.suffix.lower() == ".json":
        data = json.loads(content)
        return data if isinstance(data, dict) else {}

    try:
        import yaml  # type: ignore

        data = yaml.safe_load(content)
        return data if isinstance(data, dict) else {}
    except Exception:
        return _simple_yaml_load(content)


def _deep_merge(base: Dict[str, Any], override: Mapping[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _deep_merge(dict(merged[key]), value)
        else:
            merged[key] = value
    return merged


def _apply_override(root: Dict[str, Any], expression: str) -> None:
    if "=" not in expression:
        return
    path, raw_value = expression.split("=", 1)
    parts = [p.strip() for p in path.strip().split(".") if p.strip()]
    if not parts:
        return
    value = _to_scalar(raw_value)
    node: Dict[str, Any] = root
    for part in parts[:-1]:
        existing = node.get(part)
        if not isinstance(existing, dict):
            existing = {}
            node[part] = existing
        node = existing
    node[parts[-1]] = value


def _default_scoring_dict() -> Dict[str, Any]:
    default = ScoringConfig()
    return {
        "group_weights": dict(default.group_weights),
        "signal_weights": dict(default.signal_weights),
        "trust_multipliers": dict(default.trust_multipliers),
        "validation_multipliers": dict(default.validation_multipliers),
        "conflict_multipliers": dict(default.conflict_multipliers),
        "evidence_penalties": dict(default.evidence_penalties),
        "confidence_cap": float(default.confidence_cap),
    }


def _to_float_map(value: Any) -> Dict[str, float]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k): float(v) for k, v in value.items()}


def _to_scoring_config(cfg: Mapping[str, Any]) -> ScoringConfig:
    defaults = _default_scoring_dict()
    merged = _deep_merge(defaults, cfg)
    return ScoringConfig(
        group_weights=_to_float_map(merged.get("group_weights", {})),
        signal_weights=_to_float_map(merged.get("signal_weights", {})),
        trust_multipliers=_to_float_map(merged.get("trust_multipliers", {})),
        validation_multipliers=_to_float_map(merged.get("validation_multipliers", {})),
        conflict_multipliers=_to_float_map(merged.get("conflict_multipliers", {})),
        evidence_penalties=_to_float_map(merged.get("evidence_penalties", {})),
        confidence_cap=float(merged.get("confidence_cap", defaults["confidence_cap"])),
    )


def load_runtime_config(
    config_path: Optional[str] = None,
    overrides: Optional[Sequence[str]] = None,
) -> RuntimeConfig:
    path = Path(config_path).expanduser().resolve() if config_path else DEFAULT_CONFIG_PATH
    raw = _load_raw_config(path)

    root = dict(raw)
    if overrides:
        for expression in overrides:
            _apply_override(root, expression)

    scoring_section = root.get("scoring", root)
    if not isinstance(scoring_section, Mapping):
        scoring_section = {}

    inference_defaults: Dict[str, Any] = {
        "confidence_threshold": 0.35,
        "tie_epsilon": 1e-9,
        "min_supporting_signals": 2,
        "min_contributing_groups": 2,
        "min_distinct_supporting_groups": 2,
    }
    logging_defaults: Dict[str, Any] = {
        "enabled": True,
        "level": "INFO",
    }

    inference_section = root.get("inference", {})
    if not isinstance(inference_section, Mapping):
        inference_section = {}
    logging_section = root.get("logging", {})
    if not isinstance(logging_section, Mapping):
        logging_section = {}

    inference = _deep_merge(inference_defaults, inference_section)
    logging_cfg = _deep_merge(logging_defaults, logging_section)

    return RuntimeConfig(
        scoring=_to_scoring_config(scoring_section),
        inference=inference,
        logging=logging_cfg,
        raw=root,
    )
