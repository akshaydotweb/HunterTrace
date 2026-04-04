"""Formatters for explainability output in multiple formats."""

from __future__ import annotations

import json
from typing import Any, Dict

from huntertrace.explainability.models import ExplainabilityResult


class JsonFormatter:
    """Format explainability result as JSON."""

    @staticmethod
    def format(result: ExplainabilityResult) -> str:
        """Format as indented JSON."""
        return json.dumps(result.to_dict(), indent=2)


class TextFormatter:
    """Format explainability result as human-readable text."""

    @staticmethod
    def format(result: ExplainabilityResult) -> str:
        """Format as plain text with structure and readability."""
        lines = []

        # Header
        lines.append("=" * 80)
        lines.append("ATTRIBUTION EXPLAINABILITY REPORT")
        lines.append("=" * 80)
        lines.append("")

        # Summary
        lines.append("DECISION SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Verdict:     {result.verdict}")
        lines.append(f"Region:      {result.region or '(no attribution)'}")
        lines.append(f"Confidence:  {result.confidence:.1%}")
        lines.append("")

        # Human explanation
        lines.append("EXPLANATION")
        lines.append("-" * 80)
        lines.append(result.explanation)
        lines.append("")

        # Decision trace
        if result.decision_trace:
            lines.append("DECISION TRACE")
            lines.append("-" * 80)
            for i, step in enumerate(result.decision_trace, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        # Contributions
        if result.contributions:
            lines.append("SIGNAL CONTRIBUTIONS")
            lines.append("-" * 80)
            for contrib in result.contributions:
                role_indicator = {
                    "supporting": "+",
                    "conflicting": "−",
                    "neutral": "•",
                }.get(contrib.role, "?")
                group_text = f" [{contrib.group}]" if contrib.group else ""
                net_effect_text = f"{contrib.net_effect:+.4f}"
                lines.append(
                    f"{role_indicator} {contrib.signal_name:<30} {net_effect_text:>8} {group_text}"
                )
            lines.append("")

        # Rejected signals (for audit trail)
        if result.rejected_signals:
            lines.append("REJECTED SIGNALS")
            lines.append("-" * 80)
            for rejected in result.rejected_signals:
                lines.append(f"× {rejected.signal_name:<30} ({rejected.reason})")
            lines.append("")

        # Evidence traceability
        if result.evidence_links:
            lines.append("EVIDENCE TRACEABILITY")
            lines.append("-" * 80)
            for link in result.evidence_links:
                lines.append(f"Signal: {link.signal_name} ({link.signal_id})")
                lines.append(f"  Hop {link.hop_index}: {link.hop_from_ip or link.hop_from_host or '(no address)'}")
                if link.extracted_fields:
                    for key, value in link.extracted_fields.items():
                        lines.append(f"    {key}: {value}")
                lines.append("")

        # Anomalies
        if result.anomalies:
            lines.append("DETECTED ANOMALIES")
            lines.append("-" * 80)
            for anomaly in result.anomalies:
                severity_indicator = {
                    "high": "[HIGH]",
                    "medium": "[MED]",
                    "low": "[LOW]",
                }.get(anomaly.severity, "[?]")
                lines.append(
                    f"{severity_indicator} {anomaly.type.upper()}: {anomaly.description}"
                )
            lines.append("")

        # Limitations
        if result.limitations:
            lines.append("ANALYSIS LIMITATIONS")
            lines.append("-" * 80)
            for limit in result.limitations:
                impact_indicator = {
                    "high": "⚠",
                    "medium": "→",
                    "low": "•",
                }.get(limit.impact, "?")
                lines.append(
                    f"{impact_indicator} [{limit.category}] {limit.description}"
                )
            lines.append("")

        lines.append("=" * 80)
        return "\n".join(lines)


class MarkdownFormatter:
    """Format explainability result as Markdown."""

    @staticmethod
    def format(result: ExplainabilityResult) -> str:
        """Format as Markdown for documentation."""
        lines = []

        # Header
        lines.append("# Attribution Explainability Report")
        lines.append("")

        # Summary
        lines.append("## Decision Summary")
        lines.append("")
        lines.append(f"- **Verdict:** {result.verdict}")
        lines.append(f"- **Region:** {result.region or '(no attribution)'}")
        lines.append(f"- **Confidence:** {result.confidence:.1%}")
        lines.append("")

        # Human explanation
        lines.append("## Explanation")
        lines.append("")
        lines.append(result.explanation)
        lines.append("")

        # Decision trace
        if result.decision_trace:
            lines.append("## Decision Trace")
            lines.append("")
            for i, step in enumerate(result.decision_trace, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        # Contributions
        if result.contributions:
            lines.append("## Signal Contributions")
            lines.append("")
            lines.append("| Signal | Role | Group | Net Effect |")
            lines.append("|--------|------|-------|------------|")
            for contrib in result.contributions:
                group_text = contrib.group or "(none)"
                lines.append(
                    f"| {contrib.signal_name} | {contrib.role} | {group_text} | {contrib.net_effect:+.4f} |"
                )
            lines.append("")

        # Rejected signals (for audit trail)
        if result.rejected_signals:
            lines.append("## Rejected Signals")
            lines.append("")
            for rejected in result.rejected_signals:
                lines.append(f"- **{rejected.signal_name}**: {rejected.reason}")
            lines.append("")

        # Evidence traceability
        if result.evidence_links:
            lines.append("## Evidence Traceability")
            lines.append("")
            for link in result.evidence_links:
                lines.append(f"### {link.signal_name} ({link.signal_id})")
                lines.append("")
                lines.append(f"**Hop {link.hop_index}:** {link.hop_from_ip or link.hop_from_host or '(no address)'}")
                lines.append("")
                if link.extracted_fields:
                    lines.append("**Extracted Fields:**")
                    lines.append("")
                    for key, value in link.extracted_fields.items():
                        lines.append(f"- `{key}`: {value}")
                    lines.append("")

        # Anomalies
        if result.anomalies:
            lines.append("## Detected Anomalies")
            lines.append("")
            for anomaly in result.anomalies:
                lines.append(
                    f"### {anomaly.type.replace('_', ' ').title()} ({anomaly.severity})"
                )
                lines.append("")
                lines.append(anomaly.description)
                lines.append("")

        # Limitations
        if result.limitations:
            lines.append("## Analysis Limitations")
            lines.append("")
            for limit in result.limitations:
                lines.append(f"### {limit.category.title()} ({limit.impact})")
                lines.append("")
                lines.append(limit.description)
                lines.append("")

        return "\n".join(lines)


class FormatterFactory:
    """Factory for creating formatters by name."""

    _formatters = {
        "json": JsonFormatter,
        "text": TextFormatter,
        "markdown": MarkdownFormatter,
        "md": MarkdownFormatter,
    }

    @classmethod
    def get_formatter(cls, format_name: str):
        """Get formatter by name."""
        format_name_lower = format_name.lower()
        if format_name_lower not in cls._formatters:
            raise ValueError(
                f"Unknown format '{format_name}'. "
                f"Available: {', '.join(cls._formatters.keys())}"
            )
        return cls._formatters[format_name_lower]

    @classmethod
    def format(cls, result: ExplainabilityResult, format_name: str) -> str:
        """Format result using the specified format."""
        formatter = cls.get_formatter(format_name)
        return formatter.format(result)
