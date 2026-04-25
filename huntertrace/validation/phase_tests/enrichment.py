from __future__ import annotations

from typing import Any

from ..schema import PhaseResult, ValidationSample


def validate_enrichment(sample: ValidationSample, result: Any) -> PhaseResult:
    geo = dict(getattr(result, "geolocation_results", {}) or {})
    header = getattr(result, "header_analysis", None)
    hops = list(getattr(header, "hops", []) or [])
    candidate_ips = []
    for hop in hops:
        for attr in ("ip", "ipv6"):
            value = getattr(hop, attr, None)
            if value and value not in candidate_ips:
                candidate_ips.append(value)
    resolved = [ip for ip, data in geo.items() if getattr(data, "country", None) or getattr(data, "country_code", None)]
    rate = len(resolved) / max(len(candidate_ips), 1)
    metrics = {
        "ip_resolution_rate": rate,
        "asn_region_accuracy": 1.0 if resolved else 0.0,
    }
    errors = []
    if not geo and candidate_ips:
        errors.append("No geolocation results available")
    return PhaseResult("enrichment", bool(geo) or not candidate_ips, metrics=metrics, errors=errors)
