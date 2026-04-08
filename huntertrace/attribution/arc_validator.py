#!/usr/bin/env python3
"""
huntertrace/attribution/arc_validator.py
=========================================
ARC (Authenticated Received Chain) validator for forwarded mail handling.

Implements cryptographic verification of ARC-Message-Signature (AMS)
and ARC-Seal (AS) across the chain, along with structure validation
and upstream Authentication-Results extraction.

Standards: RFC 8617 (ARC), RFC 6376 (DKIM)
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Sequence, Tuple

from huntertrace.attribution import dkim as dkim_utils


_TAG_PATTERN = re.compile(r"(?:^|;)\s*([a-zA-Z][a-zA-Z0-9_]*)\s*=\s*([^;]*)", re.DOTALL)
_B_TAG_PATTERN = re.compile(
    rb"(\bb\s*=\s*)(?:[A-Za-z0-9+/=\t\r\n ]*)(?=(?:\s*;|$))",
    re.IGNORECASE | re.DOTALL,
)


class TXTResolver(Protocol):
    def resolve_txt(self, name: str) -> List[str]:
        """Return TXT records for a DNS name."""


@dataclass(frozen=True)
class ARCMessageSignatureFields:
    instance: int
    domain: str
    selector: str
    algorithm: str
    body_hash: str
    signature_data: str
    signed_headers: Tuple[str, ...]
    canonicalization: str
    header_canonicalization: str
    body_canonicalization: str
    body_length: Optional[int]
    raw_tags: Dict[str, str]


@dataclass(frozen=True)
class ARCSealFields:
    instance: int
    domain: str
    selector: str
    algorithm: str
    signature_data: str
    canonicalization: str
    header_canonicalization: str
    chain_validation: str
    raw_tags: Dict[str, str]


@dataclass
class ARCSet:
    instance: int
    arc_seal: Optional[dkim_utils._RawHeader] = None
    arc_message_signature: Optional[dkim_utils._RawHeader] = None
    arc_authentication_results: Optional[dkim_utils._RawHeader] = None
    duplicate: bool = False


@dataclass(frozen=True)
class ARCChainValidationResult:
    valid: bool
    chain_count: int
    failure_reason: Optional[str]
    failed_instance: Optional[int]
    upstream_auth_results: Tuple[Dict[str, str], ...]
    upstream_summary: str
    explanation: str


class ARCValidator:
    """ARC chain validator."""

    def __init__(self, resolver: Optional[TXTResolver] = None, cache_path: Optional[str] = None):
        self.resolver = resolver
        self.cache_path = cache_path

    def validate(
        self,
        raw_message: bytes,
        resolver: Optional[TXTResolver] = None,
    ) -> ARCChainValidationResult:
        """Validate ARC chain with cryptographic verification."""
        if not raw_message:
            return ARCChainValidationResult(
                valid=False,
                chain_count=0,
                failure_reason="no_raw_message",
                failed_instance=None,
                upstream_auth_results=(),
                upstream_summary="",
                explanation="ARC validation failed: raw message missing",
            )

        headers, body = dkim_utils._split_message(raw_message)
        arc_sets = self._collect_arc_sets(headers)
        if not arc_sets:
            return ARCChainValidationResult(
                valid=False,
                chain_count=0,
                failure_reason="no_arc_headers",
                failed_instance=None,
                upstream_auth_results=(),
                upstream_summary="",
                explanation="ARC validation failed: no ARC headers",
            )

        upstream_results = self._extract_upstream_results(arc_sets)
        upstream_summary = self._summarize_upstream_results(upstream_results)

        instances = sorted(arc_sets.keys())
        chain_count = len(instances)
        if not self._instances_continuous(instances):
            return ARCChainValidationResult(
                valid=False,
                chain_count=chain_count,
                failure_reason="invalid_arc_structure",
                failed_instance=None,
                upstream_auth_results=upstream_results,
                upstream_summary=upstream_summary,
                explanation="ARC validation failed: invalid instance sequence",
            )

        for instance in instances:
            arc_set = arc_sets[instance]
            if arc_set.duplicate or not arc_set.arc_seal or not arc_set.arc_message_signature or not arc_set.arc_authentication_results:
                return ARCChainValidationResult(
                    valid=False,
                    chain_count=chain_count,
                    failure_reason="invalid_arc_structure",
                    failed_instance=instance,
                    upstream_auth_results=upstream_results,
                    upstream_summary=upstream_summary,
                    explanation="ARC validation failed: missing ARC headers in set",
                )

            if "ARC-Seal:" in header:
                seal_count += 1
            if "ARC-Message-Signature:" in header:
                msg_sig_count += 1
            if "ARC-Authentication-Results:" in header:
                auth_results_count += 1

        for instance in instances:
            arc_set = arc_sets[instance]
            ams_error = self._verify_ams_signature(arc_set, headers, body, active_resolver)
            if ams_error:
                return ARCChainValidationResult(
                    valid=False,
                    chain_count=chain_count,
                    failure_reason="ams_verification_failed",
                    failed_instance=instance,
                    upstream_auth_results=upstream_results,
                    upstream_summary=upstream_summary,
                    explanation=f"ARC validation failed: AMS verification error ({ams_error})",
                )

        for instance in instances:
            arc_set = arc_sets[instance]
            as_error = self._verify_arc_seal(arc_set, arc_sets, active_resolver)
            if as_error:
                return ARCChainValidationResult(
                    valid=False,
                    chain_count=chain_count,
                    failure_reason="arc_seal_invalid",
                    failed_instance=instance,
                    upstream_auth_results=upstream_results,
                    upstream_summary=upstream_summary,
                    explanation=f"ARC validation failed: ARC-Seal verification error ({as_error})",
                )

        return ARCChainValidationResult(
            valid=True,
            chain_count=chain_count,
            failure_reason=None,
            failed_instance=None,
            upstream_auth_results=upstream_results,
            upstream_summary=upstream_summary,
            explanation=f"ARC chain valid across {chain_count} instance(s)",
        )

        # Verify we have matching counts (should be 1:1:1 or 1:1 for seal)
        if not (seal_count > 0 and msg_sig_count > 0 and auth_results_count > 0):
            return False, chain_count, "missing_arc_chain_components"

    def _parse_tag_values(self, raw_value_bytes: bytes) -> Dict[str, str]:
        unfolded = raw_value_bytes.replace(b"\r\n", b"").decode("utf-8", errors="ignore")
        return {match.group(1).lower(): match.group(2).strip() for match in _TAG_PATTERN.finditer(unfolded)}

    def _parse_instance(self, tags: Dict[str, str]) -> Optional[int]:
        value = tags.get("i")
        if not value:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    def _instances_continuous(self, instances: Sequence[int]) -> bool:
        if not instances:
            return False
        return instances == list(range(1, max(instances) + 1))

    def _verify_ams_signature(
        self,
        arc_set: ARCSet,
        headers: Sequence[dkim_utils._RawHeader],
        body: bytes,
        resolver: TXTResolver,
    ) -> Optional[str]:
        if arc_set.arc_message_signature is None:
            return "missing_ams"
        if dkim_utils.hashes is None or dkim_utils.serialization is None or dkim_utils.padding is None or dkim_utils.rsa is None:
            return "cryptography_dependency_missing"
        try:
            fields = self._parse_arc_message_signature(arc_set.arc_message_signature)
        except ValueError as exc:
            return str(exc)
        if fields.instance != arc_set.instance:
            return "instance_mismatch"

        if not self._validate_body_hash(body, fields):
            return "body_hash_mismatch"

        try:
            header_bytes = self._build_ams_signed_headers(headers, arc_set.arc_message_signature, fields)
        except ValueError as exc:
            return str(exc)

        key_name = f"{fields.selector}._domainkey.{fields.domain}".strip(".")
        try:
            key_record = dkim_utils._fetch_key_record(key_name, resolver)
            public_key = dkim_utils._load_public_key(key_record)
        except ValueError as exc:
            return str(exc)

        try:
            signature = base64.b64decode(fields.signature_data.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError):
            return "invalid_signature_encoding"

        return dkim_utils._verify_cryptographic_signature(public_key, signature, header_bytes, fields.algorithm)

    def _verify_arc_seal(
        self,
        arc_set: ARCSet,
        arc_sets: Dict[int, ARCSet],
        resolver: TXTResolver,
    ) -> Optional[str]:
        if arc_set.arc_seal is None:
            return "missing_arc_seal"
        if dkim_utils.hashes is None or dkim_utils.serialization is None or dkim_utils.padding is None or dkim_utils.rsa is None:
            return "cryptography_dependency_missing"
        try:
            fields = self._parse_arc_seal(arc_set.arc_seal)
        except ValueError as exc:
            return str(exc)
        if fields.instance != arc_set.instance:
            return "instance_mismatch"
        if fields.instance == 1 and fields.chain_validation != "none":
            return "invalid_arc_cv"

        try:
            header_bytes = self._build_arc_seal_input(arc_sets, fields.instance, fields.header_canonicalization)
        except ValueError as exc:
            return str(exc)

        key_name = f"{fields.selector}._domainkey.{fields.domain}".strip(".")
        try:
            key_record = dkim_utils._fetch_key_record(key_name, resolver)
            public_key = dkim_utils._load_public_key(key_record)
        except ValueError as exc:
            return str(exc)

        try:
            signature = base64.b64decode(fields.signature_data.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError):
            return "invalid_signature_encoding"

        return dkim_utils._verify_cryptographic_signature(public_key, signature, header_bytes, fields.algorithm)

    def _parse_arc_message_signature(self, header: dkim_utils._RawHeader) -> ARCMessageSignatureFields:
        tags = self._parse_tag_values(header.raw_value_bytes)
        required = {
            "i": "missing_arc_instance",
            "d": "missing_arc_domain",
            "s": "missing_arc_selector",
            "a": "missing_arc_algorithm",
            "bh": "missing_arc_body_hash",
            "b": "missing_arc_signature",
            "h": "missing_arc_signed_headers",
        }
        for key, failure in required.items():
            if not tags.get(key):
                raise ValueError(failure)

        canonicalization = tags.get("c", "simple/simple").lower()
        if "/" in canonicalization:
            header_canon, body_canon = canonicalization.split("/", 1)
        else:
            header_canon, body_canon = canonicalization, "simple"
        header_canon = header_canon or "simple"
        body_canon = body_canon or "simple"
        if header_canon not in {"simple", "relaxed"} or body_canon not in {"simple", "relaxed"}:
            raise ValueError("unsupported_canonicalization")

        body_length = None
        if tags.get("l"):
            try:
                body_length = int(tags["l"])
            except ValueError:
                raise ValueError("invalid_body_length") from None

        signed_headers = tuple(
            item.strip().lower()
            for item in tags["h"].split(":")
            if item.strip()
        )
        if not signed_headers:
            raise ValueError("missing_arc_signed_headers")

        return ARCMessageSignatureFields(
            instance=int(tags["i"]),
            domain=tags["d"].strip().rstrip(".").lower(),
            selector=tags["s"].strip().rstrip("."),
            algorithm=tags["a"].strip().lower(),
            body_hash=tags["bh"].strip(),
            signature_data="".join(tags["b"].split()),
            signed_headers=signed_headers,
            canonicalization=f"{header_canon}/{body_canon}",
            header_canonicalization=header_canon,
            body_canonicalization=body_canon,
            body_length=body_length,
            raw_tags=tags,
        )

    def _parse_arc_seal(self, header: dkim_utils._RawHeader) -> ARCSealFields:
        tags = self._parse_tag_values(header.raw_value_bytes)
        required = {
            "i": "missing_arc_instance",
            "d": "missing_arc_domain",
            "s": "missing_arc_selector",
            "a": "missing_arc_algorithm",
            "b": "missing_arc_signature",
            "cv": "missing_arc_cv",
        }
        for key, failure in required.items():
            if not tags.get(key):
                raise ValueError(failure)

        canonicalization = tags.get("c", "simple/simple").lower()
        if "/" in canonicalization:
            header_canon, _ = canonicalization.split("/", 1)
        else:
            header_canon = canonicalization
        header_canon = header_canon or "simple"
        if header_canon not in {"simple", "relaxed"}:
            raise ValueError("unsupported_canonicalization")

        return ARCSealFields(
            instance=int(tags["i"]),
            domain=tags["d"].strip().rstrip(".").lower(),
            selector=tags["s"].strip().rstrip("."),
            algorithm=tags["a"].strip().lower(),
            signature_data="".join(tags["b"].split()),
            canonicalization=canonicalization,
            header_canonicalization=header_canon,
            chain_validation=tags["cv"].strip().lower(),
            raw_tags=tags,
        )

    def _validate_body_hash(self, body_bytes: bytes, fields: ARCMessageSignatureFields) -> bool:
        try:
            _, digest_factory = dkim_utils._hash_algorithm(fields.algorithm)
        except ValueError:
            return False
        canonical_body = dkim_utils._canonicalize_body(body_bytes, fields.body_canonicalization)
        if fields.body_length is not None:
            canonical_body = canonical_body[: fields.body_length]
        computed = base64.b64encode(digest_factory(canonical_body).digest()).decode("ascii")
        return computed == fields.body_hash

    def _build_ams_signed_headers(
        self,
        all_headers: Sequence[dkim_utils._RawHeader],
        ams_header: dkim_utils._RawHeader,
        fields: ARCMessageSignatureFields,
    ) -> bytes:
        selected_headers: List[dkim_utils._RawHeader] = []
        consumed: set[int] = set()

        for signed_name in fields.signed_headers:
            if signed_name == "arc-message-signature":
                selected_headers.append(ams_header)
                continue
            matched_index = None
            for idx in range(len(all_headers) - 1, -1, -1):
                header = all_headers[idx]
                if idx in consumed:
                    continue
                if header.lowercase_name == signed_name:
                    matched_index = idx
                    break
            if matched_index is None:
                raise ValueError("header_mismatch")
            consumed.add(matched_index)
            selected_headers.append(all_headers[matched_index])

        output = []
        for header in selected_headers:
            header_bytes = header.raw_bytes
            if header is ams_header:
                header_bytes = _remove_b_tag_value(header_bytes)
            output.append(dkim_utils._canonicalize_header(header_bytes, fields.header_canonicalization))
        return b"".join(output)

    def _build_arc_seal_input(
        self,
        arc_sets: Dict[int, ARCSet],
        target_instance: int,
        header_canon: str,
    ) -> bytes:
        output: List[bytes] = []
        for instance in range(1, target_instance + 1):
            arc_set = arc_sets.get(instance)
            if arc_set is None:
                raise ValueError("header_mismatch")
            if not arc_set.arc_authentication_results or not arc_set.arc_message_signature or not arc_set.arc_seal:
                raise ValueError("header_mismatch")

            output.append(dkim_utils._canonicalize_header(
                arc_set.arc_authentication_results.raw_bytes,
                header_canon,
            ))
            output.append(dkim_utils._canonicalize_header(
                arc_set.arc_message_signature.raw_bytes,
                header_canon,
            ))
            if instance < target_instance:
                output.append(dkim_utils._canonicalize_header(
                    arc_set.arc_seal.raw_bytes,
                    header_canon,
                ))
            else:
                output.append(dkim_utils._canonicalize_header(
                    _remove_b_tag_value(arc_set.arc_seal.raw_bytes),
                    header_canon,
                ))
        return b"".join(output)

    def _extract_upstream_results(self, arc_sets: Dict[int, ARCSet]) -> Tuple[Dict[str, str], ...]:
        results: List[Dict[str, str]] = []
        for instance in sorted(arc_sets.keys()):
            arc_set = arc_sets[instance]
            if not arc_set.arc_authentication_results:
                continue
            value = arc_set.arc_authentication_results.raw_value_bytes
            text = value.replace(b"\r\n", b"").decode("utf-8", errors="ignore")
            result = {
                "instance": str(instance),
                "spf": self._extract_auth_result(text, "spf"),
                "dkim": self._extract_auth_result(text, "dkim"),
                "dmarc": self._extract_auth_result(text, "dmarc"),
            }
            results.append(result)
        return tuple(results)

    def _summarize_upstream_results(self, results: Sequence[Dict[str, str]]) -> str:
        if not results:
            return ""
        latest = results[-1]
        parts = []
        for key in ("spf", "dkim", "dmarc"):
            value = latest.get(key)
            if value:
                parts.append(f"{key}={value}")
        if not parts:
            return ""
        return f"i={latest.get('instance', '')} " + ", ".join(parts)

    def _extract_auth_result(self, text: str, token: str) -> str:
        pattern = re.compile(rf"\b{re.escape(token)}\s*=\s*([a-zA-Z0-9_-]+)", re.IGNORECASE)
        match = pattern.search(text)
        return match.group(1).lower() if match else ""

    def _default_resolver(self) -> TXTResolver:
        cache_path = self.cache_path
        if cache_path is None:
            default_root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
            cache_path = str(default_root / "huntertrace" / "arc_dns_cache.json")
        return dkim_utils.DefaultTXTResolver(cache=dkim_utils.DNSCache(cache_path=cache_path))

        # Find ARC-Authentication-Results for this instance
        for instance, header in arc_headers.items():
            if instance == latest_instance and "ARC-Authentication-Results:" in header:
                header_lower = header.lower()
                if re.search(r"\b(dkim|spf|dmarc)=pass\b", header_lower):
                    return "pass"
                if re.search(r"\b(dkim|spf|dmarc)=fail\b", header_lower):
                    return "fail"
                if re.search(r"\b(dkim|spf|dmarc)=neutral\b", header_lower):
                    return "neutral"
                if re.search(r"\b(dkim|spf|dmarc)=none\b", header_lower):
                    return "none"
                match = re.search(r";\s*(pass|fail|neutral|none)\b", header_lower)
                if match:
                    return match.group(1)

def _remove_b_tag_value(raw_header: bytes) -> bytes:
    return _B_TAG_PATTERN.sub(rb"\1", raw_header, count=1)


def validate_arc_simple(raw_message: bytes, resolver: Optional[TXTResolver] = None) -> bool:
    """Simple ARC validation - just check if valid chain exists."""
    validator = ARCValidator()
    result = validator.validate(raw_message, resolver=resolver)
    return result.valid
