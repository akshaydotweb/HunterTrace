#!/usr/bin/env python3
"""
Deterministic DKIM verification helpers.

This module performs actual DKIM signature verification:
  - parses DKIM-Signature fields
  - fetches selector keys from DNS TXT
  - canonicalizes body and headers
  - validates bh=
  - verifies b= against the fetched public key

Tests should inject a resolver so no external network dependency is required.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Sequence, Tuple

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:  # pragma: no cover - exercised via runtime classification
    InvalidSignature = None  # type: ignore[assignment]
    hashes = None  # type: ignore[assignment]
    serialization = None  # type: ignore[assignment]
    padding = None  # type: ignore[assignment]
    rsa = None  # type: ignore[assignment]

try:
    import dns.resolver
except ImportError:  # pragma: no cover - exercised via runtime classification
    dns = None  # type: ignore[assignment]


_TAG_PATTERN = re.compile(r"(?:^|;)\s*([a-zA-Z][a-zA-Z0-9_]*)\s*=\s*([^;]*)", re.DOTALL)
_B_TAG_PATTERN = re.compile(
    rb"(\bb\s*=\s*)(?:[A-Za-z0-9+/=\t\r\n ]*)(?=(?:\s*;|$))",
    re.IGNORECASE | re.DOTALL,
)
_WSP_PATTERN = re.compile(rb"[ \t]+")


class TXTResolver(Protocol):
    def resolve_txt(self, name: str) -> List[str]:
        """Return TXT records for a DNS name."""


@dataclass(frozen=True)
class DKIMSignatureFields:
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
    key_type: Optional[str]
    raw_tags: Dict[str, str]


@dataclass(frozen=True)
class DKIMKeyRecord:
    query_name: str
    public_key: str
    key_type: str
    flags: Tuple[str, ...]
    raw_record: str


@dataclass(frozen=True)
class DKIMSignatureVerification:
    dkim_present: bool
    dkim_valid: bool
    failure_reason: Optional[str]
    domain: Optional[str]
    selector: Optional[str]
    algorithm: Optional[str]
    signed_headers: Tuple[str, ...] = ()
    canonicalization: str = "simple/simple"
    key_type: Optional[str] = None
    flags: Tuple[str, ...] = ()
    body_hash_valid: Optional[bool] = None
    query_name: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "dkim_present": self.dkim_present,
            "dkim_valid": self.dkim_valid,
            "failure_reason": self.failure_reason,
            "domain": self.domain,
            "selector": self.selector,
            "algorithm": self.algorithm,
            "signed_headers": list(self.signed_headers),
            "canonicalization": self.canonicalization,
            "key_type": self.key_type,
            "flags": list(self.flags),
            "body_hash_valid": self.body_hash_valid,
            "query_name": self.query_name,
        }


@dataclass(frozen=True)
class DKIMVerificationSummary:
    dkim_present: bool
    dkim_valid: bool
    failure_reason: Optional[str]
    domain: Optional[str]
    selector: Optional[str]
    algorithm: Optional[str]
    signed_headers: Tuple[str, ...] = ()
    canonicalization: str = "simple/simple"
    key_type: Optional[str] = None
    flags: Tuple[str, ...] = ()
    signatures: Tuple[DKIMSignatureVerification, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, object]:
        return {
            "dkim_present": self.dkim_present,
            "dkim_valid": self.dkim_valid,
            "failure_reason": self.failure_reason,
            "domain": self.domain,
            "selector": self.selector,
            "algorithm": self.algorithm,
            "signed_headers": list(self.signed_headers),
            "canonicalization": self.canonicalization,
            "key_type": self.key_type,
            "flags": list(self.flags),
            "signatures": [item.to_dict() for item in self.signatures],
        }


@dataclass
class _RawHeader:
    name: str
    raw_bytes: bytes
    raw_value_bytes: bytes

    @property
    def lowercase_name(self) -> str:
        return self.name.lower()


class DNSCache:
    """Simple persistent TXT cache with deterministic JSON encoding."""

    def __init__(self, cache_path: Optional[str] = None):
        default_root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        self.cache_path = Path(cache_path) if cache_path else default_root / "huntertrace" / "dkim_dns_cache.json"
        self._records: Optional[Dict[str, List[str]]] = None

    def get(self, name: str) -> Optional[List[str]]:
        records = self._load()
        value = records.get(name)
        return list(value) if value is not None else None

    def set(self, name: str, records: Sequence[str]) -> None:
        cache = self._load()
        cache[name] = [str(item) for item in records]
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(cache, sort_keys=True, indent=2), encoding="utf-8")

    def _load(self) -> Dict[str, List[str]]:
        if self._records is not None:
            return self._records
        if not self.cache_path.exists():
            self._records = {}
            return self._records
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                self._records = {}
            else:
                self._records = {
                    str(key): [str(item) for item in value]
                    for key, value in data.items()
                    if isinstance(value, list)
                }
        except Exception:
            self._records = {}
        return self._records


class DefaultTXTResolver:
    def __init__(self, cache: Optional[DNSCache] = None):
        self.cache = cache or DNSCache()

    def resolve_txt(self, name: str) -> List[str]:
        cached = self.cache.get(name)
        if cached is not None:
            return cached
        if dns is None:
            raise RuntimeError("dns_resolver_unavailable")
        answers = dns.resolver.resolve(name, "TXT")
        records: List[str] = []
        for answer in answers:
            if hasattr(answer, "strings"):
                records.append(b"".join(answer.strings).decode("utf-8", errors="ignore"))
            else:
                text = getattr(answer, "to_text", lambda: str(answer))()
                records.append(text.replace('"', ""))
        self.cache.set(name, records)
        return records


def verify_message(
    raw_message: bytes,
    resolver: Optional[TXTResolver] = None,
    cache_path: Optional[str] = None,
) -> DKIMVerificationSummary:
    headers, body = _split_message(raw_message)
    dkim_headers = [header for header in headers if header.lowercase_name == "dkim-signature"]

    if not dkim_headers:
        return DKIMVerificationSummary(
            dkim_present=False,
            dkim_valid=False,
            failure_reason=None,
            domain=None,
            selector=None,
            algorithm=None,
            signatures=(),
        )

    active_resolver = resolver or DefaultTXTResolver(cache=DNSCache(cache_path))
    results = tuple(_verify_signature(header, headers, body, active_resolver) for header in dkim_headers)
    selected = next((item for item in results if item.dkim_valid), results[0])
    return DKIMVerificationSummary(
        dkim_present=True,
        dkim_valid=any(item.dkim_valid for item in results),
        failure_reason=None if any(item.dkim_valid for item in results) else selected.failure_reason,
        domain=selected.domain,
        selector=selected.selector,
        algorithm=selected.algorithm,
        signed_headers=selected.signed_headers,
        canonicalization=selected.canonicalization,
        key_type=selected.key_type,
        flags=selected.flags,
        signatures=results,
    )


def _verify_signature(
    dkim_header: _RawHeader,
    all_headers: Sequence[_RawHeader],
    body_bytes: bytes,
    resolver: TXTResolver,
) -> DKIMSignatureVerification:
    try:
        fields = _parse_dkim_signature(dkim_header)
    except ValueError as exc:
        return DKIMSignatureVerification(
            dkim_present=True,
            dkim_valid=False,
            failure_reason=str(exc),
            domain=None,
            selector=None,
            algorithm=None,
        )

    if hashes is None or serialization is None or padding is None or rsa is None:
        return DKIMSignatureVerification(
            dkim_present=True,
            dkim_valid=False,
            failure_reason="cryptography_dependency_missing",
            domain=fields.domain,
            selector=fields.selector,
            algorithm=fields.algorithm,
            signed_headers=fields.signed_headers,
            canonicalization=fields.canonicalization,
        )

    key_name = f"{fields.selector}._domainkey.{fields.domain}".strip(".")
    try:
        key_record = _fetch_key_record(key_name, resolver)
    except ValueError as exc:
        return DKIMSignatureVerification(
            dkim_present=True,
            dkim_valid=False,
            failure_reason=str(exc),
            domain=fields.domain,
            selector=fields.selector,
            algorithm=fields.algorithm,
            signed_headers=fields.signed_headers,
            canonicalization=fields.canonicalization,
            query_name=key_name,
        )

    body_hash_valid = _validate_body_hash(body_bytes, fields)
    if not body_hash_valid:
        return DKIMSignatureVerification(
            dkim_present=True,
            dkim_valid=False,
            failure_reason="body_hash_mismatch",
            domain=fields.domain,
            selector=fields.selector,
            algorithm=fields.algorithm,
            signed_headers=fields.signed_headers,
            canonicalization=fields.canonicalization,
            key_type=key_record.key_type,
            flags=key_record.flags,
            body_hash_valid=False,
            query_name=key_name,
        )

    try:
        header_bytes = _build_signed_headers(all_headers, dkim_header, fields)
    except ValueError as exc:
        return DKIMSignatureVerification(
            dkim_present=True,
            dkim_valid=False,
            failure_reason=str(exc),
            domain=fields.domain,
            selector=fields.selector,
            algorithm=fields.algorithm,
            signed_headers=fields.signed_headers,
            canonicalization=fields.canonicalization,
            key_type=key_record.key_type,
            flags=key_record.flags,
            body_hash_valid=True,
            query_name=key_name,
        )

    try:
        public_key = _load_public_key(key_record)
    except ValueError as exc:
        return DKIMSignatureVerification(
            dkim_present=True,
            dkim_valid=False,
            failure_reason=str(exc),
            domain=fields.domain,
            selector=fields.selector,
            algorithm=fields.algorithm,
            signed_headers=fields.signed_headers,
            canonicalization=fields.canonicalization,
            key_type=key_record.key_type,
            flags=key_record.flags,
            body_hash_valid=True,
            query_name=key_name,
        )

    try:
        signature = base64.b64decode(fields.signature_data.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        return DKIMSignatureVerification(
            dkim_present=True,
            dkim_valid=False,
            failure_reason="invalid_signature_encoding",
            domain=fields.domain,
            selector=fields.selector,
            algorithm=fields.algorithm,
            signed_headers=fields.signed_headers,
            canonicalization=fields.canonicalization,
            key_type=key_record.key_type,
            flags=key_record.flags,
            body_hash_valid=True,
            query_name=key_name,
        )

    verify_error = _verify_cryptographic_signature(public_key, signature, header_bytes, fields.algorithm)
    return DKIMSignatureVerification(
        dkim_present=True,
        dkim_valid=verify_error is None,
        failure_reason=verify_error,
        domain=fields.domain,
        selector=fields.selector,
        algorithm=fields.algorithm,
        signed_headers=fields.signed_headers,
        canonicalization=fields.canonicalization,
        key_type=key_record.key_type,
        flags=key_record.flags,
        body_hash_valid=True,
        query_name=key_name,
    )


def _split_message(raw_message: bytes) -> Tuple[List[_RawHeader], bytes]:
    normalized = raw_message.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    header_blob, separator, body_blob = normalized.partition(b"\n\n")
    if not separator:
        header_blob = normalized
        body_blob = b""
    lines = header_blob.split(b"\n")

    headers: List[_RawHeader] = []
    current_lines: List[bytes] = []

    for line in lines:
        if line.startswith((b" ", b"\t")) and current_lines:
            current_lines.append(line)
            continue
        if current_lines:
            headers.append(_build_raw_header(current_lines))
            current_lines = []
        if line:
            current_lines.append(line)

    if current_lines:
        headers.append(_build_raw_header(current_lines))

    return headers, body_blob


def _build_raw_header(lines: Sequence[bytes]) -> _RawHeader:
    first_line = lines[0]
    name, _, first_value = first_line.partition(b":")
    raw_value = first_value + b"".join(lines[1:])
    raw_field = b"\r\n".join(lines)
    return _RawHeader(
        name=name.decode("ascii", errors="ignore"),
        raw_bytes=raw_field,
        raw_value_bytes=raw_value,
    )


def _parse_dkim_signature(header: _RawHeader) -> DKIMSignatureFields:
    unfolded_value = header.raw_value_bytes.replace(b"\r\n", b"").decode("utf-8", errors="ignore")
    tags = {match.group(1).lower(): match.group(2).strip() for match in _TAG_PATTERN.finditer(unfolded_value)}

    required = {
        "d": "missing_dkim_domain",
        "s": "missing_dkim_selector",
        "a": "missing_dkim_algorithm",
        "bh": "missing_dkim_body_hash",
        "b": "missing_dkim_signature",
        "h": "missing_dkim_signed_headers",
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
        raise ValueError("missing_dkim_signed_headers")

    return DKIMSignatureFields(
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
        key_type=(tags.get("q") or None),
        raw_tags=tags,
    )


def _fetch_key_record(name: str, resolver: TXTResolver) -> DKIMKeyRecord:
    try:
        records = resolver.resolve_txt(name)
    except Exception as exc:
        raise ValueError("missing_key") from exc

    if not records:
        raise ValueError("missing_key")

    text = "".join(records)
    tags = {match.group(1).lower(): match.group(2).strip() for match in _TAG_PATTERN.finditer(text)}
    public_key = tags.get("p")
    if public_key is None:
        raise ValueError("invalid_key_record")
    if public_key == "":
        raise ValueError("missing_key")

    key_type = tags.get("k", "rsa").lower()
    flags = tuple(sorted(filter(None, (item.strip().lower() for item in tags.get("t", "").split(":")))))
    return DKIMKeyRecord(
        query_name=name,
        public_key="".join(public_key.split()),
        key_type=key_type,
        flags=flags,
        raw_record=text,
    )


def _canonicalize_body(body_bytes: bytes, mode: str) -> bytes:
    text = body_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    lines = text.split(b"\n")

    if mode == "relaxed":
        relaxed_lines = []
        for line in lines:
            line = re.sub(rb"[ \t]+", b" ", line.rstrip(b" \t"))
            relaxed_lines.append(line)
        lines = relaxed_lines

    while lines and lines[-1] == b"":
        lines.pop()

    if not lines:
        return b"\r\n"
    return b"\r\n".join(lines) + b"\r\n"


def _hash_algorithm(name: str):
    normalized = str(name or "").lower()
    if normalized.endswith("sha256"):
        return hashes.SHA256(), hashlib.sha256
    if normalized.endswith("sha1"):
        return hashes.SHA1(), hashlib.sha1
    raise ValueError("unsupported_algorithm")


def _validate_body_hash(body_bytes: bytes, fields: DKIMSignatureFields) -> bool:
    try:
        _, digest_factory = _hash_algorithm(fields.algorithm)
    except ValueError:
        return False
    canonical_body = _canonicalize_body(body_bytes, fields.body_canonicalization)
    if fields.body_length is not None:
        canonical_body = canonical_body[: fields.body_length]
    computed = base64.b64encode(digest_factory(canonical_body).digest()).decode("ascii")
    return computed == fields.body_hash


def _build_signed_headers(
    all_headers: Sequence[_RawHeader],
    dkim_header: _RawHeader,
    fields: DKIMSignatureFields,
) -> bytes:
    selected_headers: List[_RawHeader] = []
    consumed: set[int] = set()

    for signed_name in fields.signed_headers:
        if signed_name == "dkim-signature":
            selected_headers.append(dkim_header)
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
        if header is dkim_header:
            header_bytes = _remove_b_tag_value(header_bytes)
        output.append(_canonicalize_header(header_bytes, fields.header_canonicalization))
    return b"".join(output)


def _remove_b_tag_value(raw_header: bytes) -> bytes:
    return _B_TAG_PATTERN.sub(rb"\1", raw_header, count=1)


def _canonicalize_header(raw_header: bytes, mode: str) -> bytes:
    raw_header = raw_header.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if mode == "simple":
        return raw_header.replace(b"\n", b"\r\n") + b"\r\n"

    unfolded = raw_header.split(b"\n")
    first = unfolded[0]
    name, _, first_value = first.partition(b":")
    value = first_value + b"".join(unfolded[1:])
    value = _WSP_PATTERN.sub(b" ", value).strip(b" \t")
    return name.lower() + b":" + value + b"\r\n"


def _load_public_key(key_record: DKIMKeyRecord):
    if key_record.key_type != "rsa":
        raise ValueError("unsupported_algorithm")
    try:
        key_bytes = base64.b64decode(key_record.public_key.encode("ascii"), validate=True)
        public_key = serialization.load_der_public_key(key_bytes)
    except Exception as exc:
        raise ValueError("invalid_key") from exc
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("invalid_key")
    return public_key


def _verify_cryptographic_signature(public_key, signature: bytes, header_bytes: bytes, algorithm: str) -> Optional[str]:
    try:
        hash_obj, _ = _hash_algorithm(algorithm)
    except ValueError as exc:
        return str(exc)

    try:
        public_key.verify(signature, header_bytes, padding.PKCS1v15(), hash_obj)
    except InvalidSignature:
        return "invalid_signature"
    except Exception:
        return "invalid_signature"
    return None
