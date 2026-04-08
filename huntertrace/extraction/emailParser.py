from email import policy
from email.parser import BytesParser
from typing import Dict, List

from huntertrace.core.models.evidence import EvidenceEnvelope
from huntertrace.core.models.extracted import ExtractedEmail


def parse_email(envelope: EvidenceEnvelope) -> ExtractedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(envelope.raw_bytes)

    headers = list(msg.raw_items())
    arc_headers: Dict[str, List[str]] = {}
    x_headers: Dict[str, List[str]] = {}
    for key, value in headers:
        key_lower = key.lower()
        if key_lower.startswith("arc-"):
            arc_headers.setdefault(key_lower, []).append(value)
        elif key_lower.startswith("x-"):
            x_headers.setdefault(key_lower, []).append(value)

    return ExtractedEmail(
        evidence_id=envelope.evidence_id,
        from_header=msg.get("From"),
        to_header=msg.get("To"),
        subject_raw=msg.get("Subject"),
        date_raw=msg.get("Date"),
        message_id=msg.get("Message-ID"),
        reply_to_raw=msg.get("Reply-To"),
        content_type_raw=msg.get("Content-Type"),
        auth_results_raw=msg.get("Authentication-Results"),
        x_headers=x_headers,
        arc_headers=arc_headers,
        dkim_signatures=msg.get_all("DKIM-Signature", []),
        received_chain=[],  # fill next step
        unique_ipv4=[],
        unique_ipv6=[],
        charset_raw=msg.get_content_charset(),
    )
