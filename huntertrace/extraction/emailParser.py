from email import policy
from email.parser import BytesParser

from huntertrace.core.models.evidence import EvidenceEnvelope
from huntertrace.core.models.extracted import ExtractedEmail


def parse_email(envelope: EvidenceEnvelope) -> ExtractedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(envelope.raw_bytes)

    headers = list(msg.raw_items())

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
        x_headers={k: v for k, v in headers if k.lower().startswith("x-")},
        dkim_signatures=msg.get_all("DKIM-Signature", []),
        received_chain=[],  # fill next step
        unique_ipv4=[],
        unique_ipv6=[],
        charset_raw=msg.get_content_charset(),
    )
