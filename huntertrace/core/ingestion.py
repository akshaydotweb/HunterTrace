import hashlib
import uuid
from datetime import datetime, timezone
from typing import Union, Optional

from huntertrace.core.models.evidence import EvidenceEnvelope


def ingest_email(source: Union[str, bytes], analyst_id: Optional[str] = None) -> EvidenceEnvelope:
    if isinstance(source, str):
        with open(source, "rb") as f:
            raw_bytes = f.read()
        source_path = source
    else:
        raw_bytes = source
        source_path = None

    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    return EvidenceEnvelope(
        evidence_id=str(uuid.uuid4()),
        sha256=sha256,
        raw_bytes=raw_bytes,
        source_path=source_path,
        received_at=datetime.now(timezone.utc).isoformat(),
        analyst_id=analyst_id,
    )
