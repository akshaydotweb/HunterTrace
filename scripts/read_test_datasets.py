#!/usr/bin/env python3
"""Read mixed email dataset formats for quick testing and validation.

Supported inputs:
- Single `.eml` file
- Directory of mixed files (`.eml` + raw RFC822 mail)
- MBOX file
- Maildir folder
- Hugging Face datasets via `datasets.load_dataset(...)`
- JSON datasets:
  - `[{"case_id": ..., "signals": [...]}, ...]`
  - `{"emails": [{"file": "..."}, ...]}`

Outputs:
- Human-readable summary to stdout
- Optional JSONL export with normalized records
"""

from __future__ import annotations

import argparse
import json
import mailbox
from dataclasses import asdict, dataclass
from email import message_from_bytes
from email.message import Message
from pathlib import Path
from typing import Iterable, Iterator, Optional


@dataclass
class EmailRecord:
    source: str
    format: str
    from_header: str
    to_header: str
    subject: str
    date: str
    message_id: str
    received_hops: int
    has_spf: bool
    has_dkim: bool
    has_dmarc: bool
    has_arc: bool


def _safe_header(msg: Message, name: str) -> str:
    value = msg.get(name)
    return str(value).strip() if value is not None else ""


def _record_from_message(msg: Message, source: str, fmt: str) -> EmailRecord:
    received = msg.get_all("Received", []) or []
    auth_results = " ".join(msg.get_all("Authentication-Results", []) or []).lower()

    return EmailRecord(
        source=source,
        format=fmt,
        from_header=_safe_header(msg, "From"),
        to_header=_safe_header(msg, "To"),
        subject=_safe_header(msg, "Subject"),
        date=_safe_header(msg, "Date"),
        message_id=_safe_header(msg, "Message-ID"),
        received_hops=len(received),
        has_spf=(msg.get("Received-SPF") is not None) or (" spf=" in auth_results),
        has_dkim=(msg.get("DKIM-Signature") is not None) or (" dkim=" in auth_results),
        has_dmarc=(" dmarc=" in auth_results),
        has_arc=(
            (msg.get("ARC-Seal") is not None)
            or (msg.get("ARC-Authentication-Results") is not None)
            or (msg.get("ARC-Message-Signature") is not None)
        ),
    )


def _looks_like_email(raw: bytes) -> bool:
    lowered = raw[:4096].lower()
    return b"from:" in lowered and (b"subject:" in lowered or b"date:" in lowered)


def _read_message_file(path: Path, fmt: str = "file") -> Optional[EmailRecord]:
    try:
        raw = path.read_bytes()
        if not _looks_like_email(raw):
            return None
        msg = message_from_bytes(raw)
        return _record_from_message(msg, str(path), fmt)
    except Exception:
        return None


def _iter_mbox(path: Path) -> Iterator[EmailRecord]:
    box = mailbox.mbox(path)
    for idx, msg in enumerate(box):
        yield _record_from_message(msg, f"{path}#{idx}", "mbox")


def _iter_maildir(path: Path) -> Iterator[EmailRecord]:
    box = mailbox.Maildir(path, factory=None, create=False)
    for key, msg in box.iteritems():
        yield _record_from_message(msg, f"{path}#{key}", "maildir")


def _iter_json_dataset(path: Path) -> Iterator[EmailRecord]:
    payload = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(payload, list):
        # Format like demo/enterprise_demo_cases.json
        for idx, item in enumerate(payload):
            if not isinstance(item, dict):
                continue
            yield EmailRecord(
                source=f"{path}#{idx}",
                format="json-cases",
                from_header="",
                to_header="",
                subject=str(item.get("case_id", "")),
                date="",
                message_id="",
                received_hops=len(item.get("received_chain", []) or []),
                has_spf=False,
                has_dkim=False,
                has_dmarc=False,
                has_arc=False,
            )
        return

    if isinstance(payload, dict) and isinstance(payload.get("emails"), list):
        # Format like corpus.json with file pointers
        base = path.parent
        for idx, entry in enumerate(payload["emails"]):
            if not isinstance(entry, dict):
                continue
            file_ref = entry.get("file")
            if not file_ref:
                continue
            email_path = (base / str(file_ref)).resolve()
            rec = _read_message_file(email_path, fmt="json-ref")
            if rec is not None:
                yield rec
            else:
                yield EmailRecord(
                    source=f"{path}#{idx}",
                    format="json-ref-missing",
                    from_header="",
                    to_header="",
                    subject=str(entry.get("id", file_ref)),
                    date="",
                    message_id="",
                    received_hops=0,
                    has_spf=False,
                    has_dkim=False,
                    has_dmarc=False,
                    has_arc=False,
                )


def _iter_hf_dataset(dataset_name: str, split: str, max_rows: int, streaming: bool) -> Iterator[EmailRecord]:
    try:
        from datasets import load_dataset
    except Exception as exc:
        raise RuntimeError(
            "Hugging Face datasets support requires the 'datasets' package. "
            "Install with: pip install datasets"
        ) from exc

    ds = load_dataset(dataset_name, split=split, streaming=streaming)

    if not streaming and max_rows > 0:
        ds = ds.select(range(min(max_rows, len(ds))))

    candidate_email_fields = ("message", "raw", "email", "content", "text", "body")
    candidate_header_fields = {
        "from": ("from", "sender", "from_header"),
        "to": ("to", "recipient", "to_header"),
        "subject": ("subject", "title"),
        "date": ("date", "timestamp"),
        "message_id": ("message_id", "message-id", "id"),
    }

    for idx, row in enumerate(ds):
        if streaming and max_rows > 0 and idx >= max_rows:
            break
        if not isinstance(row, dict):
            continue

        raw_email = None
        for field in candidate_email_fields:
            value = row.get(field)
            if isinstance(value, str) and "From:" in value and ("Subject:" in value or "Date:" in value):
                raw_email = value
                break

        if raw_email:
            msg = message_from_bytes(raw_email.encode("utf-8", errors="ignore"))
            yield _record_from_message(msg, f"hf:{dataset_name}#{idx}", "hf-rfc822")
            continue

        def pick(keys: tuple[str, ...]) -> str:
            for key in keys:
                value = row.get(key)
                if value is not None:
                    return str(value).strip()
            return ""

        yield EmailRecord(
            source=f"hf:{dataset_name}#{idx}",
            format="hf-tabular",
            from_header=pick(candidate_header_fields["from"]),
            to_header=pick(candidate_header_fields["to"]),
            subject=pick(candidate_header_fields["subject"]),
            date=pick(candidate_header_fields["date"]),
            message_id=pick(candidate_header_fields["message_id"]),
            received_hops=0,
            has_spf=False,
            has_dkim=False,
            has_dmarc=False,
            has_arc=False,
        )


def _iter_directory(path: Path, recursive: bool) -> Iterator[EmailRecord]:
    pattern = "**/*" if recursive else "*"
    for child in path.glob(pattern):
        if not child.is_file():
            continue
        suffix = child.suffix.lower()

        if suffix == ".eml":
            rec = _read_message_file(child, fmt="eml")
            if rec is not None:
                yield rec
            continue

        if suffix == ".mbox":
            yield from _iter_mbox(child)
            continue

        if suffix == ".json":
            try:
                yield from _iter_json_dataset(child)
            except Exception:
                # Ignore non-dataset JSON files.
                pass
            continue

        rec = _read_message_file(child, fmt="raw-rfc822")
        if rec is not None:
            yield rec


def iter_dataset_records(path: Path, recursive: bool) -> Iterator[EmailRecord]:
    if path.is_file():
        suffix = path.suffix.lower()
        if suffix == ".eml":
            rec = _read_message_file(path, fmt="eml")
            if rec is not None:
                yield rec
            return
        if suffix == ".mbox":
            yield from _iter_mbox(path)
            return
        if suffix == ".json":
            yield from _iter_json_dataset(path)
            return
        rec = _read_message_file(path, fmt="raw-rfc822")
        if rec is not None:
            yield rec
        return

    if path.is_dir():
        # Maildir has `cur/new/tmp` directories.
        if (path / "cur").is_dir() and (path / "new").is_dir() and (path / "tmp").is_dir():
            yield from _iter_maildir(path)
            return
        yield from _iter_directory(path, recursive)


def _print_summary(records: list[EmailRecord], max_rows: int) -> None:
    print(f"Parsed records: {len(records)}")
    if not records:
        return

    total_hops = sum(r.received_hops for r in records)
    print(f"Avg Received hops: {total_hops / len(records):.2f}")
    print(
        "Auth coverage: "
        f"SPF={sum(r.has_spf for r in records)}, "
        f"DKIM={sum(r.has_dkim for r in records)}, "
        f"DMARC={sum(r.has_dmarc for r in records)}, "
        f"ARC={sum(r.has_arc for r in records)}"
    )

    print("\nSample rows:")
    for rec in records[:max_rows]:
        subj = rec.subject if rec.subject else "(no-subject)"
        print(
            f"- [{rec.format}] {rec.source}\n"
            f"  from={rec.from_header or '-'} | subject={subj[:80]} | hops={rec.received_hops}"
        )


def _write_jsonl(records: Iterable[EmailRecord], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(asdict(rec), ensure_ascii=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Read mixed email dataset formats for testing")
    parser.add_argument("path", nargs="?", help="Dataset path (file or directory)")
    parser.add_argument("--hf-dataset", help="Hugging Face dataset name, e.g. corbt/enron-emails")
    parser.add_argument("--hf-split", default="train", help="Hugging Face split (default: train)")
    parser.add_argument("--hf-max-rows", type=int, default=2000, help="Max rows to read from HF dataset")
    parser.add_argument(
        "--hf-streaming",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use streaming mode for HF datasets (default: enabled)",
    )
    parser.add_argument("--recursive", action="store_true", help="Recurse into directories")
    parser.add_argument("--max-rows", type=int, default=10, help="Max sample rows to print")
    parser.add_argument("--jsonl-out", help="Optional path to write normalized JSONL")
    args = parser.parse_args()

    if args.hf_dataset:
        records = list(_iter_hf_dataset(args.hf_dataset, args.hf_split, args.hf_max_rows, args.hf_streaming))
    else:
        if not args.path:
            parser.error("path is required unless --hf-dataset is used")
        dataset_path = Path(args.path).expanduser().resolve()
        records = list(iter_dataset_records(dataset_path, recursive=args.recursive))

    _print_summary(records, max_rows=max(1, args.max_rows))

    if args.jsonl_out:
        out_path = Path(args.jsonl_out).expanduser().resolve()
        _write_jsonl(records, out_path)
        print(f"\nWrote JSONL: {out_path}")


if __name__ == "__main__":
    main()
