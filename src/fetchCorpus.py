#!/usr/bin/env python3
"""
HunterTrace — Corpus Fetcher
=============================
Downloads real phishing email datasets from Zenodo (free, no login)
and converts them to .eml files for autoCorpusBuilder.

These are CSV datasets where each row contains a full email body
(headers + body) stored as text.

Usage:
    cd src
    python fetchCorpus.py                        # download all, extract to ../mails/eml_raw/
    python fetchCorpus.py --out ../mails/eml_raw/
    python fetchCorpus.py --limit 500            # max emails per dataset
    
Then feed to corpus builder:
    python autoCorpusBuilder.py --eml-dir ../mails/eml_raw/ --target 200
"""

import csv, os, sys, hashlib, argparse, urllib.request
from pathlib import Path

# Zenodo direct download URLs — no login required, CC-BY licensed
# Citation: Champa et al., ISDFS 2024 / ICMI 2024
DATASETS = [
    {
        "name":  "Nazario",
        "url":   "https://zenodo.org/records/8339691/files/Nazario.csv?download=1",
        "size":  "7.8 MB",
        "notes": "2400+ verified real phishing emails",
    },
    {
        "name":  "Nigerian_Fraud",
        "url":   "https://zenodo.org/records/8339691/files/Nigerian_Fraud.csv?download=1",
        "size":  "9.2 MB",
        "notes": "Nigerian 419 fraud emails — real IPs, diverse origins",
    },
    {
        "name":  "Nazario_5",
        "url":   "https://zenodo.org/records/8339691/files/Nazario_5.csv?download=1",
        "size":  "11.8 MB",
        "notes": "Extended Nazario phishing corpus v5",
    },
    {
        "name":  "CEAS_08",
        "url":   "https://zenodo.org/records/8339691/files/CEAS_08.csv?download=1",
        "size":  "67.9 MB",
        "notes": "CEAS 2008 spam corpus — large, diverse",
    },
]

def download(url: str, dest: Path, name: str) -> bool:
    if dest.exists() and dest.stat().st_size > 1000:
        print(f"  [cached]   {name} ({dest.stat().st_size // 1024} KB)")
        return True
    print(f"  [download] {name} ...", end="", flush=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HunterTrace/3.0 Research"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
        dest.write_bytes(data)
        print(f" {len(data)//1024} KB")
        return True
    except Exception as e:
        print(f" FAILED: {e}")
        return False


def csv_to_eml(csv_path: Path, out_dir: Path, limit: int, dataset_name: str) -> int:
    """
    Convert a Zenodo phishing CSV to individual .eml files.
    
    The CSVs have varying column names — we try common ones:
      'text', 'body', 'email', 'message', 'mail', 'content'
    Some have full RFC 2822 headers, some just body text.
    We save whatever we get — the header parser handles both.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0

    try:
        with open(csv_path, encoding="utf-8", errors="replace") as f:
            # Detect delimiter
            sample = f.read(4096)
            f.seek(0)
            delimiter = "," if sample.count(",") > sample.count("\t") else "\t"
            reader = csv.DictReader(f, delimiter=delimiter)
            
            # Find the column with email content
            fields = reader.fieldnames or []
            text_col = None
            for candidate in ["text", "body", "email", "message", "mail",
                               "content", "Email Text", "email_text", "Body"]:
                if candidate in fields:
                    text_col = candidate
                    break
            if not text_col and fields:
                # Use the longest-valued column heuristically
                text_col = fields[-1]
            
            print(f"  [parse]    {csv_path.name} — columns: {fields[:6]}  text_col='{text_col}'")
            
            for i, row in enumerate(reader):
                if written >= limit:
                    break
                
                raw = (row.get(text_col) or "").strip()
                if len(raw) < 150:
                    skipped += 1
                    continue
                
                # If it doesn't look like an email (no headers), add minimal ones
                if not raw.startswith(("From ", "Received:", "Date:", "From:", "Return-Path:")):
                    # Try to find a From: or Received: anywhere in first 500 chars
                    if "Received:" not in raw[:500] and "From:" not in raw[:500]:
                        # Wrap with minimal headers so our parser can work with it
                        raw = f"From: unknown@unknown.com\nDate: Thu, 1 Jan 2004 12:00:00 +0000\n\n{raw}"
                
                email_id = hashlib.md5(f"{dataset_name}_{i}".encode()).hexdigest()[:12]
                out_file = out_dir / f"{email_id}.eml"
                
                if not out_file.exists():
                    out_file.write_text(raw, encoding="utf-8", errors="replace")
                    written += 1
                else:
                    skipped += 1
                    
    except Exception as e:
        print(f"  [!] CSV parse error: {e}")
        return written

    return written


def main():
    parser = argparse.ArgumentParser(description="HunterTrace Corpus Fetcher")
    parser.add_argument("--out",      default="../mails/eml_raw/",
                        help="Output directory for .eml files")
    parser.add_argument("--dl-dir",   default="../mails/_downloads/",
                        help="Directory to cache downloaded CSVs")
    parser.add_argument("--limit",    type=int, default=800,
                        help="Max emails to extract per dataset (default 800)")
    parser.add_argument("--datasets", default="Nazario,Nigerian_Fraud,Nazario_5",
                        help="Comma-separated dataset names to download")
    args = parser.parse_args()

    out_dir = Path(args.out)
    dl_dir  = Path(args.dl_dir)
    dl_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    wanted = set(args.datasets.split(","))
    datasets = [d for d in DATASETS if d["name"] in wanted]

    total_written = 0
    print(f"\n[fetchCorpus] Downloading {len(datasets)} dataset(s)")
    print(f"              Output: {out_dir.resolve()}\n")

    for ds in datasets:
        name = ds["name"]
        print(f"\n--- {name} ({ds['size']}) — {ds['notes']} ---")
        
        csv_path = dl_dir / f"{name}.csv"
        if not download(ds["url"], csv_path, name):
            print(f"  [skip] {name} — download failed")
            continue
        
        n = csv_to_eml(csv_path, out_dir, args.limit, name)
        print(f"  [done]     {n} .eml files written")
        total_written += n

    print(f"\n{'='*55}")
    print(f"  Total .eml files: {total_written}")
    print(f"  Output dir:       {out_dir.resolve()}")
    print(f"\nNext step:")
    print(f"  python autoCorpusBuilder.py \\")
    print(f"    --eml-dir {args.out} \\")
    print(f"    --target 200")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()