#!/usr/bin/env python3
"""
generateSampleEmls.py
──────────────────────
Generates synthetic .eml files that match the entries in corpus.json.
Run this once before runEval.py when you don't have real phishing emails.

Usage:
    cd src
    python generateSampleEmls.py
    python generateSampleEmls.py --corpus ../mails/corpus.json --out-dir ../mails/samples/
"""

import json
import argparse
import random
from pathlib import Path
from datetime import datetime, timezone, timedelta


# ── Realistic per-country header data ────────────────────────────────────────

COUNTRY_PROFILES = {
    "NG": {
        "tz": "+0100", "send_hour": 10, "vpn_ip": "154.66.100.12",
        "real_ip": "102.89.45.67", "isp": "MTN Nigeria",
        "webmail": "gmail.com", "subject": "URGENT: Payment Required",
        "from_name": "Mr. Prince Adebayo",
    },
    "IN": {
        "tz": "+0530", "send_hour": 14, "vpn_ip": "45.32.100.20",
        "real_ip": "103.56.78.90", "isp": "Jio Infocomm",
        "webmail": "gmail.com", "subject": "Your Account Has Been Suspended",
        "from_name": "Support Team",
    },
    "RU": {
        "tz": "+0300", "send_hour": 11, "vpn_ip": "185.220.101.45",
        "real_ip": "95.173.136.71", "isp": "Rostelecom",
        "webmail": "yahoo.com", "subject": "Verify Your Account Immediately",
        "from_name": "Security Alert",
    },
    "CN": {
        "tz": "+0800", "send_hour": 9, "vpn_ip": "103.209.88.10",
        "real_ip": "121.41.102.45", "isp": "China Telecom",
        "webmail": "outlook.com", "subject": "Important: Action Required",
        "from_name": "Admin",
    },
    "US": {
        "tz": "-0500", "send_hour": 13, "vpn_ip": "198.54.128.92",
        "real_ip": "72.21.91.29", "isp": "Comcast",
        "webmail": "gmail.com", "subject": "Your Invoice is Ready",
        "from_name": "Billing Department",
    },
    "RO": {
        "tz": "+0200", "send_hour": 15, "vpn_ip": "46.19.36.12",
        "real_ip": "79.112.200.44", "isp": "RCS & RDS",
        "webmail": "yahoo.com", "subject": "Confirm Your Identity",
        "from_name": "Account Services",
    },
    "BR": {
        "tz": "-0300", "send_hour": 10, "vpn_ip": "177.93.58.2",
        "real_ip": "189.28.128.10", "isp": "Claro Brasil",
        "webmail": "gmail.com", "subject": "Atualização de Segurança",
        "from_name": "Suporte",
    },
    "UA": {
        "tz": "+0200", "send_hour": 12, "vpn_ip": "91.108.56.130",
        "real_ip": "176.36.112.88", "isp": "Kyivstar",
        "webmail": "outlook.com", "subject": "Password Reset Notification",
        "from_name": "IT Helpdesk",
    },
    "GH": {
        "tz": "+0000", "send_hour": 8, "vpn_ip": "154.66.50.21",
        "real_ip": "154.160.22.54", "isp": "MTN Ghana",
        "webmail": "gmail.com", "subject": "Investment Opportunity",
        "from_name": "Financial Advisor",
    },
    "PK": {
        "tz": "+0500", "send_hour": 16, "vpn_ip": "103.81.214.10",
        "real_ip": "111.68.101.23", "isp": "PTCL",
        "webmail": "yahoo.com", "subject": "Exclusive Offer for You",
        "from_name": "Customer Care",
    },
}

DEFAULT_PROFILE = {
    "tz": "+0000", "send_hour": 12, "vpn_ip": "45.77.65.211",
    "real_ip": "8.8.8.8", "isp": "Unknown ISP",
    "webmail": "gmail.com", "subject": "Important Message",
    "from_name": "Sender",
}


def build_eml(entry: dict) -> str:
    """
    Build a realistic-looking .eml file from a corpus entry.
    Includes headers that hunterTrace's pipeline can actually parse:
      - Received chain (2 hops)
      - X-Originating-IP (webmail real IP leak)
      - Date with timezone
      - DKIM-Signature
      - Message-ID
    """
    gt  = entry["ground_truth"]
    meta = entry.get("metadata", {})
    cc  = gt["country"]
    p   = COUNTRY_PROFILES.get(cc, DEFAULT_PROFILE)

    has_vpn = meta.get("has_vpn", False)
    has_tor = meta.get("has_tor", False)
    webmail_type = meta.get("webmail_type", "gmail")

    # Pick sending IP: VPN/Tor exit or real IP
    if has_tor:
        sending_ip = "185.220.101.34"   # known Tor exit
    elif has_vpn:
        sending_ip = p["vpn_ip"]
    else:
        sending_ip = p["real_ip"]

    # Date header
    tz_sign  = p["tz"][0]
    tz_hours = int(p["tz"][1:3])
    tz_mins  = int(p["tz"][3:5])
    tz_off   = timedelta(hours=tz_hours, minutes=tz_mins)
    if tz_sign == "-":
        tz_off = -tz_off
    tz_obj   = timezone(tz_off)
    dt       = datetime(2024, 6, 15, p["send_hour"], 22, 10, tzinfo=tz_obj)
    date_str = dt.strftime("%a, %d %b %Y %H:%M:%S ") + p["tz"]

    from_addr  = f"{p['from_name'].lower().replace(' ', '.')}@{p['webmail']}"
    msg_id     = f"<{entry['id']}.{cc.lower()}@{p['webmail']}>"
    dkim_domain = p["webmail"]

    # Build Received chain
    received_1 = (
        f"from mail-server.{p['webmail']} ({p['webmail']} [{sending_ip}])\n"
        f"        by mx.victim.com with ESMTPS id abc123\n"
        f"        for <victim@victim.com>; {date_str}"
    )
    received_2 = (
        f"from [{p['real_ip']}] ([{p['real_ip']}])\n"
        f"        by smtp.{p['webmail']} with ESMTPSA id xyz789\n"
        f"        for <victim@victim.com>; {date_str}"
    )

    # X-Originating-IP only present for gmail/yahoo/outlook without perfect OPSEC
    x_orig_ip = ""
    if webmail_type in ("gmail", "yahoo", "outlook") and not has_tor:
        leak_ip = p["real_ip"] if not has_vpn else p["vpn_ip"]
        x_orig_ip = f"X-Originating-IP: {leak_ip}\n"

    eml = f"""\
Received: {received_1}
Received: {received_2}
{x_orig_ip}DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={dkim_domain};
        s=20230601; h=from:to:subject:date:message-id;
        bh=abc123==; b=def456==
From: {p['from_name']} <{from_addr}>
To: victim@victim.com
Subject: {p['subject']}
Date: {date_str}
Message-ID: {msg_id}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
X-Mailer: Gmail

Dear Victim,

This is a simulated phishing email for HunterTrace evaluation purposes.
The origin country for this sample is {gt['country_name']} ({cc}).

Please disregard this message.

Regards,
{p['from_name']}
"""
    return eml


def generate(corpus_path: str, out_dir: str) -> None:
    corpus_path = Path(corpus_path)
    out_dir     = Path(out_dir)

    with open(corpus_path) as f:
        corpus = json.load(f)

    emails = corpus.get("emails", [])
    created = 0
    skipped = 0

    for entry in emails:
        # Resolve output path relative to corpus directory
        rel_file = entry["file"]                         # e.g. "samples/phish_0001.eml"
        out_path = out_dir / Path(rel_file).name         # e.g. ../mails/samples/phish_0001.eml

        out_path.parent.mkdir(parents=True, exist_ok=True)

        if out_path.exists():
            skipped += 1
            continue

        eml_content = build_eml(entry)
        out_path.write_text(eml_content)
        created += 1

    print(f"\n[generateSampleEmls] Done.")
    print(f"  Created : {created} .eml files")
    print(f"  Skipped : {skipped} (already existed)")
    print(f"  Location: {out_dir.resolve()}\n")

    # Patch corpus so file paths point to the actual output location
    # (only needed if out_dir differs from what corpus.json already records)
    needs_patch = False
    for entry in emails:
        expected = str(Path(entry["file"]))
        actual   = str(Path(out_dir.name) / Path(entry["file"]).name)
        if not (corpus_path.parent / expected).exists():
            needs_patch = True
            break

    if needs_patch:
        print("[generateSampleEmls] Patching corpus.json file paths to match output dir...")
        for entry in emails:
            fname = Path(entry["file"]).name
            entry["file"] = str(Path(out_dir.name) / fname)
        with open(corpus_path, "w") as f:
            json.dump(corpus, f, indent=2)
        print(f"  corpus.json updated — file paths now point to {out_dir.name}/\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate synthetic .eml files matching a HunterTrace corpus.json"
    )
    parser.add_argument(
        "--corpus",  default="../mails/corpus.json",
        help="Path to corpus.json (default: ../mails/corpus.json)"
    )
    parser.add_argument(
        "--out-dir", default="../mails/samples/",
        help="Directory to write .eml files into (default: ../mails/samples/)"
    )
    args = parser.parse_args()
    generate(args.corpus, args.out_dir)