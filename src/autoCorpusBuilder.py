#!/usr/bin/env python3
"""
HUNTЕРТRACE — AUTOMATED CORPUS BUILDER v2
==========================================
Downloads real spam/phishing emails from public sources, auto-labels
each one via IP geolocation, and writes a ready-to-use corpus.json.

Sources (all free, no login):
  SpamAssassin Public Corpus — 6 tarballs, ~6,000 real emails with headers

Auto-labeling:
  Parse Received: chain → geolocate public IPs → write ground truth label

Usage:
    cd src
    python autoCorpusBuilder.py                         # 150 emails default
    python autoCorpusBuilder.py --target 200
    python autoCorpusBuilder.py --eml-dir /my/emails/  # use local files
    python autoCorpusBuilder.py --target 50 --verbose
"""

import os, re, sys, json, time, email, tarfile, hashlib
import argparse, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Optional, Dict, List, Tuple


# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

GEO_API        = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org,as,proxy,hosting"
GEO_RATE_LIMIT = 1.5   # seconds between requests — ip-api free = 45/min

# All 6 SpamAssassin tarballs (gives ~6000 emails total)
SPAMASSASSIN_CORPUS = [
    ("20021010_easy_ham.tar.bz2",   "https://spamassassin.apache.org/old/publiccorpus/20021010_easy_ham.tar.bz2"),
    ("20021010_spam.tar.bz2",       "https://spamassassin.apache.org/old/publiccorpus/20021010_spam.tar.bz2"),
    ("20030228_easy_ham.tar.bz2",   "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2"),
    ("20030228_easy_ham_2.tar.bz2", "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2"),
    ("20030228_spam.tar.bz2",       "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2"),
    ("20030228_spam_2.tar.bz2",     "https://spamassassin.apache.org/old/publiccorpus/20030228_spam_2.tar.bz2"),
    ("20050311_spam_2.tar.bz2",     "https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2"),
]

ISO_NAMES = {
    "NG":"Nigeria","IN":"India","RU":"Russia","CN":"China","US":"United States",
    "RO":"Romania","BR":"Brazil","UA":"Ukraine","ZA":"South Africa","GH":"Ghana",
    "PK":"Pakistan","ID":"Indonesia","VN":"Vietnam","PH":"Philippines","TR":"Turkey",
    "IR":"Iran","BG":"Bulgaria","KP":"North Korea","BY":"Belarus","DE":"Germany",
    "FR":"France","GB":"United Kingdom","NL":"Netherlands","PL":"Poland","KE":"Kenya",
    "EG":"Egypt","MA":"Morocco","TH":"Thailand","MY":"Malaysia","SG":"Singapore",
    "BD":"Bangladesh","AU":"Australia","CA":"Canada","MX":"Mexico","AR":"Argentina",
    "SA":"Saudi Arabia","AE":"UAE","IL":"Israel","JP":"Japan","KR":"South Korea",
    "ES":"Spain","IT":"Italy","SE":"Sweden","NO":"Norway","FI":"Finland",
    "CZ":"Czech Republic","HU":"Hungary","SK":"Slovakia","AT":"Austria",
}

CC_TO_REGION = {
    "NG":"Africa","GH":"Africa","ZA":"Africa","KE":"Africa","SN":"Africa",
    "EG":"Africa","MA":"Africa","ET":"Africa","TZ":"Africa","CM":"Africa",
    "IN":"Asia","PK":"Asia","ID":"Asia","VN":"Asia","PH":"Asia","CN":"Asia",
    "IR":"Asia","KP":"Asia","TR":"Asia","BD":"Asia","TH":"Asia","MY":"Asia",
    "SG":"Asia","JP":"Asia","KR":"Asia",
    "RU":"Europe","UA":"Europe","RO":"Europe","BG":"Europe","BY":"Europe",
    "PL":"Europe","DE":"Europe","FR":"Europe","GB":"Europe","NL":"Europe",
    "ES":"Europe","IT":"Europe","SE":"Europe","NO":"Europe","FI":"Europe",
    "CZ":"Europe","HU":"Europe","SK":"Europe","AT":"Europe",
    "US":"Americas","BR":"Americas","CA":"Americas","MX":"Americas",
    "CO":"Americas","AR":"Americas","CL":"Americas",
    "SA":"Middle East","AE":"Middle East","IL":"Middle East",
    "AU":"Oceania","NZ":"Oceania",
}

DATACENTER_ORGS = [
    "amazon","aws","google","azure","microsoft","digitalocean","linode",
    "vultr","hetzner","ovh","scaleway","leaseweb","cloudflare","akamai",
    "fastly","rackspace","softlayer","internap","zenlayer","choopa",
    "quadranet","psychz","tzulo","frantech","serverius","reliablesite",
    "hosting","datacenter","data center","vps","colocation","colo",
    "selectel","timeweb","beget","aliyun","alibaba","tencent","qcloud",
]

# Mail relay services whose IPs are NOT the attacker's IP
RELAY_ORGS = [
    "google","yahoo","microsoft","amazon ses","sendgrid",
    "mailchimp","sparkpost","postmark","mailgun","exacttarget",
    "constant contact","sailthru","klaviyo","marketo",
]


# ─────────────────────────────────────────────────────────────────────────────
#  IP UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
        if a == 10: return True
        if a == 172 and 16 <= b <= 31: return True
        if a == 192 and b == 168: return True
        if a in (127, 0, 169): return True
        if a >= 224: return True
        return False
    except ValueError:
        return True


def extract_ips(text: str) -> List[str]:
    return re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)


def geolocate(ip: str, cache: dict) -> Optional[dict]:
    if ip in cache:
        return cache[ip]
    try:
        req = urllib.request.Request(
            GEO_API.format(ip=ip),
            headers={"User-Agent": "HunterTrace/2.0 Research"}
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        time.sleep(GEO_RATE_LIMIT)
        result = data if data.get("status") == "success" else None
        cache[ip] = result
        return result
    except Exception:
        cache[ip] = None
        return None


def org_is_relay(geo: dict) -> bool:
    org = (geo.get("org") or geo.get("isp") or "").lower()
    return any(kw in org for kw in RELAY_ORGS)


def classify_ip(geo: dict) -> str:
    if geo.get("proxy"):
        return "vpn"
    if geo.get("hosting"):
        return "datacenter"
    org = (geo.get("org") or geo.get("isp") or "").lower()
    if any(kw in org for kw in DATACENTER_ORGS):
        return "datacenter"
    return "residential"


# ─────────────────────────────────────────────────────────────────────────────
#  EMAIL PARSER
# ─────────────────────────────────────────────────────────────────────────────

def parse_email(raw: str) -> Optional[dict]:
    try:
        msg = email.message_from_string(raw)
    except Exception:
        return None

    received = msg.get_all("Received") or []
    if not received:
        return None

    # Collect all public IPs from Received chain (bottom = first hop)
    all_ips = []
    for hdr in received:
        all_ips.extend(extract_ips(hdr))

    # Also check X-Originating-IP
    x_orig = (msg.get("X-Originating-IP") or msg.get("X-Originating-ip") or "").strip().strip("[]")

    public_ips = [ip for ip in all_ips if not is_private(ip)]
    if x_orig and not is_private(x_orig):
        # Put X-Originating-IP first — highest priority
        public_ips = [x_orig] + [ip for ip in public_ips if ip != x_orig]

    if not public_ips:
        return None

    # Date / timezone
    date_str  = msg.get("Date", "")
    tz_offset = None
    send_hour = None
    m = re.search(r'([+-]\d{4})', date_str)
    if m:
        tz_offset = m.group(1)
    m = re.search(r'(\d{2}):\d{2}:\d{2}', date_str)
    if m:
        send_hour = int(m.group(1))

    # Webmail provider
    from_addr = msg.get("From", "").lower()
    received_str = " ".join(received).lower()
    webmail = "none"
    for provider, domains in [
        ("gmail",   ["gmail.com","googlemail.com"]),
        ("yahoo",   ["yahoo.com","ymail.com","yahoodns"]),
        ("outlook", ["outlook.com","hotmail.com","live.com"]),
        ("proton",  ["protonmail.com","proton.me"]),
    ]:
        if any(d in from_addr or d in received_str for d in domains):
            webmail = provider
            break

    # DKIM domain
    dkim = msg.get("DKIM-Signature", "")
    dkim_domain = None
    m = re.search(r'\bd=([^\s;]+)', dkim)
    if m:
        dkim_domain = m.group(1).strip(";")

    return {
        "public_ips":   public_ips,
        "has_x_orig":   bool(x_orig and not is_private(x_orig)),
        "tz_offset":    tz_offset,
        "send_hour":    send_hour,
        "webmail":      webmail,
        "from_addr":    from_addr,
        "dkim_domain":  dkim_domain,
        "subject":      msg.get("Subject", ""),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  AUTO-LABELER
# ─────────────────────────────────────────────────────────────────────────────

def auto_label(parsed: dict, geo_cache: dict, verbose: bool = False) -> Optional[dict]:
    """
    Try each public IP from most-reliable to least.
    Return the first successful non-relay geolocation.
    """
    for ip in parsed["public_ips"]:
        geo = geolocate(ip, geo_cache)
        if not geo:
            continue
        if org_is_relay(geo):
            if verbose:
                print(f"      skip {ip} — relay ({geo.get('org','')})")
            continue

        cc           = geo.get("countryCode", "XX")
        country_name = geo.get("country", ISO_NAMES.get(cc, "Unknown"))
        region       = CC_TO_REGION.get(cc, "Unknown")
        ip_type      = classify_ip(geo)
        has_vpn      = ip_type in ("vpn", "datacenter")

        # Confidence: X-Originating-IP = high, else medium
        confidence = "high" if parsed["has_x_orig"] and ip == parsed["public_ips"][0] else "medium"

        # Tier estimate
        tier = 1
        if parsed["tz_offset"]:
            tier = 2
        if parsed["has_x_orig"] and ip == parsed["public_ips"][0]:
            tier = 3

        return {
            "ip":           ip,
            "ip_type":      ip_type,
            "country":      cc,
            "country_name": country_name,
            "region":       region,
            "tier":         tier,
            "confidence":   confidence,
            "has_vpn":      has_vpn,
            "isp":          geo.get("isp", ""),
        }

    return None


# ─────────────────────────────────────────────────────────────────────────────
#  SPAMASSASSIN ITERATOR — fixed version
# ─────────────────────────────────────────────────────────────────────────────

def iter_spamassassin(download_dir: Path, verbose: bool):
    """
    Download all SpamAssassin tarballs and yield (name, raw_email) pairs.
    No limit here — caller decides when to stop.
    """
    download_dir.mkdir(parents=True, exist_ok=True)

    for fname, url in SPAMASSASSIN_CORPUS:
        local = download_dir / fname
        if not local.exists():
            print(f"  [download] {fname}  ", end="", flush=True)
            try:
                urllib.request.urlretrieve(url, local)
                print(f"({local.stat().st_size // 1024} KB)")
            except Exception as e:
                print(f"FAILED: {e}")
                continue
        else:
            print(f"  [cached]   {fname}")

        try:
            with tarfile.open(local, "r:bz2") as tar:
                members = [m for m in tar.getmembers() if m.isfile()]
                print(f"             → {len(members)} files inside")
                for member in members:
                    try:
                        f = tar.extractfile(member)
                        if f is None:
                            continue
                        raw = f.read().decode("utf-8", errors="replace")
                        if len(raw) < 100:
                            continue
                        # Use full archive path as name for uniqueness
                        yield member.name, raw
                    except Exception:
                        continue
        except Exception as e:
            print(f"  [!] Extract failed: {e}")
            continue


def iter_local(eml_dir: Path):
    """Yield (name, raw) from all .eml files in a directory."""
    files = sorted(eml_dir.rglob("*.eml")) + sorted(eml_dir.rglob("*.msg"))
    print(f"  [local] {len(files)} files in {eml_dir}")
    for f in files:
        try:
            yield f.name, f.read_text(errors="replace")
        except Exception:
            continue


# ─────────────────────────────────────────────────────────────────────────────
#  CORPUS BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_corpus(
    target:       int  = 150,
    out_path:     str  = "../mails/corpus.json",
    eml_dir:      str  = None,
    eml_out_dir:  str  = "../mails/emails/",
    verbose:      bool = False,
    resume:       bool = True,
) -> None:

    out_path    = Path(out_path)
    eml_out_dir = Path(eml_out_dir)
    dl_dir      = out_path.parent / "_downloads"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    eml_out_dir.mkdir(parents=True, exist_ok=True)

    # Resume
    entries: List[dict] = []
    seen_ids: set = set()
    seen_ips: set = set()   # avoid geolocating same origin IP twice

    if resume and out_path.exists():
        try:
            with open(out_path) as f:
                existing = json.load(f)
            entries   = existing.get("emails", [])
            seen_ids  = {e["id"] for e in entries}
            seen_ips  = {e["metadata"].get("origin_ip","") for e in entries}
            print(f"[autoCorpusBuilder] Resuming: {len(entries)} already labeled")
        except Exception:
            pass

    needed = target - len(entries)
    if needed <= 0:
        print(f"[autoCorpusBuilder] Already have {len(entries)}/{target}. Done.")
        _save(entries, out_path)
        return

    print(f"\n[autoCorpusBuilder] Target={target}  Need={needed}  Output={out_path}\n")

    geo_cache: dict = {}
    processed = skipped_parse = skipped_geo = skipped_dupe = 0
    iterator  = iter_local(Path(eml_dir)) if eml_dir else iter_spamassassin(dl_dir, verbose)

    for raw_name, raw_email in iterator:
        if len(entries) >= target:
            break

        email_id = hashlib.md5(raw_name.encode()).hexdigest()[:12]
        if email_id in seen_ids:
            skipped_dupe += 1
            continue

        processed += 1

        # Progress every 50 processed
        if processed % 50 == 0:
            pct = len(entries) / target * 100
            print(f"  [{len(entries)}/{target} = {pct:.0f}%]  "
                  f"processed={processed}  no_parse={skipped_parse}  "
                  f"no_geo={skipped_geo}  dupes={skipped_dupe}")

        parsed = parse_email(raw_email)
        if not parsed:
            skipped_parse += 1
            continue

        # Skip if we've already labeled an email from this exact IP
        primary_ip = parsed["public_ips"][0] if parsed["public_ips"] else None
        if primary_ip and primary_ip in seen_ips:
            skipped_dupe += 1
            continue

        label = auto_label(parsed, geo_cache, verbose=verbose)
        if not label:
            skipped_geo += 1
            continue

        if label["country"] in ("XX", ""):
            skipped_geo += 1
            continue

        # Save .eml
        eml_filename = f"{email_id}.eml"
        (eml_out_dir / eml_filename).write_text(raw_email, encoding="utf-8", errors="replace")

        entry = {
            "id":   email_id,
            "file": str(Path(eml_out_dir.name) / eml_filename),
            "ground_truth": {
                "country":      label["country"],
                "country_name": label["country_name"],
                "region":       label["region"],
                "tier":         label["tier"],
                "confidence":   label["confidence"],
                "notes":        f"IP={label['ip']} isp={label['isp']}",
                "labeled_by":   "autoCorpusBuilder",
                "labeled_at":   datetime.now().isoformat(),
            },
            "metadata": {
                "campaign":     "unknown",
                "has_vpn":      label["has_vpn"],
                "has_tor":      False,
                "webmail_type": parsed["webmail"],
                "origin_ip":    label["ip"],
                "ip_type":      label["ip_type"],
                "isp":          label["isp"],
                "tz_offset":    parsed["tz_offset"],
            }
        }
        entries.append(entry)
        seen_ids.add(email_id)
        if primary_ip:
            seen_ips.add(primary_ip)

        if verbose:
            print(f"  ✓ {label['country']} ({label['ip_type']:<12}) "
                  f"tier={label['tier']} {label['isp'][:30]}")

        if len(entries) % 25 == 0:
            _save(entries, out_path)
            print(f"  [saved] {len(entries)} entries")

    _save(entries, out_path)
    _print_summary(entries, target, processed, skipped_parse, skipped_geo, out_path)


def _save(entries, out_path):
    corpus = {
        "metadata": {
            "version":        "1.0",
            "created_at":     datetime.now().isoformat(),
            "total_emails":   len(entries),
            "label_schema":   "ISO-3166-1 alpha-2, auto-labeled via ip-api.com",
            "labeling_method":"autoCorpusBuilder v2",
        },
        "emails": entries,
    }
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(corpus, f, indent=2)


def _print_summary(entries, target, processed, skipped_parse, skipped_geo, out_path):
    dist = defaultdict(int)
    for e in entries:
        dist[e["ground_truth"]["country"]] += 1

    print(f"\n{'='*60}")
    print(f"CORPUS BUILD COMPLETE")
    print(f"{'='*60}")
    print(f"  Collected  : {len(entries)} / {target}")
    print(f"  Processed  : {processed}")
    print(f"  No parse   : {skipped_parse}")
    print(f"  No geo     : {skipped_geo}")
    print(f"  Output     : {out_path}")
    print(f"\n  Top countries:")
    for cc, n in sorted(dist.items(), key=lambda x: -x[1])[:12]:
        bar = "█" * n
        print(f"    {cc} ({ISO_NAMES.get(cc,cc):<22}): {bar} {n}")
    print(f"{'='*60}\n")

    if len(entries) < target:
        print(f"[!] Collected {len(entries)}/{target}.")
        print(f"    To get more emails, add your own:")
        print(f"    python autoCorpusBuilder.py --eml-dir /path/to/emails/ --target {target}\n")


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="HunterTrace Automated Corpus Builder v2"
    )
    parser.add_argument("--target",    type=int, default=150)
    parser.add_argument("--out",       default="../mails/corpus.json")
    parser.add_argument("--eml-dir",   default=None,
                        help="Use local .eml files instead of downloading")
    parser.add_argument("--eml-out",   default="../mails/emails/")
    parser.add_argument("--verbose",   action="store_true")
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args()

    build_corpus(
        target      = args.target,
        out_path    = args.out,
        eml_dir     = args.eml_dir,
        eml_out_dir = args.eml_out,
        verbose     = args.verbose,
        resume      = not args.no_resume,
    )