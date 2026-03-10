#!/usr/bin/env python3
"""
HUNTЕRТRACE — AUTOMATED CORPUS BUILDER v3
==========================================
Downloads real phishing/spam emails from multiple public sources,
auto-labels each one via IP geolocation, writes corpus.json.

Sources:
  1. SpamAssassin Public Corpus (7 tarballs, ~6000 emails)
  2. Nazario Phishing Corpus    (2400+ real phishing emails, mbox format)
  3. CSDMC2010 Spam Corpus      (4327 spam emails with full headers)

Usage:
    cd src
    python autoCorpusBuilder.py                        # 150 default
    python autoCorpusBuilder.py --target 200
    python autoCorpusBuilder.py --eml-dir /my/emails/
    python autoCorpusBuilder.py --verbose --target 50
"""

import os, re, sys, json, time, email, tarfile, zipfile, hashlib, mailbox
import argparse, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Optional, Dict, List

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

GEO_API        = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org,as,proxy,hosting"
GEO_RATE_LIMIT = 1.5

SPAMASSASSIN_CORPUS = [
    ("20021010_easy_ham.tar.bz2",   "https://spamassassin.apache.org/old/publiccorpus/20021010_easy_ham.tar.bz2"),
    ("20021010_spam.tar.bz2",       "https://spamassassin.apache.org/old/publiccorpus/20021010_spam.tar.bz2"),
    ("20030228_easy_ham.tar.bz2",   "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2"),
    ("20030228_easy_ham_2.tar.bz2", "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2"),
    ("20030228_spam.tar.bz2",       "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2"),
    ("20030228_spam_2.tar.bz2",     "https://spamassassin.apache.org/old/publiccorpus/20030228_spam_2.tar.bz2"),
    ("20050311_spam_2.tar.bz2",     "https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2"),
]

# Nazario phishing corpus — real reported phishing emails, mbox format
# Mirrored on GitHub (original monkey.org/~jose/phishing/ often offline)
NAZARIO_URLS = [
    "https://raw.githubusercontent.com/diegoocampoh/MachineLearningPhishing/master/phishing3.mbox",
    "http://monkey.org/~jose/phishing/phishing3.mbox",   # original (often slow)
]

# CSDMC2010 — classic labeled spam competition dataset
CSDMC_URL = "https://github.com/dslab-epfl/phishing/raw/master/spam/CSDMC2010_SPAM.zip"

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
    "CZ":"Czech Republic","HU":"Hungary","AT":"Austria","PT":"Portugal",
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
    "CZ":"Europe","HU":"Europe","AT":"Europe","PT":"Europe",
    "US":"Americas","BR":"Americas","CA":"Americas","MX":"Americas",
    "CO":"Americas","AR":"Americas","CL":"Americas",
    "SA":"Middle East","AE":"Middle East","IL":"Middle East",
    "AU":"Oceania","NZ":"Oceania",
}

DATACENTER_ORGS = [
    "amazon","aws","google","azure","microsoft","digitalocean","linode",
    "vultr","hetzner","ovh","scaleway","leaseweb","cloudflare","akamai",
    "fastly","rackspace","hosting","datacenter","data center","vps","colo",
    "selectel","timeweb","beget","aliyun","alibaba","tencent",
]

RELAY_ORGS = [
    "google","yahoo","microsoft","amazon ses","sendgrid","mailchimp",
    "sparkpost","postmark","mailgun","exacttarget","constant contact",
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
    if geo.get("proxy"): return "vpn"
    if geo.get("hosting"): return "datacenter"
    org = (geo.get("org") or geo.get("isp") or "").lower()
    if any(kw in org for kw in DATACENTER_ORGS): return "datacenter"
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

    all_ips = []
    for hdr in received:
        all_ips.extend(extract_ips(hdr))

    x_orig = (msg.get("X-Originating-IP") or msg.get("X-Originating-ip") or "").strip().strip("[]")
    public_ips = [ip for ip in all_ips if not is_private(ip)]
    if x_orig and not is_private(x_orig):
        public_ips = [x_orig] + [ip for ip in public_ips if ip != x_orig]

    if not public_ips:
        return None

    date_str = msg.get("Date", "")
    tz_offset = None
    send_hour = None
    m = re.search(r'([+-]\d{4})', date_str)
    if m: tz_offset = m.group(1)
    m = re.search(r'(\d{2}):\d{2}:\d{2}', date_str)
    if m: send_hour = int(m.group(1))

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

    return {
        "public_ips": public_ips,
        "has_x_orig": bool(x_orig and not is_private(x_orig)),
        "tz_offset":  tz_offset,
        "send_hour":  send_hour,
        "webmail":    webmail,
        "from_addr":  from_addr,
        "subject":    msg.get("Subject", ""),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  AUTO-LABELER
# ─────────────────────────────────────────────────────────────────────────────

def auto_label(parsed: dict, geo_cache: dict, verbose: bool = False) -> Optional[dict]:
    for ip in parsed["public_ips"]:
        geo = geolocate(ip, geo_cache)
        if not geo:
            continue
        if org_is_relay(geo):
            if verbose: print(f"      skip {ip} — relay ({geo.get('org','')})")
            continue

        cc           = geo.get("countryCode", "XX")
        country_name = geo.get("country", ISO_NAMES.get(cc, "Unknown"))
        region       = CC_TO_REGION.get(cc, "Unknown")
        ip_type      = classify_ip(geo)
        has_vpn      = ip_type in ("vpn", "datacenter")
        confidence   = "high" if parsed["has_x_orig"] and ip == parsed["public_ips"][0] else "medium"

        tier = 1
        if parsed["tz_offset"]: tier = 2
        if parsed["has_x_orig"] and ip == parsed["public_ips"][0]: tier = 3

        return {
            "ip": ip, "ip_type": ip_type, "country": cc,
            "country_name": country_name, "region": region,
            "tier": tier, "confidence": confidence,
            "has_vpn": has_vpn, "isp": geo.get("isp", ""),
        }
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  SOURCE ITERATORS
# ─────────────────────────────────────────────────────────────────────────────

def _download(url: str, dest: Path, label: str) -> bool:
    if dest.exists():
        print(f"  [cached]   {label}")
        return True
    print(f"  [download] {label} ...", end="", flush=True)
    try:
        urllib.request.urlretrieve(url, dest)
        print(f" ({dest.stat().st_size // 1024} KB)")
        return True
    except Exception as e:
        print(f" FAILED: {e}")
        if dest.exists(): dest.unlink()
        return False


def iter_spamassassin(dl_dir: Path):
    for fname, url in SPAMASSASSIN_CORPUS:
        local = dl_dir / fname
        if not _download(url, local, fname):
            continue
        try:
            with tarfile.open(local, "r:bz2") as tar:
                members = [m for m in tar.getmembers() if m.isfile()]
                print(f"             → {len(members)} files")
                for member in members:
                    try:
                        f = tar.extractfile(member)
                        if f is None: continue
                        raw = f.read().decode("utf-8", errors="replace")
                        if len(raw) >= 100:
                            yield member.name, raw
                    except Exception:
                        continue
        except Exception as e:
            print(f"  [!] Extract failed: {e}")


def iter_nazario(dl_dir: Path):
    """Download and iterate Nazario phishing corpus (mbox format)."""
    local = dl_dir / "phishing3.mbox"
    downloaded = False
    for url in NAZARIO_URLS:
        if _download(url, local, "phishing3.mbox (Nazario corpus)"):
            downloaded = True
            break
    if not downloaded:
        print("  [!] Nazario corpus unavailable — skipping")
        return

    try:
        mbox = mailbox.mbox(str(local))
        count = 0
        for i, msg in enumerate(mbox):
            try:
                raw = msg.as_string()
                if len(raw) >= 100:
                    yield f"nazario_{i:05d}", raw
                    count += 1
            except Exception:
                continue
        print(f"  [nazario]  → {count} messages")
    except Exception as e:
        print(f"  [!] Nazario parse failed: {e}")


def iter_csdmc(dl_dir: Path):
    """Download and iterate CSDMC2010 spam corpus (zip of .eml files)."""
    local = dl_dir / "CSDMC2010_SPAM.zip"
    if not _download(CSDMC_URL, local, "CSDMC2010_SPAM.zip"):
        return
    try:
        with zipfile.ZipFile(local, "r") as z:
            names = [n for n in z.namelist() if n.endswith(".eml") or "/SPAM/" in n]
            print(f"  [csdmc]    → {len(names)} files")
            for name in names:
                try:
                    raw = z.read(name).decode("utf-8", errors="replace")
                    if len(raw) >= 100:
                        yield name, raw
                except Exception:
                    continue
    except Exception as e:
        print(f"  [!] CSDMC parse failed: {e}")


def iter_local(eml_dir: Path):
    files = sorted(eml_dir.rglob("*.eml")) + sorted(eml_dir.rglob("*.msg"))
    print(f"  [local]    → {len(files)} files in {eml_dir}")
    for f in files:
        try:
            yield f.name, f.read_text(errors="replace")
        except Exception:
            continue


def all_sources(dl_dir: Path):
    """Chain all sources in order of quality."""
    print("\n[sources] SpamAssassin corpus:")
    yield from iter_spamassassin(dl_dir)
    print("\n[sources] Nazario phishing corpus:")
    yield from iter_nazario(dl_dir)
    print("\n[sources] CSDMC2010 spam corpus:")
    yield from iter_csdmc(dl_dir)


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
    dl_dir.mkdir(parents=True, exist_ok=True)

    # Resume
    entries: List[dict] = []
    seen_ids:  set = set()
    seen_ips:  set = set()

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
        print(f"[autoCorpusBuilder] Already at {len(entries)}/{target}. Done.")
        _save(entries, out_path)
        return

    print(f"\n[autoCorpusBuilder] Target={target}  Need={needed}  Output={out_path}\n")

    geo_cache: dict = {}
    processed = skipped_parse = skipped_geo = skipped_dupe = 0
    iterator  = iter_local(Path(eml_dir)) if eml_dir else all_sources(dl_dir)

    for raw_name, raw_email in iterator:
        if len(entries) >= target:
            break

        email_id = hashlib.md5(raw_name.encode()).hexdigest()[:12]
        if email_id in seen_ids:
            skipped_dupe += 1
            continue

        processed += 1
        if processed % 50 == 0:
            pct = len(entries) / target * 100
            print(f"  [{len(entries)}/{target} = {pct:.0f}%]  "
                  f"processed={processed}  no_parse={skipped_parse}  "
                  f"no_geo={skipped_geo}  dupes={skipped_dupe}")

        parsed = parse_email(raw_email)
        if not parsed:
            skipped_parse += 1
            continue

        primary_ip = parsed["public_ips"][0] if parsed["public_ips"] else None
        if primary_ip and primary_ip in seen_ips:
            skipped_dupe += 1
            continue

        label = auto_label(parsed, geo_cache, verbose=verbose)
        if not label or label["country"] in ("XX", ""):
            skipped_geo += 1
            continue

        (eml_out_dir / f"{email_id}.eml").write_text(
            raw_email, encoding="utf-8", errors="replace"
        )

        entry = {
            "id":   email_id,
            "file": str(Path(eml_out_dir.name) / f"{email_id}.eml"),
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
        if primary_ip: seen_ips.add(primary_ip)

        if verbose:
            print(f"  ✓ {label['country']} ({label['ip_type']:<12}) "
                  f"tier={label['tier']}  {label['isp'][:35]}")

        if len(entries) % 25 == 0:
            _save(entries, out_path)
            print(f"  [saved] {len(entries)} entries")

    _save(entries, out_path)
    _print_summary(entries, target, processed, skipped_parse, skipped_geo, out_path)


def _save(entries, out_path):
    corpus = {
        "metadata": {
            "version":         "1.0",
            "created_at":      datetime.now().isoformat(),
            "total_emails":    len(entries),
            "label_schema":    "ISO-3166-1 alpha-2, auto-labeled via ip-api.com",
            "labeling_method": "autoCorpusBuilder v3",
        },
        "emails": entries,
    }
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(corpus, f, indent=2)


def _print_summary(entries, target, processed, sp, sg, out_path):
    dist = defaultdict(int)
    for e in entries:
        dist[e["ground_truth"]["country"]] += 1

    print(f"\n{'='*60}")
    print(f"CORPUS BUILD COMPLETE")
    print(f"{'='*60}")
    print(f"  Collected  : {len(entries)} / {target}")
    print(f"  Processed  : {processed}")
    print(f"  No parse   : {sp}")
    print(f"  No geo     : {sg}")
    print(f"  Output     : {out_path}")
    print(f"\n  Top countries:")
    for cc, n in sorted(dist.items(), key=lambda x: -x[1])[:12]:
        bar = "█" * n
        print(f"    {cc} ({ISO_NAMES.get(cc,cc):<22}): {bar} {n}")
    print(f"{'='*60}\n")

    if len(entries) < target:
        shortage = target - len(entries)
        print(f"[!] {shortage} emails short of target.")
        print(f"    Add your own .eml files:")
        print(f"    python autoCorpusBuilder.py --eml-dir /path/to/emails/ --target {target}\n")


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="HunterTrace Automated Corpus Builder v3"
    )
    parser.add_argument("--target",    type=int, default=150)
    parser.add_argument("--out",       default="../mails/corpus.json")
    parser.add_argument("--eml-dir",   default=None)
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