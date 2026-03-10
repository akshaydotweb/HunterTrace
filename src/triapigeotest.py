
#!/usr/bin/env python3
"""
triApiGeoTest.py — HunterTrace 3-Source IP Geolocation Accuracy Tester
=======================================================================
Tests every attacker IP in your corpus against three independent geolocation
APIs and computes:

  • Per-source accuracy vs HunterTrace attributed country
  • Cross-source agreement rate (all-3 agree / 2-of-3 agree)
  • Majority-vote accuracy (most common answer across 3 sources)
  • Disagreement table — where sources conflict

APIs used (all free, no key required):
  1. ip-api.com      — pipeline's existing source
  2. ipinfo.io       — independent, returns ISO-2 codes (auto-normalised)
  3. ipwho.is        — independent, returns full country name

Usage:
    python triApiGeoTest.py \\
        --corr v3_correlation_20260307_064422.json \\
        --attr v3_attribution_20260307_064422.json \\
        --out  geo_accuracy_report.json

    # Auto-detect latest files:
    python triApiGeoTest.py --auto

    # Test only first N actors (faster during dev):
    python triApiGeoTest.py --auto --limit 10
"""

import argparse, json, time, sys
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    print("[ERROR] pip install requests")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# ISO → FULL NAME MAP  (ipinfo returns ISO-2, others return full name)
# ─────────────────────────────────────────────────────────────────────────────
ISO_TO_NAME = {
    "US": "United States",      "GB": "United Kingdom",     "DE": "Germany",
    "FR": "France",             "CA": "Canada",             "AU": "Australia",
    "JP": "Japan",              "CN": "China",              "IN": "India",
    "KR": "South Korea",        "SG": "Singapore",          "VE": "Venezuela",
    "IE": "Ireland",            "TW": "Taiwan",             "GP": "France",
    "NL": "Netherlands",        "SE": "Sweden",             "NO": "Norway",
    "FI": "Finland",            "DK": "Denmark",            "PL": "Poland",
    "RO": "Romania",            "CH": "Switzerland",        "AT": "Austria",
    "BE": "Belgium",            "ES": "Spain",              "IT": "Italy",
    "PT": "Portugal",           "CZ": "Czech Republic",     "HU": "Hungary",
    "UA": "Ukraine",            "TR": "Turkey",             "IL": "Israel",
    "ZA": "South Africa",       "MX": "Mexico",             "AR": "Argentina",
    "CL": "Chile",              "CO": "Colombia",           "PH": "Philippines",
    "TH": "Thailand",           "ID": "Indonesia",          "MY": "Malaysia",
    "VN": "Vietnam",            "PK": "Pakistan",           "BD": "Bangladesh",
    "NG": "Nigeria",            "EG": "Egypt",              "SA": "Saudi Arabia",
    "AE": "United Arab Emirates","HK":"Hong Kong",           "NZ": "New Zealand",
    "RS": "Serbia",             "HR": "Croatia",            "BG": "Bulgaria",
    "SK": "Slovakia",           "SI": "Slovenia",           "LT": "Lithuania",
    "LV": "Latvia",             "EE": "Estonia",            "BY": "Belarus",
    "MD": "Moldova",            "GE": "Georgia",            "AM": "Armenia",
    "AZ": "Azerbaijan",         "KZ": "Kazakhstan",         "UZ": "Uzbekistan",
    "TM": "Turkmenistan",       "KG": "Kyrgyzstan",         "TJ": "Tajikistan",
    "MN": "Mongolia",           "MM": "Myanmar",            "KH": "Cambodia",
    "LA": "Laos",               "NP": "Nepal",              "LK": "Sri Lanka",
    "AF": "Afghanistan",        "IQ": "Iraq",               "IR": "Iran",
    "SY": "Syria",              "JO": "Jordan",             "LB": "Lebanon",
    "KW": "Kuwait",             "QA": "Qatar",              "BH": "Bahrain",
    "OM": "Oman",               "YE": "Yemen",              "MA": "Morocco",
    "DZ": "Algeria",            "TN": "Tunisia",            "LY": "Libya",
    "SD": "Sudan",              "ET": "Ethiopia",           "KE": "Kenya",
    "TZ": "Tanzania",           "UG": "Uganda",             "GH": "Ghana",
    "CI": "Ivory Coast",        "SN": "Senegal",            "CM": "Cameroon",
    "BR": "Brazil",             "PE": "Peru",               "EC": "Ecuador",
    "BO": "Bolivia",            "PY": "Paraguay",           "UY": "Uruguay",
    "CR": "Costa Rica",         "PA": "Panama",             "GT": "Guatemala",
    "HN": "Honduras",           "SV": "El Salvador",        "NI": "Nicaragua",
    "DO": "Dominican Republic", "CU": "Cuba",               "JM": "Jamaica",
    "HT": "Haiti",              "TT": "Trinidad and Tobago","BB": "Barbados",
}


# ─────────────────────────────────────────────────────────────────────────────
# API CALLERS
# ─────────────────────────────────────────────────────────────────────────────

def ipapi_lookup(ip: str) -> dict:
    """ip-api.com — pipeline's existing source. Returns full country name."""
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,org,isp,proxy,hosting",
            timeout=6
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                return {
                    "country": d.get("country"),
                    "city":    d.get("city"),
                    "org":     d.get("org"),
                    "proxy":   d.get("proxy"),
                    "hosting": d.get("hosting"),
                    "source":  "ip-api.com",
                    "ok":      True,
                }
    except Exception as e:
        pass
    return {"country": None, "source": "ip-api.com", "ok": False}


def ipinfo_lookup(ip: str) -> dict:
    """ipinfo.io — independent source. Returns ISO-2, auto-normalised to full name."""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json",
                         headers={"Accept": "application/json"}, timeout=6)
        if r.status_code == 200:
            d = r.json()
            iso     = d.get("country", "")
            full    = ISO_TO_NAME.get(iso, iso)
            return {
                "country":     full,
                "country_iso": iso,
                "city":        d.get("city"),
                "org":         d.get("org"),
                "source":      "ipinfo.io",
                "ok":          bool(iso),
            }
    except Exception:
        pass
    return {"country": None, "source": "ipinfo.io", "ok": False}


def ipwho_lookup(ip: str) -> dict:
    """ipwho.is — third independent source. Returns full country name directly."""
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=6)
        if r.status_code == 200:
            d = r.json()
            if d.get("success"):
                return {
                    "country": d.get("country"),
                    "city":    d.get("city"),
                    "org":     d.get("connection", {}).get("org"),
                    "source":  "ipwho.is",
                    "ok":      True,
                }
    except Exception:
        pass
    return {"country": None, "source": "ipwho.is", "ok": False}


# ─────────────────────────────────────────────────────────────────────────────
# MAIN TEST RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def run_test(corr: dict, attr: dict, limit: int = None) -> dict:
    clusters = corr.get("actor_clusters", [])
    if limit:
        clusters = clusters[:limit]

    print(f"\nTesting {len(clusters)} actors across 3 independent APIs")
    print(f"Rate limits: ip-api (45/min) → 0.5s delay | ipinfo (50k/day) → 0.3s | ipwho (10k/day) → 0.3s")
    print(f"Estimated time: ~{len(clusters)*1.5:.0f} seconds\n")

    header = f"{'Actor':<12} {'IP':<18} {'Attributed':<16} {'ip-api':<16} {'ipinfo':<16} {'ipwho.is':<16} Agree"
    print(header)
    print("─" * 100)

    rows = []

    for cluster in clusters:
        actor    = cluster["actor_id"]
        ips      = cluster.get("all_origin_ips", [])
        att_ctry = cluster.get("likely_country", "?")

        if not ips:
            print(f"{actor:<12} {'NO IP':<18} {att_ctry:<16} {'—':<16} {'—':<16} {'—':<16} SKIP")
            continue

        ip = ips[0]

        # Three independent lookups with rate-limit delays
        a = ipapi_lookup(ip);  time.sleep(0.55)
        b = ipinfo_lookup(ip); time.sleep(0.35)
        c = ipwho_lookup(ip);  time.sleep(0.35)

        ca = a.get("country")
        cb = b.get("country")
        cc = c.get("country")

        available = [x for x in [ca, cb, cc] if x]

        if len(available) >= 2:
            vote_counts   = Counter(available)
            majority      = vote_counts.most_common(1)[0][0]
            majority_n    = vote_counts.most_common(1)[0][1]
            all_agree     = (len(set(available)) == 1)
            two_agree     = (majority_n >= 2)
            agree_label   = "✓ALL" if all_agree else ("≈2/3" if two_agree else "✗SPL")
        else:
            majority      = available[0] if available else None
            all_agree     = False
            two_agree     = bool(majority)
            agree_label   = "?1/3" if majority else "?NONE"

        match_ipapi  = (ca == att_ctry)
        match_ipinfo = (cb == att_ctry)
        match_ipwho  = (cc == att_ctry)
        match_maj    = (majority == att_ctry)

        row = {
            "actor":         actor,
            "ip":            ip,
            "attributed":    att_ctry,
            "ipapi":         ca,
            "ipinfo":        cb,
            "ipwho":         cc,
            "majority":      majority,
            "all_agree":     all_agree,
            "two_agree":     two_agree,
            "agree_label":   agree_label,
            "match_ipapi":   match_ipapi,
            "match_ipinfo":  match_ipinfo,
            "match_ipwho":   match_ipwho,
            "match_majority":match_maj,
            "n_sources":     len(available),
        }
        rows.append(row)

        # Highlight mismatches
        flag = "" if match_maj else " ← MISMATCH"
        print(f"{actor:<12} {ip:<18} {att_ctry:<16} {str(ca):<16} {str(cb):<16} {str(cc):<16} {agree_label}{flag}")

    # ── Summary ───────────────────────────────────────────────────────────
    tested     = [r for r in rows if r["n_sources"] >= 1]
    multi      = [r for r in rows if r["n_sources"] >= 2]
    n_all_ag   = sum(1 for r in multi if r["all_agree"])
    n_two_ag   = sum(1 for r in multi if r["two_agree"])

    n_ipapi_ok  = sum(1 for r in tested if r["match_ipapi"]  is True)
    n_ipinfo_ok = sum(1 for r in tested if r["match_ipinfo"] is True)
    n_ipwho_ok  = sum(1 for r in tested if r["match_ipwho"]  is True)
    n_maj_ok    = sum(1 for r in tested if r["match_majority"] is True)

    n_ipapi_t   = sum(1 for r in tested if r["ipapi"]  is not None)
    n_ipinfo_t  = sum(1 for r in tested if r["ipinfo"] is not None)
    n_ipwho_t   = sum(1 for r in tested if r["ipwho"]  is not None)

    print("\n" + "═" * 100)
    print(f"\n3-API GEOLOCATION ACCURACY REPORT  (n={len(tested)} actors tested)")
    print(f"\n  Source accuracy vs HunterTrace attributed country:")
    print(f"    ip-api.com :  {n_ipapi_ok}/{n_ipapi_t}   ({n_ipapi_ok/max(1,n_ipapi_t):.0%})")
    print(f"    ipinfo.io  :  {n_ipinfo_ok}/{n_ipinfo_t}   ({n_ipinfo_ok/max(1,n_ipinfo_t):.0%})")
    print(f"    ipwho.is   :  {n_ipwho_ok}/{n_ipwho_t}   ({n_ipwho_ok/max(1,n_ipwho_t):.0%})")
    print(f"    Majority   :  {n_maj_ok}/{len(tested)}   ({n_maj_ok/max(1,len(tested)):.0%})  ← most robust")

    print(f"\n  Cross-source agreement (n={len(multi)} actors with ≥2 sources):")
    print(f"    All 3 sources agree:  {n_all_ag}/{len(multi)} ({n_all_ag/max(1,len(multi)):.0%})")
    print(f"    ≥2 sources agree:     {n_two_ag}/{len(multi)} ({n_two_ag/max(1,len(multi)):.0%})")

    # Disagreements table
    disagrees = [r for r in rows if r["n_sources"] >= 2 and not r["all_agree"]]
    if disagrees:
        print(f"\n  Disagreements ({len(disagrees)} actors):")
        print(f"    {'Actor':<12} {'IP':<18} {'ip-api':<18} {'ipinfo':<18} {'ipwho.is':<18}")
        for r in disagrees:
            print(f"    {r['actor']:<12} {r['ip']:<18} {str(r['ipapi']):<18} {str(r['ipinfo']):<18} {str(r['ipwho']):<18}")

    # Mismatches vs attributed country
    mismatches = [r for r in rows if r["n_sources"] >= 2 and not r["match_majority"]]
    if mismatches:
        print(f"\n  Majority-vote differs from HunterTrace attribution ({len(mismatches)} actors):")
        print(f"    {'Actor':<12} {'Attributed':<18} {'Majority':<18} {'All sources'}")
        for r in mismatches:
            srcs = f"ipapi={r['ipapi']} ipinfo={r['ipinfo']} ipwho={r['ipwho']}"
            print(f"    {r['actor']:<12} {r['attributed']:<18} {str(r['majority']):<18} {srcs}")

    print(f"\n  INTERPRETATION:")
    majority_acc = n_maj_ok / max(1, len(tested))
    if majority_acc >= 0.85:
        print(f"  ✓ STRONG: majority-vote geolocation ({majority_acc:.0%}) is highly consistent")
        print(f"    with HunterTrace attribution. Independently verifiable.")
    elif majority_acc >= 0.70:
        print(f"  ≈ MODERATE: majority-vote ({majority_acc:.0%}) broadly consistent but")
        print(f"    some actors may warrant review (see mismatch table above).")
    else:
        print(f"  ✗ WEAK: significant disagreement ({majority_acc:.0%}) — review mismatches")
        print(f"    before submission. May indicate VPN exit IP being geolocated")
        print(f"    rather than the actor's real IP.")

    print(f"\n  NOTE: These IPs are origin IPs from email headers.")
    print(f"  Agreement = all three APIs point to same country for those IPs.")
    print(f"  Accuracy vs 'attributed' country is a proxy measure only —")
    print(f"  true ground truth requires law enforcement confirmation.")

    return {
        "generated_at":   datetime.now().isoformat(),
        "n_tested":       len(tested),
        "n_multi_source": len(multi),
        "accuracy": {
            "ipapi":    round(n_ipapi_ok  / max(1, n_ipapi_t),  4),
            "ipinfo":   round(n_ipinfo_ok / max(1, n_ipinfo_t), 4),
            "ipwho":    round(n_ipwho_ok  / max(1, n_ipwho_t),  4),
            "majority": round(n_maj_ok    / max(1, len(tested)), 4),
        },
        "agreement": {
            "all_3_agree": round(n_all_ag / max(1, len(multi)), 4),
            "at_least_2":  round(n_two_ag / max(1, len(multi)), 4),
        },
        "rows": rows,
        "disagreements":  disagrees,
        "mismatches_vs_attribution": mismatches,
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def find_latest(pattern):
    matches = sorted(Path(".").glob(pattern))
    return str(matches[-1]) if matches else None

def main():
    ap = argparse.ArgumentParser(description="3-API IP Geolocation Accuracy Tester")
    ap.add_argument("--corr",  default=None)
    ap.add_argument("--attr",  default=None)
    ap.add_argument("--out",   default="geo_accuracy_report.json")
    ap.add_argument("--auto",  action="store_true", help="Auto-detect latest JSON files")
    ap.add_argument("--limit", type=int, default=None, help="Test only first N actors")
    args = ap.parse_args()

    corr_path = args.corr or find_latest("*correlation*.json")
    attr_path = args.attr or find_latest("*attribution*.json")

    if not corr_path or not Path(corr_path).exists():
        print("[ERROR] Cannot find correlation JSON. Use --corr or --auto")
        sys.exit(1)

    corr = json.loads(Path(corr_path).read_text())
    attr = json.loads(Path(attr_path).read_text()) if attr_path else {}

    result = run_test(corr, attr, limit=args.limit)

    Path(args.out).write_text(json.dumps(result, indent=2, default=str))
    print(f"\n  Full report saved → {args.out}")


if __name__ == "__main__":
    main()