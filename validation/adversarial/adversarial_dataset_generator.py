#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_SEED  = 7331   # different from synthetic generator seed=42
DEFAULT_COUNT = 800    # 100 per scenario × 8 scenarios

# ─────────────────────────────────────────────────────────────────────────────
#  ACTOR PROFILES  (same as dataset_generator.py — import or redefine)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ActorProfile:
    country:          str
    timezone_offset:  str
    timezone_region:  str
    isp_ranges:       List[str]
    isp_country:      str
    isp_names:        List[str]
    asn:              str
    charset:          Optional[str]
    webmail_hints:    List[str]
    send_hours:       Tuple[int, int]

ACTORS: Dict[str, ActorProfile] = {
    "Nigeria": ActorProfile(
        country="Nigeria", timezone_offset="+0100",
        timezone_region="Central Europe / West Africa",
        isp_ranges=["105.112.", "41.184.", "197.210.", "105.113."],
        isp_country="Nigeria", isp_names=["Airtel Nigeria", "MTN Nigeria"],
        asn="AS36873", charset=None,
        webmail_hints=["gmail.com", "yahoo.com"], send_hours=(8, 17),
    ),
    "Russia": ActorProfile(
        country="Russia", timezone_offset="+0300",
        timezone_region="Russia (Moscow) / East Africa",
        isp_ranges=["95.165.", "85.143.", "213.87.", "77.88."],
        isp_country="Russia", isp_names=["Rostelecom", "MTS Russia"],
        asn="AS12389", charset="windows-1251",
        webmail_hints=["yandex.ru", "mail.ru"], send_hours=(9, 18),
    ),
    "China": ActorProfile(
        country="China", timezone_offset="+0800",
        timezone_region="China / Southeast Asia",
        isp_ranges=["58.211.", "112.80.", "117.135.", "123.149."],
        isp_country="China", isp_names=["China Telecom", "China Unicom"],
        asn="AS4134", charset="gbk",
        webmail_hints=["qq.com", "163.com"], send_hours=(8, 17),
    ),
    "India": ActorProfile(
        country="India", timezone_offset="+0530",
        timezone_region="India / Sri Lanka",
        isp_ranges=["103.87.", "49.43.", "117.197.", "103.6."],
        isp_country="India", isp_names=["BSNL", "Jio"],
        asn="AS9829", charset=None,
        webmail_hints=["gmail.com", "yahoo.co.in"], send_hours=(9, 18),
    ),
    "Romania": ActorProfile(
        country="Romania", timezone_offset="+0200",
        timezone_region="Eastern Europe / South Africa",
        isp_ranges=["86.125.", "86.120.", "5.2.", "79.114."],
        isp_country="Romania", isp_names=["RCS & RDS", "Romtelecom"],
        asn="AS8708", charset="windows-1250",
        webmail_hints=["gmail.com", "yahoo.com"], send_hours=(8, 17),
    ),
    "Iran": ActorProfile(
        country="Iran", timezone_offset="+0330",
        timezone_region="Iran",
        isp_ranges=["5.119.", "46.224.", "89.42.", "91.98."],
        isp_country="Iran", isp_names=["Irancell", "TCI"],
        asn="AS48159", charset=None,
        webmail_hints=["gmail.com", "yahoo.com"], send_hours=(9, 18),
    ),
    "Vietnam": ActorProfile(
        country="Vietnam", timezone_offset="+0700",
        timezone_region="Southeast Asia",
        isp_ranges=["113.161.", "42.112.", "118.71.", "1.55."],
        isp_country="Vietnam", isp_names=["VNPT", "Viettel"],
        asn="AS38731", charset="windows-1258",
        webmail_hints=["gmail.com", "yahoo.com"], send_hours=(8, 17),
    ),
    "Brazil": ActorProfile(
        country="Brazil", timezone_offset="-0300",
        timezone_region="Brazil / Argentina",
        isp_ranges=["177.37.", "200.143.", "179.108.", "186.193."],
        isp_country="Brazil", isp_names=["Claro Brazil", "Vivo"],
        asn="AS28573", charset=None,
        webmail_hints=["gmail.com", "hotmail.com"], send_hours=(8, 17),
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
#  INFRASTRUCTURE DATA
# ─────────────────────────────────────────────────────────────────────────────

# Residential proxy pool IPs — appear as clean ISP broadband, not datacenter
RESIP_POOLS = [
    ("104.28.{a}.{b}", "Cloudflare WARP RESIP",  "AS13335", "United States"),
    ("172.67.{a}.{b}", "Cloudflare CDN RESIP",   "AS13335", "United States"),
    ("67.205.{a}.{b}", "DigitalOcean RESIP pool", "AS14061", "United States"),
    ("185.162.{a}.{b}","Bright Data (Luminati)",  "AS198532","United States"),
    ("82.222.{a}.{b}", "Oxylabs RESIP pool",      "AS60068", "Germany"),
    ("185.197.{a}.{b}","IPRoyal RESIP pool",      "AS208722","Netherlands"),
]

# Legitimate corporate SMTP servers (breached — all signals point to wrong country)
COMPROMISED_RELAYS = [
    {
        "host":        "mail.mittelstand-gmbh.de",
        "ip":          "89.238.139.52",
        "isp_country": "Germany",
        "geo_country": "Germany",
        "asn":         "AS3320",
        "isp":         "Deutsche Telekom",
        "tz_offset":   "+0100",
        "charset":     "windows-1252",
        "org":         "German SME manufacturing firm",
    },
    {
        "host":        "smtp.suzuki-trading.co.jp",
        "ip":          "210.157.18.33",
        "isp_country": "Japan",
        "geo_country": "Japan",
        "asn":         "AS2527",
        "isp":         "SoftBank Japan",
        "tz_offset":   "+0900",
        "charset":     "iso-2022-jp",
        "org":         "Japanese trading company",
    },
    {
        "host":        "mail.greenfields-logistics.co.uk",
        "ip":          "194.72.6.44",
        "isp_country": "United Kingdom",
        "geo_country": "United Kingdom",
        "asn":         "AS5089",
        "isp":         "Virgin Media Business",
        "tz_offset":   "+0000",
        "charset":     "utf-8",
        "org":         "UK logistics company",
    },
    {
        "host":        "exchange.midwest-bank.com",
        "ip":          "69.63.175.18",
        "isp_country": "United States",
        "geo_country": "United States",
        "asn":         "AS7922",
        "isp":         "Comcast Business",
        "tz_offset":   "-0500",
        "charset":     "utf-8",
        "org":         "US mid-size bank",
    },
]

# VPN providers for multi-hop chaining
VPN_CHAIN_PROVIDERS = [
    ("NordVPN",    "185.130.44.",  "NL", "AS212238"),
    ("ExpressVPN", "43.132.198.", "SG", "AS136787"),
    ("ProtonVPN",  "194.165.16.", "CH", "AS209103"),
    ("Mullvad",    "193.32.249.", "SE", "AS39351"),
    ("Surfshark",  "45.134.212.", "NL", "AS9009"),
    ("CyberGhost", "37.120.131.", "DE", "AS212238"),
    ("IPVanish",   "198.54.117.", "US", "AS33387"),
]

# Decoy DNS registrars and their geo — used in dns_false_flag scenario
DNS_DECOY_REGISTRARS = [
    ("Namecheap",      "United States", "AS13335"),
    ("GoDaddy",        "United States", "AS21501"),
    ("Cloudflare DNS", "United States", "AS13335"),
    ("Hetzner Online", "Germany",       "AS24940"),
    ("OVH",            "France",        "AS16276"),
]

# Tor exit nodes (same pool as synthetic generator)
TOR_EXIT_IPS = [
    "185.220.101.47", "185.220.101.48", "104.244.76.13",
    "77.247.109.165", "5.2.74.205",     "185.130.44.108",
]

# Victim MX servers
VICTIM_MX = [
    {"host": "mx.targetcorp.com",    "ip": "203.0.113.10"},
    {"host": "mail.enterprise.org",  "ip": "198.51.100.22"},
    {"host": "mx1.bigcompany.com",   "ip": "192.0.2.55"},
]

# Subject lines and body text
SUBJECTS = [
    "URGENT: Verify Your Account Immediately",
    "Action Required: Unusual Sign-in Activity",
    "Invoice #{n} Requires Immediate Approval",
    "Security Alert: Your Password Will Expire",
    "RE: Wire Transfer Authorization Ref#{n}",
    "Your Account Has Been Suspended",
    "Final Notice: Account Verification Required",
]

BODIES = [
    "Dear Customer,\r\n\r\nYour account requires immediate verification.\r\nClick here: https://verify.secure-login.net/token/{t}\r\n\r\nRegards,\r\nSecurity Team",
    "Dear Accounts Team,\r\n\r\nPlease process the attached urgent wire transfer.\r\nRef: {t}\r\n\r\nKind regards,\r\nCFO Office",
    "Please confirm your identity to restore access.\r\nhttps://portal.account-verify.com/auth/{t}",
]


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

class RNG:
    """Thin wrapper around random.Random with domain-specific helpers."""

    def __init__(self, seed: int):
        self._r = random.Random(seed)

    def ip(self, prefix: str) -> str:
        parts = prefix.rstrip(".").split(".")
        while len(parts) < 4:
            parts.append(str(self._r.randint(1, 254)))
        return ".".join(parts)

    def pick(self, seq):
        return self._r.choice(seq)

    def sample(self, seq, n):
        return self._r.sample(seq, n)

    def randint(self, a, b):
        return self._r.randint(a, b)

    def random(self):
        return self._r.random()

    def date(self, tz_offset: str, hour: Optional[int] = None) -> str:
        """RFC 2822 Date header value with correct timezone offset."""
        sign = tz_offset[0]
        hh   = int(tz_offset[1:3])
        mm   = int(tz_offset[3:5])
        h    = hour if hour is not None else self._r.randint(8, 18)
        base = datetime(2026, self._r.randint(1, 3), self._r.randint(1, 28),
                        h, self._r.randint(0, 59), self._r.randint(0, 59),
                        tzinfo=timezone.utc)
        return base.strftime(f"%a, %d %b %Y %H:%M:%S {sign}{hh:02d}{mm:02d}")

    def offset_date(self, date_str: str, minutes: int) -> str:
        from email.utils import parsedate_to_datetime
        try:
            dt = parsedate_to_datetime(date_str) + timedelta(minutes=minutes)
            return dt.strftime("%a, %d %b %Y %H:%M:%S %z")
        except Exception:
            return date_str

    def subject(self) -> str:
        s = self.pick(SUBJECTS)
        return s.replace("{n}", str(self.randint(10000, 99999)))

    def body(self) -> str:
        return self.pick(BODIES).replace("{t}", uuid.uuid4().hex[:16])

    def msgid(self, domain: str = "smtp.example.com") -> str:
        return f"<{uuid.uuid4().hex}@{domain}>"

    def sample_id(self, prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex[:8]}"

    def mx(self) -> Dict:
        return self.pick(VICTIM_MX)


def received_header(from_host: str, from_ip: str, by_host: str, ts: str) -> str:
    return (f"from {from_host} ([{from_ip}])\r\n"
            f"        by {by_host} with ESMTPS;\r\n"
            f"        {ts}")


def assemble_email(headers: Dict[str, Any], body: str) -> str:
    lines = []
    for k, v in headers.items():
        if isinstance(v, list):
            for item in v:
                lines.append(f"{k}: {item}")
        else:
            lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(body)
    return "\r\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  SCENARIO GENERATORS
# ─────────────────────────────────────────────────────────────────────────────

class AdversarialGenerator:

    def __init__(self, rng: RNG):
        self.rng = rng

    def _pick_actor(self) -> Tuple[str, ActorProfile]:
        name = self.rng.pick(list(ACTORS.keys()))
        return name, ACTORS[name]

    # ── ADV-1: Multi-hop VPN chain ─────────────────────────────────────────
    def multihop_vpn(self) -> Dict:
        """
        Two or three chained commercial VPN hops.
        Signal destruction:
          geolocation_country → zeroed (vpn_detected reliability mode)
          isp_country         → 0.10× (near-useless VPN provider ISP)
          vpn_exit_country    → zeroed (attacker chose it deliberately)
        Surviving signals: timezone_offset (1.2× boost), charset_region (1.2×)
        Expected engine behaviour: correct if TZ+charset uniquely identify country;
          ambiguous for countries sharing TZ with a higher-prior country.
        """
        rng   = self.rng
        country, actor = self._pick_actor()
        mx    = rng.mx()

        # Pick 2 distinct VPN hops
        vpn_hops = rng.sample(VPN_CHAIN_PROVIDERS, 2)
        hop1_prov, hop1_pfx, hop1_cc, hop1_asn = vpn_hops[0]
        hop2_prov, hop2_pfx, hop2_cc, hop2_asn = vpn_hops[1]
        hop1_ip = rng.ip(hop1_pfx)
        hop2_ip = rng.ip(hop2_pfx)
        hop1_host = f"{hop1_prov.lower()}-{hop1_cc.lower()}-exit-{rng.randint(1,200)}.vpn.net"
        hop2_host = f"{hop2_prov.lower()}-{hop2_cc.lower()}-exit-{rng.randint(1,200)}.vpn.net"

        date   = rng.date(actor.timezone_offset)
        ts_h2  = rng.offset_date(date, -3)
        ts_mx  = rng.offset_date(date,  0)

        # Real actor IP never appears in headers
        real_ip = rng.ip(rng.pick(actor.isp_ranges))

        hdrs = {
            "From":         f'"Sender" <{rng.pick(["noreply","security","admin"])}@{rng.pick(actor.webmail_hints)}>',
            "To":           "victim@targetcorp.com",
            "Subject":      rng.subject(),
            "Date":         date,
            "Message-ID":   rng.msgid(hop2_host),
            "MIME-Version": "1.0",
            "Content-Type": f"text/plain; charset={actor.charset or 'utf-8'}",
            "Received": [
                received_header(mx["host"], mx["ip"], "internal.targetcorp.com", ts_mx),
                received_header(hop2_host, hop2_ip, mx["host"], ts_h2),
                received_header(hop1_host, hop1_ip, hop2_host,
                                rng.offset_date(date, -8)),
            ],
        }

        planted = [
            f"timezone_offset:{actor.timezone_offset}",
            f"timezone_region:{actor.timezone_region}",
        ]
        if actor.charset:
            planted.append(f"charset_region:{actor.charset}")
        # VPN exit country explicitly NOT planted — engine should not trust it

        return {
            "email_id":  rng.sample_id("adv_multihop_vpn"),
            "raw_email": assemble_email(hdrs, rng.body()),
            "labels": {
                "true_origin_country":  country,
                "obfuscation_type":     "multihop_vpn",
                "infrastructure":       f"vpn_chain_{hop1_prov}_{hop2_prov}",
                "confidence":           "high",
                "expected_tier_floor":  1,
                "planted_signals":      planted,
                "true_origin_ip":       real_ip,
                "vpn_chain":            [
                    {"provider": hop1_prov, "exit_ip": hop1_ip, "country": hop1_cc},
                    {"provider": hop2_prov, "exit_ip": hop2_ip, "country": hop2_cc},
                ],
                "signals_destroyed":    ["geolocation_country", "isp_country",
                                         "vpn_exit_country"],
                "signals_surviving":    ["timezone_offset", "timezone_region",
                                         "charset_region"],
                "aci_expected":         round(1.0 - 0.18 - 0.08, 3),
                "adversarial_goal":     "strip IP signals, force engine onto weak TZ-only attribution",
                "scenario":             "multihop_vpn",
            },
        }

    # ── ADV-2: Residential proxy ────────────────────────────────────────────
    def residential_proxy(self) -> Dict:
        """
        Actor exits through a residential proxy (Bright Data / Luminati / Oxylabs).
        The exit IP geolocates to a US or EU residential broadband subscriber.
        geolocation_country → False country (RESIP pool location)
        isp_country         → False country (RESIP pool ASN)
        No ACI obfuscation penalty is applied to geolocation_country reliability
        in residential_proxy mode (engine treats it as clean).
        This is the engine's hardest blind spot after compromised relay.
        """
        rng    = self.rng
        country, actor = self._pick_actor()
        mx     = rng.mx()

        pool_template, pool_org, pool_asn, pool_geo = rng.pick(RESIP_POOLS)
        # Fill in random octets
        a, b  = rng.randint(1, 254), rng.randint(1, 254)
        exit_ip   = pool_template.format(a=a, b=b)
        exit_host = f"host-{exit_ip.replace('.', '-')}.{pool_org.lower().replace(' ','-').replace('(','-').replace(')','-')}.net"

        date  = rng.date(actor.timezone_offset)
        ts_px = rng.offset_date(date, -4)

        hdrs = {
            "From":         f'"Sender" <{rng.pick(["noreply","support","alerts"])}@{rng.pick(actor.webmail_hints)}>',
            "To":           "victim@targetcorp.com",
            "Subject":      rng.subject(),
            "Date":         date,
            "Message-ID":   rng.msgid("smtp.mail.com"),
            "MIME-Version": "1.0",
            "Content-Type": f"text/plain; charset={actor.charset or 'utf-8'}",
            "Received": [
                received_header(mx["host"], mx["ip"],
                                "internal.targetcorp.com",
                                rng.offset_date(date, 0)),
                received_header(exit_host, exit_ip, mx["host"], ts_px),
            ],
        }

        # The engine will see geolocation_country=pool_geo (FALSE)
        # and timezone_offset=actor TZ (TRUE)
        # RESIP mode = no_obfuscation reliability → geo accepted at full LR
        planted = [
            f"geolocation_country:{pool_geo}",   # FALSE — RESIP pool location
            f"isp_country:{pool_geo}",            # FALSE — RESIP pool ASN country
            f"timezone_offset:{actor.timezone_offset}",  # TRUE
            f"timezone_region:{actor.timezone_region}",  # TRUE
        ]
        if actor.charset:
            planted.append(f"charset_region:{actor.charset}")

        return {
            "email_id":  rng.sample_id("adv_resip"),
            "raw_email": assemble_email(hdrs, rng.body()),
            "labels": {
                "true_origin_country":  country,
                "obfuscation_type":     "residential_proxy",
                "infrastructure":       f"resip_{pool_org.lower().split()[0]}",
                "confidence":           "low",
                "expected_tier_floor":  0,
                "planted_signals":      planted,
                "true_origin_ip":       "unknown (RESIP pool)",
                "false_geo_country":    pool_geo,
                "resip_pool":           pool_org,
                "resip_asn":            pool_asn,
                "signals_falsified":    ["geolocation_country", "isp_country"],
                "signals_true":         ["timezone_offset", "timezone_region"],
                "aci_expected":         round(1.0 - 0.25, 3),
                "adversarial_goal":     "make geo signal point to false country; engine accepts at full LR",
                "engine_blind_spot":    True,
                "blind_spot_detail":    (
                    "RESIP geo is treated identically to clean ISP geo in "
                    "no_obfuscation reliability mode.  Engine has no RESIP-aware "
                    "downweight for geolocation_country.  Expected: engine "
                    "confidently attributes to RESIP pool country."
                ),
                "scenario":             "residential_proxy",
            },
        }

    # ── ADV-3: Compromised legitimate relay ─────────────────────────────────
    def compromised_relay(self) -> Dict:
        """
        Actor routes email through a legitimately breached corporate SMTP server.
        ALL IP signals (geolocation_country, isp_country) point to the victim
        organisation's country, not the actor.
        No ACI obfuscation penalty — engine cannot detect compromised relays.
        This is the deepest engine blind spot: ACI=1.0, false attribution
        with high confidence.
        """
        rng    = self.rng
        country, actor = self._pick_actor()
        mx     = rng.mx()

        relay  = rng.pick(COMPROMISED_RELAYS)
        date   = rng.date(actor.timezone_offset)
        ts_r   = rng.offset_date(date, -10)

        # Note: From header uses actor's webmail — slight timezone leakage
        # Date header uses ACTOR timezone (actor controls it)
        # But Received timestamps use relay's actual timestamps

        hdrs = {
            "From":         f'"Sender" <{rng.pick(["noreply","finance","hr"])}@{rng.pick(actor.webmail_hints)}>',
            "To":           "victim@targetcorp.com",
            "Subject":      rng.subject(),
            "Date":         date,
            "Message-ID":   rng.msgid(relay["host"]),
            "MIME-Version": "1.0",
            # Relay re-encodes to its own charset (another false signal)
            "Content-Type": f"text/plain; charset={relay['charset']}",
            "Received": [
                received_header(mx["host"], mx["ip"],
                                "internal.targetcorp.com",
                                rng.offset_date(date, 0)),
                received_header(relay["host"], relay["ip"],
                                mx["host"], ts_r),
            ],
            # DKIM from relay's domain — further implicates relay country
            "DKIM-Signature": f"v=1; a=rsa-sha256; d={relay['host'].split('.',1)[1]}; s=mail",
        }

        # Engine sees: relay's geo, relay's ISP, relay's charset
        # Actor's TZ leaks via Date header — that's the only true signal
        planted = [
            f"geolocation_country:{relay['geo_country']}",  # FALSE
            f"isp_country:{relay['isp_country']}",          # FALSE
            f"charset_region:{relay['charset']}",           # FALSE (relay's charset)
            f"timezone_offset:{actor.timezone_offset}",     # TRUE (actor's Date header)
            f"dns_infra_country:{relay['isp_country']}",    # FALSE (relay domain)
        ]

        return {
            "email_id":  rng.sample_id("adv_compr_relay"),
            "raw_email": assemble_email(hdrs, rng.body()),
            "labels": {
                "true_origin_country":  country,
                "obfuscation_type":     "compromised_relay",
                "infrastructure":       f"breached_smtp_{relay['isp_country'].lower().replace(' ','_')}",
                "confidence":           "low",
                "expected_tier_floor":  0,
                "planted_signals":      planted,
                "relay_host":           relay["host"],
                "relay_country":        relay["geo_country"],
                "relay_org":            relay["org"],
                "true_origin_ip":       "unknown (actor used relay)",
                "signals_falsified":    ["geolocation_country", "isp_country",
                                         "charset_region", "dns_infra_country"],
                "signals_true":         ["timezone_offset"],
                "aci_expected":         1.0,
                "adversarial_goal":     "all IP signals point to breached relay country; ACI=1.0",
                "engine_blind_spot":    True,
                "blind_spot_detail":    (
                    "Engine has no compromised-relay detection.  "
                    "ACI=1.0 because no obfuscation flags fire.  "
                    "Result: high-confidence wrong attribution to relay country."
                ),
                "scenario":             "compromised_relay",
            },
        }

    # ── ADV-4: False flag infrastructure ────────────────────────────────────
    def false_flag_infra(self) -> Dict:
        """
        Actor deliberately plants signals from three distinct countries to
        confuse attribution.  Typical pattern:
          - Route through Russian VPN exit → geolocation_country=Russia
          - Send via Chinese ISP relay → isp_country=China
          - Date header uses US Eastern timezone → timezone_offset=-0500
        FalseFlagDetector should fire; confidence capped at 0.45.
        True origin hidden by this noise.
        """
        rng    = self.rng
        country, actor = self._pick_actor()

        # Pick 3 decoy countries, none of which is the true actor country
        all_decoys = ["Russia", "China", "United States", "Germany",
                      "United Kingdom", "Netherlands", "Sweden", "France"]
        # Ensure decoys are distinct from true country
        decoys = [d for d in all_decoys if d != country]
        d1, d2, d3 = rng.sample(decoys, 3)

        # decoy timezone offsets by country
        DECOY_TZ = {
            "Russia": "+0300", "China": "+0800", "United States": "-0500",
            "Germany": "+0100", "United Kingdom": "+0000", "Netherlands": "+0100",
            "Sweden": "+0100", "France": "+0100",
        }
        decoy_tz = DECOY_TZ.get(d3, "+0000")
        mx = rng.mx()
        date = rng.date(decoy_tz)  # Date header uses decoy TZ

        vpn_hop = rng.pick(VPN_CHAIN_PROVIDERS)
        vpn_ip  = rng.ip(vpn_hop[1])
        vpn_host = f"vpn-{rng.randint(1,200)}.exit.net"

        hdrs = {
            "From":         f'"Security Alert" <noreply@{rng.pick(["gmail.com","yahoo.com","outlook.com"])}>',
            "To":           "victim@targetcorp.com",
            "Subject":      rng.subject(),
            "Date":         date,
            "Message-ID":   rng.msgid(vpn_host),
            "MIME-Version": "1.0",
            "Content-Type": "text/plain; charset=utf-8",
            "Received": [
                received_header(mx["host"], mx["ip"],
                                "internal.targetcorp.com",
                                rng.offset_date(date, 0)),
                received_header(vpn_host, vpn_ip, mx["host"],
                                rng.offset_date(date, -5)),
            ],
        }

        # Engine sees signals pointing at 3+ countries → FalseFlagDetector fires
        planted = [
            f"geolocation_country:{d1}",       # VPN exit geo → decoy 1
            f"isp_country:{d2}",               # False ISP → decoy 2
            f"timezone_offset:{decoy_tz}",     # Spoofed timezone → decoy 3 country
            f"vpn_provider:{vpn_hop[0]}",      # metadata
        ]

        return {
            "email_id":  rng.sample_id("adv_false_flag"),
            "raw_email": assemble_email(hdrs, rng.body()),
            "labels": {
                "true_origin_country":  country,
                "obfuscation_type":     "false_flag_infra",
                "infrastructure":       "deliberate_false_flag",
                "confidence":           "low",
                "expected_tier_floor":  0,
                "planted_signals":      planted,
                "decoy_countries":      [d1, d2, d3],
                "true_origin_ip":       "unknown (multi-layer obfuscation)",
                "false_flag_expected":  True,
                "signals_falsified":    ["geolocation_country", "isp_country",
                                         "timezone_offset"],
                "aci_expected":         round(1.0 - 0.18, 3),
                "adversarial_goal":     (
                    f"plant signals for {d1}, {d2}, {d3} simultaneously; "
                    "FalseFlagDetector fires; confidence capped at 0.45"
                ),
                "scenario":             "false_flag_infra",
            },
        }

    # ── ADV-5: Charset normalization ────────────────────────────────────────
    def charset_normalization(self) -> Dict:
        """
        Actor with a regionally distinctive charset (windows-1251 for Russia,
        gbk for China, etc.) explicitly normalises to UTF-8 to suppress the
        charset_region signal — the most VPN-resistant passive signal.
        Tests: does the engine retain correct attribution on TZ+webmail alone?
        """
        rng    = self.rng
        country, actor = self._pick_actor()

        # Only meaningful for actors with non-null charset
        # If the actor doesn't have a distinctive charset, use Russia (windows-1251)
        if actor.charset is None:
            country, actor = "Russia", ACTORS["Russia"]

        mx   = rng.mx()
        date = rng.date(actor.timezone_offset)

        vpn_hop  = rng.pick(VPN_CHAIN_PROVIDERS)
        vpn_ip   = rng.ip(vpn_hop[1])
        vpn_host = f"exit-{rng.randint(1,200)}.{vpn_hop[0].lower()}.net"

        hdrs = {
            "From":         f'"Sender" <{rng.pick(["noreply","support"])}@{rng.pick(actor.webmail_hints)}>',
            "To":           "victim@targetcorp.com",
            "Subject":      rng.subject(),
            "Date":         date,
            "Message-ID":   rng.msgid(vpn_host),
            "MIME-Version": "1.0",
            "Content-Type": "text/plain; charset=utf-8",    # NORMALISED — charset stripped
            "Received": [
                received_header(mx["host"], mx["ip"],
                                "internal.targetcorp.com",
                                rng.offset_date(date, 0)),
                received_header(vpn_host, vpn_ip, mx["host"],
                                rng.offset_date(date, -5)),
            ],
        }

        # Charset signal suppressed; only TZ + webmail survive
        planted = [
            f"timezone_offset:{actor.timezone_offset}",
            f"timezone_region:{actor.timezone_region}",
            f"webmail_provider:{rng.pick(actor.webmail_hints)}",
            # Explicitly NO charset_region signal
        ]

        return {
            "email_id":  rng.sample_id("adv_charset_norm"),
            "raw_email": assemble_email(hdrs, rng.body()),
            "labels": {
                "true_origin_country":  country,
                "obfuscation_type":     "charset_normalization",
                "infrastructure":       f"vpn_{vpn_hop[0].lower()}_charset_stripped",
                "confidence":           "medium",
                "expected_tier_floor":  1,
                "planted_signals":      planted,
                "suppressed_signal":    f"charset_region:{actor.charset}",
                "signals_surviving":    ["timezone_offset", "timezone_region",
                                         "webmail_provider"],
                "aci_expected":         round(1.0 - 0.18 - 0.08, 3),
                "adversarial_goal":     (
                    f"suppress charset_region:{actor.charset} (LR=2.5) "
                    "by forcing UTF-8; retain TZ+webmail signals only"
                ),
                "scenario":             "charset_normalization",
            },
        }

    # ── ADV-6: IPv6 leak ───────────────────────────────────────────────────
    def ipv6_leak(self) -> Dict:
        """
        Actor uses a commercial VPN (IPv4 only) but their device has a
        routable IPv6 address that is NOT tunnelled through the VPN.
        The IPv6 address geolocates to the actor's true country.
        Signal: ipv6_country (LR=15, boosted to 22.5 under vpn_detected)
        Tests: does the engine use the VPN-resistant IPv6 signal correctly?
        """
        rng    = self.rng
        country, actor = self._pick_actor()
        mx     = rng.mx()

        # Realistic IPv6 prefixes by region (RIPE/AFRINIC/APNIC allocations)
        IPV6_PREFIXES = {
            "Nigeria":  ["2c0f:f618:", "2c0f:f248:", "2c0f:ee48:"],  # AfriNIC
            "Russia":   ["2a00:1fa0:", "2a04:4e42:", "2a02:6b8:"],   # RIPE NCC
            "China":    ["240e::", "2408::", "2409:"],                # APNIC
            "India":    ["2401:4900:", "2401::", "2402:3a80:"],       # APNIC
            "Romania":  ["2a02:2f0:", "2a04:5040:", "2a06:c400:"],   # RIPE NCC
            "Vietnam":  ["2405:4800:", "2001:ee0:", "2405:4801:"],    # APNIC
            "Brazil":   ["2804:14c:", "2804:431:", "2804:14d:"],      # LACNIC
            "Iran":     ["2a0d:5600:", "2001:df4:", "2402:a000:"],    # RIPE NCC
        }
        v6_prefixes = IPV6_PREFIXES.get(country, ["2c0f:f618:"])
        v6_prefix   = rng.pick(v6_prefixes)
        v6_addr     = v6_prefix + f"{rng.randint(0,0xffff):04x}:{rng.randint(0,0xffff):04x}"

        vpn_hop  = rng.pick(VPN_CHAIN_PROVIDERS)
        vpn_ip   = rng.ip(vpn_hop[1])
        vpn_host = f"exit-{rng.randint(1,200)}.{vpn_hop[0].lower()}.com"

        date = rng.date(actor.timezone_offset)
        mx   = rng.mx()

        hdrs = {
            "From":         f'"Sender" <{rng.pick(["noreply","admin"])}@{rng.pick(actor.webmail_hints)}>',
            "To":           "victim@targetcorp.com",
            "Subject":      rng.subject(),
            "Date":         date,
            "Message-ID":   rng.msgid(vpn_host),
            "MIME-Version": "1.0",
            "Content-Type": f"text/plain; charset={actor.charset or 'utf-8'}",
            "Received": [
                received_header(mx["host"], mx["ip"],
                                "internal.targetcorp.com",
                                rng.offset_date(date, 0)),
                # IPv4 hop through VPN — hides actor ISP
                received_header(vpn_host, vpn_ip,
                                mx["host"], rng.offset_date(date, -5)),
            ],
            # IPv6 source leaked in X-Originating-IP6 / Received IPv6
            "X-Originating-IP": v6_addr,
        }

        if actor.charset:
            planted_charset = [f"charset_region:{actor.charset}"]
        else:
            planted_charset = []

        planted = [
            f"timezone_offset:{actor.timezone_offset}",
            f"ipv6_country:{country}",     # TRUE — IPv6 leaked through VPN
            # geolocation_country not planted (VPN zeroes it)
        ] + planted_charset

        return {
            "email_id":  rng.sample_id("adv_ipv6_leak"),
            "raw_email": assemble_email(hdrs, rng.body()),
            "labels": {
                "true_origin_country":  country,
                "obfuscation_type":     "ipv6_leak",
                "infrastructure":       f"vpn_{vpn_hop[0].lower()}_ipv6_leak",
                "confidence":           "high",
                "expected_tier_floor":  2,
                "planted_signals":      planted,
                "leaked_ipv6":          v6_addr,
                "vpn_provider":         vpn_hop[0],
                "vpn_exit_ip":          vpn_ip,
                "signal_boost":         "ipv6_country LR=15.0 → 22.5 under vpn_detected mode",
                "aci_expected":         round(1.0 - 0.18 - 0.08, 3),
                "adversarial_goal":     (
                    "actor attempts full VPN anonymity but leaks IPv6; "
                    "ipv6_country (LR×1.5 boost) should dominate"
                ),
                "scenario":             "ipv6_leak",
            },
        }

    # ── ADV-7: DNS false flag ───────────────────────────────────────────────
    def dns_false_flag(self) -> Dict:
        """
        Actor registers their sending domain through a US/EU registrar (Namecheap,
        GoDaddy, Cloudflare) to make dns_infra_country point to the US.
        NS/MX/SPF records all resolve to US infrastructure.
        True origin still leaks via geolocation_country (X-Originating-IP)
        and timezone_offset.
        Tests: does geo_country + TZ overcome the DNS false flag?
        """
        rng    = self.rng
        country, actor = self._pick_actor()
        mx     = rng.mx()

        registrar, reg_country, reg_asn = rng.pick(DNS_DECOY_REGISTRARS)
        real_ip = rng.ip(rng.pick(actor.isp_ranges))
        date    = rng.date(actor.timezone_offset)

        hdrs = {
            "From":         f'"Security Team" <noreply@secure-alerts-{rng.randint(100,999)}.com>',
            "To":           "victim@targetcorp.com",
            "Subject":      rng.subject(),
            "Date":         date,
            "Message-ID":   rng.msgid(f"smtp.secure-alerts.{reg_country.lower().replace(' ','-')}.com"),
            "MIME-Version": "1.0",
            "Content-Type": f"text/plain; charset={actor.charset or 'utf-8'}",
            # DKIM from registrar's nameserver country
            "DKIM-Signature": f"v=1; a=rsa-sha256; d=secure-alerts.com; s=mail",
            "Received": [
                received_header(mx["host"], mx["ip"],
                                "internal.targetcorp.com",
                                rng.offset_date(date, 0)),
                received_header(f"smtp.isp.{country.lower()}.net", real_ip,
                                mx["host"], rng.offset_date(date, -8)),
            ],
            "X-Originating-IP": real_ip,
        }

        planted = [
            f"geolocation_country:{country}",           # TRUE (real IP visible)
            f"isp_country:{actor.isp_country}",         # TRUE
            f"dns_infra_country:{reg_country}",         # FALSE (registrar country)
            f"timezone_offset:{actor.timezone_offset}",  # TRUE
        ]
        if actor.charset:
            planted.append(f"charset_region:{actor.charset}")

        return {
            "email_id":  rng.sample_id("adv_dns_ff"),
            "raw_email": assemble_email(hdrs, rng.body()),
            "labels": {
                "true_origin_country":  country,
                "obfuscation_type":     "dns_false_flag",
                "infrastructure":       f"dns_via_{registrar.lower().replace(' ','_')}",
                "confidence":           "medium",
                "expected_tier_floor":  2,
                "planted_signals":      planted,
                "true_origin_ip":       real_ip,
                "registrar":            registrar,
                "dns_false_country":    reg_country,
                "signals_falsified":    ["dns_infra_country"],
                "signals_true":         ["geolocation_country", "isp_country",
                                         "timezone_offset"],
                "aci_expected":         1.0,
                "adversarial_goal":     (
                    f"DNS infrastructure signals point to {reg_country} via {registrar}; "
                    "geo+ISP+TZ should override the DNS false flag"
                ),
                "scenario":             "dns_false_flag",
            },
        }

    # ── ADV-8: Send-hour manipulation ───────────────────────────────────────
    def send_hour_manipulation(self) -> Dict:
        """
        Actor schedules email sends during victim-country business hours to
        appear as a local sender.  If victim is US-based, actor sends at
        09:00–17:00 US Eastern (14:00–22:00 UTC).
        Tests: does send_hour_local mislead timezone inference?
        (Engine answer: send_hour alone returns [] from _get_matching_regions —
        it only provides a boost when combined with timezone_offset.  So this
        attack has minimal effect on the Bayesian posterior.)
        """
        rng    = self.rng
        country, actor = self._pick_actor()
        mx     = rng.mx()

        # Actor sends during US Eastern business hours (09:00–17:00 EST = 14:00–22:00 UTC)
        # But Date: header still uses actor's real timezone
        # The manipulation: send_hour_local = 14 (actor time) looks like 09:00 EST
        victim_biz_start_utc = 14   # 09:00 EST
        victim_biz_end_utc   = 22   # 17:00 EST
        manipulation_hour = rng.randint(victim_biz_start_utc, victim_biz_end_utc)

        date = rng.date(actor.timezone_offset, hour=manipulation_hour)

        real_ip = rng.ip(rng.pick(actor.isp_ranges))

        hdrs = {
            "From":         f'"Support Team" <support@{rng.pick(actor.webmail_hints)}>',
            "To":           "victim@targetcorp.com",
            "Subject":      rng.subject(),
            "Date":         date,
            "Message-ID":   rng.msgid("smtp.example.com"),
            "MIME-Version": "1.0",
            "Content-Type": f"text/plain; charset={actor.charset or 'utf-8'}",
            "Received": [
                received_header(mx["host"], mx["ip"],
                                "internal.targetcorp.com",
                                rng.offset_date(date, 0)),
                received_header(f"smtp.isp-{country.lower().replace(' ','-')}.net",
                                real_ip, mx["host"],
                                rng.offset_date(date, -7)),
            ],
            "X-Originating-IP": real_ip,
        }

        planted = [
            f"geolocation_country:{country}",
            f"isp_country:{actor.isp_country}",
            f"timezone_offset:{actor.timezone_offset}",
            f"send_hour_local:{manipulation_hour}",
        ]
        if actor.charset:
            planted.append(f"charset_region:{actor.charset}")

        return {
            "email_id":  rng.sample_id("adv_sendhour"),
            "raw_email": assemble_email(hdrs, rng.body()),
            "labels": {
                "true_origin_country":    country,
                "obfuscation_type":       "send_hour_manipulation",
                "infrastructure":         "direct_smtp_hour_manipulation",
                "confidence":             "high",
                "expected_tier_floor":    2,
                "planted_signals":        planted,
                "true_origin_ip":         real_ip,
                "manipulated_send_hour":  manipulation_hour,
                "intended_impression":    "US Eastern business hours sender",
                "engine_effect":          (
                    "send_hour_local alone returns [] from _get_matching_regions "
                    "and contributes no geographic boost without timezone_offset. "
                    "True TZ+geo signals dominate.  Attack has minimal effect."
                ),
                "aci_expected":           1.0,
                "adversarial_goal":       (
                    f"send at hour {manipulation_hour} UTC (US biz hours) "
                    "to appear as local sender; real TZ+geo should override"
                ),
                "scenario":               "send_hour_manipulation",
            },
        }


# ─────────────────────────────────────────────────────────────────────────────
#  ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

SCENARIO_REGISTRY: Dict[str, Tuple[str, int]] = {
    # name → (method_name, weight)
    "multihop_vpn":          ("multihop_vpn",          12),
    "residential_proxy":     ("residential_proxy",     12),
    "compromised_relay":     ("compromised_relay",     12),
    "false_flag_infra":      ("false_flag_infra",      12),
    "charset_normalization": ("charset_normalization", 12),
    "ipv6_leak":             ("ipv6_leak",             12),
    "dns_false_flag":        ("dns_false_flag",        14),
    "send_hour_manipulation":("send_hour_manipulation",14),
}

# New obfuscation types that eval_harness.py needs to handle
ADV_OBFUSCATION_FLAGS: Dict[str, Dict[str, bool]] = {
    "multihop_vpn":          {"tor": False, "vpn": True,  "residential_proxy": False,
                              "datacenter": True,  "timestamp_spoof": False},
    "residential_proxy":     {"tor": False, "vpn": False, "residential_proxy": True,
                              "datacenter": False, "timestamp_spoof": False},
    "compromised_relay":     {"tor": False, "vpn": False, "residential_proxy": False,
                              "datacenter": False, "timestamp_spoof": False},
    "false_flag_infra":      {"tor": False, "vpn": True,  "residential_proxy": False,
                              "datacenter": False, "timestamp_spoof": False},
    "charset_normalization": {"tor": False, "vpn": True,  "residential_proxy": False,
                              "datacenter": True,  "timestamp_spoof": False},
    "ipv6_leak":             {"tor": False, "vpn": True,  "residential_proxy": False,
                              "datacenter": True,  "timestamp_spoof": False},
    "dns_false_flag":        {"tor": False, "vpn": False, "residential_proxy": False,
                              "datacenter": False, "timestamp_spoof": False},
    "send_hour_manipulation":{"tor": False, "vpn": False, "residential_proxy": False,
                              "datacenter": False, "timestamp_spoof": False},
}


def generate_adversarial_dataset(
    count:          int = DEFAULT_COUNT,
    seed:           int = DEFAULT_SEED,
    scenario_filter: Optional[str] = None,
) -> List[Dict]:
    rng = RNG(seed)
    gen = AdversarialGenerator(rng)

    if scenario_filter:
        if scenario_filter not in SCENARIO_REGISTRY:
            raise ValueError(
                f"Unknown scenario '{scenario_filter}'. "
                f"Valid: {sorted(SCENARIO_REGISTRY)}"
            )
        method = getattr(gen, SCENARIO_REGISTRY[scenario_filter][0])
        return [method() for _ in range(count)]

    names   = list(SCENARIO_REGISTRY.keys())
    weights = [SCENARIO_REGISTRY[n][1] for n in names]
    total_w = sum(weights)
    cum_w   = [sum(weights[:i+1]) / total_w for i in range(len(weights))]

    samples = []
    for _ in range(count):
        r    = rng.random()
        name = next(n for n, cw in zip(names, cum_w) if r <= cw)
        method = getattr(gen, SCENARIO_REGISTRY[name][0])
        samples.append(method())

    return samples


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HunterTrace adversarial dataset generator"
    )
    parser.add_argument("--count",    type=int, default=DEFAULT_COUNT,
                        help=f"Samples to generate (default: {DEFAULT_COUNT})")
    parser.add_argument("--out",      default="adv_dataset.json",
                        help="Output JSON file (default: adv_dataset.json)")
    parser.add_argument("--seed",     type=int, default=DEFAULT_SEED,
                        help=f"RNG seed (default: {DEFAULT_SEED})")
    parser.add_argument("--scenario", default=None,
                        choices=sorted(SCENARIO_REGISTRY),
                        help="Generate only one scenario type")
    parser.add_argument("--summary",  action="store_true",
                        help="Print distribution summary after generation")
    args = parser.parse_args()

    print(f"[adv-gen] Generating {args.count} adversarial samples "
          f"(seed={args.seed}, scenario={args.scenario or 'all'}) ...")

    samples = generate_adversarial_dataset(
        count           = args.count,
        seed            = args.seed,
        scenario_filter = args.scenario,
    )

    with open(args.out, "w") as f:
        json.dump(samples, f, indent=2)

    print(f"[adv-gen] Written {len(samples)} samples → {args.out}")

    if args.summary:
        scen_counts    = Counter(s["labels"]["scenario"]            for s in samples)
        country_counts = Counter(s["labels"]["true_origin_country"] for s in samples)
        blind_spots    = sum(1 for s in samples if s["labels"].get("engine_blind_spot"))

        print(f"\n  Scenario distribution:")
        for k, v in sorted(scen_counts.items(), key=lambda x: -x[1]):
            pct = v / len(samples) * 100
            print(f"    {k:<28} {v:>5}  ({pct:.1f}%)")

        print(f"\n  Country distribution (top 8):")
        for k, v in country_counts.most_common(8):
            pct = v / len(samples) * 100
            print(f"    {k:<24} {v:>5}  ({pct:.1f}%)")

        print(f"\n  Engine blind-spot samples: {blind_spots} / {len(samples)} "
              f"({blind_spots/len(samples)*100:.1f}%)")
        print(f"  (scenarios where ACI=1.0 but signals are fabricated)")

        print(f"\n  Expected accuracy by scenario:")
        expected = {
            "multihop_vpn":          "~82%  (TZ+charset survive VPN)",
            "residential_proxy":     "~25%  (geo points to RESIP pool country)",
            "compromised_relay":     "~10%  (all signals point to relay country)",
            "false_flag_infra":      "~30%  (FalseFlagDetector fires; cap 0.45)",
            "charset_normalization": "~80%  (TZ+webmail survive charset strip)",
            "ipv6_leak":             "~95%  (IPv6 LR=22.5 dominates)",
            "dns_false_flag":        "~70%  (geo+ISP+TZ override DNS false flag)",
            "send_hour_manipulation":"~80%  (send_hour alone has zero geo power)",
        }
        for scen in sorted(SCENARIO_REGISTRY):
            print(f"    {scen:<28}  {expected.get(scen, '?')}")

        print()
        print("  To run against eval_harness.py:")
        print(f"    python eval_harness.py --dataset {args.out} --out adv_eval_results.json")
        print(f"    python baseline_report.py --results adv_eval_results.json")


if __name__ == "__main__":
    main()
