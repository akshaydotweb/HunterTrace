#!/usr/bin/env python3
"""
huntertrace/forensics/attackerTechniqueProfiler.py
====================================================
Phase 0 — Attacker Technique Profiler
--------------------------------------

Runs BEFORE any IP backtracking. Answers the question:
  "What techniques did this attacker use to send the phishing email?"

This module analyses a raw RFC 2822 email and returns a structured
AttackerTechniqueProfile cataloguing every detected technique, the
confidence of each detection, and the MITRE ATT&CK technique ID.

The profile feeds three downstream consumers:
  1. CompletePipeline  — printed as Stage 0 before backtracking begins
  2. Bayesian engine   — forgery_score adjusts T1/T3 signal weights
  3. ActorProfiler     — TTP fingerprint for campaign clustering

INTEGRATION (drop into pipeline.py):
--------------------------------------
    # After Stage 1 header extraction, before Stage 2 IP classification:

    from huntertrace.forensics.attackerTechniqueProfiler import (
        AttackerTechniqueProfiler,
        AttackerTechniqueProfile,
    )
    ...
    # In CompletePipelineResult, add field:
    #   attacker_technique_profile: Optional[AttackerTechniqueProfile] = None

    # In CompletePipeline.__init__:
    #   self.technique_profiler = AttackerTechniqueProfiler()

    # In CompletePipeline.run(), after Stage 1:
    print("\\n[PHASE 0] Profiling attacker techniques...")
    with open(email_file, 'r', encoding='utf-8', errors='replace') as fh:
        raw_email = fh.read()
    technique_profile = self.technique_profiler.profile(
        raw_email,
        header_analysis=header_analysis,
    )
    technique_profile.print_summary()
    result.attacker_technique_profile = technique_profile

DESIGN PRINCIPLES:
------------------
  - Zero mandatory dependencies beyond stdlib + scanner.py
  - Every detection includes: name, category, confidence, MITRE ID,
    evidence list, honest_limit, and recommended_next_step
  - Confidence values are honest ceilings — not inflated
  - The forgery_score from HopTimestampForgeryDetector is exposed as
    header_integrity_score (1.0 = clean, 0.0 = forged) so the
    backtracking engine can discount Received: signals accordingly
"""

from __future__ import annotations

import re
import email as _email_lib
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from huntertrace.analysis.correlation import validate_received_chain_semantics

# ── Internal import — scanner.py is the source of truth for all 8 detectors ──
try:
    from huntertrace.forensics.scanner import (
        run_forensic_scan,
        ForensicScanSummary,
        HopTimestampForgeryDetector,
        BotSendPatternScorer,
        AIContentDetector,
        TrackingPixelDetector,
        HTMLSmugglingDetector,
        HomoglyphDomainDetector,
        ZeroPointFontDetector,
    )
    _SCANNER_AVAILABLE = True
except ImportError:
    _SCANNER_AVAILABLE = False
    ForensicScanSummary = None  # type: ignore

try:
    from huntertrace.extraction.webmail import (
        run_webmail_extraction,
        WebmailProvider,
        LeakBehaviour,
    )
    _WEBMAIL_AVAILABLE = True
except ImportError:
    _WEBMAIL_AVAILABLE = False
    WebmailProvider = None  # type: ignore


# ─────────────────────────────────────────────────────────────────────────────
#  DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DetectedTechnique:
    """
    A single attacker technique that was positively detected.

    Fields
    ------
    name            : Human-readable technique name
    category        : One of the 6 categories (see CATEGORY_* constants)
    confidence      : Float 0.0–1.0 — honest detection ceiling
    mitre_id        : MITRE ATT&CK technique ID (e.g. "T1036.007")
    evidence        : List of specific evidence strings extracted from the email
    honest_limit    : What can defeat or reduce confidence of this detection
    next_step       : Analyst recommended action based on this finding
    raw_score       : The underlying detector score before confidence mapping
    detector        : Which internal detector produced this finding
    """
    name:          str
    category:      str
    confidence:    float
    mitre_id:      str
    evidence:      List[str]
    honest_limit:  str
    next_step:     str
    raw_score:     float = 0.0
    detector:      str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name":         self.name,
            "category":     self.category,
            "confidence":   round(self.confidence, 3),
            "mitre_id":     self.mitre_id,
            "evidence":     self.evidence,
            "honest_limit": self.honest_limit,
            "next_step":    self.next_step,
            "raw_score":    round(self.raw_score, 3),
            "detector":     self.detector,
        }


@dataclass
class SendingMethod:
    """How the attacker sent the email."""
    method:          str           # e.g. "Gmail webmail", "GoPhish", "ProtonMail"
    provider:        Optional[str] # webmail provider name if known
    real_ip_leaked:  bool          # True when provider embeds client IP
    real_ip:         Optional[str] # The leaked IP if available
    confidence:      float
    evidence:        List[str]
    strips_ip:       bool = False  # ProtonMail / Tutanota pattern
    is_phishing_kit: bool = False  # GoPhish / SET detected
    is_bot_send:     bool = False  # automated bulk campaign
    bot_cv:          Optional[float] = None  # coefficient of variation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method":         self.method,
            "provider":       self.provider,
            "real_ip_leaked": self.real_ip_leaked,
            "real_ip":        self.real_ip,
            "confidence":     round(self.confidence, 3),
            "evidence":       self.evidence,
            "strips_ip":      self.strips_ip,
            "is_phishing_kit": self.is_phishing_kit,
            "is_bot_send":    self.is_bot_send,
            "bot_cv":         round(self.bot_cv, 3) if self.bot_cv is not None else None,
        }


@dataclass
class AttackerTechniqueProfile:
    """
    Complete attacker technique profile for one email.

    Produced by AttackerTechniqueProfiler.profile().
    Consumed by CompletePipeline (Phase 0 print) and ActorProfiler (TTP map).
    """
    # Core detections
    detected_techniques:    List[DetectedTechnique]

    # Sending method (the HOW they sent it)
    sending_method:         Optional[SendingMethod]

    # Header integrity — 1.0 = clean chain, 0.0 = forged
    # Backtracking engine uses this to discount Received: signals
    header_integrity_score: float           # = 1.0 - forgery_score

    # Aggregate risk
    composite_risk_score:   float           # 0.0–1.0
    risk_label:             str             # LOW | MEDIUM | HIGH | CRITICAL

    # MITRE ATT&CK IDs for all confirmed techniques
    all_mitre_ids:          List[str]

    # One-line flags for fast reading
    flags:                  List[str]

    # If ProtonMail/Tutanota detected — passive attribution blocked
    passive_attribution_blocked: bool
    canary_token_recommended:    bool

    # Raw scanner output — available for advanced consumers
    forensic_scan:          Optional[Any]   # ForensicScanSummary | None

    scanned_at:             str

    # Semantic validation of the Received: chain (optional)
    semantic_profile:        Optional[Dict[str, Any]] = None

    @property
    def technique_count(self) -> int:
        return len(self.detected_techniques)

    @property
    def high_confidence_techniques(self) -> List[DetectedTechnique]:
        return [t for t in self.detected_techniques if t.confidence >= 0.85]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanned_at":               self.scanned_at,
            "composite_risk_score":     round(self.composite_risk_score, 3),
            "risk_label":               self.risk_label,
            "header_integrity_score":   round(self.header_integrity_score, 3),
            "semantic_profile":         self.semantic_profile,
            "passive_attribution_blocked": self.passive_attribution_blocked,
            "canary_token_recommended": self.canary_token_recommended,
            "all_mitre_ids":            self.all_mitre_ids,
            "flags":                    self.flags,
            "technique_count":          self.technique_count,
            "sending_method":           self.sending_method.to_dict() if self.sending_method else None,
            "detected_techniques":      [t.to_dict() for t in self.detected_techniques],
        }

    def print_summary(self) -> None:
        """
        Print Phase 0 summary — same style as existing pipeline stage output.
        Called from CompletePipeline.run() immediately after profile() returns.
        """
        W = 80
        print()
        print("═" * W)
        print("[PHASE 0]  ATTACKER TECHNIQUE PROFILE")
        print("═" * W)
        print(f"  Risk:    {self.risk_label}  ({self.composite_risk_score:.0%})")
        print(f"  Header integrity: {self.header_integrity_score:.0%}"
              + ("  [OK — chain appears authentic]"
                 if self.header_integrity_score >= 0.85
                 else "  [WARNING — Received: chain may be forged]"))
        if self.semantic_profile:
            semantic_score = self.semantic_profile.get("chain_semantic_score")
            flags = self.semantic_profile.get("anomaly_flags", [])
            if semantic_score is not None:
                print(
                    f"  Header semantics: {semantic_score:.0%}"
                    + ("" if semantic_score >= 0.85 else "  [WARNING — semantic anomalies detected]")
                )
            if flags:
                print(f"  Semantic anomalies: {', '.join(flags[:4])}")

        if self.sending_method:
            sm = self.sending_method
            print(f"\n  Sending method: {sm.method}")
            if sm.real_ip_leaked and sm.real_ip:
                print(f"  [LEAK] Provider leaked real IP: {sm.real_ip}"
                      f"  (conf {sm.confidence:.0%})")
            if sm.strips_ip:
                print("  [BLOCKED] Provider strips all sender IP — passive attribution impossible")
                print("  [ACTION ] Deploy canary token bait document immediately")
            if sm.is_phishing_kit:
                print("  [CRITICAL] Phishing kit detected (GoPhish / SET / bulk mailer)")
            if sm.is_bot_send:
                print(f"  [BOT] Automated send pattern  CV={sm.bot_cv:.3f}")

        if self.detected_techniques:
            print(f"\n  Techniques detected ({self.technique_count}):")
            for t in self.detected_techniques:
                bar = "█" * int(t.confidence * 20)
                pad = "░" * (20 - len(bar))
                print(f"    [{t.mitre_id:<12}] {t.name:<38}"
                      f" {bar}{pad} {t.confidence:.0%}")
                for ev in t.evidence[:2]:
                    print(f"               → {ev}")
        else:
            print("\n  [OK] No attacker techniques detected in this email")

        if self.all_mitre_ids:
            print(f"\n  MITRE ATT&CK: {', '.join(self.all_mitre_ids)}")

        if self.flags:
            print(f"\n  Flags:")
            for f in self.flags:
                print(f"    ⚑  {f}")

        print("═" * W)


# ─────────────────────────────────────────────────────────────────────────────
#  CATEGORY CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

CAT_IDENTITY  = "Identity Obfuscation"
CAT_INFRA     = "Infrastructure Setup"
CAT_SEND      = "Sending Method"
CAT_CONTENT   = "Email Content"
CAT_EVASION   = "Header & Routing Evasion"
CAT_ACTIVE    = "Active Detection"


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN CLASS
# ─────────────────────────────────────────────────────────────────────────────

class AttackerTechniqueProfiler:
    """
    Profiles every attacker technique present in a single phishing email.

    Usage
    -----
        profiler = AttackerTechniqueProfiler(verbose=True)
        profile  = profiler.profile(raw_email_str, header_analysis=ha)
        profile.print_summary()   # prints Phase 0 block
        profile.to_dict()         # JSON-serialisable

    The header_analysis argument (ReceivedChainAnalysis from pipeline Stage 1)
    is optional but improves detection of infrastructure techniques.
    """

    # Known phishing kit X-Mailer fingerprints — case-insensitive substring match
    _KIT_MAILERS = [
        "gophish", "go phish", "setoolkit", "social-engineer",
        "metasploit", "evilginx", "modlishka", "muraena",
        "king phisher", "phishery", "zphisher", "blackeye",
        "shellphish", "nexphisher", "seeker",
    ]

    # SMTP relay / ESP hostnames — not attacker infrastructure
    _RELAY_PATTERNS = re.compile(
        r"(gmail|yahoo|outlook|hotmail|sendgrid|mailgun|"
        r"mailchimp|amazonses|ses\.amazonaws|sparkpost|"
        r"postmarkapp|mandrill|smtp\.office365|"
        r"protection\.outlook|pphosted|mimecast)",
        re.IGNORECASE,
    )

    # VPN provider ASN org name keywords
    _VPN_KEYWORDS = re.compile(
        r"(nordvpn|expressvpn|surfshark|mullvad|protonvpn|"
        r"private\s*internet|ipvanish|cyberghost|purevpn|"
        r"windscribe|tunnelbear|hotspotshield|hide\.me|"
        r"hideMyAss|hma\b|airvpn|perfectprivacy)",
        re.IGNORECASE,
    )

    # Datacenter / cloud org keywords
    _DC_KEYWORDS = re.compile(
        r"(amazon|amazonaws|digitalocean|linode|vultr|"
        r"hetzner|ovh\b|contabo|hostinger|hostwinds|"
        r"google\s*cloud|microsoft\s*azure|cloudflare)",
        re.IGNORECASE,
    )

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def profile(
        self,
        raw_email: str,
        header_analysis: Optional[Any] = None,
        campaign_timestamps: Optional[List[datetime]] = None,
    ) -> "AttackerTechniqueProfile":
        """
        Run full technique profiling on a raw RFC 2822 email string.

        Parameters
        ----------
        raw_email            : Complete email text (headers + body).
        header_analysis      : ReceivedChainAnalysis from Stage 1 (optional).
                               Provides enriched hop data for infrastructure checks.
        campaign_timestamps  : List of datetime objects from the same campaign
                               for bot CV scoring.  Single-email mode used if omitted.

        Returns
        -------
        AttackerTechniqueProfile
        """
        try:
            msg = _email_lib.message_from_string(raw_email)
        except Exception as exc:
            return self._empty_profile(f"Email parse error: {exc}")

        techniques: List[DetectedTechnique] = []

        # ── Run scanner.py detectors (source of truth) ────────────────────
        scan: Optional[Any] = None
        if _SCANNER_AVAILABLE:
            try:
                scan = run_forensic_scan(
                    raw_email,
                    send_timestamps=campaign_timestamps,
                    verbose=False,
                )
            except Exception as exc:
                if self.verbose:
                    print(f"  [WARNING] Forensic scan failed: {exc}")

        # ── Determine header integrity score ─────────────────────────────
        # Used by backtracking engine to discount Received: signals
        forgery_score = scan.hop_forgery.forgery_score if scan else 0.0
        header_integrity = max(0.0, 1.0 - forgery_score)
        semantic_profile: Optional[Dict[str, Any]] = None
        if header_analysis and getattr(header_analysis, "hops", None):
            hop_chain = []
            for hop in header_analysis.hops:
                hop_chain.append(
                    {
                        "position": getattr(hop, "hop_number", 0),
                        "from_hostname": getattr(hop, "from_hostname", None),
                        "by_hostname": getattr(hop, "by_hostname", None) or getattr(hop, "hostname", None),
                        "from_ip": getattr(hop, "ip", None) or getattr(hop, "ipv6", None),
                        "timestamp_raw": getattr(hop, "timestamp", None),
                        "protocol": getattr(hop, "protocol", None),
                        "tls": getattr(hop, "authentication", {}).get("tls", False),
                        "ehlo": getattr(hop, "ehlo", None),
                    }
                )
            semantic = validate_received_chain_semantics(hop_chain)
            semantic_profile = {
                "temporal_consistency_score": semantic.temporal_consistency_score,
                "chain_semantic_score": semantic.chain_semantic_score,
                "anomaly_flags": list(semantic.anomaly_flags),
                "hop_results": list(semantic.hop_results),
            }
            if semantic.chain_semantic_score < header_integrity:
                header_integrity = semantic.chain_semantic_score

        # ── CATEGORY 1: Identity Obfuscation ─────────────────────────────
        techniques += self._detect_identity_techniques(msg, scan)

        # ── CATEGORY 2: Infrastructure Setup ─────────────────────────────
        techniques += self._detect_infrastructure_techniques(msg, header_analysis)

        # ── CATEGORY 3: Sending Method ────────────────────────────────────
        # Sending method detection returns DetectedTechnique entries too
        techniques += self._detect_sending_technique_entries(msg, scan)

        # ── CATEGORY 4: Email Content Techniques ─────────────────────────
        techniques += self._detect_content_techniques(msg, scan)

        # ── CATEGORY 5: Header & Routing Evasion ─────────────────────────
        techniques += self._detect_evasion_techniques(msg, scan)

        # ── Build SendingMethod object ────────────────────────────────────
        sending_method = self._build_sending_method(msg, raw_email, scan)

        # ── Aggregate ─────────────────────────────────────────────────────
        all_mitre = sorted(set(t.mitre_id for t in techniques if t.mitre_id))
        if scan:
            all_mitre = sorted(set(all_mitre + scan.all_mitre))

        composite_risk = scan.risk_score if scan else self._fallback_risk(techniques)
        risk_label = (
            "CRITICAL" if composite_risk >= 0.75 else
            "HIGH"     if composite_risk >= 0.50 else
            "MEDIUM"   if composite_risk >= 0.25 else
            "LOW"
        )

        flags = self._build_flags(techniques, sending_method, scan, semantic_profile)

        passive_blocked = bool(
            sending_method and (sending_method.strips_ip or
            (sending_method.provider and
             any(p in (sending_method.provider or "").lower()
                 for p in ("proton", "tutanota", "tuta"))))
        )
        canary_recommended = passive_blocked or composite_risk >= 0.50

        return AttackerTechniqueProfile(
            detected_techniques=techniques,
            sending_method=sending_method,
            header_integrity_score=header_integrity,
            composite_risk_score=composite_risk,
            risk_label=risk_label,
            all_mitre_ids=all_mitre,
            flags=flags,
            passive_attribution_blocked=passive_blocked,
            canary_token_recommended=canary_recommended,
            forensic_scan=scan,
            semantic_profile=semantic_profile,
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )

    # ------------------------------------------------------------------
    # CATEGORY 1: IDENTITY OBFUSCATION
    # ------------------------------------------------------------------

    def _detect_identity_techniques(
        self, msg: Any, scan: Optional[Any]
    ) -> List[DetectedTechnique]:
        results: List[DetectedTechnique] = []

        # ── Homoglyph / IDN domain spoofing ──────────────────────────────
        if scan and scan.homoglyph.found:
            hom = scan.homoglyph
            evidence = []
            for sd in hom.suspect_domains[:5]:
                glyphs = ", ".join(sd.get("homoglyphs", [])[:3])
                brand  = sd.get("target_brand", "unknown brand")
                src    = sd.get("source", "header")
                evidence.append(
                    f"{sd['domain']} in {src} impersonates {brand}: {glyphs}"
                )
            results.append(DetectedTechnique(
                name="Homoglyph / IDN domain spoofing",
                category=CAT_IDENTITY,
                confidence=0.98,
                mitre_id="T1036.007",
                evidence=evidence,
                honest_limit=(
                    "Purely Unicode-based check. A spoofed domain using only ASCII "
                    "lookalikes (0 vs O, 1 vs l) is not caught here."
                ),
                next_step=(
                    "Block sending domain. Report to brand owner. "
                    "Check if domain was registered recently (WHOIS)."
                ),
                raw_score=1.0,
                detector="HomoglyphDomainDetector",
            ))

        # ── Display-name deception ────────────────────────────────────────
        disp_ev = self._check_display_name_deception(msg)
        if disp_ev:
            results.append(DetectedTechnique(
                name="Display-name deception",
                category=CAT_IDENTITY,
                confidence=0.90,
                mitre_id="T1036",
                evidence=disp_ev,
                honest_limit=(
                    "Brand keyword list is finite. Generic lures ('Invoice', "
                    "'Payment') with no brand name in display field are not caught."
                ),
                next_step=(
                    "Check SPF/DKIM authenticated domain against claimed brand. "
                    "Report display-name spoofing to brand abuse team."
                ),
                raw_score=0.90,
                detector="HeaderExtractor (display-name check)",
            ))

        # ── SPF hard-fail / domain mismatch ──────────────────────────────
        spf_ev = self._check_spf_fail(msg)
        if spf_ev:
            results.append(DetectedTechnique(
                name="SPF / DMARC alignment validation",
                category=CAT_IDENTITY,
                confidence=0.88,
                mitre_id="T1036.005",
                evidence=spf_ev,
                honest_limit=(
                    "SPF fail means the sending IP was not authorised by the domain owner. "
                    "A sophisticated attacker registers their own domain and sets SPF correctly "
                    "— that will pass SPF."
                ),
                next_step=(
                    "Block sender domain. Raise spoofing_risk in Stage 1. "
                    "Apply C1 counter-technique penalty in backtracking."
                ),
                raw_score=0.88,
                detector="Received-SPF header check",
            ))

        return results

    def _check_display_name_deception(self, msg: Any) -> List[str]:
        """Return evidence list if display name impersonates a known brand."""
        from_raw  = msg.get("From", "")
        reply_raw = msg.get("Reply-To", "")

        BRANDS = [
            "paypal", "amazon", "microsoft", "google", "apple",
            "netflix", "facebook", "instagram", "linkedin", "dropbox",
            "ebay", "bank", "secure", "security", "support", "account",
            "billing", "helpdesk", "it support", "hr department",
        ]
        evidence: List[str] = []
        for hdr_name, raw in [("From", from_raw), ("Reply-To", reply_raw)]:
            if not raw:
                continue
            # Extract display name (everything before <)
            m = re.match(r'^"?([^"<]+)"?\s*<([^>]+)>', raw.strip())
            if not m:
                continue
            display = m.group(1).strip().lower()
            addr    = m.group(2).strip().lower()
            # Domain part of address
            addr_domain = addr.split("@")[-1] if "@" in addr else addr

            for brand in BRANDS:
                if brand in display and brand not in addr_domain:
                    evidence.append(
                        f"{hdr_name}: display='{m.group(1).strip()}'"
                        f" ≠ domain '{addr_domain}' — impersonates '{brand}'"
                    )
                    break
        return evidence

    def _check_spf_fail(self, msg: Any) -> List[str]:
        """Return evidence list if SPF explicitly fails or softfails."""
        # Check Received-SPF header directly (most common location)
        spf_header = msg.get("Received-SPF", "") or ""
        auth_header = msg.get("Authentication-Results", "") or ""
        combined = spf_header + " " + auth_header
        combined_lower = combined.lower()
        evidence: List[str] = []

        # Received-SPF: fail ... or Authentication-Results: ... spf=fail
        if re.search(r'\bfail\b', spf_header, re.IGNORECASE) and spf_header:
            evidence.append("Received-SPF: FAIL — sending IP not authorised for claimed domain")
            ip_m = re.search(r'client-ip=([0-9a-fA-F.:]+)', combined)
            if ip_m:
                evidence.append(f"Unauthorized sender IP: {ip_m.group(1)}")
        elif re.search(r'\bsoftfail\b', spf_header, re.IGNORECASE) and spf_header:
            evidence.append("Received-SPF: SOFTFAIL (~) — domain weakly discourages sending IP")
        elif "spf=fail" in combined_lower:
            evidence.append("SPF: FAIL (Authentication-Results)")
        elif "spf=softfail" in combined_lower:
            evidence.append("SPF: SOFTFAIL (Authentication-Results)")

        # DMARC fail
        if "dmarc=fail" in combined_lower:
            evidence.append("DMARC: FAIL — neither SPF nor DKIM align with From: domain")

        return evidence

    # ------------------------------------------------------------------
    # CATEGORY 2: INFRASTRUCTURE SETUP
    # ------------------------------------------------------------------

    def _detect_infrastructure_techniques(
        self, msg: Any, header_analysis: Optional[Any]
    ) -> List[DetectedTechnique]:
        results: List[DetectedTechnique] = []

        # ── VPN detection via WHOIS/ASN from header_analysis ─────────────
        if header_analysis:
            vpn_ev = self._detect_vpn_from_headers(header_analysis)
            if vpn_ev["found"]:
                results.append(DetectedTechnique(
                    name="Commercial VPN usage",
                    category=CAT_INFRA,
                    confidence=0.88,
                    mitre_id="T1090.003",
                    evidence=vpn_ev["evidence"],
                    honest_limit=(
                        "Self-hosted WireGuard / OpenVPN on a cloud VPS appears as "
                        "DATACENTER, not VPN_PROVIDER. New VPN infrastructure "
                        "not yet in ASN databases will be missed."
                    ),
                    next_step=(
                        "Apply T7 geo-mismatch check. Use T8 DNS infrastructure "
                        "geolocation (VPN-resistant) for country attribution."
                    ),
                    raw_score=0.88,
                    detector="IPClassifier + VPN ASN keyword check",
                ))

            # ── Datacenter / self-hosted mail server ─────────────────────
            dc_ev = self._detect_datacenter_from_headers(header_analysis)
            if dc_ev["found"]:
                results.append(DetectedTechnique(
                    name="Rented VPS / cloud mail server",
                    category=CAT_INFRA,
                    confidence=0.85,
                    mitre_id="T1583.003",
                    evidence=dc_ev["evidence"],
                    honest_limit=(
                        "Legitimate corporate mail servers also run on cloud. "
                        "Context required: datacenter + missing SPF record is "
                        "much stronger indicator than datacenter alone."
                    ),
                    next_step=(
                        "Check if domain has a published SPF record. "
                        "WHOIS org and ASN enrichment (Stage 3B) will confirm."
                    ),
                    raw_score=0.85,
                    detector="IPClassifier + DATACENTER keyword check",
                ))

            # ── Tor exit node ─────────────────────────────────────────────
            tor_ev = self._detect_tor_from_headers(header_analysis)
            if tor_ev["found"]:
                results.append(DetectedTechnique(
                    name="Tor network routing",
                    category=CAT_INFRA,
                    confidence=0.95,
                    mitre_id="T1090.003",
                    evidence=tor_ev["evidence"],
                    honest_limit=(
                        "Tor obfs4 bridges are not in the public exit list — "
                        "traffic appears as normal HTTPS and will be missed. "
                        "Covers ~99% of standard Tor usage."
                    ),
                    next_step=(
                        "C3 counter-technique applied: ACI −0.40. "
                        "Deploy canary token — only technique that bypasses Tor. "
                        "Note: tracking the Tor entry guard requires legal process."
                    ),
                    raw_score=0.95,
                    detector="IPClassifier TOR_EXIT consensus check",
                ))

        # ── Hop count / proxy chain ───────────────────────────────────────
        # Infer from Received: headers directly (no header_analysis needed)
        received_list = msg.get_all("Received") or []
        if len(received_list) >= 5:
            unknown_hops = sum(
                1 for r in received_list
                if re.search(r'\bunknown\b|\bprivate\b', r, re.IGNORECASE)
            )
            if unknown_hops >= 1 or len(received_list) >= 6:
                evidence = [
                    f"Received: chain has {len(received_list)} hops"
                    f" ({unknown_hops} obfuscated with 'unknown'/'private')"
                ]
                confidence = min(0.75, 0.50 + unknown_hops * 0.10)
                results.append(DetectedTechnique(
                    name="Proxy chain / SOCKS relay",
                    category=CAT_INFRA,
                    confidence=confidence,
                    mitre_id="T1090",
                    evidence=evidence,
                    honest_limit=(
                        "A long but legitimate relay chain (e.g. corporate mail "
                        "gateway) can produce the same hop count. 'Unknown' hop "
                        "hostnames are a stronger but not conclusive signal."
                    ),
                    next_step=(
                        "T3 hop-count analysis already handles this. "
                        "Cross-check each hop IP against VPN/datacenter ASNs."
                    ),
                    raw_score=confidence,
                    detector="Received: chain hop count + obfuscation marker check",
                ))

        return results

    def _detect_vpn_from_headers(self, ha: Any) -> Dict:
        """Check hop IPs/hostnames from header_analysis for VPN org keywords."""
        evidence: List[str] = []
        for hop in getattr(ha, "hops", []):
            hostname = getattr(hop, "hostname", "") or ""
            if self._VPN_KEYWORDS.search(hostname):
                evidence.append(f"Hop {hop.hop_number}: hostname '{hostname}' matches VPN provider pattern")
        # Classifications are not available here — rely on hostname only
        return {"found": bool(evidence), "evidence": evidence}

    def _detect_datacenter_from_headers(self, ha: Any) -> Dict:
        """Check hop hostnames for cloud/datacenter keywords."""
        evidence: List[str] = []
        for hop in getattr(ha, "hops", []):
            hostname = getattr(hop, "hostname", "") or ""
            if self._DC_KEYWORDS.search(hostname):
                # Don't flag known legitimate mail relay hostnames
                if not self._RELAY_PATTERNS.search(hostname):
                    evidence.append(
                        f"Hop {hop.hop_number}: '{hostname}' — cloud/datacenter hosting"
                    )
        return {"found": bool(evidence), "evidence": evidence}

    def _detect_tor_from_headers(self, ha: Any) -> Dict:
        """Check if any classifications flag Tor (from pipeline Stage 2)."""
        evidence: List[str] = []
        # header_analysis itself doesn't carry classifications, but red_flags does
        for flag in getattr(ha, "red_flags", []):
            if "tor" in flag.lower() or "exit node" in flag.lower():
                evidence.append(flag)
        return {"found": bool(evidence), "evidence": evidence}

    # ------------------------------------------------------------------
    # CATEGORY 3: SENDING METHOD  (returns DetectedTechnique entries)
    # ------------------------------------------------------------------

    def _detect_sending_technique_entries(
        self, msg: Any, scan: Optional[Any]
    ) -> List[DetectedTechnique]:
        """
        Return DetectedTechnique entries for send-method techniques
        (GoPhish kit, bot send pattern).
        Webmail provider is handled separately in _build_sending_method().
        """
        results: List[DetectedTechnique] = []

        # ── Phishing kit / GoPhish ────────────────────────────────────────
        xmailer  = (msg.get("X-Mailer", "") or "").lower()
        kit_name = next((k for k in self._KIT_MAILERS if k in xmailer), None)
        if kit_name:
            results.append(DetectedTechnique(
                name=f"Phishing kit fingerprint ({kit_name})",
                category=CAT_SEND,
                confidence=0.97,
                mitre_id="T1566.001",
                evidence=[
                    f"X-Mailer: {msg.get('X-Mailer', '')} — matches known phishing kit pattern",
                    f"Framework: {kit_name}",
                ],
                honest_limit=(
                    "Sophisticated attackers remove or replace X-Mailer. "
                    "Bot send-pattern CV scoring catches those cases even without X-Mailer."
                ),
                next_step=(
                    "Cross-reference with T2 (bot send pattern). "
                    "Search infrastructure for other emails from same kit configuration."
                ),
                raw_score=0.97,
                detector="X-Mailer keyword check (phishing kit fingerprints)",
            ))

        # ── Bot send pattern ──────────────────────────────────────────────
        if scan and scan.send_pattern.verdict == "bot":
            cv = scan.send_pattern.cv
            evidence = [
                f"Inter-send interval CV = {cv:.3f} (threshold < 0.10 = bot)",
            ]
            if scan.send_pattern.round_intervals:
                evidence.append(
                    f"Cron-style round intervals: {scan.send_pattern.round_intervals} detected"
                )
            if scan.send_pattern.burst_count:
                evidence.append(
                    f"Burst sends (< 60s apart): {scan.send_pattern.burst_count}"
                )
            results.append(DetectedTechnique(
                name="Automated bulk send (bot pattern)",
                category=CAT_SEND,
                confidence=0.93,
                mitre_id="T1566.001",
                evidence=evidence,
                honest_limit=(
                    "Requires campaign-mode scoring (≥2 timestamps). "
                    "A patient attacker who introduces deliberate jitter "
                    "can push CV above 0.10."
                ),
                next_step=(
                    "Collect all emails in the campaign for batch CV scoring. "
                    "Correlate X-Mailer and hop pattern across the campaign."
                ),
                raw_score=cv if cv is not None else 0.0,
                detector="BotSendPatternScorer (CV of inter-send intervals)",
            ))
        elif scan and scan.send_pattern.verdict == "scripted_human":
            results.append(DetectedTechnique(
                name="Semi-automated / scripted send pattern",
                category=CAT_SEND,
                confidence=0.70,
                mitre_id="T1566.001",
                evidence=[
                    f"Inter-send interval CV = {scan.send_pattern.cv:.3f}"
                    f" (0.10–0.40 = scripted human)",
                ],
                honest_limit="Borderline range — may be a disciplined human sender.",
                next_step="Collect more campaign samples to reduce CV uncertainty.",
                raw_score=scan.send_pattern.cv or 0.0,
                detector="BotSendPatternScorer",
            ))

        # ── AI-generated content ──────────────────────────────────────────
        if scan and scan.ai_content.verdict == "ai_likely":
            ai = scan.ai_content
            evidence = list(ai.signals[:4])
            results.append(DetectedTechnique(
                name="AI-generated email content (LLM-written)",
                category=CAT_SEND,
                confidence=min(0.78, ai.ai_probability),
                mitre_id="T1059",
                evidence=evidence,
                honest_limit=(
                    "Stylometric signals are probabilistic. High-quality LLM output "
                    "(GPT-4 Turbo) is approaching human variance. Max conf 0.78."
                ),
                next_step=(
                    "Use as a corroborating signal — do not rely on this alone. "
                    "Combine with bot send pattern and campaign timing."
                ),
                raw_score=ai.ai_probability,
                detector="AIContentDetector (TTR, sentence-CV, bigram entropy)",
            ))

        return results

    # ------------------------------------------------------------------
    # CATEGORY 4: EMAIL CONTENT TECHNIQUES
    # ------------------------------------------------------------------

    def _detect_content_techniques(
        self, msg: Any, scan: Optional[Any]
    ) -> List[DetectedTechnique]:
        results: List[DetectedTechnique] = []
        if not scan:
            return results

        # ── HTML Smuggling ────────────────────────────────────────────────
        if scan.html_smuggling.found:
            sm = scan.html_smuggling
            evidence = list(sm.findings[:5])
            if sm.blob_urls:
                evidence.append(f"Blob URLs found: {sm.blob_urls[0][:80]}")
            if sm.data_uris:
                evidence.append(f"Executable data-URI: {sm.data_uris[0][:60]}…")
            results.append(DetectedTechnique(
                name="HTML smuggling (Blob URL / atob() payload)",
                category=CAT_CONTENT,
                confidence=min(0.97, 0.60 + sm.risk_score * 0.40),
                mitre_id="T1027.006",
                evidence=evidence,
                honest_limit=(
                    "Heavily obfuscated payloads avoiding blob:/atob/fromCharCode "
                    "keywords require JS AST analysis (not implemented here)."
                ),
                next_step=(
                    "Extract and decode the payload from the Blob/data-URI. "
                    "Submit to sandbox analysis (ANY.RUN, Joe Sandbox)."
                ),
                raw_score=sm.risk_score,
                detector="HTMLSmugglingDetector",
            ))

        # ── Tracking pixel ────────────────────────────────────────────────
        if scan.tracking_pixel.found:
            px = scan.tracking_pixel
            evidence = [f"Tracking pixel detected: {px.detail}"]
            if px.beacon_urls:
                evidence.append(f"Beacon URL: {px.beacon_urls[0][:100]}")
            if px.suspicious_domains:
                evidence.append(f"Tracker domains: {', '.join(px.suspicious_domains[:3])}")
            results.append(DetectedTechnique(
                name="Tracking pixel / open-beacon",
                category=CAT_CONTENT,
                confidence=0.93,
                mitre_id="T1598",
                evidence=evidence,
                honest_limit=(
                    "Beacon URL using a bare numeric IP (no domain keywords) "
                    "may evade the domain-list check. CSS-embedded pixel "
                    "dimensions are also not caught."
                ),
                next_step=(
                    "Block outbound connection to beacon domain/IP. "
                    "The attacker's server logs will show victim IPs and open times. "
                    "Consider serving a canary pixel back to the attacker."
                ),
                raw_score=1.0 if px.found else 0.0,
                detector="TrackingPixelDetector",
            ))

        # ── Zero-point font / hidden text ─────────────────────────────────
        if scan.zero_font.found:
            zf = scan.zero_font
            evidence = [f"Hidden text: {zf.detail}"]
            for snip in zf.suspect_snippets[:2]:
                evidence.append(f"Snippet: {snip[:80]}")
            results.append(DetectedTechnique(
                name="Zero-point font / hidden text injection",
                category=CAT_CONTENT,
                confidence=0.93,
                mitre_id="T1027",
                evidence=evidence,
                honest_limit=(
                    "Inline styles computed by JavaScript at render time "
                    "are not caught by static HTML analysis."
                ),
                next_step=(
                    "Extract and display hidden text for analysis. "
                    "Hidden content may contain obfuscated URLs or keywords "
                    "designed to confuse NLP spam classifiers."
                ),
                raw_score=1.0,
                detector="ZeroPointFontDetector",
            ))

        return results

    # ------------------------------------------------------------------
    # CATEGORY 5: HEADER & ROUTING EVASION
    # ------------------------------------------------------------------

    def _detect_evasion_techniques(
        self, msg: Any, scan: Optional[Any]
    ) -> List[DetectedTechnique]:
        results: List[DetectedTechnique] = []

        # ── Hop timestamp forgery ─────────────────────────────────────────
        if scan and scan.hop_forgery.verdict in ("SUSPICIOUS", "FORGED"):
            hf = scan.hop_forgery
            evidence = list(hf.regressions[:3]) + list(hf.anomalies[:3])
            evidence.insert(0, f"Forgery verdict: {hf.verdict}  score={hf.forgery_score:.3f}")
            results.append(DetectedTechnique(
                name="Received: header chain forgery",
                category=CAT_EVASION,
                confidence=min(0.92, 0.50 + hf.forgery_score),
                mitre_id="T1036.005",
                evidence=evidence,
                honest_limit=(
                    "A sophisticated attacker who correctly timestamps all "
                    "hops in chronological order will not trigger the regression "
                    "check. Private IPs mid-chain and zero-second transits are "
                    "still detectable."
                ),
                next_step=(
                    f"Header integrity score = {max(0.0, 1.0 - hf.forgery_score):.0%}. "
                    "Discount T1/T3 Received: signals in backtracking. "
                    "Focus on server-verified signals: SPF client-ip= (T4) "
                    "and DNS infrastructure (T8)."
                ),
                raw_score=hf.forgery_score,
                detector="HopTimestampForgeryDetector",
            ))

        # ── Timezone / Date header spoofing ──────────────────────────────
        tz_ev = self._check_timezone_spoof(msg)
        if tz_ev:
            results.append(DetectedTechnique(
                name="Date: header timezone spoofing",
                category=CAT_EVASION,
                confidence=0.82,
                mitre_id="T1036",
                evidence=tz_ev,
                honest_limit=(
                    "Date: is entirely client-controlled. T2 timezone correlation "
                    "cross-validates against server-added Received: timestamps, "
                    "but if Received: headers are also forged, this check fails."
                ),
                next_step=(
                    "T2 confidence already reduced to 0.10 for this email. "
                    "Rely on T4 (SPF) and T8 (DNS) for country attribution."
                ),
                raw_score=0.82,
                detector="Date:/Received: timezone cross-check",
            ))

        # ── PHP Mailer / compromised web server ───────────────────────────
        php_ev = self._check_php_mailer(msg)
        if php_ev:
            results.append(DetectedTechnique(
                name="PHP Mailer / compromised web server",
                category=CAT_EVASION,
                confidence=0.88,
                mitre_id="T1584",
                evidence=php_ev,
                honest_limit=(
                    "Only detectable via X-PHP-Originating-Script header, "
                    "which is specific to PHP mail() calls. Direct SMTP from "
                    "the compromised server does not leave this header."
                ),
                next_step=(
                    "The script path in X-PHP-Originating-Script reveals the "
                    "attacker's file on the compromised server. Contact the "
                    "hosting provider with the path for takedown."
                ),
                raw_score=0.88,
                detector="X-PHP-Originating-Script header check",
            ))

        # ── Suspicious overnight send ─────────────────────────────────────
        if scan and scan.send_pattern.overnight_sends > 0:
            send_hour = scan.send_pattern.send_hour
            if send_hour is not None and 0 <= send_hour <= 5:
                results.append(DetectedTechnique(
                    name="Anomalous send time (night-hour dispatch)",
                    category=CAT_EVASION,
                    confidence=0.60,
                    mitre_id="T1036",
                    evidence=[
                        f"Email sent at {send_hour:02d}:xx local time "
                        f"(00:00–05:59 = C4 anomaly score 0.55)"
                    ],
                    honest_limit=(
                        "Date: header is client-controlled. Night-hour sends "
                        "are common for automated campaigns regardless of location. "
                        "Use as corroborating signal only."
                    ),
                    next_step=(
                        "Cross-reference send time with claimed timezone. "
                        "If timezone is business hours in the claimed region "
                        "but actual send is 02:00, timezone spoofing is likely."
                    ),
                    raw_score=0.55,
                    detector="BotSendPatternScorer (overnight_sends flag)",
                ))

        return results

    def _check_timezone_spoof(self, msg: Any) -> List[str]:
        """
        Check if Date: header timezone is contradicted by Received: server timestamps.
        Returns evidence list if spoofing is detected.
        """
        date_str = msg.get("Date", "")
        received_list = msg.get_all("Received") or []
        if not date_str or not received_list:
            return []

        # Extract UTC offset from Date: header
        tz_m = re.search(r'([+-])(\d{2}):?(\d{2})\s*(?:\([^)]*\))?\s*$', date_str)
        if not tz_m:
            return []

        date_offset_sign = 1 if tz_m.group(1) == "+" else -1
        date_offset_hours = int(tz_m.group(2))
        date_offset_mins  = int(tz_m.group(3))
        date_offset_total = date_offset_sign * (date_offset_hours * 60 + date_offset_mins)

        # Check server timestamps in Received: headers for the same offset
        server_offsets: List[int] = []
        for rcv in received_list[:3]:
            m = re.search(r';\s+.*?([+-])(\d{2}):?(\d{2})\s*(?:\([^)]*\))?\s*$', rcv)
            if m:
                sign = 1 if m.group(1) == "+" else -1
                off  = sign * (int(m.group(2)) * 60 + int(m.group(3)))
                server_offsets.append(off)

        if not server_offsets:
            return []

        # If no server-added Received: timestamp matches the Date: timezone,
        # and the disagreement is > 2 hours, flag as spoofed
        mismatches = [
            o for o in server_offsets
            if abs(o - date_offset_total) > 120  # > 2 hours difference
        ]
        if len(mismatches) == len(server_offsets):
            claimed_h = date_offset_hours
            claimed_s = "+" if date_offset_sign > 0 else "-"
            server_sample = server_offsets[0]
            server_s = "+" if server_sample >= 0 else "-"
            server_h = abs(server_sample) // 60
            return [
                f"Date: claims UTC{claimed_s}{claimed_h:02d}:00 "
                f"but Received: server shows UTC{server_s}{server_h:02d}:00",
                "Date: header timezone contradicted by all sampled server timestamps",
            ]
        return []

    def _check_php_mailer(self, msg: Any) -> List[str]:
        """Return evidence list if PHP Mailer script path is exposed."""
        evidence: List[str] = []
        php_header = msg.get("X-PHP-Originating-Script", "")
        if php_header:
            evidence.append(
                f"X-PHP-Originating-Script: {php_header} "
                f"— PHP mail() called from this path on compromised server"
            )
        # cPanel webmail patterns
        xmailer = msg.get("X-Mailer", "")
        for cp in ("Roundcube", "Horde", "SquirrelMail"):
            if cp.lower() in xmailer.lower():
                evidence.append(
                    f"X-Mailer: {xmailer} — sent via cPanel webmail ({cp})"
                )
                break
        return evidence

    # ------------------------------------------------------------------
    # SENDING METHOD OBJECT
    # ------------------------------------------------------------------

    def _build_sending_method(
        self, msg: Any, raw_email: str, scan: Optional[Any]
    ) -> Optional[SendingMethod]:
        """
        Build a rich SendingMethod object from webmail extraction
        and X-Mailer / send-pattern analysis.
        """
        # ── Try webmail extraction first (highest confidence) ─────────────
        if _WEBMAIL_AVAILABLE:
            try:
                wm = run_webmail_extraction(raw_email)
                if wm and wm.provider != WebmailProvider.UNKNOWN:
                    provider_name = getattr(wm, "provider_name", str(wm.provider))
                    leak_beh = getattr(wm, "leak_behaviour", None)

                    strips = (leak_beh == LeakBehaviour.STRIPS_IP
                              if leak_beh is not None
                              else "proton" in provider_name.lower()
                                   or "tutanota" in provider_name.lower())

                    real_ip     = getattr(wm, "real_ip", None)
                    confidence  = getattr(wm, "confidence", 0.85)
                    leak_header = getattr(wm, "leak_header", None)

                    evidence = [f"Provider identified: {provider_name}"]
                    if real_ip:
                        evidence.append(f"Real client IP leaked: {real_ip}"
                                        f" via {leak_header}")
                    elif strips:
                        evidence.append("Provider strips all sender IP by design")

                    is_kit  = bool(next(
                        (k for k in self._KIT_MAILERS
                         if k in (msg.get("X-Mailer", "") or "").lower()),
                        None
                    ))
                    is_bot  = (scan.send_pattern.verdict == "bot") if scan else False
                    bot_cv  = scan.send_pattern.cv if scan else None

                    method_label = (
                        f"Phishing kit via {provider_name}" if is_kit
                        else f"Webmail: {provider_name}"
                    )
                    return SendingMethod(
                        method=method_label,
                        provider=provider_name,
                        real_ip_leaked=(real_ip is not None),
                        real_ip=real_ip,
                        confidence=confidence,
                        evidence=evidence,
                        strips_ip=strips,
                        is_phishing_kit=is_kit,
                        is_bot_send=is_bot,
                        bot_cv=bot_cv,
                    )
            except Exception as exc:
                if self.verbose:
                    print(f"  [WARNING] Webmail extraction in profiler failed: {exc}")

        # ── Fallback: X-Mailer / send-pattern heuristics ──────────────────
        xmailer  = msg.get("X-Mailer", "") or ""
        kit_name = next((k for k in self._KIT_MAILERS if k in xmailer.lower()), None)
        is_bot   = (scan.send_pattern.verdict == "bot") if scan else False
        bot_cv   = scan.send_pattern.cv if scan else None

        if kit_name:
            return SendingMethod(
                method=f"Phishing kit: {kit_name}",
                provider=None,
                real_ip_leaked=False,
                real_ip=None,
                confidence=0.95,
                evidence=[f"X-Mailer: {xmailer}"],
                is_phishing_kit=True,
                is_bot_send=is_bot,
                bot_cv=bot_cv,
            )

        if is_bot:
            return SendingMethod(
                method="Automated bulk mailer (unknown kit)",
                provider=None,
                real_ip_leaked=False,
                real_ip=None,
                confidence=0.80,
                evidence=[f"Bot send pattern CV={bot_cv:.3f}"],
                is_phishing_kit=False,
                is_bot_send=True,
                bot_cv=bot_cv,
            )

        # Check for SMTP desktop client
        smtp_clients = ("Outlook", "Thunderbird", "Apple Mail",
                        "Evolution", "Lotus Notes")
        for client in smtp_clients:
            if client.lower() in xmailer.lower():
                return SendingMethod(
                    method=f"Desktop SMTP client: {client}",
                    provider=None,
                    real_ip_leaked=False,
                    real_ip=None,
                    confidence=0.75,
                    evidence=[f"X-Mailer: {xmailer}"],
                )

        if xmailer:
            return SendingMethod(
                method=f"Mail client: {xmailer[:60]}",
                provider=None,
                real_ip_leaked=False,
                real_ip=None,
                confidence=0.60,
                evidence=[f"X-Mailer: {xmailer}"],
            )

        # ── Fallback: header-based ProtonMail / Tutanota detection ───────────
        if not _WEBMAIL_AVAILABLE:
            from_addr = (msg.get("From", "") or "").lower()
            rcv_all   = " ".join(msg.get_all("Received") or []).lower()
            pm_match  = (
                "protonmail" in from_addr or "@pm.me" in from_addr
                or "protonmail.ch" in rcv_all or "x-pm-message-id" in
                " ".join(k.lower() for k in msg.keys())
            )
            tuta_match = (
                "tutanota" in from_addr or "tuta.io" in from_addr
                or "tutanota" in rcv_all
            )
            if pm_match or tuta_match:
                provider_label = "ProtonMail" if pm_match else "Tutanota"
                return SendingMethod(
                    method=f"Privacy webmail: {provider_label} (strips all sender IP)",
                    provider=provider_label,
                    real_ip_leaked=False,
                    real_ip=None,
                    confidence=0.92,
                    evidence=[
                        f"Provider {provider_label} identified from From: address / Received: hostname",
                        "LeakBehaviour: STRIPS_IP — no passive attribution possible",
                    ],
                    strips_ip=True,
                )

        return None

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    def _build_flags(
        self,
        techniques: List[DetectedTechnique],
        sending_method: Optional[SendingMethod],
        scan: Optional[Any],
        semantic_profile: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        flags: List[str] = []
        if scan:
            flags.extend(scan.flags)

        if semantic_profile and semantic_profile.get("anomaly_flags"):
            flag_list = ", ".join(semantic_profile.get("anomaly_flags", [])[:3])
            flags.append(f"RECEIVED CHAIN ANOMALIES — {flag_list}")

        for t in techniques:
            if t.confidence >= 0.90 and t.category in (CAT_EVASION, CAT_INFRA):
                flag = f"{t.name} ({t.mitre_id}) — {t.evidence[0] if t.evidence else ''}"
                if flag not in flags:
                    flags.append(flag)

        if sending_method and sending_method.strips_ip:
            flags.append(
                "PASSIVE ATTRIBUTION BLOCKED — ProtonMail/Tutanota strips all sender IP"
            )
        if sending_method and sending_method.is_phishing_kit:
            flags.append(
                f"PHISHING KIT DETECTED — {sending_method.method}"
            )
        return flags

    def _fallback_risk(self, techniques: List[DetectedTechnique]) -> float:
        """Calculate composite risk when scanner.py is unavailable."""
        if not techniques:
            return 0.0
        scores = [t.confidence * t.raw_score for t in techniques if t.raw_score > 0]
        return min(1.0, sum(scores) / max(1, len(scores)))

    def _empty_profile(self, reason: str) -> "AttackerTechniqueProfile":
        return AttackerTechniqueProfile(
            detected_techniques=[],
            sending_method=None,
            header_integrity_score=1.0,
            composite_risk_score=0.0,
            risk_label="LOW",
            all_mitre_ids=[],
            flags=[f"ERROR: {reason}"],
            passive_attribution_blocked=False,
            canary_token_recommended=False,
            forensic_scan=None,
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )


# ─────────────────────────────────────────────────────────────────────────────
#  CONVENIENCE FUNCTION  (mirrors run_forensic_scan API style)
# ─────────────────────────────────────────────────────────────────────────────

def profile_attacker_techniques(
    raw_email: str,
    header_analysis: Optional[Any] = None,
    campaign_timestamps: Optional[List[datetime]] = None,
    verbose: bool = False,
) -> AttackerTechniqueProfile:
    """
    One-call convenience wrapper.

    Usage
    -----
        from huntertrace.forensics.attackerTechniqueProfiler import profile_attacker_techniques

        profile = profile_attacker_techniques(raw_email, header_analysis=ha)
        profile.print_summary()
        data = profile.to_dict()   # JSON-serialisable
    """
    return AttackerTechniqueProfiler(verbose=verbose).profile(
        raw_email,
        header_analysis=header_analysis,
        campaign_timestamps=campaign_timestamps,
    )


# ─────────────────────────────────────────────────────────────────────────────
#  CLI  (for standalone testing: python attackerTechniqueProfiler.py email.eml)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python attackerTechniqueProfiler.py <email.eml> [--json] [--verbose]")
        sys.exit(1)

    verbose_flag = "--verbose" in sys.argv
    json_flag    = "--json"    in sys.argv

    try:
        raw = open(sys.argv[1], "r", encoding="utf-8", errors="replace").read()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {sys.argv[1]}")
        sys.exit(1)

    profiler = AttackerTechniqueProfiler(verbose=verbose_flag)
    profile  = profiler.profile(raw)

    if json_flag:
        print(json.dumps(profile.to_dict(), indent=2))
    else:
        profile.print_summary()