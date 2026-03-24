#!/usr/bin/env python3
"""
HunterTrace v3 — Email Forensics Scanner
=========================================
Eight self-contained forensic detectors. Zero external dependencies (stdlib only).
Every detector parses from a raw RFC-2822 email string and returns a structured
dataclass with a .to_dict() method for JSON serialisation.

DETECTORS
---------
1. HopTimestampForgeryDetector  — hop-by-hop timestamp regression + forgery score
2. BotSendPatternScorer         — inter-send CV, cron regularity, overnight activity
3. AIContentDetector            — TTR, sentence-CV, function-word ratio, bigram entropy
4. TrackingPixelDetector        — 1×1 imgs, display:none, external beacon domains
5. HTMLSmugglingDetector        — JS blob URLs, data-URIs, atob(), eval(), fromCharCode
6. HomoglyphDomainDetector      — Unicode lookalike chars in From/Reply-To/hrefs
7. ZeroPointFontDetector        — font-size:0, display:none text, white-on-white CSS
8. ForensicScanSummary          — composite risk score aggregating all seven

PUBLIC API
----------
    from huntertrace.forensics.scanner import run_forensic_scan
    summary = run_forensic_scan(raw_email_str, verbose=True)
    summary.to_dict()   # JSON-serialisable

CLI
---
    python emailForensicsScanner.py email.eml
    python emailForensicsScanner.py email.eml --json
"""

import re
import html as _html_unescape
import math
import email as _email_lib
import unicodedata
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from collections import Counter


# ═══════════════════════════════════════════════════════════════════════════════
# 1.  HOP TIMESTAMP FORGERY DETECTOR
#     Signals: timestamp regression between hops, zero-second transits,
#     >6-hour relay gaps, private IPs mid-chain, missing interior timestamps,
#     >8 hops.
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HopForgeryResult:
    verdict:        str          # CLEAN | SUSPICIOUS | FORGED
    forgery_score:  float        # 0.0–1.0
    hop_count:      int
    hops_parsed:    int
    regressions:    List[str]    # e.g. "Hop 2→3: time went backwards by 47s"
    anomalies:      List[str]    # other anomalies
    mitre:          List[str]
    detail:         str

    def to_dict(self):
        return {
            "verdict":       self.verdict,
            "forgery_score": round(self.forgery_score, 3),
            "hop_count":     self.hop_count,
            "hops_parsed":   self.hops_parsed,
            "regressions":   self.regressions,
            "anomalies":     self.anomalies,
            "mitre":         self.mitre,
            "detail":        self.detail,
        }


class HopTimestampForgeryDetector:

    _FMTS = [
        "%a, %d %b %Y %H:%M:%S %z",
        "%d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M %z",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%d %b %Y %H:%M:%S %Z",
    ]
    _PRIV = re.compile(
        r'^(10\.|127\.|0\.'
        r'|172\.(1[6-9]|2[0-9]|3[01])\.'
        r'|192\.168\.)'
    )

    def detect(self, msg) -> HopForgeryResult:
        received = list(reversed(msg.get_all("Received") or []))  # oldest→newest
        hop_count = len(received)
        timestamps = [self._parse_ts(r) for r in received]
        anomalies: List[str] = []
        regressions: List[str] = []

        # Private IP mid-chain
        for i, rcv in enumerate(received):
            if 0 < i < hop_count - 1:
                for ip in re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', rcv):
                    if self._PRIV.match(ip):
                        anomalies.append(f"Hop {i+1}: private IP {ip} in mid-chain")

        # Missing interior timestamps
        missing = [i + 1 for i, t in enumerate(timestamps) if t is None and 0 < i < hop_count - 1]
        if missing:
            anomalies.append(f"Missing timestamp on interior hop(s): {missing}")

        # Regression + gap analysis over contiguous pairs with valid timestamps
        valid = [(i, t) for i, t in enumerate(timestamps) if t is not None]
        for k in range(1, len(valid)):
            pi, pt = valid[k - 1]
            ci, ct = valid[k]
            delta = (ct - pt).total_seconds()
            if delta < 0:
                regressions.append(
                    f"Hop {pi+1}→{ci+1}: regression {abs(delta):.0f}s "
                    f"({pt.strftime('%H:%M:%S')} → {ct.strftime('%H:%M:%S')})"
                )
            elif delta == 0:
                anomalies.append(f"Hop {pi+1}→{ci+1}: zero-second transit")
            elif delta > 21_600:
                anomalies.append(f"Hop {pi+1}→{ci+1}: delay {delta/3600:.1f}h (unusually long)")

        if hop_count > 8:
            anomalies.append(f"Excess hop count: {hop_count} (threshold: 8)")

        # Score
        score = min(1.0,
                    min(0.60, len(regressions) * 0.30)
                    + min(0.15, sum(1 for a in anomalies if "private IP" in a) * 0.08)
                    + min(0.10, sum(1 for a in anomalies if "zero-second" in a) * 0.05)
                    + min(0.10, len(missing) * 0.05)
                    + min(0.05, max(0, hop_count - 8) * 0.02))

        verdict = ("FORGED"     if score >= 0.60
                   else "SUSPICIOUS" if score >= 0.25 or regressions
                   else "CLEAN")

        mitre = (["T1036.005", "T1584"] if verdict != "CLEAN" else [])
        hops_parsed = sum(1 for t in timestamps if t is not None)
        detail = (f"{len(regressions)} regression(s), {len(anomalies)} anomaly(s) "
                  f"across {hop_count} hop(s)")

        return HopForgeryResult(
            verdict=verdict, forgery_score=round(score, 3),
            hop_count=hop_count, hops_parsed=hops_parsed,
            regressions=regressions, anomalies=anomalies,
            mitre=mitre, detail=detail,
        )

    def _parse_ts(self, rcv: str) -> Optional[datetime]:
        m = re.search(r';\s*(.+)$', rcv.strip())
        if not m:
            return None
        raw = re.sub(r'\s*\([^)]*\)\s*$', '', m.group(1)).strip()
        for fmt in self._FMTS:
            try:
                dt = datetime.strptime(raw, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# 2.  BOT SEND PATTERN SCORER
#     Single-email mode: send hour, overnight flag.
#     Campaign mode: coefficient of variation of inter-send intervals.
#       CV < 0.10 → bot, CV < 0.40 → scripted_human, else human
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SendPatternResult:
    verdict:           str          # human | scripted_human | bot | insufficient_data
    cv:                Optional[float]
    interval_count:    int
    burst_count:       int          # pairs < 60 s apart
    round_intervals:   int          # intervals on round minutes (cron signature)
    overnight_sends:   int          # 00:00–05:59 local time
    send_hour:         Optional[int]
    is_business_hours: bool
    detail:            str
    mitre:             List[str]

    def to_dict(self):
        return {
            "verdict":           self.verdict,
            "cv":                round(self.cv, 3) if self.cv is not None else None,
            "interval_count":    self.interval_count,
            "burst_count":       self.burst_count,
            "round_intervals":   self.round_intervals,
            "overnight_sends":   self.overnight_sends,
            "send_hour":         self.send_hour,
            "is_business_hours": self.is_business_hours,
            "detail":            self.detail,
            "mitre":             self.mitre,
        }


class BotSendPatternScorer:

    _FMTS = [
        "%a, %d %b %Y %H:%M:%S %z",
        "%d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
    ]

    def score_single(self, msg) -> SendPatternResult:
        date_str = msg.get("Date", "").strip()
        send_hour, is_biz, overnight = None, False, 0
        for fmt in self._FMTS:
            try:
                dt = datetime.strptime(date_str, fmt)
                send_hour = dt.hour
                is_biz    = 9 <= dt.hour <= 17
                overnight = 1 if dt.hour <= 5 else 0
                break
            except ValueError:
                continue
        return SendPatternResult(
            verdict="insufficient_data", cv=None, interval_count=0,
            burst_count=0, round_intervals=0, overnight_sends=overnight,
            send_hour=send_hour, is_business_hours=is_biz,
            detail=f"Single email — hour={send_hour}, biz={is_biz}",
            mitre=[],
        )

    def score_campaign(self, datetimes: List[datetime]) -> SendPatternResult:
        if len(datetimes) < 2:
            return SendPatternResult(
                verdict="insufficient_data", cv=None, interval_count=0,
                burst_count=0, round_intervals=0, overnight_sends=0,
                send_hour=None, is_business_hours=False,
                detail="Fewer than 2 timestamps", mitre=[],
            )
        dts  = sorted(datetimes)
        ivs  = [(dts[i+1] - dts[i]).total_seconds() for i in range(len(dts)-1)]
        mean = sum(ivs) / len(ivs)
        cv   = (math.sqrt(sum((x-mean)**2 for x in ivs) / len(ivs)) / mean
                if mean > 0 else 0.0)
        bursts = sum(1 for iv in ivs if iv < 60)
        rounds = sum(1 for iv in ivs
                     if any(abs(iv % p) < 5 for p in (60, 300, 3600)))
        nights = sum(1 for dt in dts if dt.hour <= 5)
        biz    = sum(1 for dt in dts if 9 <= dt.hour <= 17)
        peak   = Counter(dt.hour for dt in dts).most_common(1)[0][0]

        verdict = ("bot"             if cv < 0.10
                   else "scripted_human" if cv < 0.40
                   else "human")
        mitre = (["T1059"] if verdict == "bot" else [])
        if nights > len(dts) * 0.5:
            mitre.append("T1583")

        return SendPatternResult(
            verdict=verdict, cv=round(cv, 3), interval_count=len(ivs),
            burst_count=bursts, round_intervals=rounds, overnight_sends=nights,
            send_hour=peak, is_business_hours=(biz > len(dts) * 0.5),
            detail=f"CV={cv:.3f}, mean_interval={mean:.0f}s, bursts={bursts}, rounds={rounds}",
            mitre=mitre,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 3.  AI CONTENT DETECTOR
#     Stylometric signals — no ML model required, interpretable in a paper.
#       Low type-token ratio → repetitive vocabulary (AI tendency)
#       Low sentence-length CV → uniform structure (AI tendency)
#       Low function-word ratio → fewer filler words (AI tendency)
#       Low bigram entropy → predictable sequences (AI tendency)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AIContentResult:
    verdict:             str      # human_likely | ai_likely | insufficient_text
    ai_probability:      float    # 0.0–1.0
    type_token_ratio:    Optional[float]
    avg_sentence_len:    Optional[float]
    sentence_len_cv:     Optional[float]
    function_word_ratio: Optional[float]
    bigram_entropy:      Optional[float]
    signals:             List[str]
    detail:              str

    def to_dict(self):
        return {
            "verdict":             self.verdict,
            "ai_probability":      round(self.ai_probability, 3),
            "type_token_ratio":    round(self.type_token_ratio, 3) if self.type_token_ratio is not None else None,
            "avg_sentence_len":    round(self.avg_sentence_len, 1) if self.avg_sentence_len is not None else None,
            "sentence_len_cv":     round(self.sentence_len_cv, 3)  if self.sentence_len_cv  is not None else None,
            "function_word_ratio": round(self.function_word_ratio, 3) if self.function_word_ratio is not None else None,
            "bigram_entropy":      round(self.bigram_entropy, 3)    if self.bigram_entropy   is not None else None,
            "signals":             self.signals,
            "detail":              self.detail,
        }


class AIContentDetector:

    _FW = frozenset([
        "the","a","an","of","in","on","at","to","for","with","by","from","and","or",
        "but","if","as","it","is","was","are","were","be","been","have","has","had",
        "do","does","did","will","would","could","should","may","might","shall","that",
        "this","these","those","i","we","you","he","she","they","me","us","him","her",
        "them","my","our","your","his","its","their","which","who","what","when","where",
    ])

    def detect(self, msg) -> AIContentResult:
        body = self._text_body(msg)
        tokens = re.findall(r'\b[a-z]+\b', body.lower()) if body else []
        if len(tokens) < 30:
            return AIContentResult(
                verdict="insufficient_text", ai_probability=0.0,
                type_token_ratio=None, avg_sentence_len=None,
                sentence_len_cv=None, function_word_ratio=None,
                bigram_entropy=None, signals=[],
                detail=f"Too short ({len(tokens)} words)",
            )

        ttr  = len(set(tokens)) / len(tokens)
        slen = [len(s.split()) for s in re.split(r'[.!?]+', body) if len(s.split()) >= 2]
        avg_sl = sum(slen) / len(slen) if slen else None
        sl_cv  = None
        if slen and avg_sl and avg_sl > 0:
            sl_cv = math.sqrt(sum((x - avg_sl)**2 for x in slen) / len(slen)) / avg_sl

        fwr = sum(1 for t in tokens if t in self._FW) / len(tokens)

        bgs    = list(zip(tokens, tokens[1:]))
        bg_cnt = Counter(bgs)
        n_bg   = len(bgs)
        entropy = (0.0 if n_bg == 0 else
                   -sum((c/n_bg) * math.log2(c/n_bg) for c in bg_cnt.values()))

        score   = 0.0
        signals = []

        if ttr < 0.45:
            score += 0.20
            signals.append(f"Low vocabulary diversity TTR={ttr:.2f} (AI: <0.45)")
        elif ttr > 0.70:
            signals.append(f"High vocabulary diversity TTR={ttr:.2f} — human signal")

        if sl_cv is not None:
            if sl_cv < 0.30:
                score += 0.25
                signals.append(f"Uniform sentence lengths CV={sl_cv:.2f} (AI: <0.30)")
            elif sl_cv > 0.60:
                signals.append(f"Variable sentence lengths CV={sl_cv:.2f} — human signal")

        if fwr < 0.30:
            score += 0.20
            signals.append(f"Low function-word ratio {fwr:.1%} (AI: <30%)")

        if entropy < 3.0:
            score += 0.20
            signals.append(f"Low bigram entropy {entropy:.2f} bits (AI: <3.0)")
        elif entropy > 6.0:
            signals.append(f"High entropy {entropy:.2f} bits — human signal")

        score   = min(1.0, score)
        verdict = "ai_likely" if score >= 0.50 else "human_likely"

        return AIContentResult(
            verdict=verdict, ai_probability=round(score, 3),
            type_token_ratio=round(ttr, 3),
            avg_sentence_len=round(avg_sl, 1) if avg_sl else None,
            sentence_len_cv=round(sl_cv, 3) if sl_cv else None,
            function_word_ratio=round(fwr, 3),
            bigram_entropy=round(entropy, 3),
            signals=signals,
            detail=f"tokens={len(tokens)}, TTR={ttr:.2f}, SL_CV={sl_cv:.2f if sl_cv else 'n/a'}, FWR={fwr:.2f}, H={entropy:.2f}",
        )

    def _text_body(self, msg) -> str:
        parts = []
        for part in (msg.walk() if msg.is_multipart() else [msg]):
            if part.get_content_type() == "text/plain":
                try:
                    raw = part.get_payload(decode=True)
                    if raw:
                        parts.append(raw.decode(part.get_content_charset() or "utf-8", errors="ignore"))
                except Exception:
                    pass
        if not parts:  # fallback: strip HTML
            for part in (msg.walk() if msg.is_multipart() else [msg]):
                if part.get_content_type() == "text/html":
                    try:
                        raw = part.get_payload(decode=True)
                        if raw:
                            text = raw.decode(part.get_content_charset() or "utf-8", errors="ignore")
                            text = re.sub(r'<[^>]+>', ' ', text)
                            parts.append(_html_unescape.unescape(text))
                    except Exception:
                        pass
        return re.sub(r'\s+', ' ', ' '.join(parts)).strip()


# ═══════════════════════════════════════════════════════════════════════════════
# 4.  TRACKING PIXEL DETECTOR
#     1×1 px img tags, display:none imgs, known tracker domains in img src/url
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TrackingPixelResult:
    found:              bool
    pixel_count:        int
    beacon_urls:        List[str]
    hidden_img_count:   int
    suspicious_domains: List[str]
    verdict:            str      # CLEAN | TRACKING | BEACON
    mitre:              List[str]
    detail:             str

    def to_dict(self):
        return {
            "found":              self.found,
            "pixel_count":        self.pixel_count,
            "beacon_urls":        self.beacon_urls[:10],
            "hidden_img_count":   self.hidden_img_count,
            "suspicious_domains": self.suspicious_domains[:10],
            "verdict":            self.verdict,
            "mitre":              self.mitre,
            "detail":             self.detail,
        }


class TrackingPixelDetector:

    _TRACKER_KW = {
        "mailchimp","sendgrid","mailgun","constantcontact","exacttarget",
        "pardot","marketo","hubspot","intercom","track.","open.","pixel.",
        "beacon.","click.","trk.","analytics.","measure.","postmaster.",
        "e.","em.","email.",
    }

    def detect(self, msg) -> TrackingPixelResult:
        body = self._html_body(msg)
        if not body:
            return TrackingPixelResult(False,0,[],0,[],"CLEAN",[],"No HTML body")

        pixels, hidden_imgs, beacon_urls, susp = [], 0, [], []

        for tag in re.findall(r'<img[^>]+>', body, re.IGNORECASE):
            wm = re.search(r'width\s*[=:]\s*["\']?\s*(\d+)', tag, re.IGNORECASE)
            hm = re.search(r'height\s*[=:]\s*["\']?\s*(\d+)', tag, re.IGNORECASE)
            w  = int(wm.group(1)) if wm else None
            h  = int(hm.group(1)) if hm else None
            is_pixel  = (w is not None and h is not None and w <= 3 and h <= 3)
            is_hidden = bool(re.search(
                r'(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)',
                tag, re.IGNORECASE))
            src_m = re.search(r'src\s*=\s*["\']([^"\']+)', tag, re.IGNORECASE)
            src   = src_m.group(1) if src_m else ""
            if is_pixel:
                pixels.append(src)
            if is_hidden:
                hidden_imgs += 1
            if (is_pixel or is_hidden) and src:
                beacon_urls.append(src)

        for dom in re.findall(r'https?://([^/"\'>\s]+)', body):
            for kw in self._TRACKER_KW:
                if kw in dom.lower() and dom.lower() not in susp:
                    susp.append(dom.lower())
                    break

        found   = bool(pixels or hidden_imgs or susp)
        verdict = ("BEACON" if susp else "TRACKING" if found else "CLEAN")
        mitre   = (["T1598"] if found else [])

        return TrackingPixelResult(
            found=found, pixel_count=len(pixels), beacon_urls=beacon_urls[:10],
            hidden_img_count=hidden_imgs, suspicious_domains=susp[:10],
            verdict=verdict, mitre=mitre,
            detail=f"{len(pixels)} pixel(s), {hidden_imgs} hidden img(s), {len(susp)} tracker domain(s)",
        )

    def _html_body(self, msg) -> str:
        for part in (msg.walk() if msg.is_multipart() else [msg]):
            if part.get_content_type() == "text/html":
                try:
                    raw = part.get_payload(decode=True)
                    if raw:
                        return raw.decode(part.get_content_charset() or "utf-8", errors="ignore")
                except Exception:
                    pass
        return ""


# ═══════════════════════════════════════════════════════════════════════════════
# 5.  HTML SMUGGLING DETECTOR
#     JS Blob URLs, executable data-URIs, atob(), eval(), fromCharCode
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HTMLSmugglingResult:
    found:           bool
    risk_score:      float
    findings:        List[str]
    blob_urls:       List[str]
    data_uris:       List[str]
    encoded_scripts: List[str]
    verdict:         str      # CLEAN | SUSPICIOUS | SMUGGLING
    mitre:           List[str]
    detail:          str

    def to_dict(self):
        return {
            "found":           self.found,
            "risk_score":      round(self.risk_score, 3),
            "findings":        self.findings,
            "blob_urls":       self.blob_urls[:5],
            "data_uris":       [d[:80]+"…" for d in self.data_uris[:3]],
            "encoded_scripts": [e[:60]+"…" for e in self.encoded_scripts[:3]],
            "verdict":         self.verdict,
            "mitre":           self.mitre,
            "detail":          self.detail,
        }


class HTMLSmugglingDetector:

    def detect(self, msg) -> HTMLSmugglingResult:
        body = self._full_html(msg)
        if not body:
            return HTMLSmugglingResult(False,0.0,[],[],[],[],"CLEAN",[],"No HTML body")

        findings, score = [], 0.0
        blob_urls, data_uris, enc_scripts = [], [], []

        # Blob URL / createObjectURL
        blobs = (re.findall(r'blob\s*:\s*https?://[^\s"\']+', body, re.IGNORECASE)
                 + re.findall(r'URL\.createObjectURL', body, re.IGNORECASE))
        if blobs:
            blob_urls = blobs[:10]
            findings.append(f"JS Blob URL / createObjectURL ({len(blobs)}) — T1027.006")
            score += 0.40

        # Executable data-URI
        duri = re.findall(
            r'data\s*:\s*(?:application/(?:octet-stream|x-msdownload|vnd\.[^;]+)'
            r'|text/(?:html|javascript)|application/javascript)[^"\'>\s]*',
            body, re.IGNORECASE)
        if duri:
            data_uris = duri[:5]
            findings.append(f"Executable data-URI ({len(duri)}) — T1027.006")
            score += 0.35

        # Base64 in <script> / atob()
        for sb in re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE):
            b64 = re.findall(r'[A-Za-z0-9+/]{64,}={0,2}', sb)
            if b64:
                enc_scripts.extend(b64[:3])
                findings.append(f"Base64 payload in <script> ({len(b64)} blob(s))")
                score += 0.25
                break
            if re.search(r'atob\s*\(', sb, re.IGNORECASE):
                findings.append("atob() decode in <script>")
                score += 0.30
                break

        # fromCharCode
        if re.search(r'fromCharCode\s*\(', body, re.IGNORECASE):
            findings.append("String.fromCharCode() obfuscation")
            score += 0.20

        # eval() with non-literal arg
        if len(re.findall(r'eval\s*\(\s*(?!true|false|null|\d)', body, re.IGNORECASE)) > 0:
            findings.append("eval() with non-literal argument")
            score += 0.20

        score   = min(1.0, score)
        found   = bool(findings)
        verdict = ("SMUGGLING"  if score >= 0.50 else
                   "SUSPICIOUS" if score >= 0.20 else "CLEAN")
        mitre   = (["T1027.006", "T1059.007"] if found else [])

        return HTMLSmugglingResult(
            found=found, risk_score=round(score, 3),
            findings=findings, blob_urls=blob_urls,
            data_uris=data_uris, encoded_scripts=enc_scripts,
            verdict=verdict, mitre=mitre,
            detail=f"risk={score:.2f}, blob={len(blob_urls)}, duri={len(data_uris)}, enc={len(enc_scripts)}",
        )

    def _full_html(self, msg) -> str:
        parts = []
        for part in (msg.walk() if msg.is_multipart() else [msg]):
            if part.get_content_type() in ("text/html", "application/xhtml+xml"):
                try:
                    raw = part.get_payload(decode=True)
                    if raw:
                        parts.append(raw.decode(part.get_content_charset() or "utf-8", errors="ignore"))
                except Exception:
                    pass
        return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════════════════
# 6.  HOMOGLYPH DOMAIN DETECTOR
#     Scans From, Reply-To, Return-Path headers + anchor hrefs for non-ASCII
#     lookalike characters substituting ASCII letters in domain names.
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HomoglyphResult:
    found:            bool
    suspect_domains:  List[Dict]   # {domain, homoglyphs, target_brand, source}
    affected_headers: List[str]
    verdict:          str          # CLEAN | HOMOGLYPH
    mitre:            List[str]
    detail:           str

    def to_dict(self):
        return {
            "found":            self.found,
            "suspect_domains":  self.suspect_domains[:10],
            "affected_headers": self.affected_headers,
            "verdict":          self.verdict,
            "mitre":            self.mitre,
            "detail":           self.detail,
        }


class HomoglyphDomainDetector:

    _BRANDS = [
        "google","microsoft","apple","amazon","paypal","ebay","facebook",
        "instagram","twitter","linkedin","dropbox","outlook","hotmail",
        "yahoo","gmail","icloud","netflix","spotify","bank","secure","login","account",
    ]

    def detect(self, msg) -> HomoglyphResult:
        domains: Dict[str, str] = {}  # domain → source header

        for hdr in ("From", "Reply-To", "Return-Path"):
            for dom in re.findall(r'@([a-zA-Z0-9\u0080-\uFFFF._-]+)', msg.get(hdr, "")):
                if dom not in domains:
                    domains[dom] = hdr

        # Anchor hrefs in HTML body
        body = self._html_body(msg)
        if body:
            for dom in re.findall(r'href\s*=\s*["\']https?://([^/"\']+)', body, re.IGNORECASE):
                if dom not in domains:
                    domains[dom] = "href"

        suspect, affected = [], set()
        for dom, source in domains.items():
            glyphs = self._find_glyphs(dom)
            if glyphs:
                brand = self._find_brand(dom)
                suspect.append({"domain": dom, "homoglyphs": glyphs,
                                 "target_brand": brand, "source": source})
                affected.add(source)

        found   = bool(suspect)
        verdict = "HOMOGLYPH" if found else "CLEAN"
        mitre   = (["T1036.001"] if found else [])

        return HomoglyphResult(
            found=found, suspect_domains=suspect,
            affected_headers=list(affected), verdict=verdict, mitre=mitre,
            detail=(f"{len(suspect)} suspicious domain(s) with Unicode lookalike char(s)"
                    if found else "No homoglyph domains detected"),
        )

    def _find_glyphs(self, domain: str) -> List[str]:
        out = []
        for ch in domain:
            if ord(ch) > 127:
                name = unicodedata.name(ch, "UNKNOWN")
                norm = unicodedata.normalize("NFKD", ch)
                out.append(f"U+{ord(ch):04X} '{ch}' ({name})"
                            + (f" → '{norm}'" if norm != ch else ""))
        return out

    def _find_brand(self, domain: str) -> Optional[str]:
        norm = unicodedata.normalize("NFKD", domain.lower())
        norm = "".join(c for c in norm if unicodedata.category(c) != "Mn")
        for b in self._BRANDS:
            if b in norm:
                return b + ".com"
        return None

    def _html_body(self, msg) -> str:
        for part in (msg.walk() if msg.is_multipart() else [msg]):
            if part.get_content_type() == "text/html":
                try:
                    raw = part.get_payload(decode=True)
                    if raw:
                        return raw.decode(part.get_content_charset() or "utf-8", errors="ignore")
                except Exception:
                    pass
        return ""


# ═══════════════════════════════════════════════════════════════════════════════
# 7.  ZERO-POINT FONT DETECTOR
#     font-size:0, display:none on text nodes, white-text-on-white-background
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ZeroFontResult:
    found:             bool
    zero_font_count:   int
    hidden_text_count: int
    white_on_white:    int
    suspect_snippets:  List[str]   # ≤5 offending HTML snippets (first 120 chars)
    verdict:           str         # CLEAN | HIDDEN_TEXT
    mitre:             List[str]
    detail:            str

    def to_dict(self):
        return {
            "found":             self.found,
            "zero_font_count":   self.zero_font_count,
            "hidden_text_count": self.hidden_text_count,
            "white_on_white":    self.white_on_white,
            "suspect_snippets":  [s[:120] for s in self.suspect_snippets[:5]],
            "verdict":           self.verdict,
            "mitre":             self.mitre,
            "detail":            self.detail,
        }


class ZeroPointFontDetector:

    def detect(self, msg) -> ZeroFontResult:
        body = self._html_body(msg)
        if not body:
            return ZeroFontResult(False,0,0,0,[],"CLEAN",[],"No HTML body")

        snippets = []

        # font-size: 0 / 0px / 0pt / 0em
        zf = re.findall(
            r'<[^>]+style\s*=\s*["\'][^"\']*font-size\s*:\s*0(?:px|pt|em)?[^"\']*["\'][^>]*>',
            body, re.IGNORECASE)
        snippets.extend(zf[:3])

        # display:none / visibility:hidden on text containers
        ht = re.findall(
            r'<(?:span|div|p|td|font|li)[^>]*style\s*=\s*["\'][^"\']*'
            r'(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"\']*["\'][^>]*>',
            body, re.IGNORECASE)
        snippets.extend(ht[:2])

        # white / #fff / #ffffff text
        wow = re.findall(
            r'<[^>]+style\s*=\s*["\'][^"\']*color\s*:\s*(?:#fff(?:fff)?|white)\b[^"\']*["\'][^>]*>',
            body, re.IGNORECASE)
        snippets.extend(wow[:2])

        found   = bool(zf or ht or wow)
        verdict = "HIDDEN_TEXT" if found else "CLEAN"
        mitre   = (["T1036"] if found else [])

        return ZeroFontResult(
            found=found, zero_font_count=len(zf),
            hidden_text_count=len(ht), white_on_white=len(wow),
            suspect_snippets=list(dict.fromkeys(snippets))[:5],
            verdict=verdict, mitre=mitre,
            detail=f"zero_font={len(zf)}, hidden_text={len(ht)}, white_on_white={len(wow)}",
        )

    def _html_body(self, msg) -> str:
        for part in (msg.walk() if msg.is_multipart() else [msg]):
            if part.get_content_type() == "text/html":
                try:
                    raw = part.get_payload(decode=True)
                    if raw:
                        return raw.decode(part.get_content_charset() or "utf-8", errors="ignore")
                except Exception:
                    pass
        return ""


# ═══════════════════════════════════════════════════════════════════════════════
# 8.  AGGREGATE — ForensicScanSummary
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ForensicScanSummary:
    hop_forgery:    HopForgeryResult
    send_pattern:   SendPatternResult
    ai_content:     AIContentResult
    tracking_pixel: TrackingPixelResult
    html_smuggling: HTMLSmugglingResult
    homoglyph:      HomoglyphResult
    zero_font:      ZeroFontResult
    risk_score:     float          # 0.0–1.0 composite
    risk_label:     str            # LOW | MEDIUM | HIGH | CRITICAL
    all_mitre:      List[str]      # deduplicated
    flags:          List[str]      # one-line flag per positive finding
    scanned_at:     str

    def to_dict(self) -> dict:
        return {
            "scanned_at":     self.scanned_at,
            "risk_score":     round(self.risk_score, 3),
            "risk_label":     self.risk_label,
            "all_mitre":      self.all_mitre,
            "flags":          self.flags,
            "hop_forgery":    self.hop_forgery.to_dict(),
            "send_pattern":   self.send_pattern.to_dict(),
            "ai_content":     self.ai_content.to_dict(),
            "tracking_pixel": self.tracking_pixel.to_dict(),
            "html_smuggling": self.html_smuggling.to_dict(),
            "homoglyph":      self.homoglyph.to_dict(),
            "zero_font":      self.zero_font.to_dict(),
        }

    def report(self) -> str:
        lines = [
            "=" * 62,
            f"  FORENSIC SCAN  {self.scanned_at[:16]}",
            f"  Risk: {self.risk_label}  ({self.risk_score:.0%})",
            "=" * 62,
        ]
        for f in self.flags:
            lines.append(f"  ⚑  {f}")
        if not self.flags:
            lines.append("  ✓  No forensic threats detected")
        if self.all_mitre:
            lines.append(f"  MITRE: {', '.join(self.all_mitre)}")
        lines.append("=" * 62)
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

def run_forensic_scan(
    raw_email: str,
    send_timestamps: Optional[List[datetime]] = None,
    verbose: bool = False,
) -> ForensicScanSummary:
    """
    Run all seven detectors on a raw RFC-2822 email string.

    Parameters
    ----------
    raw_email        : Full email text (headers + body).
    send_timestamps  : Optional list of datetimes from the same campaign —
                       enables bot-send CV scoring. Single-email mode used
                       if omitted or <2 entries.
    verbose          : Print summary to stdout.

    Returns
    -------
    ForensicScanSummary  (call .to_dict() for JSON output)
    """
    try:
        msg = _email_lib.message_from_string(raw_email)
    except Exception as exc:
        return _empty_summary(f"Parse error: {exc}")

    hop   = HopTimestampForgeryDetector().detect(msg)
    send  = (BotSendPatternScorer().score_campaign(send_timestamps)
             if send_timestamps and len(send_timestamps) >= 2
             else BotSendPatternScorer().score_single(msg))
    ai    = AIContentDetector().detect(msg)
    pixel = TrackingPixelDetector().detect(msg)
    smug  = HTMLSmugglingDetector().detect(msg)
    hom   = HomoglyphDomainDetector().detect(msg)
    font  = ZeroPointFontDetector().detect(msg)

    # Composite risk — weighted sum
    risk = min(1.0,
               hop.forgery_score                   * 0.25
               + smug.risk_score                   * 0.30
               + (1.0 if pixel.found else 0.0)     * 0.10
               + (1.0 if hom.found   else 0.0)     * 0.20
               + (1.0 if font.found  else 0.0)     * 0.10
               + ai.ai_probability                 * 0.05)

    risk_label = ("CRITICAL" if risk >= 0.75 else
                  "HIGH"     if risk >= 0.50 else
                  "MEDIUM"   if risk >= 0.25 else "LOW")

    flags = []
    if hop.verdict   != "CLEAN":        flags.append(f"Hop forgery: {hop.verdict} — {hop.detail}")
    if send.verdict  == "bot":          flags.append(f"Bot send pattern (CV={send.cv:.3f})")
    elif send.verdict == "scripted_human": flags.append(f"Scripted send pattern (CV={send.cv:.3f})")
    if ai.verdict    == "ai_likely":    flags.append(f"AI-generated content (p={ai.ai_probability:.0%})")
    if pixel.found:                     flags.append(f"Tracking pixel: {pixel.detail}")
    if smug.found:                      flags.append(f"HTML smuggling: {smug.detail}")
    if hom.found:                       flags.append(f"Homoglyph domain: {hom.detail}")
    if font.found:                      flags.append(f"Hidden text: {font.detail}")

    all_mitre = sorted(set(
        hop.mitre + send.mitre + pixel.mitre + smug.mitre + hom.mitre + font.mitre
    ))

    summary = ForensicScanSummary(
        hop_forgery=hop, send_pattern=send, ai_content=ai,
        tracking_pixel=pixel, html_smuggling=smug,
        homoglyph=hom, zero_font=font,
        risk_score=round(risk, 3), risk_label=risk_label,
        all_mitre=all_mitre, flags=flags,
        scanned_at=datetime.now().isoformat(),
    )

    if verbose:
        print(summary.report())

    return summary


def _empty_summary(reason: str) -> ForensicScanSummary:
    e_hop   = HopForgeryResult("ERROR", 0.0, 0, 0, [], [], [], reason)
    e_send  = SendPatternResult("insufficient_data", None, 0, 0, 0, 0, None, False, reason, [])
    e_ai    = AIContentResult("insufficient_text", 0.0, None, None, None, None, None, [], reason)
    e_pix   = TrackingPixelResult(False, 0, [], 0, [], "CLEAN", [], reason)
    e_smug  = HTMLSmugglingResult(False, 0.0, [], [], [], [], "CLEAN", [], reason)
    e_hom   = HomoglyphResult(False, [], [], "CLEAN", [], reason)
    e_font  = ZeroFontResult(False, 0, 0, 0, [], "CLEAN", [], reason)
    return ForensicScanSummary(
        e_hop, e_send, e_ai, e_pix, e_smug, e_hom, e_font,
        risk_score=0.0, risk_label="LOW",
        all_mitre=[], flags=[reason],
        scanned_at=datetime.now().isoformat(),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys, json

    if len(sys.argv) < 2:
        print("Usage: python emailForensicsScanner.py <email.eml> [--json]")
        sys.exit(1)

    try:
        raw = open(sys.argv[1], "r", errors="ignore").read()
    except FileNotFoundError:
        print(f"File not found: {sys.argv[1]}")
        sys.exit(1)

    result = run_forensic_scan(raw, verbose="--json" not in sys.argv)

    if "--json" in sys.argv:
        print(json.dumps(result.to_dict(), indent=2))
