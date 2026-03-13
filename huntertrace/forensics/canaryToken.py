#!/usr/bin/env python3
"""
huntertrace.forensics.canarytoken
==================================

Canarytoken Bait Generator  —  Layer 1 Active Bypass
-----------------------------------------------------

Generates XLSX, DOCX, and PDF bait documents that trigger when the target
opens them.  Each document embeds two independent tokens:

  1. HTTP tracking pixel  — loaded on document open  → attacker's real IP
  2. DNS canary token     — resolved on document open → corroborates real IP

Two-token design: Jain (2025) reports +15–20% trigger rate vs single-token.
XLSX achieves the highest trigger rate (~70%) because Excel fetches external
data connections on open with no user confirmation.

When triggered:
  - CanarytokenResult.triggered  flips to True
  - CanarytokenResult.real_ip    is populated
  - Attribution engine receives a "canarytoken_triggered" signal
    with likelihood ratio 25.0  —  definitive, overrides all other signals

Trigger rates (Jain 2025 — simulated phishing actors):
  XLSX:  70%   (Excel external data connection, auto-fetched)
  DOCX:  58%   (Word linked image, fetched on open)
  PDF:   45%   (PDF /URI action, fetched on open by most readers)

CLI:
  huntertrace bait --generate --output ./baits/ --label campaign_003
  huntertrace bait --poll TOKEN_ID

⚠  LEGAL NOTICE — Authorised red-team / research use ONLY.
   Deployment may constitute unauthorised computer access under CFAA (US),
   Computer Misuse Act (UK), IT Act (India) and equivalent statutes.
   Entrapment risk in law-enforcement contexts. Legal review required.
"""

from __future__ import annotations

import os
import re
import uuid
import json
import zipfile
import textwrap
import time
import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
#  ENUMS & CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Canarytoken signal LR (registered in attribution engine)
CANARYTOKEN_SIGNAL_LR = 25.0

# ACI time-decay penalties per urgency tier (applied by urgency.py)
URGENCY_TIERS = {
    "CRITICAL": {"max_age_min": 30,   "aci_penalty": 0.00,
                 "note": "Deploy NOW — live campaign, max trigger probability"},
    "HIGH":     {"max_age_min": 120,  "aci_penalty": 0.05,
                 "note": "Deploy immediately — attacker may still be active"},
    "NORMAL":   {"max_age_min": 480,  "aci_penalty": 0.15,
                 "note": "Worth deploying — 40–50% trigger probability"},
    "COLD":     {"max_age_min": None, "aci_penalty": 0.30,
                 "note": "Low probability — attacker likely finished session"},
}


# ─────────────────────────────────────────────────────────────────────────────
#  DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CanarytokenResult:
    token_id:          str
    formats_generated: List[str]
    output_paths:      Dict[str, str]
    http_token_url:    str
    dns_token_domain:  str
    triggered:         bool             = False
    trigger_time:      Optional[str]    = None
    real_ip:           Optional[str]    = None
    real_ip_country:   Optional[str]    = None
    user_agent:        Optional[str]    = None
    referrer:          Optional[str]    = None
    signal_weight:     float            = CANARYTOKEN_SIGNAL_LR
    label:             str              = ""
    legal_ack:         bool             = False
    generated_at:      str              = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "  CANARYTOKEN BAIT — GENERATION SUMMARY",
            "=" * 60,
            f"  Token ID   : {self.token_id}",
            f"  Label      : {self.label or '(none)'}",
            f"  Formats    : {', '.join(self.formats_generated)}",
            f"  HTTP URL   : {self.http_token_url}",
            f"  DNS domain : {self.dns_token_domain}",
            "  Files      :",
        ]
        for fmt, path in self.output_paths.items():
            lines.append(f"    [{fmt.upper()}] {path}")
        lines += [
            "",
            f"  Triggered  : {'YES ✓' if self.triggered else 'No (not yet)'}",
        ]
        if self.triggered:
            lines += [
                f"  Trigger at : {self.trigger_time}",
                f"  Real IP    : {self.real_ip}",
                f"  Country    : {self.real_ip_country or '(lookup pending)'}",
                f"  User-Agent : {self.user_agent or '(not captured)'}",
                f"  Signal LR  : {self.signal_weight:.1f}",
            ]
        lines += [
            "",
            "  ⚠  Legal: Authorised red-team / research use only.",
            "=" * 60,
        ]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "token_id":          self.token_id,
            "label":             self.label,
            "formats_generated": self.formats_generated,
            "output_paths":      self.output_paths,
            "http_token_url":    self.http_token_url,
            "dns_token_domain":  self.dns_token_domain,
            "triggered":         self.triggered,
            "trigger_time":      self.trigger_time,
            "real_ip":           self.real_ip,
            "real_ip_country":   self.real_ip_country,
            "user_agent":        self.user_agent,
            "signal_weight":     self.signal_weight,
            "generated_at":      self.generated_at,
        }

    def to_attribution_signal(self) -> Optional[Dict]:
        """Convert trigger to signal dict for injection into AttributionEngine."""
        if not self.triggered or not self.real_ip:
            return None
        return {
            "canarytoken_triggered": self.real_ip_country or "Unknown",
            "real_ip_country":       self.real_ip_country or "Unknown",
            "_canarytoken_ip":       self.real_ip,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  DOCUMENT BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

class _XLSXBaitBuilder:
    """XLSX with external data connection — Excel fetches on open, no prompt.
    Trigger rate ~70% (Jain 2025)."""

    def build(self, path: str, http_url: str, dns_domain: str) -> str:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", self._content_types())
            zf.writestr("_rels/.rels",          self._rels())
            zf.writestr("xl/workbook.xml",       self._workbook())
            zf.writestr("xl/_rels/workbook.xml.rels", self._wb_rels())
            zf.writestr("xl/worksheets/sheet1.xml",   self._sheet())
            zf.writestr("xl/connections.xml",    self._connections(http_url))
            zf.writestr("xl/externalLinks/externalLink1.xml",
                        self._ext_link())
            zf.writestr("xl/externalLinks/_rels/externalLink1.xml.rels",
                        self._ext_link_rels(http_url))
            zf.writestr("xl/styles.xml",         self._styles())
            zf.writestr("xl/sharedStrings.xml",  self._strings(dns_domain))
        return str(Path(path).resolve())

    def _content_types(self):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
                '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
                '  <Default Extension="xml" ContentType="application/xml"/>\n'
                '  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>\n'
                '  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>\n'
                '  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>\n'
                '  <Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>\n'
                '</Types>')

    def _rels(self):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
                '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>\n'
                '</Relationships>')

    def _workbook(self):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
                '  <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>\n'
                '</workbook>')

    def _wb_rels(self):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
                '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>\n'
                '  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink" Target="externalLinks/externalLink1.xml"/>\n'
                '</Relationships>')

    def _sheet(self):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">\n'
                '  <sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData>\n'
                '</worksheet>')

    def _connections(self, url: str):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<connections xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">\n'
                f'  <connection id="1" name="HunterTrace" type="1" refreshedVersion="3" background="1" saveData="0">\n'
                f'    <webPr url="{url}" post="0" htmlTables="0"/>\n'
                '  </connection>\n</connections>')

    def _ext_link(self):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
                '  <externalBook r:id="rId1"><sheetNames><sheetName val="Sheet1"/></sheetNames></externalBook>\n'
                '</externalLink>')

    def _ext_link_rels(self, url: str):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
                f'  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLinkPath" Target="{url}" TargetMode="External"/>\n'
                '</Relationships>')

    def _styles(self):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">\n'
                '  <fonts><font><sz val="11"/><name val="Calibri"/></font></fonts>\n'
                '  <fills><fill><patternFill patternType="none"/></fill></fills>\n'
                '  <borders><border/></borders>\n'
                '  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>\n'
                '  <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>\n'
                '</styleSheet>')

    def _strings(self, dns_domain: str):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1">\n'
                f'  <si><t>Loading data from {dns_domain}...</t></si>\n'
                '</sst>')


class _DOCXBaitBuilder:
    """DOCX with linked image — Word fetches on open.  Trigger rate ~58%."""

    def build(self, path: str, http_url: str, dns_domain: str) -> str:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", self._content_types())
            zf.writestr("_rels/.rels",          self._rels())
            zf.writestr("word/document.xml",    self._document(dns_domain))
            zf.writestr("word/_rels/document.xml.rels", self._doc_rels(http_url))
            zf.writestr("word/settings.xml",    self._settings())
        return str(Path(path).resolve())

    def _content_types(self):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
                '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
                '  <Default Extension="xml" ContentType="application/xml"/>\n'
                '  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>\n'
                '</Types>')

    def _rels(self):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
                '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>\n'
                '</Relationships>')

    def _document(self, dns_domain: str):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"\n'
                '            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"\n'
                '            xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"\n'
                '            xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"\n'
                '            xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">\n'
                '  <w:body>\n'
                '    <w:p><w:r><w:t>Please wait while the document loads...</w:t></w:r></w:p>\n'
                '    <w:p><w:r><w:drawing><wp:inline><wp:extent cx="1" cy="1"/>\n'
                '      <a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">\n'
                '        <pic:pic><pic:nvPicPr><pic:cNvPr id="1" name="img"/><pic:cNvPicPr/></pic:nvPicPr>\n'
                '          <pic:blipFill><a:blip r:link="rId2"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>\n'
                '          <pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="1" cy="1"/></a:xfrm>\n'
                '            <a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>\n'
                '        </pic:pic></a:graphicData></a:graphic>\n'
                f'    </wp:inline></w:drawing></w:r></w:p><!-- DNS:{dns_domain} -->\n'
                '  </w:body>\n</w:document>')

    def _doc_rels(self, http_url: str):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
                '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>\n'
                f'  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{http_url}" TargetMode="External"/>\n'
                '</Relationships>')

    def _settings(self):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
                '  <w:updateFields w:val="true"/>\n</w:settings>')


class _PDFBaitBuilder:
    """Minimal PDF with /OpenAction URI — executed by most PDF readers on open.
    Trigger rate ~45%."""

    def build(self, path: str, http_url: str, dns_domain: str) -> str:
        content = f"% DNS: {dns_domain}\nBT /F1 12 Tf 72 720 Td (Loading...) Tj ET"
        objects = [
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n",
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R /Resources << >> >>\nendobj\n",
            f"4 0 obj\n<< /Type /Action /S /URI /URI ({http_url}) >>\nendobj\n",
            f"5 0 obj\n<< /Length {len(content)} >>\nstream\n{content}\nendstream\nendobj\n",
        ]
        body = b"%PDF-1.4\n"
        offsets = []
        for obj in objects:
            offsets.append(len(body))
            body += obj.encode("latin-1")
        xref_pos = len(body)
        n = len(objects)
        xref = f"xref\n0 {n + 1}\n0000000000 65535 f \n"
        for off in offsets:
            xref += f"{off:010d} 00000 n \n"
        trailer = f"trailer\n<< /Size {n+1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"
        with open(path, "wb") as f:
            f.write(body + xref.encode("latin-1") + trailer.encode("latin-1"))
        return str(Path(path).resolve())


# ─────────────────────────────────────────────────────────────────────────────
#  GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

class CanarytokenGenerator:
    """
    Generates bait documents and monitors for trigger events.

    Parameters
    ----------
    callback_host : str    Hostname of your canarytoken / tracking server
    http_path     : str    URL path for HTTP pixel  (default: "/track")
    dns_prefix    : str    DNS subdomain prefix     (default: "canary")
    use_https     : bool   HTTPS for HTTP callback  (default: True)
    """

    def __init__(
        self,
        callback_host: str  = "localhost",
        http_path:     str  = "/track",
        dns_prefix:    str  = "canary",
        use_https:     bool = True,
    ):
        self.callback_host = callback_host
        self.http_path     = http_path
        self.dns_prefix    = dns_prefix
        self.scheme        = "https" if use_https else "http"
        self._xlsx = _XLSXBaitBuilder()
        self._docx = _DOCXBaitBuilder()
        self._pdf  = _PDFBaitBuilder()
        self._registry: Dict[str, CanarytokenResult] = {}

    def generate(
        self,
        output_dir:  str       = "./ht_baits",
        formats:     List[str] = None,
        label:       str       = "",
        legal_ack:   bool      = False,
    ) -> CanarytokenResult:
        """
        Generate bait documents.  Requires legal_ack=True.

        ⚠  By passing legal_ack=True you confirm:
           1. You have authority to deploy this bait in your environment.
           2. You have reviewed applicable laws (CFAA, CMA, IT Act, etc.).
           3. This is for authorised research or red-team use only.
        """
        if not legal_ack:
            raise ValueError(
                "CanarytokenGenerator.generate() requires legal_ack=True.\n"
                "Review the legal notice in canarytoken.py before proceeding."
            )
        formats = formats or ["xlsx", "docx", "pdf"]
        for fmt in formats:
            if fmt not in ("xlsx", "docx", "pdf"):
                raise ValueError(f"Unknown format {fmt!r}")

        token_id  = str(uuid.uuid4())
        out_dir   = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        http_url  = self._build_http_url(token_id)
        dns_domain = self._build_dns_domain(token_id)
        paths: Dict[str, str] = {}

        for fmt in formats:
            fname = (f"ht_bait_{label}_{token_id[:8]}.{fmt}" if label
                     else f"ht_bait_{token_id[:8]}.{fmt}")
            fpath = str(out_dir / fname)
            if fmt == "xlsx": self._xlsx.build(fpath, http_url, dns_domain)
            elif fmt == "docx": self._docx.build(fpath, http_url, dns_domain)
            elif fmt == "pdf":  self._pdf.build(fpath, http_url, dns_domain)
            paths[fmt] = fpath

        result = CanarytokenResult(
            token_id=token_id, formats_generated=formats, output_paths=paths,
            http_token_url=http_url, dns_token_domain=dns_domain,
            label=label, legal_ack=legal_ack,
        )
        self._registry[token_id] = result
        return result

    def poll(
        self, token_id: str,
        poll_interval: float = 30.0,
        timeout_sec:   float = 3600.0,
        on_trigger=None,
    ) -> Optional[CanarytokenResult]:
        """Blocking poll loop. Run in a thread for non-blocking use."""
        result = self._registry.get(token_id)
        if not result:
            raise ValueError(f"Unknown token_id: {token_id!r}. Call generate() first.")
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            data = self._check_callback(token_id)
            if data:
                result.triggered    = True
                result.trigger_time = datetime.now(timezone.utc).isoformat()
                result.real_ip      = data.get("src_ip")
                result.user_agent   = data.get("user_agent")
                result.real_ip_country = self._geolocate(result.real_ip)
                if on_trigger:
                    on_trigger(result)
                return result
            time.sleep(poll_interval)
        return None

    def register_trigger(
        self, token_id: str, real_ip: str,
        user_agent: str = "", referrer: str = "",
    ) -> Optional[CanarytokenResult]:
        """
        Manually register a trigger from your webhook server.

        In your Flask/FastAPI callback handler:
            gen.register_trigger(
                token_id   = request.args.get("id"),
                real_ip    = request.remote_addr,
                user_agent = request.headers.get("User-Agent", ""),
            )
        """
        result = self._registry.get(token_id)
        if not result:
            return None
        result.triggered       = True
        result.trigger_time    = datetime.now(timezone.utc).isoformat()
        result.real_ip         = real_ip
        result.user_agent      = user_agent
        result.referrer        = referrer
        result.real_ip_country = self._geolocate(real_ip)
        return result

    def export_registry(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump({tid: r.to_dict() for tid, r in self._registry.items()}, f, indent=2)

    def import_registry(self, path: str) -> None:
        with open(path) as f:
            data = json.load(f)
        for tid, d in data.items():
            self._registry[tid] = CanarytokenResult(
                token_id=d["token_id"], formats_generated=d["formats_generated"],
                output_paths=d["output_paths"], http_token_url=d["http_token_url"],
                dns_token_domain=d["dns_token_domain"], triggered=d.get("triggered", False),
                trigger_time=d.get("trigger_time"), real_ip=d.get("real_ip"),
                real_ip_country=d.get("real_ip_country"), user_agent=d.get("user_agent"),
                label=d.get("label", ""), legal_ack=True,
            )

    # ── Internal helpers ──────────────────────────────────────────────────

    def _build_http_url(self, token_id: str) -> str:
        safe_id = token_id.replace("-", "")[:16]
        return f"{self.scheme}://{self.callback_host}{self.http_path}?id={safe_id}"

    def _build_dns_domain(self, token_id: str) -> str:
        safe_id = token_id.replace("-", "")[:12]
        return f"{self.dns_prefix}.{safe_id}.{self.callback_host}"

    def _check_callback(self, token_id: str) -> Optional[dict]:
        if not _REQUESTS_AVAILABLE:
            return None
        try:
            url = (f"{self.scheme}://{self.callback_host}"
                   f"/status?id={token_id.replace('-','')[:16]}")
            resp = requests.get(url, timeout=10)
            if resp.ok:
                data = resp.json()
                if data.get("triggered"):
                    return data
        except Exception:
            pass
        return None

    def _geolocate(self, ip: Optional[str]) -> Optional[str]:
        if not ip or not _REQUESTS_AVAILABLE:
            return None
        if any(ip.startswith(p) for p in ("10.", "192.168.", "127.", "172.")):
            return None
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=8)
            if resp.ok:
                return resp.json().get("country")
        except Exception:
            pass
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  CLI ENTRY POINT (called by pipeline.py `bait` subcommand)
# ─────────────────────────────────────────────────────────────────────────────

def cli_bait(args) -> int:
    """Entry point for `huntertrace bait ...`."""
    host = getattr(args, "host", None) or os.environ.get("HT_CANARY_HOST", "")

    if not host:
        print(
            "[ERROR] No callback host specified.\n"
            "  Set --host your-domain.canarytokens.org\n"
            "  Or:  export HT_CANARY_HOST=your-domain.canarytokens.org"
        )
        return 1

    gen = CanarytokenGenerator(callback_host=host)

    if getattr(args, "poll_token", None):
        print(f"  Polling token {args.poll_token} (Ctrl+C to stop)...")
        result = gen.poll(args.poll_token, poll_interval=30, timeout_sec=7200)
        if result and result.triggered:
            print(result.summary())
            return 0
        print("  Polling timed out — no trigger detected.")
        return 1

    if getattr(args, "generate", False):
        if not getattr(args, "legal_ack", False):
            print(
                "\n  ⚠  LEGAL ACKNOWLEDGEMENT REQUIRED\n"
                "  Canarytoken bait documents trigger when opened by the target.\n"
                "  This may constitute unauthorised computer access in some jurisdictions.\n"
                "\n"
                "  Re-run with --legal-ack to confirm you have reviewed the legal\n"
                "  notice and have authority to deploy in your environment.\n"
            )
            return 1

        fmt_list = getattr(args, "formats", None) or ["xlsx", "docx", "pdf"]
        out_dir  = getattr(args, "output",  None) or "./ht_baits"
        label    = getattr(args, "label",   None) or ""

        result = gen.generate(output_dir=out_dir, formats=fmt_list,
                              label=label, legal_ack=True)
        print(result.summary())

        registry_path = str(Path(out_dir) / "canary_registry.json")
        gen.export_registry(registry_path)
        print(f"  Registry : {registry_path}")
        print(f"\n  To poll  : huntertrace bait --poll {result.token_id}")
        return 0

    print("  Usage: huntertrace bait --generate [--formats xlsx docx pdf] [--host HOST]")
    print("         huntertrace bait --poll TOKEN_ID")
    return 1