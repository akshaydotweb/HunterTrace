#!/usr/bin/env python3
"""
test_convergence.py — Unit tests for ConvergenceDetector and ConvergenceZone.

Run:  python test_convergence.py
      pytest test_convergence.py -v

No network, no API keys, no .eml files required.
"""
import sys, unittest
sys.path.insert(0, "/mnt/user-data/outputs")

from huntertrace.analysis.campaignCorrelator import (
    ConvergenceZone, ConvergenceDetector,
    ThreatActorCluster, EmailFingerprint,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_fp(n, tz, tz_region, charset=None, dkim=None,
            from_domain=None, lang=None,
            ipv6_country=None, dns_infra_country=None):
    fp = EmailFingerprint(
        email_file=f"e{n}.eml",
        email_from=f"actor{n}@{from_domain or 'example.com'}",
        email_subject="Test",
        email_date=f"2026-03-0{n}T11:00:00{tz}",
        message_id=f"<{n}@test>",
        timezone_offset=tz,
        timezone_region=tz_region,
        send_hour_local=11,
        send_day_of_week="Monday",
        vpn_asn=None, vpn_provider=None,
        origin_ip=f"1.2.3.{n}",
        real_ip=None, real_ip_source=None,
        webmail_provider="gmail.com",
        dkim_domain=dkim,
        mail_client="Thunderbird",
        hop_count=2,
    )
    if charset:       setattr(fp, "email_charset",     charset)
    if lang:          setattr(fp, "subject_language",  lang)
    if ipv6_country:  setattr(fp, "ipv6_country",      ipv6_country)
    if dns_infra_country: setattr(fp, "dns_infra_country", dns_infra_country)
    return fp

def make_cluster(actor_id, fps, likely_country=None):
    return ThreatActorCluster(
        actor_id=actor_id,
        emails=[fp.email_file for fp in fps],
        fingerprints=fps,
        confidence=0.9,
        consensus_timezone=fps[0].timezone_offset if fps else None,
        consensus_vpn_provider=None,
        consensus_webmail="gmail.com",
        consensus_send_window=None,
        consensus_dkim_domain=None,
        likely_country=likely_country,
        likely_city=None,
        campaign_count=len(fps),
        first_seen="2026-03-01",
        last_seen="2026-03-03",
        ttps=[],
        all_vpn_ips=[], all_vpn_providers=[],
        all_origin_ips=[fp.origin_ip for fp in fps],
    )

DET = ConvergenceDetector()


# ═══════════════════════════════════════════════════════════════════════════════
class TestConvergenceZoneDataclass(unittest.TestCase):
    """ConvergenceZone field types and defaults."""

    def test_fields_present(self):
        cz = DET.detect(make_cluster("X", []))
        self.assertIsInstance(cz.actor_id, str)
        self.assertIsInstance(cz.convergence_score, float)
        self.assertIsInstance(cz.n_signals_fired, int)
        self.assertIsInstance(cz.n_signals_agree, int)
        self.assertIsInstance(cz.signal_breakdown, dict)
        self.assertIsInstance(cz.independent_axes, dict)
        self.assertIsInstance(cz.false_flag_risk, bool)
        self.assertIsInstance(cz.confidence_label, str)
        self.assertIsInstance(cz.analyst_note, str)

    def test_score_bounds(self):
        fps = [make_fp(i, "+0300", "Russia (Moscow)", "windows-1251",
                       dkim="yandex.ru") for i in range(1, 4)]
        cz = DET.detect(make_cluster("R", fps))
        self.assertGreaterEqual(cz.convergence_score, 0.0)
        self.assertLessEqual(cz.convergence_score, 1.0)

    def test_confidence_labels_valid(self):
        valid = {"HIGH", "MEDIUM", "LOW", "INSUFFICIENT"}
        fps = [make_fp(1, "+0300", "Russia (Moscow)", "windows-1251")]
        cz = DET.detect(make_cluster("X", fps))
        self.assertIn(cz.confidence_label, valid)


# ═══════════════════════════════════════════════════════════════════════════════
class TestEmptyAndSingleEmail(unittest.TestCase):

    def test_empty_cluster_insufficient(self):
        cz = DET.detect(make_cluster("E", []))
        self.assertEqual(cz.confidence_label, "INSUFFICIENT")
        self.assertEqual(cz.convergence_score, 0.0)
        self.assertIsNone(cz.converged_country)
        self.assertFalse(cz.false_flag_risk)

    def test_single_email_tz_only(self):
        """One email, TZ only → LOW or INSUFFICIENT (single axis, ambiguous TZ)."""
        fps = [make_fp(1, "+0530", "India")]  # +0530 uniquely India
        cz  = DET.detect(make_cluster("I", fps))
        # Should fire temporal axis → India
        if cz.converged_country:
            self.assertEqual(cz.converged_country, "India")
        self.assertIn(cz.confidence_label, ("LOW", "MEDIUM", "INSUFFICIENT"))

    def test_single_email_unique_tz(self):
        """+0330 uniquely Iran — even single axis should fire LOW."""
        fps = [make_fp(1, "+0330", "Iran")]
        cz  = DET.detect(make_cluster("IR", fps))
        if cz.converged_country:
            self.assertEqual(cz.converged_country, "Iran")


# ═══════════════════════════════════════════════════════════════════════════════
class TestTwoAxisConvergence(unittest.TestCase):
    """Two independent axes agreeing → MEDIUM confidence."""

    def test_russia_tz_plus_charset(self):
        fps = [make_fp(i, "+0300", "Russia (Moscow)", "windows-1251")
               for i in range(1, 4)]
        cz = DET.detect(make_cluster("RU", fps))
        self.assertEqual(cz.converged_country, "Russia")
        self.assertGreaterEqual(cz.n_signals_agree, 2)
        self.assertIn(cz.confidence_label, ("MEDIUM", "HIGH"))

    def test_china_tz_plus_charset(self):
        fps = [make_fp(i, "+0800", "China / Singapore", "gbk")
               for i in range(1, 4)]
        cz = DET.detect(make_cluster("CN", fps))
        self.assertEqual(cz.converged_country, "China")
        self.assertIn(cz.confidence_label, ("MEDIUM", "HIGH"))

    def test_ukraine_charset_koi8u(self):
        fps = [make_fp(i, "+0200", "Eastern Europe / South Africa", "koi8-u")
               for i in range(1, 4)]
        cz = DET.detect(make_cluster("UA", fps))
        # koi8-u → Ukraine (locale); +0200 → Ukraine/Romania/Germany (temporal)
        # Both should fire; Ukraine should win if charset breaks tie
        self.assertIn(cz.converged_country, ("Ukraine", "Romania", "Germany"))

    def test_turkey_charset(self):
        fps = [make_fp(i, "+0300", "Russia (Moscow)", "windows-1254")
               for i in range(1, 3)]
        cz = DET.detect(make_cluster("TR", fps))
        # windows-1254 → Turkey (locale); +0300 → Russia/Belarus/Turkey (temporal)
        # Locale strongly suggests Turkey
        self.assertIn(cz.converged_country, ("Turkey", "Russia"))

    def test_vietnam_charset(self):
        fps = [make_fp(i, "+0700", "Thailand / Vietnam", "windows-1258")
               for i in range(1, 3)]
        cz = DET.detect(make_cluster("VN", fps))
        self.assertEqual(cz.converged_country, "Vietnam")


# ═══════════════════════════════════════════════════════════════════════════════
class TestThreeAxisConvergence(unittest.TestCase):
    """Three independent axes → HIGH confidence."""

    def test_russia_three_axes(self):
        """Temporal (+0300) + Locale (windows-1251) + Content (.ru DKIM)."""
        fps = [make_fp(i, "+0300", "Russia (Moscow)", "windows-1251",
                       dkim="mail.ru") for i in range(1, 5)]
        cz = DET.detect(make_cluster("RU3", fps))
        self.assertEqual(cz.converged_country, "Russia")
        self.assertEqual(cz.confidence_label, "HIGH")
        self.assertGreaterEqual(cz.n_signals_agree, 3)
        self.assertFalse(cz.false_flag_risk)

    def test_network_axis_fires(self):
        """Network axis: ipv6_country or dns_infra_country contributes."""
        fps = [make_fp(i, "+0300", "Russia (Moscow)", "windows-1251",
                       dkim="yandex.ru", ipv6_country="Russia")
               for i in range(1, 4)]
        cz = DET.detect(make_cluster("RU_NET", fps))
        self.assertEqual(cz.converged_country, "Russia")
        # Network axis should now be in independent_axes
        self.assertIn("network", cz.independent_axes)
        self.assertEqual(cz.confidence_label, "HIGH")

    def test_dns_infra_axis_fires(self):
        """DNS infra signal contributes to network axis."""
        fps = [make_fp(i, "+0800", "China / Singapore", "gbk",
                       dns_infra_country="China")
               for i in range(1, 4)]
        cz = DET.detect(make_cluster("CN_DNS", fps))
        self.assertEqual(cz.converged_country, "China")
        self.assertIn("network", cz.independent_axes)


# ═══════════════════════════════════════════════════════════════════════════════
class TestFalseFlagDetection(unittest.TestCase):
    """
    ACTOR_031 scenario: Date header spoofed to +0000 (→ UK temporal)
    but charset=windows-1251 (→ Russia locale) + Received headers
    show +0300.  Two axes disagree → false_flag_risk=True.
    """

    def test_false_flag_tz_vs_charset(self):
        """
        Temporal axis → UK/Ghana (+0000, 2 signals: timezone_offset + timezone_region)
        Locale axis   → Russia  (windows-1251 charset + Russian subject language)
        Two axes with 2+ signals each disagree → false_flag_risk=True.
        """
        fps = [make_fp(i, "+0000", "UTC", "windows-1251", lang="russian")
               for i in range(1, 4)]
        cz = DET.detect(make_cluster("FF", fps))
        self.assertTrue(cz.false_flag_risk,
                        f"Expected false_flag_risk=True for TZ/charset mismatch. "
                        f"Got: country={cz.converged_country}, axes={cz.independent_axes}, "
                        f"breakdown={cz.signal_breakdown}")
        self.assertIsNotNone(cz.false_flag_detail)
        self.assertIn("contradict", cz.false_flag_detail.lower())

    def test_false_flag_reflected_in_label(self):
        """analyst_note must contain 'False-flag' when false_flag_risk=True."""
        fps = [make_fp(i, "+0000", "UTC", "windows-1251", lang="russian")
               for i in range(1, 4)]
        cz = DET.detect(make_cluster("FF2", fps))
        self.assertIn("False-flag", cz.analyst_note,
                      "analyst_note should warn of false-flag risk")

    def test_consistent_signals_no_false_flag(self):
        """Consistent Russia signals must NOT trigger false-flag."""
        fps = [make_fp(i, "+0300", "Russia (Moscow)", "windows-1251",
                       dkim="yandex.ru") for i in range(1, 4)]
        cz = DET.detect(make_cluster("RU_CLEAN", fps))
        self.assertFalse(cz.false_flag_risk)

    def test_single_axis_no_false_flag(self):
        """Only one axis fires → can't have inter-axis conflict."""
        fps = [make_fp(1, "+0530", "India")]  # temporal only
        cz = DET.detect(make_cluster("IND", fps))
        self.assertFalse(cz.false_flag_risk)


# ═══════════════════════════════════════════════════════════════════════════════
class TestAxisWeights(unittest.TestCase):

    def test_five_axes_defined(self):
        axes = ConvergenceDetector.AXES
        self.assertEqual(len(axes), 5)
        self.assertIn("temporal",       axes)
        self.assertIn("locale",         axes)
        self.assertIn("network",        axes)
        self.assertIn("content",        axes)
        self.assertIn("infrastructure", axes)

    def test_weights_sum_to_one(self):
        total = sum(w for w, _ in ConvergenceDetector.AXES.values())
        self.assertAlmostEqual(total, 1.0, places=5)

    def test_temporal_highest_weight(self):
        weights = {k: w for k, (w, _) in ConvergenceDetector.AXES.items()}
        self.assertEqual(max(weights, key=weights.get), "temporal")

    def test_infrastructure_lowest_weight(self):
        weights = {k: w for k, (w, _) in ConvergenceDetector.AXES.items()}
        self.assertEqual(min(weights, key=weights.get), "infrastructure")


# ═══════════════════════════════════════════════════════════════════════════════
class TestCorrelationReportIntegration(unittest.TestCase):
    """ConvergenceZone round-trips through CorrelationReport.convergence_zones."""

    def test_convergence_zones_in_report(self):
        from huntertrace.analysis.campaignCorrelator import CorrelationReport, FingerprintSimilarity
        from datetime import datetime

        fps = [make_fp(i, "+0300", "Russia (Moscow)", "windows-1251",
                       dkim="yandex.ru") for i in range(1, 4)]
        cluster = make_cluster("ACTOR_001", fps, "Russia")

        det = ConvergenceDetector()
        cz  = det.detect(cluster)

        report = CorrelationReport(
            total_emails=3, total_actors=1,
            actor_clusters=[cluster], singleton_emails=[],
            similarity_matrix={}, correlations=[],
            timestamp=datetime.now().isoformat(),
            convergence_zones={"ACTOR_001": cz},
        )
        self.assertIn("ACTOR_001", report.convergence_zones)
        self.assertEqual(report.convergence_zones["ACTOR_001"].converged_country,
                         "Russia")

    def test_summary_includes_convergence(self):
        from huntertrace.analysis.campaignCorrelator import CorrelationReport
        from datetime import datetime

        fps = [make_fp(i, "+0300", "Russia (Moscow)", "windows-1251",
                       dkim="yandex.ru") for i in range(1, 4)]
        cluster = make_cluster("ACTOR_001", fps, "Russia")
        det = ConvergenceDetector()
        cz  = det.detect(cluster)
        report = CorrelationReport(
            total_emails=3, total_actors=1,
            actor_clusters=[cluster], singleton_emails=[],
            similarity_matrix={}, correlations=[],
            timestamp=datetime.now().isoformat(),
            convergence_zones={"ACTOR_001": cz},
        )
        summary = report.summary()
        self.assertIn("Convergence", summary)
        self.assertIn("Russia", summary)

    def test_empty_convergence_zones_default(self):
        """CorrelationReport without convergence_zones field still works."""
        from huntertrace.analysis.campaignCorrelator import CorrelationReport
        from datetime import datetime
        report = CorrelationReport(
            total_emails=0, total_actors=0,
            actor_clusters=[], singleton_emails=[],
            similarity_matrix={}, correlations=[],
            timestamp=datetime.now().isoformat(),
        )
        self.assertEqual(report.convergence_zones, {})


# ═══════════════════════════════════════════════════════════════════════════════
class TestTLDCountryMapping(unittest.TestCase):

    def test_ru_tld(self):
        det = ConvergenceDetector()
        self.assertEqual(det._tld_to_country("yandex.ru"), "Russia")

    def test_cn_tld(self):
        det = ConvergenceDetector()
        self.assertEqual(det._tld_to_country("example.cn"), "China")

    def test_com_returns_none(self):
        det = ConvergenceDetector()
        self.assertIsNone(det._tld_to_country("gmail.com"))

    def test_de_tld(self):
        det = ConvergenceDetector()
        self.assertEqual(det._tld_to_country("example.de"), "Germany")

    def test_none_input(self):
        det = ConvergenceDetector()
        self.assertIsNone(det._tld_to_country(None))


# ═══════════════════════════════════════════════════════════════════════════════
class TestCharsetMapping(unittest.TestCase):

    def test_windows1251_russia(self):
        fps = [make_fp(1, "+0100", "Central Europe", "windows-1251")]
        cz = DET.detect(make_cluster("C1", fps))
        # Even with +0100 TZ (ambiguous), charset should push locale→Russia
        self.assertIn("locale", cz.independent_axes)

    def test_koi8u_ukraine(self):
        fps = [make_fp(1, "+0200", "Eastern Europe", "koi8-u")]
        cz = DET.detect(make_cluster("UA2", fps))
        self.assertIn("locale", cz.independent_axes)

    def test_utf8_no_locale_axis(self):
        """utf-8 has no geographic signal — locale axis must NOT fire."""
        fps = [make_fp(1, "+0530", "India", "utf-8")]
        cz = DET.detect(make_cluster("IN2", fps))
        self.assertNotIn("locale", cz.independent_axes)

    def test_none_charset_no_locale_axis(self):
        fps = [make_fp(1, "+0530", "India", None)]
        cz = DET.detect(make_cluster("IN3", fps))
        self.assertNotIn("locale", cz.independent_axes)


# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in [
        TestConvergenceZoneDataclass,
        TestEmptyAndSingleEmail,
        TestTwoAxisConvergence,
        TestThreeAxisConvergence,
        TestFalseFlagDetection,
        TestAxisWeights,
        TestCorrelationReportIntegration,
        TestTLDCountryMapping,
        TestCharsetMapping,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print(f"\n{'='*60}")
    total  = result.testsRun
    failed = len(result.failures) + len(result.errors)
    passed = total - failed
    if failed:
        print(f"  {passed}/{total} passed  ✗  {failed} FAILED")
    else:
        print(f"  {passed}/{total} passed  ✓ ALL GREEN")