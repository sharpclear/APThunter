import unittest

from app.services.domain_monitor import (
    _build_fingerprint_snapshot,
    _extract_web_page_summary,
    _normalize_dns_snapshot,
)


class DomainMonitorFingerprintTests(unittest.TestCase):
    def test_dns_snapshot_contains_stable_network_fingerprints(self):
        snapshot = _normalize_dns_snapshot(
            {
                "domain": "example.test",
                "records": [
                    {"type": "A", "name": "example.test", "value": "203.0.113.15", "ttl": 300},
                    {"type": "AAAA", "name": "example.test", "value": "2001:db8::15", "ttl": 60},
                    {"type": "CNAME", "name": "www.example.test", "value": "edge.example.net.", "ttl": 60},
                    {"type": "MX", "name": "example.test", "value": "mail.example.net.", "priority": 10, "ttl": 300},
                ],
            }
        )

        self.assertEqual(snapshot["resolved_ips"], ["203.0.113.15", "2001:db8::15"])
        self.assertEqual(snapshot["network_prefixes"], ["2001:db8::/48", "203.0.113.0/24"])
        self.assertEqual(snapshot["record_counts"], {"A": 1, "AAAA": 1, "CNAME": 1, "MX": 1})
        self.assertEqual(snapshot["ttl_profile"]["median"], 180.0)
        self.assertTrue(snapshot["record_set_sha256"])
        self.assertTrue(snapshot["resolved_ip_set_sha256"])

    def test_web_summary_extracts_application_fingerprints(self):
        html = b"""
        <html>
          <head>
            <title>Example Login</title>
            <meta name="generator" content="Example CMS 2.0">
            <link rel="icon" href="/assets/favicon.ico?v=2">
            <link rel="stylesheet" href="https://cdn.example.net/app.css">
            <script src="/assets/app.js"></script>
            <script>gtag('config', 'G-ABCDEF12');</script>
          </head>
          <body><form method="post" action="/session"><input name="account"></form></body>
        </html>
        """

        summary = _extract_web_page_summary(html, "text/html", "https://example.test/login")

        self.assertEqual(summary["title"], "Example Login")
        self.assertEqual(summary["generator"], "Example CMS 2.0")
        self.assertEqual(summary["favicon_urls"], ["https://example.test/assets/favicon.ico"])
        self.assertEqual(summary["external_resource_hosts"], ["cdn.example.net"])
        self.assertEqual(summary["analytics_identifiers"]["google_analytics"], ["G-ABCDEF12"])
        self.assertEqual(summary["form_targets"][0]["method"], "POST")
        self.assertTrue(summary["dom_structure_sha256"])

    def test_aggregate_snapshot_contains_temporal_relationships(self):
        fingerprint = _build_fingerprint_snapshot(
            domain="example.test",
            whois={
                "registrar_normalized": "example registrar",
                "registration_date": "2026-01-01",
                "updated_date": "2026-01-11",
                "expiration_date": "2027-01-01",
            },
            dns={"resolved_ips": ["203.0.113.15"]},
            certificate={
                "not_before": "2026-01-03T00:00:00+00:00",
                "not_after": "2026-04-03T00:00:00+00:00",
                "fingerprint": "certificate-hash",
                "spki_fingerprint": "spki-hash",
            },
            web={"status": "collected", "html_hash": "html-hash"},
        )

        self.assertEqual(fingerprint["schema_version"], "1.0")
        self.assertEqual(fingerprint["temporal"]["registration_to_update_days"], 10)
        self.assertEqual(fingerprint["temporal"]["registration_to_certificate_days"], 2)
        self.assertEqual(fingerprint["temporal"]["certificate_validity_days"], 90)
        self.assertEqual(fingerprint["tls"]["spki_sha256"], "spki-hash")


if __name__ == "__main__":
    unittest.main()
