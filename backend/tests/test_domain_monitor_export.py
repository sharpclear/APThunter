import csv
import io
import json
import unittest
from datetime import datetime
from types import SimpleNamespace

from app.services.domain_monitor_export import build_export_row, render_export_csv


class DomainMonitorExportTests(unittest.TestCase):
    def test_export_contains_target_latest_snapshot_and_source_fields(self):
        target = SimpleNamespace(
            id=7,
            domain="example.test",
            normalized_domain="example.test",
            is_active=True,
            status="active",
            monitor_interval_hours=24,
            last_checked_at=datetime(2026, 7, 23, 10, 0, 0),
            next_check_at=datetime(2026, 7, 24, 10, 0, 0),
            consecutive_failures=0,
            last_error=None,
            created_at=datetime(2026, 7, 20, 9, 0, 0),
            updated_at=datetime(2026, 7, 23, 10, 0, 0),
        )
        snapshot = SimpleNamespace(
            id=11,
            status="partial",
            collected_at=datetime(2026, 7, 23, 10, 0, 0),
            whois_snapshot={"registrar": "Example Registrar"},
            dns_snapshot={
                "resolved_ips": ["203.0.113.15"],
                "ttl_profile": {"min": 60, "max": 300, "median": 180},
            },
            certificate_snapshot={
                "tls_version": "TLSv1.3",
                "spki_fingerprint": "spki-hash",
            },
            web_snapshot={"title": "Example", "html_hash": "html-hash"},
            fingerprint_snapshot={
                "schema_version": "1.0",
                "temporal": {"certificate_validity_days": 90},
            },
            changed_fields={"sections": ["dns", "web"]},
            raw_lookup_errors=["WHOIS timeout"],
            error_message="部分字段查询失败",
        )
        source = SimpleNamespace(
            source_type="detection_task",
            task_id="T100",
            task_type="dga",
            model_id=2,
            subscription_id=None,
            alert_id=None,
            risk_score=0.98,
            risk_level="high",
            risk_record={"domain": "example.test"},
            detected_at=datetime(2026, 7, 23, 9, 58, 0),
            created_at=datetime(2026, 7, 23, 9, 59, 0),
        )

        content = render_export_csv([build_export_row(target, snapshot, [source])])
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
        row = next(reader)

        self.assertEqual(row["域名"], "example.test")
        self.assertEqual(row["追踪状态"], "正常追踪")
        self.assertEqual(row["快照状态"], "部分成功")
        self.assertEqual(row["解析IP"], '["203.0.113.15"]')
        self.assertEqual(row["TLS版本"], "TLSv1.3")
        self.assertEqual(row["证书有效周期（天）"], "90")
        source_details = json.loads(row["检测来源详情（JSON）"])
        self.assertEqual(source_details[0]["task_id"], "T100")

    def test_export_protects_spreadsheet_formula_cells(self):
        target = SimpleNamespace(
            id=8,
            domain="formula.test",
            normalized_domain="formula.test",
            is_active=True,
            status="failed",
            monitor_interval_hours=24,
            last_checked_at=None,
            next_check_at=datetime(2026, 7, 24, 10, 0, 0),
            consecutive_failures=1,
            last_error="=HYPERLINK(\"https://example.test\")",
            created_at=datetime(2026, 7, 20, 9, 0, 0),
            updated_at=datetime(2026, 7, 23, 10, 0, 0),
        )

        content = render_export_csv([build_export_row(target, None, [])])
        row = next(csv.DictReader(io.StringIO(content.decode("utf-8-sig"))))

        self.assertTrue(row["追踪错误"].startswith("'="))
        self.assertEqual(row["快照状态"], "暂无快照")


if __name__ == "__main__":
    unittest.main()
