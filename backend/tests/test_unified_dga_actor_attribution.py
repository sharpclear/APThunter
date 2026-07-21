from __future__ import annotations

import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(BACKEND_DIR / "app" / "models"))

from app.models.dga_domain_detection import _sort_dga_rows  # noqa: E402
from app.services.dga_report import _report_dga_sort_key  # noqa: E402
from app.services.unified_malicious_domain_report import (  # noqa: E402
    _build_report_context,
    build_unified_malicious_domain_payload,
)


class UnifiedDgaActorAttributionTests(unittest.TestCase):
    def test_dga_actor_fields_reach_unified_result_and_report(self) -> None:
        dga_row = {
            "域名": "5w3z932m3jw6hp.top",
            "DGA_score": 0.999999,
            "预测标签": 1,
            "预测结果": "高置信DGA",
            "命中方式": "主模型高置信",
            "DGA家族": "qadars",
            "家族归因状态": "usable",
            "APT组织名": "FIN7",
            "关联方式": "工具重叠线索",
        }
        payload = build_unified_malicious_domain_payload(
            task_id="test-dga-actor",
            input_domains=[dga_row["域名"]],
            data_source="manualInput",
            module_payloads={
                "dga": {"dga_domains": [dga_row]},
                "impersonation": {},
                "history_similarity": {},
                "apt_template_nrd": {},
            },
        )

        result = payload["unified_malicious_domains"][0]
        dga_hit = result["module_hits"]["dga"]
        self.assertEqual(dga_hit["apt_organization_names"], "FIN7")
        self.assertEqual(dga_hit["apt_relationship_types_cn"], "工具重叠线索")
        self.assertIn("APT组织=FIN7", result["命中详情"])

        context = _build_report_context(payload)
        self.assertEqual(context["dga_actor_attribution_count"], 1)
        self.assertEqual(
            context["dga_result_rows"][0]["apt_organization_names"],
            "FIN7",
        )

    def test_dga_results_are_ordered_by_attribution_quality(self) -> None:
        dga_rows = [
            {
                "域名": "unknown.example",
                "DGA_score": 0.999,
                "DGA家族": "unknown_family",
                "家族归因状态": "unknown_family",
            },
            {
                "域名": "family-only.example",
                "DGA_score": 0.950,
                "DGA家族": "bigviktor",
                "家族归因状态": "usable",
            },
            {
                "域名": "actor-clue.example",
                "DGA_score": 0.920,
                "DGA家族": "qadars",
                "家族归因状态": "usable",
                "APT组织名": "FIN7",
                "关联方式": "工具重叠线索",
            },
            {
                "域名": "actor-clue-higher.example",
                "DGA_score": 0.920049,
                "DGA家族": "qadars",
                "家族归因状态": "usable",
                "APT组织名": "FIN7",
                "关联方式": "工具重叠线索",
            },
        ]
        payload = build_unified_malicious_domain_payload(
            task_id="test-dga-order",
            input_domains=[row["域名"] for row in dga_rows],
            data_source="manualInput",
            module_payloads={
                "dga": {"dga_domains": dga_rows},
                "impersonation": {},
                "history_similarity": {},
                "apt_template_nrd": {},
            },
        )

        self.assertEqual(
            [row["域名"] for row in payload["unified_malicious_domains"]],
            [
                "actor-clue-higher.example",
                "actor-clue.example",
                "family-only.example",
                "unknown.example",
            ],
        )
        context = _build_report_context(payload)
        self.assertEqual(
            [row["domain"] for row in context["dga_result_rows"]],
            [
                "actor-clue-higher.example",
                "actor-clue.example",
                "family-only.example",
                "unknown.example",
            ],
        )
        self.assertEqual(
            [row["域名"] for row in context["top_domains"]],
            [
                "actor-clue-higher.example",
                "actor-clue.example",
                "family-only.example",
                "unknown.example",
            ],
        )

        self.assertEqual(
            [row["域名"] for row in _sort_dga_rows(dga_rows)],
            [
                "actor-clue-higher.example",
                "actor-clue.example",
                "family-only.example",
                "unknown.example",
            ],
        )
        self.assertEqual(
            [row["域名"] for row in sorted(dga_rows, key=_report_dga_sort_key)],
            [
                "actor-clue-higher.example",
                "actor-clue.example",
                "family-only.example",
                "unknown.example",
            ],
        )


if __name__ == "__main__":
    unittest.main()
