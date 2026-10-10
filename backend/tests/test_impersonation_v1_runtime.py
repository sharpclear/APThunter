from __future__ import annotations

import sys
import unittest
from pathlib import Path


MODELS_DIR = Path(__file__).resolve().parents[1] / "app" / "models"
sys.path.insert(0, str(MODELS_DIR))

from impersonation_v1.runtime import RESULT_COLUMNS, detect_impersonation_domains


class ImpersonationV1RuntimeTest(unittest.TestCase):
    def test_known_v1_candidate_uses_compatible_output(self) -> None:
        result, statistics = detect_impersonation_domains(
            [("Microsoft", "microsoft.com")],
            ["micr0s0ft.online", "microsoft.com", "mail-service.com"],
            similarity_threshold=0,
        )

        self.assertEqual(RESULT_COLUMNS, result.columns.tolist())
        self.assertEqual(["micr0s0ft.online"], result["仿冒域名"].tolist())
        self.assertEqual(["microsoft.com"], result["官方域名"].tolist())
        self.assertEqual(1, statistics["impersonation"])
        self.assertEqual("ImpersonationDomainDetection/V1", statistics["LLM研判模型"])

    def test_no_recalled_candidate_returns_empty_result(self) -> None:
        result, statistics = detect_impersonation_domains(
            [("Microsoft", "microsoft.com")],
            ["mail-service.com"],
        )

        self.assertTrue(result.empty)
        self.assertEqual(0, statistics["impersonation"])
        self.assertEqual(1, statistics["benign"])


if __name__ == "__main__":
    unittest.main()
