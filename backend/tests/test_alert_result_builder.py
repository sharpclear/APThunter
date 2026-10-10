import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

BACKEND_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = (
    BACKEND_DIR
    / "app"
    / "services"
    / "actor_matcher"
    / "alert_result_builder.py"
)
SPEC = importlib.util.spec_from_file_location("alert_result_builder", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)
build_alert_result_json = MODULE.build_alert_result_json


class AlertResultBuilderTest(unittest.TestCase):
    def test_impersonation_score_takes_precedence_over_actor_score(self) -> None:
        alert = SimpleNamespace(
            alert_id="A1",
            subscription_id="S1",
            task_id="T1",
            user_id=1,
            model_id=1,
            model_name="impersonation_detector",
            task_type="impersonation",
            threshold=None,
            created_at=None,
        )
        result = build_alert_result_json(
            alert_row=alert,
            subscription_row=None,
            task_row=None,
            high_risk_domains=["micr0s0ft.online"],
            match_results={
                "micr0s0ft.online": {
                    "domain_name": "micr0s0ft.online",
                    "actor_score": 0.0,
                }
            },
            impersonation_matches=[
                {
                    "impersonation_domain": "micr0s0ft.online",
                    "final_risk_score": "1.0",
                    "risk_level": "高",
                }
            ],
            detected_count=1,
            high_risk_count=1,
        )

        item = result["high_risk_domains"][0]
        self.assertEqual(1.0, item["risk_score"])
        self.assertEqual("high", item["risk_level"])


if __name__ == "__main__":
    unittest.main()
