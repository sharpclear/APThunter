from __future__ import annotations

import csv
import json
import sys
import unittest
from pathlib import Path


MODELS_DIR = Path(__file__).resolve().parents[1] / "app" / "models"
sys.path.insert(0, str(MODELS_DIR))

from dga_threat_actor_attribution import (  # noqa: E402
    RELATIONSHIP_TYPE_CN,
    build_actor_attribution,
    load_family_actor_associations,
    parse_attribution_details,
)


ASSOCIATIONS_CSV = (
    MODELS_DIR
    / "saved_model"
    / "dga_detection_local_model"
    / "data"
    / "reference"
    / "dga_family_apt_association"
    / "dga_family_actor_associations.csv"
)


class DgaThreatActorAttributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.associations = load_family_actor_associations(ASSOCIATIONS_CSV)

    def test_one_family_can_return_multiple_actor_clues(self) -> None:
        result = build_actor_attribution("qakbot", "usable", self.associations)

        self.assertEqual(result["APT组织名"], "GOLD CABIN、TA570、TA577")
        self.assertEqual(result["APT组织线索数"], 3)
        details = parse_attribution_details(result["APT组织关联详情"])
        self.assertEqual(len(details), 3)
        self.assertTrue(all(detail["relationship_type_cn"] for detail in details))

    def test_non_usable_family_is_not_attributed(self) -> None:
        result = build_actor_attribution(
            "qakbot",
            "caution_low_precision",
            self.associations,
        )

        self.assertEqual(result["APT组织名"], "")
        self.assertEqual(result["关联方式"], "")
        self.assertEqual(result["APT组织线索数"], 0)

    def test_family_alias_resolves_to_canonical_associations(self) -> None:
        result = build_actor_attribution("vawtrak_v1", "usable", self.associations)

        self.assertEqual(result["APT组织名"], "Neverquest operators")
        self.assertEqual(result["关联方式"], "犯罪服务运营者")

    def test_current_relationship_types_have_chinese_labels(self) -> None:
        with ASSOCIATIONS_CSV.open(newline="", encoding="utf-8") as handle:
            relationship_types = {
                row["relationship_type"] for row in csv.DictReader(handle)
            }

        self.assertEqual(relationship_types.difference(RELATIONSHIP_TYPE_CN), set())

    def test_association_summary_matches_shipped_data(self) -> None:
        data_dir = ASSOCIATIONS_CSV.parent
        with ASSOCIATIONS_CSV.open(newline="", encoding="utf-8") as handle:
            association_rows = list(csv.DictReader(handle))
        with (data_dir / "current_model_dga_family_catalog.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            model_families = {
                row["dga_family"] for row in csv.DictReader(handle)
            }
        summary = json.loads(
            (data_dir / "association_summary.json").read_text(encoding="utf-8")
        )
        association_families = {
            row["dga_family"] for row in association_rows
        }

        self.assertEqual(summary["association_row_count"], len(association_rows))
        self.assertEqual(summary["current_model_family_count"], len(model_families))
        self.assertEqual(summary["association_family_count"], len(association_families))
        self.assertEqual(
            summary["current_model_families_with_association"],
            len(association_families & model_families),
        )
        self.assertEqual(
            summary["external_association_family_count"],
            len(association_families - model_families),
        )


if __name__ == "__main__":
    unittest.main()
