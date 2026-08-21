from __future__ import annotations

import pytest

from scripts.qianxin.model_service import ModelOutputError, validate_lazarus_output


SOURCE = (
    "Kimsuky launched a spear-phishing campaign against research institutes. "
    "The attackers delivered a malicious document through email."
)


def valid_output() -> dict[str, object]:
    return {
        "title_zh": "Kimsuky针对研究机构开展鱼叉式钓鱼活动",
        "description_zh": (
            "公开报告披露，Kimsuky通过电子邮件投递恶意文档，"
            "针对研究机构开展鱼叉式钓鱼活动。"
        ),
        "threat_type": "钓鱼攻击",
        "threat_type_evidence_quote": "launched a spear-phishing campaign",
        "actor_mentions": [
            {
                "name": "Kimsuky",
                "evidence_quote": "Kimsuky launched a spear-phishing campaign",
            }
        ],
        "factual_points": [
            {
                "text_zh": "攻击者通过电子邮件投递恶意文档",
                "evidence_quote": (
                    "The attackers delivered a malicious document through email."
                ),
            }
        ],
        "confidence": 0.91,
    }


def test_lazarus_output_requires_grounded_quotes() -> None:
    value = validate_lazarus_output(valid_output(), SOURCE)
    assert value["threat_type"] == "钓鱼攻击"
    assert value["actor_mentions"][0]["name"] == "Kimsuky"

    invalid = valid_output()
    invalid["threat_type_evidence_quote"] = "exploited CVE-2099-0001"
    with pytest.raises(ModelOutputError, match="not grounded"):
        validate_lazarus_output(invalid, SOURCE)


def test_lazarus_output_rejects_internal_workflow_copy() -> None:
    invalid = valid_output()
    invalid["description_zh"] = "该事件需要人工复核后才能展示。"
    with pytest.raises(ModelOutputError, match="workflow"):
        validate_lazarus_output(invalid, SOURCE)


def test_actor_name_must_be_verbatim_in_its_quote() -> None:
    invalid = valid_output()
    invalid["actor_mentions"] = [
        {
            "name": "Lazarus Group",
            "evidence_quote": "Kimsuky launched a spear-phishing campaign",
        }
    ]
    with pytest.raises(ModelOutputError, match="not present"):
        validate_lazarus_output(invalid, SOURCE)
