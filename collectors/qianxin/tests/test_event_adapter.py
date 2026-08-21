from __future__ import annotations

from scripts.qianxin.event_adapter import (
    APT_EVENT_COLUMNS,
    SCHEMA_VERSION,
    build_apt_event_product,
    infer_threat_type,
    normalize_event_description,
)


def _report(*, quality_status: str = "ready", review_required: bool = False):
    return {
        "sha256": "a" * 64,
        "organization_id": "40",
        "organization_name": "APT28",
        "report_title": "APT28 发起新一轮鱼叉式钓鱼攻击",
        "report_date": "2026-08-12",
        "collected_at": "2026-08-13T00:00:00Z",
        "updated_at": "2026-08-13T01:00:00Z",
        "quality_status": quality_status,
        "review_required": review_required,
        "model_name": "test-model",
        "prompt_version": "test-prompt",
        "validator_version": "test-validator",
        "version": 2,
    }


def _summary():
    return {
        "summary": {
            "report_title": "APT28 发起新一轮鱼叉式钓鱼攻击",
            "key_findings": [
                {
                    "finding": "攻击者通过鱼叉式钓鱼邮件投递恶意附件",
                    "evidence_quote": "The campaign used spearphishing attachments",
                    "evidence_pages": [2],
                    "evidence_match": "exact",
                }
            ],
            "timeline": [
                {
                    "date": "2026-08-12",
                    "event": "攻击活动被披露",
                    "evidence_quote": "August 12, 2026",
                    "evidence_pages": [1],
                }
            ],
        }
    }


def test_ready_grounded_report_becomes_accepted_apt_event() -> None:
    value = build_apt_event_product(
        _report(),
        _summary(),
        {"status": "ready"},
        {
            "preview_url": "https://ti.qianxin.com/report?id=7&utm_source=test",
            "report_publisher": "Example Security",
        },
        allow_auto_accept=True,
    )

    assert value["schema_version"] == SCHEMA_VERSION
    assert value["quality_status"] == "accepted"
    assert value["review_required"] is False
    assert value["apt_event"]["id"] is None
    assert list(value["apt_event"]) == list(APT_EVENT_COLUMNS)
    assert value["apt_event"]["threat_type"] == "钓鱼攻击"
    assert value["apt_event"]["review_status"] == "accepted"
    assert value["apt_event"]["description"] == "攻击者通过鱼叉式钓鱼邮件投递恶意附件。"
    assert value["apt_event"]["link"] == "https://ti.qianxin.com/report?id=7"
    assert value["structured_event"]["variants"][0]["organization_name"] == "APT28"


def test_description_uses_complete_chinese_sentences() -> None:
    summary = _summary()
    summary["summary"]["key_findings"].extend(
        [
            {
                "finding": "随后建立 C2 通信。",
                "evidence_quote": "The implant established C2",
                "evidence_pages": [3],
            },
            {
                "finding": "最后执行数据窃取；",
                "evidence_quote": "The implant stole data",
                "evidence_pages": [4],
            },
        ]
    )

    value = build_apt_event_product(
        _report(),
        summary,
        {"status": "ready"},
        {
            "preview_url": "https://ti.qianxin.com/report?id=7",
            "report_publisher": "Example Security",
        },
        allow_auto_accept=True,
    )

    assert value["apt_event"]["description"] == (
        "攻击者通过鱼叉式钓鱼邮件投递恶意附件。"
        "随后建立 C2 通信。"
        "最后执行数据窃取。"
    )


def test_description_normalizer_is_an_idempotent_api_contract() -> None:
    source = "第一项; 第二项；第三项。；Fourth item!"
    normalized = "第一项。第二项。第三项。Fourth item!"

    assert normalize_event_description(source) == normalized
    assert normalize_event_description(normalized) == normalized
    assert normalize_event_description("  ") == ""


def test_auto_accept_is_disabled_by_default() -> None:
    value = build_apt_event_product(
        _report(),
        _summary(),
        {"status": "ready"},
        {
            "preview_url": "https://ti.qianxin.com/report?id=7",
            "report_publisher": "Example Security",
        },
    )

    variant = value["structured_event"]["variants"][0]
    assert value["quality_status"] == "needs_review"
    assert variant["review_status"] == "needs_review"
    assert "奇安信事件自动接受未启用" in variant["review_reasons"]


def test_filtered_report_is_retained_as_review_candidate() -> None:
    value = build_apt_event_product(
        _report(
            quality_status="ready_with_filtered_items",
            review_required=True,
        ),
        _summary(),
        {"status": "ready_with_filtered_items"},
        {},
        public_base_url="http://192.168.1.20:8787",
    )

    variant = value["structured_event"]["variants"][0]
    assert value["review_required"] is True
    assert variant["review_status"] == "needs_review"
    assert "来源质量状态为 ready_with_filtered_items" in variant["review_reasons"]
    assert variant["releasing_product"] == "奇安信威胁情报中心"
    assert variant["link"].endswith(f"/api/v1/reports/{'a' * 64}/pdf")
    assert "历史元数据未保存原始发布厂商" in variant["collection_notes"]


def test_placeholder_publisher_falls_back_to_qianxin() -> None:
    value = build_apt_event_product(
        _report(),
        _summary(),
        {"status": "ready"},
        {
            "preview_url": "https://ti.qianxin.com/report?id=7",
            "report_publisher": "-",
        },
        allow_auto_accept=True,
    )

    variant = value["structured_event"]["variants"][0]
    assert variant["releasing_product"] == "奇安信威胁情报中心"
    assert value["provenance"]["publisher_fallback"] is True


def test_threat_type_falls_back_to_reviewable_apt_attack() -> None:
    summary = {
        "summary": {
            "report_title": "某组织活动分析",
            "key_findings": [
                {
                    "finding": "研究人员观察到新的活动",
                    "evidence_quote": "Researchers observed new activity",
                    "evidence_pages": [1],
                }
            ],
        }
    }
    threat_type, explicit = infer_threat_type(summary)
    assert threat_type == "APT攻击"
    assert explicit is False

    value = build_apt_event_product(
        {**_report(), "report_title": "某组织活动分析"},
        summary,
        {"status": "ready"},
        {
            "preview_url": "https://ti.qianxin.com/report?id=8",
            "report_publisher": "Example Security",
        },
    )
    reasons = value["structured_event"]["variants"][0]["review_reasons"]
    assert "威胁类型仅能归为通用 APT攻击" in reasons
