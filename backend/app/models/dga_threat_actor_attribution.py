from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


RELATIONSHIP_TYPE_CN = {
    "affiliate_or_distribution_actor": "联盟或分发关系",
    "associated_malware_family": "关联恶意软件家族",
    "botnet_operator": "僵尸网络运营者",
    "codebase_or_successor_variant": "代码继承或后继变种",
    "crimeware_service_operator": "犯罪服务运营者",
    "distributed_malware": "分发过",
    "distributed_or_enabled_by_infrastructure": "基础设施分发或支撑",
    "dropper_distributed_malware": "通过投递器分发",
    "hosted_on_crimeware_infrastructure": "托管于犯罪基础设施",
    "loader_distributed_malware": "通过加载器分发",
    "malware_as_a_service_operator": "恶意软件服务运营者",
    "malware_author_or_operator": "作者或运营者",
    "malware_developed_by_actor": "开发",
    "malware_distribution_service": "恶意软件分发服务",
    "malware_family_operator": "家族运营者",
    "malware_operated_by_actor": "运营",
    "malware_used_by_actor": "使用过",
    "malware_used_in_campaign": "攻击活动中使用",
    "operator_reported": "公开报道的运营者",
    "payload_distributed_by_actor": "载荷分发",
    "reported_code_or_campaign_overlap": "代码或活动重叠线索",
    "reported_tool_overlap": "工具重叠线索",
    "shared_loader_used_by_multiple_actors": "多组织共享加载器",
    "spam_campaign_distributed_malware": "垃圾邮件活动分发",
    "spam_infrastructure_operated_by_actor": "运营垃圾邮件基础设施",
    "spam_infrastructure_used_by_actor": "使用垃圾邮件基础设施",
    "spam_service_customer_or_distribution_overlap": "垃圾邮件服务或分发重叠",
}

RELATIONSHIP_EXPLANATION_TEMPLATES = {
    "affiliate_or_distribution_actor": "{actor} 作为 {family} 的联盟成员或分发方参与传播。",
    "associated_malware_family": "{actor} 的公开恶意软件活动与 {family} 家族存在关联。",
    "botnet_operator": "{actor} 被公开报道为 {family} 僵尸网络的运营者。",
    "codebase_or_successor_variant": "{family} 与 {actor} 运营的恶意软件存在代码继承或后继变种关系。",
    "crimeware_service_operator": "{actor} 被公开报道为 {family} 犯罪服务的运营者。",
    "distributed_malware": "{actor} 曾参与分发 {family}。",
    "distributed_or_enabled_by_infrastructure": "{actor} 的基础设施曾用于分发或支撑 {family}。",
    "dropper_distributed_malware": "{actor} 曾通过投递器分发 {family}。",
    "hosted_on_crimeware_infrastructure": "{family} 曾托管在 {actor} 相关的犯罪基础设施上。",
    "loader_distributed_malware": "{actor} 曾通过加载器分发 {family}。",
    "malware_as_a_service_operator": "{actor} 被公开报道为 {family} 恶意软件服务的运营者。",
    "malware_author_or_operator": "{actor} 被公开情报关联为 {family} 的作者或运营者。",
    "malware_developed_by_actor": "{actor} 被公开情报关联为 {family} 的开发者。",
    "malware_distribution_service": "{actor} 曾作为恶意软件分发服务传播 {family}。",
    "malware_family_operator": "{actor} 被公开报道为 {family} 家族的运营者。",
    "malware_operated_by_actor": "{actor} 曾直接运营 {family}。",
    "malware_used_by_actor": "{actor} 的攻击活动曾使用 {family}。",
    "malware_used_in_campaign": "{actor} 的攻击活动中曾出现 {family}。",
    "operator_reported": "{actor} 被公开报道为 {family} 的运营者。",
    "payload_distributed_by_actor": "{actor} 曾将 {family} 作为攻击载荷进行分发。",
    "reported_code_or_campaign_overlap": "{actor} 与 {family} 在代码特征或攻击活动上存在公开报道的重叠。",
    "reported_tool_overlap": "{actor} 的相关攻击活动曾使用或涉及 {family} 工具。",
    "shared_loader_used_by_multiple_actors": "{family} 作为共享加载器，曾被 {actor} 等多个组织使用。",
    "spam_campaign_distributed_malware": "{actor} 曾通过垃圾邮件活动分发 {family}。",
    "spam_infrastructure_operated_by_actor": "{actor} 曾运营用于传播 {family} 的垃圾邮件基础设施。",
    "spam_infrastructure_used_by_actor": "{actor} 曾使用垃圾邮件基础设施传播 {family}。",
    "spam_service_customer_or_distribution_overlap": "{actor} 与 {family} 在垃圾邮件服务或分发渠道上存在公开报道的重叠。",
}

CONCRETE_FAMILY_EXCLUSIONS = {"", "unknown_family", "possible_family"}
REQUIRED_ASSOCIATION_FIELDS = {
    "dga_family",
    "actor_name",
    "relationship_type",
    "attribution_status",
    "confidence",
    "source_name",
    "source_url",
}
REQUIRED_ALIAS_FIELDS = {"alias", "canonical_family"}


def normalize_family(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def relationship_type_cn(value: Any) -> str:
    relationship_type = str(value or "").strip()
    return RELATIONSHIP_TYPE_CN.get(relationship_type, relationship_type)


def relationship_explanation_cn(
    relationship_type: Any,
    actor_name: Any,
    family: Any,
) -> str:
    relationship_key = str(relationship_type or "").strip()
    actor = "、".join(_split_actor_names(str(actor_name or ""))) or "相关组织"
    family_name = str(family or "").strip() or "该DGA家族"
    template = RELATIONSHIP_EXPLANATION_TEMPLATES.get(relationship_key)
    if template:
        return template.format(actor=actor, family=family_name)
    relationship_name = relationship_type_cn(relationship_key) or "公开情报关联"
    return f"{actor} 与 {family_name} 存在{relationship_name}关系。"


def load_family_actor_associations(path: Path) -> dict[str, list[dict[str, str]]]:
    associations: dict[str, list[dict[str, str]]] = defaultdict(list)
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing_fields = REQUIRED_ASSOCIATION_FIELDS.difference(reader.fieldnames or [])
        if missing_fields:
            raise ValueError(
                "DGA family actor association CSV is missing fields: "
                + ", ".join(sorted(missing_fields))
            )
        for row in reader:
            family = normalize_family(row.get("dga_family"))
            actor_name = str(row.get("actor_name") or "").strip()
            if family and actor_name:
                associations[family].append(dict(row))
    for rows in associations.values():
        rows.sort(
            key=lambda row: (
                -_safe_float(row.get("confidence")),
                row.get("actor_name", "").lower(),
                row.get("relationship_type", ""),
            )
        )
    result = dict(associations)
    alias_path = path.with_name("family_aliases.csv")
    if not alias_path.exists():
        return result

    with alias_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing_fields = REQUIRED_ALIAS_FIELDS.difference(reader.fieldnames or [])
        if missing_fields:
            raise ValueError(
                "DGA family alias CSV is missing fields: "
                + ", ".join(sorted(missing_fields))
            )
        for row in reader:
            alias = normalize_family(row.get("alias"))
            canonical = normalize_family(row.get("canonical_family"))
            if alias and canonical in result and alias not in result:
                result[alias] = result[canonical]
    return result


def build_actor_attribution(
    family: Any,
    family_attribution_status: Any,
    associations: dict[str, list[dict[str, str]]],
) -> dict[str, Any]:
    normalized_family = normalize_family(family)
    if (
        str(family_attribution_status or "").strip() != "usable"
        or normalized_family in CONCRETE_FAMILY_EXCLUSIONS
    ):
        return _empty_attribution()

    rows = associations.get(normalized_family, [])
    if not rows:
        return _empty_attribution()

    actor_names = _unique(
        name
        for row in rows
        for name in _split_actor_names(row.get("actor_name", ""))
    )
    relationship_names = _unique(
        relationship_type_cn(row.get("relationship_type")) for row in rows
    )
    details = []
    explanations = []
    for row in rows:
        canonical_family = normalize_family(row.get("dga_family")) or normalized_family
        explanation = relationship_explanation_cn(
            row.get("relationship_type"),
            row.get("actor_name"),
            canonical_family,
        )
        explanations.append(explanation)
        details.append({
            "dga_family": canonical_family,
            "apt_organization_name": row.get("actor_name", ""),
            "actor_aliases": row.get("actor_aliases", ""),
            "relationship_type": row.get("relationship_type", ""),
            "relationship_type_cn": relationship_type_cn(row.get("relationship_type")),
            "relationship_explanation_cn": explanation,
            "attribution_status": row.get("attribution_status", ""),
            "confidence": _safe_float(row.get("confidence")),
            "source_name": row.get("source_name", ""),
            "source_url": row.get("source_url", ""),
            "notes": row.get("notes", ""),
        })
    return {
        "APT组织名": "、".join(actor_names),
        "关联方式": "、".join(relationship_names),
        "APT组织关联说明": "；".join(_unique(explanations)),
        "APT组织线索数": len(rows),
        "APT组织关联详情": json.dumps(details, ensure_ascii=False),
    }


def parse_attribution_details(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if not value:
        return []
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []


def build_attribution_relationship_overview(
    rows: Iterable[dict[str, Any]],
) -> list[dict[str, str]]:
    overview: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        details = parse_attribution_details(
            row.get("APT组织关联详情") or row.get("apt_attribution_clues")
        )
        for detail in details:
            family = str(
                detail.get("dga_family")
                or row.get("DGA家族")
                or row.get("family")
                or ""
            ).strip()
            actor = str(detail.get("apt_organization_name") or "").strip()
            relationship_type = str(detail.get("relationship_type") or "").strip()
            if not family or not actor or not relationship_type:
                continue
            key = (normalize_family(family), actor, relationship_type)
            if key in seen:
                continue
            seen.add(key)
            overview.append(
                {
                    "family": family,
                    "apt_organization_name": "、".join(_split_actor_names(actor)),
                    "relationship_type_cn": str(
                        detail.get("relationship_type_cn")
                        or relationship_type_cn(relationship_type)
                    ).strip(),
                    "relationship_explanation_cn": str(
                        detail.get("relationship_explanation_cn")
                        or relationship_explanation_cn(
                            relationship_type,
                            actor,
                            family,
                        )
                    ).strip(),
                    "source_name": str(detail.get("source_name") or "").strip(),
                }
            )
    return overview


def _empty_attribution() -> dict[str, Any]:
    return {
        "APT组织名": "",
        "关联方式": "",
        "APT组织关联说明": "",
        "APT组织线索数": 0,
        "APT组织关联详情": "[]",
    }


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _split_actor_names(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(";") if item.strip()]


def _unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result
