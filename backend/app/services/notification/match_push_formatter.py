from __future__ import annotations

from typing import Any, List, Sequence


def _safe_text(value: Any, default: str = "") -> str:
    text = str(value or "").strip()
    return text if text else default


def build_push_message_from_match(match: Any) -> str:
    domain_name = _safe_text(getattr(match, "domain_name", ""), "未知")
    org_name = _safe_text(getattr(match, "matched_organization_name", ""), "未知")
    return f"{domain_name} -> {org_name}"


def build_batch_push_message_from_matches(matches: Sequence[Any]) -> str:
    if not matches:
        return ""

    total = len(matches)
    known_org = 0
    for row in matches:
        org = _safe_text(getattr(row, "matched_organization_name", ""))
        if org and org != "未知":
            known_org += 1

    sections = [
        "【域名与组织关联列表】",
        f"本批次高风险域名数量：{total}",
        f"已形成组织关联的域名数量：{known_org}",
        "",
    ]

    for row in matches:
        sections.append(build_push_message_from_match(row))
    return "\n".join(sections).strip()
