from __future__ import annotations

import io
import json
import math
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import pandas as pd

from app.models.dga_threat_actor_attribution import (
    build_attribution_relationship_overview,
)
from app.services.history_similarity_report import render_markdown_report_to_pdf


REPORT_TEMPLATE_PATH = (
    Path(__file__).resolve().parents[2]
    / "报告模板"
    / "恶意域名检测报告模板.md"
)

MODULE_LABELS = {
    "impersonation": "仿冒域名",
    "dga": "DGA域名",
    "history_similarity": "历史APT相似",
    "apt_template_nrd": "模板化APT域名",
}


def _cell_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and not math.isfinite(value):
        return ""
    text = str(value).strip()
    return "" if text.lower() in {"nan", "none", "nat"} else text


def _json_safe_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, float):
        return value if math.isfinite(value) else ""
    if hasattr(value, "item"):
        try:
            return _json_safe_value(value.item())
        except Exception:
            pass
    if isinstance(value, dict):
        return {key: _json_safe_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe_value(item) for item in value]
    return value


def _score(value: Any) -> float:
    try:
        score = float(value or 0)
        return score if math.isfinite(score) else 0.0
    except (TypeError, ValueError):
        return 0.0


def _format_score(value: Any) -> str:
    score = _score(value)
    return f"{score:.4f}" if score else "-"


def _percent(part: int, total: int) -> str:
    return f"{(part / total * 100):.2f}%" if total else "0.00%"


def _markdown_cell(value: Any) -> str:
    text = _cell_text(value).replace("|", "/")
    text = re.sub(r"\s+", " ", text)
    return text.strip() or "-"


def _source_label(value: str) -> str:
    return {
        "upload": "上传文件",
        "newDomain": "新注册域名",
        "manualInput": "手动输入域名",
    }.get(value or "", value or "未知")


def _row_domain(row: dict[str, Any]) -> str:
    for key in (
        "域名",
        "规范化域名",
        "仿冒域名",
        "钓鱼域名",
        "domain",
        "domain_name",
        "candidate_domain",
    ):
        domain = _cell_text(row.get(key)).lower()
        if domain:
            return domain
    return ""


def _excel_rows(excel_content: bytes, sheet_name: str) -> list[dict[str, Any]]:
    try:
        excel_file = io.BytesIO(excel_content)
        return pd.read_excel(excel_file, sheet_name=sheet_name).to_dict("records")
    except Exception:
        return []


def _excel_statistics(excel_content: bytes, fallback: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    statistics: dict[str, Any] = {}
    try:
        excel_file = io.BytesIO(excel_content)
        stats_df = pd.read_excel(excel_file, sheet_name="统计信息")
        for _, row in stats_df.iterrows():
            key = _cell_text(row.get("统计项"))
            if key:
                statistics[key] = _json_safe_value(row.get("数值"))
    except Exception:
        statistics = {}
    if not statistics and fallback:
        statistics = dict(fallback)
    return statistics


def _normalize_impersonation_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for row in rows or []:
        item = dict(row)
        domain = item.get("仿冒域名") or item.get("钓鱼域名") or item.get("candidate_domain")
        official_domain = item.get("官方域名") or item.get("目标域名") or item.get("target_domain")
        organization = (
            item.get("官方域名单位名称")
            or item.get("公司名称")
            or item.get("单位名称")
            or item.get("target_name")
        )
        unit_type = item.get("单位类型") or item.get("matched_target_type")
        if domain:
            item["仿冒域名"] = domain
            item.setdefault("钓鱼域名", domain)
        if official_domain:
            item["官方域名"] = official_domain
            item.setdefault("目标域名", official_domain)
        if organization:
            item["官方域名单位名称"] = organization
            item.setdefault("公司名称", organization)
        if unit_type:
            item["单位类型"] = unit_type
        normalized.append(_json_safe_value(item))
    return normalized


def build_impersonation_result_payload(
    excel_content: bytes,
    *,
    task_id: str,
    statistics: Optional[dict[str, Any]] = None,
    official_domain_count: Optional[int] = None,
) -> dict[str, Any]:
    results = _normalize_impersonation_rows(_excel_rows(excel_content, "检测结果"))
    phishing_rows = _excel_rows(excel_content, "仿冒域名列表")
    if not phishing_rows:
        phishing_rows = _excel_rows(excel_content, "钓鱼域名列表")
    phishing_rows = _normalize_impersonation_rows(phishing_rows)
    if not phishing_rows:
        phishing_rows = [
            row for row in results
            if row.get("仿冒域名") or row.get("钓鱼域名")
        ]

    statistics_dict = _excel_statistics(excel_content, statistics)
    return _json_safe_value({
        "ok": True,
        "task_id": task_id,
        "task_type": "impersonation",
        "statistics": statistics_dict,
        "results": results,
        "phishing_domains": phishing_rows,
        "total_count": len(results),
        "phishing_count": len(phishing_rows),
        "official_domain_count": official_domain_count,
    })


def _hit_detail(module: str, row: dict[str, Any]) -> dict[str, Any]:
    if module == "impersonation":
        return {
            "domain": _row_domain(row),
            "official_domain": _cell_text(row.get("官方域名") or row.get("目标域名")),
            "organization": _cell_text(row.get("官方域名单位名称") or row.get("公司名称")),
            "score": _score(row.get("相似度")),
            "risk_level": _cell_text(row.get("风险等级")),
            "match_type": _cell_text(row.get("匹配类型")),
            "reason": _cell_text(row.get("命中原因") or row.get("研判原因")),
        }
    if module == "dga":
        return {
            "domain": _row_domain(row),
            "score": _score(row.get("DGA_score") or row.get("dga_score")),
            "family": _cell_text(row.get("DGA家族") or row.get("family")),
            "family_attribution_status": _cell_text(
                row.get("家族归因状态") or row.get("family_attribution_status")
            ),
            "apt_organization_names": _cell_text(
                row.get("APT组织名") or row.get("apt_organization_names")
            ),
            "apt_relationship_types_cn": _cell_text(
                row.get("关联方式") or row.get("apt_relationship_types_cn")
            ),
            "hit_type": _cell_text(row.get("命中方式") or row.get("预测结果")),
            "reason": _cell_text(row.get("规则原因") or row.get("命中方式")),
        }
    if module == "history_similarity":
        return {
            "domain": _row_domain(row),
            "score": _score(row.get("综合相似度") or row.get("score")),
            "matched_domain": _cell_text(row.get("匹配历史恶意域名") or row.get("matched_positive")),
            "reason": _cell_text(row.get("命中原因")),
        }
    return {
        "domain": _row_domain(row),
        "score": _score(row.get("score") or row.get("综合评分")),
        "risk_level": _cell_text(row.get("风险等级") or row.get("risk_level")),
        "matched_template": _cell_text(row.get("匹配模板") or row.get("template")),
        "reason": _cell_text(row.get("命中原因") or row.get("reason")),
    }


def _detail_text(module_hits: dict[str, dict[str, Any]]) -> str:
    parts = []
    for module, label in MODULE_LABELS.items():
        detail = module_hits.get(module)
        if not detail:
            continue
        if module == "impersonation":
            fragments = [
                f"官方域名={detail.get('official_domain') or '-'}",
                f"单位={detail.get('organization') or '-'}",
                f"相似度={_format_score(detail.get('score'))}",
            ]
        elif module == "dga":
            fragments = [
                f"DGA分数={_format_score(detail.get('score'))}",
                f"家族={detail.get('family') or '-'}",
            ]
            if detail.get("apt_organization_names"):
                fragments.extend(
                    [
                        f"APT组织={detail.get('apt_organization_names')}",
                        f"关联方式={detail.get('apt_relationship_types_cn') or '-'}",
                    ]
                )
        elif module == "history_similarity":
            fragments = [
                f"相似度={_format_score(detail.get('score'))}",
                f"匹配历史域名={detail.get('matched_domain') or '-'}",
            ]
        else:
            fragments = [
                f"风险分={_format_score(detail.get('score'))}",
                f"匹配模板={detail.get('matched_template') or '-'}",
            ]
        parts.append(f"{label}（{'；'.join(fragments)}）")
    return "；".join(parts)


def _collect_hits(module: str, payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    list_key = {
        "impersonation": "phishing_domains",
        "dga": "dga_domains",
        "history_similarity": "history_similarity_domains",
        "apt_template_nrd": "apt_template_nrd_domains",
    }[module]
    hits: dict[str, dict[str, Any]] = {}
    for row in payload.get(list_key) or []:
        if not isinstance(row, dict):
            continue
        domain = _row_domain(row)
        if not domain:
            continue
        detail = _hit_detail(module, row)
        current = hits.get(domain)
        if current is None or _score(detail.get("score")) > _score(current.get("score")):
            hits[domain] = detail
    return hits


def _dga_display_priority(detail: dict[str, Any]) -> int:
    family = _cell_text(detail.get("family"))
    family_status = _cell_text(detail.get("family_attribution_status"))
    has_concrete_family = (
        family_status == "usable"
        and family not in {"", "unknown_family", "possible_family"}
    )
    if has_concrete_family and _cell_text(detail.get("apt_organization_names")):
        return 0
    if has_concrete_family:
        return 1
    return 2


def _unified_malicious_sort_key(row: dict[str, Any]) -> tuple[int, float, str]:
    dga_detail = (row.get("module_hits") or {}).get("dga")
    if isinstance(dga_detail, dict):
        return (
            _dga_display_priority(dga_detail),
            -_score(dga_detail.get("score")),
            _row_domain(row),
        )
    return (3, 0.0, _row_domain(row))


def build_unified_malicious_domain_payload(
    *,
    task_id: str,
    input_domains: list[str],
    data_source: str,
    module_payloads: dict[str, dict[str, Any]],
    model_names: Optional[dict[str, str]] = None,
    thresholds: Optional[dict[str, Any]] = None,
    date_range: Optional[list[str]] = None,
    generated_at: Optional[datetime] = None,
) -> dict[str, Any]:
    generated_at = generated_at or datetime.utcnow()
    model_names = model_names or {}
    thresholds = thresholds or {}

    ordered_domains: list[str] = []
    seen = set()
    for domain in input_domains or []:
        normalized = _cell_text(domain).lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            ordered_domains.append(normalized)

    hits_by_module = {
        module: _collect_hits(module, module_payloads.get(module) or {})
        for module in MODULE_LABELS
    }

    results = []
    malicious_domains = []
    normal_domains = []
    label_counter: Counter[str] = Counter()
    overlap_counter: Counter[str] = Counter()

    for domain in ordered_domains:
        module_hits = {
            module: hits[domain]
            for module, hits in hits_by_module.items()
            if domain in hits
        }
        labels = [MODULE_LABELS[module] for module in MODULE_LABELS if module in module_hits]
        for label in labels:
            label_counter[label] += 1
        if labels:
            overlap_counter[" + ".join(labels)] += 1

        row = {
            "域名": domain,
            "判定结果": "恶意" if labels else "正常",
            "恶意类别": "、".join(labels) if labels else "",
            "恶意类别标签": labels,
            "命中模块数": len(labels),
            "命中详情": _detail_text(module_hits),
            "module_hits": module_hits,
        }
        results.append(row)
        if labels:
            malicious_domains.append(row)
        else:
            normal_domains.append(row)

    total = len(ordered_domains)
    malicious_domains.sort(key=_unified_malicious_sort_key)
    malicious_count = len(malicious_domains)
    normal_count = len(normal_domains)
    statistics = {
        "总域名数": total,
        "恶意域名数": malicious_count,
        "正常域名数": normal_count,
        "恶意域名占比": _percent(malicious_count, total),
        "仿冒域名数": label_counter.get(MODULE_LABELS["impersonation"], 0),
        "DGA域名数": label_counter.get(MODULE_LABELS["dga"], 0),
        "历史APT相似域名数": label_counter.get(MODULE_LABELS["history_similarity"], 0),
        "模板化APT域名数": label_counter.get(MODULE_LABELS["apt_template_nrd"], 0),
    }

    payload = {
        "ok": True,
        "task_id": task_id,
        "task_type": "malicious",
        "unified_detection": True,
        "generated_at": generated_at.isoformat(),
        "data_source": data_source,
        "data_source_label": _source_label(data_source),
        "date_range": date_range or [],
        "model_names": model_names,
        "thresholds": thresholds,
        "statistics": statistics,
        "results": results,
        "malicious_domains": malicious_domains,
        "unified_malicious_domains": malicious_domains,
        "normal_domains": normal_domains,
        "total_count": total,
        "malicious_count": malicious_count,
        "normal_count": normal_count,
        "label_counts": dict(label_counter),
        "overlap_counts": dict(overlap_counter),
        "module_results": module_payloads,
    }
    return _json_safe_value(payload)


def build_unified_malicious_domain_result_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")


def _dga_result_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    dga_payload = (payload.get("module_results") or {}).get("dga") or {}
    rows: list[dict[str, Any]] = []
    seen_domains: set[str] = set()
    for row in dga_payload.get("dga_domains") or []:
        if not isinstance(row, dict):
            continue
        domain = _row_domain(row)
        actor_names = _cell_text(
            row.get("APT组织名") or row.get("apt_organization_names")
        )
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)
        family = _cell_text(row.get("DGA家族") or row.get("family"))
        family_status = _cell_text(
            row.get("家族归因状态") or row.get("family_attribution_status")
        )
        rows.append(
            {
                "domain": domain,
                "_score_value": _score(row.get("DGA_score") or row.get("dga_score")),
                "score": _format_score(row.get("DGA_score") or row.get("dga_score")),
                "family": family or "unknown_family",
                "family_attribution_status": family_status,
                "apt_organization_names": actor_names or "-",
                "apt_relationship_types_cn": _cell_text(
                    row.get("关联方式") or row.get("apt_relationship_types_cn")
                )
                or "-",
            }
        )
    sorted_rows = sorted(
        rows,
        key=lambda row: (
            _dga_display_priority(
                {
                    "family": row["family"],
                    "family_attribution_status": row["family_attribution_status"],
                    "apt_organization_names": ""
                    if row["apt_organization_names"] == "-"
                    else row["apt_organization_names"],
                }
            ),
            -row["_score_value"],
            row["domain"],
        ),
    )
    for row in sorted_rows:
        row.pop("_score_value", None)
    return sorted_rows


def _build_report_context(payload: dict[str, Any]) -> dict[str, Any]:
    total = int(payload.get("total_count") or 0)
    malicious_count = int(payload.get("malicious_count") or 0)
    statistics = payload.get("statistics") or {}
    label_counts = payload.get("label_counts") or {}
    overlap_counts = payload.get("overlap_counts") or {}
    malicious_domains = payload.get("unified_malicious_domains") or []

    module_summaries = [
        {
            "module": label,
            "count": int(label_counts.get(label, 0) or 0),
            "percent": _percent(int(label_counts.get(label, 0) or 0), total),
            "model_name": (payload.get("model_names") or {}).get(module, "-"),
        }
        for module, label in MODULE_LABELS.items()
    ]

    overlap_summaries = [
        {"labels": labels, "count": count, "percent": _percent(count, malicious_count)}
        for labels, count in sorted(overlap_counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    if not overlap_summaries:
        overlap_summaries = [{"labels": "未命中", "count": 0, "percent": "0.00%"}]

    top_domains = list(malicious_domains)[:50]
    if not top_domains:
        top_domains = [
            {
                "域名": "未命中",
                "恶意类别": "-",
                "命中模块数": 0,
                "命中详情": "本次任务未发现被任一模块判定为恶意的域名",
            }
        ]

    dga_result_rows = _dga_result_rows(payload)
    dga_source_rows = (
        ((payload.get("module_results") or {}).get("dga") or {}).get("dga_domains")
        or []
    )
    actor_relationship_overview = build_attribution_relationship_overview(
        row for row in dga_source_rows if isinstance(row, dict)
    )
    dga_actor_attribution_count = sum(
        row["apt_organization_names"] != "-" for row in dga_result_rows
    )

    return {
        "task_id": payload.get("task_id"),
        "generated_at": _cell_text(payload.get("generated_at"))[:19].replace("T", " "),
        "data_source_label": payload.get("data_source_label") or _source_label(payload.get("data_source") or ""),
        "date_range": payload.get("date_range") or [],
        "statistics": statistics,
        "total_count": total,
        "malicious_count": malicious_count,
        "normal_count": int(payload.get("normal_count") or 0),
        "malicious_rate": statistics.get("恶意域名占比") or _percent(malicious_count, total),
        "module_summaries": module_summaries,
        "overlap_summaries": overlap_summaries,
        "top_domains": top_domains,
        "dga_result_count": len(dga_result_rows),
        "dga_actor_attribution_count": dga_actor_attribution_count,
        "dga_result_rows": dga_result_rows,
        "actor_relationship_overview": actor_relationship_overview,
        "thresholds": payload.get("thresholds") or {},
    }


def render_unified_malicious_domain_report_markdown(payload: dict[str, Any]) -> str:
    try:
        from jinja2 import Environment
    except ImportError as exc:
        raise RuntimeError("缺少 Jinja2 依赖，无法渲染恶意域名检测报告模板") from exc

    template_text = REPORT_TEMPLATE_PATH.read_text(encoding="utf-8")
    env = Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)
    env.filters["mdcell"] = _markdown_cell
    template = env.from_string(template_text)
    return template.render(**_build_report_context(payload))


def generate_unified_malicious_domain_pdf_report(payload: dict[str, Any]) -> bytes:
    markdown_text = render_unified_malicious_domain_report_markdown(payload)
    return render_markdown_report_to_pdf(
        markdown_text,
        task_id=str(payload.get("task_id") or ""),
        report_title="APTHunter 恶意域名检测报告",
    )
