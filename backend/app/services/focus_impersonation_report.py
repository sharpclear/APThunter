from __future__ import annotations

import math
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from app.services.history_similarity_report import render_markdown_report_to_pdf
from app.services.unified_malicious_domain_report import build_impersonation_result_payload


REPORT_TEMPLATE_PATH = (
    Path(__file__).resolve().parents[2]
    / "报告模板"
    / "重点单位仿冒检测报告模板.md"
)


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


def _markdown_cell(value: Any) -> str:
    text = _cell_text(value).replace("|", "/")
    text = re.sub(r"\s+", " ", text)
    return text.strip() or "-"


def _percent(part: int, total: int) -> str:
    return f"{(part / total * 100):.2f}%" if total else "0.00%"


def _parse_count(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            return None
        return max(0, int(value))
    text = _cell_text(value).replace(",", "")
    if not text:
        return None
    match = re.search(r"-?\d+(?:\.\d+)?", text)
    if not match:
        return None
    try:
        return max(0, int(float(match.group(0))))
    except ValueError:
        return None


def _stats_count(statistics: dict[str, Any], keys: tuple[str, ...], fallback: int) -> int:
    for key in keys:
        parsed = _parse_count(statistics.get(key))
        if parsed is not None:
            return parsed
    return max(0, int(fallback or 0))


def _stats_percent(statistics: dict[str, Any], keys: tuple[str, ...], part: int, total: int) -> str:
    for key in keys:
        value = statistics.get(key)
        text = _cell_text(value)
        if not text:
            continue
        if "%" in text:
            return text
        try:
            number = float(text.replace(",", ""))
        except ValueError:
            continue
        if not math.isfinite(number):
            continue
        return f"{(number * 100 if 0 <= number <= 1 else number):.2f}%"
    return _percent(part, total)


def normalize_official_domain_rows(official_domains: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen = set()
    for item in official_domains or []:
        company = ""
        domain = ""
        confidence: Any = ""
        reason = ""
        if isinstance(item, dict):
            company = item.get("单位名称") or item.get("公司名称") or item.get("organization") or item.get("company") or ""
            domain = item.get("官方域名") or item.get("域名") or item.get("domain") or item.get("target_domain") or ""
            confidence = item.get("confidence") if item.get("confidence") is not None else item.get("置信度", "")
            reason = item.get("reason") or item.get("说明") or item.get("evidence") or ""
        elif isinstance(item, (list, tuple)):
            if len(item) >= 2:
                company, domain = item[0], item[1]
            elif len(item) == 1:
                domain = item[0]
        else:
            domain = item

        domain = _cell_text(domain).lower()
        if not domain or domain in seen:
            continue
        seen.add(domain)
        rows.append({
            "单位名称": _cell_text(company),
            "官方域名": domain,
            "置信度": confidence,
            "说明": _cell_text(reason),
        })
    return _json_safe_value(rows)


def _impersonation_domain(item: dict[str, Any]) -> str:
    return _cell_text(item.get("仿冒域名") or item.get("钓鱼域名") or item.get("域名"))


def _official_domain(item: dict[str, Any]) -> str:
    return _cell_text(item.get("官方域名") or item.get("目标域名"))


def _official_name(item: dict[str, Any]) -> str:
    return _cell_text(item.get("官方域名单位名称") or item.get("公司名称") or item.get("单位名称"))


def build_focus_impersonation_report_payload(
    excel_content: bytes,
    *,
    task_id: str,
    query_name: str,
    official_domains: Any,
    statistics: Optional[dict[str, Any]] = None,
    date_range: Optional[list[str]] = None,
    generated_at: Optional[datetime] = None,
) -> dict[str, Any]:
    generated_at = generated_at or datetime.utcnow()
    base_payload = build_impersonation_result_payload(
        excel_content,
        task_id=task_id,
        statistics=statistics,
    )
    official_rows = normalize_official_domain_rows(official_domains)
    phishing_rows = base_payload.get("phishing_domains") or []
    statistics_dict = dict(base_payload.get("statistics") or {})
    if statistics:
        statistics_dict.update(_json_safe_value(statistics))
    detail_total_count = int(base_payload.get("total_count") or 0)
    detail_phishing_count = int(base_payload.get("phishing_count") or len(phishing_rows))
    total_count = _stats_count(statistics_dict, ("总域名数", "total"), detail_total_count)
    phishing_count = _stats_count(
        statistics_dict,
        ("仿冒域名数", "钓鱼域名数", "impersonation"),
        detail_phishing_count,
    )
    normal_count = _stats_count(
        statistics_dict,
        ("正常域名数", "benign"),
        max(0, total_count - phishing_count),
    )
    phishing_rate = _stats_percent(
        statistics_dict,
        ("仿冒域名占比", "钓鱼域名占比", "impersonation_rate"),
        phishing_count,
        total_count,
    )

    target_counts: dict[str, int] = {}
    for row in phishing_rows:
        if not isinstance(row, dict):
            continue
        target = _official_name(row) or _official_domain(row) or "未知对象"
        target_counts[target] = target_counts.get(target, 0) + 1
    target_summaries = [
        {"target": target, "count": count, "percent": _percent(count, phishing_count)}
        for target, count in sorted(target_counts.items(), key=lambda item: (-item[1], item[0]))
    ]

    return _json_safe_value({
        "ok": True,
        "task_id": task_id,
        "task_type": "impersonation",
        "focus_impersonation_detection": True,
        "query_name": query_name,
        "generated_at": generated_at.isoformat(),
        "date_range": date_range or [],
        "statistics": statistics_dict,
        "official_domains": official_rows,
        "results": base_payload.get("results") or [],
        "phishing_domains": phishing_rows,
        "total_count": total_count,
        "phishing_count": phishing_count,
        "normal_count": normal_count,
        "phishing_rate": phishing_rate,
        "target_summaries": target_summaries,
    })


def _build_report_context(payload: dict[str, Any]) -> dict[str, Any]:
    official_rows = payload.get("official_domains") or []
    phishing_rows = payload.get("phishing_domains") or []
    top_domains = [
        {
            "domain": _impersonation_domain(row),
            "target": _official_name(row) or _official_domain(row) or "未知对象",
            "official_domain": _official_domain(row),
            "match_type": _cell_text(row.get("匹配类型")),
            "risk_level": _cell_text(row.get("风险等级")),
            "reason": _cell_text(row.get("研判原因") or row.get("命中原因") or row.get("关键特征")),
        }
        for row in phishing_rows[:50]
        if isinstance(row, dict)
    ]
    if not top_domains:
        top_domains = [{
            "domain": "未命中",
            "target": "-",
            "official_domain": "-",
            "match_type": "-",
            "risk_level": "-",
            "reason": "本次任务未发现重点单位仿冒域名",
        }]

    return {
        "task_id": payload.get("task_id"),
        "query_name": payload.get("query_name") or "-",
        "generated_at": _cell_text(payload.get("generated_at"))[:19].replace("T", " "),
        "date_range": payload.get("date_range") or [],
        "official_domains": official_rows,
        "official_domain_count": len(official_rows),
        "statistics": payload.get("statistics") or {},
        "total_count": int(payload.get("total_count") or 0),
        "phishing_count": int(payload.get("phishing_count") or 0),
        "normal_count": int(payload.get("normal_count") or 0),
        "phishing_rate": payload.get("phishing_rate") or "0.00%",
        "target_summaries": payload.get("target_summaries") or [],
        "top_domains": top_domains,
    }


def render_focus_impersonation_report_markdown(payload: dict[str, Any]) -> str:
    try:
        from jinja2 import Environment
    except ImportError as exc:
        raise RuntimeError("缺少 Jinja2 依赖，无法渲染重点单位仿冒检测报告模板") from exc

    template_text = REPORT_TEMPLATE_PATH.read_text(encoding="utf-8")
    env = Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)
    env.filters["mdcell"] = _markdown_cell
    template = env.from_string(template_text)
    return template.render(**_build_report_context(payload))


def generate_focus_impersonation_pdf_report(payload: dict[str, Any]) -> bytes:
    markdown_text = render_focus_impersonation_report_markdown(payload)
    return render_markdown_report_to_pdf(
        markdown_text,
        task_id=str(payload.get("task_id") or ""),
        report_title="APTHunter 重点单位仿冒检测报告",
    )
