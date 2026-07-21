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
    / "DGA域名检测报告模板.md"
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


def _score(value: Any) -> float:
    try:
        score = float(value or 0)
        return score if math.isfinite(score) else 0.0
    except (TypeError, ValueError):
        return 0.0


def _format_score(value: Any) -> str:
    return f"{_score(value):.4f}"


def _percent(part: int, total: int) -> str:
    return f"{(part / total * 100):.2f}%" if total else "0.00%"


def _int_stat(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


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
    for key in ("域名", "规范化域名", "domain", "domain_name"):
        domain = _cell_text(row.get(key)).lower()
        if domain:
            return domain
    return ""


def _is_dga_hit(row: dict[str, Any]) -> bool:
    if not isinstance(row, dict):
        return False
    label = _cell_text(row.get("预测标签"))
    result = _cell_text(row.get("预测结果"))
    return label in {"1", "1.0"} or result in {"高置信DGA", "DGA-like"}


def _dedupe_dga_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best_by_domain: dict[str, dict[str, Any]] = {}
    ordered_domains: list[str] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        domain = _row_domain(row)
        if not domain:
            continue
        current = best_by_domain.get(domain)
        if current is None:
            ordered_domains.append(domain)
            best_by_domain[domain] = row
            continue
        current_score = _score(current.get("DGA_score") or current.get("dga_score"))
        if _score(row.get("DGA_score") or row.get("dga_score")) > current_score:
            best_by_domain[domain] = row
    return [best_by_domain[domain] for domain in ordered_domains]


def _read_statistics(excel_file: io.BytesIO) -> dict[str, Any]:
    statistics_dict: dict[str, Any] = {}
    try:
        excel_file.seek(0)
        stats_df = pd.read_excel(excel_file, sheet_name="统计信息")
        for _, row in stats_df.iterrows():
            key = _cell_text(row.get("统计项"))
            if key:
                statistics_dict[key] = _json_safe_value(row.get("数值"))
    except Exception:
        statistics_dict = {}
    return statistics_dict


def build_dga_result_payload(
    excel_content: bytes,
    *,
    task_id: str,
    result_file_key: Optional[str] = None,
    result_filename: Optional[str] = None,
    dga_meta: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build the JSON payload used by online result views after PDF replaces XLSX."""
    excel_file = io.BytesIO(excel_content)
    try:
        results_df = pd.read_excel(excel_file, sheet_name="预测结果")
    except Exception:
        results_df = pd.DataFrame()

    statistics_dict = _read_statistics(excel_file)

    dga_rows: list[dict[str, Any]] = []
    try:
        excel_file.seek(0)
        dga_df = pd.read_excel(excel_file, sheet_name="DGA域名列表")
        dga_rows = dga_df.to_dict("records")
    except Exception:
        pass

    family_rows: list[dict[str, Any]] = []
    try:
        excel_file.seek(0)
        family_df = pd.read_excel(excel_file, sheet_name="DGA家族统计")
        family_rows = family_df.to_dict("records")
    except Exception:
        pass

    results_list = results_df.to_dict("records")
    dga_list = _dedupe_dga_rows(dga_rows)
    if not dga_list:
        dga_list = _dedupe_dga_rows([row for row in results_list if _is_dga_hit(row)])

    payload = {
        "ok": True,
        "task_id": task_id,
        "task_type": "dga",
        "statistics": statistics_dict,
        "results": results_list,
        "dga_domains": dga_list,
        "dga_family_statistics": family_rows,
        "result_file_key": result_file_key,
        "result_filename": result_filename or f"{task_id}_report.pdf",
        "total_count": len(results_list),
        "dga_count": len(dga_list),
        "dga_detection": dga_meta or {},
    }
    return _json_safe_value(payload)


def build_dga_result_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")


def _family_label(value: Any) -> str:
    family = _cell_text(value)
    if family in {"", "unknown_family", "possible_family"}:
        return "未识别具体家族"
    return family


def _family_is_concrete(value: Any) -> bool:
    family = _cell_text(value)
    return family not in {"", "unknown_family", "possible_family"}


def _hit_type(row: dict[str, Any]) -> str:
    return _cell_text(row.get("命中方式") or row.get("hit_type") or row.get("reason")) or "高置信DGA"


def _report_dga_sort_key(row: dict[str, Any]) -> tuple[int, float, str]:
    family = row.get("DGA家族") or row.get("family")
    status = _cell_text(
        row.get("家族归因状态") or row.get("family_attribution_status")
    )
    has_concrete_family = status == "usable" and _family_is_concrete(family)
    has_actor_clue = bool(
        _cell_text(row.get("APT组织名") or row.get("apt_organization_names"))
    )
    if has_concrete_family and has_actor_clue:
        priority = 0
    elif has_concrete_family:
        priority = 1
    else:
        priority = 2
    return (
        priority,
        -_score(row.get("DGA_score") or row.get("dga_score")),
        _row_domain(row),
    )


def _family_overview_from_payload(
    *,
    family_rows: list[dict[str, Any]],
    dga_rows: list[dict[str, Any]],
    dga_count: int,
) -> list[dict[str, Any]]:
    overview: list[dict[str, Any]] = []
    for row in family_rows or []:
        family = _family_label(row.get("DGA家族") or row.get("family"))
        count = _int_stat(row.get("高置信DGA数量") or row.get("count"), 0)
        if count <= 0:
            continue
        overview.append({"family": family, "count": count, "percent": _percent(count, dga_count)})
    if overview:
        return overview

    counter = Counter(_family_label(row.get("DGA家族") or row.get("family")) for row in dga_rows)
    if not counter:
        return [{"family": "未命中", "count": 0, "percent": "0.00%"}]
    return [
        {"family": family, "count": count, "percent": _percent(count, dga_count)}
        for family, count in counter.most_common(10)
    ]


def _build_report_context(
    payload: dict[str, Any],
    *,
    task_id: str,
    model_name: str,
    data_source: str,
    candidate_threshold: float,
    date_range: Optional[list[str]] = None,
    generated_at: Optional[datetime] = None,
) -> dict[str, Any]:
    generated_at = generated_at or datetime.utcnow()
    statistics = payload.get("statistics") or {}
    results = payload.get("results") or []
    dga_rows = payload.get("dga_domains") or []
    family_rows = payload.get("dga_family_statistics") or []
    dga_meta = payload.get("dga_detection") or {}

    total = _int_stat(statistics.get("总域名数") or payload.get("total_count"), len(results))
    candidate_count = _int_stat(statistics.get("DGA候选数") or dga_meta.get("candidate_count"), 0)
    if not candidate_count:
        family_input_threshold = _score(dga_meta.get("family_input_threshold") or candidate_threshold)
        candidate_count = sum(1 for row in results if _score(row.get("DGA_score") or row.get("dga_score")) >= family_input_threshold)
    dga_count = _int_stat(statistics.get("高置信DGA域名数") or statistics.get("DGA域名数") or payload.get("dga_count"), len(dga_rows))
    direct_count = _int_stat(statistics.get("主模型高置信数"), 0)
    if not direct_count:
        direct_threshold = _score(dga_meta.get("direct_high_confidence_threshold") or 0.98)
        direct_count = sum(1 for row in dga_rows if _score(row.get("DGA_score") or row.get("dga_score")) >= direct_threshold)
    family_promoted_count = _int_stat(statistics.get("家族确认提升数"), 0)
    family_attributed_count = _int_stat(statistics.get("识别出DGA家族的域名数") or dga_meta.get("family_attributed_count"), 0)
    if not family_attributed_count:
        family_attributed_count = sum(1 for row in dga_rows if _cell_text(row.get("家族归因状态")) == "usable")
    unique_family_count = _int_stat(statistics.get("识别出的DGA家族种类数"), 0)
    if not unique_family_count:
        unique_family_count = len(
            {
                _cell_text(row.get("DGA家族") or row.get("family"))
                for row in dga_rows
                if _cell_text(row.get("家族归因状态")) == "usable"
                and _family_is_concrete(row.get("DGA家族") or row.get("family"))
            }
        )
    dga_rate_text = str(statistics.get("DGA域名占比") or _percent(dga_count, total))
    detection_policy = _cell_text(statistics.get("检测口径") or dga_meta.get("high_confidence_policy")) or (
        f"DGA分数达到主模型高置信阈值，或DGA分数达到候选阈值 {candidate_threshold:.2f} 且家族识别可展示"
    )

    invalid_count = _int_stat(statistics.get("无效输入数"), 0)
    duplicate_count = _int_stat(statistics.get("重复输入数"), 0)
    valid_count = max(0, total)

    candidate_only_count = max(0, candidate_count - dga_count)
    normal_count = max(0, total - dga_count - candidate_only_count)
    risk_levels = [
        {
            "level": "高置信DGA",
            "count": dga_count,
            "percent": _percent(dga_count, total),
            "action": "建议优先复核并按需阻断",
        },
        {
            "level": "DGA候选",
            "count": candidate_only_count,
            "percent": _percent(candidate_only_count, total),
            "action": "建议加入持续观察并结合解析行为复核",
        },
        {
            "level": "正常",
            "count": normal_count,
            "percent": _percent(normal_count, total),
            "action": "保留结果用于后续回溯",
        },
    ]

    top_rows = sorted(dga_rows, key=_report_dga_sort_key)[:30]
    top_domains = [
        {
            "domain": _cell_text(row.get("域名") or row.get("domain")),
            "score": _format_score(row.get("DGA_score") or row.get("dga_score")),
            "hit_type": _hit_type(row),
            "family": _family_label(row.get("DGA家族") or row.get("family")),
            "family_confidence": _format_score(row.get("家族置信度") or row.get("family_confidence")),
            "apt_organization_names": _cell_text(
                row.get("APT组织名") or row.get("apt_organization_names")
            ),
            "apt_relationship_types_cn": _cell_text(
                row.get("关联方式") or row.get("apt_relationship_types_cn")
            ),
        }
        for row in top_rows
    ]
    if not top_domains:
        top_domains = [
            {
                "domain": "未命中",
                "score": "0.0000",
                "hit_type": "-",
                "family": "-",
                "family_confidence": "0.0000",
                "apt_organization_names": "-",
                "apt_relationship_types_cn": "-",
            }
        ]

    family_overview = _family_overview_from_payload(
        family_rows=family_rows,
        dga_rows=dga_rows,
        dga_count=dga_count,
    )
    actor_relationship_overview = build_attribution_relationship_overview(dga_rows)

    hit_counter = Counter(_hit_type(row) for row in dga_rows)
    hit_type_overview = [
        {"hit_type": hit_type, "count": count, "percent": _percent(count, dga_count)}
        for hit_type, count in hit_counter.most_common(8)
    ]
    if not hit_type_overview:
        hit_type_overview = [{"hit_type": "未命中", "count": 0, "percent": "0.00%"}]

    if dga_count:
        conclusion = (
            f"本次任务共检测域名 {total} 条，发现高置信DGA域名 {dga_count} 条，占比 {dga_rate_text}。"
            f"其中主模型高置信 {direct_count} 条，家族确认提升 {family_promoted_count} 条，"
            f"可展示具体家族的域名 {family_attributed_count} 条，覆盖 {unique_family_count} 个DGA家族。"
            "建议优先复核高分、家族归因明确和命中方式为家族确认提升的域名。"
        )
        final_conclusion = (
            f"本次DGA域名检测发现 {dga_count} 条高置信DGA域名。"
            "建议结合解析记录、访问日志和外部情报完成确认，并对确认异常对象执行阻断和回溯。"
        )
    elif candidate_only_count:
        conclusion = (
            f"本次任务共检测域名 {total} 条，发现 DGA候选 {candidate_only_count} 条，但未达到高置信DGA口径。"
            "建议对候选域名持续观察，重点关注后续解析和访问行为变化。"
        )
        final_conclusion = "本次DGA域名检测未发现高置信DGA域名，但存在候选对象，建议纳入持续监测。"
    else:
        conclusion = (
            f"本次任务共检测域名 {total} 条，未发现达到候选阈值 {candidate_threshold:.2f} 的DGA域名。"
            "当前结果可作为后续回溯基线，建议结合新注册域名数据持续复检。"
        )
        final_conclusion = "本次DGA域名检测未发现高置信DGA域名。当前结论不代表域名绝对安全，建议持续复检。"

    return {
        "report_no": f"APTHunter-DGA-{generated_at.strftime('%Y%m%d')}-{task_id}",
        "generated_at": generated_at.strftime("%Y-%m-%d %H:%M:%S"),
        "task_id": task_id,
        "model_name": model_name,
        "data_source_label": _source_label(data_source),
        "detection_scope": "、".join(date_range or []) if date_range else _source_label(data_source),
        "total": total,
        "candidate_count": candidate_count,
        "dga_count": dga_count,
        "normal_count": normal_count,
        "dga_rate_text": dga_rate_text,
        "candidate_threshold_text": f"{candidate_threshold:.2f}",
        "direct_count": direct_count,
        "family_promoted_count": family_promoted_count,
        "family_attributed_count": family_attributed_count,
        "unique_family_count": unique_family_count,
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "duplicate_count": duplicate_count,
        "detection_policy": detection_policy,
        "risk_levels": risk_levels,
        "top_domains": top_domains,
        "actor_relationship_overview": actor_relationship_overview,
        "family_overview": family_overview,
        "hit_type_overview": hit_type_overview,
        "conclusion": conclusion,
        "final_conclusion": final_conclusion,
    }


def render_dga_report_markdown(
    payload: dict[str, Any],
    *,
    task_id: str,
    model_name: str,
    data_source: str,
    candidate_threshold: float,
    date_range: Optional[list[str]] = None,
    generated_at: Optional[datetime] = None,
) -> str:
    try:
        from jinja2 import Environment
    except ImportError as exc:
        raise RuntimeError("缺少 Jinja2 依赖，无法渲染DGA域名检测报告模板") from exc

    template_text = REPORT_TEMPLATE_PATH.read_text(encoding="utf-8")
    env = Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)
    env.filters["mdcell"] = _markdown_cell
    template = env.from_string(template_text)
    context = _build_report_context(
        payload,
        task_id=task_id,
        model_name=model_name,
        data_source=data_source,
        candidate_threshold=candidate_threshold,
        date_range=date_range,
        generated_at=generated_at,
    )
    return template.render(**context)


def generate_dga_pdf_report(
    payload: dict[str, Any],
    *,
    task_id: str,
    model_name: str,
    data_source: str,
    candidate_threshold: float,
    date_range: Optional[list[str]] = None,
    generated_at: Optional[datetime] = None,
) -> bytes:
    markdown_text = render_dga_report_markdown(
        payload,
        task_id=task_id,
        model_name=model_name,
        data_source=data_source,
        candidate_threshold=candidate_threshold,
        date_range=date_range,
        generated_at=generated_at,
    )
    return render_markdown_report_to_pdf(
        markdown_text,
        task_id=task_id,
        report_title="APTHunter DGA域名检测报告",
    )
