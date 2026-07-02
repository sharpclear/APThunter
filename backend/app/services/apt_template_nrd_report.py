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

from app.services.history_similarity_report import render_markdown_report_to_pdf


REPORT_TEMPLATE_PATH = (
    Path(__file__).resolve().parents[2]
    / "报告模板"
    / "模板化APT域名检测报告模板.md"
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
    text = _cell_text(value)
    text = text.replace("|", "/")
    text = re.sub(r"\s+", " ", text)
    return text.strip() or "-"


def _source_label(value: str) -> str:
    return {
        "upload": "上传文件",
        "newDomain": "新注册域名",
        "manualInput": "手动输入域名",
    }.get(value or "", value or "未知")


def _risk_label(row: dict[str, Any]) -> str:
    value = _cell_text(row.get("风险等级") or row.get("risk_level")).lower()
    return {
        "high": "高",
        "medium": "中",
        "low": "低",
        "高": "高",
        "中": "中",
        "低": "低",
    }.get(value, value or "未知")


def _is_apt_hit(row: dict[str, Any]) -> bool:
    if not isinstance(row, dict):
        return False
    label = _cell_text(row.get("预测标签"))
    result = _cell_text(row.get("预测结果"))
    return label in {"1", "1.0"} or result in {"模板化APT命中", "APT模板命中"} or _score(row.get("score")) > 0


def _dedupe_domain_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best_by_domain: dict[str, dict[str, Any]] = {}
    ordered_domains: list[str] = []
    for row in rows or []:
        domain = _cell_text(row.get("域名") or row.get("domain")).lower()
        if not domain:
            continue
        current = best_by_domain.get(domain)
        if current is None:
            ordered_domains.append(domain)
            best_by_domain[domain] = row
            continue
        if _score(row.get("score")) > _score(current.get("score")):
            best_by_domain[domain] = row
    return [best_by_domain[domain] for domain in ordered_domains]


def build_apt_template_nrd_result_payload(
    excel_content: bytes,
    *,
    task_id: str,
    result_file_key: Optional[str] = None,
    result_filename: Optional[str] = None,
    apt_meta: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build the JSON payload used by online result views after PDF replaces XLSX."""
    excel_file = io.BytesIO(excel_content)
    try:
        results_df = pd.read_excel(excel_file, sheet_name="预测结果")
    except Exception:
        results_df = pd.DataFrame()

    statistics_dict: dict[str, Any] = {}
    try:
        excel_file.seek(0)
        stats_df = pd.read_excel(excel_file, sheet_name="统计信息")
        for _, row in stats_df.iterrows():
            statistics_dict[_cell_text(row.get("统计项"))] = _json_safe_value(row.get("数值"))
    except Exception:
        statistics_dict = {}

    apt_rows: list[dict[str, Any]] = []
    try:
        excel_file.seek(0)
        try:
            apt_df = pd.read_excel(excel_file, sheet_name="模板化APT域名列表")
        except Exception:
            excel_file.seek(0)
            apt_df = pd.read_excel(excel_file, sheet_name="APT模板命中域名列表")
        apt_rows = apt_df.to_dict("records")
    except Exception:
        pass

    results_list = results_df.to_dict("records")
    apt_list = _dedupe_domain_rows(apt_rows)
    if not apt_list:
        apt_list = _dedupe_domain_rows([row for row in results_list if _is_apt_hit(row)])

    payload = {
        "ok": True,
        "task_id": task_id,
        "task_type": "apt_template_nrd",
        "statistics": statistics_dict,
        "results": results_list,
        "apt_template_nrd_domains": apt_list,
        "result_file_key": result_file_key,
        "result_filename": result_filename or f"{task_id}_report.pdf",
        "total_count": len(results_list),
        "apt_template_nrd_count": len(apt_list),
        "apt_template_nrd_detection": apt_meta or {},
    }
    return _json_safe_value(payload)


def build_apt_template_nrd_result_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")


def _build_report_context(
    payload: dict[str, Any],
    *,
    task_id: str,
    model_name: str,
    data_source: str,
    score_threshold: float,
    date_range: Optional[list[str]] = None,
    generated_at: Optional[datetime] = None,
) -> dict[str, Any]:
    generated_at = generated_at or datetime.utcnow()
    statistics = payload.get("statistics") or {}
    results = payload.get("results") or []
    apt_rows = payload.get("apt_template_nrd_domains") or []
    apt_meta = payload.get("apt_template_nrd_detection") or {}
    input_stats = apt_meta.get("input_stats") or {}

    total = _int_stat(statistics.get("总域名数") or payload.get("total_count"), len(results))
    matched_count = _int_stat(statistics.get("模板化APT域名数") or statistics.get("APT模板命中域名数"), 0)
    high_risk_count = _int_stat(statistics.get("高风险域名数") or payload.get("apt_template_nrd_count"), len(apt_rows))
    normal_count = _int_stat(statistics.get("正常域名数"), max(0, total - matched_count))
    matched_rate_text = str(statistics.get("模板化APT域名占比") or statistics.get("APT模板命中域名占比") or _percent(matched_count, total))
    high_risk_rate_text = str(statistics.get("高风险域名占比") or _percent(high_risk_count, total))
    template_count = _int_stat(statistics.get("模板数量") or apt_meta.get("template_count"), 0)
    valid_count = _int_stat(input_stats.get("valid_count"), total)
    invalid_count = _int_stat(statistics.get("无效输入数") or input_stats.get("invalid_count"), 0)
    duplicate_count = _int_stat(statistics.get("重复输入数") or input_stats.get("duplicate_count"), 0)
    template_match_counts = apt_meta.get("template_match_counts") or {}

    matched_rows = [row for row in results if _is_apt_hit(row)]
    risk_counter = Counter(_risk_label(row) for row in matched_rows)
    template_counter = Counter(
        _cell_text(row.get("匹配模板") or row.get("matched_template"))
        for row in apt_rows
        if _cell_text(row.get("匹配模板") or row.get("matched_template"))
    )
    if not template_counter and isinstance(template_match_counts, dict):
        template_counter = Counter({str(key): int(value) for key, value in template_match_counts.items()})
    reason_counter = Counter(_cell_text(row.get("命中原因") or row.get("reason")) or "命中模板化APT域名模板" for row in apt_rows)

    risk_levels = []
    for level in ("高", "中", "低", "未知"):
        count = risk_counter.get(level, 0)
        risk_levels.append(
            {
                "level": level,
                "count": count,
                "percent": _percent(count, max(1, matched_count)),
                "action": {
                    "高": "建议立即复核并优先阻断",
                    "中": "建议结合基础设施证据复核",
                    "低": "建议加入持续观察",
                    "未知": "建议人工补充研判",
                }[level],
            }
        )

    top_rows = sorted(apt_rows or matched_rows, key=lambda row: _score(row.get("score")), reverse=True)[:30]
    top_domains = [
        {
            "domain": _cell_text(row.get("域名") or row.get("domain")),
            "score": _format_score(row.get("score")),
            "risk_level": _risk_label(row),
            "template": _cell_text(row.get("匹配模板") or row.get("matched_template")) or "未知",
            "reason": _cell_text(row.get("命中原因") or row.get("reason")) or "命中模板化APT域名模板",
        }
        for row in top_rows
    ]
    if not top_domains:
        top_domains = [
            {
                "domain": "未命中",
                "score": "0.0000",
                "risk_level": "-",
                "template": "-",
                "reason": "本次任务未发现达到阈值的模板化APT域名",
            }
        ]

    template_overview = [
        {"template": template, "count": count, "percent": _percent(count, high_risk_count)}
        for template, count in template_counter.most_common(10)
    ]
    if not template_overview:
        template_overview = [{"template": "未命中", "count": 0, "percent": "0.00%"}]

    reason_overview = [
        {"reason": reason, "count": count, "percent": _percent(count, high_risk_count)}
        for reason, count in reason_counter.most_common(8)
    ]
    if not reason_overview:
        reason_overview = [{"reason": "未命中", "count": 0, "percent": "0.00%"}]

    if high_risk_count:
        conclusion = (
            f"本次任务共检测域名 {total} 条，发现模板化APT域名 {matched_count} 条，"
            f"其中达到预警阈值 {score_threshold:.2f} 的高风险域名 {high_risk_count} 条，高风险占比 {high_risk_rate_text}。"
            "命中结果说明部分域名在命名结构上符合历史APT注册模板，应结合解析、证书、WHOIS 和访问日志进行复核。"
        )
        final_conclusion = (
            f"本次模板化APT域名检测发现 {high_risk_count} 条高风险模板命中域名。"
            "建议优先处置风险分较高和命中高频模板的域名，并将同类模板纳入持续监测。"
        )
    elif matched_count:
        conclusion = (
            f"本次任务共检测域名 {total} 条，发现模板化APT域名 {matched_count} 条，"
            f"但未发现达到预警阈值 {score_threshold:.2f} 的高风险域名。建议对命中模板对象继续观察。"
        )
        final_conclusion = "本次检测存在模板命中但未达到高风险阈值，建议结合后续新注册域名数据持续复检。"
    else:
        conclusion = (
            f"本次任务共检测域名 {total} 条，未发现模板化APT域名命中。"
            "建议保留检测结果用于后续回溯，并持续跟进模板库更新。"
        )
        final_conclusion = "本次模板化APT域名检测未发现命中对象。当前结论不代表域名绝对安全，建议持续复检。"

    return {
        "report_no": f"APTHunter-TemplatedAPT-{generated_at.strftime('%Y%m%d')}-{task_id}",
        "generated_at": generated_at.strftime("%Y-%m-%d %H:%M:%S"),
        "task_id": task_id,
        "model_name": model_name,
        "data_source_label": _source_label(data_source),
        "detection_scope": "、".join(date_range or []) if date_range else _source_label(data_source),
        "total": total,
        "matched_count": matched_count,
        "high_risk_count": high_risk_count,
        "normal_count": normal_count,
        "matched_rate_text": matched_rate_text,
        "high_risk_rate_text": high_risk_rate_text,
        "score_threshold_text": f"{score_threshold:.2f}",
        "template_count": template_count,
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "duplicate_count": duplicate_count,
        "matched_template_count": len(template_counter),
        "risk_levels": risk_levels,
        "top_domains": top_domains,
        "template_overview": template_overview,
        "reason_overview": reason_overview,
        "conclusion": conclusion,
        "final_conclusion": final_conclusion,
    }


def render_apt_template_nrd_report_markdown(
    payload: dict[str, Any],
    *,
    task_id: str,
    model_name: str,
    data_source: str,
    score_threshold: float,
    date_range: Optional[list[str]] = None,
    generated_at: Optional[datetime] = None,
) -> str:
    try:
        from jinja2 import Environment
    except ImportError as exc:
        raise RuntimeError("缺少 Jinja2 依赖，无法渲染模板化APT域名检测报告模板") from exc

    template_text = REPORT_TEMPLATE_PATH.read_text(encoding="utf-8")
    env = Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)
    env.filters["mdcell"] = _markdown_cell
    template = env.from_string(template_text)
    context = _build_report_context(
        payload,
        task_id=task_id,
        model_name=model_name,
        data_source=data_source,
        score_threshold=score_threshold,
        date_range=date_range,
        generated_at=generated_at,
    )
    return template.render(**context)


def generate_apt_template_nrd_pdf_report(
    payload: dict[str, Any],
    *,
    task_id: str,
    model_name: str,
    data_source: str,
    score_threshold: float,
    date_range: Optional[list[str]] = None,
    generated_at: Optional[datetime] = None,
) -> bytes:
    markdown_text = render_apt_template_nrd_report_markdown(
        payload,
        task_id=task_id,
        model_name=model_name,
        data_source=data_source,
        score_threshold=score_threshold,
        date_range=date_range,
        generated_at=generated_at,
    )
    return render_markdown_report_to_pdf(markdown_text, task_id=task_id)
