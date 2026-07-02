from __future__ import annotations

import io
import json
import math
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional
from xml.sax.saxutils import escape

import pandas as pd


REPORT_TEMPLATE_PATH = (
    Path(__file__).resolve().parents[2]
    / "报告模板"
    / "历史APT域名相似性检测报告模板.md"
)

PAGE_WIDTH = 595.28
PAGE_HEIGHT = 841.89
PAGE_MARGIN_LEFT = 42
PAGE_MARGIN_RIGHT = 42
PAGE_MARGIN_TOP = 52
PAGE_MARGIN_BOTTOM = 44


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


def _row_domain(row: dict[str, Any]) -> str:
    for key in ("域名", "规范化域名", "domain", "domain_name"):
        domain = _cell_text(row.get(key)).lower()
        if domain:
            return domain
    return ""


def _row_score(row: dict[str, Any]) -> float:
    try:
        score = float(row.get("综合相似度") or row.get("score") or 0)
        return score if math.isfinite(score) else 0.0
    except (TypeError, ValueError):
        return 0.0


def _dedupe_history_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
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
        if _row_score(row) > _row_score(current):
            best_by_domain[domain] = row
    return [best_by_domain[domain] for domain in ordered_domains]


def build_history_similarity_result_payload(
    excel_content: bytes,
    *,
    task_id: str,
    result_file_key: Optional[str] = None,
    result_filename: Optional[str] = None,
    history_meta: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build the JSON payload used by the frontend after the downloadable PDF replaces XLSX."""
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

    history_rows: list[dict[str, Any]] = []
    try:
        excel_file.seek(0)
        history_df = pd.read_excel(excel_file, sheet_name="历史相似域名列表")
        history_rows = history_df.to_dict("records")
    except Exception:
        pass

    results_list = results_df.to_dict("records")
    history_list = _dedupe_history_rows(history_rows)
    if not history_list:
        history_list = _dedupe_history_rows(
            row
            for row in results_list
            if row.get("预测标签") == 1 or row.get("预测结果") == "历史高度相似"
        )

    payload = {
        "ok": True,
        "task_id": task_id,
        "task_type": "history_similarity",
        "statistics": statistics_dict,
        "results": results_list,
        "history_similarity_domains": history_list,
        "result_file_key": result_file_key,
        "result_filename": result_filename or f"{task_id}_report.pdf",
        "total_count": len(results_list),
        "history_similarity_count": len(history_list),
        "history_similarity_detection": history_meta or {},
    }
    return _json_safe_value(payload)


def build_history_similarity_result_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")


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


def _risk_level(score: float) -> str:
    if score >= 0.90:
        return "严重"
    if score >= 0.80:
        return "高危"
    if score >= 0.65:
        return "中危"
    return "待确认"


def _source_label(value: str) -> str:
    return {
        "upload": "上传文件",
        "newDomain": "新注册域名",
        "manualInput": "手动输入域名",
    }.get(value or "", value or "未知")


def _markdown_cell(value: Any) -> str:
    text = _cell_text(value)
    text = text.replace("|", "/")
    text = re.sub(r"\s+", " ", text)
    return text.strip() or "-"


def _int_stat(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _build_report_context(
    payload: dict[str, Any],
    *,
    task_id: str,
    model_name: str,
    data_source: str,
    min_score: float,
    top_k: int,
    date_range: Optional[list[str]] = None,
    generated_at: Optional[datetime] = None,
) -> dict[str, Any]:
    generated_at = generated_at or datetime.utcnow()
    statistics = payload.get("statistics") or {}
    history_rows = payload.get("history_similarity_domains") or []
    detection_meta = payload.get("history_similarity_detection") or {}
    input_stats = detection_meta.get("input_stats") or {}

    total = _int_stat(statistics.get("总域名数") or payload.get("total_count"), 0)
    hit_count = _int_stat(statistics.get("历史相似域名数") or payload.get("history_similarity_count"), 0)
    normal_count = _int_stat(statistics.get("正常域名数"), max(0, total - hit_count))
    rate_text = str(statistics.get("历史相似域名占比") or _percent(hit_count, total))
    avg_score = sum(_score(row.get("综合相似度")) for row in history_rows) / hit_count if hit_count else 0.0
    max_score = max((_score(row.get("综合相似度")) for row in history_rows), default=0.0)

    candidate_pairs = _int_stat(statistics.get("历史匹配对数") or detection_meta.get("candidate_pairs"), 0)
    history_domains = _int_stat(statistics.get("历史样本数") or detection_meta.get("history_domains"), 0)
    index_seeds = _int_stat(statistics.get("索引样本数") or detection_meta.get("index_seeds"), 0)
    valid_count = _int_stat(input_stats.get("valid_count"), total)
    invalid_count = _int_stat(statistics.get("无效输入数") or input_stats.get("invalid_count"), 0)
    duplicate_count = _int_stat(statistics.get("重复输入数") or input_stats.get("duplicate_count"), 0)

    level_counter = Counter(_risk_level(_score(row.get("综合相似度"))) for row in history_rows)
    reason_counter = Counter(_cell_text(row.get("命中原因")) or "相似命名" for row in history_rows)
    matched_counter = Counter(
        _cell_text(row.get("匹配历史恶意域名"))
        for row in history_rows
        if _cell_text(row.get("匹配历史恶意域名"))
    )

    top_rows = sorted(history_rows, key=lambda row: _score(row.get("综合相似度")), reverse=True)[:30]
    top_domains = [
        {
            "domain": _cell_text(row.get("域名")),
            "score": _format_score(row.get("综合相似度")),
            "matched_domain": _cell_text(row.get("匹配历史恶意域名")) or "未知",
            "reason": _cell_text(row.get("命中原因")) or "相似命名",
        }
        for row in top_rows
    ]
    if not top_domains:
        top_domains = [
            {
                "domain": "未命中",
                "score": "0.0000",
                "matched_domain": "-",
                "reason": "本次任务未发现历史APT相似域名",
            }
        ]

    risk_levels = []
    for level in ("严重", "高危", "中危", "待确认"):
        count = level_counter.get(level, 0)
        risk_levels.append(
            {
                "level": level,
                "count": count,
                "percent": _percent(count, hit_count),
                "action": {
                    "严重": "建议立即阻断并回溯访问",
                    "高危": "建议阻断或优先复核",
                    "中危": "建议加入持续观察",
                    "待确认": "建议人工复核",
                }[level],
            }
        )

    feature_overview = [
        {"reason": reason, "count": count, "percent": _percent(count, hit_count)}
        for reason, count in reason_counter.most_common(8)
    ]
    if not feature_overview:
        feature_overview = [{"reason": "未命中", "count": 0, "percent": "0.00%"}]

    matched_history = [
        {"domain": domain, "count": count}
        for domain, count in matched_counter.most_common(8)
    ]

    if hit_count:
        conclusion = (
            f"本次任务共检测域名 {total} 条，命中历史APT相似域名 {hit_count} 条，"
            f"命中占比 {rate_text}。最高综合相似度为 {max_score:.4f}，平均综合相似度为 {avg_score:.4f}。"
            "这些域名与历史样本在字符片段、前后结构、token 重合或相同后缀方面存在相似特征，"
            "建议结合解析记录、证书和外部情报进行复核。"
        )
        final_conclusion = (
            f"本次历史APT域名相似性检测发现 {hit_count} 条相似域名，占全部检测对象 {rate_text}。"
            "结果说明存在与历史APT或恶意基础设施相似的命名模式，应结合基础设施证据和业务访问日志完成最终研判。"
        )
    else:
        conclusion = (
            f"本次任务共检测域名 {total} 条，未发现达到最低相似度 {min_score:.2f} 的历史APT相似域名。"
            "建议保留结果用于后续回溯，并对新注册或业务敏感域名持续观察。"
        )
        final_conclusion = (
            "本次历史APT域名相似性检测未发现达到阈值的相似域名。"
            "当前结论不代表域名绝对安全，建议在后续任务中持续复检。"
        )

    return {
        "report_no": f"APTHunter-HistoryAPT-{generated_at.strftime('%Y%m%d')}-{task_id}",
        "generated_at": generated_at.strftime("%Y-%m-%d %H:%M:%S"),
        "task_id": task_id,
        "model_name": model_name,
        "data_source_label": _source_label(data_source),
        "detection_scope": "、".join(date_range or []) if date_range else _source_label(data_source),
        "total": total,
        "hit_count": hit_count,
        "normal_count": normal_count,
        "rate_text": rate_text,
        "min_score_text": f"{min_score:.2f}",
        "top_k": top_k,
        "history_domains": history_domains,
        "index_seeds": index_seeds,
        "candidate_pairs": candidate_pairs,
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "duplicate_count": duplicate_count,
        "conclusion": conclusion,
        "final_conclusion": final_conclusion,
        "risk_levels": risk_levels,
        "top_domains": top_domains,
        "feature_overview": feature_overview,
        "matched_history": matched_history,
    }


def render_history_similarity_report_markdown(
    payload: dict[str, Any],
    *,
    task_id: str,
    model_name: str,
    data_source: str,
    min_score: float,
    top_k: int,
    date_range: Optional[list[str]] = None,
    generated_at: Optional[datetime] = None,
) -> str:
    """Render the Markdown report from the repository template."""
    try:
        from jinja2 import Environment
    except ImportError as exc:
        raise RuntimeError("缺少 Jinja2 依赖，无法渲染历史APT域名相似性检测报告模板") from exc

    template_text = REPORT_TEMPLATE_PATH.read_text(encoding="utf-8")
    env = Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)
    env.filters["mdcell"] = _markdown_cell
    template = env.from_string(template_text)
    context = _build_report_context(
        payload,
        task_id=task_id,
        model_name=model_name,
        data_source=data_source,
        min_score=min_score,
        top_k=top_k,
        date_range=date_range,
        generated_at=generated_at,
    )
    return template.render(**context)


def generate_history_similarity_pdf_report(
    payload: dict[str, Any],
    *,
    task_id: str,
    model_name: str,
    data_source: str,
    min_score: float,
    top_k: int,
    date_range: Optional[list[str]] = None,
    generated_at: Optional[datetime] = None,
) -> bytes:
    """Generate a polished PDF report with ReportLab Platypus layout."""
    markdown_text = render_history_similarity_report_markdown(
        payload,
        task_id=task_id,
        model_name=model_name,
        data_source=data_source,
        min_score=min_score,
        top_k=top_k,
        date_range=date_range,
        generated_at=generated_at,
    )
    return render_markdown_report_to_pdf(markdown_text, task_id=task_id)


def render_markdown_report_to_pdf(markdown_text: str, *, task_id: str) -> bytes:
    """Render a repository Markdown report into a paginated PDF."""
    return _markdown_to_pdf(markdown_text, task_id=task_id)


def _load_reportlab():
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont
        from reportlab.platypus import (
            LongTable,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            TableStyle,
        )
    except ImportError as exc:
        raise RuntimeError("缺少 ReportLab 依赖，无法生成历史APT域名相似性检测 PDF 报告") from exc

    return {
        "A4": A4,
        "LongTable": LongTable,
        "PageBreak": PageBreak,
        "Paragraph": Paragraph,
        "ParagraphStyle": ParagraphStyle,
        "SimpleDocTemplate": SimpleDocTemplate,
        "Spacer": Spacer,
        "TableStyle": TableStyle,
        "TA_CENTER": TA_CENTER,
        "TA_LEFT": TA_LEFT,
        "UnicodeCIDFont": UnicodeCIDFont,
        "colors": colors,
        "getSampleStyleSheet": getSampleStyleSheet,
        "pdfmetrics": pdfmetrics,
    }


def _register_fonts(rl: dict[str, Any]) -> tuple[str, str]:
    pdfmetrics = rl["pdfmetrics"]
    font_name = "STSong-Light"
    try:
        pdfmetrics.getFont(font_name)
    except KeyError:
        pdfmetrics.registerFont(rl["UnicodeCIDFont"](font_name))
    return font_name, font_name


def _build_styles(rl: dict[str, Any], font_regular: str, font_bold: str) -> dict[str, Any]:
    colors = rl["colors"]
    ParagraphStyle = rl["ParagraphStyle"]
    TA_CENTER = rl["TA_CENTER"]
    TA_LEFT = rl["TA_LEFT"]

    styles = rl["getSampleStyleSheet"]()
    return {
        "title": ParagraphStyle(
            "HistoryReportTitle",
            parent=styles["Title"],
            fontName=font_bold,
            fontSize=20,
            leading=28,
            textColor=colors.HexColor("#102A43"),
            alignment=TA_CENTER,
            wordWrap="CJK",
            spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "HistoryReportHeading2",
            parent=styles["Heading2"],
            fontName=font_bold,
            fontSize=13.5,
            leading=19,
            textColor=colors.HexColor("#153E75"),
            wordWrap="CJK",
            spaceBefore=12,
            spaceAfter=8,
        ),
        "body": ParagraphStyle(
            "HistoryReportBody",
            parent=styles["BodyText"],
            fontName=font_regular,
            fontSize=10.2,
            leading=16,
            textColor=colors.HexColor("#1F2933"),
            alignment=TA_LEFT,
            wordWrap="CJK",
            spaceAfter=7,
        ),
        "meta": ParagraphStyle(
            "HistoryReportMeta",
            parent=styles["BodyText"],
            fontName=font_regular,
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#52606D"),
            alignment=TA_CENTER,
            wordWrap="CJK",
            spaceAfter=5,
        ),
        "bullet": ParagraphStyle(
            "HistoryReportBullet",
            parent=styles["BodyText"],
            fontName=font_regular,
            fontSize=10,
            leading=15,
            leftIndent=15,
            firstLineIndent=-10,
            textColor=colors.HexColor("#1F2933"),
            wordWrap="CJK",
            spaceAfter=5,
        ),
        "cell": ParagraphStyle(
            "HistoryReportCell",
            parent=styles["BodyText"],
            fontName=font_regular,
            fontSize=8.7,
            leading=12.5,
            textColor=colors.HexColor("#1F2933"),
            wordWrap="CJK",
        ),
        "cell_header": ParagraphStyle(
            "HistoryReportCellHeader",
            parent=styles["BodyText"],
            fontName=font_bold,
            fontSize=8.8,
            leading=12,
            textColor=colors.white,
            alignment=TA_CENTER,
            wordWrap="CJK",
        ),
        "note": ParagraphStyle(
            "HistoryReportNote",
            parent=styles["BodyText"],
            fontName=font_regular,
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#334E68"),
            wordWrap="CJK",
            leftIndent=8,
            rightIndent=8,
            spaceAfter=8,
        ),
    }


def _markdown_to_pdf(markdown_text: str, *, task_id: str) -> bytes:
    rl = _load_reportlab()
    font_regular, font_bold = _register_fonts(rl)
    styles = _build_styles(rl, font_regular, font_bold)
    story = _markdown_to_flowables(markdown_text, rl, styles)
    buffer = io.BytesIO()
    doc = rl["SimpleDocTemplate"](
        buffer,
        pagesize=rl["A4"],
        leftMargin=PAGE_MARGIN_LEFT,
        rightMargin=PAGE_MARGIN_RIGHT,
        topMargin=PAGE_MARGIN_TOP,
        bottomMargin=PAGE_MARGIN_BOTTOM,
        title=f"APTHunter 历史APT域名相似性检测报告 {task_id}",
        author="APTHunter",
    )

    def draw_page(canvas, document):
        canvas.saveState()
        canvas.setFont(font_regular, 8)
        canvas.setFillColor(rl["colors"].HexColor("#829AB1"))
        canvas.drawString(PAGE_MARGIN_LEFT, 24, "APTHunter 历史APT域名相似性检测报告")
        canvas.drawRightString(PAGE_WIDTH - PAGE_MARGIN_RIGHT, 24, f"第 {document.page} 页")
        canvas.setStrokeColor(rl["colors"].HexColor("#D9E2EC"))
        canvas.line(PAGE_MARGIN_LEFT, 36, PAGE_WIDTH - PAGE_MARGIN_RIGHT, 36)
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    return buffer.getvalue()


def _markdown_to_flowables(markdown_text: str, rl: dict[str, Any], styles: dict[str, Any]) -> list[Any]:
    lines = markdown_text.splitlines()
    flowables: list[Any] = []
    paragraph_lines: list[str] = []
    index = 0

    def flush_paragraph() -> None:
        if not paragraph_lines:
            return
        text = " ".join(line.strip() for line in paragraph_lines if line.strip())
        if text:
            flowables.append(rl["Paragraph"](escape(text), styles["body"]))
        paragraph_lines.clear()

    while index < len(lines):
        raw_line = lines[index]
        line = raw_line.strip()

        if not line:
            flush_paragraph()
            index += 1
            continue

        if line == "<!-- pagebreak -->":
            flush_paragraph()
            flowables.append(rl["PageBreak"]())
            index += 1
            continue

        if line.startswith("# "):
            flush_paragraph()
            flowables.append(rl["Paragraph"](escape(line[2:].strip()), styles["title"]))
            index += 1
            continue

        if line.startswith("## "):
            flush_paragraph()
            flowables.append(rl["Paragraph"](escape(line[3:].strip()), styles["h2"]))
            index += 1
            continue

        if line.startswith(("报告编号：", "生成时间：")):
            flush_paragraph()
            flowables.append(rl["Paragraph"](escape(line), styles["meta"]))
            index += 1
            continue

        if line.startswith(">"):
            flush_paragraph()
            flowables.append(rl["Paragraph"](escape(line.lstrip(">").strip()), styles["note"]))
            index += 1
            continue

        if _is_table_start(lines, index):
            flush_paragraph()
            table_lines: list[str] = [lines[index], lines[index + 1]]
            index += 2
            while index < len(lines) and lines[index].strip().startswith("|"):
                table_lines.append(lines[index])
                index += 1
            flowables.append(_build_table(table_lines, rl, styles))
            flowables.append(rl["Spacer"](1, 8))
            continue

        if line.startswith("- "):
            flush_paragraph()
            flowables.append(rl["Paragraph"](escape(line[2:].strip()), styles["bullet"], bulletText="•"))
            index += 1
            continue

        paragraph_lines.append(raw_line)
        index += 1

    flush_paragraph()
    return flowables


def _is_table_start(lines: list[str], index: int) -> bool:
    if index + 1 >= len(lines):
        return False
    if not lines[index].strip().startswith("|"):
        return False
    separator = lines[index + 1].strip()
    return bool(re.match(r"^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$", separator))


def _split_table_row(line: str) -> list[str]:
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|"):
        text = text[:-1]
    return [cell.strip() for cell in text.split("|")]


def _build_table(table_lines: list[str], rl: dict[str, Any], styles: dict[str, Any]) -> Any:
    colors = rl["colors"]
    LongTable = rl["LongTable"]
    Paragraph = rl["Paragraph"]
    TableStyle = rl["TableStyle"]

    headers = _split_table_row(table_lines[0])
    body_rows = [_split_table_row(line) for line in table_lines[2:] if line.strip().startswith("|")]
    column_count = max(len(headers), *(len(row) for row in body_rows)) if body_rows else len(headers)
    headers = _pad_row(headers, column_count)
    body_rows = [_pad_row(row, column_count) for row in body_rows]

    data = [
        [Paragraph(escape(cell), styles["cell_header"]) for cell in headers],
        *[
            [Paragraph(escape(cell), styles["cell"]) for cell in row]
            for row in body_rows
        ],
    ]
    table = LongTable(
        data,
        colWidths=_column_widths(headers, column_count),
        repeatRows=1,
        splitByRow=1,
        hAlign="LEFT",
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1D4E89")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FBFF")]),
                ("GRID", (0, 0), (-1, -1), 0.45, colors.HexColor("#D9E2EC")),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#BCCCDC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _pad_row(row: list[str], length: int) -> list[str]:
    return [*row, *([""] * max(0, length - len(row)))]


def _column_widths(headers: list[str], column_count: int) -> list[float]:
    available_width = PAGE_WIDTH - PAGE_MARGIN_LEFT - PAGE_MARGIN_RIGHT
    header_text = "|".join(headers)
    if column_count == 2:
        return [available_width * 0.68, available_width * 0.32]
    if column_count == 3:
        return [available_width * 0.54, available_width * 0.22, available_width * 0.24]
    if column_count == 4 and "匹配历史APT域名" in header_text:
        return [available_width * 0.30, available_width * 0.15, available_width * 0.27, available_width * 0.28]
    if column_count == 4 and "处置建议" in header_text:
        return [available_width * 0.18, available_width * 0.16, available_width * 0.16, available_width * 0.50]
    if column_count == 4:
        return [available_width * 0.18, available_width * 0.32, available_width * 0.18, available_width * 0.32]
    return [available_width / max(1, column_count)] * column_count
