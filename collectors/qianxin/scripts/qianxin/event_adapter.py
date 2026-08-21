from __future__ import annotations

import hashlib
import re
from datetime import date
from typing import Any, Mapping

from .core import normalize_report_publisher, normalize_title, normalize_url


SOURCE = "qianxin"
SCHEMA_VERSION = "apthunter.apt_events.v1"
APT_EVENT_COLUMNS = (
    "id",
    "event_key",
    "event_date",
    "date_precision",
    "title",
    "description",
    "link",
    "event_type",
    "threat_type",
    "releasing_product",
    "region",
    "latitude",
    "longitude",
    "organization_id",
    "severity",
    "confidence",
    "review_status",
    "evidence",
    "collection_notes",
    "created_at",
)
MAJOR_THREAT_TYPES = {"供应链攻击", "漏洞利用", "勒索软件", "APT攻击"}
SEVERITY_FOUR_TYPES = {"C2通信", "钓鱼攻击", "凭证窃取"}
DESCRIPTION_SENTENCE_ENDINGS = ("。", "！", "？", ".", "!", "?", "…")
DESCRIPTION_SEPARATOR_RE = re.compile(r"[；;]+")


def _summary_body(summary: Mapping[str, Any]) -> Mapping[str, Any]:
    value = summary.get("summary")
    return value if isinstance(value, Mapping) else {}


def _iter_mappings(value: Any):
    if isinstance(value, list):
        for item in value:
            if isinstance(item, Mapping):
                yield item


def normalize_event_description(value: Any) -> str:
    """Return API event text as complete, semicolon-free sentences."""

    text = str(value or "").strip()
    if not text:
        return ""
    sentences: list[str] = []
    for part in DESCRIPTION_SEPARATOR_RE.split(text):
        sentence = part.strip()
        if not sentence:
            continue
        if not sentence.endswith(DESCRIPTION_SENTENCE_ENDINGS):
            sentence += "。"
        sentences.append(sentence)
    return "".join(sentences)


def _text_corpus(summary: Mapping[str, Any]) -> str:
    body = _summary_body(summary)
    values: list[str] = [
        str(body.get("report_title") or ""),
        str(body.get("executive_summary_zh") or ""),
    ]
    for field, keys in (
        ("key_findings", ("finding", "evidence_quote")),
        ("attack_chain", ("stage", "activity", "evidence_quote")),
        ("malware_tools", ("name", "role", "evidence_quote")),
        ("vulnerabilities", ("cve", "description", "evidence_quote")),
    ):
        for item in _iter_mappings(body.get(field)):
            values.extend(str(item.get(key) or "") for key in keys)
    return "\n".join(values).casefold()


def infer_threat_type(summary: Mapping[str, Any]) -> tuple[str, bool]:
    """Return the controlled threat type and whether an explicit signal was found."""

    body = _summary_body(summary)
    corpus = _text_corpus(summary)
    rules = (
        ("勒索软件", (r"勒索", r"ransomware")),
        (
            "供应链攻击",
            (
                r"供应链",
                r"supply[ -]?chain",
                r"恶意(?:npm|pypi|nuget|软件)包",
                r"malicious (?:npm|pypi|nuget|software) package",
            ),
        ),
        ("钓鱼攻击", (r"鱼叉式?钓鱼", r"钓鱼", r"spearphish", r"phishing")),
        (
            "凭证窃取",
            (r"凭证(?:窃取|盗取)", r"credential (?:theft|steal)", r"steal credentials"),
        ),
        (
            "漏洞利用",
            (r"漏洞利用", r"exploit(?:ation|ed|ing)?", r"zero[ -]?day", r"0day"),
        ),
        (
            "C2通信",
            (
                r"(?<![a-z0-9])c2(?![a-z0-9])",
                r"(?<![a-z0-9])c&c(?![a-z0-9])",
                r"command[ -]?and[ -]?control",
                r"命令与控制",
            ),
        ),
        (
            "恶意软件",
            (r"恶意软件", r"malware", r"后门", r"木马", r"backdoor", r"trojan"),
        ),
    )
    for threat_type, patterns in rules:
        if any(re.search(pattern, corpus, flags=re.IGNORECASE) for pattern in patterns):
            return threat_type, True
    if list(_iter_mappings(body.get("vulnerabilities"))):
        return "漏洞利用", True
    if list(_iter_mappings(body.get("malware_tools"))):
        return "恶意软件", True
    return "APT攻击", False


def _description(summary: Mapping[str, Any], fallback: str) -> str:
    body = _summary_body(summary)
    findings = [
        str(item.get("finding") or "").strip()
        for item in _iter_mappings(body.get("key_findings"))
        if str(item.get("finding") or "").strip()
    ]
    if findings:
        return normalize_event_description("；".join(dict.fromkeys(findings)))
    executive = str(body.get("executive_summary_zh") or "").strip()
    return normalize_event_description(executive or fallback)


def _evidence(
    summary: Mapping[str, Any],
    *,
    url: str,
    title: str,
    publisher: str,
    report_date: str | None,
    accessed_at: str | None,
    sha256: str,
) -> list[dict[str, Any]]:
    body = _summary_body(summary)
    result: list[dict[str, Any]] = []
    for item in _iter_mappings(body.get("key_findings")):
        quote = str(item.get("evidence_quote") or "").strip()
        pages = item.get("evidence_pages")
        if not quote or not isinstance(pages, list) or not pages:
            continue
        result.append(
            {
                "url": url,
                "title": title,
                "publisher": publisher,
                "published_date": report_date,
                "accessed_at": accessed_at,
                "source_level": "B",
                "supports": [
                    "event_date",
                    "title",
                    "description",
                    "threat_type",
                    "organization_id",
                ],
                "evidence_quote": quote,
                "evidence_pages": pages,
                "evidence_match": item.get("evidence_match"),
                "document_sha256": sha256,
            }
        )
    return result


def _event_key(*, link: str, organization_id: str, event_date: str, title: str) -> str:
    material = "\n".join(
        (normalize_url(link), organization_id, event_date, normalize_title(title))
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_apt_event_product(
    report: Mapping[str, Any],
    summary: Mapping[str, Any],
    quality: Mapping[str, Any],
    metadata: Mapping[str, Any] | None = None,
    *,
    public_base_url: str = "",
    allow_auto_accept: bool = False,
) -> dict[str, Any]:
    metadata = metadata or {}
    sha256 = str(report.get("sha256") or "").lower()
    report_date = str(report.get("report_date") or "").strip()
    organization_id = str(report.get("organization_id") or "").strip()
    organization_name = str(report.get("organization_name") or "").strip()
    title = str(report.get("report_title") or "").strip()
    source_url = normalize_url(
        str(metadata.get("preview_url") or metadata.get("pdf_url") or "")
    )
    if not source_url and public_base_url and sha256:
        source_url = public_base_url.rstrip("/") + f"/api/v1/reports/{sha256}/pdf"
    publisher = normalize_report_publisher(metadata.get("report_publisher"))
    publisher_fallback = not publisher
    if not publisher:
        publisher = "奇安信威胁情报中心"

    description = _description(summary, title)
    threat_type, explicit_threat_signal = infer_threat_type(summary)
    evidence = _evidence(
        summary,
        url=source_url,
        title=title,
        publisher=publisher,
        report_date=report_date or None,
        accessed_at=str(report.get("collected_at") or "") or None,
        sha256=sha256,
    )
    source_quality = str(quality.get("status") or report.get("quality_status") or "")
    review_reasons: list[str] = []
    if source_quality != "ready" or bool(report.get("review_required")):
        review_reasons.append(f"来源质量状态为 {source_quality or 'unknown'}")
    try:
        parsed_date = date.fromisoformat(report_date)
        if parsed_date > date.today():
            review_reasons.append("报告日期晚于当前日期")
    except ValueError:
        review_reasons.append("报告日期不是 YYYY-MM-DD")
    if not organization_id or not organization_name:
        review_reasons.append("组织 ID 或组织名称缺失")
    if not title:
        review_reasons.append("标题缺失")
    elif len(title) > 500:
        review_reasons.append("标题超过 500 字符")
        title = title[:500]
    if not description:
        review_reasons.append("描述缺失")
    if not source_url.startswith(("http://", "https://")):
        review_reasons.append("缺少可由虚拟机访问的 HTTP(S) 报告链接")
    if not evidence:
        review_reasons.append("没有带 PDF 页码的关键发现证据")
    if not explicit_threat_signal:
        review_reasons.append("威胁类型仅能归为通用 APT攻击")
    timeline = list(_iter_mappings(_summary_body(summary).get("timeline")))
    if len(timeline) > 1:
        review_reasons.append("报告包含多个时间线条目，可能需要拆分为多条事件")
    if not review_reasons and not allow_auto_accept:
        review_reasons.append("奇安信事件自动接受未启用")

    review_reasons = list(dict.fromkeys(review_reasons))
    review_status = "accepted" if not review_reasons else "needs_review"
    confidence = 0.88 if review_status == "accepted" else 0.72
    event_type = "major" if threat_type in MAJOR_THREAT_TYPES else "normal"
    severity = (
        5 if event_type == "major" else (4 if threat_type in SEVERITY_FOUR_TYPES else 3)
    )
    notes: list[str] = []
    if publisher_fallback:
        notes.append("历史元数据未保存原始发布厂商，使用奇安信聚合平台作为发布来源")
    notes.extend(review_reasons)
    variant = {
        "id": None,
        "event_key": _event_key(
            link=source_url,
            organization_id=organization_id,
            event_date=report_date,
            title=title,
        ),
        "event_date": report_date or None,
        "date_precision": "publication_date" if report_date else None,
        "title": title or None,
        "description": description or None,
        "link": source_url or None,
        "event_type": event_type,
        "threat_type": threat_type,
        "releasing_product": publisher,
        "region": None,
        "latitude": None,
        "longitude": None,
        "organization_id": int(organization_id) if organization_id.isdigit() else None,
        "organization_name": organization_name or None,
        "severity": severity,
        "confidence": confidence,
        "review_status": review_status,
        "review_reasons": review_reasons,
        "evidence": evidence,
        "collection_notes": "；".join(notes) or None,
        "created_at": None,
    }
    apt_event = {column: variant.get(column) for column in APT_EVENT_COLUMNS}
    value = {
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE,
        "source_event_id": sha256,
        "version": int(report.get("version") or 1),
        "title": variant["title"],
        "description": variant["description"],
        "event_time": variant["event_date"],
        "report_time": variant["event_date"],
        "collected_at": report.get("collected_at"),
        "updated_at": report.get("updated_at"),
        "quality_status": (
            "accepted" if review_status == "accepted" else "needs_review"
        ),
        "source_quality_status": source_quality,
        "review_required": review_status != "accepted",
        "source_url": source_url or None,
        "organization": {
            "id": variant["organization_id"],
            "name": variant["organization_name"],
        },
        "threat_type": threat_type,
        "releasing_product": publisher,
        "primary_link": source_url or None,
        "apt_event": apt_event,
        "structured_event": {"variants": [variant]},
        "evidence": evidence,
        "provenance": {
            "report_sha256": sha256,
            "model": report.get("model_name"),
            "prompt_version": report.get("prompt_version"),
            "validator_version": report.get("validator_version"),
            "publisher_fallback": publisher_fallback,
        },
        "links": {
            "report": f"/api/v1/reports/{sha256}",
            "summary": f"/api/v1/reports/{sha256}/summary",
            "quality": f"/api/v1/reports/{sha256}/quality",
            "pdf": f"/api/v1/reports/{sha256}/pdf",
            "self": f"/api/v1/events/{sha256}",
        },
    }
    return value
