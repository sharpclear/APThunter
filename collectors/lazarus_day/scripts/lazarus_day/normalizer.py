from __future__ import annotations

import hashlib
import re
import unicodedata
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import (
    FORBIDDEN_EVENT_FIELDS,
    REQUIRED_EVENT_FIELDS,
    THREAT_TYPES,
    MatchResult,
    NormalizationResult,
    OriginalSource,
    ReportRecord,
    ValidationError,
)


TRACKING_QUERY_KEYS = {
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "ref_src",
    "source",
}
PRESENTATION_QUERY_KEYS = {"amp", "display", "output", "print", "share"}

HARD_NON_EVENT_TITLE_PATTERNS = (
    "naming system",
    "threat actor naming",
    "threat profile",
    "intelligence dossier",
    "podcast",
    "webinar",
    "conference agenda",
    "命名体系",
    "命名系统",
    "组织介绍",
)
REVIEW_ONLY_TITLE_PATTERNS = (
    "annual report",
    "quarterly report",
    "monthly report",
    "trend report",
    "threat trends",
    "年度报告",
    "季度报告",
    "月度报告",
    "趋势报告",
)
NON_EVENT_TAGS = {"trend", "slides", "youtube", "podcast"}
EVENT_INDICATORS = (
    "attack",
    "attacks",
    "campaign",
    "compromise",
    "compromised",
    "intrusion",
    "malware",
    "backdoor",
    "trojan",
    "ransomware",
    "phishing",
    "spearphishing",
    "credential",
    "exploit",
    "vulnerability",
    "c2",
    "command and control",
    "supply chain",
    "malicious",
    "breach",
    "攻击",
    "入侵",
    "恶意",
    "后门",
    "木马",
    "勒索",
    "钓鱼",
    "凭证",
    "漏洞",
    "供应链",
    "공격",
    "악성",
    "피싱",
)

SOURCE_A_MARKERS = (
    ".gov",
    "cisa.gov",
    "cert.",
    "ncsc.",
    "police.",
    "fbi.gov",
    "justice.gov",
)
SOURCE_B_MARKERS = (
    "ahnlab",
    "asec.",
    "mandiant",
    "google",
    "microsoft",
    "crowdstrike",
    "kaspersky",
    "securelist",
    "welivesecurity",
    "eset",
    "paloaltonetworks",
    "unit42",
    "trendmicro",
    "sentinelone",
    "recordedfuture",
    "s2w",
    "genians",
    "checkmarx",
    "socket.dev",
    "safedep",
    "elastic.co",
    "jumpsec",
    "proofpoint",
    "securitylab.github",
)
SOURCE_C_MARKERS = (
    "bleepingcomputer",
    "therecord",
    "securityweek",
    "thehackernews",
    "dailynk",
    "bloomberg",
    "wsj",
    "reuters",
)


def canonicalize_url(url: str) -> str:
    value = url.strip()
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValidationError(f"不是有效的 HTTP/HTTPS URL：{url!r}")
    scheme = parts.scheme.lower()
    hostname = parts.hostname.lower()
    try:
        port = parts.port
    except ValueError as exc:
        raise ValidationError(f"URL 端口无效：{url!r}") from exc
    if port and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        hostname = f"{hostname}:{port}"
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    if path != "/":
        path = path.rstrip("/")
    query_items = []
    for key, value_part in parse_qsl(parts.query, keep_blank_values=True):
        lowered = key.casefold()
        if (
            lowered.startswith("utm_")
            or lowered in TRACKING_QUERY_KEYS
            or lowered in PRESENTATION_QUERY_KEYS
        ):
            continue
        query_items.append((key, value_part))
    query_items.sort()
    query = urlencode(query_items, doseq=True)
    return urlunsplit((scheme, hostname, path, query, ""))


def normalize_title_for_key(title: str) -> str:
    normalized = unicodedata.normalize("NFKC", title).casefold()
    return "".join(character for character in normalized if character.isalnum())


def make_event_key(
    canonical_link: str,
    organization_id: int | None,
    event_date: str,
    title: str,
) -> str:
    material = (
        f"{canonical_link}\n"
        f"{'' if organization_id is None else organization_id}\n"
        f"{event_date}\n"
        f"{normalize_title_for_key(title)}"
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def infer_source_level(publisher: str, url: str) -> str:
    haystack = f"{publisher} {url}".casefold()
    if any(marker in haystack for marker in SOURCE_A_MARKERS):
        return "A"
    if any(marker in haystack for marker in SOURCE_B_MARKERS):
        return "B"
    if any(marker in haystack for marker in SOURCE_C_MARKERS):
        return "C"
    return "C"


def classify_report(report: ReportRecord) -> tuple[bool, str]:
    title = report.title.casefold()
    combined = " ".join(
        [report.title, report.summary, *report.tags]
    ).casefold()
    tags = {tag.casefold() for tag in report.tags}
    has_event = any(indicator in combined for indicator in EVENT_INDICATORS)
    if any(pattern in title for pattern in HARD_NON_EVENT_TITLE_PATTERNS):
        return False, "标题表明该条目是命名、档案或宣传内容"
    if any(pattern in title for pattern in REVIEW_ONLY_TITLE_PATTERNS):
        if has_event and report.related_actors:
            return True, "趋势或周期报告包含攻击线索，但无法自动拆分"
        return False, "趋势或周期报告无法可靠拆分出具体活动"
    if tags.intersection(NON_EVENT_TAGS) and not has_event:
        return False, "仅含 Trend/Slides/Youtube/Podcast 等非事件标签"
    if not has_event:
        return False, "未检测到可识别的具体攻击或威胁行为"
    return True, "检测到明确攻击行为关键词"


def infer_threat_type(report: ReportRecord) -> str:
    title = report.title.casefold()
    tags = " ".join(report.tags).casefold()
    summary = report.summary.casefold()
    combined = f"{title} {tags} {summary}"
    priorities = (
        (
            "供应链攻击",
            ("supplychain", "supply chain", "npm", "pypi", "供应链"),
        ),
        (
            "钓鱼攻击",
            ("phishing", "spearphishing", "spear-phishing", "钓鱼", "피싱"),
        ),
        (
            "勒索软件",
            ("ransomware", "勒索"),
        ),
        (
            "凭证窃取",
            (
                "credential theft",
                "credential steal",
                "password steal",
                "infostealer",
                "凭证",
            ),
        ),
        (
            "漏洞利用",
            ("vulnerability", "exploit", "zero-day", "0-day", "cve-", "漏洞"),
        ),
        (
            "C2通信",
            ("command and control", "c2", "回连"),
        ),
        (
            "恶意软件",
            ("malware", "backdoor", "trojan", "rat", "loader", "恶意", "后门", "木马"),
        ),
        (
            "APT攻击",
            ("attack", "campaign", "intrusion", "compromise", "攻击", "入侵", "공격"),
        ),
    )
    for threat_type, markers in priorities:
        if any(marker in combined for marker in markers):
            return threat_type
    return "其他"


def normalize_report(
    report: ReportRecord,
    match: MatchResult,
    original: OriginalSource | None,
    *,
    related_actors_split: bool = False,
) -> NormalizationResult:
    is_event, classification_reason = classify_report(report)
    if not is_event:
        return NormalizationResult(event=None, rejected_reason=classification_reason)

    organization = match.organization
    organization_id = organization.id if organization else None
    organization_name = (
        organization.name
        if organization
        else (report.related_actors[0] if report.related_actors else "未匹配组织")
    )
    threat_type = infer_threat_type(report)
    review_reasons: list[str] = []
    notes = [classification_reason]
    title_folded = report.title.casefold()
    if (
        any(pattern in title_folded for pattern in REVIEW_ONLY_TITLE_PATTERNS)
        or {tag.casefold() for tag in report.tags}.intersection(NON_EVENT_TAGS)
    ):
        review_reasons.append("趋势、Slides 或周期报告需人工拆分具体活动")

    if match.status == "unmatched":
        review_reasons.append("组织名称未匹配现有组织索引")
    elif match.status == "conflict":
        review_reasons.append(match.reason or "组织匹配存在冲突")
    else:
        notes.append(f"组织匹配方式：{match.method}")

    if report.date_precision in {"month", "year"}:
        review_reasons.append("来源日期只有月份或年份，未伪造具体日期")
        date_precision = report.date_precision
    else:
        date_precision = "publication_date"
        notes.append("未提取到明确攻击发生日，使用报告发布日期")

    source_accessible = (
        original is not None
        and original.error is None
        and original.http_status is not None
        and 200 <= original.http_status < 400
    )
    if not source_accessible:
        review_reasons.append("原始来源未获取或未验证，主链接回退到 lazarus.day")
    elif original and original.source_level not in {"A", "B"}:
        review_reasons.append(
            f"原始来源等级为 {original.source_level}，不足以单独自动接受"
        )

    chinese_context = _contains_chinese(report.summary) or _contains_chinese(
        report.title
    )
    if not chinese_context:
        review_reasons.append("非中文来源缺少可验证的中文客观概述")
    if len(report.related_actors) > 1 and not related_actors_split:
        review_reasons.append("报告涉及多个 Related Actors，无法自动拆分")
    for warning in report.parse_warnings:
        if warning not in notes:
            notes.append(warning)

    confidence = _confidence(
        report=report,
        match=match,
        source_accessible=source_accessible,
        source_level=(original.source_level if original else "D"),
        chinese_context=chinese_context,
    )
    if confidence < 0.75:
        review_reasons.append(f"置信度 {confidence:.2f} 低于 0.75")

    link = (
        canonicalize_url(original.final_url)
        if source_accessible and original
        else canonicalize_url(report.lazarus_day_url)
    )
    title = _chinese_title(report, organization_name, threat_type)
    description = _chinese_description(
        report, organization_name, threat_type
    )
    evidence = [_lazarus_evidence(report)]
    if source_accessible and original:
        evidence.append(_original_evidence(report, original))

    review_reasons = list(dict.fromkeys(review_reasons))
    notes.extend(review_reasons)
    review_status = "needs_review" if review_reasons else "accepted"
    event = {
        "schema_version": "1.0",
        "record_type": "event",
        "db_id": None,
        "event_date": report.published_date,
        "date_precision": date_precision,
        "title": title[:500],
        "description": description,
        "threat_type": threat_type,
        "organization_id": organization_id,
        "organization_name": organization_name,
        "releasing_product": report.publisher or None,
        "link": link,
        "confidence": confidence,
        "review_status": review_status,
        "evidence": evidence,
        "collection_notes": "；".join(dict.fromkeys(notes)) or None,
        "collected_at": report.fetched_at,
    }
    validate_event(event, allow_partial_date=review_status == "needs_review")
    return NormalizationResult(
        event=event,
        review_reasons=tuple(review_reasons),
        unmatched=organization_id is None,
    )


def validate_event(
    event: dict[str, object], *, allow_partial_date: bool = False
) -> None:
    keys = set(event)
    required = set(REQUIRED_EVENT_FIELDS)
    missing = required - keys
    extra_forbidden = keys.intersection(FORBIDDEN_EVENT_FIELDS)
    if missing:
        raise ValidationError(f"标准事件缺少字段：{sorted(missing)}")
    if extra_forbidden:
        raise ValidationError(f"标准事件包含禁止字段：{sorted(extra_forbidden)}")
    if event["schema_version"] != "1.0" or event["record_type"] != "event":
        raise ValidationError("schema_version 或 record_type 无效")
    if event["db_id"] is not None:
        raise ValidationError("新事件 db_id 必须为 null")
    date_value = str(event["event_date"])
    date_pattern = (
        r"^\d{4}(?:-\d{2}(?:-\d{2})?)?$"
        if allow_partial_date
        else r"^\d{4}-\d{2}-\d{2}$"
    )
    if not re.match(date_pattern, date_value):
        raise ValidationError(f"event_date 格式无效：{date_value}")
    if event["threat_type"] not in THREAT_TYPES:
        raise ValidationError(f"威胁类型不在受控词表：{event['threat_type']}")
    if event["review_status"] not in {"accepted", "needs_review", "rejected"}:
        raise ValidationError("review_status 无效")
    confidence = event["confidence"]
    if not isinstance(confidence, (float, int)) or not 0 <= confidence <= 1:
        raise ValidationError("confidence 必须在 0 到 1 之间")
    if not isinstance(event["evidence"], list) or not event["evidence"]:
        raise ValidationError("每条事件至少需要一项 evidence")
    if not str(event["title"]).strip() or len(str(event["title"])) > 500:
        raise ValidationError("title 为空或超过 500 字符")
    if not str(event["description"]).strip():
        raise ValidationError("description 为空")
    canonicalize_url(str(event["link"]))


def _confidence(
    *,
    report: ReportRecord,
    match: MatchResult,
    source_accessible: bool,
    source_level: str,
    chinese_context: bool,
) -> float:
    value = 0.20
    if match.status == "matched":
        value += 0.30 if (match.method or "").startswith("related_actor") else 0.20
    value += 0.15
    if report.date_precision == "day":
        value += 0.10
    if source_accessible:
        value += 0.10
    if source_level in {"A", "B"}:
        value += 0.10
    if chinese_context:
        value += 0.05
    return round(min(1.0, value), 2)


def _lazarus_evidence(report: ReportRecord) -> dict[str, object]:
    supports = [
        "event_date",
        "title",
        "description",
        "threat_type",
        "releasing_product",
    ]
    if report.related_actors:
        supports.append("organization_id")
    return {
        "url": canonicalize_url(report.lazarus_day_url),
        "title": report.title,
        "publisher": "lazarus.day",
        "published_date": (
            report.published_date if report.date_precision == "day" else None
        ),
        "accessed_at": report.fetched_at,
        "source_level": "D",
        "supports": supports,
    }


def _original_evidence(
    report: ReportRecord, original: OriginalSource
) -> dict[str, object]:
    supports = ["link"]
    if original.title:
        supports.append("title")
    if original.published_date:
        supports.append("event_date")
    if original.summary and any(
        indicator in original.summary.casefold()
        for indicator in EVENT_INDICATORS
    ):
        supports.extend(["description", "threat_type"])
    return {
        "url": canonicalize_url(original.final_url),
        "title": original.title or report.title,
        "publisher": report.publisher or urlsplit(original.final_url).hostname or "",
        "published_date": original.published_date or report.published_date,
        "accessed_at": original.fetched_at,
        "source_level": original.source_level,
        "supports": list(dict.fromkeys(supports)),
    }


def _chinese_title(
    report: ReportRecord, organization_name: str, threat_type: str
) -> str:
    if _contains_chinese(report.title):
        if organization_name.casefold() in report.title.casefold():
            return report.title
        return f"{organization_name}：{report.title}"
    return f"{organization_name}相关{threat_type}活动（{report.publisher or '公开来源'}报告）"


def _chinese_description(
    report: ReportRecord, organization_name: str, threat_type: str
) -> str:
    title = " ".join(report.title.split())
    publisher = report.publisher or "公开来源"
    return (
        f"{publisher}于{report.published_date}发布报告《{title}》。"
        f"lazarus.day 的公开页面将该报告与{organization_name}关联，"
        f"并显示其涉及{threat_type}相关活动。当前采集器未调用外部翻译或"
        "生成模型，未从来源中补写国家、目标、恶意软件或影响；"
        "具体技术细节和攻击发生日期应由人工依据原始报告复核。"
    )


def _contains_chinese(value: str) -> bool:
    return bool(re.search(r"[\u4e00-\u9fff]", value))
