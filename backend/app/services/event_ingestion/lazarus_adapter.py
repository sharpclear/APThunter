from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import date
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SOURCE = "lazarus.day"
THREAT_TYPES = {
    "钓鱼攻击",
    "C2通信",
    "漏洞利用",
    "恶意软件",
    "凭证窃取",
    "供应链攻击",
    "勒索软件",
    "APT攻击",
    "其他",
}
MAJOR_THREAT_TYPES = {"供应链攻击", "漏洞利用", "勒索软件", "APT攻击"}
SEVERITY_FOUR_TYPES = {"C2通信", "钓鱼攻击"}
AUTO_DATE_PRECISIONS = {"day", "publication_date"}
TRACKING_QUERY_KEYS = {
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "ref",
    "source",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class IngestionCandidate:
    source: str
    source_record_id: str
    variant_key: str
    source_version: int
    quality_status: str
    review_required: bool
    variant: dict[str, Any]
    payload: dict[str, Any]

    @property
    def source_identity_hash(self) -> str:
        material = "\n".join((self.source, self.source_record_id, self.variant_key))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    @property
    def payload_json(self) -> str:
        return json.dumps(
            self.payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    @property
    def payload_sha256(self) -> str:
        return hashlib.sha256(self.payload_json.encode("utf-8")).hexdigest()


def canonicalize_url(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return text
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return text
    query = [
        (key, item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        if not key.lower().startswith("utm_") and key.lower() not in TRACKING_QUERY_KEYS
    ]
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            path,
            urlencode(query, doseq=True),
            "",
        )
    ).rstrip("/")


def normalize_title(value: Any) -> str:
    normalized = unicodedata.normalize("NFKC", str(value or ""))
    return " ".join(normalized.casefold().split())


def _fallback_variant_key(variant: Mapping[str, Any]) -> str:
    material = "\n".join(
        str(variant.get(key) or "").strip()
        for key in ("link", "organization_id", "event_date", "title")
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_event_candidates(
    event: Mapping[str, Any],
    *,
    source: str,
) -> list[IngestionCandidate]:
    source = str(source or "").strip()
    if not source or len(source) > 64:
        raise ValueError("事件来源标识无效")
    event_source = str(event.get("source") or source).strip()
    if event_source != source:
        raise ValueError(f"事件来源不匹配: expected={source}, actual={event_source}")
    source_record_id = str(event.get("source_event_id") or "").strip()
    if not source_record_id:
        raise ValueError(f"{source} 事件缺少 source_event_id")
    try:
        source_version = max(1, int(event.get("version") or 1))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{source} 事件 version 无效") from exc
    quality_status = str(event.get("quality_status") or "unknown").strip()
    review_required = bool(event.get("review_required"))
    structured = event.get("structured_event")
    variants = structured.get("variants") if isinstance(structured, Mapping) else None
    if not isinstance(variants, list) or not variants:
        variants = [{}]

    source_metadata = {
        "source": event_source,
        "source_event_id": source_record_id,
        "version": source_version,
        "title": event.get("title"),
        "description": event.get("description"),
        "event_time": event.get("event_time"),
        "report_time": event.get("report_time"),
        "collected_at": event.get("collected_at"),
        "updated_at": event.get("updated_at"),
        "quality_status": quality_status,
        "review_required": review_required,
        "source_url": event.get("source_url"),
        "original_source_url": event.get("original_source_url"),
        "provenance": event.get("provenance") or {},
        "links": event.get("links") or {},
    }
    candidates: list[IngestionCandidate] = []
    for index, value in enumerate(variants):
        variant = dict(value) if isinstance(value, Mapping) else {}
        variant_key = str(variant.get("event_key") or "").strip().lower()
        if not SHA256_RE.fullmatch(variant_key):
            variant_key = _fallback_variant_key(variant or source_metadata)
        if not variant:
            variant_key = f"source-{variant_key}"
        candidates.append(
            IngestionCandidate(
                source=source,
                source_record_id=source_record_id,
                variant_key=variant_key,
                source_version=source_version,
                quality_status=quality_status,
                review_required=review_required,
                variant=variant,
                payload={
                    "schema_version": "1.0",
                    "source_metadata": source_metadata,
                    "variant_index": index,
                    "variant": variant,
                },
            )
        )
    return candidates


def build_lazarus_candidates(event: Mapping[str, Any]) -> list[IngestionCandidate]:
    return build_event_candidates(event, source=SOURCE)


def _evidence_is_sufficient(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    levels: list[str] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        url = canonicalize_url(item.get("url"))
        level = str(item.get("source_level") or "").strip().upper()
        if url and level in {"A", "B", "C", "D"}:
            levels.append(level)
    return "A" in levels or "B" in levels or sum(x in {"B", "C"} for x in levels) >= 2


def validate_lazarus_variant(
    candidate: IngestionCandidate,
    organization_names: set[str],
    *,
    today: date | None = None,
) -> tuple[list[str], dict[str, Any]]:
    variant = candidate.variant
    errors: list[str] = []
    if candidate.quality_status != "accepted" or candidate.review_required:
        errors.append("来源质量状态不是可自动导入的 accepted")
    if str(variant.get("review_status") or "") != "accepted":
        errors.append("variant 尚未接受")

    event_date_text = str(variant.get("event_date") or "").strip()
    try:
        event_date = date.fromisoformat(event_date_text)
        if event_date > (today or date.today()):
            errors.append("事件日期晚于当前日期")
    except ValueError:
        event_date = None
        errors.append("event_date 不是 YYYY-MM-DD")

    date_precision = str(variant.get("date_precision") or "").strip()
    if date_precision not in AUTO_DATE_PRECISIONS:
        errors.append("日期精度不足或缺失")

    title = str(variant.get("title") or "").strip()
    description = str(variant.get("description") or "").strip()
    if not title or len(title) > 500:
        errors.append("标题为空或超过 500 字符")
    if not description:
        errors.append("描述为空")

    threat_type = str(variant.get("threat_type") or "").strip()
    if threat_type not in THREAT_TYPES:
        errors.append("threat_type 不在受控词表")

    organization_name = str(variant.get("organization_name") or "").strip()
    normalized_org_names = {name.casefold() for name in organization_names if name}
    if (
        not organization_name
        or organization_name.casefold() not in normalized_org_names
    ):
        errors.append("组织 ID 与名称不一致")

    try:
        confidence = float(variant.get("confidence"))
        if not 0 <= confidence <= 1:
            raise ValueError
        if confidence < 0.75:
            errors.append("置信度低于 0.75")
    except (TypeError, ValueError):
        confidence = None
        errors.append("置信度缺失或无效")

    link = canonicalize_url(variant.get("link"))
    if not link.startswith(("http://", "https://")):
        errors.append("来源链接无效")
    evidence = variant.get("evidence")
    if not _evidence_is_sufficient(evidence):
        errors.append("证据数量或来源等级不足")
    releasing_product = str(variant.get("releasing_product") or "").strip()
    if not releasing_product:
        errors.append("发布机构为空")

    event_key = str(variant.get("event_key") or "").strip().lower()
    if not SHA256_RE.fullmatch(event_key):
        event_key = _fallback_variant_key(variant)

    event_type = "major" if threat_type in MAJOR_THREAT_TYPES else "normal"
    severity = (
        5 if event_type == "major" else (4 if threat_type in SEVERITY_FOUR_TYPES else 3)
    )
    clean = {
        "event_key": event_key,
        "event_date": event_date,
        "date_precision": date_precision,
        "title": title,
        "description": description,
        "threat_type": threat_type,
        "organization_name": organization_name,
        "releasing_product": releasing_product,
        "link": link,
        "confidence": confidence,
        "evidence": evidence if isinstance(evidence, list) else [],
        "collection_notes": "；".join(
            str(item).strip()
            for item in (variant.get("review_reasons") or [])
            if str(item).strip()
        )
        or None,
        "event_type": event_type,
        "severity": severity,
    }
    return list(dict.fromkeys(errors)), clean
