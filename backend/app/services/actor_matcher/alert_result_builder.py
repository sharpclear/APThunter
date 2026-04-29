from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence


def _to_plain_value(value: Any) -> Any:
    """
    将常见不可 JSON 序列化对象转换为基础类型。
    """
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, set):
        return [_to_plain_value(v) for v in sorted(value, key=lambda x: str(x))]
    if isinstance(value, (list, tuple)):
        return [_to_plain_value(v) for v in value]
    if isinstance(value, Mapping):
        return {str(k): _to_plain_value(v) for k, v in value.items()}
    if hasattr(value, "_asdict"):
        return _to_plain_value(value._asdict())
    return str(value)


def _getattr_or_dict(data: Any, key: str, default: Any = None) -> Any:
    if data is None:
        return default
    if isinstance(data, Mapping):
        return data.get(key, default)
    return getattr(data, key, default)


def _index_match_results(match_results: Any) -> Dict[str, Dict[str, Any]]:
    """
    将不同输入形态的匹配结果归一化为：
    { domain_name(lower): match_result_dict }
    """
    if not match_results:
        return {}

    if isinstance(match_results, Mapping):
        indexed: Dict[str, Dict[str, Any]] = {}
        for key, value in match_results.items():
            domain_key = str(key or "").strip().lower()
            if not domain_key or not isinstance(value, Mapping):
                continue
            indexed[domain_key] = dict(value)
        return indexed

    indexed = {}
    if isinstance(match_results, Sequence):
        for item in match_results:
            if not isinstance(item, Mapping):
                continue
            domain_name = str(item.get("domain_name") or item.get("domain") or "").strip().lower()
            if not domain_name:
                continue
            indexed[domain_name] = dict(item)
    return indexed


def _build_domain_score_map(results_malicious_subscription: Any) -> Dict[str, float]:
    score_map: Dict[str, float] = {}
    if not results_malicious_subscription:
        return score_map
    if not isinstance(results_malicious_subscription, Sequence):
        return score_map
    for item in results_malicious_subscription:
        if not isinstance(item, Mapping):
            continue
        domain = str(item.get("domain") or item.get("域名") or "").strip().lower()
        if not domain:
            continue
        try:
            score_map[domain] = float(item.get("恶意概率", item.get("malicious_score", item.get("score", 0.0))))
        except (TypeError, ValueError):
            continue
    return score_map


def _score_to_level(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


def _build_evidence_lines(match_result: Mapping[str, Any]) -> List[str]:
    evidence = match_result.get("evidence_json") or match_result.get("evidence") or {}
    if not isinstance(evidence, Mapping):
        return []

    lines: List[str] = []
    best_ioc = evidence.get("best_ioc")
    if best_ioc:
        lines.append(f"与历史 IOC 域名 {best_ioc} 具备相似特征")
    if evidence.get("tld_hit"):
        lines.append("TLD 或结构模式相似")
    keyword_overlap = evidence.get("keyword_overlap") or []
    if isinstance(keyword_overlap, Sequence) and not isinstance(keyword_overlap, (str, bytes)):
        overlap_terms = [str(v).strip() for v in keyword_overlap if str(v).strip()]
        if overlap_terms:
            lines.append(f"关键词重叠: {', '.join(overlap_terms[:5])}")
    if not lines and match_result.get("reason_summary"):
        lines.append(str(match_result.get("reason_summary")))
    return lines


def _build_matched_organizations(match_result: Mapping[str, Any]) -> List[Dict[str, Any]]:
    top_candidates = match_result.get("top_candidates_json") or match_result.get("top_candidates") or []
    matched_orgs: List[Dict[str, Any]] = []

    if isinstance(top_candidates, Sequence) and not isinstance(top_candidates, (str, bytes)):
        for candidate in top_candidates:
            if not isinstance(candidate, Mapping):
                continue
            score_value = candidate.get("score")
            try:
                match_score = float(score_value) if score_value is not None else None
            except (TypeError, ValueError):
                match_score = None
            candidate_evidence = candidate.get("evidence") or {}
            candidate_lines = _build_evidence_lines({"evidence_json": candidate_evidence})
            matched_orgs.append(
                {
                    "organization_id": _to_plain_value(candidate.get("organization_id")),
                    "organization_name": _to_plain_value(candidate.get("name")),
                    "confidence": _to_plain_value(candidate.get("confidence")),
                    "match_score": match_score,
                    "evidence": candidate_lines,
                }
            )

    if matched_orgs:
        return matched_orgs

    organization_id = match_result.get("matched_organization_id")
    organization_name = match_result.get("matched_organization_name")
    if organization_id is None and not organization_name:
        return []

    actor_score = match_result.get("actor_score")
    try:
        actor_score_value = float(actor_score) if actor_score is not None else None
    except (TypeError, ValueError):
        actor_score_value = None
    return [
        {
            "organization_id": _to_plain_value(organization_id),
            "organization_name": _to_plain_value(organization_name),
            "confidence": _to_plain_value(match_result.get("actor_confidence")),
            "match_score": actor_score_value,
            "evidence": _build_evidence_lines(match_result),
        }
    ]


def build_alert_result_json(
    *,
    alert_row: Any,
    subscription_row: Optional[Any],
    task_row: Optional[Any],
    high_risk_domains: Sequence[str],
    match_results: Optional[Any] = None,
    results_malicious_subscription: Optional[Sequence[Mapping[str, Any]]] = None,
    detected_count: Optional[int] = None,
    high_risk_count: Optional[int] = None,
    alert_time: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    组装单次预警完整结果 JSON（仅构建对象，不做持久化/上传）。
    - match_results 支持：
      1) {domain: match_result}
      2) [match_result, ...]（每项包含 domain_name/domain）
    """
    match_by_domain = _index_match_results(match_results)
    risk_score_map = _build_domain_score_map(results_malicious_subscription)

    normalized_domains: List[str] = []
    seen = set()
    for domain in high_risk_domains or []:
        domain_text = str(domain or "").strip()
        if not domain_text:
            continue
        domain_key = domain_text.lower()
        if domain_key in seen:
            continue
        seen.add(domain_key)
        normalized_domains.append(domain_text)

    domain_items: List[Dict[str, Any]] = []
    for domain_name in normalized_domains:
        domain_key = domain_name.lower()
        match_result = match_by_domain.get(domain_key, {})
        if not isinstance(match_result, Mapping):
            match_result = {}

        risk_score = risk_score_map.get(domain_key)
        if risk_score is None:
            actor_score = match_result.get("actor_score")
            try:
                risk_score = float(actor_score) if actor_score is not None else None
            except (TypeError, ValueError):
                risk_score = None

        org_score = match_result.get("actor_score")
        try:
            org_score = float(org_score) if org_score is not None else None
        except (TypeError, ValueError):
            org_score = None

        domain_items.append(
            {
                "domain": domain_name,
                "risk_score": risk_score,
                "risk_level": _score_to_level(risk_score),
                "scores": {
                    "scenario_score": None,
                    "infrastructure_score": None,
                    "organization_score": org_score,
                },
                "matched_organizations": _build_matched_organizations(match_result),
                "top_candidates": _to_plain_value(
                    match_result.get("top_candidates_json") or match_result.get("top_candidates") or []
                ),
                "evidence_summary": {
                    "domain_features": _to_plain_value(
                        _getattr_or_dict(
                            _getattr_or_dict(match_result, "enrichment_snapshot_json", {}),
                            "domain_features",
                            {},
                        )
                    ),
                    "organization_match": _to_plain_value(
                        match_result.get("evidence_json") or match_result.get("evidence") or {}
                    ),
                },
                "detected_at": _to_plain_value(alert_time or _getattr_or_dict(alert_row, "created_at")),
            }
        )

    detected_count_value = (
        detected_count
        if detected_count is not None
        else _getattr_or_dict(alert_row, "detected_count", len(normalized_domains))
    )
    high_risk_count_value = (
        high_risk_count
        if high_risk_count is not None
        else _getattr_or_dict(alert_row, "high_risk_count", len(normalized_domains))
    )

    payload = {
        "schema_version": "v1",
        "alert": {
            "alert_id": _getattr_or_dict(alert_row, "alert_id"),
            "subscription_id": _getattr_or_dict(alert_row, "subscription_id"),
            "task_id": _getattr_or_dict(alert_row, "task_id"),
            "user_id": _getattr_or_dict(alert_row, "user_id"),
            "model_id": _getattr_or_dict(alert_row, "model_id"),
            "model_name": _getattr_or_dict(alert_row, "model_name"),
            "task_type": _getattr_or_dict(alert_row, "task_type"),
            "frequency": _getattr_or_dict(subscription_row, "frequency"),
            "alert_time": _to_plain_value(alert_time or _getattr_or_dict(alert_row, "created_at")),
            "threshold": _getattr_or_dict(alert_row, "threshold"),
        },
        "summary": {
            "detected_count": detected_count_value,
            "high_risk_count": high_risk_count_value,
        },
        "high_risk_domains": domain_items,
        "meta": {
            "task_db_id": _getattr_or_dict(task_row, "id"),
            "subscription_db_id": _getattr_or_dict(subscription_row, "id"),
            "source": "subscription_alert",
        },
    }
    return _to_plain_value(payload)
