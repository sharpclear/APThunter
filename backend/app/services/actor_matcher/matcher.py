import re
from typing import Any, Dict, List, Sequence, Tuple

from app.services.actor_matcher.domain_features import (
    compute_pattern_score,
    extract_domain_features,
    max_ioc_similarity,
)


def _tokenize_text(value: str) -> List[str]:
    if not value:
        return []
    return [t for t in re.split(r"[-_.\d\s]+", value.lower()) if t]


def _confidence_from_score(score: float) -> str:
    if score >= 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _normalize_domain_term_text(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("码" + "址", "域名")
    if isinstance(value, list):
        return [_normalize_domain_term_text(item) for item in value]
    if isinstance(value, dict):
        return {k: _normalize_domain_term_text(v) for k, v in value.items()}
    return value


def _score_one_profile(domain_name: str, profile: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    features = extract_domain_features(domain_name)
    profile_iocs = [str(x) for x in (profile.get("previous_domains") or []) if str(x).strip()]
    profile_keywords = {
        str(x).strip().lower() for x in (profile.get("keywords") or []) if str(x).strip()
    }
    profile_tlds = {
        str(x).strip().lower().lstrip(".")
        for x in (profile.get("common_tlds") or [])
        if str(x).strip()
    }

    ioc_score, best_ioc = max_ioc_similarity(features.domain, profile_iocs)
    token_set = set(features.tokens)
    keyword_overlap = token_set & profile_keywords
    keyword_score = (
        float(len(keyword_overlap)) / float(max(1, len(profile_keywords)))
        if profile_keywords
        else 0.0
    )
    tld_score = 1.0 if features.tld and features.tld in profile_tlds else 0.0
    pattern_score = compute_pattern_score(features.tokens)

    alias_tokens = set()
    for alias in profile.get("alias") or []:
        alias_tokens.update(_tokenize_text(str(alias)))
    name_tokens = set(_tokenize_text(str(profile.get("name") or "")))
    label_hit_score = 1.0 if (features.sld and features.sld in (alias_tokens | name_tokens)) else 0.0

    final_score = (
        0.45 * ioc_score
        + 0.2 * keyword_score
        + 0.1 * tld_score
        + 0.15 * pattern_score
        + 0.1 * label_hit_score
    )
    final_score = max(0.0, min(1.0, final_score))

    evidence = {
        "ioc_score": ioc_score,
        "best_ioc": best_ioc,
        "keyword_overlap": sorted(keyword_overlap),
        "keyword_score": keyword_score,
        "tld_hit": bool(tld_score > 0),
        "pattern_score": pattern_score,
        "label_hit": bool(label_hit_score > 0),
    }
    if "explanation" in evidence:
        evidence["explanation"] = _normalize_domain_term_text(evidence.get("explanation"))
    return final_score, evidence


def match_domain_to_actors(domain_name: str, actor_profiles: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []

    for profile in actor_profiles:
        score, evidence = _score_one_profile(domain_name, profile)
        candidates.append(
            {
                "organization_id": profile.get("organization_id"),
                "name": profile.get("name"),
                "score": score,
                "confidence": _confidence_from_score(score),
                "evidence": evidence,
            }
        )

    candidates.sort(key=lambda x: x.get("score", 0.0), reverse=True)
    top_candidates = candidates[:5]
    best = top_candidates[0] if top_candidates else None
    best_score = float(best.get("score") or 0.0) if best else 0.0
    matched = best if best and best_score > 0 else None

    reason_summary = "该域名暂未与已知组织 IOC 画像形成稳定关联，建议作为未知来源疑似恶意域名纳入监测。"
    if matched:
        best_name = str(matched.get("name") or "").strip() or "未知组织"
        reason_summary = (
            f"该域名与 {best_name} 历史 IOC 画像在域名关键词、字符串相似度或结构模式上存在相似性，"
            f"建议作为疑似 {best_name} 相关域名纳入重点监测。"
        )

    top_candidates_json = _normalize_domain_term_text(top_candidates)
    evidence_json = _normalize_domain_term_text(matched.get("evidence") if matched else {})

    return {
        "domain_name": domain_name,
        "matched_organization_id": matched.get("organization_id") if matched else None,
        "matched_organization_name": matched.get("name") if matched else None,
        "actor_score": best_score,
        "actor_confidence": best.get("confidence") if best else "none",
        "reason_summary": reason_summary,
        "evidence_json": evidence_json,
        "top_candidates_json": top_candidates_json,
        "enrichment_snapshot_json": {
            "domain_features": extract_domain_features(domain_name).__dict__,
            "candidate_count": len(candidates),
        },
        "match_method": "rule_v1",
        "best_match": matched or {},
    }
