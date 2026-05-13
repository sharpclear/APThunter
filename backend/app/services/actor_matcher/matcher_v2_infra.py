import re
from datetime import date, datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from app.services.actor_matcher.domain_features import (
    compute_pattern_score,
    extract_domain_features,
    max_ioc_similarity,
)
from app.services.actor_matcher.domain_infra_snapshot_loader import (
    load_domain_infra_snapshot,
)
from app.services.actor_matcher.infra_profile_cache_loader import (
    load_actor_infra_profiles_from_cache,
)


def _clamp_score(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except Exception:
        return 0.0


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    text = re.sub(r"\s+", " ", str(value).strip().lower())
    return text.rstrip(".")


def _tokenize_text(value: Any) -> Set[str]:
    return {token for token in re.split(r"[-_.\d\s]+", _safe_text(value)) if token}


def _mapping_keys(value: Any) -> Set[str]:
    if isinstance(value, Mapping):
        return {_safe_text(key) for key in value.keys() if _safe_text(key)}
    if isinstance(value, (list, tuple, set)):
        return {_safe_text(item) for item in value if _safe_text(item)}
    if value:
        normalized = _safe_text(value)
        return {normalized} if normalized else set()
    return set()


def _list_values(value: Any) -> Set[str]:
    if isinstance(value, Mapping):
        return {_safe_text(item) for item in value.values() if _safe_text(item)}
    if isinstance(value, (list, tuple, set)):
        return {_safe_text(item) for item in value if _safe_text(item)}
    normalized = _safe_text(value)
    return {normalized} if normalized else set()


def _date_values(value: Any) -> Set[str]:
    if not value:
        return set()
    if isinstance(value, Mapping):
        raw_values = value.keys()
    elif isinstance(value, (list, tuple, set)):
        raw_values = value
    else:
        raw_values = [value]
    out: Set[str] = set()
    for item in raw_values:
        if isinstance(item, (datetime, date)):
            out.add(item.date().isoformat() if isinstance(item, datetime) else item.isoformat())
            continue
        normalized = _safe_text(item)
        if normalized:
            out.add(normalized[:10])
    return out


def _score_set_overlap(left: Set[str], right: Set[str]) -> Tuple[float, Set[str]]:
    if not left or not right:
        return 0.0, set()
    overlap = left & right
    if not overlap:
        return 0.0, set()
    return _clamp_score(len(overlap) / max(1, min(len(left), len(right)))), overlap


def _global_org_count(global_stats: Mapping[str, Any], key: str) -> int:
    try:
        value_frequency = global_stats.get("value_organization_frequency") or {}
        return int(value_frequency.get(key, 0) or 0) if isinstance(value_frequency, Mapping) else 0
    except Exception:
        return 0


def _uniqueness_weight(global_stats: Mapping[str, Any], key: str) -> float:
    org_count = _global_org_count(global_stats, key)
    if org_count <= 1:
        return 1.0
    if org_count == 2:
        return 0.75
    if org_count <= 5:
        return 0.45
    return 0.2


def _add_evidence(
    evidence: List[Dict[str, Any]],
    *,
    strength: str,
    category: str,
    field: str,
    values: Sequence[str],
    score: float,
    description: str,
) -> None:
    cleaned = sorted({_safe_text(value) for value in values if _safe_text(value)})
    if not cleaned and score <= 0:
        return
    evidence.append(
        {
            "strength": strength,
            "category": category,
            "field": field,
            "values": cleaned,
            "score": round(_clamp_score(score), 4),
            "description": description,
        }
    )


def _profile_from_legacy(profile: Mapping[str, Any]) -> Dict[str, Any]:
    historical_domains = [
        _safe_text(item)
        for item in (profile.get("historical_domains") or profile.get("previous_domains") or [])
        if _safe_text(item)
    ]
    tlds: Dict[str, int] = {}
    tokens: Dict[str, int] = {}
    sld_patterns: Dict[str, int] = {}
    for domain in historical_domains:
        features = extract_domain_features(domain)
        if features.tld:
            tlds[features.tld] = tlds.get(features.tld, 0) + 1
        for token in features.tokens:
            tokens[token] = tokens.get(token, 0) + 1
        sld_pattern = _sld_structure_pattern(features.sld)
        if sld_pattern:
            sld_patterns[sld_pattern] = sld_patterns.get(sld_pattern, 0) + 1

    for keyword in profile.get("keywords") or []:
        keyword_text = _safe_text(keyword)
        if keyword_text:
            tokens[keyword_text] = max(1, tokens.get(keyword_text, 0))
    for tld in profile.get("common_tlds") or []:
        tld_text = _safe_text(tld).lstrip(".")
        if tld_text:
            tlds[tld_text] = max(1, tlds.get(tld_text, 0))

    return {
        "organization_id": profile.get("organization_id"),
        "organization_name": profile.get("name") or profile.get("organization_name") or "",
        "domain_profile": {
            "historical_domains": historical_domains,
            "tokens": tokens,
            "tld": tlds,
            "sld_patterns": sld_patterns,
        },
        "whois_profile": {},
        "dns_profile": {},
        "ssl_profile": {},
        "summary": {},
    }


def _sld_structure_pattern(sld: str) -> str:
    parts: List[str] = []
    for token in re.split(r"([-.])", sld or ""):
        if not token:
            continue
        if token in {"-", "."}:
            parts.append(token)
            continue
        has_alpha = bool(re.search(r"[a-z]", token))
        has_digit = bool(re.search(r"\d", token))
        if has_alpha and has_digit:
            parts.append("alpha_digit")
        elif has_alpha:
            parts.append("alpha")
        elif has_digit:
            parts.append("digit")
        else:
            parts.append("symbol")
    return "".join(parts) or "unknown"


def _load_actor_cache(actor_profiles: Sequence[Dict[str, Any]], db) -> Dict[str, Any]:
    if db is not None:
        cached = load_actor_infra_profiles_from_cache(db)
        if cached.get("actors"):
            return cached
    actors: Dict[Any, Dict[str, Any]] = {}
    for profile in actor_profiles or []:
        converted = _profile_from_legacy(profile)
        org_id = converted.get("organization_id")
        if org_id is not None:
            actors[org_id] = converted
    return {"actors": actors, "global_stats": {}}


def _empty_snapshot() -> Dict[str, Any]:
    return {
        "whois": {"status": "not_collected"},
        "dns": {"status": "not_collected"},
        "ssl": {"status": "not_collected"},
    }


def _has_infra_data(snapshot: Mapping[str, Any]) -> bool:
    return any(
        isinstance(snapshot.get(section), Mapping)
        and snapshot.get(section, {}).get("status") == "collected"
        for section in ("whois", "dns", "ssl")
    )


def _domain_profile_score(
    domain_name: str,
    actor: Mapping[str, Any],
    global_stats: Mapping[str, Any],
) -> Tuple[float, Dict[str, float], List[Dict[str, Any]]]:
    features = extract_domain_features(domain_name)
    domain_profile = actor.get("domain_profile") or {}
    historical_domains = [
        _safe_text(item)
        for item in domain_profile.get("historical_domains", [])
        if _safe_text(item)
    ]
    ioc_score, best_ioc = max_ioc_similarity(features.domain, historical_domains)

    actor_tokens = _mapping_keys(
        domain_profile.get("tokens") or domain_profile.get("token_frequency")
    )
    domain_tokens = {_safe_text(token) for token in features.tokens if _safe_text(token)}
    keyword_overlap = actor_tokens & domain_tokens
    distinctive_keyword_score = 0.0
    if keyword_overlap:
        weighted = [
            _uniqueness_weight(global_stats, f"domain:{token}")
            for token in keyword_overlap
        ]
        distinctive_keyword_score = _clamp_score(sum(weighted) / max(1, min(len(domain_tokens), 3)))

    sld_pattern = _sld_structure_pattern(features.sld)
    actor_patterns = _mapping_keys(
        domain_profile.get("sld_patterns")
        or domain_profile.get("sld_structure_patterns")
    )
    structure_score = 1.0 if sld_pattern and sld_pattern in actor_patterns else 0.0

    org_name_tokens = _tokenize_text(actor.get("organization_name"))
    label_hit_score = 1.0 if features.sld and features.sld in org_name_tokens else 0.0

    actor_tlds = _mapping_keys(domain_profile.get("tld") or domain_profile.get("tld_frequency"))
    tld_score = 1.0 if features.tld and features.tld in actor_tlds else 0.0

    weak_pattern_score = compute_pattern_score(features.tokens)

    score = (
        0.45 * ioc_score
        + 0.20 * distinctive_keyword_score
        + 0.15 * structure_score
        + 0.08 * label_hit_score
        + 0.07 * tld_score
        + 0.05 * weak_pattern_score
    )
    score = _clamp_score(score)

    evidence: List[Dict[str, Any]] = []
    if ioc_score > 0:
        strength = "medium" if ioc_score >= 0.45 else "weak"
        _add_evidence(
            evidence,
            strength=strength,
            category="domain",
            field="historical_domains",
            values=[best_ioc] if best_ioc else [],
            score=ioc_score,
            description="与组织历史域名存在字符串相似度",
        )
    if keyword_overlap:
        _add_evidence(
            evidence,
            strength="medium",
            category="domain",
            field="distinctive_keywords",
            values=sorted(keyword_overlap),
            score=distinctive_keyword_score,
            description="命中组织域名画像中的相对独特关键词",
        )
    if structure_score > 0:
        _add_evidence(
            evidence,
            strength="medium",
            category="domain",
            field="sld_structure",
            values=[sld_pattern],
            score=structure_score,
            description="二级域名结构模式与组织画像一致",
        )
    if tld_score > 0:
        _add_evidence(
            evidence,
            strength="weak",
            category="domain",
            field="tld",
            values=[features.tld],
            score=tld_score,
            description="TLD 与组织历史画像一致",
        )
    if weak_pattern_score > 0:
        _add_evidence(
            evidence,
            strength="weak",
            category="domain",
            field="weak_pattern",
            values=features.tokens,
            score=weak_pattern_score,
            description="命中通用仿冒/服务类模式词",
        )

    return (
        score,
        {
            "ioc": _clamp_score(ioc_score),
            "distinctive_keyword": distinctive_keyword_score,
            "structure": structure_score,
            "label_hit": label_hit_score,
            "tld": tld_score,
            "weak_pattern": weak_pattern_score,
        },
        evidence,
    )


def _score_whois(
    snapshot: Mapping[str, Any],
    actor: Mapping[str, Any],
    global_stats: Mapping[str, Any],
) -> Tuple[float, List[Dict[str, Any]]]:
    whois = snapshot.get("whois") or {}
    if whois.get("status") != "collected":
        return 0.0, []
    profile = actor.get("whois_profile") or {}
    evidence: List[Dict[str, Any]] = []
    components: List[float] = []

    ns_score, ns_overlap = _score_set_overlap(
        _list_values(whois.get("name_servers")),
        _mapping_keys(profile.get("name_servers") or profile.get("name_server_frequency")),
    )
    if ns_overlap:
        weighted = max(_uniqueness_weight(global_stats, f"whois:name_server:{value}") for value in ns_overlap)
        ns_score = _clamp_score(ns_score * weighted)
        strength = "strong" if weighted >= 0.75 else "weak"
        _add_evidence(
            evidence,
            strength=strength,
            category="whois",
            field="name_servers",
            values=sorted(ns_overlap),
            score=ns_score,
            description="WHOIS NS 与组织画像重合",
        )
        components.append(1.0 if strength == "strong" else ns_score * 0.5)

    registrar = _safe_text(whois.get("registrar"))
    actor_registrars = _mapping_keys(profile.get("registrar") or profile.get("registrar_frequency"))
    if registrar and registrar in actor_registrars:
        weight = _uniqueness_weight(global_stats, f"whois:registrar:{registrar}")
        registrar_score = _clamp_score(weight)
        strength = "medium" if weight >= 0.45 else "weak"
        _add_evidence(
            evidence,
            strength=strength,
            category="whois",
            field="registrar",
            values=[registrar],
            score=registrar_score,
            description="WHOIS registrar 与组织画像重合",
        )
        components.append(0.65 if strength == "medium" else registrar_score * 0.35)

    domain_dates = _date_values([whois.get("registration_date"), whois.get("expiration_date")])
    actor_dates = _date_values(profile.get("registration_dates")) | _date_values(profile.get("expiration_dates"))
    date_score, date_overlap = _score_set_overlap(domain_dates, actor_dates)
    if date_overlap:
        _add_evidence(
            evidence,
            strength="medium",
            category="whois",
            field="registration_window",
            values=sorted(date_overlap),
            score=date_score,
            description="注册/过期日期窗口与组织历史画像重合",
        )
        components.append(0.5 * date_score)

    return (_clamp_score(max(components) if components else 0.0), evidence)


def _score_dns(
    snapshot: Mapping[str, Any],
    actor: Mapping[str, Any],
) -> Tuple[float, List[Dict[str, Any]]]:
    dns = snapshot.get("dns") or {}
    if dns.get("status") != "collected":
        return 0.0, []
    profile = actor.get("dns_profile") or {}
    evidence: List[Dict[str, Any]] = []
    components: List[float] = []

    ip_score, ip_overlap = _score_set_overlap(
        _list_values(dns.get("ips")),
        _mapping_keys(profile.get("ips") or profile.get("ip_frequency")),
    )
    if ip_overlap:
        _add_evidence(
            evidence,
            strength="strong",
            category="dns",
            field="ips",
            values=sorted(ip_overlap),
            score=ip_score,
            description="DNS IP 与组织画像重合",
        )
        components.append(1.0)

    cname_score, cname_overlap = _score_set_overlap(
        _list_values(dns.get("cnames")),
        _mapping_keys(profile.get("cname") or profile.get("cname_frequency")),
    )
    if cname_overlap:
        _add_evidence(
            evidence,
            strength="strong",
            category="dns",
            field="cnames",
            values=sorted(cname_overlap),
            score=cname_score,
            description="DNS CNAME 与组织画像重合",
        )
        components.append(0.95)

    for field, profile_key, output_field in (
        ("mx_records", "mx", "mx_records"),
        ("txt_records", "txt", "txt_records"),
    ):
        medium_score, overlap = _score_set_overlap(
            _list_values(dns.get(field)),
            _mapping_keys(profile.get(profile_key) or profile.get(f"{profile_key}_frequency")),
        )
        if overlap:
            _add_evidence(
                evidence,
                strength="medium",
                category="dns",
                field=output_field,
                values=sorted(overlap),
                score=medium_score,
                description=f"DNS {output_field} 与组织画像重合",
            )
            components.append(0.65 * medium_score)

    ttl_score, ttl_overlap = _score_set_overlap(
        {str(item) for item in dns.get("ttls") or []},
        _mapping_keys(profile.get("ttl") or profile.get("ttl_frequency")),
    )
    if ttl_overlap:
        _add_evidence(
            evidence,
            strength="weak",
            category="dns",
            field="ttls",
            values=sorted(ttl_overlap),
            score=ttl_score,
            description="DNS TTL 与组织画像重合",
        )
        components.append(0.25 * ttl_score)

    return (_clamp_score(max(components) if components else 0.0), evidence)


def _score_ssl(
    snapshot: Mapping[str, Any],
    actor: Mapping[str, Any],
) -> Tuple[float, List[Dict[str, Any]]]:
    ssl_snapshot = snapshot.get("ssl") or {}
    if ssl_snapshot.get("status") != "collected":
        return 0.0, []
    profile = actor.get("ssl_profile") or {}
    evidence: List[Dict[str, Any]] = []
    components: List[float] = []

    for field, profile_key, label in (
        ("fingerprints", "fingerprints", "fingerprints"),
        ("san_names", "san", "san_names"),
    ):
        score, overlap = _score_set_overlap(
            _list_values(ssl_snapshot.get(field)),
            _mapping_keys(profile.get(profile_key) or profile.get(f"{profile_key}_frequency")),
        )
        if overlap:
            _add_evidence(
                evidence,
                strength="strong",
                category="ssl",
                field=label,
                values=sorted(overlap),
                score=score,
                description=f"SSL {label} 与组织画像重合",
            )
            components.append(1.0 if field == "fingerprints" else 0.9)

    for field, profile_key, label in (
        ("subjects", "subject", "subjects"),
        ("issuers", "issuer", "issuers"),
    ):
        score, overlap = _score_set_overlap(
            _list_values(ssl_snapshot.get(field)),
            _mapping_keys(profile.get(profile_key) or profile.get(f"{profile_key}_frequency")),
        )
        if overlap:
            _add_evidence(
                evidence,
                strength="medium",
                category="ssl",
                field=label,
                values=sorted(overlap),
                score=score,
                description=f"SSL {label} 模板与组织画像重合",
            )
            components.append(0.65 * score)

    return (_clamp_score(max(components) if components else 0.0), evidence)


def _effective_evidence_count(evidence: Sequence[Mapping[str, Any]]) -> int:
    return sum(1 for item in evidence if item.get("strength") in {"strong", "medium"})


def _has_only_weak(evidence: Sequence[Mapping[str, Any]]) -> bool:
    return bool(evidence) and all(item.get("strength") == "weak" for item in evidence)


def _confidence(status: str, score: float) -> str:
    if status == "suspected_match":
        if score >= 0.75:
            return "high"
        if score >= 0.55:
            return "medium"
        return "low"
    if status in {"candidate_only", "ambiguous"}:
        return "candidate"
    return "none"


def _status_reason(status: str, org_name: str, score: float) -> str:
    if status == "suspected_match":
        return f"该域名与 {org_name} 在域名画像和基础设施证据上形成疑似关联，综合评分 {score:.2f}。"
    if status == "ambiguous":
        return f"该域名存在多个接近候选组织，Top1/Top2 差距不足 0.10，暂不做唯一归因。"
    if status == "candidate_only":
        return "该域名仅形成候选关联，证据强度或有效证据数量不足，建议人工复核。"
    return "该域名暂未与已知组织基础设施画像形成稳定关联。"


def _score_one_actor(
    domain_name: str,
    actor: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    global_stats: Mapping[str, Any],
) -> Dict[str, Any]:
    domain_score, domain_components, domain_evidence = _domain_profile_score(
        domain_name, actor, global_stats
    )
    whois_score, whois_evidence = _score_whois(snapshot, actor, global_stats)
    dns_score, dns_evidence = _score_dns(snapshot, actor)
    ssl_score, ssl_evidence = _score_ssl(snapshot, actor)
    infra_score = _clamp_score(0.25 * whois_score + 0.45 * dns_score + 0.30 * ssl_score)
    has_infra = _has_infra_data(snapshot)
    final_score = (
        _clamp_score(0.60 * domain_score + 0.40 * infra_score)
        if has_infra
        else domain_score
    )

    evidence = domain_evidence + whois_evidence + dns_evidence + ssl_evidence
    org_id = actor.get("organization_id")
    org_name = str(actor.get("organization_name") or "").strip() or "未知组织"
    return {
        "organization_id": org_id,
        "name": org_name,
        "score": final_score,
        "scores": {
            "final_score": final_score,
            "domain_profile_score": domain_score,
            "infra_evidence_score": infra_score if has_infra else None,
            "whois_infra_score": whois_score,
            "dns_infra_score": dns_score,
            "ssl_cert_score": ssl_score,
        },
        "domain_score_components": domain_components,
        "evidence": evidence,
        "effective_evidence_count": _effective_evidence_count(evidence),
        "evidence_strengths": sorted({item.get("strength") for item in evidence if item.get("strength")}),
        "has_infra_snapshot": has_infra,
    }


def match_domain_to_actors_v2_infra(
    domain_name: str,
    actor_profiles: Sequence[Dict[str, Any]],
    db=None,
) -> Dict[str, Any]:
    actor_cache = _load_actor_cache(actor_profiles, db)
    actors = actor_cache.get("actors") or {}
    global_stats = actor_cache.get("global_stats") or {}
    snapshot = load_domain_infra_snapshot(db, domain_name) if db is not None else _empty_snapshot()
    features = extract_domain_features(domain_name)

    candidates: List[Dict[str, Any]] = []
    for actor in actors.values():
        candidates.append(_score_one_actor(domain_name, actor, snapshot, global_stats))

    candidates.sort(key=lambda item: float(item.get("score") or 0.0), reverse=True)
    top_candidates = candidates[:5]
    best = top_candidates[0] if top_candidates else None
    second = top_candidates[1] if len(top_candidates) > 1 else None

    match_status = "no_match"
    matched = None
    best_score = float(best.get("score") or 0.0) if best else 0.0
    score_gap = best_score - float(second.get("score") or 0.0) if best and second else best_score

    if best and best_score >= 0.35:
        if _has_only_weak(best.get("evidence") or []):
            match_status = "candidate_only"
            matched = best
        elif int(best.get("effective_evidence_count") or 0) < 2:
            match_status = "candidate_only"
            matched = best
        elif second and score_gap < 0.10:
            match_status = "ambiguous"
            matched = best
        else:
            match_status = "suspected_match"
            matched = best

    output_scores = (
        (matched or best).get("scores")
        if (matched or best)
        else {
            "final_score": best_score,
            "domain_profile_score": 0.0,
            "infra_evidence_score": None if not _has_infra_data(snapshot) else 0.0,
            "whois_infra_score": 0.0,
            "dns_infra_score": 0.0,
            "ssl_cert_score": 0.0,
        }
    )
    evidence_json = matched.get("evidence") if matched else []
    org_name = str(matched.get("name") or "").strip() if matched else ""

    return {
        "domain_name": domain_name,
        "match_method": "rule_v2_infra",
        "match_status": match_status,
        "matched_organization_id": matched.get("organization_id") if matched else None,
        "matched_organization_name": org_name or None,
        "actor_score": round(best_score, 4),
        "actor_confidence": _confidence(match_status, best_score),
        "reason_summary": _status_reason(match_status, org_name or "未知组织", best_score),
        "scores": {
            key: (round(value, 4) if isinstance(value, float) else value)
            for key, value in output_scores.items()
        },
        "evidence_json": evidence_json,
        "top_candidates_json": [
            {
                "organization_id": item.get("organization_id"),
                "name": item.get("name"),
                "score": round(float(item.get("score") or 0.0), 4),
                "scores": {
                    key: (round(value, 4) if isinstance(value, float) else value)
                    for key, value in (item.get("scores") or {}).items()
                },
                "effective_evidence_count": item.get("effective_evidence_count", 0),
                "evidence_strengths": item.get("evidence_strengths", []),
            }
            for item in top_candidates
        ],
        "enrichment_snapshot_json": {
            "domain_features": features.__dict__,
            "infra_snapshot": snapshot,
            "candidate_count": len(candidates),
            "top_score_gap": round(score_gap, 4),
            "used_cache_profile_count": len(actors),
            "infra_data_available": _has_infra_data(snapshot),
        },
        "best_match": matched or {},
    }
