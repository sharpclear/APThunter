from typing import Any, Dict, List, Optional, Sequence

from app.entities import AlertDomainMatch


def _first_value(payload: Dict[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in payload and payload.get(key) is not None:
            return payload.get(key)
    return None


def _resolve_profile_version(
    actor_profiles: Sequence[Dict[str, Any]], explicit_version: Optional[str]
) -> Optional[str]:
    if explicit_version:
        return explicit_version
    versions: List[str] = []
    for profile in actor_profiles:
        version = profile.get("profile_version")
        if version is None:
            continue
        text_version = str(version).strip()
        if text_version:
            versions.append(text_version)
    if not versions:
        return None
    if len(set(versions)) == 1:
        return versions[0]
    return "mixed"


def create_alert_domain_match(
    db,
    alert_id: int,
    task_id: Optional[int],
    domain_id: Optional[int],
    match_result: Dict[str, Any],
) -> AlertDomainMatch:
    payload = dict(match_result or {})

    domain_name = _first_value(payload, ("domain_name", "domain"))
    if domain_name is None or not str(domain_name).strip():
        raise ValueError("domain_name is required for alert_domain_matches snapshot")
    domain_name = str(domain_name).strip()

    best_match = payload.get("best_match")
    if not isinstance(best_match, dict):
        best_match = {}

    matched_organization_id = _first_value(
        payload,
        ("matched_organization_id", "organization_id"),
    )
    if matched_organization_id is None:
        matched_organization_id = best_match.get("organization_id")

    matched_organization_name = _first_value(
        payload,
        ("matched_organization_name", "organization_name"),
    )
    if matched_organization_name is None:
        matched_organization_name = best_match.get("name")

    row = AlertDomainMatch(
        alert_id=alert_id,
        task_id=task_id if task_id is not None else payload.get("task_id"),
        domain_id=domain_id if domain_id is not None else payload.get("domain_id"),
        domain_name=domain_name,
        malicious_score=_first_value(payload, ("malicious_score", "score")),
        risk_level=payload.get("risk_level"),
        matched_organization_id=matched_organization_id,
        matched_organization_name=matched_organization_name,
        actor_score=_first_value(payload, ("actor_score", "match_score")),
        actor_confidence=_first_value(payload, ("actor_confidence", "confidence")),
        reason_summary=_first_value(payload, ("reason_summary", "reason")),
        evidence_json=_first_value(payload, ("evidence_json", "evidence")),
        top_candidates_json=_first_value(
            payload,
            ("top_candidates_json", "top_candidates", "candidates"),
        ),
        enrichment_snapshot_json=_first_value(
            payload,
            ("enrichment_snapshot_json", "enrichment_snapshot"),
        ),
        model_id=payload.get("model_id"),
        model_version=payload.get("model_version"),
        actor_profile_version=payload.get("actor_profile_version"),
        match_method=payload.get("match_method") or "rule_v1",
        status=payload.get("status") or "pending",
    )
    db.add(row)
    db.flush()
    return row


def create_alert_domain_matches_for_domains(
    db,
    alert_id: int,
    task_id: Optional[int],
    domains: List[Dict[str, Any]],
    actor_profiles: List[Dict[str, Any]],
    model_id: Optional[int],
    model_version: Optional[str],
    actor_profile_version: Optional[str],
) -> List[AlertDomainMatch]:
    created_rows: List[AlertDomainMatch] = []
    resolved_profile_version = _resolve_profile_version(actor_profiles, actor_profile_version)

    for domain_item in domains:
        if not isinstance(domain_item, dict):
            raise ValueError("domains items must be dict")

        domain_name = _first_value(domain_item, ("domain_name", "domain"))
        if domain_name is None or not str(domain_name).strip():
            raise ValueError("domain_name/domain is required in domains item")

        match_result_obj = _first_value(
            domain_item,
            ("match_result", "match", "actor_match_result"),
        )
        if match_result_obj is None:
            match_result_obj = {}
        if not isinstance(match_result_obj, dict):
            raise ValueError("match_result must be a dict when provided")

        payload = dict(match_result_obj)
        payload.setdefault("domain_name", str(domain_name).strip())
        payload.setdefault("domain_id", domain_item.get("domain_id"))
        payload.setdefault(
            "malicious_score",
            _first_value(domain_item, ("malicious_score", "score")),
        )
        payload.setdefault("model_id", model_id)
        payload.setdefault("model_version", model_version)
        payload.setdefault("actor_profile_version", resolved_profile_version)
        payload.setdefault("status", "pending")

        row = create_alert_domain_match(
            db=db,
            alert_id=alert_id,
            task_id=task_id,
            domain_id=domain_item.get("domain_id"),
            match_result=payload,
        )
        created_rows.append(row)

    return created_rows
