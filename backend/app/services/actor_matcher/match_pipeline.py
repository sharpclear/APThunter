import logging
from typing import Dict, List, Optional

from sqlalchemy import text

from app.services.actor_matcher.match_store import create_alert_domain_match
from app.services.actor_matcher.matcher import match_domain_to_actors
from app.services.actor_matcher.profile_loader import load_actor_profiles

logger = logging.getLogger("uvicorn.error")


def _resolve_domain_id(db, domain_name: str) -> Optional[int]:
    row = db.execute(
        text("SELECT id FROM domains WHERE domain_name = :domain_name LIMIT 1"),
        {"domain_name": domain_name},
    ).first()
    if row:
        return int(row[0])

    try:
        db.execute(
            text("INSERT INTO domains (domain_name) VALUES (:domain_name)"),
            {"domain_name": domain_name},
        )
        created = db.execute(
            text("SELECT id FROM domains WHERE domain_name = :domain_name LIMIT 1"),
            {"domain_name": domain_name},
        ).first()
        if created:
            return int(created[0])
    except Exception:
        logger.exception("创建 domains 记录失败 domain_name=%s", domain_name)
    return None


def _build_malicious_score_map(results_malicious_subscription) -> Dict[str, float]:
    score_map: Dict[str, float] = {}
    if not results_malicious_subscription:
        return score_map
    for item in results_malicious_subscription:
        try:
            domain_name = str(item.get("域名") or item.get("domain") or "").strip()
            if not domain_name:
                continue
            prob = float(item.get("恶意概率", 0.0))
            score_map[domain_name] = prob
        except Exception:
            continue
    return score_map


def persist_actor_matches_for_alert(
    db,
    *,
    alert_row,
    task_row,
    high_risk_domains: List[str],
    model_id: Optional[int],
    model_version: Optional[str],
    results_malicious_subscription=None,
) -> int:
    actor_profiles = load_actor_profiles(db)
    if not actor_profiles:
        logger.warning("组织画像为空，跳过组织关联匹配 alert_id=%s", getattr(alert_row, "id", None))
        return 0

    malicious_score_map = _build_malicious_score_map(results_malicious_subscription)
    created_count = 0
    task_numeric_id = getattr(task_row, "id", None)
    profile_version = "actor_profile_v1"
    if actor_profiles:
        versions = {
            str(p.get("profile_version")).strip()
            for p in actor_profiles
            if str(p.get("profile_version") or "").strip()
        }
        if len(versions) == 1:
            profile_version = next(iter(versions))
        elif len(versions) > 1:
            profile_version = "mixed"

    for domain in high_risk_domains or []:
        domain_name = str(domain or "").strip()
        if not domain_name:
            continue
        try:
            domain_id = _resolve_domain_id(db, domain_name)
            match_result = match_domain_to_actors(domain_name, actor_profiles)
            match_result["model_id"] = model_id
            match_result["model_version"] = model_version
            match_result["actor_profile_version"] = profile_version
            match_result["malicious_score"] = malicious_score_map.get(domain_name)
            match_result["match_method"] = "rule_v1"
            match_result["status"] = "pending"

            create_alert_domain_match(
                db=db,
                alert_id=int(alert_row.id),
                task_id=int(task_numeric_id) if task_numeric_id is not None else None,
                domain_id=domain_id,
                match_result=match_result,
            )
            created_count += 1
        except Exception:
            logger.exception(
                "保存域名组织关联失败，已跳过 alert_id=%s domain=%s",
                getattr(alert_row, "id", None),
                domain_name,
            )
            continue
    return created_count
