#!/usr/bin/env python3
"""
最小验证脚本：组织画像读取 + 域名组织关联匹配（只读，不写库）

验证内容：
1) 从 apt_organizations 读取组织画像
2) 对测试域名执行 match_domain_to_actors
3) 输出 matched_organization_name、actor_score、evidence_json、top_candidates_json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict


def _prepare_import_path() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))  # backend/scripts
    backend_root = os.path.dirname(script_dir)  # backend
    if backend_root not in sys.path:
        sys.path.insert(0, backend_root)


_prepare_import_path()

from app.db.session import SessionLocal  # noqa: E402
from app.services.actor_matcher import load_actor_profiles, match_domain_to_actors  # noqa: E402


def _build_output(domain: str, match_result: Dict[str, Any], profile_count: int) -> Dict[str, Any]:
    return {
        "domain": domain,
        "actor_profiles_loaded": profile_count,
        "matched_organization_name": match_result.get("matched_organization_name"),
        "actor_score": match_result.get("actor_score"),
        "actor_confidence": match_result.get("actor_confidence"),
        "evidence_json": match_result.get("evidence_json"),
        "top_candidates_json": match_result.get("top_candidates_json"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="验证组织关联匹配流程（只读）")
    parser.add_argument(
        "--domain",
        required=True,
        help="待测试域名，例如: login-secure-example.com",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="输出候选组织数量（默认5）",
    )
    args = parser.parse_args()

    db = SessionLocal()
    try:
        profiles = load_actor_profiles(db)
        print(f"[verify-actor-match] loaded_profiles={len(profiles)}")

        result = match_domain_to_actors(args.domain, profiles)
        top_candidates = result.get("top_candidates_json")
        if isinstance(top_candidates, list):
            result["top_candidates_json"] = top_candidates[: max(1, args.top)]

        payload = _build_output(args.domain, result, len(profiles))
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    main()
