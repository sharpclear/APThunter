from __future__ import annotations

import io
import json
import os
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Optional, Tuple

import pandas as pd

try:
    from apt_nrd_similarity_detector import (
        Candidate,
        DomainSimilarityIndex,
        is_domain_like,
        normalize_domain,
        prepare_positive_seeds,
        read_domains_from_path,
        score_nrd_domains,
    )
except ImportError:
    from .apt_nrd_similarity_detector import (  # type: ignore
        Candidate,
        DomainSimilarityIndex,
        is_domain_like,
        normalize_domain,
        prepare_positive_seeds,
        read_domains_from_path,
        score_nrd_domains,
    )


CURRENT_DIR = Path(__file__).resolve().parent
APP_DIR = CURRENT_DIR.parent
PROJECT_DIR = APP_DIR.parent.parent
DEFAULT_HISTORY_PATH = CURRENT_DIR / "dataset" / "history_data" / "训练黑数据.xlsx"
DEFAULT_MIN_SCORE = float(os.getenv("HISTORY_SIMILARITY_MIN_SCORE", "0.65"))
DEFAULT_TOP_K = int(os.getenv("HISTORY_SIMILARITY_TOP_K", "10"))


def _clamp_score(value: Optional[float], default: float = DEFAULT_MIN_SCORE) -> float:
    try:
        score = float(value if value is not None else default)
    except (TypeError, ValueError):
        score = default
    return max(0.0, min(1.0, score))


def _normalize_domains(raw_domains: Iterable[Any]) -> Tuple[list[str], dict[str, int]]:
    domains: list[str] = []
    seen = set()
    raw_count = 0
    invalid_count = 0
    duplicate_count = 0
    for raw in raw_domains:
        raw_count += 1
        domain = normalize_domain(raw)
        if not is_domain_like(domain):
            invalid_count += 1
            continue
        if domain in seen:
            duplicate_count += 1
            continue
        seen.add(domain)
        domains.append(domain)
    return domains, {
        "raw_count": raw_count,
        "valid_count": len(domains),
        "invalid_count": invalid_count,
        "duplicate_count": duplicate_count,
    }


def read_domains_from_file(file_content: bytes, filename: str) -> list[str]:
    file_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if file_ext == "txt":
        text = file_content.decode("utf-8", errors="ignore")
        raw_domains = [line.strip() for line in text.splitlines() if line.strip()]
    elif file_ext == "csv":
        df = pd.read_csv(io.BytesIO(file_content))
        column = "domain" if "domain" in df.columns else df.columns[0]
        raw_domains = df[column].dropna().astype(str).tolist()
    elif file_ext == "xlsx":
        df = pd.read_excel(io.BytesIO(file_content))
        column = "domain" if "domain" in df.columns else df.columns[0]
        raw_domains = df[column].dropna().astype(str).tolist()
    else:
        raise ValueError(f"不支持的文件类型: {file_ext}")

    domains, _ = _normalize_domains(raw_domains)
    if not domains:
        raise ValueError("文件中没有找到有效域名")
    return domains


def _history_path(model_path: Optional[str]) -> Path:
    if not model_path:
        return DEFAULT_HISTORY_PATH
    candidate = Path(model_path)
    if candidate.is_absolute():
        return candidate
    for base in (CURRENT_DIR, APP_DIR, PROJECT_DIR):
        resolved = (base / candidate).resolve()
        if resolved.exists():
            return resolved
    if candidate.name == DEFAULT_HISTORY_PATH.name and DEFAULT_HISTORY_PATH.exists():
        return DEFAULT_HISTORY_PATH
    return (CURRENT_DIR / candidate).resolve()


@lru_cache(maxsize=8)
def _load_history_index(history_path: str, mtime_ns: int, top_k: int) -> tuple[DomainSimilarityIndex, dict[str, Any]]:
    path = Path(history_path)
    positives = read_domains_from_path(path)
    seeds = prepare_positive_seeds(positives)
    index = DomainSimilarityIndex.build(seeds, top_k=top_k)
    route_counts = Counter(seed.route for seed in seeds)
    meta = {
        "history_path": str(path),
        "history_domains": len(positives),
        "history_seeds": len(seeds),
        "index_seeds": len(index.seeds),
        "seed_route_counts": dict(sorted(route_counts.items())),
    }
    return index, meta


def _get_history_index(model_path: Optional[str], top_k: int) -> tuple[DomainSimilarityIndex, dict[str, Any]]:
    path = _history_path(model_path)
    if not path.is_file():
        raise FileNotFoundError(f"历史恶意域名文件不存在: {path}")
    stat = path.stat()
    return _load_history_index(str(path), stat.st_mtime_ns, max(1, int(top_k or DEFAULT_TOP_K)))


def _reason_label(reasons: str) -> str:
    mapping = {
        "similar_to_history": "与历史恶意域名字符串相似",
        "token_overlap": "关键词重叠",
        "common_prefix": "公共前缀明显",
        "common_suffix": "公共后缀明显",
        "same_suffix": "相同域名后缀",
        "weak_similarity": "弱相似候选",
    }
    parts = [part for part in str(reasons or "").split(";") if part]
    return "；".join(mapping.get(part, part) for part in parts)


def _candidate_to_row(candidate: Candidate) -> dict[str, Any]:
    return {
        "域名": candidate.domain,
        "规范化域名": candidate.normalized_domain,
        "匹配历史恶意域名": candidate.matched_positive,
        "综合相似度": round(float(candidate.final_score), 6),
        "TF-IDF相似度": round(float(candidate.tfidf_similarity), 6),
        "重排序相似度": round(float(candidate.rerank_score), 6),
        "候选路由": candidate.route,
        "历史样本路由": candidate.matched_positive_route,
        "命中原因": _reason_label(candidate.reasons),
        "原因代码": candidate.reasons,
        "预测标签": 1,
        "预测结果": "历史高度相似",
        "特征JSON": candidate.features_json,
    }


def _normal_row(domain: str) -> dict[str, Any]:
    return {
        "域名": domain,
        "规范化域名": domain,
        "匹配历史恶意域名": "",
        "综合相似度": 0.0,
        "TF-IDF相似度": 0.0,
        "重排序相似度": 0.0,
        "候选路由": "",
        "历史样本路由": "",
        "命中原因": "",
        "原因代码": "",
        "预测标签": 0,
        "预测结果": "未命中",
        "特征JSON": "{}",
    }


def _build_excel(
    *,
    domains: list[str],
    candidate_rows: list[dict[str, Any]],
    best_rows_by_domain: dict[str, dict[str, Any]],
    suspicious_only: bool,
    input_stats: dict[str, int],
    index_meta: dict[str, Any],
    min_score: float,
    top_k: int,
) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    history_count = len(best_rows_by_domain)
    total = len(domains)
    normal_count = max(0, total - history_count)
    history_rate = history_count / total * 100 if total else 0.0

    history_rows = [
        best_rows_by_domain[domain]
        for domain in domains
        if domain in best_rows_by_domain
    ]

    if suspicious_only:
        result_rows = history_rows
    else:
        result_rows = [
            best_rows_by_domain.get(domain) or _normal_row(domain)
            for domain in domains
        ]

    stats_rows = [
        ("总域名数", total),
        ("历史相似域名数", history_count),
        ("正常域名数", normal_count),
        ("历史相似域名占比", f"{history_rate:.2f}%"),
        ("历史匹配对数", len(candidate_rows)),
        ("历史样本数", index_meta.get("history_domains", 0)),
        ("索引样本数", index_meta.get("index_seeds", 0)),
        ("最低相似度阈值", f"{min_score:.2f}"),
        ("TopK", top_k),
        ("无效输入数", input_stats.get("invalid_count", 0)),
        ("重复输入数", input_stats.get("duplicate_count", 0)),
    ]

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        pd.DataFrame(result_rows).to_excel(writer, sheet_name="预测结果", index=False)
        pd.DataFrame(stats_rows, columns=["统计项", "数值"]).to_excel(writer, sheet_name="统计信息", index=False)
        pd.DataFrame(history_rows).to_excel(writer, sheet_name="历史相似域名列表", index=False)

    statistics = {
        "total": total,
        "history_similarity": history_count,
        "benign": normal_count,
        "history_similarity_rate": history_rate,
        "candidate_pairs": len(candidate_rows),
        "min_score": min_score,
        "top_k": top_k,
    }
    meta = {
        **index_meta,
        "input_stats": input_stats,
        "candidate_pairs": len(candidate_rows),
        "history_similarity_count": history_count,
        "parameters": {
            "min_score": min_score,
            "top_k": top_k,
        },
    }
    return output.getvalue(), statistics, meta


def predict_from_domains(
    domains: list[str],
    source_label: Optional[str] = None,
    model_path: Optional[str] = None,
    *,
    min_score: Optional[float] = None,
    top_k: int = DEFAULT_TOP_K,
    suspicious_only: bool = False,
) -> tuple[bytes, dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    normalized_domains, input_stats = _normalize_domains(domains)
    if not normalized_domains:
        raise ValueError("域名列表为空或没有有效域名")

    resolved_min_score = _clamp_score(min_score)
    resolved_top_k = max(1, int(top_k or DEFAULT_TOP_K))
    index, index_meta = _get_history_index(model_path, resolved_top_k)
    candidates = score_nrd_domains(
        normalized_domains,
        index,
        min_score=resolved_min_score,
        top_k=resolved_top_k,
    )
    candidate_rows = [_candidate_to_row(candidate) for candidate in candidates]

    best_rows_by_domain: dict[str, dict[str, Any]] = {}
    for row in candidate_rows:
        domain = str(row.get("域名") or "").lower()
        current = best_rows_by_domain.get(domain)
        if current is None or float(row.get("综合相似度") or 0) > float(current.get("综合相似度") or 0):
            best_rows_by_domain[domain] = row

    excel_content, statistics, meta = _build_excel(
        domains=normalized_domains,
        candidate_rows=candidate_rows,
        best_rows_by_domain=best_rows_by_domain,
        suspicious_only=suspicious_only,
        input_stats=input_stats,
        index_meta=index_meta,
        min_score=resolved_min_score,
        top_k=resolved_top_k,
    )
    meta["source_label"] = source_label or ""
    alert_rows = list(best_rows_by_domain.values())
    return excel_content, statistics, meta, alert_rows


def predict_from_file(
    file_content: bytes,
    filename: str,
    model_path: Optional[str] = None,
    *,
    min_score: Optional[float] = None,
    top_k: int = DEFAULT_TOP_K,
    suspicious_only: bool = False,
) -> tuple[bytes, dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    domains = read_domains_from_file(file_content, filename)
    return predict_from_domains(
        domains,
        filename,
        model_path,
        min_score=min_score,
        top_k=top_k,
        suspicious_only=suspicious_only,
    )


def alert_rows_to_score_records(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records = []
    for row in rows:
        domain = str(row.get("域名") or "").strip()
        if not domain:
            continue
        try:
            score = float(row.get("综合相似度") or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        records.append(
            {
                "domain": domain,
                "score": score,
                "history_similarity_score": score,
                "matched_positive": row.get("匹配历史恶意域名") or "",
                "reason": row.get("命中原因") or "",
                "raw": json.loads(json.dumps(row, ensure_ascii=False, default=str)),
            }
        )
    return records
