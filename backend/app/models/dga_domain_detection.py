from __future__ import annotations

import io
import os
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from dga_detection_utils import extract_sld, normalize_domain
from dga_detector import _score_raw_domains, load_metadata, load_model
from malicious_detection import read_domains_from_file


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MODEL_PATH = os.path.join(CURRENT_DIR, "saved_model", "dga_cnn_detector.keras")
DEFAULT_CANDIDATE_THRESHOLD = float(os.getenv("DGA_CANDIDATE_THRESHOLD", "0.99"))

_MODEL_CACHE: dict[str, tuple[Any, dict[str, Any]]] = {}


def _resolve_model_path(model_path: Optional[str]) -> str:
    value = (model_path or "").strip()
    if not value:
        return DEFAULT_MODEL_PATH
    if os.path.isabs(value):
        return value
    return os.path.normpath(os.path.join(CURRENT_DIR, value))


def _resolve_metadata_path(model_path: str) -> str:
    base, ext = os.path.splitext(model_path)
    candidates = [
        f"{base}.metadata.json" if ext else f"{model_path}.metadata.json",
        f"{model_path}.metadata.json",
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return candidates[0]


def _load_detector(model_path: Optional[str]) -> tuple[Any, dict[str, Any], str]:
    resolved_model_path = _resolve_model_path(model_path)
    cache_key = os.path.abspath(resolved_model_path)
    if cache_key not in _MODEL_CACHE:
        metadata = load_metadata(_resolve_metadata_path(resolved_model_path))
        model = load_model(resolved_model_path, metadata)
        _MODEL_CACHE[cache_key] = (model, metadata)
    model, metadata = _MODEL_CACHE[cache_key]
    return model, metadata, resolved_model_path


def _dedupe_domains(domains: List[str]) -> List[str]:
    normalized_domains = []
    seen = set()
    for domain in domains:
        normalized = normalize_domain(str(domain or ""))
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        normalized_domains.append(normalized)
    return normalized_domains


def predict_from_file(
    file_content: bytes,
    filename: str,
    model_path: Optional[str] = None,
    candidate_threshold: float = DEFAULT_CANDIDATE_THRESHOLD,
) -> Tuple[bytes, Dict[str, Any], Dict[str, Any]]:
    domains = read_domains_from_file(file_content, filename)
    return predict_from_domains(domains, filename, model_path, candidate_threshold)


def predict_from_domains(
    domains: List[str],
    source_label: Optional[str] = None,
    model_path: Optional[str] = None,
    candidate_threshold: float = DEFAULT_CANDIDATE_THRESHOLD,
) -> Tuple[bytes, Dict[str, Any], Dict[str, Any]]:
    clean_domains = _dedupe_domains(domains)
    model, metadata, resolved_model_path = _load_detector(model_path)
    scored_rows = _score_raw_domains(
        raw_domains=clean_domains,
        model=model,
        metadata=metadata,
        threshold=candidate_threshold,
        domain_field_name="domain",
    )

    candidates = [
        row for row in scored_rows
        if float(row.get("dga_like_score") or 0) >= candidate_threshold
    ]

    result_rows = []
    dga_rows = []
    for scored in scored_rows:
        domain = scored["domain"]
        score = float(scored.get("dga_like_score") or 0)
        candidate = score >= candidate_threshold
        row = {
            "域名": domain,
            "规范化域名": scored.get("normalized_domain") or normalize_domain(domain),
            "SLD": scored.get("model_input_text") or extract_sld(domain),
            "DGA_score": round(score, 6),
            "模型候选": "是" if candidate else "否",
            "预测标签": 1 if candidate else 0,
            "预测结果": "DGA-like" if candidate else "正常",
        }
        result_rows.append(row)
        if candidate:
            dga_rows.append(row)

    excel_content, statistics = _build_excel(result_rows, dga_rows, len(candidates))
    meta = {
        "source_label": source_label,
        "model_path": os.path.relpath(resolved_model_path, CURRENT_DIR),
        "candidate_threshold": candidate_threshold,
        "candidate_count": len(candidates),
    }
    return excel_content, statistics, meta


def _build_excel(
    result_rows: List[Dict[str, Any]],
    dga_rows: List[Dict[str, Any]],
    candidate_count: int,
) -> Tuple[bytes, Dict[str, Any]]:
    total = len(result_rows)
    dga_count = len(dga_rows)
    normal_count = total - dga_count
    dga_rate = dga_count / total * 100 if total else 0.0
    statistics = {
        "总域名数": total,
        "DGA候选数": candidate_count,
        "DGA域名数": dga_count,
        "正常域名数": normal_count,
        "DGA域名占比": f"{dga_rate:.2f}%",
    }
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        pd.DataFrame(result_rows).to_excel(writer, sheet_name="预测结果", index=False)
        pd.DataFrame(
            [{"统计项": key, "数值": value} for key, value in statistics.items()]
        ).to_excel(writer, sheet_name="统计信息", index=False)
        if dga_rows:
            pd.DataFrame(dga_rows).to_excel(writer, sheet_name="DGA域名列表", index=False)
    return output.getvalue(), statistics
