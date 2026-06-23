from __future__ import annotations

import io
import os
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from dga_binary_detector import (
    DEFAULT_BINARY_THRESHOLD,
    DEFAULT_MODEL_PATH as DEFAULT_BINARY_MODEL_PATH,
    get_model_thresholds,
    score_raw_domains,
)
from dga_features import normalize_domain, split_domain


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MODEL_PATH = DEFAULT_BINARY_MODEL_PATH
DEFAULT_CANDIDATE_THRESHOLD = float(os.getenv("DGA_CANDIDATE_THRESHOLD", str(DEFAULT_BINARY_THRESHOLD)))


def _resolve_model_path(model_path: Optional[str]) -> str:
    value = (model_path or "").strip()
    if not value:
        return DEFAULT_MODEL_PATH
    if os.path.isabs(value):
        resolved = value
    else:
        resolved = os.path.normpath(os.path.join(CURRENT_DIR, value))
    return resolved


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


def _read_domains_from_file(file_content: bytes, filename: str) -> List[str]:
    domains: List[str] = []
    file_ext = filename.split(".")[-1].lower() if "." in filename else ""
    try:
        if file_ext == "csv":
            df = pd.read_csv(io.BytesIO(file_content))
            if "domain" in df.columns:
                domains = df["domain"].dropna().astype(str).tolist()
            else:
                domains = df.iloc[:, 0].dropna().astype(str).tolist()
        elif file_ext == "xlsx":
            df = pd.read_excel(io.BytesIO(file_content))
            if "domain" in df.columns:
                domains = df["domain"].dropna().astype(str).tolist()
            else:
                domains = df.iloc[:, 0].dropna().astype(str).tolist()
        elif file_ext == "txt":
            content = file_content.decode("utf-8", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)
        else:
            raise ValueError(f"不支持的文件类型: {file_ext}")
    except Exception as exc:
        raise ValueError(f"读取DGA检测文件失败: {exc}") from exc
    return [domain for domain in domains if domain and str(domain).strip()]


def predict_from_file(
    file_content: bytes,
    filename: str,
    model_path: Optional[str] = None,
    candidate_threshold: float = DEFAULT_CANDIDATE_THRESHOLD,
) -> Tuple[bytes, Dict[str, Any], Dict[str, Any]]:
    domains = _read_domains_from_file(file_content, filename)
    return predict_from_domains(domains, filename, model_path, candidate_threshold)


def predict_from_domains(
    domains: List[str],
    source_label: Optional[str] = None,
    model_path: Optional[str] = None,
    candidate_threshold: float = DEFAULT_CANDIDATE_THRESHOLD,
) -> Tuple[bytes, Dict[str, Any], Dict[str, Any]]:
    clean_domains = _dedupe_domains(domains)
    resolved_model_path = _resolve_model_path(model_path)
    scored_rows = score_raw_domains(
        raw_domains=clean_domains,
        model_path=resolved_model_path,
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
            "SLD": scored.get("model_input_text") or split_domain(domain).sld,
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
        "algorithm": "dga_binary_detector",
        "thresholds": get_model_thresholds(resolved_model_path, threshold=candidate_threshold),
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
