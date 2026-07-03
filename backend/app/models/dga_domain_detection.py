from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pandas as pd

from dga_features import normalize_domain, split_domain
from dga_local_detector import (
    DEFAULT_DIRECT_HIGH_CONFIDENCE_THRESHOLD,
    DEFAULT_FAMILY_AUDIT,
    DEFAULT_FAMILY_CONFIDENCE_THRESHOLD,
    DEFAULT_FAMILY_INPUT_THRESHOLD,
    DEFAULT_FAMILY_MODEL,
    DEFAULT_MODEL,
    DgaDetector,
)


CURRENT_DIR = Path(__file__).resolve().parent
DEFAULT_PACKAGE_DIR = CURRENT_DIR / "saved_model" / "dga_detection_local_model"
DEFAULT_MODEL_PATH = DEFAULT_MODEL
DEFAULT_DIRECT_THRESHOLD = DEFAULT_DIRECT_HIGH_CONFIDENCE_THRESHOLD
DEFAULT_FAMILY_THRESHOLD = DEFAULT_FAMILY_INPUT_THRESHOLD
DEFAULT_FAMILY_CONFIDENCE = DEFAULT_FAMILY_CONFIDENCE_THRESHOLD
DEFAULT_UNCERTAIN_THRESHOLD = 0.70
_DETECTOR_CACHE: dict[tuple[str, str, str, float, float, float, float], DgaDetector] = {}
_DGA_RUNTIME_ENV = "DGA_RUNTIME_PYTHON"
_DGA_SUBPROCESS_ENV = "DGA_DETECTION_SUBPROCESS"


def _resolve_path(value: str | os.PathLike[str]) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = CURRENT_DIR / path
    return path.resolve()


def _resolve_model_resources(model_path: Optional[str]) -> tuple[Path, Path | None, Path | None, Path]:
    """Resolve a DB model_path into main model, family model, audit CSV and package directory."""

    if model_path and str(model_path).strip():
        resolved = _resolve_path(str(model_path).strip())
        if resolved.is_dir():
            package_dir = resolved
            main_model = package_dir / "models" / "model_dga_detector.joblib"
        else:
            main_model = resolved
            package_dir = (
                resolved.parent.parent
                if resolved.name == "model_dga_detector.joblib" and resolved.parent.name == "models"
                else DEFAULT_PACKAGE_DIR
            )
    else:
        package_dir = DEFAULT_PACKAGE_DIR
        main_model = DEFAULT_MODEL

    family_model = package_dir / "models" / "family_sequence_gru_public_sources_user_approved" / "model_dga_family_sequence_gru.pt"
    family_audit = (
        package_dir
        / "data"
        / "holdout"
        / "family_attribution_audit_sequence_gru_default_threshold_0p98"
        / "family_attribution_audit_by_family.csv"
    )
    if not family_model.exists() and DEFAULT_FAMILY_MODEL.exists():
        family_model = DEFAULT_FAMILY_MODEL
    if not family_audit.exists() and DEFAULT_FAMILY_AUDIT.exists():
        family_audit = DEFAULT_FAMILY_AUDIT

    return (
        main_model,
        family_model if family_model.exists() else None,
        family_audit if family_audit.exists() else None,
        package_dir,
    )


def _get_detector(
    *,
    model_path: Path,
    family_model_path: Path | None,
    family_audit_path: Path | None,
    direct_threshold: float,
    family_input_threshold: float,
    family_confidence_threshold: float,
    uncertain_threshold: float,
) -> DgaDetector:
    cache_key = (
        str(model_path),
        str(family_model_path or ""),
        str(family_audit_path or ""),
        float(direct_threshold),
        float(family_input_threshold),
        float(family_confidence_threshold),
        float(uncertain_threshold),
    )
    if cache_key not in _DETECTOR_CACHE:
        _DETECTOR_CACHE[cache_key] = DgaDetector(
            model_path,
            family_model_path=family_model_path,
            family_audit_path=family_audit_path,
            high_threshold=direct_threshold,
            suspicious_threshold=family_input_threshold,
            uncertain_threshold=uncertain_threshold,
            family_input_threshold=family_input_threshold,
            family_confidence_threshold=family_confidence_threshold,
            promote_family_attribution_to_high_confidence=True,
        )
    return _DETECTOR_CACHE[cache_key]


def _dedupe_domains(domains: Sequence[str]) -> List[str]:
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
            domains = (
                df["domain"].dropna().astype(str).tolist()
                if "domain" in df.columns
                else df.iloc[:, 0].dropna().astype(str).tolist()
            )
        elif file_ext == "xlsx":
            df = pd.read_excel(io.BytesIO(file_content))
            domains = (
                df["domain"].dropna().astype(str).tolist()
                if "domain" in df.columns
                else df.iloc[:, 0].dropna().astype(str).tolist()
            )
        elif file_ext == "txt":
            content = file_content.decode("utf-8", errors="ignore")
            domains = [
                line.strip()
                for line in content.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        else:
            raise ValueError(f"不支持的文件类型: {file_ext}")
    except Exception as exc:
        raise ValueError(f"读取DGA检测文件失败: {exc}") from exc
    return [domain for domain in domains if domain and str(domain).strip()]


def predict_from_file(
    file_content: bytes,
    filename: str,
    model_path: Optional[str] = None,
    candidate_threshold: float = DEFAULT_FAMILY_THRESHOLD,
) -> Tuple[bytes, Dict[str, Any], Dict[str, Any]]:
    domains = _read_domains_from_file(file_content, filename)
    return predict_from_domains(domains, filename, model_path, candidate_threshold)


def predict_from_domains(
    domains: List[str],
    source_label: Optional[str] = None,
    model_path: Optional[str] = None,
    candidate_threshold: float = DEFAULT_FAMILY_THRESHOLD,
) -> Tuple[bytes, Dict[str, Any], Dict[str, Any]]:
    family_input_threshold = (
        DEFAULT_FAMILY_THRESHOLD if candidate_threshold is None else float(candidate_threshold)
    )
    if _should_delegate_to_dga_runtime():
        return _predict_from_domains_with_dga_runtime(
            domains,
            source_label,
            model_path,
            family_input_threshold,
        )

    direct_threshold = DEFAULT_DIRECT_THRESHOLD
    family_confidence_threshold = DEFAULT_FAMILY_CONFIDENCE

    clean_domains = _dedupe_domains(domains)
    main_model, family_model, family_audit, package_dir = _resolve_model_resources(model_path)
    detector = _get_detector(
        model_path=main_model,
        family_model_path=family_model,
        family_audit_path=family_audit,
        direct_threshold=direct_threshold,
        family_input_threshold=family_input_threshold,
        family_confidence_threshold=family_confidence_threshold,
        uncertain_threshold=DEFAULT_UNCERTAIN_THRESHOLD,
    )
    scored_rows = detector.predict(clean_domains, include_debug=True)

    result_rows: list[dict[str, Any]] = []
    dga_rows: list[dict[str, Any]] = []
    risk_records: list[dict[str, Any]] = []
    for result in scored_rows:
        row = _build_result_row(
            result,
            direct_threshold=direct_threshold,
            family_input_threshold=family_input_threshold,
        )
        result_rows.append(row)
        if row["预测标签"] == 1:
            dga_rows.append(row)
            risk_records.append(_build_risk_record(row))

    dga_rows = _sort_dga_rows(dga_rows)
    result_rows = _sort_result_rows(result_rows)
    excel_content, statistics = _build_excel(
        result_rows,
        dga_rows,
        family_input_threshold=family_input_threshold,
        direct_threshold=direct_threshold,
    )
    meta = {
        "source_label": source_label,
        "algorithm": "dga_local_detector_with_sequence_gru_family_attribution",
        "model_path": _safe_relative_path(main_model),
        "package_dir": _safe_relative_path(package_dir),
        "family_model_path": _safe_relative_path(family_model) if family_model else None,
        "family_audit_path": _safe_relative_path(family_audit) if family_audit else None,
        "direct_high_confidence_threshold": direct_threshold,
        "family_input_threshold": family_input_threshold,
        "family_confidence_threshold": family_confidence_threshold,
        "show_concrete_family_only_when_status": "usable",
        "high_confidence_policy": _policy_text(
            direct_threshold=direct_threshold,
            family_input_threshold=family_input_threshold,
        ),
        "high_confidence_count": len(dga_rows),
        "candidate_count": sum(1 for row in result_rows if _safe_float(row.get("DGA_score")) >= family_input_threshold),
        "family_attributed_count": sum(1 for row in dga_rows if row.get("家族归因状态") == "usable"),
        "risk_records": risk_records,
    }
    return excel_content, statistics, meta


def _should_delegate_to_dga_runtime() -> bool:
    if os.environ.get(_DGA_SUBPROCESS_ENV) == "1":
        return False
    runtime_python = os.environ.get(_DGA_RUNTIME_ENV, "").strip()
    if not runtime_python:
        return False
    try:
        runtime_path = Path(runtime_python).expanduser().absolute()
        current_path = Path(sys.executable).expanduser().absolute()
    except Exception:
        return False
    return runtime_path.exists() and runtime_path != current_path


def _predict_from_domains_with_dga_runtime(
    domains: Sequence[str],
    source_label: Optional[str],
    model_path: Optional[str],
    candidate_threshold: float,
) -> Tuple[bytes, Dict[str, Any], Dict[str, Any]]:
    runtime_python = os.environ[_DGA_RUNTIME_ENV].strip()
    with tempfile.TemporaryDirectory(prefix="apthunter_dga_") as temp_dir:
        temp_path = Path(temp_dir)
        input_path = temp_path / "input.json"
        excel_path = temp_path / "result.xlsx"
        payload = {
            "domains": list(domains),
            "source_label": source_label,
            "model_path": model_path,
            "candidate_threshold": candidate_threshold,
            "excel_path": str(excel_path),
        }
        input_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        env = dict(os.environ)
        env[_DGA_SUBPROCESS_ENV] = "1"
        completed = subprocess.run(
            [runtime_python, str(Path(__file__).resolve()), "--runtime-predict", str(input_path)],
            cwd=str(CURRENT_DIR),
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                "DGA runtime scoring failed: "
                f"{(completed.stderr or completed.stdout or '').strip()}"
            )
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        if not lines:
            raise RuntimeError("DGA runtime scoring failed: empty runtime response")
        try:
            result_payload = json.loads(lines[-1])
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "DGA runtime scoring failed: invalid runtime response "
                f"{completed.stdout.strip()}"
            ) from exc
        if not excel_path.exists():
            raise RuntimeError("DGA runtime scoring failed: result workbook was not created")
        return (
            excel_path.read_bytes(),
            dict(result_payload.get("statistics") or {}),
            dict(result_payload.get("meta") or {}),
        )


def _safe_relative_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(CURRENT_DIR))
    except Exception:
        return str(path)


def _safe_float(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _format_score(value: object, digits: int = 6) -> str:
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return ""


def _format_threshold(value: float) -> str:
    return f"{float(value):.2f}".rstrip("0").rstrip(".")


def _policy_text(*, direct_threshold: float, family_input_threshold: float) -> str:
    return (
        f"dga_score >= {_format_threshold(direct_threshold)} or "
        f"dga_score >= {_format_threshold(family_input_threshold)} with usable family attribution"
    )


def _policy_text_cn(*, direct_threshold: float, family_input_threshold: float) -> str:
    return (
        f"DGA分数>={_format_threshold(direct_threshold)}，或"
        f"DGA分数>={_format_threshold(family_input_threshold)}且家族识别可展示"
    )


def _build_result_row(
    result: dict[str, str],
    *,
    direct_threshold: float,
    family_input_threshold: float,
) -> dict[str, Any]:
    domain = result.get("domain") or ""
    score = _safe_float(result.get("dga_score"))
    family = result.get("predicted_family") or ""
    family_status = result.get("family_attribution_status") or ""
    high_confidence = result.get("dga_label") == "high_confidence_dga"
    family_promoted = (
        high_confidence
        and score < direct_threshold
        and score >= family_input_threshold
        and family_status == "usable"
        and family not in {"", "unknown_family", "possible_family"}
    )
    if high_confidence and score >= direct_threshold:
        hit_type = "主模型高置信"
    elif family_promoted:
        hit_type = "家族确认提升"
    elif score >= family_input_threshold:
        hit_type = "进入家族识别池"
    else:
        hit_type = ""

    if high_confidence:
        prediction = "高置信DGA"
    elif score >= family_input_threshold:
        prediction = "DGA候选"
    else:
        prediction = "正常"

    return {
        "域名": domain,
        "规范化域名": domain,
        "SLD": split_domain(domain).sld,
        "DGA_score": round(score, 6),
        "预测标签": 1 if high_confidence else 0,
        "预测结果": prediction,
        "模型候选": "是" if score >= family_input_threshold else "否",
        "命中方式": hit_type,
        "DGA家族": family or "unknown_family",
        "家族置信度": _format_score(result.get("family_confidence")),
        "家族归因状态": family_status,
        "Top1家族": result.get("top_family") or "",
        "Top1家族置信度": _format_score(result.get("top_family_confidence")),
        "家族Top3": result.get("family_top3") or "",
        "命中原因": result.get("reason") or "",
    }


def _build_risk_record(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "domain": row.get("域名"),
        "risk_score": _safe_float(row.get("DGA_score")),
        "risk_level": "high",
        "label": row.get("预测结果"),
        "family": row.get("DGA家族"),
        "family_confidence": _safe_float(row.get("家族置信度")),
        "family_attribution_status": row.get("家族归因状态"),
        "reason": row.get("命中方式") or row.get("命中原因"),
    }


def _dga_sort_key(row: dict[str, Any]) -> tuple[int, int, float, str]:
    family = str(row.get("DGA家族") or "")
    status = str(row.get("家族归因状态") or "")
    if status == "usable" and family not in {"", "unknown_family", "possible_family"}:
        family_rank = 0
    elif family == "possible_family" or status.startswith("caution_"):
        family_rank = 1
    else:
        family_rank = 2
    hit_rank = 0 if row.get("命中方式") == "主模型高置信" else 1
    return (family_rank, hit_rank, -_safe_float(row.get("DGA_score")), str(row.get("域名") or ""))


def _sort_dga_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=_dga_sort_key)


def _sort_result_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        rows,
        key=lambda row: (
            0 if row.get("预测标签") == 1 else 1,
            *_dga_sort_key(row),
        ),
    )


def _family_distribution_rows(dga_rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    counter = Counter(
        row.get("DGA家族")
        for row in dga_rows
        if row.get("家族归因状态") == "usable"
        and row.get("DGA家族") not in {"", "unknown_family", "possible_family"}
    )
    return [
        {"DGA家族": family, "高置信DGA数量": count}
        for family, count in counter.most_common()
    ]


def _build_excel(
    result_rows: List[Dict[str, Any]],
    dga_rows: List[Dict[str, Any]],
    *,
    family_input_threshold: float,
    direct_threshold: float,
) -> Tuple[bytes, Dict[str, Any]]:
    total = len(result_rows)
    dga_count = len(dga_rows)
    normal_count = total - dga_count
    candidate_count = sum(1 for row in result_rows if _safe_float(row.get("DGA_score")) >= family_input_threshold)
    direct_count = sum(1 for row in dga_rows if _safe_float(row.get("DGA_score")) >= direct_threshold)
    family_promoted_count = sum(1 for row in dga_rows if row.get("命中方式") == "家族确认提升")
    family_attributed_count = sum(1 for row in dga_rows if row.get("家族归因状态") == "usable")
    unique_family_count = len(
        {
            row.get("DGA家族")
            for row in dga_rows
            if row.get("家族归因状态") == "usable"
            and row.get("DGA家族") not in {"", "unknown_family", "possible_family"}
        }
    )
    dga_rate = dga_count / total * 100 if total else 0.0
    statistics = {
        "总域名数": total,
        "DGA候选数": candidate_count,
        "高置信DGA域名数": dga_count,
        "DGA域名数": dga_count,
        "主模型高置信数": direct_count,
        "家族确认提升数": family_promoted_count,
        "识别出DGA家族的域名数": family_attributed_count,
        "识别出的DGA家族种类数": unique_family_count,
        "正常域名数": normal_count,
        "DGA域名占比": f"{dga_rate:.2f}%",
        "检测口径": _policy_text_cn(
            direct_threshold=direct_threshold,
            family_input_threshold=family_input_threshold,
        ),
    }
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        pd.DataFrame(result_rows).to_excel(writer, sheet_name="预测结果", index=False)
        pd.DataFrame(
            [{"统计项": key, "数值": value} for key, value in statistics.items()]
        ).to_excel(writer, sheet_name="统计信息", index=False)
        pd.DataFrame(dga_rows).to_excel(writer, sheet_name="DGA域名列表", index=False)
        pd.DataFrame(_family_distribution_rows(dga_rows)).to_excel(
            writer,
            sheet_name="DGA家族统计",
            index=False,
        )
    return output.getvalue(), statistics


def _run_runtime_predict(input_path: str) -> int:
    payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
    excel_content, statistics, meta = predict_from_domains(
        payload.get("domains") or [],
        payload.get("source_label"),
        payload.get("model_path"),
        candidate_threshold=payload.get("candidate_threshold", DEFAULT_FAMILY_THRESHOLD),
    )
    excel_path = Path(payload["excel_path"])
    excel_path.write_bytes(excel_content)
    print(json.dumps({"statistics": statistics, "meta": meta}, ensure_ascii=False))
    return 0


def _main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if len(args) == 2 and args[0] == "--runtime-predict":
        return _run_runtime_predict(args[1])
    raise SystemExit("usage: dga_domain_detection.py --runtime-predict INPUT_JSON")


if __name__ == "__main__":
    raise SystemExit(_main())
