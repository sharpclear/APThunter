from __future__ import annotations

import io
import tempfile
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

from .candidate_recall import load_keywords as load_recall_keywords
from .candidate_recall import recall_candidates
from .feature_extract import load_keywords as load_feature_keywords
from .normalize import normalize_domain
from .official_alias import build_official_alias_groups
from .predict import (
    DEFAULT_MIN_SCORE,
    OUTPUT_COLUMNS,
    add_explanation_columns,
    add_model_scores,
    add_unique_candidate_rank_columns,
    ensure_prediction_pair_columns,
    extract_prediction_features,
    target_subtype_label,
    target_tier_label,
    write_prediction_report,
    write_prediction_word_report,
    write_unique_candidate_output,
)
from .target_profile import build_target_profiles, load_positive_threshold, load_token_policy


PACKAGE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = PACKAGE_DIR / "configs"
MODEL_DIR = PACKAGE_DIR / "models"
DATA_DIR = PACKAGE_DIR / "data"

KEYWORDS_PATH = CONFIG_DIR / "keywords.yaml"
TOKEN_POLICY_PATH = CONFIG_DIR / "token_policy.yaml"
THRESHOLDS_PATH = CONFIG_DIR / "thresholds.yaml"
HISTORY_PAIRS_PATH = DATA_DIR / "labeled_pairs_with_categories.csv"
MANUAL_REVIEW_PATH = DATA_DIR / "manual_review_labels.csv"

RESULT_COLUMNS = [
    "仿冒域名",
    "官方域名",
    "公司名称",
    "单位类型",
    "单位小类",
    "相似度",
    "匹配类型",
    "风险等级",
    "命中原因",
    "LLM研判标签",
    "LLM研判分数",
    "研判原因",
    "LLM处置结果",
    "关键特征",
]

RISK_LEVEL_LABELS = {
    "high": "高",
    "medium": "中",
    "low": "低",
}

CATEGORY_LABELS = {
    "brand_combo": "品牌组合",
    "service_entry": "业务入口仿冒",
    "prefix_suffix": "前后缀仿冒",
    "typo": "拼写变体",
    "confusable": "视觉混淆",
    "hyphenation": "连字符变体",
    "tld_replace": "后缀替换",
    "subdomain_deception": "子域名欺骗",
    "template_reuse": "历史模板复用",
    "pinyin_abbr": "拼音缩写",
    "other_suspicious": "其他可疑",
}


def detect_impersonation_domains(
    official_domains: Iterable[Any],
    detection_domains: Iterable[Any],
    similarity_threshold: float | None = None,
    return_scored: bool = False,
) -> tuple[pd.DataFrame, dict[str, Any]] | tuple[pd.DataFrame, dict[str, Any], pd.DataFrame]:
    official_rows = _coerce_official_domains(official_domains)
    raw_detection_domains = list(detection_domains or [])
    candidate_domains = _coerce_detection_domains(raw_detection_domains)

    if not official_rows:
        raise ValueError("官方域名列表中没有有效域名")
    if not candidate_domains:
        result = _empty_result()
        statistics = _build_statistics(len(raw_detection_domains), 0, 0, target_count=len(official_rows))
        if return_scored:
            return result, statistics, _empty_scored_result()
        return result, statistics

    whitelist = pd.DataFrame(official_rows)
    if "target_tier" not in whitelist.columns:
        whitelist["target_tier"] = ""
    token_policy = load_token_policy(TOKEN_POLICY_PATH, KEYWORDS_PATH)
    profiles = build_target_profiles(
        whitelist,
        token_policy=token_policy,
        enough_positive_min=load_positive_threshold(THRESHOLDS_PATH),
    )
    profiles = profiles.drop_duplicates("target_domain", keep="first").reset_index(drop=True)
    if profiles.empty:
        raise ValueError("官方域名列表中没有可构建目标画像的域名")

    domain_frame = pd.DataFrame({"domain": candidate_domains})
    recall_keywords = load_recall_keywords(KEYWORDS_PATH)
    recalled = recall_candidates(
        domain_frame,
        profiles,
        domain_col="domain",
        keywords=recall_keywords,
    )
    if recalled.empty:
        result = _empty_result()
        statistics = _build_statistics(
            len(raw_detection_domains),
            0,
            0,
            target_count=len(profiles),
        )
        if return_scored:
            return result, statistics, _empty_scored_result()
        return result, statistics

    pairs = ensure_prediction_pair_columns(recalled, profiles)
    feature_keywords = load_feature_keywords(KEYWORDS_PATH)
    features, _ = extract_prediction_features(
        pairs,
        keywords=feature_keywords,
        history_pairs=HISTORY_PAIRS_PATH,
    )
    alias_groups = build_official_alias_groups(
        whitelist,
        profiles,
        weak_tokens=token_policy["weak_target_tokens"],
        generic_tokens=token_policy["generic_medium_target_tokens"],
    )
    scored, category_thresholds = add_model_scores(
        features,
        MODEL_DIR,
        manual_review_path=MANUAL_REVIEW_PATH,
        alias_groups_path=alias_groups,
    )
    scored = add_explanation_columns(scored, category_thresholds, feature_keywords)

    min_score = _normalize_threshold(similarity_threshold)
    selected = scored[
        (scored["final_score"] >= min_score) & (scored["risk_level"] != "ignore")
    ].copy()
    if not selected.empty:
        ranked = add_unique_candidate_rank_columns(selected)
        selected = (
            ranked.sort_values(
                [
                    "final_score",
                    "_unique_recall_priority",
                    "_unique_contains_target",
                    "_unique_cloud_prefix_confusable",
                    "rule_score",
                    "svm_score",
                ],
                ascending=[False, False, False, False, False, False],
            )
            .drop_duplicates("candidate_domain", keep="first")
            .drop(columns=[column for column in ranked.columns if column.startswith("_unique_")])
            .reset_index(drop=True)
        )
    else:
        selected = selected.reset_index(drop=True)
    result = _build_result_dataframe(selected)
    statistics = _build_statistics(
        len(raw_detection_domains),
        len(result),
        len(recalled),
        target_count=len(profiles),
        scored_count=len(scored),
    )
    if return_scored:
        return result, statistics, selected
    return result, statistics


def predict_from_domains(
    official_domains: Iterable[Any],
    detection_domains: Iterable[Any],
    similarity_threshold: float | None = None,
) -> tuple[bytes, dict[str, Any]]:
    result, statistics = detect_impersonation_domains(
        official_domains,
        detection_domains,
        similarity_threshold=similarity_threshold,
    )
    return _build_result_excel(result, statistics), statistics


def predict_from_domains_with_report(
    official_domains: Iterable[Any],
    detection_domains: Iterable[Any],
    similarity_threshold: float | None = None,
) -> tuple[bytes, dict[str, Any], bytes]:
    result, statistics, scored_result = detect_impersonation_domains(
        official_domains,
        detection_domains,
        similarity_threshold=similarity_threshold,
        return_scored=True,
    )
    excel_content = _build_result_excel(result, statistics)
    report_content = _build_word_report(scored_result, statistics)
    return excel_content, statistics, report_content


def _coerce_official_domains(official_domains: Iterable[Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in official_domains or []:
        company = ""
        domain = ""
        unit_type = ""
        unit_subtype = ""
        unit_subtype_label = ""
        if isinstance(item, dict):
            company = (
                item.get("单位名称")
                or item.get("公司名称")
                or item.get("target_name")
                or item.get("company")
                or item.get("organization")
                or ""
            )
            domain = (
                item.get("官方域名")
                or item.get("目标域名")
                or item.get("域名")
                or item.get("target_domain")
                or item.get("domain")
                or ""
            )
            unit_type = (
                item.get("单位类型")
                or item.get("官方域名单位类型")
                or item.get("机构类型")
                or item.get("target_tier")
                or item.get("target_type")
                or item.get("matched_target_type")
                or ""
            )
            unit_subtype = (
                item.get("单位小类")
                or item.get("单位子类型")
                or item.get("官方域名单位小类")
                or item.get("target_subtype")
                or ""
            )
            unit_subtype_label = (
                item.get("单位小类名称")
                or item.get("单位子类型名称")
                or item.get("matched_target_subtype")
                or item.get("target_subtype_label")
                or ""
            )
        elif isinstance(item, (list, tuple)):
            if len(item) >= 2:
                company, domain = item[0], item[1]
                if len(item) >= 3:
                    unit_type = item[2]
                if len(item) >= 4:
                    unit_subtype = item[3]
                if len(item) >= 5:
                    unit_subtype_label = item[4]
            elif item:
                domain = item[0]
        else:
            domain = item

        normalized = normalize_domain(domain).get("normalized_domain", "")
        if normalized and normalized not in seen:
            seen.add(normalized)
            rows.append(
                {
                    "target_name": str(company or "").strip(),
                    "target_domain": normalized,
                    "target_tier": str(unit_type or "").strip(),
                    "target_subtype": str(unit_subtype or "").strip(),
                    "target_subtype_label": str(unit_subtype_label or "").strip(),
                }
            )
    return rows


def _coerce_detection_domains(domains: Iterable[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for raw_domain in domains:
        domain = normalize_domain(raw_domain).get("normalized_domain", "")
        if domain and domain not in seen:
            seen.add(domain)
            result.append(domain)
    return result


def _normalize_threshold(value: float | None) -> float:
    if value is None:
        return DEFAULT_MIN_SCORE
    try:
        return min(1.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        return DEFAULT_MIN_SCORE


def _empty_result() -> pd.DataFrame:
    return pd.DataFrame(columns=RESULT_COLUMNS)


def _empty_scored_result() -> pd.DataFrame:
    return pd.DataFrame(columns=OUTPUT_COLUMNS)


def _build_result_dataframe(scored: pd.DataFrame) -> pd.DataFrame:
    if scored.empty:
        return _empty_result()

    rows = []
    for row in scored.to_dict("records"):
        risk_level = str(row.get("risk_level") or "low")
        final_score = float(row.get("final_score") or 0.0)
        reason = str(row.get("reason") or "")
        category = str(row.get("main_category") or "other_suspicious")
        all_categories = str(row.get("all_categories") or "").strip()
        category_values = [
            value.strip()
            for value in all_categories.split("|")
            if value and value.strip()
        ] or [category]
        match_type = "\\".join(
            dict.fromkeys(CATEGORY_LABELS.get(value, value) for value in category_values)
        )
        unit_type = row.get("matched_target_type") or target_tier_label(
            row.get("target_tier") or row.get("target_tier_x") or row.get("target_tier_y")
        )
        unit_subtype = row.get("matched_target_subtype") or target_subtype_label(
            row.get("target_subtype") or row.get("target_subtype_x") or row.get("target_subtype_y"),
            row.get("target_subtype_label")
            or row.get("target_subtype_label_x")
            or row.get("target_subtype_label_y")
            or "",
        )
        rows.append(
            {
                "仿冒域名": row.get("candidate_domain", ""),
                "官方域名": row.get("target_domain", ""),
                "公司名称": row.get("target_name", ""),
                "单位类型": unit_type,
                "单位小类": unit_subtype,
                "相似度": f"{final_score:.4f}",
                "匹配类型": match_type,
                "风险等级": RISK_LEVEL_LABELS.get(risk_level, risk_level),
                "命中原因": reason,
                "LLM研判标签": f"V1本地模型-{risk_level}",
                "LLM研判分数": f"{final_score:.4f}",
                "研判原因": reason,
                "LLM处置结果": (
                    "保留高危告警" if risk_level == "high" else "保留人工复核"
                ),
                "关键特征": row.get("matched_features", ""),
            }
        )
    return pd.DataFrame(rows, columns=RESULT_COLUMNS)


def _build_word_report(scored: pd.DataFrame, statistics: dict[str, Any]) -> bytes:
    with tempfile.TemporaryDirectory(prefix="impersonation_v1_report_") as temp_dir:
        report_dir = Path(temp_dir)
        full_output = report_dir / "suspicious_domains_result.csv"
        unique_output = report_dir / "suspicious_domains_result_unique_candidates.csv"
        markdown_output = report_dir / "prediction_report.md"
        word_output = report_dir / "prediction_report.docx"
        high_value_review_output = report_dir / "review_high_value_targets.csv"

        report_df = scored.copy() if scored is not None else _empty_scored_result()
        if report_df.empty:
            report_df = _empty_scored_result()
        report_df.to_csv(full_output, index=False, encoding="utf-8-sig")
        unique_df = write_unique_candidate_output(report_df, unique_output)
        pd.DataFrame(columns=OUTPUT_COLUMNS).to_csv(
            high_value_review_output,
            index=False,
            encoding="utf-8-sig",
        )

        summary = {
            "target_count": int(statistics.get("target_count", 0) or 0),
            "input_domain_count": int(statistics.get("total", 0) or 0),
            "recalled_count": int(statistics.get("算法候选数", 0) or 0),
            "scored_count": int(statistics.get("scored_count", len(report_df)) or 0),
            "output_count": int(len(report_df)),
            "unique_candidate_count": int(len(unique_df)),
            "high_value_review_count": 0,
            "risk_level_counts": (
                report_df["risk_level"].value_counts().to_dict()
                if "risk_level" in report_df.columns
                else {}
            ),
            "target_type_counts": (
                report_df["matched_target_type"].value_counts().to_dict()
                if "matched_target_type" in report_df.columns
                else {}
            ),
            "output": str(full_output),
            "unique_output": str(unique_output),
            "report_output": str(markdown_output),
            "word_report_output": str(word_output),
            "high_value_review_output": str(high_value_review_output),
        }
        write_prediction_report(summary, markdown_output)
        write_prediction_word_report(summary, word_output)
        return word_output.read_bytes()


def _build_statistics(
    total: int,
    impersonation: int,
    recalled: int,
    target_count: int = 0,
    scored_count: int = 0,
) -> dict[str, Any]:
    benign = max(total - impersonation, 0)
    impersonation_rate = impersonation / total * 100 if total else 0.0
    return {
        "total": total,
        "impersonation": impersonation,
        "benign": benign,
        "impersonation_rate": impersonation_rate,
        "target_count": target_count,
        "scored_count": scored_count,
        "总域名数": total,
        "受保护目标数": target_count,
        "算法候选数": recalled,
        "模型评分候选数": scored_count,
        "仿冒域名数": impersonation,
        "正常域名数": benign,
        "仿冒域名占比": f"{impersonation_rate:.2f}%",
        "LLM研判状态": "未使用（V1本地模型）",
        "LLM研判模型": "ImpersonationDomainDetection/V1",
        "LLM已研判数": 0,
    }


def _build_result_excel(result: pd.DataFrame, statistics: dict[str, Any]) -> bytes:
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        result.to_excel(writer, sheet_name="检测结果", index=False)
        pd.DataFrame(
            {
                "统计项": [
                    "总域名数",
                    "受保护目标数",
                    "算法候选数",
                    "模型评分候选数",
                    "仿冒域名数",
                    "正常域名数",
                    "仿冒域名占比",
                    "LLM研判状态",
                    "LLM研判模型",
                    "LLM已研判数",
                ],
                "数值": [
                    statistics["total"],
                    statistics.get("target_count", 0),
                    statistics["算法候选数"],
                    statistics.get("scored_count", 0),
                    statistics["impersonation"],
                    statistics["benign"],
                    f"{statistics['impersonation_rate']:.2f}%",
                    statistics["LLM研判状态"],
                    statistics["LLM研判模型"],
                    statistics["LLM已研判数"],
                ],
            }
        ).to_excel(writer, sheet_name="统计信息", index=False)
        result.to_excel(writer, sheet_name="仿冒域名列表", index=False)
    return output.getvalue()
