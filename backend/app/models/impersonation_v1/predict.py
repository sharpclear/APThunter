from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
import pandas as pd

try:
    from .candidate_recall import load_keywords as load_recall_keywords
    from .candidate_recall import recall_candidates
    from .feature_extract import extract_features, load_keywords as load_feature_keywords
    from .normalize import normalize_domain
    from .output_paths import resolve_output_file
    from .target_profile import PROFILE_FIELDS, build_target_profiles, load_token_policy, read_whitelist
except ImportError:  # pragma: no cover - used when run as python predict.py
    from candidate_recall import load_keywords as load_recall_keywords
    from candidate_recall import recall_candidates
    from feature_extract import extract_features, load_keywords as load_feature_keywords
    from normalize import normalize_domain
    from output_paths import resolve_output_file
    from target_profile import PROFILE_FIELDS, build_target_profiles, load_token_policy, read_whitelist


READ_ENCODINGS = ("utf-8-sig", "utf-8", "gbk")
PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_MIN_SCORE = 0.45
DEFAULT_TOP_K_PER_TARGET = 100
DEFAULT_HISTORY_PAIRS = PACKAGE_DIR / "data/labeled_pairs_with_categories.csv"
DEFAULT_MANUAL_REVIEW = PACKAGE_DIR / "data/manual_review_labels.csv"
DEFAULT_ALIAS_GROUPS = PACKAGE_DIR / "data/official_alias_groups.csv"
RISK_THRESHOLDS = {"high": 0.85, "medium": 0.65, "low": 0.45}
STRONG_RULE_FALLBACK_LOW = 0.45
STRONG_RULE_FALLBACK_MEDIUM = 0.65
STRONG_RULE_FALLBACK_HIGH = 0.85
STRONG_RULE_MODEL_SUPPORT = 0.50
STRONG_RULE_SVM_SUPPORT = 0.90
STRONG_RULE_HIGH_MODEL_SUPPORT = 0.65
STRONG_RULE_HIGH_SVM_SUPPORT = 0.93
HIGH_CONFIDENCE_RISK_WORDS = {
    "login",
    "logon",
    "signin",
    "verify",
    "secure",
    "security",
    "account",
    "auth",
    "sso",
    "vpn",
    "password",
    "reset",
    "recover",
    "oauth",
    "token",
    "otp",
}
HIGH_VALUE_FINANCE_CONTEXT_WORDS = {
    "auth",
    "authenticate",
    "authentication",
    "bank",
    "banking",
    "card",
    "confirm",
    "confirmation",
    "credit",
    "kyc",
    "login",
    "otp",
    "payment",
    "secure",
    "verify",
    "verification",
    "validate",
    "validation",
}
FALLBACK_GENERIC_TOKENS = {
    "blockchain",
    "direct",
    "energy",
    "football",
    "government",
    "investor",
    "privacy",
    "processing",
    "register",
    "signal",
}
HIGH_VALUE_REVIEW_TOP_N = 500
HIGH_VALUE_GENERIC_REVIEW_RESERVED_TOP_N = 100
HIGH_VALUE_GENERIC_REVIEW_MIN_SCORE = 2.0
HIGH_VALUE_GENERIC_TIER_TERMS = {
    "gov": {
        "gov",
        "government",
        "justice",
        "court",
        "tax",
        "police",
        "customs",
        "passport",
        "immigration",
        "state",
        "national",
        "public",
        "ministry",
        "official",
    },
    "edu": {
        "edu",
        "education",
        "university",
        "college",
        "school",
        "campus",
        "student",
        "academy",
        "institute",
    },
    "finance": {
        "bank",
        "banking",
        "finance",
        "financial",
        "pay",
        "payment",
        "wallet",
        "card",
        "loan",
        "credit",
        "securities",
        "insurance",
        "fund",
    },
}
HIGH_VALUE_GENERIC_RISK_TERMS = HIGH_CONFIDENCE_RISK_WORDS | {
    "support",
    "service",
    "portal",
    "notice",
    "update",
    "mail",
    "app",
    "id",
}
HIGH_VALUE_SUSPICIOUS_TLDS = {
    "top",
    "xyz",
    "vip",
    "shop",
    "site",
    "online",
    "info",
    "live",
    "click",
    "work",
    "cc",
    "icu",
    "cfd",
    "mom",
}
CLOUD_PREFIX_SUFFIX = "cloud"
CLOUD_PREFIX_CONFUSABLE_PAIRS = {
    frozenset(("i", "l")),
    frozenset(("i", "1")),
    frozenset(("l", "1")),
}
OUTPUT_COLUMNS = [
    "candidate_domain",
    "matched_target_name",
    "matched_target_domain",
    "matched_target_type",
    "matched_target_subtype",
    "target_tier",
    "target_subtype",
    "target_type_source",
    "final_score",
    "risk_level",
    "main_category",
    "all_categories",
    "matched_features",
    "rule_score",
    "lgbm_binary_score",
    "brand_service_score",
    "typo_confusable_score",
    "svm_score",
    "reason",
]
HIGH_VALUE_REVIEW_COLUMNS = [
    "candidate_domain",
    "matched_target_name",
    "matched_target_domain",
    "target_tier",
    "target_subtype",
    "matched_target_subtype",
    "possible_tier",
    "is_high_value_target",
    "target_has_enough_positive",
    "final_score",
    "risk_level",
    "main_category",
    "matched_token",
    "matched_token_type",
    "recall_reason",
    "matched_features",
    "rule_score",
    "lgbm_binary_score",
    "brand_service_score",
    "typo_confusable_score",
    "svm_score",
    "high_value_review_score",
    "high_value_pattern",
    "target_match_confidence",
    "high_value_review_type",
    "review_reason",
    "suggested_action",
    "reason",
]
CATEGORY_SCORE_COLUMNS = {
    "brand_combo": "brand_combo_score",
    "service_entry": "service_entry_score",
    "prefix_suffix": "prefix_suffix_score",
    "typo": "typo_score",
    "confusable": "confusable_score",
    "hyphenation": "hyphenation_score",
    "tld_replace": "tld_replace_score",
}
CATEGORY_MODEL_FILES = {
    "brand_combo": "lgbm_category_brand_combo.pkl",
    "service_entry": "lgbm_category_service_entry.pkl",
    "prefix_suffix": "lgbm_category_prefix_suffix.pkl",
}
RF_MODEL_FILES = {
    "typo": "rf_category_typo.pkl",
    "confusable": "rf_category_confusable.pkl",
    "hyphenation": "rf_category_hyphenation.pkl",
    "tld_replace": "rf_category_tld_replace.pkl",
}
RECALL_CATEGORY_MAP = {
    "confusable_match": "confusable",
    "spelling_variant_match": "typo",
    "transposition_match": "typo",
    "no_hyphen_match": "hyphenation",
    "subdomain_deception": "subdomain_deception",
    "tld_replace": "tld_replace",
    "risk_word_combo": "service_entry",
    "fuzzy_match": "typo",
}
CATEGORY_PRIORITY = [
    "service_entry",
    "prefix_suffix",
    "typo",
    "confusable",
    "subdomain_deception",
    "brand_combo",
    "tld_replace",
    "hyphenation",
    "pinyin_abbr",
    "template_reuse",
]
MAX_OUTPUT_CATEGORIES = 4
RULE_SERVICE_ENTRY_WORDS = HIGH_CONFIDENCE_RISK_WORDS | {
    "app",
    "contact",
    "help",
    "mail",
    "notice",
    "portal",
    "support",
    "update",
    "webmail",
}


def read_csv_with_fallback(path: str | Path) -> pd.DataFrame:
    input_path = Path(path)
    errors: list[str] = []
    for encoding in READ_ENCODINGS:
        try:
            return pd.read_csv(input_path, encoding=encoding, low_memory=False)
        except UnicodeDecodeError as exc:
            errors.append(f"{encoding}: {exc}")
    raise ValueError(f"failed to read {input_path}: {'; '.join(errors)}")


def load_targets(path: str | Path) -> pd.DataFrame:
    target_path = Path(path)
    raw = read_csv_with_fallback(target_path)
    if _looks_like_target_profiles(raw):
        profiles = raw.copy()
    else:
        profiles = build_target_profiles(read_whitelist(target_path))
    return profiles.reset_index(drop=True)


def _looks_like_target_profiles(df: pd.DataFrame) -> bool:
    required = {"target_domain", "target_sld", "target_suffix", "strong_tokens"}
    return required.issubset(set(df.columns))


def write_empty_output(output: str | Path) -> None:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(columns=OUTPUT_COLUMNS).to_csv(output_path, index=False, encoding="utf-8-sig")


def target_tier_label(value: Any) -> str:
    tier = str(value or "").strip().lower()
    return {
        "gov": "政府",
        "edu": "教育",
        "finance": "金融",
        "brand": "品牌",
        "cloud": "云服务",
        "ecommerce": "电商",
        "media": "媒体",
        "other": "其他",
    }.get(tier, "其他")


def target_subtype_label(value: Any, label: Any = "") -> str:
    explicit_label = str(label or "").strip()
    if explicit_label and explicit_label.lower() != "nan":
        return explicit_label
    subtype = str(value or "").strip().lower()
    return {
        "email": "邮箱服务",
        "social": "社交平台",
        "internet_company": "互联网公司",
        "developer": "开发者平台",
        "cloud_service": "云服务",
        "payment": "支付平台",
        "crypto": "加密货币",
        "banking": "银行金融",
        "financial_institution": "金融机构",
        "ecommerce": "电商零售",
        "game": "游戏娱乐",
        "travel": "旅游出行",
        "government": "政府机构",
        "education": "教育机构",
        "media": "媒体资讯",
        "other_brand": "其他品牌",
        "other": "其他",
    }.get(subtype, "其他")


def target_tier_label(value: Any) -> str:
    tier = str(value or "").strip().lower()
    return {
        "gov": "政府",
        "edu": "教育",
        "finance": "金融",
        "brand": "品牌",
        "cloud": "云服务",
        "ecommerce": "电商",
        "media": "媒体",
        "other": "其他",
    }.get(tier, "其他")


def target_subtype_label(value: Any, label: Any = "") -> str:
    explicit_label = str(label or "").strip()
    if explicit_label and explicit_label.lower() != "nan":
        return explicit_label
    subtype = str(value or "").strip().lower()
    return {
        "email": "邮箱服务",
        "social": "社交平台",
        "internet_company": "互联网公司",
        "developer": "开发者平台",
        "cloud_service": "云服务",
        "payment": "支付平台",
        "crypto": "加密货币",
        "banking": "银行金融",
        "financial_institution": "金融机构",
        "ecommerce": "电商零售",
        "game": "游戏娱乐",
        "travel": "旅游出行",
        "government": "政府机构",
        "education": "教育机构",
        "media": "媒体资讯",
        "other_brand": "其他品牌",
        "other": "其他",
    }.get(subtype, "其他")


def write_unique_candidate_output(output_df: pd.DataFrame, output: str | Path) -> pd.DataFrame:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_df.empty:
        unique_df = pd.DataFrame(columns=OUTPUT_COLUMNS)
    else:
        ranked = add_unique_candidate_rank_columns(output_df)
        unique_df = (
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
    unique_df.to_csv(output_path, index=False, encoding="utf-8-sig")
    return unique_df


def add_unique_candidate_rank_columns(output_df: pd.DataFrame) -> pd.DataFrame:
    result = output_df.copy()
    recall_reason = result.get("matched_features", pd.Series("", index=result.index)).fillna("").astype(str)
    result["_unique_contains_target"] = (
        recall_reason.str.contains("contains_target_sld", regex=False)
        | recall_reason.str.contains("contains_target_sld_confusable_norm", regex=False)
    ).astype(int)

    main_category = result.get("main_category", pd.Series("", index=result.index)).fillna("").astype(str)
    reason_priority = pd.Series(0, index=result.index, dtype=int)
    reason_priority = reason_priority.mask(recall_reason.str.contains("recall:risk_word_combo", regex=False), 50)
    reason_priority = reason_priority.mask(recall_reason.str.contains("recall:exact_match", regex=False), 45)
    reason_priority = reason_priority.mask(recall_reason.str.contains("recall:tld_replace", regex=False), 40)
    reason_priority = reason_priority.mask(recall_reason.str.contains("recall:confusable_match", regex=False), 35)
    reason_priority = reason_priority.mask(recall_reason.str.contains("recall:no_hyphen_match", regex=False), 30)
    reason_priority = reason_priority.mask(recall_reason.str.contains("recall:subdomain_deception", regex=False), 25)
    reason_priority = reason_priority.mask(recall_reason.str.contains("recall:spelling_variant_match", regex=False), 15)
    reason_priority = reason_priority.mask(recall_reason.str.contains("recall:fuzzy_match", regex=False), 12)
    reason_priority = reason_priority.mask(main_category.eq("service_entry"), reason_priority + 3)
    result["_unique_recall_priority"] = reason_priority
    result["_unique_cloud_prefix_confusable"] = result.apply(
        cloud_prefix_confusable_unique_priority,
        axis=1,
    )
    return result


def cloud_prefix_confusable_unique_priority(row: pd.Series) -> int:
    """Prefer iCloud-like targets when the candidate token is an l/i visual typo."""
    matched_features = text(row.get("matched_features")).lower()
    if "recall:spelling_variant_match" not in matched_features:
        return 0

    target_sld = text(normalize_domain(row.get("matched_target_domain", "")).get("sld_clean")).lower()
    if not target_sld.endswith(CLOUD_PREFIX_SUFFIX):
        return 0
    target_prefix = target_sld[: -len(CLOUD_PREFIX_SUFFIX)]
    if len(target_prefix) != 1:
        return 0

    candidate_sld = text(normalize_domain(row.get("candidate_domain", "")).get("sld_clean")).lower()
    candidate_tokens = [
        token
        for token in re.findall(r"[a-z0-9]+", candidate_sld)
        if len(token) == len(target_sld) and token.endswith(CLOUD_PREFIX_SUFFIX)
    ]
    for token in candidate_tokens:
        candidate_prefix = token[: -len(CLOUD_PREFIX_SUFFIX)]
        if candidate_prefix == target_prefix:
            return 30
        if frozenset((candidate_prefix, target_prefix)) in CLOUD_PREFIX_CONFUSABLE_PAIRS:
            return 20
    return 0


def write_prediction_report(summary: dict[str, Any], output: str | Path) -> None:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    risk_counts = summary.get("risk_level_counts", {}) or {}
    type_counts = summary.get("target_type_counts", {}) or {}
    lines = [
        "# Prediction Report",
        "",
        f"- targets: {summary.get('target_count', 0)}",
        f"- input domains: {summary.get('input_domain_count', 0)}",
        f"- recalled pairs: {summary.get('recalled_count', 0)}",
        f"- scored pairs: {summary.get('scored_count', 0)}",
        f"- output pairs: {summary.get('output_count', 0)}",
        f"- unique candidates: {summary.get('unique_candidate_count', 0)}",
        "",
        "## Risk Level Counts",
        *[f"- {level}: {count}" for level, count in sorted(risk_counts.items())],
        "",
        "## Target Type Counts",
        *[f"- {target_type}: {count}" for target_type, count in sorted(type_counts.items())],
        "",
        "## Files",
        f"- result: {summary.get('output', '')}",
        f"- unique candidates: {summary.get('unique_output', '')}",
        f"- high value review: {summary.get('high_value_review_output', '')}",
        "",
        "## Notes",
        "- Scores are based only on domain strings, target profiles, historical labels, and local models.",
        "- DNS, WHOIS, certificates, web content, search results, and LLM judgments are not used.",
    ]
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def ensure_prediction_pair_columns(pairs: pd.DataFrame, profiles: pd.DataFrame) -> pd.DataFrame:
    result = pairs.copy()
    result["label"] = 0
    result["sample_type"] = "predict"

    profile_columns = [
        column
        for column in [
            "target_domain",
            "target_registered_domain",
            "target_subdomain",
            "pinyin_full",
            "pinyin_initials",
            "is_high_value_target",
            "target_tier",
            "target_subtype",
            "target_subtype_label",
            "target_type_source",
            "target_has_enough_positive",
            "target_indicators",
        ]
        if column in profiles.columns
    ]
    if "target_domain" in profile_columns:
        merge_df = profiles[profile_columns].drop_duplicates("target_domain")
        result = result.merge(merge_df, on="target_domain", how="left", suffixes=("", "_profile"))
        for column in (
            "target_registered_domain",
            "target_subdomain",
            "target_subtype",
            "target_subtype_label",
            "target_type_source",
            "target_tier",
            "target_has_enough_positive",
            "target_indicators",
            "is_high_value_target",
        ):
            profile_column = f"{column}_profile"
            if profile_column in result.columns:
                result[column] = result[column].where(result[column].notna(), result[profile_column])
                result = result.drop(columns=[profile_column])

    for field in PROFILE_FIELDS:
        if field not in result.columns:
            result[field] = ""
    return result


def prepare_numeric_features(df: pd.DataFrame, feature_columns: Sequence[str]) -> pd.DataFrame:
    missing = [column for column in feature_columns if column not in df.columns]
    if missing:
        raise ValueError(f"missing model feature columns: {missing[:10]}")
    x = df.loc[:, list(feature_columns)].copy()
    for column in feature_columns:
        x[column] = pd.to_numeric(x[column], errors="coerce")
    return x.replace([np.inf, -np.inf], np.nan).fillna(0.0)


def predict_model_proba(model: Any, x: Any) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(x)
        classes = list(getattr(model, "classes_", []))
        if not classes and hasattr(model, "named_steps"):
            classes = list(getattr(model.named_steps.get("clf"), "classes_", []))
        if 1 in classes:
            return probabilities[:, classes.index(1)]
        if probabilities.ndim == 2 and probabilities.shape[1] > 1:
            return probabilities[:, 1]
        return np.zeros(len(x), dtype=float)
    if hasattr(model, "decision_function"):
        decision = np.asarray(model.decision_function(x), dtype=float)
        return 1.0 / (1.0 + np.exp(-decision))
    raise ValueError(f"model does not support predict_proba or decision_function: {type(model)}")


def load_model_payload(path: str | Path) -> dict[str, Any]:
    payload = joblib.load(path)
    if isinstance(payload, dict) and "model" in payload:
        return payload
    return {"model": payload}


def add_model_scores(
    features: pd.DataFrame,
    model_dir: str | Path,
    manual_review_path: str | Path | None = DEFAULT_MANUAL_REVIEW,
    alias_groups_path: str | Path | None = DEFAULT_ALIAS_GROUPS,
    disable_alias_guard: bool = False,
) -> tuple[pd.DataFrame, dict[str, float]]:
    model_path = Path(model_dir)
    result = features.copy()
    category_thresholds: dict[str, float] = {}

    binary_payload = load_model_payload(model_path / "lgbm_binary.pkl")
    binary_columns = binary_payload.get("feature_columns") or []
    result["lgbm_binary_score"] = predict_model_proba(
        binary_payload["model"],
        prepare_numeric_features(result, binary_columns),
    )

    for category, filename in CATEGORY_MODEL_FILES.items():
        payload = load_model_payload(model_path / filename)
        columns = payload.get("feature_columns") or binary_columns
        result[CATEGORY_SCORE_COLUMNS[category]] = predict_model_proba(
            payload["model"],
            prepare_numeric_features(result, columns),
        )
        category_thresholds[category] = float(payload.get("threshold") or 0.5)

    for category, filename in RF_MODEL_FILES.items():
        payload = load_model_payload(model_path / filename)
        columns = payload.get("feature_columns") or binary_columns
        result[CATEGORY_SCORE_COLUMNS[category]] = predict_model_proba(
            payload["model"],
            prepare_numeric_features(result, columns),
        )
        category_thresholds[category] = float(payload.get("threshold") or 0.5)

    svm_payload = load_model_payload(model_path / "svm_char_ngram.pkl")
    svm_text = build_svm_text(result, svm_payload)
    result["svm_score"] = predict_model_proba(svm_payload["model"], svm_text)

    result["brand_service_score"] = result[
        ["brand_combo_score", "service_entry_score", "prefix_suffix_score"]
    ].max(axis=1)
    result["typo_confusable_score"] = result[
        ["typo_score", "confusable_score", "hyphenation_score", "tld_replace_score"]
    ].max(axis=1)

    fusion_payload = load_model_payload(model_path / "fusion_model.pkl")
    fusion_columns = fusion_payload.get("feature_columns") or [
        "rule_score",
        "lgbm_binary_score",
        "brand_combo_score",
        "service_entry_score",
        "prefix_suffix_score",
        "typo_score",
        "confusable_score",
        "hyphenation_score",
        "tld_replace_score",
        "svm_score",
        "max_history_similarity",
        "hard_filter_pass",
    ]
    result["final_score"] = predict_model_proba(
        fusion_payload["model"],
        prepare_numeric_features(result, fusion_columns),
    )
    result = apply_strong_rule_fallback(result)
    risk_thresholds = fusion_payload.get("risk_thresholds") or RISK_THRESHOLDS
    result["risk_level"] = assign_risk_level(result["final_score"], risk_thresholds)
    result = apply_official_domain_guard(result)
    if not disable_alias_guard:
        result = apply_official_alias_guard(result, alias_groups_path)
    result = apply_manual_review_guard(result, manual_review_path)
    return result, category_thresholds


def build_svm_text(df: pd.DataFrame, payload: dict[str, Any]) -> pd.Series:
    text_columns = payload.get("text_columns") or ["candidate_sld", "target_sld"]
    candidate_col = text_columns[0] if text_columns else "candidate_sld"
    target_col = text_columns[1] if len(text_columns) > 1 else "target_sld"
    candidate = df[candidate_col].fillna("").astype(str).str.lower().str.strip()
    target = df[target_col].fillna("").astype(str).str.lower().str.strip()
    return candidate + " [SEP] " + target


def assign_risk_level(score: pd.Series | np.ndarray, thresholds: dict[str, float]) -> np.ndarray:
    values = np.asarray(score, dtype=float)
    return np.select(
        [
            values >= float(thresholds.get("high", 0.85)),
            values >= float(thresholds.get("medium", 0.65)),
            values >= float(thresholds.get("low", 0.45)),
        ],
        ["high", "medium", "low"],
        default="ignore",
    )


def apply_strong_rule_fallback(df: pd.DataFrame) -> pd.DataFrame:
    """Apply a conservative floor for strong, explainable brand-rule hits.

    The fallback is intentionally limited to strong target tokens that survived
    hard filtering and contain the target SLD. Medium/weak/generic tokens are
    not promoted here.
    """
    if df.empty:
        return df
    result = df.copy()
    rule_score = numeric_column(result, "rule_score")
    token_type = result.get("matched_token_type", pd.Series("", index=result.index)).fillna("").astype(str).str.lower()
    matched_token = result.get("matched_token", pd.Series("", index=result.index)).fillna("").astype(str).str.lower()
    contains_target = numeric_column(result, "contains_target_sld") == 1
    contains_target_confusable = numeric_column(result, "contains_target_sld_confusable_norm") == 1
    hard_filter = bool_column(result, "hard_filter_pass")
    target_sld = result.get("target_sld", pd.Series("", index=result.index)).fillna("").astype(str)
    target_sld_long = target_sld.str.len() >= 5
    blocked_tokens = load_fallback_block_tokens()
    blocked_generic_token = target_sld.str.lower().isin(blocked_tokens) | matched_token.isin(blocked_tokens)
    recall_reason = result.get("recall_reason", pd.Series("", index=result.index)).fillna("").astype(str).str.lower()
    spelling_variant_noise = spelling_variant_output_noise_series(result, recall_reason)
    typo_rule_evidence = recall_reason.isin(
        {"spelling_variant_match", "transposition_match", "fuzzy_match"}
    ) & matched_token.eq(target_sld.str.lower())
    strong_target_evidence = (
        contains_target
        | (contains_target_confusable & recall_reason.eq("confusable_match"))
        | typo_rule_evidence
    )

    strong_core = (
        token_type.eq("strong")
        & strong_target_evidence
        & hard_filter
        & target_sld_long
        & (rule_score >= 0.78)
        & ~blocked_generic_token
        & ~spelling_variant_noise
    )
    if not strong_core.any():
        result["strong_rule_fallback"] = 0
        result["strong_rule_fallback_floor"] = 0.0
        return result

    suffix_changed = numeric_column(result, "suffix_changed") == 1
    suspicious_tld = numeric_column(result, "is_suspicious_tld") == 1
    hyphenation = numeric_column(result, "hyphen_count") > 0
    digit = numeric_column(result, "digit_count") > 0
    visual = numeric_column(result, "has_digit_letter_confusion") == 1
    strong_risk_words = numeric_column(result, "strong_risk_word_count") > 0
    medium_or_weak_risk_words = (
        numeric_column(result, "medium_risk_word_count") + numeric_column(result, "weak_risk_word_count")
    ) > 0
    risk_words = strong_risk_words | medium_or_weak_risk_words
    candidate_text = (
        result.get("candidate_sld", result.get("candidate_domain", pd.Series("", index=result.index)))
        .fillna("")
        .astype(str)
        .str.lower()
    )
    high_confidence_risk = candidate_text.apply(
        lambda text: any(
            re.search(rf"(^|[-0-9.]){re.escape(word)}($|[-0-9.])", text)
            for word in HIGH_CONFIDENCE_RISK_WORDS
        )
    )
    structural_recall = recall_reason.isin(
        {
            "risk_word_combo",
            "tld_replace",
            "no_hyphen_match",
            "confusable_match",
            "spelling_variant_match",
            "transposition_match",
            "fuzzy_match",
            "subdomain_deception",
        }
    )
    context_count = (
        suffix_changed.astype(int)
        + suspicious_tld.astype(int)
        + hyphenation.astype(int)
        + digit.astype(int)
        + visual.astype(int)
        + risk_words.astype(int)
        + structural_recall.astype(int)
    )
    model_support = (
        (numeric_column(result, "lgbm_binary_score") >= STRONG_RULE_MODEL_SUPPORT)
        | (numeric_column(result, "svm_score") >= STRONG_RULE_SVM_SUPPORT)
        | (numeric_column(result, "brand_service_score") >= 0.70)
        | (numeric_column(result, "typo_confusable_score") >= 0.70)
    )
    high_model_support = (
        (numeric_column(result, "lgbm_binary_score") >= STRONG_RULE_HIGH_MODEL_SUPPORT)
        | (numeric_column(result, "svm_score") >= STRONG_RULE_HIGH_SVM_SUPPORT)
        | (numeric_column(result, "brand_service_score") >= 0.85)
        | (numeric_column(result, "typo_confusable_score") >= 0.85)
    )
    high_confidence_rule = high_confidence_risk & (context_count >= 2)
    tier = coalesce_columns(result, ["target_tier", "target_tier_x", "target_tier_y"], default="").astype(str).str.lower()
    high_value = normalize_bool_series(
        coalesce_columns(result, ["is_high_value_target", "is_high_value_target_x", "is_high_value_target_y"], default=False)
    )
    svm_score = numeric_column(result, "svm_score")
    finance_context_word = tier.eq("finance") & candidate_text.apply(
        lambda text: any(word in text for word in HIGH_VALUE_FINANCE_CONTEXT_WORDS)
    )
    high_value_typo_recall = recall_reason.isin(
        {"spelling_variant_match", "transposition_match", "fuzzy_match"}
    )
    high_value_brand_context = (
        tier.isin({"finance", "cloud"})
        & (
            suspicious_tld
            | finance_context_word
            | recall_reason.isin({"tld_replace", "confusable_match"})
            | high_value_typo_recall
            | (svm_score >= 0.85)
        )
        & (
            (svm_score >= 0.45)
            | suspicious_tld
            | finance_context_word
            | recall_reason.isin({"tld_replace", "confusable_match"})
            | high_value_typo_recall
        )
    )
    brand_confusable_context = recall_reason.eq("confusable_match") & (svm_score >= 0.55)

    low_mask = strong_core & (context_count >= 1) & (
        model_support | high_confidence_rule | high_value_brand_context | brand_confusable_context
    )
    medium_mask = low_mask & (
        (model_support & (context_count >= 2))
        | high_confidence_rule
        | (
            high_value_brand_context
            & (
                suspicious_tld
                | finance_context_word
                | recall_reason.isin({"tld_replace", "confusable_match"})
                | high_value_typo_recall
                | (svm_score >= 0.80)
            )
        )
        | brand_confusable_context
    )
    high_mask = medium_mask & (
        (high_model_support & (context_count >= 2) & (digit | visual | high_confidence_risk | hyphenation | suspicious_tld))
        | (model_support & high_confidence_rule & (context_count >= 3))
    )

    floor = pd.Series(0.0, index=result.index, dtype=float)
    floor.loc[low_mask] = STRONG_RULE_FALLBACK_LOW
    floor.loc[medium_mask] = STRONG_RULE_FALLBACK_MEDIUM
    floor.loc[high_mask] = STRONG_RULE_FALLBACK_HIGH
    original_score = numeric_column(result, "final_score")
    result["final_score"] = np.maximum(original_score, floor)
    result["strong_rule_fallback"] = (floor > original_score).astype(int)
    result["strong_rule_fallback_floor"] = floor
    return result


def load_fallback_block_tokens() -> set[str]:
    try:
        policy = load_token_policy()
    except Exception:
        policy = {}
    tokens: set[str] = set(FALLBACK_GENERIC_TOKENS)
    for key in (
        "weak_target_tokens",
        "generic_medium_target_tokens",
        "inherited_target_tokens",
        "forbidden_strong_tokens",
        "spelling_variant_block_base_tokens",
        "spelling_variant_complete_word_block_tokens",
    ):
        tokens.update(str(token).lower().strip() for token in policy.get(key, set()) if str(token).strip())
    return tokens


def load_fallback_suffix_pair_blocks() -> set[tuple[str, str]]:
    try:
        policy = load_token_policy()
    except Exception:
        return {("lay", "pay"), ("play", "pay")}
    pairs = policy.get("spelling_variant_suffix_pair_blocks", set()) or set()
    normalized: set[tuple[str, str]] = set()
    for pair in pairs:
        if not isinstance(pair, tuple) or len(pair) != 2:
            continue
        candidate, target = str(pair[0]).lower().strip(), str(pair[1]).lower().strip()
        if candidate and target:
            normalized.add((candidate, target))
    return normalized | {("lay", "pay"), ("play", "pay")}


def spelling_variant_output_noise_series(df: pd.DataFrame, recall_reason: pd.Series) -> pd.Series:
    if df.empty:
        return pd.Series(False, index=df.index)
    block_tokens = load_fallback_block_tokens()
    suffix_pairs = load_fallback_suffix_pair_blocks()
    variant_reason = recall_reason.isin({"spelling_variant_match", "transposition_match", "fuzzy_match"})
    if not variant_reason.any():
        return pd.Series(False, index=df.index)
    return pd.Series(
        [
            bool(is_variant_word_noise(row, block_tokens, suffix_pairs)) if is_variant else False
            for (_, row), is_variant in zip(df.iterrows(), variant_reason)
        ],
        index=df.index,
    )


def is_variant_word_noise(
    row: pd.Series,
    block_tokens: set[str],
    suffix_pairs: set[tuple[str, str]],
) -> bool:
    candidate_sld = text(row.get("candidate_sld")).lower()
    if not candidate_sld:
        candidate_sld = text(normalize_domain(row.get("candidate_domain", "")).get("sld_clean")).lower()
    target_sld = text(row.get("target_sld")).lower()
    if not target_sld:
        target_sld = text(normalize_domain(row.get("target_domain", "")).get("sld_clean")).lower()
    candidate_compact = re.sub(r"[^a-z0-9]+", "", candidate_sld)
    target_compact = re.sub(r"[^a-z0-9]+", "", target_sld)
    candidate_tokens = {
        token
        for token in re.findall(r"[a-z0-9]+", candidate_sld)
        if token
    }
    for token in candidate_tokens & block_tokens:
        if candidate_compact == token or candidate_compact.endswith(token):
            return True
    for candidate_suffix, target_suffix in suffix_pairs:
        if (
            candidate_suffix
            and target_suffix
            and candidate_compact.endswith(candidate_suffix)
            and target_compact.endswith(target_suffix)
            and candidate_compact[: -len(candidate_suffix)]
            == target_compact[: -len(target_suffix)]
        ):
            return True
    return False


def numeric_column(df: pd.DataFrame, column: str) -> pd.Series:
    return pd.to_numeric(df.get(column, pd.Series(0, index=df.index)), errors="coerce").fillna(0.0)


def bool_column(df: pd.DataFrame, column: str) -> pd.Series:
    value = df.get(column, pd.Series(False, index=df.index))
    if value.dtype == bool:
        return value.fillna(False)
    return value.fillna("").astype(str).str.lower().isin({"1", "true", "yes", "y"})


def apply_official_domain_guard(df: pd.DataFrame) -> pd.DataFrame:
    """Suppress exact official-domain self matches from final alerting."""
    if "candidate_domain" not in df.columns or "target_domain" not in df.columns:
        return df
    result = df.copy()
    candidate = result["candidate_domain"].fillna("").astype(str).str.lower().str.strip()
    target = result["target_domain"].fillna("").astype(str).str.lower().str.strip()
    official_match = (candidate != "") & (candidate == target)
    if official_match.any():
        result.loc[official_match, "final_score"] = 0.0
        result.loc[official_match, "risk_level"] = "ignore"
    return result


def apply_official_alias_guard(
    df: pd.DataFrame,
    alias_groups_path: str | Path | pd.DataFrame | None = DEFAULT_ALIAS_GROUPS,
) -> pd.DataFrame:
    """Suppress candidate-target pairs that are official aliases in the same group."""
    if alias_groups_path is None:
        return df
    if isinstance(alias_groups_path, str) and alias_groups_path.strip() == "":
        return df
    if "candidate_domain" not in df.columns or "target_domain" not in df.columns:
        return df

    if isinstance(alias_groups_path, pd.DataFrame):
        groups = alias_groups_path.copy()
    else:
        groups_path = Path(alias_groups_path)
        if not groups_path.exists():
            return df
        groups = read_csv_with_fallback(groups_path)

    required = {"alias_group_id", "target_domain"}
    if not required.issubset(groups.columns):
        return df

    alias_map = build_alias_group_map(groups)
    if not alias_map:
        return df

    result = df.copy()
    candidate = result["candidate_domain"].fillna("").astype(str).str.lower().str.strip()
    target = result["target_domain"].fillna("").astype(str).str.lower().str.strip()
    alias_match = [
        bool(left and right and left != right and alias_map.get(left, set()) & alias_map.get(right, set()))
        for left, right in zip(candidate, target)
    ]
    alias_mask = pd.Series(alias_match, index=result.index)
    if alias_mask.any():
        result.loc[alias_mask, "final_score"] = 0.0
        result.loc[alias_mask, "risk_level"] = "ignore"
    return result


def build_alias_group_map(groups: pd.DataFrame) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    clean = groups[["alias_group_id", "target_domain"]].dropna().copy()
    clean["target_domain"] = clean["target_domain"].astype(str).str.lower().str.strip()
    clean["alias_group_id"] = clean["alias_group_id"].astype(str).str.strip()
    clean = clean[(clean["target_domain"] != "") & (clean["alias_group_id"] != "")]
    for row in clean.itertuples(index=False):
        result.setdefault(row.target_domain, set()).add(row.alias_group_id)
    return result


def apply_manual_review_guard(df: pd.DataFrame, manual_review_path: str | Path | None) -> pd.DataFrame:
    """Suppress candidate-target pairs that analysts confirmed as false positives."""
    if not manual_review_path:
        return df
    review_path = Path(manual_review_path)
    if not review_path.exists():
        return df
    if "candidate_domain" not in df.columns or "target_domain" not in df.columns:
        return df

    manual_review = read_csv_with_fallback(review_path)
    required = {"candidate_domain", "target_domain", "review_label"}
    if not required.issubset(manual_review.columns):
        return df

    labels = pd.to_numeric(manual_review["review_label"], errors="coerce")
    blocked = manual_review.loc[labels == 0, ["candidate_domain", "target_domain"]].copy()
    if blocked.empty:
        return df

    blocked["pair_key"] = blocked.apply(
        lambda row: f"{text(row['candidate_domain']).lower()}|{text(row['target_domain']).lower()}",
        axis=1,
    )
    blocked_keys = set(blocked["pair_key"])
    result = df.copy()
    pair_keys = (
        result["candidate_domain"].fillna("").astype(str).str.lower().str.strip()
        + "|"
        + result["target_domain"].fillna("").astype(str).str.lower().str.strip()
    )
    blocked_mask = pair_keys.isin(blocked_keys)
    if blocked_mask.any():
        result.loc[blocked_mask, "final_score"] = 0.0
        result.loc[blocked_mask, "risk_level"] = "ignore"
    return result


def add_explanation_columns(
    df: pd.DataFrame,
    category_thresholds: dict[str, float],
    keywords: dict[str, set[str]],
) -> pd.DataFrame:
    result = df.copy()
    explanations = result.apply(
        lambda row: explain_prediction(row, category_thresholds, keywords), axis=1
    )
    result["main_category"] = [item["main_category"] for item in explanations]
    result["all_categories"] = [item["all_categories"] for item in explanations]
    result["matched_features"] = [item["matched_features"] for item in explanations]
    result["reason"] = [item["reason"] for item in explanations]
    return result


def explain_prediction(
    row: pd.Series,
    category_thresholds: dict[str, float],
    keywords: dict[str, set[str]],
) -> dict[str, str]:
    categories = category_hits(row, category_thresholds, keywords)
    recall_category = RECALL_CATEGORY_MAP.get(str(row.get("recall_reason", "")), "")
    if recall_category and recall_category not in categories:
        categories.append(recall_category)
    if not categories:
        best_category = max(
            CATEGORY_SCORE_COLUMNS,
            key=lambda name: float(row.get(CATEGORY_SCORE_COLUMNS[name], 0) or 0),
        )
        if float(row.get(CATEGORY_SCORE_COLUMNS[best_category], 0) or 0) >= 0.35:
            categories.append(best_category)
    categories = order_output_categories(categories, row)[:MAX_OUTPUT_CATEGORIES]

    main_category = categories[0] if categories else "other_suspicious"
    matched_features = build_matched_features(row, keywords)
    reason_parts = []
    token = text(row.get("matched_token"))
    token_type = text(row.get("matched_token_type"))
    recall_reason = text(row.get("recall_reason"))
    if token:
        reason_parts.append(f"matched {token_type or 'target'} token '{token}'")
    if recall_reason:
        reason_parts.append(f"recall rule: {recall_reason}")
    if matched_features:
        reason_parts.append(f"features: {matched_features}")
    reason_parts.append(
        "scores: "
        f"rule={float(row.get('rule_score', 0) or 0):.3f}, "
        f"lgbm={float(row.get('lgbm_binary_score', 0) or 0):.3f}, "
        f"fusion={float(row.get('final_score', 0) or 0):.3f}"
    )
    return {
        "main_category": main_category,
        "all_categories": "|".join(categories) if categories else "other_suspicious",
        "matched_features": matched_features,
        "reason": "; ".join(reason_parts),
    }


def category_hits(
    row: pd.Series,
    thresholds: dict[str, float],
    keywords: dict[str, set[str]] | None = None,
) -> list[str]:
    hits: list[str] = []
    for category, score_column in CATEGORY_SCORE_COLUMNS.items():
        score = float(row.get(score_column, 0) or 0)
        threshold = float(thresholds.get(category, 0.5))
        if score >= threshold:
            hits.append(category)
    hits.extend(rule_supplemental_category_hits(row, keywords or {}))
    return order_output_categories(hits, row)[:MAX_OUTPUT_CATEGORIES]


def rule_supplemental_category_hits(row: pd.Series, keywords: dict[str, set[str]]) -> list[str]:
    """Add conservative rule-based category labels for explainable outputs."""
    hits: list[str] = []
    recall_reason = text(row.get("recall_reason")).lower()
    token_type = text(row.get("matched_token_type")).lower()
    matched_token = clean_category_token(text(row.get("matched_token")).lower())
    candidate_sld = text(row.get("candidate_sld")).lower()
    target_sld = text(row.get("target_sld")).lower()
    candidate_clean = clean_category_token(candidate_sld)
    target_clean = clean_category_token(target_sld)
    candidate_text = f"{candidate_sld}.{text(row.get('candidate_subdomain')).lower()}"
    strong_token = token_type == "strong"
    hard_filter = boolish(row.get("hard_filter_pass"))
    contains_target = row_float(row, "contains_target_sld") == 1
    contains_target_confusable = row_float(row, "contains_target_sld_confusable_norm") == 1
    suffix_changed = row_float(row, "suffix_changed") == 1
    suspicious_tld = row_float(row, "is_suspicious_tld") == 1
    hyphenated = row_float(row, "hyphen_count") > 0
    digit_count = row_float(row, "digit_count") > 0
    visual_confusable = row_float(row, "has_digit_letter_confusion") == 1
    strong_target_evidence = strong_token and hard_filter and (
        contains_target
        or contains_target_confusable
        or (target_clean and matched_token == target_clean)
        or recall_reason in {"spelling_variant_match", "transposition_match", "fuzzy_match", "confusable_match"}
    )
    if not strong_target_evidence:
        return hits

    risk_words = set(find_risk_words(row, keywords))
    service_context = has_service_entry_context(candidate_text, risk_words)
    target_extra = candidate_has_extra_target_context(candidate_clean, target_clean)
    boundary_target = target_at_candidate_boundary(candidate_sld, target_sld)

    if (
        strong_token
        and contains_target
        and target_extra
        and (hyphenated or digit_count or suffix_changed or suspicious_tld or service_context or row_float(row, "rule_score") >= 0.78)
    ):
        hits.append("brand_combo")

    if strong_token and service_context and (contains_target or boundary_target or recall_reason == "risk_word_combo"):
        hits.append("service_entry")

    if strong_token and boundary_target and target_extra and (service_context or hyphenated or digit_count or suspicious_tld):
        hits.append("prefix_suffix")

    if recall_reason in {"spelling_variant_match", "transposition_match", "fuzzy_match"}:
        hits.append("typo")

    if recall_reason == "confusable_match" or (visual_confusable and (contains_target_confusable or contains_target)):
        hits.append("confusable")

    if recall_reason == "subdomain_deception":
        hits.append("subdomain_deception")

    if suffix_changed and is_tld_replace_like(row, candidate_clean, target_clean, recall_reason):
        hits.append("tld_replace")

    if hyphenated and (contains_target or contains_target_confusable or recall_reason == "no_hyphen_match"):
        hits.append("hyphenation")

    if row_float(row, "contains_pinyin_full") == 1 or row_float(row, "contains_pinyin_initials") == 1:
        hits.append("pinyin_abbr")

    if row_float(row, "same_template_count") > 0 or row_float(row, "max_history_similarity") >= 0.92:
        hits.append("template_reuse")

    return list(dict.fromkeys(hits))


def order_output_categories(categories: Sequence[str], row: pd.Series) -> list[str]:
    unique = [category for category in dict.fromkeys(categories) if category and category != "other_suspicious"]
    priority = {category: index for index, category in enumerate(CATEGORY_PRIORITY)}
    return sorted(
        unique,
        key=lambda category: (
            priority.get(category, len(priority)),
            -float(row.get(CATEGORY_SCORE_COLUMNS.get(category, ""), 0) or 0),
        ),
    )


def has_service_entry_context(candidate_text: str, risk_words: set[str]) -> bool:
    tokens = set(re.findall(r"[a-z0-9]+", candidate_text.lower()))
    if tokens & RULE_SERVICE_ENTRY_WORDS:
        return True
    return any(
        re.search(rf"(^|[-_.0-9]){re.escape(word)}($|[-_.0-9])", candidate_text.lower())
        for word in RULE_SERVICE_ENTRY_WORDS
    ) or bool(risk_words & RULE_SERVICE_ENTRY_WORDS)


def candidate_has_extra_target_context(candidate_clean: str, target_clean: str) -> bool:
    if not candidate_clean or not target_clean or target_clean not in candidate_clean:
        return False
    extra = candidate_clean.replace(target_clean, "", 1)
    return bool(re.sub(r"[^a-z0-9]", "", extra))


def target_at_candidate_boundary(candidate_sld: str, target_sld: str) -> bool:
    candidate = candidate_sld.lower().strip("-")
    target = target_sld.lower().strip("-")
    if not candidate or not target or candidate == target:
        return False
    return (
        candidate.startswith(target)
        or candidate.endswith(target)
        or candidate.startswith(f"{target}-")
        or candidate.endswith(f"-{target}")
    )


def is_tld_replace_like(row: pd.Series, candidate_clean: str, target_clean: str, recall_reason: str) -> bool:
    if recall_reason == "tld_replace":
        return True
    if candidate_clean and target_clean and candidate_clean == target_clean:
        return True
    return row_float(row, "rapidfuzz_ratio") >= 0.93 and row_float(row, "normalized_edit_distance") <= 0.12


def clean_category_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def row_float(row: pd.Series, column: str) -> float:
    try:
        value = row.get(column, 0)
        if value is None or pd.isna(value):
            return 0.0
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def build_matched_features(row: pd.Series, keywords: dict[str, set[str]]) -> str:
    features: list[str] = []
    recall_reason = text(row.get("recall_reason"))
    if recall_reason:
        features.append(f"recall:{recall_reason}")
    token = text(row.get("matched_token"))
    if token:
        features.append(f"token:{token}")
    risk_words = find_risk_words(row, keywords)
    if risk_words:
        features.append(f"risk_words:{','.join(risk_words)}")
    if boolish(row.get("hard_filter_pass")):
        features.append("hard_filter_pass")
    if int(float(row.get("is_suspicious_tld", 0) or 0)) == 1:
        features.append("suspicious_tld")
    if int(float(row.get("suffix_changed", 0) or 0)) == 1:
        features.append("suffix_changed")
    if int(float(row.get("hyphen_count", 0) or 0)) > 0:
        features.append("hyphenation")
    if int(float(row.get("has_digit_letter_confusion", 0) or 0)) == 1:
        features.append("visual_confusable")
    if int(float(row.get("contains_target_sld", 0) or 0)) == 1:
        features.append("contains_target_sld")
    if int(float(row.get("contains_target_sld_confusable_norm", 0) or 0)) == 1:
        features.append("contains_target_sld_confusable_norm")
    if recall_reason == "subdomain_deception":
        features.append("subdomain_deception")
    if int(float(row.get("strong_rule_fallback", 0) or 0)) == 1:
        floor = float(row.get("strong_rule_fallback_floor", 0) or 0)
        features.append(f"strong_rule_fallback:{floor:.2f}")
    return "|".join(dict.fromkeys(features))


def find_risk_words(row: pd.Series, keywords: dict[str, set[str]]) -> list[str]:
    text_value = f"{text(row.get('candidate_sld'))}.{text(row.get('candidate_subdomain'))}".lower()
    tokens = set(re.findall(r"[a-z0-9]+", text_value))
    words = []
    for group in ("strong_risk_words", "medium_risk_words", "weak_risk_words"):
        for word in sorted(keywords.get(group, set())):
            if word in tokens or word in text_value:
                words.append(word)
    return words[:12]


def make_output(
    scored: pd.DataFrame,
    output: str | Path,
    min_score: float = DEFAULT_MIN_SCORE,
    top_k_per_target: int = DEFAULT_TOP_K_PER_TARGET,
) -> pd.DataFrame:
    result = scored.copy()
    result = result[result["final_score"] >= min_score].copy()
    if result.empty:
        output_df = pd.DataFrame(columns=OUTPUT_COLUMNS)
    else:
        result = result.sort_values("final_score", ascending=False)
        if top_k_per_target > 0:
            result = result.groupby("target_domain", group_keys=False).head(top_k_per_target)
        target_tier = coalesce_columns(result, ["target_tier", "target_tier_x", "target_tier_y"], default="other")
        target_subtype = coalesce_columns(
            result, ["target_subtype", "target_subtype_x", "target_subtype_y"], default="other"
        )
        target_subtype_label_series = coalesce_columns(
            result,
            ["target_subtype_label", "target_subtype_label_x", "target_subtype_label_y"],
            default="",
        )
        target_type_source = coalesce_columns(
            result, ["target_type_source", "target_type_source_x", "target_type_source_y"], default="auto"
        )
        output_df = pd.DataFrame(
            {
                "candidate_domain": result["candidate_domain"],
                "matched_target_name": result["target_name"],
                "matched_target_domain": result["target_domain"],
                "matched_target_type": target_tier.map(target_tier_label),
                "matched_target_subtype": [
                    target_subtype_label(subtype, label)
                    for subtype, label in zip(target_subtype, target_subtype_label_series)
                ],
                "target_tier": target_tier,
                "target_subtype": target_subtype,
                "target_type_source": target_type_source,
                "final_score": result["final_score"],
                "risk_level": result["risk_level"],
                "main_category": result["main_category"],
                "all_categories": result["all_categories"],
                "matched_features": result["matched_features"],
                "rule_score": result["rule_score"],
                "lgbm_binary_score": result["lgbm_binary_score"],
                "brand_service_score": result["brand_service_score"],
                "typo_confusable_score": result["typo_confusable_score"],
                "svm_score": result["svm_score"],
                "reason": result["reason"],
            }
        )
        output_df = output_df[OUTPUT_COLUMNS].sort_values("final_score", ascending=False)

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_df.to_csv(output_path, index=False, encoding="utf-8-sig")
    return output_df


def make_high_value_review_output(
    scored: pd.DataFrame,
    output: str | Path,
    top_n: int = HIGH_VALUE_REVIEW_TOP_N,
    min_rule_score: float = 0.58,
    domain_df: pd.DataFrame | None = None,
    domain_col: str = "domain",
) -> pd.DataFrame:
    result = scored.copy()
    if result.empty:
        review_df = make_high_value_generic_review_rows(domain_df, domain_col=domain_col)
        if top_n > 0 and not review_df.empty:
            review_df = review_df.head(top_n)
    else:
        target_tier = coalesce_columns(result, ["target_tier", "target_tier_x", "target_tier_y"], default="")
        target_subtype = coalesce_columns(
            result, ["target_subtype", "target_subtype_x", "target_subtype_y"], default=""
        )
        target_subtype_label_series = coalesce_columns(
            result,
            ["target_subtype_label", "target_subtype_label_x", "target_subtype_label_y"],
            default="",
        )
        is_high_value_target = coalesce_columns(
            result,
            ["is_high_value_target", "is_high_value_target_x", "is_high_value_target_y"],
            default=False,
        )
        target_has_enough_positive = coalesce_columns(
            result,
            ["target_has_enough_positive", "target_has_enough_positive_x", "target_has_enough_positive_y"],
            default=True,
        )
        tier = target_tier.fillna("").astype(str).str.lower()
        high_value = normalize_bool_series(is_high_value_target)
        enough_positive = normalize_bool_series(target_has_enough_positive)
        candidate = result.get("candidate_domain", pd.Series("", index=result.index)).fillna("").astype(str).str.lower()
        target = result.get("target_domain", pd.Series("", index=result.index)).fillna("").astype(str).str.lower()
        high_value_review_score = build_high_value_review_score(
            result,
            tier=tier,
            high_value=high_value,
            enough_positive=enough_positive,
        )
        mask = (
            (tier.isin({"gov", "edu", "finance"}) | high_value | (~enough_positive & tier.isin({"gov", "edu", "finance", "cloud"})))
            & (candidate != "")
            & (candidate != target)
            & (numeric_column(result, "rule_score") >= float(min_rule_score))
        )
        selected = result.loc[mask].copy()
        selected["high_value_review_score"] = high_value_review_score.loc[selected.index]
        selected = selected.sort_values(
            ["high_value_review_score", "final_score", "rule_score"],
            ascending=[False, False, False],
        )
        target_review_df = build_target_high_value_review_frame(
            selected,
            target_tier=target_tier,
            target_subtype=target_subtype,
            target_subtype_label_series=target_subtype_label_series,
            is_high_value_target=is_high_value_target,
            target_has_enough_positive=target_has_enough_positive,
        )
        generic_review_df = make_high_value_generic_review_rows(domain_df, domain_col=domain_col)
        review_df = merge_high_value_review_frames(target_review_df, generic_review_df, top_n=top_n)
        review_df = ensure_high_value_review_columns(review_df)

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    review_df.to_csv(output_path, index=False, encoding="utf-8-sig")
    return review_df


def merge_high_value_review_frames(
    target_review_df: pd.DataFrame,
    generic_review_df: pd.DataFrame,
    top_n: int,
) -> pd.DataFrame:
    target_review_df = ensure_high_value_review_columns(target_review_df)
    generic_review_df = ensure_high_value_review_columns(generic_review_df)
    if top_n > 0 and not generic_review_df.empty:
        generic_keep = min(HIGH_VALUE_GENERIC_REVIEW_RESERVED_TOP_N, max(1, top_n // 5), len(generic_review_df))
        generic_part = generic_review_df.head(generic_keep)
        target_part = target_review_df.head(max(top_n - len(generic_part), 0))
        review_df = pd.concat([target_part, generic_part], ignore_index=True, sort=False)
    else:
        review_df = pd.concat([target_review_df, generic_review_df], ignore_index=True, sort=False)
        if not review_df.empty:
            review_df["high_value_review_score"] = pd.to_numeric(
                review_df["high_value_review_score"], errors="coerce"
            ).fillna(0.0)
            review_df = review_df.sort_values(
                ["high_value_review_score", "final_score", "rule_score"],
                ascending=[False, False, False],
            )
            review_df = review_df.drop_duplicates(
                subset=["candidate_domain", "matched_target_domain", "high_value_review_type"],
                keep="first",
            )
            if top_n > 0:
                review_df = review_df.head(top_n)
    if not review_df.empty:
        review_df["high_value_review_score"] = pd.to_numeric(
            review_df["high_value_review_score"], errors="coerce"
        ).fillna(0.0)
        review_df = review_df.sort_values(
            ["high_value_review_type", "high_value_review_score", "final_score", "rule_score"],
            ascending=[False, False, False, False],
        )
        review_df = review_df.drop_duplicates(
            subset=["candidate_domain", "matched_target_domain", "high_value_review_type"],
            keep="first",
        )
    return ensure_high_value_review_columns(review_df)


def build_target_high_value_review_frame(
    selected: pd.DataFrame,
    target_tier: pd.Series,
    target_subtype: pd.Series,
    target_subtype_label_series: pd.Series,
    is_high_value_target: pd.Series,
    target_has_enough_positive: pd.Series,
) -> pd.DataFrame:
    if selected.empty:
        return pd.DataFrame(columns=HIGH_VALUE_REVIEW_COLUMNS)
    index = selected.index
    possible_tier = target_tier.loc[index].fillna("").astype(str).str.lower()
    high_value_pattern = [
        "|".join(patterns)
        for patterns in (
            infer_target_high_value_patterns(row, possible_tier.loc[row_index])
            for row_index, row in selected.iterrows()
        )
    ]
    review_reason = [
        infer_target_review_reason(row, possible_tier.loc[row_index])
        for row_index, row in selected.iterrows()
    ]
    review_df = pd.DataFrame(
        {
            "candidate_domain": selected["candidate_domain"],
            "matched_target_name": selected["target_name"],
            "matched_target_domain": selected["target_domain"],
            "target_tier": target_tier.loc[index],
            "target_subtype": target_subtype.loc[index],
            "matched_target_subtype": [
                target_subtype_label(subtype, label)
                for subtype, label in zip(target_subtype.loc[index], target_subtype_label_series.loc[index])
            ],
            "possible_tier": possible_tier,
            "is_high_value_target": is_high_value_target.loc[index],
            "target_has_enough_positive": target_has_enough_positive.loc[index],
            "final_score": selected["final_score"],
            "risk_level": selected["risk_level"],
            "main_category": selected["main_category"],
            "matched_token": selected.get("matched_token", ""),
            "matched_token_type": selected.get("matched_token_type", ""),
            "recall_reason": selected.get("recall_reason", ""),
            "matched_features": selected["matched_features"],
            "rule_score": selected["rule_score"],
            "lgbm_binary_score": selected["lgbm_binary_score"],
            "brand_service_score": selected["brand_service_score"],
            "typo_confusable_score": selected["typo_confusable_score"],
            "svm_score": selected["svm_score"],
            "high_value_review_score": selected["high_value_review_score"],
            "high_value_pattern": high_value_pattern,
            "target_match_confidence": [
                infer_target_match_confidence(row) for _, row in selected.iterrows()
            ],
            "high_value_review_type": "target_based",
            "review_reason": review_reason,
            "suggested_action": "check_label",
            "reason": selected["reason"],
        }
    )
    return ensure_high_value_review_columns(review_df)


def ensure_high_value_review_columns(df: pd.DataFrame) -> pd.DataFrame:
    result = df.copy()
    for column in HIGH_VALUE_REVIEW_COLUMNS:
        if column not in result.columns:
            result[column] = ""
    return result[HIGH_VALUE_REVIEW_COLUMNS].reset_index(drop=True)


def build_high_value_review_score(
    df: pd.DataFrame,
    tier: pd.Series,
    high_value: pd.Series,
    enough_positive: pd.Series,
) -> pd.Series:
    score = pd.Series(0.0, index=df.index)
    score += numeric_column(df, "final_score") * 3.0
    score += numeric_column(df, "rule_score") * 2.0
    score += tier.isin({"gov", "edu", "finance"}).astype(float) * 1.5
    score += high_value.astype(float) * 1.0
    score += (~enough_positive & tier.isin({"gov", "edu", "finance", "cloud"})).astype(float) * 0.8
    score += df.get("risk_level", pd.Series("", index=df.index)).fillna("").astype(str).str.lower().isin(
        {"high", "medium", "low"}
    ).astype(float) * 0.7
    score += df.get("matched_token_type", pd.Series("", index=df.index)).fillna("").astype(str).str.lower().isin(
        {"strong", "short"}
    ).astype(float) * 0.4
    score += df.get("recall_reason", pd.Series("", index=df.index)).fillna("").astype(str).str.lower().isin(
        {"confusable_match", "fuzzy_match", "risk_word_combo", "subdomain_deception"}
    ).astype(float) * 0.5
    score += (numeric_column(df, "strong_risk_word_count") > 0).astype(float) * 0.4
    score += (numeric_column(df, "is_suspicious_tld") > 0).astype(float) * 0.3
    return score.round(6)


def infer_target_high_value_patterns(row: pd.Series, possible_tier: str) -> list[str]:
    patterns: list[str] = []
    if possible_tier:
        patterns.append(f"target_tier:{possible_tier}")
    risk_level = text(row.get("risk_level")).lower()
    if risk_level and risk_level != "ignore":
        patterns.append(f"risk_level:{risk_level}")
    recall_reason = text(row.get("recall_reason"))
    if recall_reason:
        patterns.append(f"recall:{recall_reason}")
    token_type = text(row.get("matched_token_type"))
    if token_type:
        patterns.append(f"token_type:{token_type}")
    if int(float(row.get("strong_risk_word_count", 0) or 0)) > 0:
        patterns.append("strong_risk_word")
    if int(float(row.get("is_suspicious_tld", 0) or 0)) > 0:
        patterns.append("suspicious_tld")
    if int(float(row.get("suffix_changed", 0) or 0)) > 0:
        patterns.append("suffix_changed")
    return patterns or ["high_value_target_watch"]


def infer_target_review_reason(row: pd.Series, possible_tier: str) -> str:
    risk_level = text(row.get("risk_level")).lower()
    enough = boolish(row.get("target_has_enough_positive", True))
    if possible_tier in {"gov", "edu", "finance"} and risk_level in {"medium", "low"}:
        return f"{possible_tier}_medium_low_alert_review"
    if possible_tier in {"gov", "edu", "finance", "cloud"} and not enough:
        return f"{possible_tier}_low_positive_target_review"
    if risk_level == "ignore":
        return f"{possible_tier or 'high_value'}_low_score_watch"
    return "high_value_target_watch"


def infer_target_match_confidence(row: pd.Series) -> str:
    token_type = text(row.get("matched_token_type")).lower()
    rule_score = float(row.get("rule_score", 0) or 0)
    final_score = float(row.get("final_score", 0) or 0)
    recall_reason = text(row.get("recall_reason")).lower()
    if token_type == "strong" and (rule_score >= 0.75 or final_score >= 0.65):
        return "strong"
    if recall_reason in {"confusable_match", "fuzzy_match", "tld_replace"} and rule_score >= 0.70:
        return "medium"
    if token_type in {"medium", "short"} or rule_score >= 0.58:
        return "medium"
    return "weak"


def make_high_value_generic_review_rows(
    domain_df: pd.DataFrame | None,
    domain_col: str = "domain",
) -> pd.DataFrame:
    if domain_df is None or domain_df.empty:
        return pd.DataFrame(columns=HIGH_VALUE_REVIEW_COLUMNS)
    if domain_col not in domain_df.columns:
        domain_col = str(domain_df.columns[0])

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in domain_df[domain_col].tolist():
        parsed = normalize_domain(raw)
        candidate_domain = parsed.get("normalized_domain", "")
        if not candidate_domain or candidate_domain in seen:
            continue
        seen.add(candidate_domain)
        review = detect_high_value_generic_pattern(parsed)
        if not review:
            continue
        rows.append(
            {
                "candidate_domain": candidate_domain,
                "matched_target_name": "possible high-value target",
                "matched_target_domain": "",
                "target_tier": "",
                "possible_tier": review["possible_tier"],
                "is_high_value_target": True,
                "target_has_enough_positive": False,
                "final_score": 0.0,
                "risk_level": "ignore",
                "main_category": "high_value_generic_impersonation",
                "matched_token": "",
                "matched_token_type": "generic_pattern",
                "recall_reason": "high_value_generic_pattern",
                "matched_features": review["matched_features"],
                "rule_score": review["rule_score"],
                "lgbm_binary_score": 0.0,
                "brand_service_score": 0.0,
                "typo_confusable_score": 0.0,
                "svm_score": 0.0,
                "high_value_review_score": review["high_value_review_score"],
                "high_value_pattern": review["high_value_pattern"],
                "target_match_confidence": "none",
                "high_value_review_type": "generic_pattern",
                "review_reason": "high_value_generic_pattern_no_exact_target",
                "suggested_action": "check_label",
                "reason": (
                    "domain string contains high-value gov/edu/finance pattern but no reliable "
                    "target attribution; review manually before adding a labeled pair"
                ),
            }
        )
    if not rows:
        return pd.DataFrame(columns=HIGH_VALUE_REVIEW_COLUMNS)
    result = pd.DataFrame(rows)
    return ensure_high_value_review_columns(
        result.sort_values(["high_value_review_score", "rule_score"], ascending=[False, False])
    )


def detect_high_value_generic_pattern(parsed: dict[str, Any]) -> dict[str, Any] | None:
    candidate_sld = text(parsed.get("sld_clean") or parsed.get("sld")).lower()
    subdomain = text(parsed.get("subdomain")).lower()
    suffix = text(parsed.get("suffix")).lower()
    if not candidate_sld:
        return None
    joined = f"{candidate_sld}.{subdomain}".strip(".")
    tokens = set(re.findall(r"[a-z0-9]+", joined.replace("-", " ")))
    for part in re.split(r"[-.]", joined):
        if part:
            tokens.add(part)

    tier_hits: dict[str, list[str]] = {}
    for tier, terms in HIGH_VALUE_GENERIC_TIER_TERMS.items():
        hits = sorted(term for term in terms if term in tokens or term in joined)
        if hits:
            tier_hits[tier] = hits
    if not tier_hits:
        return None

    risk_hits = sorted(term for term in HIGH_VALUE_GENERIC_RISK_TERMS if term in tokens or term in joined)
    structure_hits: list[str] = []
    if suffix in HIGH_VALUE_SUSPICIOUS_TLDS:
        structure_hits.append(f"suspicious_tld:{suffix}")
    if "-" in candidate_sld:
        structure_hits.append("hyphenated_sld")
    if any(ch.isdigit() for ch in candidate_sld):
        structure_hits.append("digit_in_sld")
    if len(candidate_sld) >= 18:
        structure_hits.append("long_sld")

    best_tier = max(
        tier_hits,
        key=lambda tier: (len(tier_hits[tier]), 1 if tier == "gov" else 0, 1 if tier == "finance" else 0),
    )
    score = (
        1.0
        + min(len(tier_hits[best_tier]), 3) * 0.6
        + min(len(risk_hits), 3) * 0.4
        + min(len(structure_hits), 3) * 0.3
    )
    # A single broad word such as "bank" or "edu" is too noisy unless the domain also has
    # suspicious structure or a second review signal.
    if score < HIGH_VALUE_GENERIC_REVIEW_MIN_SCORE:
        return None
    if len(tier_hits[best_tier]) == 1 and not risk_hits and not structure_hits:
        return None

    pattern_parts = [f"{best_tier}:{','.join(tier_hits[best_tier][:5])}"]
    if risk_hits:
        pattern_parts.append(f"risk:{','.join(risk_hits[:5])}")
    if structure_hits:
        pattern_parts.append(f"structure:{','.join(structure_hits[:5])}")
    return {
        "possible_tier": best_tier,
        "matched_features": "|".join(pattern_parts),
        "high_value_pattern": "|".join(pattern_parts),
        "rule_score": round(min(score / 4.0, 1.0), 6),
        "high_value_review_score": round(score, 6),
    }


def coalesce_columns(df: pd.DataFrame, names: Sequence[str], default: Any = "") -> pd.Series:
    result = pd.Series(np.nan, index=df.index)
    for name in names:
        if name not in df.columns:
            continue
        values = df[name]
        mask = result.isna() | result.astype(str).str.strip().str.lower().isin({"", "nan", "none"})
        result.loc[mask] = values.loc[mask]
    result = result.fillna(default)
    blank_mask = result.astype(str).str.strip().str.lower().isin({"", "nan", "none"})
    if blank_mask.any():
        result.loc[blank_mask] = default
    return result


def normalize_bool_series(values: pd.Series) -> pd.Series:
    if values.dtype == bool:
        return values.fillna(False)
    return values.fillna("").astype(str).str.lower().isin({"1", "true", "yes", "y"})


def extract_prediction_features(
    pairs: pd.DataFrame,
    keywords: dict[str, set[str]],
    history_pairs: str | Path | None = DEFAULT_HISTORY_PAIRS,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    history_summary: dict[str, Any] = {
        "history_pairs": str(history_pairs) if history_pairs else "",
        "history_positive_count": 0,
        "used_history": False,
    }
    combined = pairs.copy()
    if history_pairs:
        history_path = Path(history_pairs)
        if history_path.exists():
            history_df = read_csv_with_fallback(history_path)
            if "label" in history_df.columns:
                labels = pd.to_numeric(history_df["label"], errors="coerce").fillna(0).astype(int)
                positives = history_df.loc[labels == 1].copy()
                history_summary["history_positive_count"] = int(len(positives))
                if not positives.empty:
                    combined = pd.concat([combined, positives], ignore_index=True, sort=False)
                    history_summary["used_history"] = True
        else:
            history_summary["missing_history_path"] = str(history_path)

    features, _, _ = extract_features(combined, keywords=keywords)
    return features.iloc[: len(pairs)].copy(), history_summary


def predict(
    targets: str | Path,
    domains: str | Path,
    model_dir: str | Path,
    output: str | Path,
    domain_col: str = "domain",
    min_score: float = DEFAULT_MIN_SCORE,
    top_k_per_target: int = DEFAULT_TOP_K_PER_TARGET,
    history_pairs: str | Path | None = DEFAULT_HISTORY_PAIRS,
    manual_review: str | Path | None = DEFAULT_MANUAL_REVIEW,
    alias_groups: str | Path | None = DEFAULT_ALIAS_GROUPS,
    disable_alias_guard: bool = False,
    unique_output: str | Path | None = None,
    report_output: str | Path | None = None,
    high_value_review_output: str | Path | None = None,
    high_value_review_top_n: int = HIGH_VALUE_REVIEW_TOP_N,
) -> dict[str, Any]:
    profiles = load_targets(targets)
    domain_df = read_csv_with_fallback(domains)
    recall_keywords = load_recall_keywords()
    recalled = recall_candidates(domain_df, profiles, domain_col=domain_col, keywords=recall_keywords)
    if recalled.empty:
        write_empty_output(output)
        unique_count = 0
        if unique_output:
            write_unique_candidate_output(pd.DataFrame(columns=OUTPUT_COLUMNS), unique_output)
        high_value_review_count = 0
        if high_value_review_output:
            Path(high_value_review_output).parent.mkdir(parents=True, exist_ok=True)
            high_value_review_df = make_high_value_review_output(
                pd.DataFrame(),
                output=high_value_review_output,
                top_n=high_value_review_top_n,
                domain_df=domain_df,
                domain_col=domain_col,
            )
            high_value_review_count = int(len(high_value_review_df))
        summary = {
            "target_count": int(len(profiles)),
            "input_domain_count": int(len(domain_df)),
            "recalled_count": 0,
            "scored_count": 0,
            "output_count": 0,
            "unique_candidate_count": unique_count,
            "output": str(output),
            "unique_output": str(unique_output) if unique_output else "",
            "report_output": str(report_output) if report_output else "",
            "high_value_review_output": str(high_value_review_output) if high_value_review_output else "",
            "high_value_review_count": high_value_review_count,
        }
        if report_output:
            write_prediction_report(summary, report_output)
        print("no recalled candidate-target pairs; wrote empty output")
        return summary

    pairs = ensure_prediction_pair_columns(recalled, profiles)
    feature_keywords = load_feature_keywords()
    features, history_summary = extract_prediction_features(
        pairs,
        keywords=feature_keywords,
        history_pairs=history_pairs,
    )
    scored, category_thresholds = add_model_scores(
        features,
        model_dir,
        manual_review_path=manual_review,
        alias_groups_path=alias_groups,
        disable_alias_guard=disable_alias_guard,
    )
    scored = add_explanation_columns(scored, category_thresholds, feature_keywords)
    output_df = make_output(
        scored,
        output=output,
        min_score=min_score,
        top_k_per_target=top_k_per_target,
    )
    high_value_review_count = 0
    if high_value_review_output:
        high_value_review_df = make_high_value_review_output(
            scored,
            output=high_value_review_output,
            top_n=high_value_review_top_n,
            domain_df=domain_df,
            domain_col=domain_col,
        )
        high_value_review_count = int(len(high_value_review_df))
    unique_count = 0
    if unique_output:
        unique_df = write_unique_candidate_output(output_df, unique_output)
        unique_count = int(len(unique_df))
    summary = {
        "target_count": int(len(profiles)),
        "input_domain_count": int(len(domain_df)),
        "recalled_count": int(len(recalled)),
        "scored_count": int(len(scored)),
        "output_count": int(len(output_df)),
        "unique_candidate_count": unique_count,
        "high_value_review_count": high_value_review_count,
        **history_summary,
        "manual_review": str(manual_review) if manual_review else "",
        "alias_groups": str(alias_groups) if alias_groups and not disable_alias_guard else "",
        "alias_guard_disabled": bool(disable_alias_guard),
        "risk_level_counts": output_df["risk_level"].value_counts().to_dict()
        if "risk_level" in output_df
        else {},
        "target_type_counts": output_df["matched_target_type"].value_counts().to_dict()
        if "matched_target_type" in output_df
        else {},
        "output": str(output),
        "unique_output": str(unique_output) if unique_output else "",
        "report_output": str(report_output) if report_output else "",
        "high_value_review_output": str(high_value_review_output) if high_value_review_output else "",
    }
    if report_output:
        write_prediction_report(summary, report_output)
    return summary


def text(value: Any) -> str:
    if value is None or pd.isna(value):
        return ""
    value_text = str(value).strip()
    return "" if value_text.lower() == "nan" else value_text


def boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return text(value).lower() in {"1", "true", "yes", "y"}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Predict suspicious impersonation domains from targets and candidate domains."
    )
    parser.add_argument("--targets", required=True, help="Target profiles CSV or whitelist CSV path.")
    parser.add_argument("--domains", required=True, help="Candidate domains CSV path.")
    parser.add_argument("--model-dir", required=True, help="Directory containing trained models.")
    parser.add_argument(
        "--output",
        default="",
        help=(
            "Output suspicious domains CSV path. If omitted, writes to "
            "outputs/final_results/<task_date>_<task_name>/suspicious_domains_result.csv."
        ),
    )
    parser.add_argument(
        "--unique-output",
        default="",
        help=(
            "Output CSV with one best row per candidate domain. If omitted, writes beside "
            "--output as suspicious_domains_result_unique_candidates.csv."
        ),
    )
    parser.add_argument(
        "--report-output",
        default="",
        help="Prediction report Markdown path. If omitted, writes prediction_report.md beside --output.",
    )
    parser.add_argument(
        "--high-value-review-output",
        default="",
        help=(
            "Output CSV for high-value target watch candidates. If omitted, writes to "
            "outputs/active_learning/<task_date>_<task_name>/review_high_value_targets.csv."
        ),
    )
    parser.add_argument(
        "--high-value-review-top-n",
        type=int,
        default=HIGH_VALUE_REVIEW_TOP_N,
        help="Maximum high-value watch rows to output. Use 0 to disable the cap.",
    )
    parser.add_argument("--output-root", default="outputs", help="Root directory for archived outputs.")
    parser.add_argument("--task-date", default="", help="Task date for archived output folder, e.g. 2026-06-10.")
    parser.add_argument(
        "--task-name",
        default="",
        help="Task name suffix for archived output folder. Defaults to the candidate-domain file stem.",
    )
    parser.add_argument("--domain-col", default="domain", help="Candidate domain column name.")
    parser.add_argument("--min-score", type=float, default=DEFAULT_MIN_SCORE, help="Minimum final_score to output.")
    parser.add_argument(
        "--top-k-per-target",
        type=int,
        default=DEFAULT_TOP_K_PER_TARGET,
        help="Maximum output rows per target domain. Use 0 to disable.",
    )
    parser.add_argument(
        "--history-pairs",
        default=str(DEFAULT_HISTORY_PAIRS),
        help=(
            "Optional historical labeled pairs CSV used only for history similarity features. "
            "Use an empty string to disable."
        ),
    )
    parser.add_argument(
        "--manual-review",
        default=str(DEFAULT_MANUAL_REVIEW),
        help=(
            "Optional manual review CSV. Pairs with review_label=0 are suppressed from final alerting. "
            "Use an empty string to disable."
        ),
    )
    parser.add_argument(
        "--alias-groups",
        default=str(DEFAULT_ALIAS_GROUPS),
        help=(
            "Optional official_alias_groups.csv. Candidate-target pairs in the same alias group "
            "are suppressed from final alerting. Use an empty string to disable."
        ),
    )
    parser.add_argument(
        "--disable-alias-guard",
        action="store_true",
        help="Disable official alias guard while keeping exact self-domain suppression.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    output_path = resolve_output_file(
        args.output or None,
        kind="final_results",
        filename="suspicious_domains_result.csv",
        output_root=args.output_root,
        task_date=args.task_date or None,
        task_name=args.task_name or None,
        source_path=args.domains,
    )
    unique_output = Path(args.unique_output) if args.unique_output else output_path.with_name(
        "suspicious_domains_result_unique_candidates.csv"
    )
    report_output = Path(args.report_output) if args.report_output else output_path.with_name("prediction_report.md")
    high_value_review_output = (
        Path(args.high_value_review_output)
        if args.high_value_review_output
        else resolve_output_file(
            None,
            kind="active_learning",
            filename="review_high_value_targets.csv",
            output_root=args.output_root,
            task_date=args.task_date or None,
            task_name=args.task_name or None,
            source_path=args.domains,
        )
    )
    summary = predict(
        targets=args.targets,
        domains=args.domains,
        model_dir=args.model_dir,
        output=output_path,
        domain_col=args.domain_col,
        min_score=args.min_score,
        top_k_per_target=args.top_k_per_target,
        history_pairs=args.history_pairs or None,
        manual_review=args.manual_review or None,
        alias_groups=args.alias_groups or None,
        disable_alias_guard=args.disable_alias_guard,
        unique_output=unique_output,
        report_output=report_output,
        high_value_review_output=high_value_review_output,
        high_value_review_top_n=args.high_value_review_top_n,
    )
    for key, value in summary.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    main()
