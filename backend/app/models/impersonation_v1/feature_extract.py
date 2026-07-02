from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import pandas as pd
import yaml
from pypinyin import Style, lazy_pinyin
from rapidfuzz import fuzz
from rapidfuzz.distance import JaroWinkler, LCSseq, Levenshtein
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import pairwise_distances_chunked

try:
    from .normalize import confusable_normalize, normalize_domain
except ImportError:  # pragma: no cover - used when run as python feature_extract.py
    from normalize import confusable_normalize, normalize_domain


READ_ENCODINGS = ("utf-8-sig", "utf-8", "gbk")
PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_KEYWORDS_PATH = PACKAGE_DIR / "configs/keywords.yaml"
DEFAULT_TEMPLATES_PATH = PACKAGE_DIR / "configs/templates.yaml"

CATEGORY_COLUMNS = [
    "category_brand_combo",
    "category_prefix_suffix",
    "category_service_entry",
    "category_typo",
    "category_confusable",
    "category_hyphenation",
    "category_tld_replace",
    "category_subdomain_deception",
    "category_pinyin_abbr",
    "category_template_reuse",
    "category_other_suspicious",
]

FEATURE_COLUMNS = [
    "edit_distance",
    "normalized_edit_distance",
    "rapidfuzz_ratio",
    "jaro_winkler",
    "lcs_ratio",
    "contains_target_sld",
    "contains_target_sld_no_hyphen",
    "contains_target_sld_confusable_norm",
    "has_adjacent_transposition",
    "adjacent_transposition_count",
    "single_swap_match_target_sld",
    "best_transposition_ratio",
    "adjacent_transposition_similarity_gain",
    "has_spelling_variant",
    "repeated_char_collapse_match_target_sld",
    "single_insertion_match_target_sld",
    "single_deletion_match_target_sld",
    "single_substitution_match_target_sld",
    "best_spelling_variant_ratio",
    "target_sld_position",
    "target_sld_position_ratio",
    "target_at_sld_prefix",
    "target_at_sld_suffix",
    "target_has_left_boundary",
    "target_has_right_boundary",
    "prefix_extra_len",
    "suffix_extra_len",
    "prefix_suffix_risk_word_count",
    "prefix_suffix_has_strong_risk",
    "prefix_suffix_only_noise",
    "contains_pinyin_full",
    "contains_pinyin_initials",
    "contains_short_abbr",
    "short_abbr_with_strong_risk",
    "has_digit_letter_confusion",
    "has_0_o",
    "has_1_l",
    "has_3_e",
    "has_5_s",
    "has_rn_m",
    "has_vv_w",
    "is_punycode",
    "starts_with_xn",
    "strong_risk_word_count",
    "medium_risk_word_count",
    "weak_risk_word_count",
    "has_login",
    "has_verify",
    "has_secure",
    "has_account",
    "has_mail",
    "has_vpn",
    "has_sso",
    "has_oa",
    "has_support",
    "has_update",
    "candidate_domain_len",
    "candidate_sld_len",
    "candidate_label_count",
    "hyphen_count",
    "digit_count",
    "alpha_count",
    "digit_ratio",
    "hyphen_ratio",
    "is_long_sld",
    "is_very_long_sld",
    "suffix_changed",
    "is_suspicious_tld",
    "target_is_high_value_suffix",
    "candidate_suffix_encoded",
    "target_tier_encoded",
    "target_tier_gov",
    "target_tier_edu",
    "target_tier_finance",
    "target_tier_brand",
    "target_tier_cloud",
    "target_tier_ecommerce",
    "target_tier_media",
    "target_tier_other",
    "rule_score",
    "hard_filter_pass",
    "matched_token_type_encoded",
    "recall_reason_encoded",
    "max_history_similarity",
    "nearest_history_positive_distance",
    "same_template_count",
    "matched_template_count",
    "best_template_similarity",
    "matched_template_is_seed",
]

STRONG_RISK_DEFAULT = {
    "login",
    "logon",
    "signin",
    "verify",
    "auth",
    "account",
    "password",
    "secure",
    "security",
    "sso",
    "webmail",
    "vpn",
    "token",
    "oauth",
    "reset",
    "recover",
    "2fa",
    "mfa",
    "otp",
}
MEDIUM_RISK_DEFAULT = {
    "portal",
    "service",
    "support",
    "update",
    "admin",
    "mail",
    "email",
    "payment",
    "pay",
    "bank",
    "official",
    "gov",
    "cn",
    "notice",
    "api",
    "user",
    "oa",
}
WEAK_RISK_DEFAULT = {
    "app",
    "online",
    "cloud",
    "system",
    "office",
    "site",
    "center",
    "download",
    "help",
    "home",
}
SUSPICIOUS_TLD_DEFAULT = {
    "top",
    "xyz",
    "vip",
    "shop",
    "site",
    "online",
    "icu",
    "live",
    "click",
    "work",
    "store",
    "info",
    "cc",
    "tk",
}
TEMPLATE_DEFAULT = {
    "login-{target}",
    "{target}-login",
    "verify-{target}",
    "{target}-verify",
    "secure-{target}",
    "{target}-secure",
    "auth-{target}",
    "{target}-auth",
    "help-{target}",
    "{target}-help",
    "support-{target}",
    "{target}-support",
    "secure-account-{target}",
    "account-update-{target}",
    "sso-login-{target}",
    "mail-vpn-{target}",
    "login-verify-{target}",
    "{target}-login-verify",
}
HIGH_VALUE_SUFFIXES = {"gov.cn", "edu.cn", "ac.cn", "org.cn", "com.cn"}
MATCHED_TOKEN_TYPE_MAP = {"": 0, "weak": 0, "short": 1, "medium": 2, "strong": 3}
TARGET_TIER_MAP = {
    "other": 0,
    "gov": 1,
    "edu": 2,
    "finance": 3,
    "brand": 4,
    "cloud": 5,
    "ecommerce": 6,
    "media": 7,
}


def read_pairs(path: str | Path) -> pd.DataFrame:
    input_path = Path(path)
    errors: list[str] = []
    for encoding in READ_ENCODINGS:
        try:
            return pd.read_csv(input_path, encoding=encoding, low_memory=False)
        except UnicodeDecodeError as exc:
            errors.append(f"{encoding}: {exc}")
    raise ValueError(f"failed to read {input_path}: {'; '.join(errors)}")


def load_keywords(path: str | Path = DEFAULT_KEYWORDS_PATH) -> dict[str, set[str]]:
    config_path = Path(path)
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
    else:
        data = {}
    return {
        "strong_risk_words": set(data.get("strong_risk_words") or STRONG_RISK_DEFAULT),
        "medium_risk_words": set(data.get("medium_risk_words") or MEDIUM_RISK_DEFAULT),
        "weak_risk_words": set(data.get("weak_risk_words") or WEAK_RISK_DEFAULT),
        "suspicious_tlds": set(data.get("suspicious_tlds") or SUSPICIOUS_TLD_DEFAULT),
    }


def load_templates(path: str | Path = DEFAULT_TEMPLATES_PATH) -> set[str]:
    config_path = Path(path)
    if not config_path.exists():
        return set(TEMPLATE_DEFAULT)
    with config_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    return set(data.get("templates") or TEMPLATE_DEFAULT)


def extract_features(
    pairs: pd.DataFrame,
    keywords: dict[str, set[str]] | None = None,
    templates: set[str] | None = None,
) -> tuple[pd.DataFrame, list[str], dict[str, Any]]:
    """Build numeric ML features while preserving original pair and label columns."""
    keyword_sets = keywords or load_keywords()
    template_patterns = templates or load_templates()
    result = pairs.copy()
    _ensure_base_columns(result)

    candidate_cache = _domain_cache(result["candidate_domain"])
    target_name_pinyin_cache = {
        name: make_pinyin_tokens(name) for name in result["target_name"].fillna("").astype(str).unique()
    }
    suffix_frequency = result["candidate_suffix"].fillna("").astype(str).str.lower().value_counts(normalize=True)
    recall_reason_map = _make_category_map(result.get("recall_reason", pd.Series(dtype=str)))

    feature_records: list[dict[str, Any]] = []
    for _, row in result.iterrows():
        feature_records.append(
            _extract_row_features(
                row,
                candidate_cache,
                target_name_pinyin_cache,
                suffix_frequency,
                recall_reason_map,
                keyword_sets,
                template_patterns,
            )
        )

    feature_frame = pd.DataFrame(feature_records, index=result.index)
    history_features = compute_history_features(result)
    feature_frame = pd.concat([feature_frame, history_features], axis=1)

    missing_before_fill = feature_frame[FEATURE_COLUMNS].isna().sum().to_dict()
    feature_frame[FEATURE_COLUMNS] = feature_frame[FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan)
    feature_frame[FEATURE_COLUMNS] = feature_frame[FEATURE_COLUMNS].fillna(0)

    for column in FEATURE_COLUMNS:
        feature_frame[column] = pd.to_numeric(feature_frame[column], errors="coerce").fillna(0)

    result = result.drop(columns=[column for column in FEATURE_COLUMNS if column in result.columns])
    result = pd.concat([result.reset_index(drop=True), feature_frame[FEATURE_COLUMNS].reset_index(drop=True)], axis=1)
    metadata = {
        "feature_columns": FEATURE_COLUMNS,
        "category_columns": [column for column in CATEGORY_COLUMNS if column in result.columns],
        "notes": {
            "jaro_winkler": "rapidfuzz.distance.JaroWinkler.similarity, range 0..1",
            "candidate_suffix_encoded": "frequency encoding computed on the input dataset",
            "history_similarity": "char n-gram TF-IDF cosine similarity against label=1 history samples",
        },
        "encoders": {
            "matched_token_type_encoded": MATCHED_TOKEN_TYPE_MAP,
            "recall_reason_encoded": recall_reason_map,
        },
        "missing_values_before_fill": {
            column: int(value) for column, value in missing_before_fill.items() if int(value) > 0
        },
    }
    return result, FEATURE_COLUMNS, metadata


def compute_history_features(pairs: pd.DataFrame) -> pd.DataFrame:
    texts = pairs.apply(_history_text, axis=1).fillna("").astype(str).tolist()
    positive_mask = pairs["label"].fillna(0).astype(int) == 1 if "label" in pairs else pd.Series(False, index=pairs.index)
    positive_texts = pairs.loc[positive_mask].apply(_history_text, axis=1).fillna("").astype(str).tolist()

    same_template_counts = _same_template_counts(pairs, positive_mask)
    if not positive_texts or not texts:
        return pd.DataFrame(
            {
                "max_history_similarity": np.zeros(len(pairs), dtype=float),
                "nearest_history_positive_distance": np.ones(len(pairs), dtype=float),
                "same_template_count": same_template_counts,
            },
            index=pairs.index,
        )

    try:
        vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), lowercase=True, max_features=50000)
        positive_matrix = vectorizer.fit_transform(positive_texts)
        all_matrix = vectorizer.transform(texts)
        distances = _nearest_cosine_distances(all_matrix, positive_matrix)
        similarities = 1.0 - distances
    except ValueError:
        distances = np.ones(len(pairs), dtype=float)
        similarities = np.zeros(len(pairs), dtype=float)

    return pd.DataFrame(
        {
            "max_history_similarity": np.clip(similarities, 0.0, 1.0),
            "nearest_history_positive_distance": np.clip(distances, 0.0, 1.0),
            "same_template_count": same_template_counts,
        },
        index=pairs.index,
    )


def write_outputs(features: pd.DataFrame, metadata: dict[str, Any], output: str | Path, feature_columns_path: str | Path) -> None:
    output_path = Path(output)
    columns_path = Path(feature_columns_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    columns_path.parent.mkdir(parents=True, exist_ok=True)
    features.to_csv(output_path, index=False, encoding="utf-8-sig")
    with columns_path.open("w", encoding="utf-8") as file:
        json.dump(metadata, file, ensure_ascii=False, indent=2)


def summarize_features(features: pd.DataFrame, feature_columns: Sequence[str]) -> dict[str, Any]:
    missing = features[list(feature_columns)].isna().sum()
    return {
        "sample_count": int(len(features)),
        "feature_count": int(len(feature_columns)),
        "missing_value_count": int(missing.sum()),
        "missing_value_top10": {key: int(value) for key, value in missing[missing > 0].head(10).items()},
    }


def make_pinyin_tokens(text: str) -> tuple[str, str]:
    chinese_text = "".join(re.findall(r"[\u4e00-\u9fff]+", text or ""))
    if not chinese_text:
        return "", ""
    full_parts = lazy_pinyin(chinese_text, style=Style.NORMAL, errors="ignore")
    initial_parts = lazy_pinyin(chinese_text, style=Style.FIRST_LETTER, errors="ignore")
    return "".join(full_parts).lower(), "".join(initial_parts).lower()


def _extract_row_features(
    row: pd.Series,
    candidate_cache: dict[str, dict[str, Any]],
    pinyin_cache: dict[str, tuple[str, str]],
    suffix_frequency: pd.Series,
    recall_reason_map: dict[str, int],
    keywords: dict[str, set[str]],
    templates: set[str],
) -> dict[str, Any]:
    candidate_domain = _text(row.get("candidate_domain"))
    candidate_sld = _clean_sld(row.get("candidate_sld"))
    target_sld = _clean_sld(row.get("target_sld"))
    candidate_suffix = _text(row.get("candidate_suffix")).lower()
    target_suffix = _text(row.get("target_suffix")).lower()
    target_tier = _text(row.get("target_tier")).lower() or "other"
    if target_tier not in TARGET_TIER_MAP:
        target_tier = "other"
    candidate_subdomain = _text(row.get("candidate_subdomain")).lower()
    target_name = _text(row.get("target_name"))

    candidate_no_hyphen = candidate_sld.replace("-", "")
    target_no_hyphen = target_sld.replace("-", "")
    candidate_confusable = confusable_normalize(candidate_sld)
    target_confusable = confusable_normalize(target_sld)
    max_len = max(len(candidate_sld), len(target_sld), 1)
    edit_distance = Levenshtein.distance(candidate_sld, target_sld) if candidate_sld or target_sld else 0
    target_position = candidate_sld.find(target_sld) if target_sld else -1
    tokens = _tokens(candidate_sld) | _tokens(candidate_subdomain)
    risk_counts = _risk_counts(candidate_sld, candidate_subdomain, keywords)
    edge_features = _prefix_suffix_features(candidate_sld, target_sld, keywords)
    template_features = _template_features(candidate_sld, target_sld, templates)
    transposition_features = _transposition_features(candidate_sld, target_sld)
    spelling_variant_features = _spelling_variant_features(candidate_sld, target_sld)
    pinyin_full, pinyin_initials = pinyin_cache.get(target_name, ("", ""))
    parsed_candidate = candidate_cache.get(candidate_domain, normalize_domain(candidate_domain))

    record = {
        "edit_distance": edit_distance,
        "normalized_edit_distance": edit_distance / max_len,
        "rapidfuzz_ratio": fuzz.ratio(candidate_sld, target_sld) / 100.0 if (candidate_sld or target_sld) else 0.0,
        "jaro_winkler": JaroWinkler.similarity(candidate_sld, target_sld) if (candidate_sld or target_sld) else 0.0,
        "lcs_ratio": LCSseq.similarity(candidate_sld, target_sld) / max_len if (candidate_sld or target_sld) else 0.0,
        "contains_target_sld": int(bool(target_sld and target_sld in candidate_sld)),
        "contains_target_sld_no_hyphen": int(bool(target_no_hyphen and target_no_hyphen in candidate_no_hyphen)),
        "contains_target_sld_confusable_norm": int(bool(target_confusable and target_confusable in candidate_confusable)),
        **transposition_features,
        **spelling_variant_features,
        "target_sld_position": target_position,
        "target_sld_position_ratio": target_position / max(len(candidate_sld), 1) if target_position >= 0 else -1.0,
        **edge_features,
        "contains_pinyin_full": int(bool(pinyin_full and len(pinyin_full) >= 5 and pinyin_full in candidate_sld)),
        "contains_pinyin_initials": int(bool(pinyin_initials and len(pinyin_initials) >= 2 and pinyin_initials in candidate_sld)),
        "contains_short_abbr": int(bool(target_sld and len(target_sld) <= 4 and target_sld in candidate_sld)),
        "short_abbr_with_strong_risk": int(bool(target_sld and len(target_sld) <= 4 and target_sld in candidate_sld and risk_counts["strong"] > 0)),
        "has_digit_letter_confusion": int(_has_digit_letter_confusion(candidate_sld)),
        "has_0_o": int("0" in candidate_sld),
        "has_1_l": int("1" in candidate_sld),
        "has_3_e": int("3" in candidate_sld),
        "has_5_s": int("5" in candidate_sld),
        "has_rn_m": int("rn" in candidate_sld),
        "has_vv_w": int("vv" in candidate_sld),
        "is_punycode": int(bool(parsed_candidate.get("is_punycode"))),
        "starts_with_xn": int(bool(parsed_candidate.get("starts_with_xn"))),
        "strong_risk_word_count": risk_counts["strong"],
        "medium_risk_word_count": risk_counts["medium"],
        "weak_risk_word_count": risk_counts["weak"],
        "has_login": int(_contains_risk_word(candidate_sld, candidate_subdomain, "login")),
        "has_verify": int(_contains_risk_word(candidate_sld, candidate_subdomain, "verify")),
        "has_secure": int(_contains_risk_word(candidate_sld, candidate_subdomain, "secure")),
        "has_account": int(_contains_risk_word(candidate_sld, candidate_subdomain, "account")),
        "has_mail": int(_contains_risk_word(candidate_sld, candidate_subdomain, "mail")),
        "has_vpn": int(_contains_risk_word(candidate_sld, candidate_subdomain, "vpn")),
        "has_sso": int(_contains_risk_word(candidate_sld, candidate_subdomain, "sso")),
        "has_oa": int(_contains_risk_word(candidate_sld, candidate_subdomain, "oa")),
        "has_support": int(_contains_risk_word(candidate_sld, candidate_subdomain, "support")),
        "has_update": int(_contains_risk_word(candidate_sld, candidate_subdomain, "update")),
        "candidate_domain_len": len(candidate_domain),
        "candidate_sld_len": len(candidate_sld),
        "candidate_label_count": int(parsed_candidate.get("label_count") or _label_count(candidate_domain)),
        "hyphen_count": candidate_sld.count("-"),
        "digit_count": sum(char.isdigit() for char in candidate_sld),
        "alpha_count": sum(char.isalpha() for char in candidate_sld),
        "digit_ratio": _safe_ratio(sum(char.isdigit() for char in candidate_sld), len(candidate_sld)),
        "hyphen_ratio": _safe_ratio(candidate_sld.count("-"), len(candidate_sld)),
        "is_long_sld": int(len(candidate_sld) >= 20),
        "is_very_long_sld": int(len(candidate_sld) >= 30),
        "suffix_changed": int(bool(candidate_suffix and target_suffix and candidate_suffix != target_suffix)),
        "is_suspicious_tld": int(candidate_suffix in keywords["suspicious_tlds"]),
        "target_is_high_value_suffix": int(target_suffix in HIGH_VALUE_SUFFIXES),
        "candidate_suffix_encoded": float(suffix_frequency.get(candidate_suffix, 0.0)),
        "target_tier_encoded": TARGET_TIER_MAP.get(target_tier, 0),
        "target_tier_gov": int(target_tier == "gov"),
        "target_tier_edu": int(target_tier == "edu"),
        "target_tier_finance": int(target_tier == "finance"),
        "target_tier_brand": int(target_tier == "brand"),
        "target_tier_cloud": int(target_tier == "cloud"),
        "target_tier_ecommerce": int(target_tier == "ecommerce"),
        "target_tier_media": int(target_tier == "media"),
        "target_tier_other": int(target_tier == "other"),
        "rule_score": float(pd.to_numeric(row.get("rule_score", 0), errors="coerce") if not pd.isna(row.get("rule_score", 0)) else 0.0),
        "hard_filter_pass": int(_boolish(row.get("hard_filter_pass"))),
        "matched_token_type_encoded": MATCHED_TOKEN_TYPE_MAP.get(_text(row.get("matched_token_type")).lower(), 0),
        "recall_reason_encoded": recall_reason_map.get(_text(row.get("recall_reason")).lower(), 0),
        **template_features,
    }
    return record


def _nearest_cosine_distances(all_matrix: Any, positive_matrix: Any) -> np.ndarray:
    chunks = pairwise_distances_chunked(
        all_matrix,
        positive_matrix,
        metric="cosine",
        working_memory=128,
    )
    mins = [np.asarray(chunk).min(axis=1) for chunk in chunks]
    if not mins:
        return np.ones(all_matrix.shape[0], dtype=float)
    return np.concatenate(mins)


def _same_template_counts(pairs: pd.DataFrame, positive_mask: pd.Series) -> np.ndarray:
    signatures = pairs.apply(_template_signature, axis=1)
    positive_counts = signatures[positive_mask].value_counts()
    return signatures.map(positive_counts).fillna(0).astype(int).to_numpy()


def _transposition_features(candidate_sld: str, target_sld: str) -> dict[str, Any]:
    empty = {
        "has_adjacent_transposition": 0,
        "adjacent_transposition_count": 0,
        "single_swap_match_target_sld": 0,
        "best_transposition_ratio": 0.0,
        "adjacent_transposition_similarity_gain": 0.0,
    }
    if not candidate_sld or not target_sld or len(target_sld) < 5:
        return empty

    target = target_sld.replace("-", "")
    if len(target) < 5:
        return empty
    forms = _transposition_candidate_forms(candidate_sld, len(target))
    if not forms:
        return empty

    base_ratio = max(fuzz.ratio(form, target) for form in forms) / 100.0
    exact_swap_count = 0
    best_swap_ratio = 0.0
    for form in forms:
        for variant in _adjacent_swap_variants(form):
            ratio = fuzz.ratio(variant, target) / 100.0
            best_swap_ratio = max(best_swap_ratio, ratio)
            if variant == target:
                exact_swap_count += 1

    has_transposition = int(exact_swap_count > 0 or best_swap_ratio > base_ratio)
    return {
        "has_adjacent_transposition": has_transposition,
        "adjacent_transposition_count": exact_swap_count,
        "single_swap_match_target_sld": int(exact_swap_count > 0),
        "best_transposition_ratio": best_swap_ratio,
        "adjacent_transposition_similarity_gain": max(best_swap_ratio - base_ratio, 0.0),
    }


def _spelling_variant_features(candidate_sld: str, target_sld: str) -> dict[str, Any]:
    empty = {
        "has_spelling_variant": 0,
        "repeated_char_collapse_match_target_sld": 0,
        "single_insertion_match_target_sld": 0,
        "single_deletion_match_target_sld": 0,
        "single_substitution_match_target_sld": 0,
        "best_spelling_variant_ratio": 0.0,
    }
    if not candidate_sld or not target_sld:
        return empty
    target = target_sld.replace("-", "")
    if len(target) < 5:
        return empty

    forms = _spelling_variant_candidate_forms(candidate_sld, len(target))
    if not forms:
        return empty

    repeated_match = False
    insertion_match = False
    deletion_match = False
    substitution_match = False
    best_ratio = 0.0
    for form in forms:
        if not form or form == target:
            continue
        collapsed = _collapse_repeated_chars(form)
        if collapsed != form:
            best_ratio = max(best_ratio, fuzz.ratio(collapsed, target) / 100.0)
            if collapsed == target:
                repeated_match = True
        distance = Levenshtein.distance(form, target)
        best_ratio = max(best_ratio, fuzz.ratio(form, target) / 100.0)
        if distance != 1:
            continue
        if len(form) == len(target) + 1:
            insertion_match = True
        elif len(form) + 1 == len(target):
            deletion_match = True
        elif len(form) == len(target):
            substitution_match = True

    has_variant = repeated_match or insertion_match or deletion_match or substitution_match
    return {
        "has_spelling_variant": int(has_variant),
        "repeated_char_collapse_match_target_sld": int(repeated_match),
        "single_insertion_match_target_sld": int(insertion_match),
        "single_deletion_match_target_sld": int(deletion_match),
        "single_substitution_match_target_sld": int(substitution_match),
        "best_spelling_variant_ratio": best_ratio if has_variant else 0.0,
    }


def _transposition_candidate_forms(candidate_sld: str, target_len: int) -> set[str]:
    forms: set[str] = set()
    raw_parts = [candidate_sld, candidate_sld.replace("-", "")]
    raw_parts.extend(re.findall(r"[a-z0-9]+", candidate_sld))
    for part in raw_parts:
        part = (part or "").strip("-")
        if len(part) >= 5:
            forms.add(part)
        if target_len >= 5 and len(part) >= target_len:
            for idx in range(0, len(part) - target_len + 1):
                forms.add(part[idx : idx + target_len])
    return forms


def _spelling_variant_candidate_forms(candidate_sld: str, target_len: int) -> set[str]:
    forms: set[str] = set()
    raw_parts = [candidate_sld, candidate_sld.replace("-", "")]
    raw_parts.extend(re.findall(r"[a-z0-9]+", candidate_sld))
    for part in raw_parts:
        part = (part or "").strip("-")
        if len(part) >= 5:
            forms.add(part)
        for window_len in {target_len - 1, target_len, target_len + 1}:
            if window_len < 5 or len(part) < window_len:
                continue
            for idx in range(0, len(part) - window_len + 1):
                forms.add(part[idx : idx + window_len])
    return forms


def _collapse_repeated_chars(text: str) -> str:
    return re.sub(r"([a-z0-9])\1+", r"\1", text or "")


def _adjacent_swap_variants(text: str) -> set[str]:
    variants: set[str] = set()
    chars = list(text or "")
    for idx in range(len(chars) - 1):
        if chars[idx] == chars[idx + 1]:
            continue
        swapped = chars[:]
        swapped[idx], swapped[idx + 1] = swapped[idx + 1], swapped[idx]
        variants.add("".join(swapped))
    return variants


def _prefix_suffix_features(
    candidate_sld: str,
    target_sld: str,
    keywords: dict[str, set[str]],
) -> dict[str, Any]:
    if not candidate_sld or not target_sld:
        return {
            "target_at_sld_prefix": 0,
            "target_at_sld_suffix": 0,
            "target_has_left_boundary": 0,
            "target_has_right_boundary": 0,
            "prefix_extra_len": 0,
            "suffix_extra_len": 0,
            "prefix_suffix_risk_word_count": 0,
            "prefix_suffix_has_strong_risk": 0,
            "prefix_suffix_only_noise": 0,
        }

    position = candidate_sld.find(target_sld)
    if position < 0:
        no_hyphen_candidate = candidate_sld.replace("-", "")
        no_hyphen_target = target_sld.replace("-", "")
        position = no_hyphen_candidate.find(no_hyphen_target)
        if position >= 0:
            left = no_hyphen_candidate[:position]
            right = no_hyphen_candidate[position + len(no_hyphen_target) :]
            candidate_for_boundary = no_hyphen_candidate
            target_for_boundary = no_hyphen_target
        else:
            return {
                "target_at_sld_prefix": 0,
                "target_at_sld_suffix": 0,
                "target_has_left_boundary": 0,
                "target_has_right_boundary": 0,
                "prefix_extra_len": 0,
                "suffix_extra_len": 0,
                "prefix_suffix_risk_word_count": 0,
                "prefix_suffix_has_strong_risk": 0,
                "prefix_suffix_only_noise": 0,
            }
    else:
        left = candidate_sld[:position].strip("-")
        right = candidate_sld[position + len(target_sld) :].strip("-")
        candidate_for_boundary = candidate_sld
        target_for_boundary = target_sld

    at_prefix = int(candidate_for_boundary.startswith(target_for_boundary))
    at_suffix = int(candidate_for_boundary.endswith(target_for_boundary))
    left_boundary = int(position == 0 or (position > 0 and candidate_for_boundary[position - 1] == "-"))
    right_index = position + len(target_for_boundary)
    right_boundary = int(
        right_index == len(candidate_for_boundary)
        or (0 <= right_index < len(candidate_for_boundary) and candidate_for_boundary[right_index] == "-")
    )
    edge_tokens = _tokens(left) | _tokens(right)
    if left:
        edge_tokens.add(left)
    if right:
        edge_tokens.add(right)
    strong = keywords["strong_risk_words"]
    medium = keywords["medium_risk_words"]
    weak = keywords["weak_risk_words"]
    risk_count = sum(
        1
        for word in strong | medium | weak | {"help", "web", "my"}
        if word in edge_tokens or (left and (left.startswith(word) or left.endswith(word))) or (right and (right.startswith(word) or right.endswith(word)))
    )
    return {
        "target_at_sld_prefix": at_prefix,
        "target_at_sld_suffix": at_suffix,
        "target_has_left_boundary": left_boundary,
        "target_has_right_boundary": right_boundary,
        "prefix_extra_len": len(left),
        "suffix_extra_len": len(right),
        "prefix_suffix_risk_word_count": risk_count,
        "prefix_suffix_has_strong_risk": int(
            any(
                word in edge_tokens
                or (left and (left.startswith(word) or left.endswith(word)))
                or (right and (right.startswith(word) or right.endswith(word)))
                for word in strong
            )
        ),
        "prefix_suffix_only_noise": int(bool(left or right) and risk_count == 0),
    }


def _template_features(
    candidate_sld: str,
    target_sld: str,
    templates: set[str],
) -> dict[str, Any]:
    if not candidate_sld:
        return {
            "matched_template_count": 0,
            "best_template_similarity": 0.0,
            "matched_template_is_seed": 0,
        }
    expanded_templates = [
        template.replace("{target}", target_sld or "")
        for template in templates
        if template and (target_sld or "{target}" not in template)
    ]
    expanded_templates = [template for template in expanded_templates if template]
    if not expanded_templates:
        return {
            "matched_template_count": 0,
            "best_template_similarity": 0.0,
            "matched_template_is_seed": 0,
        }
    no_hyphen = candidate_sld.replace("-", "")
    match_count = 0
    best_similarity = 0.0
    for template in expanded_templates:
        template_no_hyphen = template.replace("-", "")
        if template in candidate_sld or template_no_hyphen in no_hyphen:
            match_count += 1
        best_similarity = max(best_similarity, fuzz.ratio(candidate_sld, template) / 100.0)
    return {
        "matched_template_count": match_count,
        "best_template_similarity": best_similarity,
        "matched_template_is_seed": int(match_count > 0),
    }


def _history_text(row: pd.Series) -> str:
    return f"{_clean_sld(row.get('candidate_sld'))} [SEP] {_clean_sld(row.get('target_sld'))}"


def _template_signature(row: pd.Series) -> str:
    candidate_sld = _clean_sld(row.get("candidate_sld"))
    target_sld = _clean_sld(row.get("target_sld"))
    signature = candidate_sld
    if target_sld:
        signature = signature.replace(target_sld, "{target}", 1)
        no_hyphen_target = target_sld.replace("-", "")
        if "{target}" not in signature and no_hyphen_target:
            signature = signature.replace(no_hyphen_target, "{target}", 1)
    signature = re.sub(r"\d+", "#", signature)
    signature = re.sub(r"[a-z]{12,}", "{word}", signature)
    return signature


def _ensure_base_columns(df: pd.DataFrame) -> None:
    for column in (
        "candidate_domain",
        "candidate_sld",
        "candidate_suffix",
        "candidate_subdomain",
        "target_name",
        "target_domain",
        "target_sld",
        "target_suffix",
        "target_tier",
        "label",
        "sample_type",
        "rule_score",
        "hard_filter_pass",
        "matched_token_type",
        "recall_reason",
    ):
        if column not in df.columns:
            df[column] = ""
    for category in CATEGORY_COLUMNS:
        if category not in df.columns:
            df[category] = 0


def _domain_cache(domains: pd.Series) -> dict[str, dict[str, Any]]:
    unique_domains = domains.fillna("").astype(str).str.lower().unique()
    return {domain: normalize_domain(domain) for domain in unique_domains}


def _risk_counts(candidate_sld: str, candidate_subdomain: str, keywords: dict[str, set[str]]) -> dict[str, int]:
    return {
        "strong": sum(1 for word in keywords["strong_risk_words"] if _contains_risk_word(candidate_sld, candidate_subdomain, word)),
        "medium": sum(1 for word in keywords["medium_risk_words"] if _contains_risk_word(candidate_sld, candidate_subdomain, word)),
        "weak": sum(1 for word in keywords["weak_risk_words"] if _contains_risk_word(candidate_sld, candidate_subdomain, word)),
    }


def _contains_risk_word(candidate_sld: str, candidate_subdomain: str, word: str) -> bool:
    text = f"{candidate_sld}.{candidate_subdomain}".strip(".")
    tokens = _tokens(text)
    return word in tokens or word in candidate_sld or word in candidate_subdomain


def _has_digit_letter_confusion(candidate_sld: str) -> bool:
    return any(marker in candidate_sld for marker in ("0", "1", "3", "5", "q", "rn", "vv"))


def _make_category_map(values: pd.Series) -> dict[str, int]:
    cleaned = sorted({_text(value).lower() for value in values.fillna("").tolist() if _text(value)})
    return {value: idx + 1 for idx, value in enumerate(cleaned)}


def _tokens(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]+", str(text or "").lower()) if token}


def _label_count(domain: str) -> int:
    return len([label for label in str(domain or "").split(".") if label])


def _safe_ratio(numerator: int | float, denominator: int | float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def _clean_sld(value: Any) -> str:
    return re.sub(r"[^a-z0-9-]+", "", _text(value).lower()).strip("-")


def _text(value: Any) -> str:
    if value is None or pd.isna(value):
        return ""
    text = str(value).strip()
    return "" if text.lower() == "nan" else text


def _boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return _text(value).lower() in {"1", "true", "yes", "y"}


def _print_summary(summary: dict[str, Any]) -> None:
    print(f"sample_count={summary['sample_count']}")
    print(f"feature_count={summary['feature_count']}")
    print(f"missing_value_count={summary['missing_value_count']}")
    for column, count in summary["missing_value_top10"].items():
        print(f"missing_value.{column}={count}")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract numeric ML features from labeled candidate-target pairs."
    )
    parser.add_argument("--input", required=True, help="Input labeled pairs CSV path.")
    parser.add_argument("--output", required=True, help="Output feature CSV path.")
    parser.add_argument(
        "--feature-columns",
        help="Output feature column JSON path. Defaults to feature_columns.json beside --output.",
    )
    parser.add_argument(
        "--keywords",
        default=str(DEFAULT_KEYWORDS_PATH),
        help="Risk-word keyword YAML path.",
    )
    parser.add_argument(
        "--templates",
        default=str(DEFAULT_TEMPLATES_PATH),
        help="Template YAML path for template-derived features.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    feature_columns_path = args.feature_columns or str(Path(args.output).with_name("feature_columns.json"))
    pairs = read_pairs(args.input)
    features, feature_columns, metadata = extract_features(
        pairs,
        keywords=load_keywords(args.keywords),
        templates=load_templates(args.templates),
    )
    write_outputs(features, metadata, args.output, feature_columns_path)
    _print_summary(summarize_features(features, feature_columns))
    print(f"output={Path(args.output)}")
    print(f"feature_columns={Path(feature_columns_path)}")


if __name__ == "__main__":
    main()
