from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import re
from pathlib import Path
import time
from typing import Any, Sequence
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as xml_escape
import zipfile

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
DEFAULT_WORD_REPORT_TEMPLATE = PACKAGE_DIR / "configs/report_template.docx"
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

CATEGORY_LABELS = {
    "brand_combo": "品牌/机构词拼接",
    "prefix_suffix": "前后缀仿冒",
    "service_entry": "业务入口仿冒",
    "typo": "拼写错误",
    "confusable": "视觉混淆",
    "hyphenation": "连字符变体",
    "tld_replace": "后缀替换",
    "subdomain_deception": "子域名欺骗",
    "pinyin_abbr": "拼音/缩写命中",
    "template_reuse": "历史模板复用",
    "high_value_generic_impersonation": "高价值泛化仿冒",
    "other_suspicious": "其他可疑",
}
CATEGORY_DESCRIPTIONS = {
    "brand_combo": "目标词与品牌、业务词或额外字符串组合。",
    "prefix_suffix": "目标词位于前缀或后缀，并拼接诱导词或噪声词。",
    "service_entry": "出现登录、认证、邮箱、VPN、SSO、账号等业务入口语义。",
    "typo": "与目标主体存在插入、删除、替换、重复字符或相邻字符交换。",
    "confusable": "存在数字字母替换、rn/m、vv/w、punycode 等视觉混淆。",
    "hyphenation": "通过连字符插入或去连字符后命中目标。",
    "tld_replace": "主体相同或相近，但后缀与官方域名不同。",
    "subdomain_deception": "目标词出现在子域名结构中。",
    "pinyin_abbr": "命中中文单位拼音、拼音首字母或短缩写。",
    "template_reuse": "命中历史高频仿冒模板或模板相似度高。",
    "high_value_generic_impersonation": "包含政府、教育、金融等高价值泛化语义，但目标归属需人工确认。",
    "other_suspicious": "未归入上述类型的可疑样本。",
}
RISK_LEVEL_LABELS = {
    "high": "高风险",
    "medium": "中风险",
    "low": "低风险",
    "ignore": "忽略/人工观察",
}
RISK_LEVEL_ACTIONS = {
    "high": "优先人工复核，确认后进入处置或封禁流程。",
    "medium": "结合目标重要性、命中原因和上下文进行复核。",
    "low": "默认观察，优先关注高价值目标和重复出现模板。",
    "ignore": "不作为正式告警，可在高价值 review 池中抽样检查。",
}
RECALL_REASON_LABELS = {
    "confirmed_false_positive": "人工确认误报",
    "confirmed_positive": "人工确认正样本",
    "confusable_match": "触发视觉混淆命中",
    "exact_match": "触发目标词精确命中",
    "false_positive": "人工误报回灌",
    "fuzzy_match": "触发相似度模糊命中",
    "no_hyphen_match": "去连字符后命中目标词",
    "official_alias_group": "命中官方别名保护",
    "positive": "历史正样本",
    "risk_word_combo": "目标词与风险词组合命中",
    "spelling_variant_match": "触发拼写变体命中",
    "subdomain_deception": "触发子域名欺骗结构",
    "synthetic_brand_combo": "合成品牌拼接样本",
    "synthetic_confusable": "合成视觉混淆样本",
    "synthetic_generic_or_risk_word": "合成泛词或风险词样本",
    "synthetic_gov_edu_context": "合成政府教育语境样本",
    "synthetic_hyphenation": "合成连字符变体样本",
    "synthetic_prefix_suffix": "合成前后缀样本",
    "synthetic_service_entry": "合成业务入口样本",
    "synthetic_short_weak_context": "合成短词弱词上下文样本",
    "synthetic_subdomain_deception": "合成子域名欺骗样本",
    "synthetic_tld_replace": "合成后缀替换样本",
    "synthetic_typo": "合成拼写错误样本",
    "tld_replace": "触发后缀替换命中",
    "transposition_match": "触发相邻字符交换命中",
    "true_positive": "人工确认仿冒",
}
RISK_WORD_LABELS = {
    "account": "账户",
    "app": "应用",
    "auth": "认证",
    "bank": "银行",
    "blog": "博客",
    "checkout": "结账",
    "cloud": "云服务",
    "login": "登录",
    "mail": "邮箱",
    "official": "官方",
    "pay": "支付",
    "payment": "支付",
    "portal": "门户",
    "secure": "安全",
    "security": "安全",
    "sso": "单点登录",
    "support": "支持",
    "update": "更新",
    "verify": "验证",
    "vpn": "VPN",
    "store": "商店",
}
FEATURE_LABELS = {
    "hard_filter_pass": "通过召回硬过滤",
    "suspicious_tld": "使用可疑后缀",
    "suffix_changed": "官方域名后缀发生变化",
    "hyphenation": "存在连字符变体",
    "contains_target_sld": "包含官方域名主体",
    "contains_target_sld_no_hyphen": "去连字符后包含官方域名主体",
    "contains_target_sld_confusable_norm": "混淆归一后包含官方域名主体",
    "digit_letter_confusion": "存在数字字母混淆",
    "visual_confusion": "存在视觉混淆",
    "punycode": "存在 punycode 编码",
    "subdomain_deception": "存在子域名欺骗结构",
    "strong_rule_fallback": "强规则兜底提分",
    "brand_combo": "品牌词拼接结构",
    "prefix_suffix": "前后缀拼接结构",
    "service_entry": "业务入口语境",
    "typo": "拼写错误变体",
    "confusable": "视觉混淆变体",
    "tld_replace": "后缀替换",
}
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
    """Return a display label for target_tier."""
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
    """Return a display label for target_subtype, preferring explicit labels."""
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


def markdown_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> list[str]:
    if not rows:
        return ["_无数据。_"]
    lines = [
        "| " + " | ".join(str(item) for item in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(item) for item in row) + " |")
    return lines


def fmt_int(value: Any) -> str:
    try:
        return f"{int(float(value)):,}"
    except (TypeError, ValueError):
        return "0"


def fmt_float(value: Any, digits: int = 4) -> str:
    try:
        if pd.isna(value):
            return "0"
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return "0"


def fmt_percent(part: Any, total: Any) -> str:
    try:
        total_value = float(total)
        if total_value <= 0:
            return "0.00%"
        return f"{float(part) / total_value:.2%}"
    except (TypeError, ValueError):
        return "0.00%"


def read_report_csv(path_value: Any) -> pd.DataFrame:
    path_text = str(path_value or "").strip()
    if not path_text:
        return pd.DataFrame()
    path = Path(path_text)
    if not path.exists():
        return pd.DataFrame()
    return read_csv_with_fallback(path)


def report_task_date(summary: dict[str, Any]) -> str:
    for key in ("output", "unique_output", "pdf_report_output", "report_output", "word_report_output"):
        path_text = str(summary.get(key, ""))
        match = re.search(r"(20\d{2}-\d{2}-\d{2})", path_text)
        if match:
            return match.group(1)
    return ""


def report_task_name(summary: dict[str, Any]) -> str:
    output_path = Path(str(summary.get("output", "")))
    for part in reversed(output_path.parts):
        if re.match(r"20\d{2}-\d{2}-\d{2}_", part):
            return part
    return output_path.stem or "prediction_task"


def score_series(df: pd.DataFrame) -> pd.Series:
    if "final_score" not in df.columns:
        return pd.Series(dtype=float)
    return pd.to_numeric(df["final_score"], errors="coerce").fillna(0.0)


def risk_count(df: pd.DataFrame, level: str) -> int:
    if "risk_level" not in df.columns:
        return 0
    return int((df["risk_level"].fillna("").astype(str) == level).sum())


def normalized_target_type(row: pd.Series) -> str:
    tier = text(row.get("target_tier")).lower()
    if tier:
        return target_tier_label(tier)
    target_type = text(row.get("matched_target_type"))
    return target_type if target_type else "其他"


def add_report_target_type(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df.copy()
    result = df.copy()
    result["_report_target_type"] = result.apply(normalized_target_type, axis=1)
    return result


def risk_summary_rows(df: pd.DataFrame) -> list[list[str]]:
    total = len(df)
    rows: list[list[str]] = []
    for level in ["high", "medium", "low", "ignore"]:
        if "risk_level" in df.columns:
            subset = df[df["risk_level"].fillna("").astype(str) == level]
        else:
            subset = pd.DataFrame()
        if subset.empty and level == "ignore":
            continue
        rows.append(
            [
                RISK_LEVEL_LABELS.get(level, level),
                fmt_int(len(subset)),
                fmt_percent(len(subset), total),
                fmt_float(score_series(subset).mean() if not subset.empty else 0.0),
                RISK_LEVEL_ACTIONS.get(level, ""),
            ]
        )
    return rows


def category_summary_rows(df: pd.DataFrame, limit: int = 12) -> list[list[str]]:
    if df.empty or "main_category" not in df.columns:
        return []
    total = len(df)
    rows: list[list[str]] = []
    grouped = df.groupby(df["main_category"].fillna("other_suspicious").astype(str), dropna=False)
    items = sorted(grouped, key=lambda item: len(item[1]), reverse=True)[:limit]
    for category, group in items:
        rows.append(
            [
                CATEGORY_LABELS.get(category, category),
                fmt_int(len(group)),
                fmt_percent(len(group), total),
                fmt_float(score_series(group).mean()),
                fmt_int(risk_count(group, "high")),
                CATEGORY_DESCRIPTIONS.get(category, ""),
            ]
        )
    return rows


def target_type_summary_rows(df: pd.DataFrame, limit: int = 12) -> list[list[str]]:
    if df.empty:
        return []
    report_df = add_report_target_type(df)
    total = len(report_df)
    rows: list[list[str]] = []
    grouped = report_df.groupby("_report_target_type", dropna=False)
    items = sorted(grouped, key=lambda item: len(item[1]), reverse=True)[:limit]
    for target_type, group in items:
        rows.append(
            [
                target_type or "其他",
                fmt_int(len(group)),
                fmt_percent(len(group), total),
                fmt_float(score_series(group).mean()),
                fmt_int(risk_count(group, "high")),
                fmt_int(risk_count(group, "medium")),
                fmt_int(risk_count(group, "low")),
            ]
        )
    return rows


def top_target_rows(df: pd.DataFrame, limit: int | None = 12) -> list[list[str]]:
    if df.empty:
        return []
    report_df = add_report_target_type(df)
    for column in ["matched_target_name", "matched_target_domain", "_report_target_type"]:
        if column not in report_df.columns:
            report_df[column] = ""
    grouped = report_df.groupby(
        ["matched_target_name", "matched_target_domain", "_report_target_type"],
        dropna=False,
    )
    items = sorted(grouped, key=lambda item: len(item[1]), reverse=True)
    if limit is not None:
        items = items[:limit]
    rows: list[list[str]] = []
    for (name, domain, target_type), group in items:
        rows.append(
            [
                text(name) or "-",
                text(domain) or "-",
                text(target_type) or "其他",
                fmt_int(len(group)),
                fmt_float(score_series(group).mean(), 3),
                f"{risk_count(group, 'high')}/{risk_count(group, 'medium')}/{risk_count(group, 'low')}",
            ]
        )
    return rows


def example_rows(df: pd.DataFrame, limit: int | None = 10) -> list[list[str]]:
    if df.empty:
        return []
    report_df = df.copy()
    if "final_score" in report_df.columns:
        report_df["_score"] = score_series(report_df)
        report_df = report_df.sort_values("_score", ascending=False)
    rows: list[list[str]] = []
    if limit is not None:
        report_df = report_df.head(limit)
    for row in report_df.itertuples(index=False):
        item = row._asdict()
        rows.append(
            [
                text(item.get("candidate_domain")) or "-",
                text(item.get("matched_target_domain")) or "-",
                RISK_LEVEL_LABELS.get(text(item.get("risk_level")), text(item.get("risk_level"))),
                fmt_float(item.get("final_score")),
                CATEGORY_LABELS.get(text(item.get("main_category")), text(item.get("main_category")) or "-"),
            ]
        )
    return rows


def high_value_review_rows(review_df: pd.DataFrame) -> list[list[str]]:
    if review_df.empty:
        return []
    rows: list[list[str]] = []
    if "risk_level" in review_df.columns:
        grouped = review_df.groupby(review_df["risk_level"].fillna("ignore").astype(str), dropna=False)
        for level, group in sorted(grouped, key=lambda item: len(item[1]), reverse=True):
            rows.append(
                [
                    RISK_LEVEL_LABELS.get(level, level),
                    fmt_int(len(group)),
                    fmt_float(score_series(group).mean() if "final_score" in group.columns else 0.0),
                ]
            )
    return rows


def docx_text(value: Any) -> str:
    return xml_escape(str(value if value is not None else ""))


def docx_run(value: Any, bold: bool = False, size: int = 21, color: str = "1F2937") -> str:
    bold_xml = "<w:b/>" if bold else ""
    return (
        "<w:r>"
        "<w:rPr>"
        '<w:rFonts w:ascii="Microsoft YaHei" w:hAnsi="Microsoft YaHei" '
        'w:eastAsia="Microsoft YaHei" w:cs="Microsoft YaHei"/>'
        f'<w:color w:val="{color}"/>'
        f'<w:sz w:val="{size}"/>'
        f"{bold_xml}"
        "</w:rPr>"
        f'<w:t xml:space="preserve">{docx_text(value)}</w:t>'
        "</w:r>"
    )


def docx_paragraph(
    value: Any = "",
    *,
    bold: bool = False,
    size: int = 21,
    color: str = "1F2937",
    align: str = "",
    spacing_after: int = 120,
) -> str:
    align_xml = f'<w:jc w:val="{align}"/>' if align else ""
    return (
        "<w:p>"
        "<w:pPr>"
        f'<w:spacing w:after="{spacing_after}" w:line="300" w:lineRule="auto"/>'
        f"{align_xml}"
        "</w:pPr>"
        f"{docx_run(value, bold=bold, size=size, color=color)}"
        "</w:p>"
    )


def docx_heading(value: Any, level: int = 1) -> str:
    size = 34 if level == 1 else 27
    color = "0F172A" if level == 1 else "1E3A8A"
    spacing = 180 if level == 1 else 140
    return docx_paragraph(value, bold=True, size=size, color=color, spacing_after=spacing)


def docx_cell(value: Any, *, header: bool = False) -> str:
    fill = '<w:shd w:fill="EAF2FF"/>' if header else ""
    text_color = "0F172A" if header else "1F2937"
    return (
        "<w:tc>"
        "<w:tcPr>"
        '<w:tcW w:w="0" w:type="auto"/>'
        f"{fill}"
        '<w:tcMar><w:top w:w="80" w:type="dxa"/><w:left w:w="90" w:type="dxa"/>'
        '<w:bottom w:w="80" w:type="dxa"/><w:right w:w="90" w:type="dxa"/></w:tcMar>'
        "</w:tcPr>"
        f"{docx_paragraph(value, bold=header, size=19, color=text_color, spacing_after=0)}"
        "</w:tc>"
    )


def docx_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    if not rows:
        return docx_paragraph("无数据。", color="64748B")
    table_rows = [
        "<w:tr>" + "".join(docx_cell(header, header=True) for header in headers) + "</w:tr>"
    ]
    for row in rows:
        table_rows.append("<w:tr>" + "".join(docx_cell(item) for item in row) + "</w:tr>")
    return (
        "<w:tbl>"
        "<w:tblPr>"
        '<w:tblStyle w:val="TableGrid"/>'
        '<w:tblW w:w="0" w:type="auto"/>'
        '<w:tblBorders>'
        '<w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:left w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:right w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        "</w:tblBorders>"
        "</w:tblPr>"
        "<w:tblGrid/>"
        + "".join(table_rows)
        + "</w:tbl>"
        + docx_paragraph("", spacing_after=80)
    )


def docx_bullets(items: Sequence[str]) -> str:
    return "".join(docx_paragraph(f"• {item}", size=20, spacing_after=60) for item in items)


def docx_document_xml(body_xml: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:xml="http://www.w3.org/XML/1998/namespace">'
        "<w:body>"
        f"{body_xml}"
        "<w:sectPr>"
        '<w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080" '
        'w:header="720" w:footer="720" w:gutter="0"/>'
        "</w:sectPr>"
        "</w:body>"
        "</w:document>"
    )


def docx_styles_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:style w:type="paragraph" w:default="1" w:styleId="Normal">'
        '<w:name w:val="Normal"/>'
        '<w:rPr><w:rFonts w:ascii="Microsoft YaHei" w:hAnsi="Microsoft YaHei" '
        'w:eastAsia="Microsoft YaHei" w:cs="Microsoft YaHei"/><w:sz w:val="21"/></w:rPr>'
        "</w:style>"
        '<w:style w:type="table" w:default="1" w:styleId="TableGrid">'
        '<w:name w:val="Table Grid"/>'
        '<w:tblPr><w:tblBorders>'
        '<w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:left w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:right w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        "</w:tblBorders></w:tblPr>"
        "</w:style>"
        "</w:styles>"
    )


def write_docx_package(output: str | Path, body_xml: str) -> None:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
        '<Override PartName="/docProps/core.xml" '
        'ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        '<Override PartName="/docProps/app.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" '
        'Target="docProps/core.xml"/>'
        '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" '
        'Target="docProps/app.xml"/>'
        "</Relationships>"
    )
    document_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
        "</Relationships>"
    )
    core = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:dcmitype="http://purl.org/dc/dcmitype/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        "<dc:title>APTHunter 仿冒域名检测总览报告</dc:title>"
        "<dc:creator>APTHunter</dc:creator>"
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created>'
        f'<dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified>'
        "</cp:coreProperties>"
    )
    app = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
        'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
        "<Application>APTHunter</Application>"
        "</Properties>"
    )
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("word/_rels/document.xml.rels", document_rels)
        archive.writestr("word/document.xml", docx_document_xml(body_xml))
        archive.writestr("word/styles.xml", docx_styles_xml())
        archive.writestr("docProps/core.xml", core)
        archive.writestr("docProps/app.xml", app)


DOCX_W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def docx_element_text(element: ET.Element) -> str:
    return "".join((node.text or "") for node in element.iter(f"{DOCX_W_NS}t")).strip()


def set_docx_element_text(element: ET.Element, value: Any) -> None:
    texts = list(element.iter(f"{DOCX_W_NS}t"))
    if texts:
        texts[0].text = str(value)
        for node in texts[1:]:
            node.text = ""
        return
    run = ET.SubElement(element, f"{DOCX_W_NS}r")
    text_node = ET.SubElement(run, f"{DOCX_W_NS}t")
    text_node.text = str(value)


def docx_table_rows(table: ET.Element) -> list[ET.Element]:
    return [child for child in list(table) if child.tag == f"{DOCX_W_NS}tr"]


def docx_row_cells(row: ET.Element) -> list[ET.Element]:
    return [child for child in list(row) if child.tag == f"{DOCX_W_NS}tc"]


def set_template_table(table: ET.Element, rows: Sequence[Sequence[Any]]) -> None:
    current_rows = docx_table_rows(table)
    if not current_rows:
        return
    template_rows = [copy.deepcopy(row) for row in current_rows]
    for row in current_rows:
        table.remove(row)
    for row_index, values in enumerate(rows):
        template_index = min(row_index, len(template_rows) - 1)
        row = copy.deepcopy(template_rows[template_index])
        cells = docx_row_cells(row)
        for cell_index, value in enumerate(values):
            if cell_index >= len(cells):
                break
            set_docx_element_text(cells[cell_index], value)
        for cell in cells[len(values) :]:
            set_docx_element_text(cell, "")
        table.append(row)


def set_first_paragraph_starting_with(root: ET.Element, prefix: str, value: str) -> None:
    for paragraph in root.iter(f"{DOCX_W_NS}p"):
        if docx_element_text(paragraph).startswith(prefix):
            set_docx_element_text(paragraph, value)
            return


def set_paragraph_after_heading(root: ET.Element, heading: str, offset: int, value: str) -> None:
    paragraphs = [node for node in root.iter(f"{DOCX_W_NS}p")]
    for index, paragraph in enumerate(paragraphs):
        if docx_element_text(paragraph) == heading:
            target_index = index + offset
            if target_index < len(paragraphs):
                set_docx_element_text(paragraphs[target_index], value)
            return


def report_chinese_date(date_text: str) -> str:
    match = re.match(r"(\d{4})-(\d{2})-(\d{2})", date_text or "")
    if not match:
        return date_text or "本次"
    year, month, day = match.groups()
    return f"{int(year)} 年 {int(month)} 月 {int(day)} 日"


def risk_short(value: Any) -> str:
    return {"high": "高", "medium": "中", "low": "低", "ignore": "忽略"}.get(text(value).lower(), text(value))


def category_label(value: Any) -> str:
    key = text(value)
    return CATEGORY_LABELS.get(key, key or "其他可疑")


def risk_words_to_chinese(value: str) -> str:
    words = [word.strip() for word in re.split(r"[,;/]+", value) if word.strip()]
    labels = [RISK_WORD_LABELS.get(word.lower(), word) for word in words]
    return "、".join(labels)


def feature_piece_to_chinese(piece: str) -> str:
    item = piece.strip()
    if not item:
        return ""
    key, sep, value = item.partition(":")
    key = key.strip().lower()
    value = value.strip()
    if key == "recall":
        return RECALL_REASON_LABELS.get(value.lower(), f"召回规则：{value}")
    if key == "token":
        return f"命中目标词 {value}" if value else "命中目标词"
    if key == "risk_words":
        return f"组合风险词：{risk_words_to_chinese(value)}" if value else "组合风险词"
    if key == "strong_rule_fallback":
        return f"强规则兜底提分至 {value}" if value else "强规则兜底提分"
    if key in FEATURE_LABELS:
        return FEATURE_LABELS[key]
    if item in FEATURE_LABELS:
        return FEATURE_LABELS[item]
    if key in RECALL_REASON_LABELS:
        return RECALL_REASON_LABELS[key]
    # Keep short unknown evidence, but describe it as an internal feature instead of
    # leaking raw English feature chains into the report.
    return f"命中内部特征：{item}"


def evidence_text_to_chinese(value: Any) -> str:
    raw = text(value)
    if not raw:
        return ""
    # Prefer the compact matched_features chain when available.
    if "|" in raw:
        translated = [feature_piece_to_chinese(piece) for piece in raw.split("|")]
        result = [piece for piece in translated if piece]
        return "；".join(dict.fromkeys(result))

    replacements = {
        "matched strong token": "命中强目标词",
        "matched medium token": "命中中等目标词",
        "matched short token": "命中短缩写目标词",
        "recall rule": "召回规则",
        "features": "命中特征",
        "scores": "模型分数",
        "fusion": "融合分",
        "rule": "规则分",
        "lgbm": "LightGBM 分",
    }
    result = raw
    for source, target in replacements.items():
        result = result.replace(source, target)
    for source, target in RECALL_REASON_LABELS.items():
        result = result.replace(source, target)
    for source, target in FEATURE_LABELS.items():
        result = result.replace(source, target)
    return result


def concise_evidence(row: pd.Series) -> str:
    """Compact evidence for dense Word tables."""
    raw_features = text(row.get("matched_features")).lower()
    recall_reason = text(row.get("recall_reason")).lower()
    parts: list[str] = []
    if recall_reason == "risk_word_combo" or "risk_words:" in raw_features:
        parts.append("风险词组合")
    elif recall_reason == "spelling_variant_match":
        parts.append("拼写变体")
    elif recall_reason == "transposition_match":
        parts.append("字符交换")
    elif recall_reason == "confusable_match":
        parts.append("视觉混淆")
    elif recall_reason == "tld_replace":
        parts.append("后缀替换")
    elif recall_reason == "subdomain_deception":
        parts.append("子域名欺骗")
    elif recall_reason == "exact_match" or "contains_target_sld" in raw_features:
        parts.append("目标词命中")
    elif recall_reason:
        parts.append(RECALL_REASON_LABELS.get(recall_reason, "规则命中"))

    for feature_key, label in [
        ("suspicious_tld", "可疑后缀"),
        ("suffix_changed", "后缀变化"),
        ("hyphenation", "连字符"),
        ("contains_target_sld_confusable_norm", "混淆命中"),
        ("contains_target_sld", "包含主体"),
        ("strong_rule_fallback", "强规则兜底"),
    ]:
        if feature_key in raw_features and label not in parts:
            parts.append(label)

    if not parts:
        category = category_label(row.get("main_category"))
        parts.append(category if category != "其他可疑" else "模型融合命中")
    return " / ".join(parts[:4])


def top_risk_detail_rows(df: pd.DataFrame, limit: int | None = None) -> list[list[str]]:
    if df.empty:
        return []
    report_df = df.copy()
    report_df["_score"] = score_series(report_df)
    report_df = report_df.sort_values("_score", ascending=False)
    if limit is not None:
        report_df = report_df.head(limit)
    rows: list[list[str]] = []
    for index, (_, row) in enumerate(report_df.iterrows(), start=1):
        rows.append(
            [
                index,
                text(row.get("candidate_domain")) or "-",
                text(row.get("matched_target_name")) or text(row.get("matched_target_domain")) or "-",
                fmt_float(row.get("final_score")),
                category_label(row.get("main_category")),
                concise_evidence(row),
            ]
        )
    return rows


def high_value_detail_rows(review_df: pd.DataFrame, limit: int | None = None) -> list[list[str]]:
    if review_df.empty:
        return []
    report_df = review_df.copy()
    report_df["_review_score"] = pd.to_numeric(
        report_df.get("high_value_review_score", 0), errors="coerce"
    ).fillna(0.0)
    report_df["_score"] = score_series(report_df)
    report_df = report_df.sort_values(["_review_score", "_score"], ascending=[False, False])
    if limit is not None:
        report_df = report_df.head(limit)
    rows: list[list[str]] = []
    for index, (_, row) in enumerate(report_df.iterrows(), start=1):
        rows.append(
            [
                index,
                text(row.get("candidate_domain")) or "-",
                text(row.get("matched_target_name")) or "possible high-value target",
                text(row.get("matched_target_domain")) or "-",
                fmt_float(row.get("final_score")),
                risk_short(row.get("risk_level")),
                category_label(row.get("main_category")),
            ]
        )
    return rows


def review_suggestion_rows(unique_count: int, high: int, medium: int, low: int, high_value: int) -> list[list[str]]:
    return [
        [
            f"高风险候选（{fmt_int(high)} 条）",
            "优先人工核验",
            "核验目标词、域名归属、页面用途与是否存在登录/支付/账号诱导；确认后再采取阻断、告警或情报同步措施。",
        ],
        [
            f"中风险候选（{fmt_int(medium)} 条）",
            "分层复核",
            "优先处理金融、政府、教育、云服务等高价值目标；对泛词、短词和多品牌组合场景重点排除误报。",
        ],
        [
            f"低风险候选（{fmt_int(low)} 条）",
            "持续观察",
            "保留结果与特征，后续可结合人工复核、重复出现情况或外部验证数据再做升级。",
        ],
        [
            f"正式去重候选（{fmt_int(unique_count)} 条）",
            "日常运营复核",
            "以去重结果作为日常复核主入口，完整候选对结果用于排查同一域名匹配多个目标的情况。",
        ],
        [
            f"高价值目标人工复核池（{fmt_int(high_value)} 条）",
            "独立人工筛查",
            "不与正式告警混合统计；重点关注政府、教育、金融等对象的中低分候选。",
        ],
        [
            "模型与规则优化",
            "闭环回灌",
            "将人工确认的正样本、误报样本、官方别名和泛词治理结果回灌目标画像、难负样本池和目标词策略。",
        ],
    ]


def build_template_report_tables(
    summary: dict[str, Any],
    formal_df: pd.DataFrame,
    high_value_review_df: pd.DataFrame,
) -> list[list[list[Any]]]:
    task_date = report_task_date(summary)
    generated_date = datetime.now().strftime("%Y-%m-%d")
    unique_count = int(summary.get("unique_candidate_count", len(formal_df)) or 0)
    high = risk_count(formal_df, "high")
    medium = risk_count(formal_df, "medium")
    low = risk_count(formal_df, "low")
    scores = score_series(formal_df)
    basic = [
        ["项目", "内容"],
        ["项目名称", "APTHunter"],
        ["报告名称", "APTHunter 仿冒域名检测总览报告"],
        ["报告编号", f"APTHunter-IMD-Summary-{task_date.replace('-', '') or 'unknown'}-001"],
        ["检测周期", task_date or "-"],
        ["生成时间", generated_date],
        ["数据来源", f"{report_chinese_date(task_date)} APTHunter 新注册域名检测任务结果"],
        ["检测范围", "面向受保护单位、品牌、政府、教育、金融、云服务等目标的疑似仿冒域名检测"],
        ["结果口径", f"正式告警去重候选结果（{fmt_int(unique_count)} 条）"],
        ["原始输入域名数", f"{fmt_int(summary.get('input_domain_count', 0))} 条（任务运行统计）"],
        [
            "规则召回候选对",
            f"{fmt_int(summary.get('recalled_count', 0))} 个待检测域名 × 受保护目标域名候选对（任务运行统计）",
        ],
        ["最终输出候选对", f"{fmt_int(summary.get('output_count', 0))} 条（任务运行统计）"],
        ["去重后正式候选域名", f"{fmt_int(unique_count)} 条"],
        [
            "高价值目标人工复核池",
            f"{fmt_int(summary.get('high_value_review_count', len(high_value_review_df)))} 条（独立人工复核池，不与正式告警混合统计）",
        ],
        ["模型版本", "2026 年 6 月 29 日拼写泛词防护重训模型"],
        ["报告数据文件", "本次任务去重候选明细文件"],
    ]
    indicators = [
        ["指标", "数值", "指标", "数值"],
        ["检测输入", fmt_int(summary.get("input_domain_count", 0)), "正式去重候选", fmt_int(unique_count)],
        ["高风险", fmt_int(high), "中风险", fmt_int(medium)],
        ["低风险", fmt_int(low), "高价值目标人工复核池", fmt_int(summary.get("high_value_review_count", len(high_value_review_df)))],
        ["平均最终风险分", fmt_float(scores.mean() if len(scores) else 0), "最高最终风险分", fmt_float(scores.max() if len(scores) else 0)],
    ]
    categories = [["主仿冒类型", "数量", "占比", "平均风险分", "高风险数量", "主要风险说明"]]
    categories.extend(category_summary_rows(formal_df))
    risks = [["风险等级", "域名数量", "占比", "平均风险分", "处置建议"]]
    risks.extend(risk_summary_rows(formal_df))
    target_types = [["目标类型", "数量", "占比", "平均风险分", "高风险", "中风险", "低风险"]]
    target_types.extend(target_type_summary_rows(formal_df))
    targets = [["匹配目标", "官方域名", "目标类型", "候选数", "平均分", "高/中/低"]]
    targets.extend(top_target_rows(formal_df, limit=None))
    top_risks = [["序号", "疑似仿冒域名", "匹配目标", "风险分", "主类型", "主要依据"]]
    top_risks.extend(top_risk_detail_rows(formal_df, limit=None))
    high_value = [["序号", "候选域名", "匹配目标", "官方域名", "风险分", "等级", "主类型"]]
    high_value.extend(high_value_detail_rows(high_value_review_df, limit=20))
    evidence_static = [
        ["证据维度", "主要内容", "在报告中的含义"],
        ["目标词命中", "候选主体包含或近似包含目标域名主体、品牌词、机构词、拼音或缩写", "说明候选与具体保护目标存在文本关联"],
        ["风险上下文", "登录、验证、安全、账户、虚拟专用网络、单点登录和支付等风险语境", "提升业务入口、账号或支付仿冒的可疑程度"],
        ["结构与后缀", "连字符、数字、长度异常、后缀替换、可疑后缀", "识别常见构造方式，但不单独作为确认依据"],
        ["拼写与视觉变体", "编辑距离、字符交换、数字字母替换、视觉混淆", "识别拼写错误与视觉混淆式仿冒"],
        ["历史模板", "字符片段与历史模式相似度", "辅助发现重复使用的命名模板"],
    ]
    suggestions = [["对象", "建议动作", "具体措施"]]
    suggestions.extend(review_suggestion_rows(unique_count, high, medium, low, int(summary.get("high_value_review_count", len(high_value_review_df)) or 0)))
    return [basic, indicators, categories, risks, target_types, targets, top_risks, high_value, evidence_static, suggestions]


def render_prediction_word_report_from_template(
    summary: dict[str, Any],
    output: str | Path,
    template: str | Path = DEFAULT_WORD_REPORT_TEMPLATE,
) -> None:
    template_path = Path(template)
    if not template_path.exists():
        raise FileNotFoundError(f"report template not found: {template_path}")

    result_df = read_report_csv(summary.get("output", ""))
    unique_df = read_report_csv(summary.get("unique_output", ""))
    high_value_review_df = read_report_csv(summary.get("high_value_review_output", ""))
    formal_df = unique_df if not unique_df.empty else result_df
    formal_df = formal_df.copy()
    high_value_review_df = high_value_review_df.copy()
    task_date = report_task_date(summary)
    unique_count = int(summary.get("unique_candidate_count", len(formal_df)) or 0)
    high = risk_count(formal_df, "high")
    medium = risk_count(formal_df, "medium")
    low = risk_count(formal_df, "low")
    high_value_count = int(summary.get("high_value_review_count", len(high_value_review_df)) or 0)
    typed = add_report_target_type(formal_df)
    brand_finance_count = 0
    if not typed.empty and "_report_target_type" in typed.columns:
        brand_finance_count = int(typed["_report_target_type"].isin(["品牌", "金融"]).sum())
    brand_finance_ratio = fmt_percent(brand_finance_count, unique_count)
    category_rows = category_summary_rows(formal_df)
    main_categories = "、".join(row[0] for row in category_rows[:4]) if category_rows else "多类型仿冒"
    high_prefix_count = 0
    high_service_count = 0
    if not formal_df.empty and "main_category" in formal_df.columns:
        high_df = formal_df[formal_df.get("risk_level", "").astype(str) == "high"]
        high_prefix_count = int((high_df["main_category"].astype(str) == "prefix_suffix").sum())
        high_service_count = int((high_df["main_category"].astype(str) == "service_entry").sum())

    with zipfile.ZipFile(template_path, "r") as source_zip:
        document_xml = source_zip.read("word/document.xml")
        root = ET.fromstring(document_xml)
        tables = list(root.iter(f"{DOCX_W_NS}tbl"))
        table_data = build_template_report_tables(summary, formal_df, high_value_review_df)
        for table, rows in zip(tables, table_data):
            set_template_table(table, rows)

        set_first_paragraph_starting_with(
            root,
            "本报告基于 APTHunter",
            (
                "本报告基于 APTHunter 仿冒域名检测任务结果编制，主体统计以去重后的正式候选域名为口径。"
                "输入量、规则召回量、候选对输出量及高价值目标人工复核池规模均引用本次任务运行摘要；"
                "报告未纳入域名解析、注册信息、网页、证书或外部情报验证结论。"
            ),
        )
        set_paragraph_after_heading(
            root,
            "二、总体检测结论",
            1,
            (
                f"本统计周期内，APTHunter 仿冒域名检测系统共对 {fmt_int(summary.get('input_domain_count', 0))} "
                f"条新注册域名执行检测。经规则召回与多模型融合评分后，最终形成 {fmt_int(unique_count)} "
                f"条去重后的正式疑似仿冒候选域名，其中高风险 {fmt_int(high)} 条、中风险 {fmt_int(medium)} "
                f"条、低风险 {fmt_int(low)} 条。正式候选主要匹配品牌与金融类受保护目标，共 {fmt_int(brand_finance_count)} "
                f"条，占全部正式候选的 {brand_finance_ratio}。"
            ),
        )
        set_paragraph_after_heading(
            root,
            "二、总体检测结论",
            2,
            (
                f"从 APTHunter 的仿冒类型识别结果看，{main_categories} 为本期主要形态。"
                f"高风险候选中，前后缀仿冒 {fmt_int(high_prefix_count)} 条、业务入口仿冒 {fmt_int(high_service_count)} 条，"
                "说明“明确目标词 + 登录/认证/安全等风险语境 + 结构或后缀异常”仍是主要高置信触发模式。"
            ),
        )
        set_paragraph_after_heading(
            root,
            "二、总体检测结论",
            3,
            (
                "需要注意的是：本报告中的候选结果仅基于 APTHunter 的域名字符串、目标画像、规则召回和传统机器学习模型进行判断。"
                "系统未在本次报告范围内使用域名解析、域名注册信息、证书、网页内容或外部威胁情报，"
                "因此建议将高风险结果作为优先人工核验对象，而不是直接视为已确认恶意域名。"
            ),
        )
        set_first_paragraph_starting_with(
            root,
            "本期主仿冒类型",
            (
                "本期主仿冒类型按照 APTHunter 模型输出的“主仿冒类型”统计。"
                "单个候选可能同时命中多个仿冒类别，本节以“主类型”口径展示，便于反映本期最主要的仿冒手法分布。"
            ),
        )
        set_first_paragraph_starting_with(
            root,
            "APTHunter 的风险等级",
            "APTHunter 的风险等级由模型融合分数与强规则兜底策略共同确定；高风险不等于已经确认的恶意域名，中低风险也不表示完全无风险。",
        )
        set_first_paragraph_starting_with(
            root,
            "本期正式候选按",
            (
                "APTHunter 正式候选按“匹配目标类型”进行统计。品牌类目标通常占主要比例；"
                "政府、教育、金融和云服务等高价值目标即使正式告警数量较少，也会进入高价值目标人工复核池进行补充观察。"
            ),
        )
        set_first_paragraph_starting_with(root, "5.1 ", "5.1 匹配目标分布（全量）")
        set_first_paragraph_starting_with(
            root,
            "本期正式去重候选中",
            (
                f"本期正式去重候选中，高价值目标相关结果需结合人工复核池一起观察。"
                f"本次高价值目标人工复核池共 {fmt_int(high_value_count)} 条，主要用于发现低分但值得关注的政府、教育、金融和云服务候选。"
            ),
        )
        set_first_paragraph_starting_with(root, "7.1 ", "7.1 正式疑似仿冒域名全量清单")
        set_first_paragraph_starting_with(root, "7.2 ", "7.2 高价值目标候选人工复核池（Top 20）")

        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as target_zip:
            for item in source_zip.infolist():
                data = source_zip.read(item.filename)
                if item.filename == "word/document.xml":
                    data = ET.tostring(root, encoding="utf-8", xml_declaration=True)
                target_zip.writestr(item, data)


def write_prediction_word_report(summary: dict[str, Any], output: str | Path) -> None:
    output_path = Path(output)
    if DEFAULT_WORD_REPORT_TEMPLATE.exists():
        try:
            render_prediction_word_report_from_template(summary, output_path, DEFAULT_WORD_REPORT_TEMPLATE)
        except PermissionError:
            fallback = output_path.with_name(
                f"{output_path.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{output_path.suffix}"
            )
            render_prediction_word_report_from_template(summary, fallback, DEFAULT_WORD_REPORT_TEMPLATE)
            print(f"word_report_output_locked={output_path}; wrote_fallback={fallback}")
        return

    result_df = read_report_csv(summary.get("output", ""))
    unique_df = read_report_csv(summary.get("unique_output", ""))
    high_value_review_df = read_report_csv(summary.get("high_value_review_output", ""))
    formal_df = unique_df if not unique_df.empty else result_df
    formal_scores = score_series(formal_df)
    task_date = report_task_date(summary)
    task_name = report_task_name(summary)
    high_count = risk_count(formal_df, "high")
    medium_count = risk_count(formal_df, "medium")
    low_count = risk_count(formal_df, "low")
    top_category = "-"
    if not formal_df.empty and "main_category" in formal_df.columns:
        category_key = str(formal_df["main_category"].value_counts().idxmax())
        top_category = CATEGORY_LABELS.get(category_key, category_key)
    top_type = "-"
    if not formal_df.empty:
        typed = add_report_target_type(formal_df)
        if "_report_target_type" in typed.columns and not typed["_report_target_type"].empty:
            top_type = str(typed["_report_target_type"].value_counts().idxmax())

    body: list[str] = [
        docx_paragraph("APTHunter 仿冒域名检测总览报告", bold=True, size=42, color="0F172A", align="center"),
        docx_paragraph(f"检测任务：{task_name}", size=22, color="475569", align="center"),
        docx_paragraph(f"检测日期：{task_date or '-'}", size=22, color="475569", align="center"),
        docx_heading("一、任务基本信息"),
        docx_table(
            ["项目", "内容"],
            [
                ["项目名称", "APTHunter 仿冒域名检测"],
                ["报告编号", f"APTHunter-IMD-Summary-{task_date.replace('-', '') or 'unknown'}-001"],
                ["检测任务", task_name],
                ["检测日期", task_date or "-"],
                ["数据来源", f"{task_date or '本次'} 新注册域名清单"],
                ["模型版本", "2026-06-29 typo word guard retrain"],
                ["判别输入边界", "仅使用域名字符串、目标画像、历史样本、人工复核标签和本地传统模型"],
            ],
        ),
        docx_heading("二、执行摘要"),
        docx_paragraph(
            f"本次检测共处理 {fmt_int(summary.get('input_domain_count', 0))} 条新注册域名，"
            f"基于 {fmt_int(summary.get('target_count', 0))} 个受保护目标画像进行规则召回，"
            f"形成 {fmt_int(summary.get('recalled_count', 0))} 个候选对并完成模型打分。"
        ),
        docx_paragraph(
            f"按当前阈值输出正式候选对 {fmt_int(summary.get('output_count', 0))} 条，"
            f"按候选域名去重后为 {fmt_int(summary.get('unique_candidate_count', 0))} 条。"
            f"其中高风险 {fmt_int(high_count)} 条，中风险 {fmt_int(medium_count)} 条，低风险 {fmt_int(low_count)} 条。"
            f"主要仿冒类型为 {top_category}，主要匹配目标类型为 {top_type}。"
        ),
        docx_paragraph(
            "本报告结果仅代表 APTHunter 基于域名字符串和本地模型的风险判断，"
            "未使用 DNS、WHOIS、证书、网页内容、搜索引擎结果或 LLM 判断作为 V1 必需输入。"
        ),
        docx_heading("三、关键指标"),
        docx_table(
            ["指标", "数值"],
            [
                ["受保护目标数", fmt_int(summary.get("target_count", 0))],
                ["原始新注册域名数", fmt_int(summary.get("input_domain_count", 0))],
                ["规则召回候选对", fmt_int(summary.get("recalled_count", 0))],
                ["模型打分候选对", fmt_int(summary.get("scored_count", 0))],
                ["正式输出候选对", fmt_int(summary.get("output_count", 0))],
                ["去重正式候选域名", fmt_int(summary.get("unique_candidate_count", 0))],
                ["高价值目标人工 review 池", fmt_int(summary.get("high_value_review_count", 0))],
                ["平均最终风险分", fmt_float(formal_scores.mean() if len(formal_scores) else 0.0)],
                ["最高最终风险分", fmt_float(formal_scores.max() if len(formal_scores) else 0.0)],
            ],
        ),
        docx_heading("四、风险等级分布"),
        docx_table(["风险等级", "数量", "占比", "平均风险分", "建议动作"], risk_summary_rows(formal_df)),
        docx_paragraph("风险等级由融合模型分数、规则证据和强规则兜底策略共同确定。"),
        docx_heading("五、仿冒类型统计"),
        docx_table(
            ["仿冒类型", "数量", "占比", "平均风险分", "高风险数量", "说明"],
            category_summary_rows(formal_df),
        ),
        docx_paragraph("一条域名可能同时命中多个仿冒类型，表格按 main_category 统计主要形态分布。"),
        docx_heading("六、被仿冒目标类型分析"),
        docx_table(
            ["目标类型", "数量", "占比", "平均风险分", "高/中/低风险"],
            [
                [row[0], row[1], row[2], row[3], f"{row[4]}/{row[5]}/{row[6]}"]
                for row in target_type_summary_rows(formal_df)
            ],
        ),
        docx_heading("七、重点匹配目标分布"),
        docx_table(
            ["匹配目标", "官方域名", "目标类型", "候选数", "平均分", "高/中/低"],
            top_target_rows(formal_df),
        ),
        docx_heading("八、高价值目标人工 review 池"),
        docx_paragraph(
            f"本次额外生成高价值目标人工 review 池 {fmt_int(len(high_value_review_df))} 条。"
            "该文件包含部分未达到正式告警阈值但涉及政府、教育、金融、云服务等目标的候选，"
            "用于人工抽查和补充样本，不等同于正式告警。"
        ),
        docx_table(["review 风险等级", "数量", "平均风险分"], high_value_review_rows(high_value_review_df)),
        docx_heading("九、TOP 风险样例"),
        docx_table(["候选域名", "匹配官方域名", "风险等级", "最终分", "主要类型"], example_rows(formal_df)),
        docx_heading("十、复核建议"),
        docx_bullets(
            [
                "优先复核去重结果中的高风险和中风险结果。",
                "对高价值目标 review 池中涉及政府、教育、金融、云服务的候选进行抽样复核。",
                "确认误报样本回灌到 manual_review_labels.csv，标记 review_label=0。",
                "确认仿冒样本回灌到 manual_review_labels.csv，标记 review_label=1，并尽量修正准确 target_domain。",
                "目标归属不明确但明显可疑的域名先进入高价值 review 池或单独记录，不强行绑定具体目标。",
            ]
        ),
        docx_heading("十一、边界与风险提示"),
        docx_bullets(
            [
                "本系统不使用 LLM 作为判别模型。",
                "本系统不依赖 DNS、WHOIS、证书、网页内容、搜索引擎结果或外部威胁情报作为 V1 必需输入。",
                "泛词型目标、短品牌词、一个字母加通用词的官方域名仍可能带来误报或目标归属歧义。",
                "高价值 review 池是人工候选池，不代表正式告警结论。",
            ]
        ),
        docx_heading("十二、输出文件"),
        docx_bullets(
            [
                f"完整结果：{summary.get('output', '')}",
                f"去重结果：{summary.get('unique_output', '')}",
                f"Markdown 报告：{summary.get('report_output', '')}",
                f"Word 报告：{summary.get('word_report_output', '')}",
                f"高价值 review：{summary.get('high_value_review_output', '')}",
            ]
        ),
    ]
    write_docx_package(output, "".join(body))


def convert_docx_to_pdf_with_word(source_docx: str | Path, output_pdf: str | Path) -> None:
    """Convert a DOCX report to PDF through Microsoft Word COM automation."""
    import pythoncom
    import win32com.client

    source_path = Path(source_docx).resolve()
    output_path = Path(output_pdf).resolve()
    if not source_path.exists():
        raise FileNotFoundError(f"source docx not found: {source_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    def com_call(func: Any, retries: int = 20, delay_seconds: float = 0.5) -> Any:
        last_error: Exception | None = None
        for _ in range(retries):
            try:
                return func()
            except Exception as exc:  # pragma: no cover - depends on local Office state
                last_error = exc
                error_code = exc.args[0] if getattr(exc, "args", None) else None
                if error_code != -2147418111:
                    raise
                pythoncom.PumpWaitingMessages()
                time.sleep(delay_seconds)
        if last_error is not None:
            raise last_error
        return None

    pythoncom.CoInitialize()
    word = None
    document = None
    try:
        word = com_call(lambda: win32com.client.DispatchEx("Word.Application"))
        word.Visible = False
        word.DisplayAlerts = 0
        document = com_call(
            lambda: word.Documents.Open(
                FileName=str(source_path),
                ConfirmConversions=False,
                ReadOnly=True,
                AddToRecentFiles=False,
                OpenAndRepair=True,
            )
        )
        com_call(
            lambda: document.ExportAsFixedFormat(
                OutputFileName=str(output_path),
                ExportFormat=17,
                OpenAfterExport=False,
                OptimizeFor=0,
                Range=0,
                Item=0,
                IncludeDocProps=True,
                KeepIRM=True,
                CreateBookmarks=1,
                DocStructureTags=True,
                BitmapMissingFonts=True,
                UseISO19005_1=False,
            )
        )
    finally:
        if document is not None:
            try:
                com_call(lambda: document.Close(False), retries=5)
            except Exception:
                pass
        if word is not None:
            try:
                com_call(lambda: word.Quit(), retries=5)
            except Exception:
                pass
        pythoncom.CoUninitialize()


def write_prediction_pdf_report(
    summary: dict[str, Any],
    output: str | Path,
    source_docx: str | Path | None = None,
) -> None:
    """Write a direct PDF report for one prediction task.

    The PDF renderer intentionally does not depend on Word automation. The
    optional ``source_docx`` argument is kept for backward-compatible callers
    and is ignored.
    """
    output_path = Path(output)

    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont
        from reportlab.platypus import (
            CondPageBreak,
            LongTable,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover - exercised only when dependency is missing
        raise RuntimeError("PDF report output requires the 'reportlab' package. Install requirements.txt.") from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    except Exception:
        pass

    font_name = "STSong-Light"
    page_size = landscape(A4)
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=page_size,
        rightMargin=1.0 * cm,
        leftMargin=1.0 * cm,
        topMargin=1.0 * cm,
        bottomMargin=1.0 * cm,
        title="APTHunter 仿冒域名检测总览报告",
        author="APTHunter",
    )

    sample_styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ChineseTitle",
        parent=sample_styles["Title"],
        fontName=font_name,
        fontSize=20,
        leading=26,
        alignment=TA_CENTER,
        spaceAfter=10,
        textColor=colors.HexColor("#0F172A"),
    )
    subtitle_style = ParagraphStyle(
        "ChineseSubtitle",
        parent=sample_styles["Normal"],
        fontName=font_name,
        fontSize=10,
        leading=14,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#475569"),
        spaceAfter=14,
    )
    heading_style = ParagraphStyle(
        "ChineseHeading",
        parent=sample_styles["Heading2"],
        fontName=font_name,
        fontSize=13,
        leading=17,
        spaceBefore=10,
        spaceAfter=6,
        keepWithNext=True,
        textColor=colors.HexColor("#1E3A8A"),
    )
    subheading_style = ParagraphStyle(
        "ChineseSubHeading",
        parent=sample_styles["Heading3"],
        fontName=font_name,
        fontSize=10.5,
        leading=14,
        spaceBefore=6,
        spaceAfter=4,
        keepWithNext=False,
        textColor=colors.HexColor("#334155"),
    )
    body_style = ParagraphStyle(
        "ChineseBody",
        parent=sample_styles["Normal"],
        fontName=font_name,
        fontSize=9,
        leading=13,
        spaceAfter=6,
        textColor=colors.HexColor("#1F2937"),
    )
    cell_style = ParagraphStyle(
        "ChineseCell",
        parent=sample_styles["Normal"],
        fontName=font_name,
        fontSize=7.2,
        leading=9,
        textColor=colors.HexColor("#1F2937"),
    )
    header_style = ParagraphStyle(
        "ChineseHeaderCell",
        parent=cell_style,
        fontName=font_name,
        fontSize=7.4,
        leading=9,
        textColor=colors.white,
        alignment=TA_CENTER,
    )

    result_df = read_report_csv(summary.get("output", ""))
    unique_df = read_report_csv(summary.get("unique_output", ""))
    high_value_review_df = read_report_csv(summary.get("high_value_review_output", ""))
    formal_df = unique_df if not unique_df.empty else result_df

    def inferred_row_count(path_value: Any) -> int:
        df = read_report_csv(path_value)
        return int(len(df)) if not df.empty else 0

    def summary_count(key: str, fallback: int = 0) -> int:
        try:
            value = int(float(summary.get(key, 0) or 0))
        except (TypeError, ValueError):
            value = 0
        return value if value > 0 else int(fallback)

    task_date = report_task_date(summary)
    task_name = report_task_name(summary)
    input_domain_count = summary_count("input_domain_count", inferred_row_count(summary.get("input", "")))
    target_count = summary_count(
        "target_count",
        inferred_row_count(summary.get("targets", "")) or inferred_row_count("data/interim/target_profiles.csv"),
    )
    output_count = summary_count("output_count", len(result_df))
    unique_candidate_count = summary_count("unique_candidate_count", len(formal_df))
    high_value_review_count = summary_count("high_value_review_count", len(high_value_review_df))
    scored_count = summary_count("scored_count", len(result_df))
    recalled_count = summary_count("recalled_count", scored_count or output_count)
    high_count = risk_count(formal_df, "high")
    medium_count = risk_count(formal_df, "medium")
    low_count = risk_count(formal_df, "low")
    formal_scores = score_series(formal_df)
    risk_labels = {"high": "高风险", "medium": "中风险", "low": "低风险", "ignore": "忽略"}
    risk_actions = {
        "high": "优先人工复核并进入处置流程",
        "medium": "结合目标重要性分层复核",
        "low": "持续观察，必要时补充样本",
        "ignore": "默认不告警",
    }
    category_labels = {
        "brand_combo": "品牌组合",
        "prefix_suffix": "前后缀仿冒",
        "service_entry": "业务入口仿冒",
        "typo": "拼写错误",
        "confusable": "视觉混淆",
        "hyphenation": "连字符变体",
        "tld_replace": "后缀替换",
        "subdomain_deception": "子域名欺骗",
        "pinyin_abbr": "拼音/缩写仿冒",
        "template_reuse": "历史模板复用",
        "high_value_generic_impersonation": "高价值泛化仿冒",
        "other_suspicious": "其他可疑",
    }
    category_descriptions = {
        "brand_combo": "目标品牌词与其他词组合。",
        "prefix_suffix": "目标词位于前缀或后缀，并拼接诱导词。",
        "service_entry": "包含 login、auth、mail、vpn、support 等入口词。",
        "typo": "与目标主体存在少字、多字、换字或相邻字符交换。",
        "confusable": "存在 0/o、1/l、q/g、punycode 等视觉混淆。",
        "hyphenation": "通过连字符拆分或拼接目标词。",
        "tld_replace": "主体相同或相近，但后缀发生变化。",
        "subdomain_deception": "目标词出现在子域名位置。",
        "pinyin_abbr": "命中中文单位拼音、首字母或缩写。",
        "template_reuse": "复用历史高频仿冒模板。",
        "high_value_generic_impersonation": "包含政府、教育、金融等泛化高价值语义。",
        "other_suspicious": "存在可疑证据但未归入具体类型。",
    }
    tier_labels = {
        "gov": "政府",
        "edu": "教育",
        "finance": "金融",
        "cloud": "云服务",
        "ecommerce": "电商",
        "media": "媒体",
        "brand": "品牌",
        "other": "其他",
    }

    def para(value: Any, style: ParagraphStyle = body_style) -> Paragraph:
        safe = xml_escape(text(value)).replace("\n", "<br/>")
        return Paragraph(safe or "-", style)

    def pdf_risk_label(value: Any) -> str:
        return risk_labels.get(text(value).lower(), text(value) or "-")

    def pdf_category_label(value: Any) -> str:
        return category_labels.get(text(value), text(value) or "其他可疑")

    def pdf_target_type(row: pd.Series) -> str:
        tier = text(row.get("target_tier")).lower()
        if tier:
            return tier_labels.get(tier, tier)
        subtype = text(row.get("target_subtype"))
        if subtype:
            return subtype
        return text(row.get("matched_target_type")) or "其他"

    def pdf_evidence(row: pd.Series) -> str:
        features = text(row.get("matched_features")).lower()
        recall = text(row.get("recall_reason")).lower()
        parts: list[str] = []
        if recall == "risk_word_combo" or "risk_words:" in features:
            parts.append("风险词组合")
        elif recall == "spelling_variant_match":
            parts.append("拼写变体")
        elif recall == "transposition_match":
            parts.append("字符交换")
        elif recall == "confusable_match":
            parts.append("视觉混淆")
        elif recall == "tld_replace":
            parts.append("后缀替换")
        elif recall == "subdomain_deception":
            parts.append("子域名欺骗")
        elif recall == "exact_match" or "contains_target_sld" in features:
            parts.append("目标词命中")
        elif recall:
            parts.append("规则命中")
        for feature_key, label in [
            ("suspicious_tld", "可疑后缀"),
            ("suffix_changed", "后缀变化"),
            ("hyphenation", "连字符"),
            ("contains_target_sld_confusable_norm", "混淆归一命中"),
            ("contains_target_sld", "包含目标主体"),
            ("strong_rule_fallback", "强规则兜底"),
        ]:
            if feature_key in features and label not in parts:
                parts.append(label)
        return " / ".join(parts[:4]) or pdf_category_label(row.get("main_category"))

    def pdf_risk_summary_rows(df: pd.DataFrame) -> list[list[str]]:
        total = len(df)
        rows: list[list[str]] = []
        for level in ("high", "medium", "low"):
            subset = df[df.get("risk_level", pd.Series(dtype=str)).fillna("").astype(str) == level]
            rows.append(
                [
                    pdf_risk_label(level),
                    fmt_int(len(subset)),
                    fmt_percent(len(subset), total),
                    fmt_float(score_series(subset).mean() if not subset.empty else 0.0),
                    risk_actions[level],
                ]
            )
        return rows

    def pdf_category_summary_rows(df: pd.DataFrame, limit: int = 12) -> list[list[str]]:
        if df.empty or "main_category" not in df.columns:
            return []
        total = len(df)
        rows: list[list[str]] = []
        grouped = df.groupby(df["main_category"].fillna("other_suspicious").astype(str), dropna=False)
        for category, group in sorted(grouped, key=lambda item: len(item[1]), reverse=True)[:limit]:
            rows.append(
                [
                    pdf_category_label(category),
                    fmt_int(len(group)),
                    fmt_percent(len(group), total),
                    fmt_float(score_series(group).mean()),
                    fmt_int(risk_count(group, "high")),
                    category_descriptions.get(category, ""),
                ]
            )
        return rows

    def pdf_target_type_summary_rows(df: pd.DataFrame, limit: int = 12) -> list[list[str]]:
        if df.empty:
            return []
        typed = df.copy()
        typed["_pdf_target_type"] = typed.apply(pdf_target_type, axis=1)
        total = len(typed)
        rows: list[list[str]] = []
        grouped = typed.groupby("_pdf_target_type", dropna=False)
        for target_type, group in sorted(grouped, key=lambda item: len(item[1]), reverse=True)[:limit]:
            rows.append(
                [
                    text(target_type) or "其他",
                    fmt_int(len(group)),
                    fmt_percent(len(group), total),
                    fmt_float(score_series(group).mean()),
                    f"{risk_count(group, 'high')}/{risk_count(group, 'medium')}/{risk_count(group, 'low')}",
                ]
            )
        return rows

    def pdf_detail_rows(df: pd.DataFrame, limit: int | None = None) -> list[list[str]]:
        if df.empty:
            return []
        report_df = df.copy()
        report_df["_score"] = score_series(report_df)
        report_df = report_df.sort_values("_score", ascending=False)
        if limit is not None:
            report_df = report_df.head(limit)
        rows: list[list[str]] = []
        for index, (_, row) in enumerate(report_df.iterrows(), start=1):
            rows.append(
                [
                    index,
                    text(row.get("candidate_domain")) or "-",
                    text(row.get("matched_target_name")) or text(row.get("matched_target_domain")) or "-",
                    fmt_float(row.get("final_score")),
                    pdf_category_label(row.get("main_category")),
                    pdf_evidence(row),
                ]
            )
        return rows

    def pdf_high_value_rows(review_df: pd.DataFrame, limit: int = 20) -> list[list[str]]:
        if review_df.empty:
            return []
        report_df = review_df.copy()
        report_df["_review_score"] = pd.to_numeric(
            report_df.get("high_value_review_score", 0), errors="coerce"
        ).fillna(0.0)
        report_df["_score"] = score_series(report_df)
        report_df = report_df.sort_values(["_review_score", "_score"], ascending=[False, False]).head(limit)
        rows: list[list[str]] = []
        for index, (_, row) in enumerate(report_df.iterrows(), start=1):
            rows.append(
                [
                    index,
                    text(row.get("candidate_domain")) or "-",
                    text(row.get("matched_target_name")) or "高价值泛化候选",
                    text(row.get("matched_target_domain")) or "-",
                    fmt_float(row.get("final_score")),
                    pdf_risk_label(row.get("risk_level")),
                    pdf_category_label(row.get("main_category")),
                ]
            )
        return rows

    def pdf_review_suggestion_rows() -> list[list[str]]:
        return [
            ["高风险候选", "优先人工复核", "核验目标归属、风险词、后缀变化和是否存在登录/支付/账号诱导。"],
            ["中风险候选", "分层复核", "优先处理金融、政府、教育、云服务等高价值目标。"],
            ["低风险候选", "持续观察", "结合重复出现、人工复核和后续样本回灌再升级。"],
            ["高价值 review 池", "独立抽查", "不等同正式告警，用于发现低分漏报和目标错配。"],
            ["人工回灌", "闭环优化", "确认正样本写入 review_label=1，确认误报写入 review_label=0。"],
        ]

    def table(headers: Sequence[Any], rows: Sequence[Sequence[Any]], widths: Sequence[float] | None = None) -> LongTable:
        data = [[para(header, header_style) for header in headers]]
        data.extend([[para(item, cell_style) for item in row] for row in rows])
        col_widths = list(widths) if widths else None
        result = LongTable(data, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.white),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        result.setStyle(TableStyle(style_commands))
        setattr(result, "_apthunter_data", data)
        setattr(result, "_apthunter_col_widths", col_widths)
        setattr(result, "_apthunter_style_commands", style_commands)
        return result

    def stabilize_pdf_story(flowables: Sequence[Any]) -> list[Any]:
        """Add report pagination hints without coupling to section text."""
        stabilized: list[Any] = []
        for flowable in flowables:
            style_name = getattr(getattr(flowable, "style", None), "name", "")
            if style_name == "ChineseHeading":
                stabilized.append(CondPageBreak(1.4 * cm))
                stabilized.append(flowable)
                continue
            if style_name == "ChineseSubHeading":
                stabilized.append(CondPageBreak(2.2 * cm))
                stabilized.append(flowable)
                continue
            stabilized.append(flowable)
        return stabilized

    def build_word_like_pdf_story() -> list[Any]:
        """Build a PDF report with the same chapter logic as the legacy Word report."""
        category_rows = pdf_category_summary_rows(formal_df)
        target_type_rows = pdf_target_type_summary_rows(formal_df)
        top_targets = top_target_rows(formal_df, limit=20)

        category_names = [row[0] for row in category_rows[:4]]
        category_text = "、".join(category_names) if category_names else "多类型疑似仿冒"
        target_type_names = [row[0] for row in target_type_rows[:4]]
        target_type_text = "、".join(target_type_names) if target_type_names else "品牌、金融、云服务等目标"

        category_series = (
            formal_df["main_category"].fillna("").astype(str)
            if "main_category" in formal_df.columns
            else pd.Series(dtype=str)
        )
        prefix_count = int((category_series == "prefix_suffix").sum())
        service_count = int((category_series == "service_entry").sum())
        typo_count = int((category_series == "typo").sum())
        confusable_count = int((category_series == "confusable").sum())
        hyphen_count = int((category_series == "hyphenation").sum())
        tld_count = int((category_series == "tld_replace").sum())

        high_df = (
            formal_df[formal_df["risk_level"].fillna("").astype(str) == "high"]
            if "risk_level" in formal_df.columns
            else formal_df.iloc[0:0]
        )
        high_category_series = (
            high_df["main_category"].fillna("").astype(str)
            if "main_category" in high_df.columns
            else pd.Series(dtype=str)
        )
        high_main_text = (
            "、".join(
                pdf_category_label(category)
                for category in high_category_series.value_counts().head(3).index.tolist()
                if category
            )
            or "高风险品牌组合与业务入口仿冒"
        )

        return [
            Paragraph("APTHunter 仿冒域名检测总览报告", title_style),
            Paragraph(f"检测任务：{task_name}　检测日期：{task_date or '-'}", subtitle_style),
            Paragraph("一、报告基本信息", heading_style),
            Paragraph(
                "本报告基于 APTHunter 仿冒域名检测任务结果编制，面向新注册域名，"
                "识别与受保护单位、品牌、机构官方域名高度相似且具有误导性的疑似仿冒域名。"
                "报告内容包括总体检测结论、风险等级分布、仿冒类型统计、目标类型分析、重点样本清单及处置建议。",
                body_style,
            ),
            table(
                ["项目", "内容"],
                [
                    ["项目名称", "APTHunter 仿冒域名检测"],
                    ["报告编号", f"APTHunter-IMD-Summary-{task_date.replace('-', '') or 'unknown'}-001"],
                    ["检测任务", task_name],
                    ["检测日期", task_date or "-"],
                    ["数据来源", f"{task_date or '-'} APTHunter 新注册域名检测任务结果"],
                    ["模型版本", "2026-06-29 typo word guard retrain"],
                    ["检测边界", "仅基于域名字符串、目标画像、历史样本、人工复核标签和本地传统机器学习模型。"],
                ],
                widths=[4.2 * cm, 21.0 * cm],
            ),
            Paragraph("二、总体检测结论", heading_style),
            Paragraph(
                (
                    f"本次检测共处理 {fmt_int(input_domain_count)} 条新注册域名，"
                    f"基于 {fmt_int(target_count)} 个受保护目标画像进行规则召回，"
                    f"形成 {fmt_int(recalled_count)} 个候选对并完成模型融合打分。"
                ),
                body_style,
            ),
            Paragraph(
                (
                    f"检测后正式输出疑似仿冒候选对 {fmt_int(output_count)} 条，"
                    f"按候选域名去重后为 {fmt_int(unique_candidate_count)} 条。"
                    f"其中高风险 {fmt_int(high_count)} 条、中风险 {fmt_int(medium_count)} 条、低风险 {fmt_int(low_count)} 条。"
                ),
                body_style,
            ),
            Paragraph(
                (
                    f"从类型上看，本轮结果主要集中在 {category_text}；"
                    f"从被仿冒目标看，主要涉及 {target_type_text}。"
                    "低风险和高价值 review 池结果主要用于人工抽查与样本回灌，不等同于全部直接告警。"
                ),
                body_style,
            ),
            Paragraph("三、仿冒域名类型统计", heading_style),
            Paragraph(
                "本节按照模型输出的主要仿冒类型进行统计。一个域名可能同时命中多个规则或模型类别，"
                "表中主要类型用于报告展示，完整多标签结果以 all_categories 字段为准。",
                body_style,
            ),
            table(
                ["仿冒类型", "数量", "占比", "平均风险分", "高风险数量", "说明"],
                category_rows,
                widths=[3.0 * cm, 1.8 * cm, 1.8 * cm, 2.2 * cm, 2.0 * cm, 15.0 * cm],
            ),
            Paragraph("四、风险等级分布", heading_style),
            Paragraph(
                "风险等级由最终融合分数映射生成：高风险优先处置，中风险结合目标重要性复核，"
                "低风险用于观察和主动学习。该分级不依赖 WHOIS、DNS、网页内容或外部威胁情报。",
                body_style,
            ),
            table(["风险等级", "数量", "占比", "平均风险分", "建议动作"], pdf_risk_summary_rows(formal_df)),
            Paragraph("五、被仿冒目标类型分析", heading_style),
            Paragraph(
                "本节从被仿冒目标维度观察候选分布，用于判断风险是否集中在金融、政府、教育、云服务等高价值目标，"
                "并辅助后续制定分层处置策略。",
                body_style,
            ),
            table(
                ["目标类型", "数量", "占比", "平均风险分", "高/中/低风险"],
                target_type_rows,
            ),
            Paragraph("5.1 匹配目标分布（Top 20）", subheading_style),
            table(
                ["目标名称", "目标域名", "目标类型", "数量", "平均风险分", "高/中/低风险"],
                top_targets,
                widths=[5.0 * cm, 5.0 * cm, 2.6 * cm, 1.8 * cm, 2.2 * cm, 2.4 * cm],
            ),
            Paragraph("5.2 高价值目标观察", subheading_style),
            Paragraph(
                (
                    f"本轮高价值目标人工 review 池共包含 {fmt_int(high_value_review_count)} 条候选。"
                    "该池主要用于发现低分漏报、目标错配和高价值泛化仿冒，不作为正式告警直接下发。"
                ),
                body_style,
            ),
            Paragraph("六、各类疑似仿冒域名分析", heading_style),
            Paragraph("6.1 前后缀与业务入口仿冒", subheading_style),
            Paragraph(
                (
                    f"前后缀仿冒和业务入口仿冒分别检出 {fmt_int(prefix_count)} 条、"
                    f"{fmt_int(service_count)} 条。这类样本通常在目标主体前后拼接 login、auth、support、account、mail、vpn 等诱导词，"
                    "容易被误认为官方登录、客服、账号或运维入口。"
                ),
                body_style,
            ),
            Paragraph("6.2 拼写错误与视觉混淆", subheading_style),
            Paragraph(
                (
                    f"拼写错误与视觉混淆分别检出 {fmt_int(typo_count)} 条、{fmt_int(confusable_count)} 条。"
                    "系统会结合编辑距离、相邻字符交换、重复字符、视觉混淆字符和字符 n-gram 模型识别该类样本。"
                    "对 tiger、cloud、chain 等泛词驱动的拼写相似误报，已通过可配置 token policy 和规则阻断进行压制。"
                ),
                body_style,
            ),
            Paragraph("6.3 后缀替换与结构欺骗", subheading_style),
            Paragraph(
                (
                    f"后缀替换和连字符变体分别检出 {fmt_int(tld_count)} 条、{fmt_int(hyphen_count)} 条。"
                    "该类样本常见于主体相同或高度相似但顶级域变化、使用可疑 TLD、或通过连字符拆分目标主体的场景。"
                ),
                body_style,
            ),
            Paragraph("6.4 高风险类别集中性", subheading_style),
            Paragraph(
                (
                    f"高风险样本主要集中在 {high_main_text}。这些样本通常同时满足目标词命中、诱导词组合、"
                    "可疑后缀、视觉混淆或强规则兜底等多项证据，因此进入优先复核和处置队列。"
                ),
                body_style,
            ),
            Paragraph("七、重点疑似仿冒域名清单", heading_style),
            Paragraph("7.1 正式疑似仿冒域名全量清单", subheading_style),
            Paragraph(
                "下表列出本次正式输出的疑似仿冒域名清单。为控制版面，主要依据字段进行了摘要化展示；"
                "更完整的命中特征与模型分数可在 CSV 结果文件中查看。",
                body_style,
            ),
            table(
                ["序号", "候选域名", "匹配目标", "最终分", "主要类型", "主要依据"],
                pdf_detail_rows(formal_df, limit=None),
                widths=[1.1 * cm, 5.4 * cm, 5.2 * cm, 1.7 * cm, 3.0 * cm, 9.8 * cm],
            ),
            Paragraph("7.2 高价值目标候选人工复核池（Top 20）", subheading_style),
            Paragraph(
                "下表展示高价值目标人工复核池中的 Top 20 候选。该列表用于发现潜在漏报和目标错配，"
                "其中样本需经人工确认后再回灌训练集。",
                body_style,
            ),
            table(
                ["序号", "候选域名", "目标名称", "目标域名", "最终分", "风险", "类型"],
                pdf_high_value_rows(high_value_review_df, limit=20),
                widths=[1.1 * cm, 5.0 * cm, 5.0 * cm, 4.4 * cm, 1.6 * cm, 1.4 * cm, 4.0 * cm],
            ),
            Paragraph("7.3 中低风险候选处置原则", subheading_style),
            Paragraph("中风险候选建议结合目标类型、命中特征和历史复核结果进行人工确认。", body_style),
            Paragraph("低风险候选默认不直接告警，可纳入主动学习抽样或持续观察。", body_style),
            Paragraph("高价值目标相关低分样本应保留在 review 通道中，避免因阈值过高造成漏报。", body_style),
            Paragraph("八、检测证据说明与报告边界", heading_style),
            Paragraph(
                "本报告的检测证据来自域名字符串、官方目标画像、规则召回、传统机器学习模型分数和历史人工复核样本。"
                "报告不会编造 DNS、WHOIS、证书、网页内容或外部情报结论。",
                body_style,
            ),
            Paragraph("8.1 报告边界", subheading_style),
            Paragraph("本报告仅用于仿冒域名风险研判和人工复核辅助，不代表域名已经实际投递攻击。", body_style),
            Paragraph("若需进入封禁、通报或执法流程，建议结合访问日志、解析记录、页面内容、证书和业务侧确认进一步核验。", body_style),
            Paragraph("低分但涉及政府、教育、金融等目标的候选，应优先通过人工 review 池进行抽查。", body_style),
            Paragraph("九、总体处置建议", heading_style),
            Paragraph(
                "建议优先复核高风险候选；对高价值目标的中低风险候选进行分层抽查；"
                "对确认误报和确认仿冒样本持续写入人工复核标签，用于压制泛词误报并增强高价值目标召回能力。",
                body_style,
            ),
            table(["对象", "动作", "说明"], pdf_review_suggestion_rows()),
            Paragraph("十、报告结论", heading_style),
            Paragraph(
                (
                    f"本次检测在 {fmt_int(input_domain_count)} 条新注册域名中，"
                    f"识别出 {fmt_int(unique_candidate_count)} 条去重后的疑似仿冒候选，"
                    f"其中高风险 {fmt_int(high_count)} 条。整体看，检测结果主要集中在 {category_text}，"
                    "符合近期仿冒域名以品牌词拼接、业务入口诱导和拼写变体为主的特征。"
                ),
                body_style,
            ),
            Paragraph(
                "本轮输出结果建议作为安全运营和人工复核的优先级参考。对高风险候选应尽快确认与处置；"
                "对中低风险和高价值 review 池候选，应结合业务上下文进行抽查，确认后回灌人工标签。",
                body_style,
            ),
            Paragraph(
                "后续优化重点仍然是：持续清理泛词目标和官方别名、补充高价值目标真实正样本、"
                "校准拼写错误类模型阈值，并通过每日人工复核闭环降低误报与漏报。",
                body_style,
            ),
        ]

    story: list[Any] = [
        Paragraph("APTHunter 仿冒域名检测总览报告", title_style),
        Paragraph(f"检测任务：{task_name}　检测日期：{task_date or '-'}", subtitle_style),
        Paragraph("一、任务基本信息", heading_style),
        table(
            ["项目", "内容"],
            [
                ["项目名称", "APTHunter 仿冒域名检测"],
                ["报告编号", f"APTHunter-IMD-Summary-{task_date.replace('-', '') or 'unknown'}-001"],
                ["检测任务", task_name],
                ["检测日期", task_date or "-"],
                ["数据来源", f"{task_date or '-'} APTHunter 新注册域名检测任务结果"],
                ["模型版本", "2026-06-29 typo word guard retrain"],
                ["输入边界", "仅使用域名字符串、目标画像、历史样本、人工复核标签和本地传统模型"],
            ],
            widths=[4.2 * cm, 21.0 * cm],
        ),
        Spacer(1, 8),
        Paragraph("二、执行摘要", heading_style),
        Paragraph(
            (
                f"本次检测共处理 {fmt_int(summary.get('input_domain_count', 0))} 条新注册域名，"
                f"基于 {fmt_int(summary.get('target_count', 0))} 个受保护目标画像进行规则召回，"
                f"形成 {fmt_int(summary.get('recalled_count', 0))} 个候选对并完成模型打分。"
            ),
            body_style,
        ),
        Paragraph(
            (
                f"正式候选对 {fmt_int(summary.get('output_count', 0))} 条，"
                f"按候选域名去重后 {fmt_int(summary.get('unique_candidate_count', 0))} 条；"
                f"其中高风险 {fmt_int(high_count)} 条，中风险 {fmt_int(medium_count)} 条，低风险 {fmt_int(low_count)} 条。"
            ),
            body_style,
        ),
        Paragraph("三、关键指标", heading_style),
        table(
            ["指标", "数值"],
            [
                ["受保护目标数", fmt_int(summary.get("target_count", 0))],
                ["原始新注册域名数", fmt_int(summary.get("input_domain_count", 0))],
                ["规则召回候选对", fmt_int(summary.get("recalled_count", 0))],
                ["模型打分候选对", fmt_int(summary.get("scored_count", 0))],
                ["正式输出候选对", fmt_int(summary.get("output_count", 0))],
                ["去重正式候选域名", fmt_int(summary.get("unique_candidate_count", 0))],
                ["高价值目标人工 review 池", fmt_int(summary.get("high_value_review_count", 0))],
                ["平均最终风险分", fmt_float(formal_scores.mean() if len(formal_scores) else 0.0)],
                ["最高最终风险分", fmt_float(formal_scores.max() if len(formal_scores) else 0.0)],
            ],
            widths=[7.0 * cm, 5.5 * cm],
        ),
        Spacer(1, 6),
        Paragraph("四、风险等级分布", heading_style),
        table(["风险等级", "数量", "占比", "平均风险分", "建议动作"], pdf_risk_summary_rows(formal_df)),
        Paragraph("五、仿冒类型统计", heading_style),
        table(
            ["仿冒类型", "数量", "占比", "平均风险分", "高风险数量", "说明"],
            pdf_category_summary_rows(formal_df),
            widths=[3.0 * cm, 1.8 * cm, 1.8 * cm, 2.2 * cm, 2.0 * cm, 15.0 * cm],
        ),
        Paragraph("六、被仿冒目标类型分析", heading_style),
        table(
            ["目标类型", "数量", "占比", "平均风险分", "高/中/低风险"],
            pdf_target_type_summary_rows(formal_df),
        ),
        PageBreak(),
        Paragraph("七、正式疑似仿冒域名明细（按候选域名去重）", heading_style),
        table(
            ["序号", "候选域名", "匹配目标", "最终分", "主要类型", "主要依据"],
            pdf_detail_rows(formal_df, limit=None),
            widths=[1.1 * cm, 5.4 * cm, 5.2 * cm, 1.7 * cm, 3.0 * cm, 9.8 * cm],
        ),
        PageBreak(),
        Paragraph("八、高价值目标人工 review 池（Top 20）", heading_style),
        Paragraph(
            "该部分包含部分未达到正式告警阈值但涉及政府、教育、金融、云服务等目标的候选，仅用于人工抽查，不等同于正式告警。",
            body_style,
        ),
        table(
            ["序号", "候选域名", "目标名称", "目标域名", "最终分", "风险", "类型"],
            pdf_high_value_rows(high_value_review_df, limit=20),
            widths=[1.1 * cm, 5.0 * cm, 5.0 * cm, 4.4 * cm, 1.6 * cm, 1.4 * cm, 4.0 * cm],
        ),
        Paragraph("九、复核建议", heading_style),
        table(["对象", "动作", "说明"], pdf_review_suggestion_rows()),
        Paragraph("十、报告结论", heading_style),
        Paragraph(
            "本次检测结果建议作为安全运营和人工复核的优先级参考。"
            "后续应继续通过人工复核标签回灌、泛词误报压制和高价值目标样本补齐来优化检测效果。",
            body_style,
        ),
    ]

    story = build_word_like_pdf_story()
    doc.build(stabilize_pdf_story(story))


def write_pdf_report_with_word_layout(
    summary: dict[str, Any],
    output: str | Path,
    word_output: str | Path | None = None,
) -> None:
    """Create the official PDF report directly, with optional DOCX debug output."""
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report_summary = {
        **summary,
        "pdf_report_output": str(output_path),
        "word_report_output": str(word_output) if word_output else "",
    }
    if word_output:
        write_prediction_word_report(report_summary, word_output)
    write_prediction_pdf_report(report_summary, output_path)

def write_prediction_report(summary: dict[str, Any], output: str | Path) -> None:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result_df = read_report_csv(summary.get("output", ""))
    unique_df = read_report_csv(summary.get("unique_output", ""))
    high_value_review_df = read_report_csv(summary.get("high_value_review_output", ""))
    formal_df = unique_df if not unique_df.empty else result_df
    formal_scores = score_series(formal_df)
    task_date = report_task_date(summary)
    task_name = report_task_name(summary)
    high_count = risk_count(formal_df, "high")
    medium_count = risk_count(formal_df, "medium")
    low_count = risk_count(formal_df, "low")
    top_category = "-"
    if not formal_df.empty and "main_category" in formal_df.columns:
        top_category = CATEGORY_LABELS.get(
            str(formal_df["main_category"].value_counts().idxmax()),
            str(formal_df["main_category"].value_counts().idxmax()),
        )
    top_type = "-"
    if not formal_df.empty:
        typed = add_report_target_type(formal_df)
        if "_report_target_type" in typed.columns and not typed["_report_target_type"].empty:
            top_type = str(typed["_report_target_type"].value_counts().idxmax())

    lines = [
        "# APTHunter 仿冒域名检测总览报告",
        "",
        "## 一、任务基本信息",
        "",
        *markdown_table(
            ["项目", "内容"],
            [
                ["项目名称", "APTHunter 仿冒域名检测"],
                ["报告编号", f"APTHunter-IMD-Summary-{task_date.replace('-', '') or 'unknown'}-001"],
                ["检测任务", task_name],
                ["检测日期", task_date or "-"],
                ["报告生成文件", str(output_path)],
                ["数据来源", f"{task_date or '本次'} 新注册域名清单"],
                ["模型版本", "2026-06-29 typo word guard retrain"],
                ["判别输入边界", "仅使用域名字符串、目标画像、历史样本、人工复核标签和本地传统模型"],
            ],
        ),
        "",
        "## 二、执行摘要",
        "",
        (
            f"本次检测共处理 **{fmt_int(summary.get('input_domain_count', 0))}** 条新注册域名，"
            f"基于 **{fmt_int(summary.get('target_count', 0))}** 个受保护目标画像进行规则召回，"
            f"形成 **{fmt_int(summary.get('recalled_count', 0))}** 个候选对并完成模型打分。"
        ),
        "",
        (
            f"按当前阈值输出正式候选对 **{fmt_int(summary.get('output_count', 0))}** 条，"
            f"按候选域名去重后为 **{fmt_int(summary.get('unique_candidate_count', 0))}** 条。"
            f"其中高风险 **{fmt_int(high_count)}** 条，中风险 **{fmt_int(medium_count)}** 条，"
            f"低风险 **{fmt_int(low_count)}** 条。主要仿冒类型为 **{top_category}**，"
            f"主要匹配目标类型为 **{top_type}**。"
        ),
        "",
        (
            "本报告结果仅代表 APTHunter 基于域名字符串和本地模型的风险判断，"
            "未使用 DNS、WHOIS、证书、网页内容、搜索引擎结果或 LLM 判断作为 V1 必需输入。"
        ),
        "",
        "## 三、关键指标",
        "",
        *markdown_table(
            ["指标", "数值"],
            [
                ["受保护目标数", fmt_int(summary.get("target_count", 0))],
                ["原始新注册域名数", fmt_int(summary.get("input_domain_count", 0))],
                ["规则召回候选对", fmt_int(summary.get("recalled_count", 0))],
                ["模型打分候选对", fmt_int(summary.get("scored_count", 0))],
                ["正式输出候选对", fmt_int(summary.get("output_count", 0))],
                ["去重正式候选域名", fmt_int(summary.get("unique_candidate_count", 0))],
                ["高价值目标人工 review 池", fmt_int(summary.get("high_value_review_count", 0))],
                ["平均最终风险分", fmt_float(formal_scores.mean() if len(formal_scores) else 0.0)],
                ["最高最终风险分", fmt_float(formal_scores.max() if len(formal_scores) else 0.0)],
            ],
        ),
        "",
        "## 四、风险等级分布",
        "",
        *markdown_table(
            ["风险等级", "数量", "占比", "平均风险分", "建议动作"],
            risk_summary_rows(formal_df),
        ),
        "",
        "风险等级说明：高风险优先进入人工复核和处置流程；中风险结合目标重要性和命中原因复核；低风险默认观察，重点关注高价值目标和重复模板。",
        "",
        "## 五、仿冒类型统计",
        "",
        *markdown_table(
            ["仿冒类型", "数量", "占比", "平均风险分", "高风险数量", "说明"],
            category_summary_rows(formal_df),
        ),
        "",
        "说明：一条域名可能同时命中多个仿冒类型，表格按 `main_category` 统计，用于展示主要形态分布。",
        "",
        "## 六、被仿冒目标类型分析",
        "",
        *markdown_table(
            ["目标类型", "数量", "占比", "平均风险分", "高/中/低风险"],
            [
                [row[0], row[1], row[2], row[3], f"{row[4]}/{row[5]}/{row[6]}"]
                for row in target_type_summary_rows(formal_df)
            ],
        ),
        "",
        "## 七、重点匹配目标分布",
        "",
        *markdown_table(
            ["匹配目标", "官方域名", "目标类型", "候选数", "平均分", "高/中/低"],
            top_target_rows(formal_df, limit=None),
        ),
        "",
        "## 八、高价值目标人工 review 池",
        "",
        (
            f"本次额外生成高价值目标人工 review 池 **{fmt_int(len(high_value_review_df))}** 条。"
            "该文件包含部分未达到正式告警阈值但涉及政府、教育、金融、云服务等目标的候选，"
            "用于人工抽查和补充样本，不等同于正式告警。"
        ),
        "",
        *markdown_table(
            ["review 风险等级", "数量", "平均风险分"],
            high_value_review_rows(high_value_review_df),
        ),
        "",
        "## 九、TOP 风险样例",
        "",
        *markdown_table(
            ["候选域名", "匹配官方域名", "风险等级", "最终分", "主要类型"],
            example_rows(formal_df, limit=None),
        ),
        "",
        "## 十、复核建议",
        "",
        "1. 优先复核 `suspicious_domains_result_unique_candidates.csv` 中的高风险和中风险结果。",
        "2. 对 `review_high_value_targets.csv` 中涉及政府、教育、金融、云服务的候选进行抽样复核，尤其关注 `ignore` 中命中高价值泛化模式的域名。",
        "3. 对确认误报的样本回灌到 `data/raw/manual_review_labels.csv`，标记为 `review_label=0`。",
        "4. 对确认仿冒的样本回灌到 `data/raw/manual_review_labels.csv`，标记为 `review_label=1`，并尽量修正准确的 `target_domain`。",
        "5. 对目标归属不明确但明显可疑的域名，先进入高价值 review 池或单独记录，不建议强行写成某个具体目标的正样本。",
        "",
        "## 十一、边界与风险提示",
        "",
        "- 本系统不使用 LLM 作为判别模型。",
        "- 本系统不依赖 DNS、WHOIS、证书、网页内容、搜索引擎结果或外部威胁情报作为 V1 必需输入。",
        "- 泛词型目标、短品牌词、一个字母加通用词的官方域名仍可能带来误报或目标归属歧义。",
        "- 合成正样本用于提高高价值目标召回，但权重较低，仍需真实复核样本持续校准。",
        "- 高价值 review 池是人工候选池，不代表正式告警结论。",
        "",
        "## 十二、输出文件",
        "",
        f"- result: {summary.get('output', '')}",
        f"- unique candidates: {summary.get('unique_output', '')}",
        f"- report: {summary.get('report_output', '')}",
        f"- high value review: {summary.get('high_value_review_output', '')}",
        "",
        "## 附：模型与历史样本信息",
        "",
        *markdown_table(
            ["项目", "内容"],
            [
                ["history_pairs", summary.get("history_pairs", "")],
                ["history_positive_count", fmt_int(summary.get("history_positive_count", 0))],
                ["used_history", summary.get("used_history", False)],
                ["manual_review", summary.get("manual_review", "")],
                ["alias_groups", summary.get("alias_groups", "")],
                ["alias_guard_disabled", summary.get("alias_guard_disabled", False)],
            ],
        ),
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
    word_report_output: str | Path | None = None,
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
            "word_report_output": str(word_report_output) if word_report_output else "",
            "high_value_review_output": str(high_value_review_output) if high_value_review_output else "",
            "high_value_review_count": high_value_review_count,
        }
        if report_output:
            write_prediction_report(summary, report_output)
        if word_report_output:
            write_prediction_word_report(summary, word_report_output)
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
        "word_report_output": str(word_report_output) if word_report_output else "",
        "high_value_review_output": str(high_value_review_output) if high_value_review_output else "",
    }
    if report_output:
        write_prediction_report(summary, report_output)
    if word_report_output:
        write_prediction_word_report(summary, word_report_output)
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
        "--word-report-output",
        default="",
        help="Prediction report Word DOCX path. If omitted, writes prediction_report.docx beside --output.",
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
    word_report_output = (
        Path(args.word_report_output)
        if args.word_report_output
        else output_path.with_name("prediction_report.docx")
    )
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
        word_report_output=word_report_output,
        high_value_review_output=high_value_review_output,
        high_value_review_top_n=args.high_value_review_top_n,
    )
    for key, value in summary.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    main()
