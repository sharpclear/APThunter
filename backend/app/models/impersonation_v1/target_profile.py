from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Iterable, Sequence

import pandas as pd
import yaml
from pypinyin import Style, lazy_pinyin

try:
    from .normalize import normalize_domain
except ImportError:  # pragma: no cover - used when run as python target_profile.py
    from normalize import normalize_domain


PROFILE_FIELDS = [
    "target_name",
    "target_domain",
    "target_registered_domain",
    "target_sld",
    "target_suffix",
    "target_subdomain",
    "target_tier",
    "target_subtype",
    "target_subtype_label",
    "target_type_source",
    "target_positive_count",
    "target_negative_count",
    "target_has_enough_positive",
    "target_threshold_profile",
    "target_tokens",
    "strong_tokens",
    "medium_tokens",
    "short_tokens",
    "weak_tokens",
    "specific_tokens",
    "inherited_tokens",
    "token_policy_reason",
    "pinyin_full",
    "pinyin_initials",
    "is_high_value_target",
    "target_indicators",
]

NAME_COLUMNS = ("target_name", "单位名称", "name", "org_name", "organization")
DOMAIN_COLUMNS = ("target_domain", "域名", "domain", "normalized_domain", "host")
PAIR_TARGET_DOMAIN_COLUMNS = ("target_domain", "正常域名", "official_domain", "domain")
READ_ENCODINGS = ("utf-8-sig", "utf-8", "gbk")
PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_KEYWORDS_PATH = PACKAGE_DIR / "configs/keywords.yaml"
DEFAULT_TOKEN_POLICY_PATH = PACKAGE_DIR / "configs/token_policy.yaml"
DEFAULT_THRESHOLDS_PATH = PACKAGE_DIR / "configs/thresholds.yaml"
DEFAULT_TARGET_SUBTYPES_PATH = PACKAGE_DIR / "configs/target_subtypes.yaml"
DEFAULT_TARGET_TYPE_OVERRIDES_PATH = PACKAGE_DIR / "data/target_type_overrides.csv"
DEFAULT_ENOUGH_POSITIVE_MIN = 10

DEFAULT_WEAK_TARGET_TOKENS = {
    "admin",
    "app",
    "apps",
    "api",
    "apis",
    "ads",
    "cdn",
    "cloud",
    "center",
    "dev",
    "developer",
    "docs",
    "download",
    "email",
    "help",
    "home",
    "login",
    "mail",
    "name",
    "names",
    "online",
    "office",
    "page",
    "pages",
    "portal",
    "service",
    "services",
    "site",
    "static",
    "support",
    "system",
    "web",
    "webmail",
    "www",
}
DEFAULT_GENERIC_MEDIUM_TARGET_TOKENS = {
    "bank",
    "casino",
    "finance",
    "game",
    "market",
    "media",
    "news",
    "pay",
    "search",
    "shop",
    "sports",
    "store",
    "studio",
}
DEFAULT_INHERITED_TARGET_TOKENS = {
    "cn",
    "china",
    "edu",
    "gov",
    "national",
    "public",
    "state",
}
DEFAULT_FORBIDDEN_STRONG_TOKENS = {
    "cloud",
    "digital",
    "global",
    "mail",
    "online",
    "portal",
    "service",
}

GOVERNMENT_KEYWORDS = {
    "政府",
    "公安",
    "法院",
    "检察",
    "税务",
    "海关",
    "政务",
    "财政",
    "外交",
    "厅",
    "局",
    "委",
    "gov",
    "government",
    "ministry",
    "bureau",
}

EDUCATION_KEYWORDS = {
    "大学",
    "学院",
    "学校",
    "教育",
    "中学",
    "小学",
    "研究院",
    "实验室",
    "university",
    "college",
    "school",
    "education",
    "academy",
    "institute",
}

FINANCE_KEYWORDS = {
    "银行",
    "证券",
    "保险",
    "金融",
    "基金",
    "期货",
    "bank",
    "finance",
    "financial",
    "insurance",
    "securities",
    "fund",
    "pay",
    "payment",
    "icbc",
    "ccb",
    "abc",
    "boc",
    "支付",
}

GOV_TIER_KEYWORDS = GOVERNMENT_KEYWORDS | {"委员会", "部", "检察院"}
EDU_TIER_KEYWORDS = EDUCATION_KEYWORDS | {"科学院"}
FINANCE_TIER_KEYWORDS = FINANCE_KEYWORDS
CLOUD_TIER_KEYWORDS = {
    "cloud",
    "aliyun",
    "tencentcloud",
    "huawei cloud",
    "huaweicloud",
    "云",
}
ECOMMERCE_TIER_KEYWORDS = {
    "shop",
    "mall",
    "store",
    "taobao",
    "tmall",
    "jd",
    "amazon",
    "ebay",
    "淘宝",
    "天猫",
    "京东",
}
MEDIA_TIER_KEYWORDS = {
    "新闻",
    "传媒",
    "电视",
    "广播",
    "日报",
    "网",
    "news",
    "media",
    "tv",
    "radio",
    "daily",
}
TARGET_TIERS = ("gov", "edu", "finance", "cloud", "ecommerce", "media", "brand", "other")

HIGH_VALUE_SUFFIXES = {"gov.cn", "edu.cn", "ac.cn"}
CONDITIONAL_HIGH_VALUE_SUFFIXES = {"org.cn", "com.cn"}


def read_whitelist(path: str | Path) -> pd.DataFrame:
    """Read a whitelist CSV with common encodings used by Chinese datasets."""
    input_path = Path(path)
    errors: list[str] = []
    for encoding in READ_ENCODINGS:
        try:
            return pd.read_csv(input_path, encoding=encoding)
        except UnicodeDecodeError as exc:
            errors.append(f"{encoding}: {exc}")
    joined_errors = "; ".join(errors)
    raise ValueError(f"failed to read whitelist with encodings {READ_ENCODINGS}: {joined_errors}")


def load_token_policy(
    path: str | Path = DEFAULT_TOKEN_POLICY_PATH,
    fallback_path: str | Path = DEFAULT_KEYWORDS_PATH,
) -> dict[str, set[str]]:
    """Load target-token tiering policy from token_policy.yaml with keywords.yaml fallback."""
    data: dict[str, Any] = {}
    config_path = Path(path) if str(path).strip() else None
    if config_path and config_path.is_file():
        with config_path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
    elif fallback_path:
        fallback = Path(fallback_path)
        if fallback.is_file():
            with fallback.open("r", encoding="utf-8") as file:
                data = yaml.safe_load(file) or {}

    weak_tokens = set(data.get("weak_tokens") or set())
    generic_medium_tokens = (
        set(data.get("generic_medium_target_tokens") or set())
        | set(data.get("generic_medium_tokens") or set())
        | set(data.get("medium_tokens") or set())
    )
    inherited_tokens = set(data.get("inherited_tokens") or set())
    forbidden_strong = set(data.get("forbidden_strong_tokens") or set())
    spelling_variant_block = set(data.get("spelling_variant_block_base_tokens") or set())
    spelling_variant_complete_word_block = set(
        data.get("spelling_variant_complete_word_block_tokens") or set()
    )
    spelling_variant_suffix_pair_blocks = normalize_suffix_pair_blocks(
        data.get("spelling_variant_suffix_pair_blocks") or set()
    )

    return {
        "weak_target_tokens": normalize_policy_tokens(
            set(data.get("weak_target_tokens") or set())
            | weak_tokens
            | DEFAULT_WEAK_TARGET_TOKENS
        ),
        "generic_medium_target_tokens": normalize_policy_tokens(
            generic_medium_tokens | DEFAULT_GENERIC_MEDIUM_TARGET_TOKENS
        ),
        "inherited_target_tokens": normalize_policy_tokens(
            inherited_tokens | DEFAULT_INHERITED_TARGET_TOKENS
        ),
        "forbidden_strong_tokens": normalize_policy_tokens(
            forbidden_strong | DEFAULT_FORBIDDEN_STRONG_TOKENS
        ),
        "spelling_variant_block_base_tokens": normalize_policy_tokens(spelling_variant_block),
        "spelling_variant_complete_word_block_tokens": normalize_policy_tokens(
            spelling_variant_complete_word_block
        ),
        "spelling_variant_suffix_pair_blocks": spelling_variant_suffix_pair_blocks,
    }


def read_table(path: str | Path) -> pd.DataFrame:
    input_path = Path(path)
    if input_path.suffix.lower() in {".xlsx", ".xls"}:
        return pd.read_excel(input_path)

    errors: list[str] = []
    for encoding in READ_ENCODINGS:
        try:
            return pd.read_csv(input_path, encoding=encoding, low_memory=False)
        except UnicodeDecodeError as exc:
            errors.append(f"{encoding}: {exc}")
    raise ValueError(f"failed to read {input_path}: {'; '.join(errors)}")


def load_target_subtype_config(path: str | Path = DEFAULT_TARGET_SUBTYPES_PATH) -> dict[str, Any]:
    config_path = Path(path)
    if not str(path).strip() or not config_path.exists():
        return {"subtypes": {}, "defaults": {}}
    with config_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    return {
        "subtypes": data.get("subtypes") or {},
        "defaults": data.get("defaults") or {},
    }


def load_target_type_overrides(path: str | Path = DEFAULT_TARGET_TYPE_OVERRIDES_PATH) -> dict[str, dict[str, str]]:
    override_path = Path(path)
    if not str(path).strip() or not override_path.exists():
        return {}
    df = read_table(override_path)
    if df.empty:
        return {}
    domain_col = _find_optional_column(df, ("target_domain", "domain", "域名", "鍩熷悕"))
    if not domain_col:
        return {}
    overrides: dict[str, dict[str, str]] = {}
    for _, row in df.iterrows():
        domain = normalize_domain(_clean_cell(row.get(domain_col)))["normalized_domain"]
        if not domain:
            continue
        overrides[domain] = {
            "target_name": _clean_cell(row.get("target_name")),
            "target_tier": _clean_cell(row.get("target_tier")),
            "target_subtype": _clean_cell(row.get("target_subtype")),
            "target_subtype_label": _clean_cell(row.get("target_subtype_label")),
            "target_type_source": _clean_cell(row.get("target_type_source")) or "manual_override",
            "note": _clean_cell(row.get("note")),
        }
    return overrides


def load_positive_threshold(path: str | Path = DEFAULT_THRESHOLDS_PATH) -> int:
    config_path = Path(path)
    if not config_path.exists():
        return DEFAULT_ENOUGH_POSITIVE_MIN
    with config_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    value = (
        data.get("target_profile", {}).get("enough_positive_min")
        or data.get("target_profile", {}).get("target_has_enough_positive_min")
        or DEFAULT_ENOUGH_POSITIVE_MIN
    )
    return int(value)


def build_target_profiles(
    whitelist: pd.DataFrame,
    token_policy: dict[str, set[str]] | None = None,
    subtype_config: dict[str, Any] | None = None,
    type_overrides: dict[str, dict[str, str]] | None = None,
    positive_counts: dict[str, int] | None = None,
    negative_counts: dict[str, int] | None = None,
    enough_positive_min: int = DEFAULT_ENOUGH_POSITIVE_MIN,
) -> pd.DataFrame:
    """Build target profiles from organization names and official domains."""
    name_col = _find_column(whitelist, NAME_COLUMNS, "target name")
    domain_col = _find_column(whitelist, DOMAIN_COLUMNS, "target domain")
    policy = token_policy or load_token_policy()
    subtype_rules = subtype_config or load_target_subtype_config()
    overrides = type_overrides or {}

    records: list[dict[str, Any]] = []
    for _, row in whitelist.iterrows():
        target_name = _clean_cell(row.get(name_col))
        raw_domain = _clean_cell(row.get(domain_col))
        if not raw_domain:
            continue
        normalized_domain = normalize_domain(raw_domain)["normalized_domain"]
        records.append(
            build_target_profile(
                target_name,
                raw_domain,
                token_policy=policy,
                subtype_config=subtype_rules,
                type_override=overrides.get(normalized_domain),
                target_positive_count=(positive_counts or {}).get(normalized_domain, 0),
                target_negative_count=(negative_counts or {}).get(normalized_domain, 0),
                enough_positive_min=enough_positive_min,
            )
        )

    return pd.DataFrame(records, columns=PROFILE_FIELDS)


def build_target_profile(
    target_name: str,
    target_domain: str,
    token_policy: dict[str, set[str]] | None = None,
    subtype_config: dict[str, Any] | None = None,
    type_override: dict[str, str] | None = None,
    target_positive_count: int = 0,
    target_negative_count: int = 0,
    enough_positive_min: int = DEFAULT_ENOUGH_POSITIVE_MIN,
) -> dict[str, Any]:
    """Build one protected-target profile from a display name and official domain."""
    parsed = normalize_domain(target_domain)
    target_sld = parsed["sld_clean"] or parsed["sld"]
    pinyin_full, pinyin_initials = make_pinyin_tokens(target_name)
    policy = token_policy or load_token_policy()

    strong_tokens: list[str] = []
    medium_tokens: list[str] = []
    short_tokens: list[str] = []
    weak_tokens: list[str] = []
    inherited_tokens: list[str] = []
    token_policy_reasons: list[str] = []

    specific_candidates, inherited_candidates = _candidate_tokens(
        target_name,
        target_sld,
        parsed.get("subdomain", ""),
        pinyin_full,
        pinyin_initials,
    )

    for token in inherited_candidates:
        cleaned = _clean_token(token)
        if cleaned:
            _append_unique(inherited_tokens, cleaned)
            _append_unique(token_policy_reasons, f"{cleaned}:inherited_from_subdomain_target")

    for token in specific_candidates:
        reason = _assign_token(
            token,
            strong_tokens,
            medium_tokens,
            short_tokens,
            weak_tokens,
            inherited_tokens,
            policy,
        )
        if reason:
            _append_unique(token_policy_reasons, reason)

    indicators = infer_target_indicators(target_name, parsed["suffix"], target_sld)
    target_tier = infer_target_tier(target_name, parsed["suffix"], target_sld)
    subtype_rules = subtype_config or load_target_subtype_config()
    target_subtype, target_subtype_label = infer_target_subtype(
        target_name=target_name,
        target_domain=parsed["normalized_domain"],
        target_sld=target_sld,
        suffix=parsed["suffix"],
        target_tier=target_tier,
        config=subtype_rules,
    )
    target_type_source = "auto"
    if type_override:
        override_tier = _clean_cell(type_override.get("target_tier"))
        override_subtype = _clean_cell(type_override.get("target_subtype"))
        override_label = _clean_cell(type_override.get("target_subtype_label"))
        if override_tier:
            target_tier = override_tier
        if override_subtype:
            target_subtype = override_subtype
            target_type_source = _clean_cell(type_override.get("target_type_source")) or "manual_override"
        if override_label:
            target_subtype_label = override_label
            target_type_source = _clean_cell(type_override.get("target_type_source")) or "manual_override"
    is_high_value = is_high_value_target(parsed["suffix"], indicators)
    has_enough_positive = int(target_positive_count) >= int(enough_positive_min)
    threshold_profile = target_threshold_profile(target_tier, has_enough_positive)
    specific_tokens = _unique_tokens([*strong_tokens, *medium_tokens, *short_tokens])
    target_tokens = _unique_tokens(
        [*specific_tokens, *weak_tokens, *inherited_tokens]
    )

    return {
        "target_name": target_name,
        "target_domain": parsed["normalized_domain"],
        "target_registered_domain": parsed["registered_domain"],
        "target_sld": target_sld,
        "target_suffix": parsed["suffix"],
        "target_subdomain": parsed["subdomain"],
        "target_tier": target_tier,
        "target_subtype": target_subtype,
        "target_subtype_label": target_subtype_label,
        "target_type_source": target_type_source,
        "target_positive_count": int(target_positive_count),
        "target_negative_count": int(target_negative_count),
        "target_has_enough_positive": bool(has_enough_positive),
        "target_threshold_profile": threshold_profile,
        "target_tokens": _join_tokens(target_tokens),
        "strong_tokens": _join_tokens(strong_tokens),
        "medium_tokens": _join_tokens(medium_tokens),
        "short_tokens": _join_tokens(short_tokens),
        "weak_tokens": _join_tokens(weak_tokens),
        "specific_tokens": _join_tokens(specific_tokens),
        "inherited_tokens": _join_tokens(inherited_tokens),
        "token_policy_reason": _join_raw_tokens(token_policy_reasons),
        "pinyin_full": pinyin_full,
        "pinyin_initials": pinyin_initials,
        "is_high_value_target": bool(is_high_value),
        "target_indicators": _join_tokens(indicators),
    }


def make_pinyin_tokens(text: str) -> tuple[str, str]:
    chinese_text = "".join(re.findall(r"[\u4e00-\u9fff]+", text or ""))
    if not chinese_text:
        return "", ""

    full_parts = lazy_pinyin(chinese_text, style=Style.NORMAL, errors="ignore")
    initial_parts = lazy_pinyin(chinese_text, style=Style.FIRST_LETTER, errors="ignore")
    return "".join(full_parts).lower(), "".join(initial_parts).lower()


def infer_target_indicators(target_name: str, suffix: str, target_sld: str = "") -> list[str]:
    text = f"{target_name} {target_sld}".lower()
    indicators: list[str] = []

    if suffix == "gov.cn" or _contains_any(text, GOVERNMENT_KEYWORDS):
        indicators.append("government")
    if suffix in {"edu.cn", "ac.cn"} or _contains_any(text, EDUCATION_KEYWORDS):
        indicators.append("education")
    if _contains_any(text, FINANCE_KEYWORDS):
        indicators.append("finance")

    return _unique_tokens(indicators)


def infer_target_tier(target_name: str, suffix: str, target_sld: str = "") -> str:
    text = f"{target_name} {target_sld}".lower()
    suffix_text = str(suffix or "").lower()

    if "gov" in suffix_text or _contains_any(text, GOV_TIER_KEYWORDS):
        return "gov"
    if "edu" in suffix_text or suffix_text.startswith("ac.") or suffix_text == "ac.cn" or _contains_any(text, EDU_TIER_KEYWORDS):
        return "edu"
    if _contains_any(text, FINANCE_TIER_KEYWORDS):
        return "finance"
    if _contains_any(text, CLOUD_TIER_KEYWORDS):
        return "cloud"
    if _contains_any(text, ECOMMERCE_TIER_KEYWORDS):
        return "ecommerce"
    if _contains_any(text, MEDIA_TIER_KEYWORDS):
        return "media"
    if _is_clear_brand_target(target_name, target_sld):
        return "brand"
    return "other"


def infer_target_subtype(
    target_name: str,
    target_domain: str,
    target_sld: str,
    suffix: str,
    target_tier: str,
    config: dict[str, Any] | None = None,
) -> tuple[str, str]:
    rules = (config or {}).get("subtypes") or {}
    defaults = (config or {}).get("defaults") or {}
    tier = str(target_tier or "other").lower()
    domain = str(target_domain or "").lower()
    sld = str(target_sld or "").lower()
    text = f"{target_name} {domain} {sld} {suffix}".lower()

    for subtype, rule in rules.items():
        allowed_tiers = {str(value).lower() for value in (rule.get("target_tiers") or [])}
        if allowed_tiers and tier not in allowed_tiers:
            continue
        domains = {str(value).lower() for value in (rule.get("domains") or [])}
        slds = {str(value).lower() for value in (rule.get("slds") or [])}
        keywords = [str(value).lower() for value in (rule.get("keywords") or [])]
        if domain in domains or sld in slds or _contains_any(text, keywords):
            return str(subtype), str(rule.get("label") or subtype)

    default_label = str(defaults.get(tier) or defaults.get("other") or tier or "other")
    if tier == "brand":
        return "other_brand", default_label
    if tier == "finance":
        return "financial_institution", default_label
    if tier == "gov":
        return "government", default_label
    if tier == "edu":
        return "education", default_label
    if tier == "cloud":
        return "cloud_service", default_label
    if tier == "ecommerce":
        return "ecommerce", default_label
    if tier == "media":
        return "media", default_label
    return "other", default_label


def target_threshold_profile(target_tier: str, has_enough_positive: bool) -> str:
    if target_tier == "other":
        return "other"
    suffix = "enough_positive" if has_enough_positive else "low_positive"
    return f"{target_tier}_{suffix}"


def is_high_value_target(suffix: str, indicators: Iterable[str]) -> bool:
    indicator_set = set(indicators)
    if suffix in HIGH_VALUE_SUFFIXES:
        return True
    if suffix in CONDITIONAL_HIGH_VALUE_SUFFIXES and indicator_set:
        return True
    return bool(indicator_set & {"government", "education", "finance"})


def count_pairs_by_target(path: str | Path | None, positive_only: bool = False) -> dict[str, int]:
    if not path:
        return {}
    input_path = Path(path)
    if not input_path.exists():
        return {}
    df = read_table(input_path)
    if df.empty:
        return {}
    domain_col = _find_optional_column(df, PAIR_TARGET_DOMAIN_COLUMNS)
    if not domain_col:
        return {}
    working = df.copy()
    if positive_only and "label" in working.columns:
        labels = pd.to_numeric(working["label"], errors="coerce").fillna(0).astype(int)
        working = working[labels == 1]
    domains = working[domain_col].map(lambda value: normalize_domain(_clean_cell(value))["normalized_domain"])
    domains = domains[domains.astype(bool)]
    return {str(domain): int(count) for domain, count in domains.value_counts().items()}


def count_negative_pairs_by_target(path: str | Path | None) -> dict[str, int]:
    if not path:
        return {}
    input_path = Path(path)
    if not input_path.exists():
        return {}
    df = read_table(input_path)
    if df.empty or "label" not in df.columns:
        return {}
    domain_col = _find_optional_column(df, PAIR_TARGET_DOMAIN_COLUMNS)
    if not domain_col:
        return {}
    labels = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
    negatives = df[labels == 0]
    domains = negatives[domain_col].map(lambda value: normalize_domain(_clean_cell(value))["normalized_domain"])
    domains = domains[domains.astype(bool)]
    return {str(domain): int(count) for domain, count in domains.value_counts().items()}


def summarize_profiles(profiles: pd.DataFrame) -> dict[str, int]:
    summary = {
        "target_count": int(len(profiles)),
        "strong_token_count": _count_token_column(profiles, "strong_tokens"),
        "short_token_count": _count_token_column(profiles, "short_tokens"),
        "weak_token_count": _count_token_column(profiles, "weak_tokens"),
        "specific_token_count": _count_token_column(profiles, "specific_tokens"),
        "inherited_token_count": _count_token_column(profiles, "inherited_tokens"),
        "high_value_target_count": int(profiles["is_high_value_target"].sum())
        if "is_high_value_target" in profiles
        else 0,
        "enough_positive_target_count": int(
            profiles["target_has_enough_positive"].fillna(False).astype(bool).sum()
        )
        if "target_has_enough_positive" in profiles
        else 0,
    }
    if "target_tier" in profiles:
        for tier, count in profiles["target_tier"].fillna("other").value_counts().items():
            summary[f"target_tier.{tier}"] = int(count)
    if "target_subtype" in profiles:
        for subtype, count in profiles["target_subtype"].fillna("other").value_counts().head(20).items():
            summary[f"target_subtype.{subtype}"] = int(count)
    if "target_type_source" in profiles:
        for source, count in profiles["target_type_source"].fillna("auto").value_counts().items():
            summary[f"target_type_source.{source}"] = int(count)
    return summary


def write_target_profiles(profiles: pd.DataFrame, output: str | Path) -> None:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    profiles.to_csv(output_path, index=False, encoding="utf-8-sig")


def _candidate_tokens(
    target_name: str,
    target_sld: str,
    target_subdomain: str,
    pinyin_full: str,
    pinyin_initials: str,
) -> tuple[list[str], list[str]]:
    specific_tokens: list[str] = []
    inherited_tokens: list[str] = []
    subdomain_tokens = [
        token
        for token in _split_ascii_tokens(target_subdomain)
        if token and token not in {"www"}
    ]

    if subdomain_tokens:
        specific_tokens.extend(subdomain_tokens)
        inherited_tokens.extend(_split_ascii_tokens(target_sld))
        inherited_tokens.append(target_sld)
    else:
        specific_tokens.extend(_split_ascii_tokens(target_sld))
        specific_tokens.append(target_sld)

    specific_tokens.extend(_split_ascii_tokens(target_name))
    if pinyin_full:
        specific_tokens.append(pinyin_full)
    if pinyin_initials:
        specific_tokens.append(pinyin_initials)
    return _unique_tokens(specific_tokens), _unique_tokens(inherited_tokens)


def _assign_token(
    token: str,
    strong_tokens: list[str],
    medium_tokens: list[str],
    short_tokens: list[str],
    weak_tokens: list[str],
    inherited_tokens: list[str],
    token_policy: dict[str, set[str]],
) -> str:
    cleaned = _clean_token(token)
    if not cleaned:
        return ""

    if cleaned in token_policy["inherited_target_tokens"]:
        _append_unique(inherited_tokens, cleaned)
        return f"{cleaned}:policy_inherited"
    if cleaned in token_policy["weak_target_tokens"]:
        _append_unique(weak_tokens, cleaned)
        return f"{cleaned}:policy_weak"
    if cleaned in token_policy["forbidden_strong_tokens"]:
        _append_unique(weak_tokens, cleaned)
        return f"{cleaned}:forbidden_strong_to_weak"
    elif cleaned in token_policy["generic_medium_target_tokens"]:
        _append_unique(medium_tokens, cleaned)
        return f"{cleaned}:generic_medium"
    elif len(cleaned) <= 4:
        _append_unique(short_tokens, cleaned)
        return f"{cleaned}:short_length"
    elif len(cleaned) >= 6:
        _append_unique(strong_tokens, cleaned)
        return f"{cleaned}:strong_length"
    else:
        _append_unique(medium_tokens, cleaned)
        return f"{cleaned}:medium_length"


def _split_ascii_tokens(text: str) -> list[str]:
    return [_clean_token(token) for token in re.findall(r"[A-Za-z0-9]+", text or "")]


def _clean_token(token: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "", str(token).lower()).strip("-")


def normalize_policy_tokens(tokens: Iterable[Any]) -> set[str]:
    return {_clean_token(token) for token in tokens if _clean_token(token)}


def normalize_suffix_pair_blocks(values: Iterable[Any]) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for value in values:
        if isinstance(value, dict):
            candidate = _clean_token(value.get("candidate_suffix", ""))
            target = _clean_token(value.get("target_suffix", ""))
        else:
            parts = re.split(r"[:>|,]", str(value), maxsplit=1)
            if len(parts) != 2:
                continue
            candidate = _clean_token(parts[0])
            target = _clean_token(parts[1])
        if candidate and target:
            pairs.add((candidate, target))
    return pairs


def _find_column(df: pd.DataFrame, candidates: Sequence[str], label: str) -> str:
    for candidate in candidates:
        if candidate in df.columns:
            return candidate
    raise ValueError(f"missing {label} column; expected one of: {', '.join(candidates)}")


def _find_optional_column(df: pd.DataFrame, candidates: Sequence[str]) -> str | None:
    for candidate in candidates:
        if candidate in df.columns:
            return candidate
    return None


def _is_clear_brand_target(target_name: str, target_sld: str) -> bool:
    cleaned_sld = _clean_token(target_sld)
    if len(cleaned_sld) >= 3 and cleaned_sld not in DEFAULT_WEAK_TARGET_TOKENS:
        return True
    ascii_tokens = [token for token in _split_ascii_tokens(target_name) if len(token) >= 3]
    return bool(ascii_tokens)


def _clean_cell(value: Any) -> str:
    if pd.isna(value):
        return ""
    return str(value).strip()


def _contains_any(text: str, keywords: Iterable[str]) -> bool:
    return any(keyword.lower() in text for keyword in keywords)


def _unique_tokens(tokens: Iterable[str]) -> list[str]:
    result: list[str] = []
    for token in tokens:
        cleaned = _clean_token(token)
        if cleaned and cleaned not in result:
            result.append(cleaned)
    return result


def _append_unique(tokens: list[str], token: str) -> None:
    if token not in tokens:
        tokens.append(token)


def _join_tokens(tokens: Iterable[str]) -> str:
    return "|".join(_unique_tokens(tokens))


def _join_raw_tokens(tokens: Iterable[str]) -> str:
    result: list[str] = []
    for token in tokens:
        text = str(token).strip()
        if text and text not in result:
            result.append(text)
    return "|".join(result)


def _count_token_column(df: pd.DataFrame, column: str) -> int:
    if column not in df:
        return 0
    return int(
        df[column]
        .fillna("")
        .map(lambda value: len([token for token in str(value).split("|") if token]))
        .sum()
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build protected target profiles from whitelist domains."
    )
    parser.add_argument("--whitelist", required=True, help="Whitelist CSV path.")
    parser.add_argument("--output", required=True, help="Output target profile CSV path.")
    parser.add_argument(
        "--keywords",
        default=str(DEFAULT_KEYWORDS_PATH),
        help="Legacy keyword YAML path used as token policy fallback.",
    )
    parser.add_argument(
        "--token-policy",
        default=str(DEFAULT_TOKEN_POLICY_PATH),
        help="Token policy YAML path for weak/inherited/forbidden-strong target tokens.",
    )
    parser.add_argument(
        "--thresholds",
        default=str(DEFAULT_THRESHOLDS_PATH),
        help="Threshold YAML path containing target-profile settings.",
    )
    parser.add_argument(
        "--target-subtypes",
        default=str(DEFAULT_TARGET_SUBTYPES_PATH),
        help="Target subtype YAML path used to auto-classify protected targets.",
    )
    parser.add_argument(
        "--target-type-overrides",
        default=str(DEFAULT_TARGET_TYPE_OVERRIDES_PATH),
        help="Optional CSV with manual target_tier/target_subtype overrides.",
    )
    parser.add_argument(
        "--positive-pairs",
        default="",
        help="Optional positive pairs/raw positive file used to count positives by target_domain.",
    )
    parser.add_argument(
        "--labeled-pairs",
        default="",
        help="Optional labeled pairs file used to count negatives by target_domain.",
    )
    parser.add_argument(
        "--min-positive-count",
        type=int,
        default=None,
        help="Override thresholds.yaml target_has_enough_positive minimum.",
    )
    parser.add_argument(
        "--disable-token-policy",
        action="store_true",
        help="Use legacy keyword/default token tiers instead of configs/token_policy.yaml.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    whitelist = read_whitelist(args.whitelist)
    token_policy = (
        load_token_policy(args.token_policy, fallback_path=args.keywords)
        if not args.disable_token_policy
        else load_token_policy(args.keywords, fallback_path="")
    )
    enough_positive_min = (
        int(args.min_positive_count)
        if args.min_positive_count is not None
        else load_positive_threshold(args.thresholds)
    )
    profiles = build_target_profiles(
        whitelist,
        token_policy=token_policy,
        subtype_config=load_target_subtype_config(args.target_subtypes),
        type_overrides=load_target_type_overrides(args.target_type_overrides),
        positive_counts=count_pairs_by_target(args.positive_pairs, positive_only=True),
        negative_counts=count_negative_pairs_by_target(args.labeled_pairs),
        enough_positive_min=enough_positive_min,
    )
    write_target_profiles(profiles, args.output)

    summary = summarize_profiles(profiles)
    for key, value in summary.items():
        print(f"{key}={value}")
    print(f"output={Path(args.output)}")


if __name__ == "__main__":
    main()
