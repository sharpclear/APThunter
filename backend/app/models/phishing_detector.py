import os
import re
import io
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple, Iterable, Optional
import numpy as np
import pandas as pd
from tqdm import tqdm

from phishing_deepseek_llm_judge import KEEP_RECOMMENDATIONS, MODEL_NAME as LLM_MODEL_NAME, build_candidate_items, judge_batch


# =========================================================
# 1. 配置区
# =========================================================

TARGET_EXCEL_PATH = r"E:\项目\APT组织域名预测\预测结果\钓鱼检测\目标域名\输入列表.xlsx"
NEW_DOMAIN_FOLDER = r"E:\项目\APT组织域名预测\预测结果\新增域名_钓鱼检测"
OUTPUT_DIR = r"E:\项目\APT组织域名预测\预测结果\钓鱼检测\结果"

# CANINE 默认作为“过滤歧义候选”的复核模块
ENABLE_CANINE = True
CANINE_MODEL_PATH = r"./models/canine-s"

# CANINE 只处理规则召回后的歧义候选，避免对数百万域名直接跑模型
CANINE_MAX_CANDIDATES = 30000
CANINE_BATCH_SIZE = 64

# 最终最低输出阈值。实际还会按 strong / medium / short / weak 分层过滤
GLOBAL_MIN_SCORE = 0.58

# Claude Opus LLM 作为仿冒候选最终输出前的研判步骤
LLM_BATCH_SIZE = int(os.getenv("PHISHING_LLM_BATCH_SIZE", os.getenv("LLM_JUDGER_BATCH_SIZE", "200")))
LLM_MAX_WORKERS = int(os.getenv("PHISHING_LLM_MAX_WORKERS", os.getenv("LLM_JUDGER_MAX_WORKERS", "10")))
LLM_TIMEOUT_SEC = int(os.getenv("PHISHING_LLM_TIMEOUT_SEC", os.getenv("LLM_JUDGER_TIMEOUT_SEC", "180")))
LLM_MAX_RETRIES = int(os.getenv("PHISHING_LLM_MAX_RETRIES", "3"))
LLM_RETRY_SLEEP_SEC = int(os.getenv("PHISHING_LLM_RETRY_SLEEP_SEC", "5"))
LLM_MAX_TOKENS = int(os.getenv("PHISHING_LLM_MAX_TOKENS", "32768"))

# Excel 单文件行数上限
EXCEL_MAX_ROWS = 1_000_000

# 是否过滤和目标域名完全相同的域名
SKIP_EXACT_TARGET_DOMAIN = True

# 进度打印间隔
LOG_EVERY_N = 200_000
_ORIGINAL_GLOBAL_MIN_SCORE = GLOBAL_MIN_SCORE


def _log_required(message: str) -> None:
    print(message)


# =========================================================
# 2. 可选依赖
# =========================================================

try:
    from rapidfuzz import fuzz
    HAS_RAPIDFUZZ = True
except Exception:
    import difflib
    HAS_RAPIDFUZZ = False

try:
    import tldextract
    TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
    HAS_TLDEXTRACT = True
except Exception:
    TLD_EXTRACTOR = None
    HAS_TLDEXTRACT = False


# =========================================================
# 3. 词表配置
# =========================================================

COMMON_MULTI_SUFFIXES = sorted(
    {
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
        "com.hk", "org.hk", "gov.hk", "edu.hk",
        "co.uk", "gov.uk", "ac.uk",
        "com.au", "net.au", "org.au",
        "co.jp", "ne.jp", "or.jp", "go.jp",
        "com.sg", "gov.sg", "edu.sg",
        "com.tw", "org.tw", "gov.tw", "edu.tw",
        "state.gov",
    },
    key=lambda x: x.count("."),
    reverse=True,
)

COMMON_SECOND_LEVEL_SUFFIX_LABELS = {
    "ac", "co", "com", "edu", "go", "gov", "ne", "net", "or", "org",
}

# 完全不作为目标关键词的词
STOP_TERMS = {
    "www", "com", "cn", "net", "org", "gov", "edu", "ac", "hk", "cc",
    "zh", "en", "zhcn", "cnzh", "c", "html", "index",
}

# 通用弱词。命中这些词不能直接判定仿冒，必须搭配强风险词 + 目标指示词
WEAK_COMMON_TERMS = {
    "sport", "mail", "mod", "mot", "mem", "mee", "mca", "moa", "moj",
    "china", "beijing", "state", "global", "center", "centers", "group",
    "life", "bank", "service", "support", "cloud", "online", "office",
    "system", "app", "portal", "admin", "pay", "shop", "news", "media",
}

# 一些短但具有较强品牌/机构指向性的词
IMPORTANT_SHORT_TERMS = {
    "aws", "ibm", "pbc", "icbc", "ccb", "boc", "cdb", "bcg", "ge",
    "pg", "jnj", "mfa", "moe", "miit", "ndrc", "csrc", "samr", "nhc",
    "sgcc", "crcc", "crec",
}

# 明确的强品牌/机构词
MANUAL_STRONG_TERMS = {
    "microsoft", "apple", "intel", "cisco", "starbucks", "pfizer",
    "boeing", "goldmansachs", "jpmorganchina", "morganstanley",
    "mckinsey", "sinopharm", "sinosure", "abchina", "bankcomm",
    "educationusa", "fourseasons", "columbia", "stanford", "wharton",
    "uchicago", "duke", "nyu", "yale", "marriott", "icbc", "citic",
    "picc", "chinalife", "cntaiping", "customs", "chinatax", "xuexi",
    "beijinggov", "tobacco", "energychina", "bjwatergroup", "bjsubway",
    "chinaunicom", "chinatower", "china-tower", "sinograin", "cofco",
    "comac", "crrcgc", "ccccltd", "bauhinia", "cnpubg",
}

# 强风险词：出现后明显更像登录、认证、账号劫持、邮件入口等钓鱼场景
STRONG_RISK_WORDS = {
    "login", "logon", "signin", "sign-in", "verify", "verification",
    "auth", "authenticate", "authentication", "account", "password",
    "passwd", "pwd", "secure", "security", "sso", "webmail", "vpn",
    "token", "oauth", "idp", "cas", "reset", "recover", "recovery",
    "unlock", "2fa", "mfa", "otp", "cert", "certificate",
}

# 中风险词：需要和目标词、结构异常、后缀异常等组合
MEDIUM_RISK_WORDS = {
    "portal", "service", "support", "update", "admin", "mail", "email",
    "payment", "pay", "bank", "wallet", "official", "gov", "cn",
    "china", "notice", "safe", "oa", "api", "user", "member",
}

# 弱风险词：单独基本不能说明问题
WEAK_RISK_WORDS = {
    "app", "online", "cloud", "system", "office", "site", "center",
    "sign", "download", "help", "home",
}

SUSPICIOUS_SUFFIXES = {
    "top", "xyz", "vip", "shop", "site", "online", "club", "icu",
    "click", "work", "live", "mom", "cyou", "lol", "bond", "quest",
    "monster", "bar", "buzz", "info", "biz", "store", "pro", "pw",
}

BASE_TARGET_INDICATORS = {
    "official",
}

BASE_HIGH_VALUE_SUFFIXES = {
    "gov.cn", "edu.cn", "ac.cn", "state.gov",
}

BASE_IMPORTANT_SUFFIXES = {
    "com.cn", "org.cn", "net.cn",
}

BASE_FINANCIAL_TERMS = {
    "icbc", "abchina", "boc", "ccb", "bankcomm", "citic",
    "pbc", "cdb", "eximbank", "adbc", "csrc",
}

GENERIC_DOMAIN_TERMS = {
    "account", "accounts", "admin", "api", "app", "apps", "auth",
    "bank", "cdn", "center", "centers", "cloud", "data", "download",
    "email", "global", "group", "help", "home", "info", "life",
    "login", "mail", "media", "mobile", "news", "office", "online",
    "pay", "payment", "portal", "secure", "security", "service",
    "services", "shop", "site", "sport", "support", "system", "user",
    "wallet", "web", "webmail", "www",
}

INFRASTRUCTURE_LABELS = {
    "www", "m", "mobile", "wap", "web", "cdn", "static", "assets",
    "img", "image", "images", "css", "js", "api", "openapi", "dev",
    "test", "stage", "staging", "prod", "ns", "ns1", "ns2", "dns",
    "smtp", "imap", "pop", "mail", "mx", "ftp",
}

TARGET_INDICATOR_CANDIDATES = {
    "ac", "america", "au", "beijing", "britain", "canada",
    "china", "cn", "de", "edu", "education", "eu", "fr", "go",
    "gov", "government", "hk", "in", "india", "jp", "japan", "kr",
    "official", "sg", "state", "taiwan", "tw", "uk", "unitedkingdom",
    "us", "usa", "zhongguo",
}

COUNTRY_ALIAS_BY_CC = {
    "cn": {"china", "zhongguo"},
    "us": {"usa", "america"},
    "uk": {"britain", "unitedkingdom"},
    "jp": {"japan"},
    "in": {"india"},
}

SERVICE_STRONG_CANDIDATES = {
    "auth", "authenticate", "authentication", "cas", "idp", "login",
    "logon", "mfa", "oauth", "otp", "password", "pwd", "secure",
    "security", "signin", "sso", "token", "verify", "vpn", "webmail",
}

SERVICE_MEDIUM_CANDIDATES = {
    "admin", "api", "email", "mail", "member", "notice", "oa",
    "official", "portal", "service", "support", "update", "user",
}

CONFUSABLE_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
})


@dataclass
class LexiconConfig:
    common_multi_suffixes: List[str]
    stop_terms: Set[str]
    weak_common_terms: Set[str]
    important_short_terms: Set[str]
    manual_strong_terms: Set[str]
    strong_risk_words: Set[str]
    medium_risk_words: Set[str]
    weak_risk_words: Set[str]
    suspicious_suffixes: Set[str]
    target_indicators: Set[str]
    high_value_suffixes: Set[str]
    important_suffixes: Set[str]
    financial_terms: Set[str]
    generated_stop_terms: Set[str] = field(default_factory=set)
    generated_weak_common_terms: Set[str] = field(default_factory=set)
    generated_important_short_terms: Set[str] = field(default_factory=set)
    generated_manual_strong_terms: Set[str] = field(default_factory=set)
    generated_target_indicators: Set[str] = field(default_factory=set)
    generated_high_value_suffixes: Set[str] = field(default_factory=set)


def sort_suffixes(suffixes: Iterable[str]) -> List[str]:
    return sorted(
        {str(s).strip().lower() for s in suffixes if str(s).strip()},
        key=lambda x: (x.count("."), len(x)),
        reverse=True,
    )


def create_base_lexicon() -> LexiconConfig:
    return LexiconConfig(
        common_multi_suffixes=sort_suffixes(COMMON_MULTI_SUFFIXES),
        stop_terms=set(STOP_TERMS),
        weak_common_terms=set(WEAK_COMMON_TERMS),
        important_short_terms=set(IMPORTANT_SHORT_TERMS),
        manual_strong_terms=set(MANUAL_STRONG_TERMS),
        strong_risk_words=set(STRONG_RISK_WORDS),
        medium_risk_words=set(MEDIUM_RISK_WORDS),
        weak_risk_words=set(WEAK_RISK_WORDS),
        suspicious_suffixes=set(SUSPICIOUS_SUFFIXES),
        target_indicators=set(BASE_TARGET_INDICATORS),
        high_value_suffixes=set(BASE_HIGH_VALUE_SUFFIXES),
        important_suffixes=set(BASE_IMPORTANT_SUFFIXES),
        financial_terms=set(BASE_FINANCIAL_TERMS),
    )


BASE_LEXICON = create_base_lexicon()


def resolve_lexicon(lexicon: Optional[LexiconConfig] = None) -> LexiconConfig:
    return lexicon if lexicon is not None else BASE_LEXICON


# =========================================================
# 4. 数据结构
# =========================================================

@dataclass
class DomainParts:
    raw: str
    host: str
    registered_domain: str
    sld: str
    suffix: str
    subdomain: str
    labels: List[str]
    sld_clean: str
    sld_confusable: str
    full_clean: str
    tokens: Set[str]


@dataclass
class TargetTerm:
    text: str
    grade: str  # strong / medium / short / weak


@dataclass
class TargetProfile:
    target_id: int
    raw_domain: str
    company: str
    host: str
    registered_domain: str
    sld: str
    suffix: str
    subdomain: str
    labels: List[str]
    full_clean: str
    terms: Dict[str, TargetTerm] = field(default_factory=dict)


@dataclass
class Hit:
    term: str
    grade: str
    match_kind: str      # exact / confusable / fuzzy
    position: str        # token / full / prefix / suffix / substring / combined
    similarity: float


@dataclass
class MatchResult:
    domain: str
    registered_domain: str
    sld: str
    suffix: str
    target_domain: str
    company: str
    score: float
    rule_score: float
    canine_similarity: Optional[float]
    category: str
    need_canine: bool
    match_type: str
    evidence: List[str]
    llm_label: str = ""
    llm_score: Optional[float] = None
    llm_reason: str = ""
    llm_key_features: str = ""
    llm_disposition: str = ""


# =========================================================
# 5. 域名规范化
# =========================================================

def clean_token(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


def split_label_tokens(s: str) -> List[str]:
    if not s:
        return []
    tokens = re.split(r"[^a-z0-9]+", s.lower())
    return [clean_token(t) for t in tokens if clean_token(t)]


def normalize_host(raw_value: str) -> str:
    if raw_value is None:
        return ""

    s = str(raw_value).strip().lower()
    if not s or s == "nan":
        return ""

    s = s.replace("\\", "/")
    s = s.strip(" \t\r\n\"'<>，。；;、")

    if "://" in s:
        parsed = urlparse(s)
        host = parsed.netloc
    else:
        host = s.split("/")[0]

    if "@" in host:
        host = host.split("@")[-1]

    if ":" in host:
        host = host.split(":")[0]

    host = host.strip(".")
    if host.startswith("www."):
        host = host[4:]

    host = re.sub(r"[^a-z0-9\.\-_]", "", host)
    host = re.sub(r"\.+", ".", host).strip(".")
    return host


def fallback_extract_domain(
    host: str,
    lexicon: Optional[LexiconConfig] = None,
) -> Tuple[str, str, str, str, List[str]]:
    labels = [x for x in host.split(".") if x]
    if not labels:
        return "", "", "", "", []

    if len(labels) == 1:
        return host, labels[0], "", "", labels

    active_lexicon = resolve_lexicon(lexicon)
    for suffix in active_lexicon.common_multi_suffixes:
        suffix_labels = suffix.split(".")
        if labels[-len(suffix_labels):] == suffix_labels:
            if len(labels) > len(suffix_labels):
                sld = labels[-len(suffix_labels) - 1]
                registered = ".".join(labels[-len(suffix_labels) - 1:])
                subdomain = ".".join(labels[:-len(suffix_labels) - 1])
                return registered, sld, suffix, subdomain, labels

    if (
        len(labels) >= 3
        and len(labels[-1]) == 2
        and labels[-2] in COMMON_SECOND_LEVEL_SUFFIX_LABELS
    ):
        suffix = ".".join(labels[-2:])
        sld = labels[-3]
        registered = ".".join(labels[-3:])
        subdomain = ".".join(labels[:-3])
        return registered, sld, suffix, subdomain, labels

    suffix = labels[-1]
    sld = labels[-2]
    registered = ".".join(labels[-2:])
    subdomain = ".".join(labels[:-2])
    return registered, sld, suffix, subdomain, labels


def extract_domain_parts(
    raw_value: str,
    lexicon: Optional[LexiconConfig] = None,
) -> Optional[DomainParts]:
    host = normalize_host(raw_value)
    if not host:
        return None

    labels = [x for x in host.split(".") if x]
    if not labels:
        return None

    if HAS_TLDEXTRACT:
        ext = TLD_EXTRACTOR(host)
        if ext.domain and ext.suffix:
            registered_domain = f"{ext.domain}.{ext.suffix}"
            sld = ext.domain
            suffix = ext.suffix
            subdomain = ext.subdomain
        else:
            registered_domain, sld, suffix, subdomain, labels = fallback_extract_domain(host, lexicon)
    else:
        registered_domain, sld, suffix, subdomain, labels = fallback_extract_domain(host, lexicon)

    if not sld:
        return None

    sld_clean = clean_token(sld)
    sld_confusable = clean_token(sld.translate(CONFUSABLE_TRANSLATION))
    full_clean = clean_token(host)

    tokens = set(split_label_tokens(sld))
    tokens.update(split_label_tokens(subdomain))
    tokens = {t for t in tokens if t}

    return DomainParts(
        raw=str(raw_value).strip(),
        host=host,
        registered_domain=registered_domain,
        sld=sld,
        suffix=suffix,
        subdomain=subdomain,
        labels=labels,
        sld_clean=sld_clean,
        sld_confusable=sld_confusable,
        full_clean=full_clean,
        tokens=tokens,
    )


def labels_before_suffix(labels: List[str], suffix: str) -> List[str]:
    if not labels:
        return []
    if not suffix:
        return labels
    suffix_len = len([x for x in suffix.split(".") if x])
    if suffix_len <= 0 or suffix_len >= len(labels):
        return labels
    return labels[:-suffix_len]


def add_term_stat(stats: Dict, term: str, profile_id: int, company_key: str, source: str):
    term = clean_token(term)
    if not term:
        return
    item = stats[term]
    item["profiles"].add(profile_id)
    item["companies"].add(company_key)
    item[source] += 1


def build_dynamic_lexicon(profiles: List[TargetProfile]) -> LexiconConfig:
    """
    根据本次上传的官方域名生成动态词表。
    固定词表保留为安全基线；动态词表只补充本次目标的品牌词、短缩写、
    弱通用词、目标指示词和高价值后缀。
    """
    lexicon = create_base_lexicon()

    term_stats = defaultdict(
        lambda: {
            "profiles": set(),
            "companies": set(),
            "sld_main": 0,
            "sld_split": 0,
            "subdomain": 0,
            "label": 0,
        }
    )
    official_suffixes = set()
    suffix_label_terms = set()
    company_keys = set()
    generated_stop_terms = set()
    generated_weak_terms = set()
    generated_short_terms = set()
    generated_strong_terms = set()
    generated_indicators = set()
    generated_high_value_suffixes = set()
    generated_important_suffixes = set()
    generated_financial_terms = set()

    financial_markers = {
        "bank", "finance", "financial", "securities", "insurance",
        "credit", "trust", "capital", "asset", "fund", "pay", "wallet",
    }

    for profile in profiles:
        company_key = clean_token(profile.company) or profile.registered_domain or profile.host
        company_keys.add(company_key)

        suffix = str(profile.suffix or "").lower()
        if suffix:
            official_suffixes.add(suffix)
            if "." in suffix:
                generated_important_suffixes.add(suffix)

            suffix_labels = [clean_token(x) for x in suffix.split(".") if clean_token(x)]
            suffix_label_terms.update(suffix_labels)
            generated_stop_terms.update(suffix_labels)

            for label in suffix_labels:
                if label in {"gov", "edu", "ac"}:
                    generated_indicators.add(label)
                if len(label) == 2 and label not in {"co"}:
                    generated_indicators.add(label)
                    generated_indicators.update(COUNTRY_ALIAS_BY_CC.get(label, set()))

            if suffix == "state.gov" or any(label in {"gov", "edu", "ac"} for label in suffix_labels):
                generated_high_value_suffixes.add(suffix)

        sld_clean = clean_token(profile.sld)
        sld_confusable = clean_token(profile.sld.translate(CONFUSABLE_TRANSLATION))
        for term in {sld_clean, sld_confusable}:
            add_term_stat(term_stats, term, profile.target_id, company_key, "sld_main")

        for token in split_label_tokens(profile.sld):
            add_term_stat(term_stats, token, profile.target_id, company_key, "sld_split")

        non_suffix_labels = labels_before_suffix(profile.labels, profile.suffix)
        subdomain_labels = set(split_label_tokens(profile.subdomain))

        for label in non_suffix_labels:
            label_clean = clean_token(label)
            if not label_clean:
                continue
            add_term_stat(term_stats, label_clean, profile.target_id, company_key, "label")
            if label_clean in subdomain_labels:
                add_term_stat(term_stats, label_clean, profile.target_id, company_key, "subdomain")

            for token in split_label_tokens(label):
                add_term_stat(term_stats, token, profile.target_id, company_key, "label")
                if token in subdomain_labels:
                    add_term_stat(term_stats, token, profile.target_id, company_key, "subdomain")

        company_clean = clean_token(profile.company)
        if any(marker in company_clean for marker in financial_markers):
            for term in {sld_clean, sld_confusable}:
                if term:
                    generated_financial_terms.add(term)

    profile_count = max(1, len(profiles))
    company_count = max(1, len(company_keys))
    profile_freq_threshold = max(5, int(profile_count * 0.20))
    company_freq_threshold = max(3, int(company_count * 0.20))

    for term, stat in term_stats.items():
        if term in suffix_label_terms:
            generated_stop_terms.add(term)

        if term in INFRASTRUCTURE_LABELS and stat["subdomain"] > 0:
            generated_stop_terms.add(term)

        if term in GENERIC_DOMAIN_TERMS:
            generated_weak_terms.add(term)

        if len(term) <= 2 and len(stat["profiles"]) >= 2:
            generated_stop_terms.add(term)

        is_cross_target_common = (
            len(stat["profiles"]) >= profile_freq_threshold
            and len(stat["companies"]) >= company_freq_threshold
            and stat["sld_main"] == 0
        )
        if is_cross_target_common:
            generated_weak_terms.add(term)

        if term in TARGET_INDICATOR_CANDIDATES:
            generated_indicators.add(term)

    generated_stop_terms -= {"gov", "edu", "ac"}
    generated_weak_terms -= generated_stop_terms

    blocked_terms = lexicon.stop_terms | generated_stop_terms | lexicon.weak_common_terms | generated_weak_terms

    for term, stat in term_stats.items():
        if term in blocked_terms or len(term) < 2:
            continue

        is_main_sld = stat["sld_main"] > 0
        is_subdomain_brand = stat["subdomain"] > 0 and term not in INFRASTRUCTURE_LABELS

        if is_main_sld:
            if len(term) <= 4:
                generated_short_terms.add(term)
            elif len(term) >= 5:
                generated_strong_terms.add(term)
        elif is_subdomain_brand:
            if len(term) == 4:
                generated_short_terms.add(term)
            elif len(term) >= 6:
                generated_strong_terms.add(term)

    generated_short_terms -= blocked_terms
    generated_strong_terms -= blocked_terms

    lexicon.common_multi_suffixes = sort_suffixes(set(lexicon.common_multi_suffixes) | official_suffixes)
    lexicon.stop_terms.update(generated_stop_terms)
    lexicon.weak_common_terms.update(generated_weak_terms)
    lexicon.important_short_terms.update(generated_short_terms)
    lexicon.manual_strong_terms.update(generated_strong_terms)
    lexicon.target_indicators.update(generated_indicators)
    lexicon.high_value_suffixes.update(generated_high_value_suffixes)
    lexicon.important_suffixes.update(generated_important_suffixes)
    lexicon.financial_terms.update(generated_financial_terms)
    lexicon.strong_risk_words.update(term_stats.keys() & SERVICE_STRONG_CANDIDATES)
    lexicon.medium_risk_words.update(term_stats.keys() & SERVICE_MEDIUM_CANDIDATES)

    lexicon.generated_stop_terms = generated_stop_terms
    lexicon.generated_weak_common_terms = generated_weak_terms
    lexicon.generated_important_short_terms = generated_short_terms
    lexicon.generated_manual_strong_terms = generated_strong_terms
    lexicon.generated_target_indicators = generated_indicators
    lexicon.generated_high_value_suffixes = generated_high_value_suffixes

    return lexicon


# =========================================================
# 6. 目标域名读取与目标词分级
# =========================================================

def looks_like_domain(value: str) -> bool:
    value = str(value).strip().lower()
    if value in {"", "nan"}:
        return False
    return "." in value or "/" in value


def infer_domain_and_company_columns(df: pd.DataFrame) -> Tuple[str, Optional[str]]:
    columns = list(df.columns)

    domain_col = None
    company_col = None

    for col in columns:
        name = str(col).strip().lower()
        if name in {"域名", "domain", "目标域名", "target_domain"}:
            domain_col = col
        if name in {"单位名称", "公司名称", "机构名称", "company", "organization", "单位"}:
            company_col = col

    if domain_col is None:
        scores = {}
        for col in columns:
            series = df[col].dropna().astype(str)
            if len(series) == 0:
                scores[col] = 0
            else:
                scores[col] = series.apply(looks_like_domain).mean()
        domain_col = max(scores, key=scores.get)

    if company_col is None:
        candidates = [c for c in columns if c != domain_col]
        company_col = candidates[0] if candidates else None

    return domain_col, company_col


def classify_target_term(
    term: str,
    lexicon: Optional[LexiconConfig] = None,
) -> Optional[str]:
    active_lexicon = resolve_lexicon(lexicon)
    term = clean_token(term)
    if not term:
        return None

    if term in active_lexicon.stop_terms:
        return None

    if len(term) < 2:
        return None

    if term in active_lexicon.weak_common_terms:
        return "weak"

    if term in active_lexicon.manual_strong_terms:
        return "strong"

    if term in active_lexicon.important_short_terms:
        return "short"

    if len(term) <= 3:
        return "short"

    if len(term) <= 5:
        return "medium"

    return "strong"


def build_target_terms(
    parts: DomainParts,
    lexicon: Optional[LexiconConfig] = None,
) -> Dict[str, TargetTerm]:
    candidates = set()

    # 注册域名主标签
    if parts.sld:
        candidates.add(clean_token(parts.sld))
        candidates.add(clean_token(parts.sld.translate(CONFUSABLE_TRANSLATION)))

    # 子域名标签也保留，例如 educationusa.state.gov 中的 educationusa
    for label in parts.labels:
        label_clean = clean_token(label)
        if label_clean:
            candidates.add(label_clean)

    # 连字符分词，例如 china-tower -> china, tower
    for token in split_label_tokens(parts.sld):
        candidates.add(token)

    terms = {}

    for term in candidates:
        grade = classify_target_term(term, lexicon)
        if not grade:
            continue
        terms[term] = TargetTerm(text=term, grade=grade)

    return terms


def load_target_profiles(excel_path: str) -> Tuple[List[TargetProfile], LexiconConfig]:
    df = pd.read_excel(excel_path, dtype=str)

    # 如果第一行被误当成表头，且表头里看起来像域名，则重新按无表头读取
    if any(looks_like_domain(c) for c in df.columns) and "域名" not in [str(c).strip() for c in df.columns]:
        df = pd.read_excel(excel_path, dtype=str, header=None)

    domain_col, company_col = infer_domain_and_company_columns(df)

    profiles = []
    seen_hosts = set()

    for _, row in df.iterrows():
        raw_domain = row.get(domain_col, "")
        company = row.get(company_col, "") if company_col is not None else ""
        company = "" if pd.isna(company) else str(company).strip()

        parts = extract_domain_parts(raw_domain)
        if parts is None:
            continue

        if parts.host in seen_hosts:
            continue
        seen_hosts.add(parts.host)

        profile = TargetProfile(
            target_id=len(profiles),
            raw_domain=str(raw_domain).strip(),
            company=company,
            host=parts.host,
            registered_domain=parts.registered_domain,
            sld=parts.sld,
            suffix=parts.suffix,
            subdomain=parts.subdomain,
            labels=parts.labels,
            full_clean=parts.full_clean,
            terms={},
        )

        profiles.append(profile)

    lexicon = build_dynamic_lexicon(profiles)

    for profile in profiles:
        profile.terms = build_target_terms(profile, lexicon)

    return profiles, lexicon


# =========================================================
# 7. 索引构建
# =========================================================

def build_indexes(profiles: List[TargetProfile]) -> Dict:
    term_to_targets = defaultdict(list)
    length_to_terms = defaultdict(list)
    grade_to_terms = defaultdict(set)

    exact_hosts = set()
    exact_registered = set()

    for p in profiles:
        exact_hosts.add(p.host)
        exact_registered.add(p.registered_domain)

        for term, term_obj in p.terms.items():
            term_to_targets[term].append((p.target_id, term_obj.grade))
            length_to_terms[len(term)].append(term)
            grade_to_terms[term_obj.grade].add(term)

    # 正则只用于长度 >= 4 的词，短词用严格 token / 组合规则，避免误报
    regex_terms = [
        t for t in term_to_targets.keys()
        if len(t) >= 4
    ]
    regex_terms = sorted(regex_terms, key=len, reverse=True)

    main_regex = None
    if regex_terms:
        pattern = "|".join(re.escape(t) for t in regex_terms)
        main_regex = re.compile(pattern)

    short_terms = {
        t for t in term_to_targets.keys()
        if len(t) <= 3 or any(g == "short" for _, g in term_to_targets[t])
    }

    strong_medium_terms = {
        t for t in term_to_targets.keys()
        if any(g in {"strong", "medium"} for _, g in term_to_targets[t])
    }

    return {
        "term_to_targets": term_to_targets,
        "length_to_terms": length_to_terms,
        "grade_to_terms": grade_to_terms,
        "main_regex": main_regex,
        "short_terms": short_terms,
        "strong_medium_terms": strong_medium_terms,
        "exact_hosts": exact_hosts,
        "exact_registered": exact_registered,
    }


# =========================================================
# 8. 风险词检测
# =========================================================

def contains_word_or_substring(parts: DomainParts, word: str) -> bool:
    w = clean_token(word)
    if not w:
        return False

    if w in parts.tokens:
        return True

    if len(w) >= 4 and w in parts.sld_clean:
        return True

    return False


def get_risk_hits(
    parts: DomainParts,
    lexicon: Optional[LexiconConfig] = None,
) -> Tuple[Set[str], Set[str], Set[str]]:
    active_lexicon = resolve_lexicon(lexicon)
    strong = set()
    medium = set()
    weak = set()

    for w in active_lexicon.strong_risk_words:
        if contains_word_or_substring(parts, w):
            strong.add(w)

    for w in active_lexicon.medium_risk_words:
        if contains_word_or_substring(parts, w):
            medium.add(w)

    for w in active_lexicon.weak_risk_words:
        if contains_word_or_substring(parts, w):
            weak.add(w)

    return strong, medium, weak


def has_target_indicator(
    parts: DomainParts,
    lexicon: Optional[LexiconConfig] = None,
) -> bool:
    """
    目标指示词：根据本次官方域名后缀和标签动态生成。
    对 mail、sport 等弱通用词，必须有目标指示词才更值得怀疑。
    """
    active_lexicon = resolve_lexicon(lexicon)
    indicators = {clean_token(x) for x in active_lexicon.target_indicators if clean_token(x)}
    if parts.tokens & indicators:
        return True

    s = parts.sld_clean
    for indicator in indicators:
        if len(indicator) >= 4 and indicator in s:
            return True
        if indicator in {"gov", "edu", "official"} and indicator in s:
            return True
        if indicator == "cn" and s.endswith("cn"):
            return True

    return False


def has_structure_anomaly(parts: DomainParts) -> bool:
    if "-" in parts.sld:
        return True
    if re.search(r"\d", parts.sld):
        return True
    if len(parts.sld_clean) >= 18:
        return True
    return False


def suffix_is_suspicious(
    parts: DomainParts,
    lexicon: Optional[LexiconConfig] = None,
) -> bool:
    if not parts.suffix:
        return False
    active_lexicon = resolve_lexicon(lexicon)
    last = parts.suffix.split(".")[-1]
    return last in active_lexicon.suspicious_suffixes


# =========================================================
# 9. 相似度
# =========================================================

def fuzzy_ratio(a: str, b: str, score_cutoff: float = 0.0) -> float:
    if not a or not b:
        return 0.0

    if HAS_RAPIDFUZZ:
        return float(fuzz.ratio(a, b, score_cutoff=score_cutoff))

    ratio = difflib.SequenceMatcher(None, a, b).ratio() * 100
    return ratio if ratio >= score_cutoff else 0.0


def infer_position(parts: DomainParts, term: str) -> str:
    s = parts.sld_clean

    if term in parts.tokens:
        return "token"

    if s == term:
        return "full"

    if s.startswith(term):
        return "prefix"

    if s.endswith(term):
        return "suffix"

    return "substring"


# =========================================================
# 10. 命中规则
# =========================================================

def add_hit(
    target_hits: Dict[int, List[Hit]],
    indexes: Dict,
    term: str,
    match_kind: str,
    position: str,
    similarity: float,
):
    for target_id, grade in indexes["term_to_targets"].get(term, []):
        target_hits[target_id].append(
            Hit(
                term=term,
                grade=grade,
                match_kind=match_kind,
                position=position,
                similarity=similarity,
            )
        )


def find_exact_hits(
    parts: DomainParts,
    indexes: Dict,
    lexicon: Optional[LexiconConfig] = None,
) -> Dict[int, List[Hit]]:
    active_lexicon = resolve_lexicon(lexicon)
    target_hits = defaultdict(list)
    main_regex = indexes["main_regex"]

    # 长度 >= 4 的词：正则匹配
    for text, kind in [
        (parts.sld_clean, "exact"),
        (parts.sld_confusable, "confusable"),
    ]:
        if not text or main_regex is None:
            continue

        if kind == "confusable" and text == parts.sld_clean:
            continue

        for m in main_regex.finditer(text):
            term = m.group(0)
            position = infer_position(parts, term)
            add_hit(target_hits, indexes, term, kind, position, 100.0)

    # 短词：只允许 token 命中，或者和强风险词组合
    short_terms = indexes["short_terms"]

    # token 命中
    for token in parts.tokens:
        if token in short_terms:
            add_hit(target_hits, indexes, token, "exact", "token", 100.0)

    # mfalogin / mfagov / pbcsecure 这类组合形式
    # 只有在候选域名本身包含强风险词或目标指示词时才检查短词组合
    strong_hits, medium_hits, _ = get_risk_hits(parts, active_lexicon)
    allow_short_combined = bool(strong_hits) or has_target_indicator(parts, active_lexicon)

    if allow_short_combined:
        suffix_candidates = set()
        suffix_candidates.update(clean_token(w) for w in active_lexicon.strong_risk_words)
        suffix_candidates.update(clean_token(w) for w in active_lexicon.target_indicators)

        s = parts.sld_clean

        for term in short_terms:
            if len(term) < 2:
                continue

            if s == term:
                continue

            # term + risk，例如 mfalogin、pbcsecure
            for risk in suffix_candidates:
                if not risk:
                    continue

                if s.startswith(term + risk) or s.endswith(risk + term):
                    add_hit(target_hits, indexes, term, "exact", "combined", 100.0)
                    break

    return target_hits


def find_fuzzy_hits(
    parts: DomainParts,
    indexes: Dict,
    lexicon: Optional[LexiconConfig] = None,
) -> Dict[int, List[Hit]]:
    """
    模糊匹配只用于 strong / medium 目标词，且只在候选域名已经有一定可疑性时启用。
    不对 short / weak 词做 fuzzy，避免 mee->meeting、mot->motor 这类误报。
    """
    active_lexicon = resolve_lexicon(lexicon)
    target_hits = defaultdict(list)

    strong_hits, medium_hits, _ = get_risk_hits(parts, active_lexicon)
    suspicious_context = (
        bool(strong_hits)
        or bool(medium_hits)
        or has_structure_anomaly(parts)
        or suffix_is_suspicious(parts, active_lexicon)
    )

    if not suspicious_context:
        return target_hits

    tokens = set(parts.tokens)
    tokens.add(parts.sld_clean)
    tokens.add(parts.sld_confusable)
    tokens = {t for t in tokens if 5 <= len(t) <= 40}

    if not tokens:
        return target_hits

    length_to_terms = indexes["length_to_terms"]
    strong_medium_terms = indexes["strong_medium_terms"]

    for token in tokens:
        token_len = len(token)

        candidate_terms = []
        for l in range(max(5, token_len - 2), token_len + 3):
            candidate_terms.extend(length_to_terms.get(l, []))

        candidate_terms = [
            t for t in candidate_terms
            if t in strong_medium_terms and t not in active_lexicon.weak_common_terms and len(t) >= 5
        ]

        # 限制每个 token 的比较数量
        candidate_terms = sorted(
            set(candidate_terms),
            key=lambda x: abs(len(x) - token_len)
        )[:60]

        for term in candidate_terms:
            if term in token or token in term:
                continue

            if len(term) <= 6:
                cutoff = 88
            elif len(term) <= 10:
                cutoff = 84
            else:
                cutoff = 82

            sim = fuzzy_ratio(token, term, score_cutoff=cutoff)

            if sim >= cutoff:
                add_hit(target_hits, indexes, term, "fuzzy", "fuzzy", sim)

    return target_hits


def merge_hits(*hit_dicts: Dict[int, List[Hit]]) -> Dict[int, List[Hit]]:
    merged = defaultdict(list)
    for d in hit_dicts:
        for target_id, hits in d.items():
            merged[target_id].extend(hits)
    return merged


# =========================================================
# 11. 打分与强约束过滤
# =========================================================

GRADE_PRIORITY = {
    "weak": 1,
    "short": 2,
    "medium": 3,
    "strong": 4,
}


def dedup_hits(hits: List[Hit]) -> List[Hit]:
    best = {}
    for h in hits:
        key = (h.term, h.grade, h.match_kind, h.position)
        old = best.get(key)
        if old is None or h.similarity > old.similarity:
            best[key] = h
    return list(best.values())


def best_category(hits: List[Hit]) -> str:
    if not hits:
        return "weak"
    return max(hits, key=lambda x: GRADE_PRIORITY.get(x.grade, 0)).grade


def base_brand_score(hit: Hit) -> float:
    if hit.grade == "strong":
        if hit.match_kind == "fuzzy":
            return 0.36
        if hit.position in {"token", "full"}:
            return 0.52
        if hit.position in {"prefix", "suffix", "combined"}:
            return 0.48
        return 0.42

    if hit.grade == "medium":
        if hit.match_kind == "fuzzy":
            return 0.30
        if hit.position in {"token", "full"}:
            return 0.40
        if hit.position in {"prefix", "suffix", "combined"}:
            return 0.36
        return 0.28

    if hit.grade == "short":
        if hit.position in {"token", "full"}:
            return 0.36
        if hit.position == "combined":
            return 0.34
        return 0.20

    # weak
    if hit.position in {"token", "full"}:
        return 0.22
    if hit.position == "combined":
        return 0.20
    return 0.12


def suffix_score(
    target: TargetProfile,
    parts: DomainParts,
    brand_score: float,
    lexicon: Optional[LexiconConfig] = None,
) -> Tuple[float, List[str]]:
    """
    后缀相关打分。
    注意：
    - 后缀不一致仍然参与打分，但不再写入命中原因
    - 只有可疑后缀写入命中原因，例如：候选域名使用可疑后缀 top
    """
    score = 0.0
    evidence = []

    if not parts.suffix:
        return score, evidence

    active_lexicon = resolve_lexicon(lexicon)

    # 后缀异常只在已经有较强目标命中时才有意义
    # 这里只打分，不再输出“目标后缀为 xxx，候选后缀为 xxx”
    if brand_score >= 0.30 and target.suffix and parts.suffix != target.suffix:
        if target.suffix in active_lexicon.high_value_suffixes:
            score += 0.06
        elif target.suffix in active_lexicon.important_suffixes:
            score += 0.04
        else:
            score += 0.03

    # 仅保留可疑后缀证据
    if suffix_is_suspicious(parts, active_lexicon):
        score += 0.05
        suffix_label = parts.suffix.split(".")[-1]
        evidence.append(f"候选域名使用可疑后缀 {suffix_label}")

    return min(score, 0.10), evidence


def structure_score(parts: DomainParts) -> Tuple[float, List[str]]:
    score = 0.0
    evidence = []

    if "-" in parts.sld:
        score += 0.03
        evidence.append("SLD 中包含连字符")

    if re.search(r"\d", parts.sld):
        score += 0.03
        evidence.append("SLD 中包含数字")

    if len(parts.sld_clean) >= 18:
        score += 0.03
        evidence.append("SLD 长度较长")

    if len(parts.sld_clean) >= 25:
        score += 0.02
        evidence.append("SLD 异常偏长")

    return min(score, 0.08), evidence


def target_value_score(
    target: TargetProfile,
    lexicon: Optional[LexiconConfig] = None,
) -> Tuple[float, List[str]]:
    """
    高价值目标加分。
    注意：
    - 仍然参与打分
    - 不再写入命中原因，避免出现“目标属于政府/教育类高价值域名”
    """
    score = 0.0
    active_lexicon = resolve_lexicon(lexicon)

    if target.suffix in active_lexicon.high_value_suffixes:
        score += 0.04

    if any(t in active_lexicon.financial_terms for t in target.terms):
        score += 0.04

    return min(score, 0.06), []


def risk_score(
    strong_hits: Set[str],
    medium_hits: Set[str],
    weak_hits: Set[str],
) -> Tuple[float, List[str]]:
    """
    风险词打分。
    命中原因中只保留强风险词和中风险词，弱风险词不再展示。
    """
    score = 0.0
    evidence = []

    if strong_hits:
        score += 0.24
        evidence.append("包含强风险词：" + ",".join(sorted(strong_hits)))

    if medium_hits:
        score += 0.12
        evidence.append("包含中风险词：" + ",".join(sorted(medium_hits)))

    # 弱风险词只参与极小加分，不写入命中原因
    if weak_hits:
        score += 0.03

    return min(score, 0.30), evidence


def passes_hard_gate(
    category: str,
    hits: List[Hit],
    parts: DomainParts,
    target: TargetProfile,
    strong_risk: Set[str],
    medium_risk: Set[str],
    lexicon: Optional[LexiconConfig] = None,
) -> Tuple[bool, str]:
    """
    v3 的关键：不同目标词类型使用不同硬约束。
    """
    active_lexicon = resolve_lexicon(lexicon)
    target_indicator = has_target_indicator(parts, active_lexicon)
    structure = has_structure_anomaly(parts)
    suffix_susp = suffix_is_suspicious(parts, active_lexicon)

    any_token_or_full = any(h.position in {"token", "full"} for h in hits)
    any_prefix_suffix = any(h.position in {"prefix", "suffix", "combined"} for h in hits)
    any_fuzzy = any(h.match_kind == "fuzzy" for h in hits)

    # strong：强品牌词可以召回，但纯 substring + 无风险上下文不通过
    if category == "strong":
        if any_token_or_full or any_prefix_suffix:
            return True, "强目标词命中"
        if any_fuzzy and (strong_risk or medium_risk or structure or suffix_susp):
            return True, "强目标词近似命中且存在可疑上下文"
        if strong_risk or medium_risk or structure or suffix_susp:
            return True, "强目标词子串命中且存在可疑上下文"
        return False, "强目标词仅弱子串命中，缺少可疑上下文"

    # medium：必须有风险词、目标指示词、结构异常之一
    if category == "medium":
        if strong_risk:
            return True, "中等目标词命中且包含强风险词"
        if medium_risk and (target_indicator or structure or suffix_susp):
            return True, "中等目标词命中且包含中风险上下文"
        if any_token_or_full and target_indicator and (structure or suffix_susp):
            return True, "中等目标词独立命中且包含目标指示词"
        return False, "中等目标词缺少足够上下文"

    # short：短词必须是 token / combined，且必须搭配强风险词或明确目标指示
    if category == "short":
        if not (any_token_or_full or any_prefix_suffix):
            return False, "短目标词不是独立 token 或组合形式"

        if strong_risk:
            return True, "短目标词命中且包含强风险词"

        if target_indicator and (medium_risk or structure or suffix_susp):
            return True, "短目标词命中且包含目标指示词"

        return False, "短目标词缺少强风险词或目标指示词"

    # weak：通用弱词必须同时满足：独立 token + 强风险词 + 目标指示词
    if category == "weak":
        if any_token_or_full and strong_risk and target_indicator:
            return True, "弱通用词独立命中，且包含强风险词和目标指示词"
        return False, "弱通用词不满足强约束"

    return False, "未知类别"


def category_threshold(category: str) -> float:
    if category == "strong":
        return 0.60
    if category == "medium":
        return 0.64
    if category == "short":
        return 0.62
    if category == "weak":
        return 0.74
    return 0.70


def need_canine_filter(category: str, score: float, hits: List[Hit]) -> bool:
    if category in {"short", "weak"}:
        return True
    if any(h.match_kind == "fuzzy" for h in hits):
        return True
    if category == "medium" and score < 0.72:
        return True
    if category == "strong" and score < 0.66:
        return True
    return False


def calculate_result(
    parts: DomainParts,
    target: TargetProfile,
    hits: List[Hit],
    lexicon: Optional[LexiconConfig] = None,
) -> Optional[MatchResult]:
    active_lexicon = resolve_lexicon(lexicon)
    hits = dedup_hits(hits)

    if not hits:
        return None

    category = best_category(hits)

    strong_risk, medium_risk, weak_risk = get_risk_hits(parts, active_lexicon)

    gate_ok, gate_reason = passes_hard_gate(
        category=category,
        hits=hits,
        parts=parts,
        target=target,
        strong_risk=strong_risk,
        medium_risk=medium_risk,
        lexicon=active_lexicon,
    )

    if not gate_ok:
        return None

    evidence = []

    # 只保留类似“强目标词命中”这种简短结论
    evidence.append(gate_reason)

    # 品牌/目标词命中分取最高
    brand_scores = [base_brand_score(h) for h in hits]
    brand_score = max(brand_scores) if brand_scores else 0.0

    best_hit = max(hits, key=lambda h: base_brand_score(h))

    # 精简目标词命中原因，不再输出类别、方式、相似度
    evidence.append(f"目标词命中：{best_hit.term}")

    score = brand_score

    r_score, r_evi = risk_score(strong_risk, medium_risk, weak_risk)
    score += r_score
    evidence.extend(r_evi)

    s_score, s_evi = suffix_score(target, parts, brand_score, active_lexicon)
    score += s_score
    evidence.extend(s_evi)

    st_score, st_evi = structure_score(parts)
    score += st_score
    evidence.extend(st_evi)

    # 高价值目标仍然打分，但不再写入命中原因
    tv_score, _ = target_value_score(target, active_lexicon)
    score += tv_score

    # 目标指示词仍然打分，但不再写入命中原因
    if has_target_indicator(parts, active_lexicon):
        score += 0.04

    score = min(score, 1.0)

    threshold = max(GLOBAL_MIN_SCORE, category_threshold(category))
    if score < threshold:
        return None

    match_types = sorted({
        h.grade for h in hits
    } | {
        h.match_kind for h in hits
    })

    return MatchResult(
        domain=parts.host,
        registered_domain=parts.registered_domain,
        sld=parts.sld,
        suffix=parts.suffix,
        target_domain=target.host,
        company=target.company,
        score=score,
        rule_score=score,
        canine_similarity=None,
        category=category,
        need_canine=need_canine_filter(category, score, hits),
        match_type="+".join(match_types),
        evidence=evidence,
    )


# =========================================================
# 12. 单域名检测
# =========================================================

def detect_one_domain(
    raw_domain: str,
    profiles: List[TargetProfile],
    indexes: Dict,
    lexicon: Optional[LexiconConfig] = None,
) -> Optional[MatchResult]:
    active_lexicon = resolve_lexicon(lexicon)
    parts = extract_domain_parts(raw_domain, active_lexicon)
    if parts is None:
        return None

    if SKIP_EXACT_TARGET_DOMAIN:
        if parts.host in indexes["exact_hosts"] or parts.registered_domain in indexes["exact_registered"]:
            return None

    exact_hits = find_exact_hits(parts, indexes, active_lexicon)
    fuzzy_hits = find_fuzzy_hits(parts, indexes, active_lexicon)
    all_hits = merge_hits(exact_hits, fuzzy_hits)

    if not all_hits:
        return None

    best_result = None

    for target_id, hits in all_hits.items():
        target = profiles[target_id]
        result = calculate_result(parts, target, hits, active_lexicon)

        if result is None:
            continue

        if best_result is None or result.score > best_result.score:
            best_result = result

    return best_result


# =========================================================
# 13. 流式读取新增域名
# =========================================================

def iter_domain_lines_from_txt(txt_path: str) -> Iterable[str]:
    with open(txt_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                yield line


def iter_domain_lines_from_zip(zip_path: str) -> Iterable[str]:
    with zipfile.ZipFile(zip_path, "r") as z:
        names = [n for n in z.namelist() if not n.endswith("/")]

        daily_names = [
            n for n in names
            if os.path.basename(n).lower() == "dailyupdate.txt"
        ]

        txt_names = daily_names if daily_names else [
            n for n in names
            if n.lower().endswith(".txt")
        ]

        for name in txt_names:
            with z.open(name, "r") as f:
                for raw_line in f:
                    try:
                        line = raw_line.decode("utf-8", errors="ignore").strip()
                    except Exception:
                        line = raw_line.decode("gbk", errors="ignore").strip()
                    if line:
                        yield line


def collect_input_files(top_folder: str) -> List[str]:
    files = []

    for root, _, filenames in os.walk(top_folder):
        for filename in filenames:
            path = os.path.join(root, filename)
            lower = filename.lower()

            if lower.endswith(".zip") or lower.endswith(".txt"):
                files.append(path)

    return files


def iter_all_new_domains(top_folder: str) -> Iterable[str]:
    files = collect_input_files(top_folder)

    for path in tqdm(files, desc="读取新增域名文件", disable=True):
        lower = path.lower()

        try:
            if lower.endswith(".zip"):
                yield from iter_domain_lines_from_zip(path)
            elif lower.endswith(".txt"):
                yield from iter_domain_lines_from_txt(path)
        except Exception as e:
            pass


# =========================================================
# 14. CANINE 过滤
# =========================================================

def generate_canine_embeddings(
    domains: List[str],
    model_path: str,
    batch_size: int = 64,
) -> np.ndarray:
    import torch
    from transformers import CanineTokenizer, CanineModel

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    tokenizer = CanineTokenizer.from_pretrained(model_path)
    model = CanineModel.from_pretrained(model_path).to(device)
    model.eval()

    embeddings = []

    for i in tqdm(range(0, len(domains), batch_size), desc="CANINE 嵌入计算", disable=True):
        batch_domains = domains[i:i + batch_size]

        inputs = tokenizer(
            batch_domains,
            padding=True,
            truncation=True,
            return_tensors="pt",
            max_length=128,
        ).to(device)

        with torch.no_grad():
            outputs = model(**inputs)

        sequence_output = outputs.last_hidden_state
        attention_mask = inputs.attention_mask

        mask = attention_mask.unsqueeze(-1).expand(sequence_output.size()).float()
        sum_embeddings = torch.sum(sequence_output * mask, dim=1)
        sum_mask = torch.clamp(mask.sum(dim=1), min=1e-9)
        batch_embeddings = sum_embeddings / sum_mask

        embeddings.append(batch_embeddings.cpu().numpy())

    return np.concatenate(embeddings, axis=0)


def cosine_sim_one(a: np.ndarray, b: np.ndarray) -> float:
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    if denom == 0:
        return 0.0
    return float(np.dot(a, b) / denom)


def canine_threshold_for_result(r: MatchResult) -> float:
    if r.category == "weak":
        return 0.62
    if r.category == "short":
        return 0.60
    if r.category == "medium":
        return 0.56
    if r.category == "strong":
        return 0.50
    return 0.60


def apply_canine_filter(results: List[MatchResult]) -> List[MatchResult]:
    """
    CANINE 只用于过滤歧义候选。
    注意：
    - 不再把 CANINE 相似度写入命中原因
    - 不再导出 CANINE 相似度字段
    """
    if not ENABLE_CANINE:
        return results

    need_check = [r for r in results if r.need_canine]

    if not need_check:
        return results

    if len(need_check) > CANINE_MAX_CANDIDATES:
        need_check = sorted(need_check, key=lambda x: x.rule_score, reverse=True)[:CANINE_MAX_CANDIDATES]

    checked_pairs = {(r.domain, r.target_domain) for r in need_check}

    try:
        unique_domains = sorted(set(
            [r.domain for r in need_check]
            + [r.target_domain for r in need_check]
        ))

        embeddings = generate_canine_embeddings(
            unique_domains,
            CANINE_MODEL_PATH,
            batch_size=CANINE_BATCH_SIZE,
        )

        emb_map = {d: e for d, e in zip(unique_domains, embeddings)}

        filtered = []

        for r in results:
            pair = (r.domain, r.target_domain)

            # 不需要 CANINE 的高置信规则结果直接保留
            if pair not in checked_pairs:
                filtered.append(r)
                continue

            sim = cosine_sim_one(emb_map[r.domain], emb_map[r.target_domain])
            r.canine_similarity = sim

            threshold = canine_threshold_for_result(r)

            if sim >= threshold:
                # CANINE 可以继续轻微影响分数，但不再写入命中原因
                if sim >= 0.80:
                    r.score = min(1.0, r.score + 0.06)
                elif sim >= 0.70:
                    r.score = min(1.0, r.score + 0.03)

                filtered.append(r)

        return filtered

    except Exception as e:
        return results


# =========================================================
# 15. 保存结果
# =========================================================

def risk_level(score: float) -> str:
    if score >= 0.80:
        return "高危"
    if score >= 0.68:
        return "中危"
    return "低危"



def dedup_evidence(evidence: List[str]) -> List[str]:
    """
    对命中原因去重，并过滤空字符串。
    """
    seen = set()
    result = []

    for item in evidence:
        item = str(item).strip()
        if not item:
            continue

        if item not in seen:
            seen.add(item)
            result.append(item)

    return result


def _result_to_llm_candidate(result: MatchResult) -> Dict[str, Any]:
    return {
        "domain": result.domain,
        "official_domain": result.target_domain,
        "company": result.company,
        "algorithm_score": result.score,
        "match_type": result.match_type,
        "risk_level": risk_level(result.score),
        "evidence": "；".join(dedup_evidence(result.evidence)),
    }


def _safe_float_or_none(value: Any) -> Optional[float]:
    try:
        return max(0.0, min(1.0, float(value)))
    except Exception:
        return None


def _judge_candidates_with_llm(results: List[MatchResult]) -> Tuple[List[MatchResult], Dict[str, Any]]:
    if not results:
        return [], {"status": "no_candidates", "judged_count": 0, "candidate_count": 0, "failed_batches": 0}

    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("仿冒检测LLM研判需要配置 DEEPSEEK_API_KEY，未研判结果不会输出")

    candidate_items = build_candidate_items([_result_to_llm_candidate(result) for result in results])
    batches = [
        candidate_items[index : index + LLM_BATCH_SIZE]
        for index in range(0, len(candidate_items), LLM_BATCH_SIZE)
    ]
    completed: Dict[int, List[Dict[str, Any]]] = {}
    errors: Dict[int, str] = {}
    max_workers = max(1, min(LLM_MAX_WORKERS, len(batches)))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_index = {
            executor.submit(
                judge_batch,
                api_key,
                batch,
                index + 1,
                timeout_seconds=LLM_TIMEOUT_SEC,
                max_retries=LLM_MAX_RETRIES,
                retry_sleep_seconds=LLM_RETRY_SLEEP_SEC,
                max_tokens=LLM_MAX_TOKENS,
            ): index + 1
            for index, batch in enumerate(batches)
        }
        for future in as_completed(future_to_index):
            batch_index = future_to_index[future]
            try:
                completed[batch_index] = future.result()
            except Exception as exc:
                errors[batch_index] = str(exc)

    rows: List[Dict[str, Any]] = []
    for index in sorted(completed):
        rows.extend(completed[index])

    llm_index = {str(row.get("domain") or ""): row for row in rows}
    final_results: List[MatchResult] = []
    for result in results:
        llm = llm_index.get(result.domain)
        if not llm:
            continue
        result.llm_label = str(llm.get("label") or "uncertain")
        result.llm_score = _safe_float_or_none(llm.get("impersonation_likelihood"))
        result.llm_reason = str(llm.get("reason") or "")
        key_features = llm.get("key_features") or ""
        if isinstance(key_features, list):
            result.llm_key_features = ",".join(str(item) for item in key_features)
        else:
            result.llm_key_features = str(key_features)
        result.llm_disposition = str(llm.get("disposition") or "")
        if result.llm_disposition in KEEP_RECOMMENDATIONS:
            final_results.append(result)

    status = "completed" if not errors else ("failed" if not rows else "partial_failed")
    return final_results, {
        "status": status,
        "model": os.getenv("DEEPSEEK_MODEL", LLM_MODEL_NAME),
        "judged_count": len(rows),
        "candidate_count": len(results),
        "batch_size": LLM_BATCH_SIZE,
        "batch_count": len(batches),
        "failed_batches": len(errors),
        "errors": errors,
        "kept_count": len(final_results),
    }

'''"规则分": f"{r.rule_score:.4f}",
        "CANINE相似度": "" if r.canine_similarity is None else f"{r.canine_similarity:.4f}",
        "目标词类别": r.category,
        "是否CANINE复核": "是" if r.need_canine else "否",
        "匹配类型": r.match_type,'''
def result_to_dict(r: MatchResult) -> Dict[str, str]:
    """
    最终导出的字段。
    仅保留用户需要的 6 列。
    """
    return {
        "疑似仿冒域名": r.domain,
        "官方域名": r.target_domain,
        "单位名称": r.company,
        "风险等级": risk_level(r.score),
        "最终风险分": f"{r.score:.4f}",
        "命中原因": "；".join(dedup_evidence(r.evidence)),
    }




def save_results(results: List[MatchResult], output_dir: str):
    """
    仅导出 xlsx 文件，不再导出 csv。
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d")
    xlsx_path = os.path.join(output_dir, f"仿冒域名检测结果_v3_{timestamp}.xlsx")

    columns = [
        "疑似仿冒域名",
        "官方域名",
        "单位名称",
        "风险等级",
        "最终风险分",
        "命中原因",
    ]

    if results:
        df = pd.DataFrame([result_to_dict(r) for r in results])
        df = df[columns]
    else:
        df = pd.DataFrame(columns=columns)

    try:
        df.to_excel(xlsx_path, index=False, engine="openpyxl")
    except Exception as e:
        raise RuntimeError(f"Excel 保存失败: {e}") from e


def _load_target_profiles_from_records(official_domains: List[Tuple[str, str]]) -> Tuple[List[TargetProfile], LexiconConfig]:
    profiles = []
    seen_hosts = set()

    for company, raw_domain in official_domains:
        parts = extract_domain_parts(raw_domain)
        if parts is None:
            continue
        if parts.host in seen_hosts:
            continue
        seen_hosts.add(parts.host)
        profiles.append(
            TargetProfile(
                target_id=len(profiles),
                raw_domain=str(raw_domain).strip(),
                company=str(company or "").strip(),
                host=parts.host,
                registered_domain=parts.registered_domain,
                sld=parts.sld,
                suffix=parts.suffix,
                subdomain=parts.subdomain,
                labels=parts.labels,
                full_clean=parts.full_clean,
                terms={},
            )
        )

    lexicon = build_dynamic_lexicon(profiles)
    for profile in profiles:
        profile.terms = build_target_terms(profile, lexicon)
    return profiles, lexicon


def _coerce_official_domains(official_domains) -> List[Tuple[str, str]]:
    coerced = []
    for item in official_domains or []:
        company = ""
        domain = ""
        if isinstance(item, dict):
            company = item.get("单位名称") or item.get("公司名称") or item.get("company") or item.get("organization") or ""
            domain = item.get("官方域名") or item.get("域名") or item.get("domain") or item.get("目标域名") or item.get("target_domain") or ""
        elif isinstance(item, (list, tuple)):
            if len(item) >= 2:
                company, domain = item[0], item[1]
            elif len(item) == 1:
                domain = item[0]
        else:
            domain = item
        domain = normalize_host(str(domain or ""))
        company = str(company or "").strip()
        if domain:
            coerced.append((company, domain))
    return coerced


def _build_official_domain_dataframe(official_domains) -> pd.DataFrame:
    rows = []
    seen = set()
    for item in official_domains or []:
        company = ""
        domain = ""
        confidence = ""
        source = ""
        reason = ""
        if isinstance(item, dict):
            company = item.get("单位名称") or item.get("公司名称") or item.get("company") or item.get("organization") or ""
            domain = item.get("官方域名") or item.get("域名") or item.get("domain") or item.get("目标域名") or item.get("target_domain") or ""
            confidence = item.get("confidence") if item.get("confidence") is not None else ""
            source = item.get("source") or ""
            reason = item.get("reason") or item.get("evidence") or ""
        elif isinstance(item, (list, tuple)):
            if len(item) >= 2:
                company, domain = item[0], item[1]
            elif len(item) == 1:
                domain = item[0]
        else:
            domain = item

        normalized_domain = normalize_host(str(domain or ""))
        if not normalized_domain or normalized_domain in seen:
            continue
        seen.add(normalized_domain)
        rows.append({
            "单位名称": str(company or "").strip(),
            "官方域名": normalized_domain,
            "置信度": confidence,
            "来源": source,
            "说明": str(reason or "").strip(),
        })
    return pd.DataFrame(rows, columns=["单位名称", "官方域名", "置信度", "来源", "说明"])


def _read_domains_from_table(file_content: bytes, filename: str) -> pd.DataFrame:
    file_ext = filename.split(".")[-1].lower() if "." in filename else ""
    if file_ext == "csv":
        return pd.read_csv(io.BytesIO(file_content), dtype=str)
    if file_ext == "xlsx":
        return pd.read_excel(io.BytesIO(file_content), dtype=str)
    if file_ext == "txt":
        lines = file_content.decode("utf-8", errors="ignore").splitlines()
        rows = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"[,，\t]+", line, maxsplit=1)
            if len(parts) == 1:
                rows.append({"域名": parts[0].strip()})
            else:
                rows.append({"单位名称": parts[0].strip(), "域名": parts[1].strip()})
        return pd.DataFrame(rows)
    raise ValueError(f"不支持的文件类型: {file_ext}")


def read_official_domains_from_file(file_content: bytes, filename: str) -> List[Tuple[str, str]]:
    try:
        df = _read_domains_from_table(file_content, filename)
        if df.empty:
            return []
        domain_col, company_col = infer_domain_and_company_columns(df)
        official_domains = []
        for _, row in df.iterrows():
            domain = normalize_host(row.get(domain_col, ""))
            company = row.get(company_col, "") if company_col is not None else ""
            if pd.isna(company):
                company = ""
            if domain:
                official_domains.append((str(company).strip(), domain))
        return official_domains
    except Exception as exc:
        raise ValueError(f"读取官方域名文件失败: {exc}") from exc


def read_detection_domains_from_file(file_content: bytes, filename: str) -> List[str]:
    try:
        df = _read_domains_from_table(file_content, filename)
        if df.empty:
            return []
        domain_col = None
        for col in df.columns:
            name = str(col).strip().lower()
            if name in {"域名", "domain", "待检测域名", "新注册域名"}:
                domain_col = col
                break
        if domain_col is None:
            domain_col = df.columns[0]
        domains = []
        seen = set()
        for value in df[domain_col].dropna().tolist():
            domain = normalize_host(value)
            if domain and domain not in seen:
                seen.add(domain)
                domains.append(domain)
        return domains
    except Exception as exc:
        raise ValueError(f"读取待检测域名文件失败: {exc}") from exc


def _run_detection(
    official_domains: List[Tuple[str, str]],
    detection_domains: List[str],
    similarity_threshold: Optional[float] = None,
) -> Tuple[List[MatchResult], dict]:
    official_domains = _coerce_official_domains(official_domains)
    if not official_domains:
        raise ValueError("官方域名列表为空")
    if not detection_domains:
        raise ValueError("待检测域名列表为空")

    profiles, lexicon = _load_target_profiles_from_records(official_domains)
    if not profiles:
        raise ValueError("官方域名列表中没有有效域名")

    _log_required(f"成功加载官方域名数量: {len(profiles)}")
    _log_required(f"新增域名总计处理: {len(detection_domains):,} 条")

    indexes = build_indexes(profiles)
    results_by_domain: Dict[str, MatchResult] = {}
    for raw_domain in detection_domains:
        result = detect_one_domain(raw_domain, profiles, indexes, lexicon)
        if result is None:
            continue
        old = results_by_domain.get(result.domain)
        if old is None or result.score > old.score:
            results_by_domain[result.domain] = result

    results = list(results_by_domain.values())
    if results:
        results = apply_canine_filter(results)

    min_score = similarity_threshold if similarity_threshold is not None else GLOBAL_MIN_SCORE
    results = [
        r for r in results
        if r.score >= max(float(min_score), category_threshold(r.category))
    ]
    llm_candidates_count = len(results)
    results, llm_meta = _judge_candidates_with_llm(results)
    results.sort(key=lambda x: x.score, reverse=True)
    _log_required(f"最终输出疑似仿冒域名数量: {len(results):,}")

    statistics = {
        "total": len(detection_domains),
        "phishing": len(results),
        "benign": len(detection_domains) - len(results),
        "phishing_rate": len(results) / len(detection_domains) * 100 if detection_domains else 0,
        "总域名数": len(detection_domains),
        "算法候选数": llm_candidates_count,
        "钓鱼域名数": len(results),
        "正常域名数": len(detection_domains) - len(results),
        "钓鱼域名占比": f"{len(results) / len(detection_domains) * 100:.2f}%" if detection_domains else "0.00%",
        "LLM研判状态": llm_meta.get("status"),
        "LLM研判模型": llm_meta.get("model", LLM_MODEL_NAME),
        "LLM已研判数": llm_meta.get("judged_count", 0),
    }
    return results, statistics


def _build_result_dataframe(results: List[MatchResult]) -> pd.DataFrame:
    columns = [
        "钓鱼域名",
        "官方域名",
        "公司名称",
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
    rows = []
    for result in results:
        rows.append({
            "钓鱼域名": result.domain,
            "官方域名": result.target_domain,
            "公司名称": result.company,
            "相似度": f"{result.score:.4f}",
            "匹配类型": result.match_type,
            "风险等级": risk_level(result.score),
            "命中原因": "；".join(dedup_evidence(result.evidence)),
            "LLM研判标签": result.llm_label,
            "LLM研判分数": "" if result.llm_score is None else f"{result.llm_score:.4f}",
            "研判原因": result.llm_reason,
            "LLM处置结果": result.llm_disposition,
            "关键特征": result.llm_key_features,
        })
    return pd.DataFrame(rows, columns=columns)


def _build_result_excel(results: List[MatchResult], statistics: dict, official_domains) -> bytes:
    df = _build_result_dataframe(results)
    official_df = _build_official_domain_dataframe(official_domains)
    excel_buffer = io.BytesIO()
    with pd.ExcelWriter(excel_buffer, engine="openpyxl") as writer:
        df.to_excel(writer, sheet_name="检测结果", index=False)
        stats_df = pd.DataFrame({
            "统计项": ["总域名数", "算法候选数", "钓鱼域名数", "正常域名数", "钓鱼域名占比", "LLM研判状态", "LLM研判模型", "LLM已研判数"],
            "数值": [
                statistics.get("total", 0),
                statistics.get("算法候选数", 0),
                statistics.get("phishing", 0),
                statistics.get("benign", 0),
                f"{statistics.get('phishing_rate', 0):.2f}%",
                statistics.get("LLM研判状态", ""),
                statistics.get("LLM研判模型", ""),
                statistics.get("LLM已研判数", 0),
            ],
        })
        stats_df.to_excel(writer, sheet_name="统计信息", index=False)
        official_df.to_excel(writer, sheet_name="官方域名列表", index=False)
    return excel_buffer.getvalue()


def detect_phishing_domains(
    official_domains: List[Tuple[str, str]],
    detection_domains: List[str],
    similarity_threshold: Optional[float] = None,
) -> Tuple[pd.DataFrame, dict]:
    results, statistics = _run_detection(official_domains, detection_domains, similarity_threshold)
    return _build_result_dataframe(results), statistics


def predict_from_domains(
    official_domains: List[Tuple[str, str]],
    detection_domains: List[str],
    similarity_threshold: Optional[float] = None,
) -> Tuple[bytes, dict]:
    results, statistics = _run_detection(official_domains, detection_domains, similarity_threshold)
    return _build_result_excel(results, statistics, official_domains), statistics


def predict_from_file(
    official_file_content: bytes,
    official_filename: str,
    detection_file_content: bytes | None = None,
    detection_filename: str | None = None,
    detection_domains: List[str] | None = None,
    similarity_threshold: Optional[float] = None,
) -> Tuple[bytes, dict]:
    official_domains = read_official_domains_from_file(official_file_content, official_filename)
    if detection_domains is None:
        if detection_file_content is None or detection_filename is None:
            raise ValueError("必须提供待检测域名文件或域名列表")
        detection_domains = read_detection_domains_from_file(detection_file_content, detection_filename)
    return predict_from_domains(official_domains, detection_domains, similarity_threshold=similarity_threshold)


# =========================================================
# 16. 主流程
# =========================================================

def print_target_term_stats(profiles: List[TargetProfile]):
    return None


def print_dynamic_lexicon_stats(lexicon: LexiconConfig):
    return None


def main():
    profiles, lexicon = load_target_profiles(TARGET_EXCEL_PATH)

    if not profiles:
        return

    _log_required(f"成功加载官方域名数量: {len(profiles)}")
    print_dynamic_lexicon_stats(lexicon)
    print_target_term_stats(profiles)

    indexes = build_indexes(profiles)

    results_by_domain: Dict[str, MatchResult] = {}

    total = 0
    rule_matched = 0

    for raw_domain in iter_all_new_domains(NEW_DOMAIN_FOLDER):
        total += 1

        result = detect_one_domain(raw_domain, profiles, indexes, lexicon)

        if result is not None:
            rule_matched += 1

            old = results_by_domain.get(result.domain)
            if old is None or result.score > old.score:
                results_by_domain[result.domain] = result

    _log_required(f"新增域名总计处理: {total:,} 条")

    results = list(results_by_domain.values())

    if results:
        results = apply_canine_filter(results)

    results = [
        r for r in results
        if r.score >= max(GLOBAL_MIN_SCORE, category_threshold(r.category))
    ]

    results.sort(key=lambda x: x.score, reverse=True)

    _log_required(f"最终输出疑似仿冒域名数量: {len(results):,}")

    save_results(results, OUTPUT_DIR)


if __name__ == "__main__":
    main()
