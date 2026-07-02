from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

import pandas as pd
import yaml
from rapidfuzz import fuzz
from rapidfuzz.distance import Levenshtein

try:
    from .normalize import confusable_normalize, normalize_domain
except ImportError:  # pragma: no cover - used when run as python candidate_recall.py
    from normalize import confusable_normalize, normalize_domain


OUTPUT_FIELDS = [
    "candidate_domain",
    "candidate_registered_domain",
    "candidate_sld",
    "candidate_suffix",
    "candidate_subdomain",
    "target_name",
    "target_domain",
    "target_sld",
    "target_suffix",
    "matched_token",
    "matched_token_type",
    "recall_reason",
    "rule_score",
    "hard_filter_pass",
]
AUDIT_FIELDS = [
    *OUTPUT_FIELDS,
    "pre_filter_score",
    "hard_filter_reason",
]
CONTEXT_FIELDS = [
    "candidate_domain",
    "candidate_registered_domain",
    "candidate_sld",
    "candidate_suffix",
    "candidate_subdomain",
    "candidate_tokens",
    "subdomain_tokens",
    "strong_risk_words",
    "medium_risk_words",
    "weak_risk_words",
    "is_suspicious_tld",
    "has_structure_anomaly",
]

READ_ENCODINGS = ("utf-8-sig", "utf-8", "gbk")
PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_KEYWORDS_PATH = PACKAGE_DIR / "configs/keywords.yaml"
DEFAULT_TOKEN_POLICY_PATH = PACKAGE_DIR / "configs/token_policy.yaml"
MIN_TOKEN_LEN = 2
SHORT_RECALL_MIN_LEN = 3
FUZZY_RATIO_MIN = 88
FUZZY_MAX_LENGTH_DELTA = 2
TRANSPOSITION_MIN_TOKEN_LEN = 5
TRANSPOSITION_NEAR_RATIO_MIN = 90
TRANSPOSITION_NEAR_MAX_DISTANCE = 1
SPELLING_VARIANT_MIN_TOKEN_LEN = 5
SPELLING_VARIANT_MAX_LENGTH_DELTA = 1
DEFAULT_SPELLING_VARIANT_BLOCK_BASE_TOKENS = {
    "account",
    "admin",
    "app",
    "auth",
    "bank",
    "cloud",
    "email",
    "help",
    "login",
    "mail",
    "online",
    "pay",
    "payment",
    "portal",
    "secure",
    "service",
    "shop",
    "site",
    "store",
    "support",
    "verify",
    "web",
}
DEFAULT_SPELLING_VARIANT_COMPLETE_WORD_BLOCK_TOKENS = {
    "import",
    "lay",
    "pages",
    "play",
    "sense",
}
DEFAULT_SPELLING_VARIANT_SUFFIX_PAIR_BLOCKS = {
    ("lay", "pay"),
    ("play", "pay"),
}

DEFAULT_STRONG_RISK_WORDS = {
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
DEFAULT_MEDIUM_RISK_WORDS = {
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
DEFAULT_WEAK_RISK_WORDS = {
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
DEFAULT_SUSPICIOUS_TLDS = {
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

EMBEDDED_TOKEN_ALLOWED_FRAGMENTS = (
    DEFAULT_STRONG_RISK_WORDS
    | DEFAULT_MEDIUM_RISK_WORDS
    | DEFAULT_WEAK_RISK_WORDS
    | {
        "cdn",
        "cdns",
        "go",
        "my",
        "safe",
    }
)
TARGET_INDICATOR_CONTEXTS = {"government", "education", "finance"}
NON_PROMOTING_MEDIUM_RISK_WORDS = {"cn", "gov"}
INDEXED_TOKEN_TYPES = ("strong", "medium", "short", "weak")
RECALL_TOKEN_TYPES = ("strong", "medium", "short")
REASON_PRIORITY = {
    "subdomain_deception": 60,
    "confusable_match": 50,
    "spelling_variant_match": 47,
    "no_hyphen_match": 45,
    "tld_replace": 45,
    "transposition_match": 44,
    "risk_word_combo": 35,
    "fuzzy_match": 25,
    "exact_match": 20,
}


@dataclass(frozen=True)
class TokenRef:
    profile_idx: int
    token: str
    token_type: str


@dataclass
class CandidateContext:
    parsed: dict[str, Any]
    sld: str
    sld_no_hyphen: str
    sld_confusable_norm: str
    subdomain: str
    suffix: str
    candidate_tokens: set[str]
    subdomain_tokens: set[str]
    strong_risk_words: set[str]
    medium_risk_words: set[str]
    weak_risk_words: set[str]
    is_suspicious_tld: bool
    has_structure_anomaly: bool

    @property
    def has_strong_risk(self) -> bool:
        return bool(self.strong_risk_words)

    @property
    def has_any_risk(self) -> bool:
        return bool(self.strong_risk_words or self.medium_risk_words or self.weak_risk_words)

    @property
    def promoting_medium_risk_words(self) -> set[str]:
        return self.medium_risk_words - NON_PROMOTING_MEDIUM_RISK_WORDS

    @property
    def has_promoting_risk(self) -> bool:
        return bool(self.strong_risk_words or self.promoting_medium_risk_words)


class RecallIndex:
    def __init__(
        self,
        profiles: pd.DataFrame,
        spelling_variant_block_base_tokens: set[str] | None = None,
        spelling_variant_complete_word_block_tokens: set[str] | None = None,
        spelling_variant_suffix_pair_blocks: set[tuple[str, str]] | None = None,
    ) -> None:
        self.profiles = profiles.reset_index(drop=True)
        self.spelling_variant_block_base_tokens = (
            set(DEFAULT_SPELLING_VARIANT_BLOCK_BASE_TOKENS)
            if spelling_variant_block_base_tokens is None
            else set(spelling_variant_block_base_tokens)
        )
        self.spelling_variant_complete_word_block_tokens = (
            set(DEFAULT_SPELLING_VARIANT_COMPLETE_WORD_BLOCK_TOKENS)
            if spelling_variant_complete_word_block_tokens is None
            else set(spelling_variant_complete_word_block_tokens)
        )
        self.spelling_variant_suffix_pair_blocks = (
            set(DEFAULT_SPELLING_VARIANT_SUFFIX_PAIR_BLOCKS)
            if spelling_variant_suffix_pair_blocks is None
            else set(spelling_variant_suffix_pair_blocks)
        )
        self.token_index: dict[str, list[TokenRef]] = defaultdict(list)
        self.token_index_by_type: dict[str, dict[str, list[TokenRef]]] = {
            token_type: defaultdict(list) for token_type in INDEXED_TOKEN_TYPES
        }
        self.no_hyphen_index: dict[str, list[TokenRef]] = defaultdict(list)
        self.no_hyphen_index_by_type: dict[str, dict[str, list[TokenRef]]] = {
            token_type: defaultdict(list) for token_type in INDEXED_TOKEN_TYPES
        }
        self.confusable_index: dict[str, list[TokenRef]] = defaultdict(list)
        self.confusable_index_by_type: dict[str, dict[str, list[TokenRef]]] = {
            token_type: defaultdict(list) for token_type in INDEXED_TOKEN_TYPES
        }
        self.target_sld_index: dict[str, list[int]] = defaultdict(list)
        self.tokens_by_length: dict[int, list[TokenRef]] = defaultdict(list)
        self.tokens_by_first_char: dict[str, dict[int, list[TokenRef]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.tokens_by_prefix: dict[str, dict[int, list[TokenRef]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.spelling_variant_index: dict[str, list[TokenRef]] = defaultdict(list)
        self.token_lengths: set[int] = set()
        self.token_lengths_by_type: dict[str, set[int]] = {
            token_type: set() for token_type in INDEXED_TOKEN_TYPES
        }
        self.no_hyphen_lengths: set[int] = set()
        self.no_hyphen_lengths_by_type: dict[str, set[int]] = {
            token_type: set() for token_type in INDEXED_TOKEN_TYPES
        }
        self.confusable_lengths: set[int] = set()
        self.confusable_lengths_by_type: dict[str, set[int]] = {
            token_type: set() for token_type in INDEXED_TOKEN_TYPES
        }
        self._build()

    def _build(self) -> None:
        seen_refs: set[tuple[int, str, str]] = set()
        for profile_idx, row in self.profiles.iterrows():
            target_sld = _clean_token(row.get("target_sld", ""))
            indexed_target_tokens = {
                token
                for token_type in RECALL_TOKEN_TYPES
                for token in parse_token_list(row.get(f"{token_type}_tokens", ""))
            }
            if target_sld and target_sld in indexed_target_tokens:
                self.target_sld_index[target_sld].append(profile_idx)

            for token_type in INDEXED_TOKEN_TYPES:
                column = f"{token_type}_tokens"
                for token in parse_token_list(row.get(column, "")):
                    if len(token) < MIN_TOKEN_LEN:
                        continue
                    if token_type == "short" and len(token) < SHORT_RECALL_MIN_LEN:
                        continue
                    ref_key = (profile_idx, token, token_type)
                    if ref_key in seen_refs:
                        continue
                    seen_refs.add(ref_key)
                    ref = TokenRef(profile_idx=profile_idx, token=token, token_type=token_type)
                    self.token_index[token].append(ref)
                    self.token_index_by_type[token_type][token].append(ref)
                    self.token_lengths.add(len(token))
                    self.token_lengths_by_type[token_type].add(len(token))

                    no_hyphen = token.replace("-", "")
                    if no_hyphen and len(no_hyphen) >= MIN_TOKEN_LEN:
                        self.no_hyphen_index[no_hyphen].append(ref)
                        self.no_hyphen_index_by_type[token_type][no_hyphen].append(ref)
                        self.no_hyphen_lengths.add(len(no_hyphen))
                        self.no_hyphen_lengths_by_type[token_type].add(len(no_hyphen))

                    confusable = confusable_normalize(token)
                    if confusable and len(confusable) >= MIN_TOKEN_LEN:
                        self.confusable_index[confusable].append(ref)
                        self.confusable_index_by_type[token_type][confusable].append(ref)
                        self.confusable_lengths.add(len(confusable))
                        self.confusable_lengths_by_type[token_type].add(len(confusable))

                    if token_type in {"strong", "medium"}:
                        self.tokens_by_length[len(token)].append(ref)
                        self.tokens_by_first_char[token[0]][len(token)].append(ref)
                        prefix = token[:2] if len(token) >= 2 else token[0]
                        self.tokens_by_prefix[prefix][len(token)].append(ref)
                    if token_type == "strong" and len(token) >= SPELLING_VARIANT_MIN_TOKEN_LEN:
                        for variant in _one_char_deletion_variants(token):
                            self.spelling_variant_index[variant].append(ref)


def read_csv_with_fallback(path: str | Path) -> pd.DataFrame:
    input_path = Path(path)
    errors: list[str] = []
    for encoding in READ_ENCODINGS:
        try:
            return pd.read_csv(input_path, encoding=encoding)
        except UnicodeDecodeError as exc:
            errors.append(f"{encoding}: {exc}")
    raise ValueError(f"failed to read {input_path} with supported encodings: {'; '.join(errors)}")


def load_keywords(path: str | Path = DEFAULT_KEYWORDS_PATH) -> dict[str, set[str]]:
    config_path = Path(path)
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
    else:
        data = {}

    return {
        "strong_risk_words": set(data.get("strong_risk_words") or DEFAULT_STRONG_RISK_WORDS),
        "medium_risk_words": set(data.get("medium_risk_words") or DEFAULT_MEDIUM_RISK_WORDS),
        "weak_risk_words": set(data.get("weak_risk_words") or DEFAULT_WEAK_RISK_WORDS),
        "suspicious_tlds": set(data.get("suspicious_tlds") or DEFAULT_SUSPICIOUS_TLDS),
    }


def load_token_policy(path: str | Path = DEFAULT_TOKEN_POLICY_PATH) -> dict[str, set[str]]:
    """Load recall token policy used to block generic spelling-variant bases."""
    data: dict[str, Any] = {}
    config_path = Path(path) if str(path).strip() else None
    if config_path and config_path.is_file():
        with config_path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}

    configured_block = _normalize_policy_tokens(data.get("spelling_variant_block_base_tokens") or set())
    configured_complete_word_block = _normalize_policy_tokens(
        data.get("spelling_variant_complete_word_block_tokens") or set()
    )
    configured_suffix_pair_blocks = _normalize_suffix_pair_blocks(
        data.get("spelling_variant_suffix_pair_blocks") or set()
    )
    weak_tokens = _normalize_policy_tokens(
        set(data.get("weak_tokens") or set()) | set(data.get("weak_target_tokens") or set())
    )
    generic_medium_tokens = _normalize_policy_tokens(
        set(data.get("generic_medium_target_tokens") or set())
        | set(data.get("generic_medium_tokens") or set())
        | set(data.get("medium_tokens") or set())
    )
    forbidden_strong = _normalize_policy_tokens(data.get("forbidden_strong_tokens") or set())
    inherited_tokens = _normalize_policy_tokens(
        set(data.get("inherited_tokens") or set()) | set(data.get("inherited_target_tokens") or set())
    )

    spelling_variant_block_base_tokens = (
        set(DEFAULT_SPELLING_VARIANT_BLOCK_BASE_TOKENS)
        | DEFAULT_STRONG_RISK_WORDS
        | DEFAULT_MEDIUM_RISK_WORDS
        | DEFAULT_WEAK_RISK_WORDS
        | configured_block
        | weak_tokens
        | generic_medium_tokens
        | forbidden_strong
        | inherited_tokens
    )
    spelling_variant_complete_word_block_tokens = (
        set(DEFAULT_SPELLING_VARIANT_COMPLETE_WORD_BLOCK_TOKENS)
        | configured_complete_word_block
        | weak_tokens
        | generic_medium_tokens
    )
    spelling_variant_suffix_pair_blocks = (
        set(DEFAULT_SPELLING_VARIANT_SUFFIX_PAIR_BLOCKS) | configured_suffix_pair_blocks
    )
    return {
        "spelling_variant_block_base_tokens": spelling_variant_block_base_tokens,
        "spelling_variant_complete_word_block_tokens": spelling_variant_complete_word_block_tokens,
        "spelling_variant_suffix_pair_blocks": spelling_variant_suffix_pair_blocks,
    }


def recall_candidates(
    domains: pd.DataFrame,
    profiles: pd.DataFrame,
    domain_col: str = "domain",
    keywords: dict[str, set[str]] | None = None,
    token_policy: dict[str, set[str]] | None = None,
) -> pd.DataFrame:
    """Generate candidate_domain x target_domain recall pairs."""
    recalled, _, _ = recall_candidates_with_audit(
        domains,
        profiles,
        domain_col=domain_col,
        keywords=keywords,
        token_policy=token_policy,
        audit=False,
    )
    return recalled


def recall_candidates_with_audit(
    domains: pd.DataFrame,
    profiles: pd.DataFrame,
    domain_col: str = "domain",
    keywords: dict[str, set[str]] | None = None,
    token_policy: dict[str, set[str]] | None = None,
    audit: bool = True,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Generate recall pairs plus optional pre-filter audit and candidate context."""
    if domain_col not in domains.columns:
        raise ValueError(f"domain column not found: {domain_col}")

    keyword_sets = keywords or load_keywords()
    policy = token_policy if token_policy is not None else load_token_policy()
    recall_index = RecallIndex(
        profiles,
        spelling_variant_block_base_tokens=policy.get("spelling_variant_block_base_tokens"),
        spelling_variant_complete_word_block_tokens=policy.get(
            "spelling_variant_complete_word_block_tokens"
        ),
        spelling_variant_suffix_pair_blocks=policy.get("spelling_variant_suffix_pair_blocks"),
    )
    records: list[dict[str, Any]] = []
    context_records: list[dict[str, Any]] = []

    for raw_domain in domains[domain_col].dropna().drop_duplicates():
        context = build_candidate_context(raw_domain, keyword_sets)
        context_records.append(_candidate_context_record(context))
        if not context.sld:
            continue
        records.extend(_recall_one_candidate(context, recall_index, keyword_sets, audit=audit))

    contexts = pd.DataFrame(context_records, columns=CONTEXT_FIELDS)
    if not records:
        return pd.DataFrame(columns=OUTPUT_FIELDS), pd.DataFrame(columns=AUDIT_FIELDS), contexts

    audit_pairs = pd.DataFrame(records)
    audit_pairs = audit_pairs.sort_values(
        by=["hard_filter_pass", "rule_score", "candidate_domain", "target_domain"],
        ascending=[False, False, True, True],
    )
    audit_pairs = audit_pairs.drop_duplicates(
        subset=["candidate_domain", "target_domain"], keep="first"
    )
    recalled = audit_pairs[audit_pairs["hard_filter_pass"]].copy()
    return (
        recalled[OUTPUT_FIELDS].reset_index(drop=True),
        audit_pairs[AUDIT_FIELDS].reset_index(drop=True),
        contexts.reset_index(drop=True),
    )


def build_candidate_context(raw_domain: Any, keywords: dict[str, set[str]]) -> CandidateContext:
    parsed = normalize_domain(raw_domain)
    sld = _clean_token(parsed.get("sld_clean") or parsed.get("sld", ""))
    subdomain = _clean_domain_part(parsed.get("subdomain", ""))
    suffix = str(parsed.get("suffix", "")).lower()
    sld_no_hyphen = sld.replace("-", "")
    sld_confusable_norm = confusable_normalize(sld)
    candidate_tokens = set(_split_domain_tokens(sld))
    subdomain_tokens = set(_split_domain_tokens(subdomain))
    all_tokens = candidate_tokens | subdomain_tokens

    strong_risk_words = _matched_words(all_tokens, keywords["strong_risk_words"])
    medium_risk_words = _matched_words(all_tokens, keywords["medium_risk_words"])
    weak_risk_words = _matched_words(all_tokens, keywords["weak_risk_words"])
    label_count = int(parsed.get("label_count") or 0)
    has_structure_anomaly = bool(
        subdomain
        or label_count >= 4
        or sld.count("-") >= 2
        or parsed.get("is_punycode")
        or parsed.get("starts_with_xn")
    )

    return CandidateContext(
        parsed=parsed,
        sld=sld,
        sld_no_hyphen=sld_no_hyphen,
        sld_confusable_norm=sld_confusable_norm,
        subdomain=subdomain,
        suffix=suffix,
        candidate_tokens=candidate_tokens,
        subdomain_tokens=subdomain_tokens,
        strong_risk_words=strong_risk_words,
        medium_risk_words=medium_risk_words,
        weak_risk_words=weak_risk_words,
        is_suspicious_tld=suffix in keywords["suspicious_tlds"],
        has_structure_anomaly=has_structure_anomaly,
    )


def parse_token_list(value: Any) -> list[str]:
    if pd.isna(value):
        return []
    return [
        token
        for token in (_clean_token(part) for part in str(value).split("|"))
        if token and token != "nan"
    ]


def summarize_recalled_pairs(recalled: pd.DataFrame) -> dict[str, Any]:
    if recalled.empty:
        return {
            "recall_count": 0,
            "hard_filter_pass_count": 0,
            "recall_reason_counts": {},
            "matched_token_type_counts": {},
        }
    return {
        "recall_count": int(len(recalled)),
        "hard_filter_pass_count": int(recalled["hard_filter_pass"].sum()),
        "recall_reason_counts": recalled["recall_reason"].value_counts().to_dict(),
        "matched_token_type_counts": recalled["matched_token_type"].value_counts().to_dict(),
    }


def write_recalled_pairs(recalled: pd.DataFrame, output: str | Path) -> None:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    recalled.to_csv(output_path, index=False, encoding="utf-8-sig")


def write_audit_outputs(
    audit_pairs: pd.DataFrame,
    contexts: pd.DataFrame,
    audit_output: str | Path | None = None,
    rejected_output: str | Path | None = None,
    context_output: str | Path | None = None,
) -> None:
    if audit_output:
        output_path = Path(audit_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        audit_pairs.to_csv(output_path, index=False, encoding="utf-8-sig")
        print(f"audit_output_rows={len(audit_pairs)}")
    if rejected_output:
        rejected = audit_pairs[~audit_pairs["hard_filter_pass"]].copy()
        output_path = Path(rejected_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        rejected.to_csv(output_path, index=False, encoding="utf-8-sig")
        print(f"rejected_output_rows={len(rejected)}")
    if context_output:
        output_path = Path(context_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        contexts.to_csv(output_path, index=False, encoding="utf-8-sig")
        print(f"context_output_rows={len(contexts)}")


def _recall_one_candidate(
    context: CandidateContext,
    recall_index: RecallIndex,
    keywords: dict[str, set[str]],
    audit: bool = False,
) -> list[dict[str, Any]]:
    match_map: dict[tuple[int, str], dict[str, Any]] = {}
    active_types = _audit_token_types(context) if audit else _active_token_types(context)

    _add_substring_matches_for_types(
        match_map,
        context,
        recall_index,
        recall_index.token_index_by_type,
        recall_index.token_lengths_by_type,
        context.sld,
        "exact_match",
        base_score=0.78,
        token_types=active_types,
        allow_weak=audit,
    )
    for token in context.candidate_tokens:
        for token_type in active_types:
            for ref in recall_index.token_index_by_type[token_type].get(token, []):
                _add_match(
                    match_map,
                    context,
                    recall_index,
                    ref,
                    "exact_match",
                    0.82,
                    allow_weak=audit,
                )

    if "-" in context.sld:
        _add_substring_matches_for_types(
            match_map,
            context,
            recall_index,
            recall_index.no_hyphen_index_by_type,
            recall_index.no_hyphen_lengths_by_type,
            context.sld_no_hyphen,
            "no_hyphen_match",
            base_score=0.84,
            token_types=active_types,
            allow_weak=audit,
        )

    if context.sld_confusable_norm != context.sld:
        _add_substring_matches_for_types(
            match_map,
            context,
            recall_index,
            recall_index.confusable_index_by_type,
            recall_index.confusable_lengths_by_type,
            context.sld_confusable_norm,
            "confusable_match",
            base_score=0.86,
            token_types=active_types,
            allow_weak=audit,
        )

    if context.subdomain:
        _add_substring_matches_for_types(
            match_map,
            context,
            recall_index,
            recall_index.token_index_by_type,
            recall_index.token_lengths_by_type,
            context.subdomain,
            "subdomain_deception",
            base_score=0.90,
            token_types=active_types,
            allow_weak=audit,
        )

    _add_spelling_variant_matches(match_map, context, recall_index)
    _add_transposition_matches(match_map, context, recall_index)

    for profile_idx in recall_index.target_sld_index.get(context.sld, []):
        row = recall_index.profiles.iloc[profile_idx]
        if str(row.get("target_suffix", "")).lower() != context.suffix:
            target_sld = _clean_token(row.get("target_sld", ""))
            ref = _token_ref_for_target_sld(row, profile_idx, target_sld)
            _add_match(match_map, context, recall_index, ref, "tld_replace", 0.82)

    _add_fuzzy_matches(match_map, context, recall_index)

    records: list[dict[str, Any]] = []
    for match in match_map.values():
        row = recall_index.profiles.iloc[match["profile_idx"]]
        hard_filter_pass, hard_filter_reason = _hard_filter_decision(context, row, match)
        if not hard_filter_pass and not audit:
            continue
        score = _score_match(context, match, hard_filter_pass)
        records.append(
            {
                "candidate_domain": context.parsed["normalized_domain"],
                "candidate_registered_domain": context.parsed["registered_domain"],
                "candidate_sld": context.sld,
                "candidate_suffix": context.suffix,
                "candidate_subdomain": context.parsed["subdomain"],
                "target_name": row.get("target_name", ""),
                "target_domain": row.get("target_domain", ""),
                "target_sld": row.get("target_sld", ""),
                "target_suffix": row.get("target_suffix", ""),
                "matched_token": match["matched_token"],
                "matched_token_type": match["matched_token_type"],
                "recall_reason": match["recall_reason"],
                "rule_score": round(score, 4),
                "hard_filter_pass": bool(hard_filter_pass),
                "pre_filter_score": round(float(match["base_score"]), 4),
                "hard_filter_reason": hard_filter_reason,
            }
        )

    return records


def _active_token_types(context: CandidateContext) -> tuple[str, ...]:
    token_types = ["strong"]
    if context.has_promoting_risk or context.is_suspicious_tld or context.has_structure_anomaly:
        token_types.append("medium")
    if context.has_strong_risk or (
        context.is_suspicious_tld and context.has_promoting_risk
    ):
        token_types.append("short")
    return tuple(token_types)


def _audit_token_types(context: CandidateContext) -> tuple[str, ...]:
    """Audit normal recall candidates plus weak-token rejections without exploding search space."""
    token_types = list(_active_token_types(context))
    for token_type in ("short", "weak"):
        if token_type not in token_types:
            token_types.append(token_type)
    return tuple(token_types)


def _add_substring_matches_for_types(
    match_map: dict[tuple[int, str], dict[str, Any]],
    context: CandidateContext,
    recall_index: RecallIndex,
    index_by_type: dict[str, dict[str, list[TokenRef]]],
    token_lengths_by_type: dict[str, set[int]],
    text: str,
    reason: str,
    base_score: float,
    token_types: Sequence[str],
    allow_weak: bool = False,
) -> None:
    if not text:
        return
    for token_type in token_types:
        index = index_by_type[token_type]
        token_lengths = token_lengths_by_type[token_type]
        for substring in _candidate_substrings(text, token_lengths):
            for ref in index.get(substring, []):
                _add_match(
                    match_map,
                    context,
                    recall_index,
                    ref,
                    reason,
                    base_score,
                    allow_weak=allow_weak,
                )


def _add_fuzzy_matches(
    match_map: dict[tuple[int, str], dict[str, Any]],
    context: CandidateContext,
    recall_index: RecallIndex,
) -> None:
    fuzzy_inputs = {
        token
        for token in {context.sld, context.sld_no_hyphen, *context.candidate_tokens}
        if len(token) >= 5
    }
    if context.has_any_risk or context.is_suspicious_tld or context.has_structure_anomaly:
        fuzzy_inputs.update(
            token
            for token in context.subdomain_tokens
            if len(token) >= 5
        )

    for candidate in fuzzy_inputs:
        length_range = range(
            max(MIN_TOKEN_LEN, len(candidate) - FUZZY_MAX_LENGTH_DELTA),
            len(candidate) + FUZZY_MAX_LENGTH_DELTA + 1,
        )
        refs: list[TokenRef] = []
        prefix = candidate[:2] if len(candidate) >= 2 else candidate[0]
        prefix_buckets = recall_index.tokens_by_prefix.get(prefix, {})
        for token_len in length_range:
            refs.extend(prefix_buckets.get(token_len, []))

        for ref in refs:
            if ref.token == candidate:
                continue
            row = recall_index.profiles.iloc[ref.profile_idx]
            if _is_generic_or_weak_profile_token(row, ref.token):
                continue
            if _is_blocked_spelling_variant_base(candidate, recall_index.spelling_variant_block_base_tokens):
                continue
            if _is_blocked_spelling_variant_pair(candidate, ref.token, context, recall_index):
                continue
            ratio = fuzz.ratio(candidate, ref.token)
            if ratio >= FUZZY_RATIO_MIN:
                _add_match(
                    match_map,
                    context,
                    recall_index,
                    ref,
                    "fuzzy_match",
                    min(0.79, ratio / 100),
                )


def _add_transposition_matches(
    match_map: dict[tuple[int, str], dict[str, Any]],
    context: CandidateContext,
    recall_index: RecallIndex,
) -> None:
    for candidate in _transposition_inputs(context):
        prefix = candidate[:2] if len(candidate) >= 2 else candidate[:1]
        prefix_buckets = recall_index.tokens_by_prefix.get(prefix, {})
        refs: list[TokenRef] = []
        for token_len in range(
            max(MIN_TOKEN_LEN, len(candidate) - TRANSPOSITION_NEAR_MAX_DISTANCE),
            len(candidate) + TRANSPOSITION_NEAR_MAX_DISTANCE + 1,
        ):
            refs.extend(prefix_buckets.get(token_len, []))

        for ref in refs:
            if ref.token_type != "strong" or ref.token == candidate:
                continue
            row = recall_index.profiles.iloc[ref.profile_idx]
            if _is_generic_or_weak_profile_token(row, ref.token):
                continue
            if _is_blocked_spelling_variant_pair(candidate, ref.token, context, recall_index):
                continue
            score = _transposition_match_score(candidate, ref.token)
            if score <= 0:
                continue
            _add_match(
                match_map,
                context,
                recall_index,
                ref,
                "transposition_match",
                score,
            )


def _add_spelling_variant_matches(
    match_map: dict[tuple[int, str], dict[str, Any]],
    context: CandidateContext,
    recall_index: RecallIndex,
) -> None:
    for candidate in _spelling_variant_inputs(context):
        refs = _spelling_variant_refs(candidate, recall_index)
        for ref in refs:
            if ref.token_type != "strong" or ref.token == candidate:
                continue
            row = recall_index.profiles.iloc[ref.profile_idx]
            if _is_generic_or_weak_profile_token(row, ref.token):
                continue
            if _is_blocked_spelling_variant_pair(candidate, ref.token, context, recall_index):
                continue
            score = _spelling_variant_match_score(
                candidate,
                ref.token,
                recall_index.spelling_variant_block_base_tokens,
            )
            if score <= 0:
                continue
            _add_match(
                match_map,
                context,
                recall_index,
                ref,
                "spelling_variant_match",
                score,
            )


def _spelling_variant_inputs(context: CandidateContext) -> set[str]:
    candidates = {
        token
        for token in {context.sld_no_hyphen, *context.candidate_tokens}
        if len(token) >= SPELLING_VARIANT_MIN_TOKEN_LEN
    }
    if "-" not in context.sld and len(context.sld) >= SPELLING_VARIANT_MIN_TOKEN_LEN:
        candidates.add(context.sld)
    if context.has_any_risk or context.is_suspicious_tld or context.has_structure_anomaly:
        candidates.update(
            token
            for token in context.subdomain_tokens
            if len(token) >= SPELLING_VARIANT_MIN_TOKEN_LEN
        )
    return {candidate for candidate in candidates if re.fullmatch(r"[a-z0-9]+", candidate or "")}


def _spelling_variant_refs(candidate: str, recall_index: RecallIndex) -> list[TokenRef]:
    if not candidate:
        return []
    if _is_blocked_spelling_variant_base(
        candidate,
        recall_index.spelling_variant_block_base_tokens,
    ):
        return []
    if candidate in recall_index.token_index_by_type["strong"]:
        return []
    refs: list[TokenRef] = []
    seen: set[tuple[int, str, str]] = set()
    lookup_keys = set()
    collapsed = _collapse_repeated_chars(candidate)
    if collapsed != candidate:
        lookup_keys.add(("exact", collapsed))
    for variant in _one_char_deletion_variants(candidate):
        lookup_keys.add(("exact", variant))
        lookup_keys.add(("deleted", variant))
    lookup_keys.add(("deleted", candidate))

    for lookup_kind, key_value in lookup_keys:
        if lookup_kind == "exact":
            bucket = recall_index.token_index_by_type["strong"].get(key_value, [])
        else:
            bucket = recall_index.spelling_variant_index.get(key_value, [])
        for ref in bucket:
            key = (ref.profile_idx, ref.token, ref.token_type)
            if key not in seen:
                seen.add(key)
                refs.append(ref)
    return refs


def _spelling_variant_match_score(
    candidate: str,
    target: str,
    spelling_variant_block_base_tokens: set[str] | None = None,
) -> float:
    if _is_blocked_spelling_variant_base(candidate, spelling_variant_block_base_tokens):
        return 0.0
    if len(candidate) < SPELLING_VARIANT_MIN_TOKEN_LEN or len(target) < SPELLING_VARIANT_MIN_TOKEN_LEN:
        return 0.0
    collapsed = _collapse_repeated_chars(candidate)
    if collapsed != candidate and collapsed == target:
        return 0.87
    if abs(len(candidate) - len(target)) > SPELLING_VARIANT_MAX_LENGTH_DELTA:
        return 0.0
    distance = Levenshtein.distance(candidate, target)
    if distance != 1:
        return 0.0
    if len(candidate) == len(target) + 1:
        return 0.86
    if len(candidate) + 1 == len(target):
        return 0.84
    if len(candidate) == len(target):
        return 0.83
    return 0.0


def _is_blocked_spelling_variant_base(
    candidate: str,
    spelling_variant_block_base_tokens: set[str] | None = None,
) -> bool:
    value = _clean_token(candidate).replace("-", "")
    block_tokens = (
        spelling_variant_block_base_tokens
        if spelling_variant_block_base_tokens is not None
        else DEFAULT_SPELLING_VARIANT_BLOCK_BASE_TOKENS
    )
    if value in block_tokens:
        return True
    return value in DEFAULT_STRONG_RISK_WORDS or value in DEFAULT_MEDIUM_RISK_WORDS or value in DEFAULT_WEAK_RISK_WORDS


def _is_blocked_spelling_variant_pair(
    candidate: str,
    target: str,
    context: CandidateContext,
    recall_index: RecallIndex,
) -> bool:
    candidate_value = _clean_token(candidate).replace("-", "")
    target_value = _clean_token(target).replace("-", "")
    if not candidate_value or not target_value:
        return False

    candidate_tokens = {
        _clean_token(token).replace("-", "")
        for token in {*context.candidate_tokens, *context.subdomain_tokens}
        if token
    }
    complete_word_blocks = recall_index.spelling_variant_complete_word_block_tokens
    for token in candidate_tokens & complete_word_blocks:
        if candidate_value == token or candidate_value.endswith(token):
            return True

    for candidate_suffix, target_suffix in recall_index.spelling_variant_suffix_pair_blocks:
        if not candidate_suffix or not target_suffix:
            continue
        if not candidate_value.endswith(candidate_suffix) or not target_value.endswith(target_suffix):
            continue
        candidate_prefix = candidate_value[: -len(candidate_suffix)]
        target_prefix = target_value[: -len(target_suffix)]
        if candidate_prefix and candidate_prefix == target_prefix:
            return True
    return False


def _collapse_repeated_chars(text: str) -> str:
    return re.sub(r"([a-z0-9])\1+", r"\1", text or "")


def _one_char_deletion_variants(text: str) -> set[str]:
    value = text or ""
    if len(value) < SPELLING_VARIANT_MIN_TOKEN_LEN:
        return set()
    return {
        value[:idx] + value[idx + 1 :]
        for idx in range(len(value))
        if len(value) - 1 >= SPELLING_VARIANT_MIN_TOKEN_LEN
    }


def _transposition_inputs(context: CandidateContext) -> set[str]:
    candidates = {
        token
        for token in {context.sld_no_hyphen, *context.candidate_tokens}
        if len(token) >= TRANSPOSITION_MIN_TOKEN_LEN
    }
    if "-" not in context.sld and len(context.sld) >= TRANSPOSITION_MIN_TOKEN_LEN:
        candidates.add(context.sld)
    if context.has_any_risk or context.is_suspicious_tld or context.has_structure_anomaly:
        candidates.update(
            token
            for token in context.subdomain_tokens
            if len(token) >= TRANSPOSITION_MIN_TOKEN_LEN
        )
    return {candidate for candidate in candidates if re.fullmatch(r"[a-z0-9]+", candidate or "")}


def _transposition_match_score(candidate: str, target: str) -> float:
    if len(candidate) < TRANSPOSITION_MIN_TOKEN_LEN or len(target) < TRANSPOSITION_MIN_TOKEN_LEN:
        return 0.0
    if abs(len(candidate) - len(target)) > TRANSPOSITION_NEAR_MAX_DISTANCE:
        return 0.0
    if _single_adjacent_swap_match(candidate, target):
        return 0.84
    base_ratio = fuzz.ratio(candidate, target)
    if base_ratio < 80:
        return 0.0
    for variant in _adjacent_swap_variants(candidate):
        if Levenshtein.distance(variant, target) > TRANSPOSITION_NEAR_MAX_DISTANCE:
            continue
        ratio = fuzz.ratio(variant, target)
        if ratio >= TRANSPOSITION_NEAR_RATIO_MIN:
            return min(0.83, ratio / 100)
    return 0.0


def _single_adjacent_swap_match(candidate: str, target: str) -> bool:
    if len(candidate) != len(target) or candidate == target:
        return False
    return target in _adjacent_swap_variants(candidate)


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


def _is_generic_or_weak_profile_token(row: pd.Series, token: str) -> bool:
    token = _clean_token(token)
    if not token:
        return True
    for column in ("weak_tokens", "inherited_tokens", "medium_tokens"):
        if token in parse_token_list(row.get(column, "")):
            return True
    return False


def _add_match(
    match_map: dict[tuple[int, str], dict[str, Any]],
    context: CandidateContext,
    recall_index: RecallIndex,
    ref: TokenRef,
    reason: str,
    base_score: float,
    allow_weak: bool = False,
) -> None:
    if ref.token_type in {"weak", "inherited"} and not allow_weak:
        return
    if reason == "no_hyphen_match" and ref.token in context.sld:
        return
    if reason == "confusable_match" and ref.token in context.sld:
        return

    row = recall_index.profiles.iloc[ref.profile_idx]
    if reason == "risk_word_combo" and not context.has_any_risk:
        return

    reason = _promote_reason_for_context(reason, context)
    score = _adjust_base_score(base_score, ref.token_type, reason)
    key = (ref.profile_idx, ref.token)
    previous = match_map.get(key)
    rank = REASON_PRIORITY.get(reason, 0)
    previous_rank = REASON_PRIORITY.get(previous["recall_reason"], 0) if previous else -1
    if previous is None or (rank, score) > (previous_rank, previous["base_score"]):
        match_map[key] = {
            "profile_idx": ref.profile_idx,
            "matched_token": ref.token,
            "matched_token_type": ref.token_type,
            "recall_reason": reason,
            "base_score": score,
            "target_indicators": row.get("target_indicators", ""),
        }


def _promote_reason_for_context(reason: str, context: CandidateContext) -> str:
    if reason in {
        "subdomain_deception",
        "tld_replace",
        "confusable_match",
        "spelling_variant_match",
        "transposition_match",
        "no_hyphen_match",
    }:
        return reason
    if context.has_promoting_risk:
        return "risk_word_combo"
    return reason


def _adjust_base_score(base_score: float, token_type: str, reason: str) -> float:
    score = base_score
    if reason == "risk_word_combo":
        score = max(score, 0.88)
    elif reason == "subdomain_deception":
        score = max(score, 0.90)
    elif reason == "confusable_match":
        score = max(score, 0.86)
    elif reason == "spelling_variant_match":
        score = max(score, 0.85)
    elif reason == "transposition_match":
        score = max(score, 0.84)
    elif reason == "no_hyphen_match":
        score = max(score, 0.84)
    elif reason == "tld_replace":
        score = max(score, 0.82)
    if token_type in {"weak", "inherited"}:
        score = min(score, 0.42)
    elif token_type == "short":
        score = min(score, 0.58)
    elif token_type == "medium":
        score = min(score, 0.72)
    return score


def _hard_filter_pass(context: CandidateContext, row: pd.Series, match: dict[str, Any]) -> bool:
    return _hard_filter_decision(context, row, match)[0]


def _hard_filter_decision(
    context: CandidateContext,
    row: pd.Series,
    match: dict[str, Any],
) -> tuple[bool, str]:
    token_type = str(match["matched_token_type"])
    reason = str(match["recall_reason"])
    indicators = set(parse_token_list(row.get("target_indicators", "")))
    has_indicator_context = bool(indicators & TARGET_INDICATOR_CONTEXTS)
    has_structural_context = reason in {"subdomain_deception", "tld_replace"} or (
        context.has_structure_anomaly and reason != "exact_match"
    )

    if token_type == "weak":
        return False, "weak_token_only"
    if token_type == "inherited":
        return False, "inherited_token_not_enough_target_evidence"
    if token_type == "short":
        passed = bool(
            context.has_strong_risk
            or (context.is_suspicious_tld and context.has_promoting_risk)
            or (has_indicator_context and context.has_strong_risk)
        )
        if passed:
            return True, "pass"
        return False, "short_token_without_strong_risk_or_suspicious_tld"
    if token_type == "medium":
        matched_token = _clean_token(match.get("matched_token", ""))
        if _is_embedded_word_completion_noise(context, matched_token, reason):
            return False, "medium_token_embedded_in_completed_word"
        passed = bool(context.has_promoting_risk or context.is_suspicious_tld or has_structural_context)
        if passed:
            return True, "pass"
        return False, "medium_token_without_risk_structure_or_suspicious_tld"
    if token_type == "strong":
        target_sld = _clean_token(row.get("target_sld", ""))
        matched_token = _clean_token(match.get("matched_token", ""))
        if _is_embedded_word_completion_noise(context, matched_token, reason):
            return False, "strong_token_embedded_in_completed_word"
        passed = bool(
            matched_token == target_sld
            or len(matched_token) >= 8
            or context.has_promoting_risk
            or has_structural_context
        )
        if passed:
            return True, "pass"
        return False, "strong_substring_without_specific_or_context"
    return False, "unknown_token_type"


def _is_embedded_word_completion_noise(
    context: CandidateContext,
    matched_token: str,
    reason: str,
) -> bool:
    """Reject target tokens that only appear as letters inside another word.

    Examples: digitlabs -> gitlab, geniusbank -> usbank, shizucloud -> ucloud.
    Prefix brand extensions such as alipaygo remain allowed.
    """
    if reason not in {"exact_match", "no_hyphen_match", "confusable_match"}:
        return False
    if context.has_promoting_risk:
        return False

    token = _clean_token(matched_token)
    if not token:
        return False
    if reason == "no_hyphen_match":
        text = context.sld_no_hyphen
        token = token.replace("-", "")
    elif reason == "confusable_match":
        text = context.sld_confusable_norm
        token = confusable_normalize(token)
    else:
        text = context.sld

    position = text.find(token)
    if position < 0:
        return False

    end = position + len(token)
    left_boundary = position == 0 or not text[position - 1].isalpha()
    right_boundary = end == len(text) or not text[end].isalpha()
    if left_boundary and right_boundary:
        return False

    left_extra = _alpha_tail(text[:position])
    right_extra = _alpha_head(text[end:])
    if _is_allowed_embedded_extra(left_extra) or _is_allowed_embedded_extra(right_extra):
        return False

    if not left_boundary and not right_boundary:
        return True
    if not left_boundary and right_boundary and len(left_extra) >= 2:
        return True
    return False


def _alpha_tail(text: str) -> str:
    match = re.search(r"([a-z]+)$", text or "")
    return match.group(1) if match else ""


def _alpha_head(text: str) -> str:
    match = re.search(r"^([a-z]+)", text or "")
    return match.group(1) if match else ""


def _is_allowed_embedded_extra(extra: str) -> bool:
    if not extra:
        return False
    if extra in EMBEDDED_TOKEN_ALLOWED_FRAGMENTS:
        return True
    return any(
        len(fragment) >= 3 and (extra.startswith(fragment) or extra.endswith(fragment))
        for fragment in EMBEDDED_TOKEN_ALLOWED_FRAGMENTS
    )


def _score_match(context: CandidateContext, match: dict[str, Any], hard_filter_pass: bool) -> float:
    score = float(match["base_score"])
    if context.is_suspicious_tld:
        score += 0.04
    if context.has_strong_risk:
        score += 0.04
    elif context.promoting_medium_risk_words:
        score += 0.02

    if not hard_filter_pass:
        return min(score, 0.39)
    return min(score, 0.99)


def _token_ref_for_target_sld(row: pd.Series, profile_idx: int, target_sld: str) -> TokenRef:
    for token_type in RECALL_TOKEN_TYPES:
        if target_sld in parse_token_list(row.get(f"{token_type}_tokens", "")):
            return TokenRef(profile_idx=profile_idx, token=target_sld, token_type=token_type)
    return TokenRef(profile_idx=profile_idx, token=target_sld, token_type="strong")


def _candidate_context_record(context: CandidateContext) -> dict[str, Any]:
    return {
        "candidate_domain": context.parsed.get("normalized_domain", ""),
        "candidate_registered_domain": context.parsed.get("registered_domain", ""),
        "candidate_sld": context.sld,
        "candidate_suffix": context.suffix,
        "candidate_subdomain": context.parsed.get("subdomain", ""),
        "candidate_tokens": _join_sorted(context.candidate_tokens),
        "subdomain_tokens": _join_sorted(context.subdomain_tokens),
        "strong_risk_words": _join_sorted(context.strong_risk_words),
        "medium_risk_words": _join_sorted(context.medium_risk_words),
        "weak_risk_words": _join_sorted(context.weak_risk_words),
        "is_suspicious_tld": bool(context.is_suspicious_tld),
        "has_structure_anomaly": bool(context.has_structure_anomaly),
    }


def _candidate_substrings(text: str, token_lengths: set[int]) -> Iterable[str]:
    seen: set[str] = set()
    text_len = len(text)
    for token_len in token_lengths:
        if token_len < MIN_TOKEN_LEN or token_len > text_len:
            continue
        for start in range(0, text_len - token_len + 1):
            substring = text[start : start + token_len]
            if substring not in seen:
                seen.add(substring)
                yield substring


def _split_domain_tokens(text: str) -> list[str]:
    return [_clean_token(token) for token in re.findall(r"[a-z0-9]+", text or "") if token]


def _matched_words(tokens: set[str], words: set[str]) -> set[str]:
    return {word for word in words if word in tokens}


def _clean_token(value: Any) -> str:
    return re.sub(r"[^a-z0-9-]+", "", str(value).lower()).strip("-")


def _clean_domain_part(value: Any) -> str:
    return re.sub(r"[^a-z0-9.-]+", "", str(value).lower()).strip(".")


def _normalize_policy_tokens(values: Iterable[Any]) -> set[str]:
    return {
        cleaned
        for value in values
        if (cleaned := _clean_token(value).replace("-", ""))
    }


def _normalize_suffix_pair_blocks(values: Iterable[Any]) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for value in values:
        if isinstance(value, dict):
            candidate = _clean_token(value.get("candidate_suffix", "")).replace("-", "")
            target = _clean_token(value.get("target_suffix", "")).replace("-", "")
        else:
            parts = re.split(r"[:>|,]", str(value), maxsplit=1)
            if len(parts) != 2:
                continue
            candidate = _clean_token(parts[0]).replace("-", "")
            target = _clean_token(parts[1]).replace("-", "")
        if candidate and target:
            pairs.add((candidate, target))
    return pairs


def _join_sorted(values: Iterable[str]) -> str:
    return "|".join(sorted(value for value in values if value))


def _print_summary(summary: dict[str, Any]) -> None:
    print(f"recall_count={summary['recall_count']}")
    print(f"hard_filter_pass_count={summary['hard_filter_pass_count']}")
    reason_counts = summary["recall_reason_counts"]
    token_type_counts = summary["matched_token_type_counts"]
    print(f"recall_reason_count={len(reason_counts)}")
    for reason, count in reason_counts.items():
        print(f"recall_reason.{reason}={count}")
    print(f"matched_token_type_count={len(token_type_counts)}")
    for token_type, count in token_type_counts.items():
        print(f"matched_token_type.{token_type}={count}")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recall candidate-domain x target-domain pairs with domain-string rules."
    )
    parser.add_argument("--domains", required=True, help="CSV file containing candidate domains.")
    parser.add_argument("--profiles", required=True, help="Target profiles CSV file.")
    parser.add_argument("--output", required=True, help="Output recalled pairs CSV file.")
    parser.add_argument("--domain-col", default="domain", help="Candidate domain column name.")
    parser.add_argument(
        "--audit-output",
        help="Optional CSV path for all pre-filter rule-hit pairs.",
    )
    parser.add_argument(
        "--rejected-output",
        help="Optional CSV path for rule-hit pairs rejected by hard filters.",
    )
    parser.add_argument(
        "--context-output",
        help="Optional CSV path for per-candidate pre-recall context.",
    )
    parser.add_argument(
        "--keywords",
        default=str(DEFAULT_KEYWORDS_PATH),
        help="Risk-word keyword YAML path.",
    )
    parser.add_argument(
        "--token-policy",
        default=str(DEFAULT_TOKEN_POLICY_PATH),
        help="Token policy YAML path for broad-token spelling-variant blocking.",
    )
    parser.add_argument(
        "--disable-token-policy",
        action="store_true",
        help="Use legacy spelling-variant blocking without configs/token_policy.yaml additions.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    domains = read_csv_with_fallback(args.domains)
    profiles = read_csv_with_fallback(args.profiles)
    keywords = load_keywords(args.keywords)
    token_policy = (
        {
            "spelling_variant_block_base_tokens": set(DEFAULT_SPELLING_VARIANT_BLOCK_BASE_TOKENS),
            "spelling_variant_complete_word_block_tokens": set(
                DEFAULT_SPELLING_VARIANT_COMPLETE_WORD_BLOCK_TOKENS
            ),
            "spelling_variant_suffix_pair_blocks": set(DEFAULT_SPELLING_VARIANT_SUFFIX_PAIR_BLOCKS),
        }
        if args.disable_token_policy
        else load_token_policy(args.token_policy)
    )
    needs_audit = bool(args.audit_output or args.rejected_output or args.context_output)
    recalled, audit_pairs, contexts = recall_candidates_with_audit(
        domains,
        profiles,
        domain_col=args.domain_col,
        keywords=keywords,
        token_policy=token_policy,
        audit=needs_audit,
    )
    write_recalled_pairs(recalled, args.output)
    if needs_audit:
        write_audit_outputs(
            audit_pairs,
            contexts,
            audit_output=args.audit_output,
            rejected_output=args.rejected_output,
            context_output=args.context_output,
        )

    summary = summarize_recalled_pairs(recalled)
    _print_summary(summary)
    print(f"output={Path(args.output)}")


if __name__ == "__main__":
    main()
