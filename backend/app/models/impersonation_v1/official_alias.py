from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Sequence

import pandas as pd

try:
    from .normalize import normalize_domain
    from .target_profile import load_token_policy
except ImportError:  # pragma: no cover - used when run as python official_alias.py
    from normalize import normalize_domain
    from target_profile import load_token_policy


READ_ENCODINGS = ("utf-8-sig", "utf-8", "gbk")
PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_WHITELIST = PACKAGE_DIR / "data/whitelist_clean.csv"
DEFAULT_PROFILES = PACKAGE_DIR / "data/target_profiles.csv"
DEFAULT_GROUPS_OUT = PACKAGE_DIR / "data/official_alias_groups.csv"
DEFAULT_NEGATIVES_OUT = PACKAGE_DIR / "data/official_alias_negative_pairs.csv"
DEFAULT_TOKEN_POLICY = Path("configs/token_policy.yaml")
NAME_COLUMNS = ("单位名称", "target_name", "name", "org_name", "organization")
DOMAIN_COLUMNS = ("域名", "target_domain", "domain", "normalized_domain", "host")
GROUP_REASON_PRIORITY = ("exact_name", "normalized_name", "same_sld_diff_suffix")
GROUP_COLUMNS = [
    "alias_group_id",
    "target_name",
    "target_domain",
    "target_sld",
    "target_suffix",
    "group_reason",
]
NEGATIVE_COLUMNS = [
    "candidate_domain",
    "candidate_registered_domain",
    "candidate_sld",
    "candidate_suffix",
    "candidate_subdomain",
    "target_name",
    "target_domain",
    "target_registered_domain",
    "target_sld",
    "target_suffix",
    "target_subdomain",
    "label",
    "sample_type",
    "source_type",
    "rule_score",
    "matched_token",
    "matched_token_type",
    "recall_reason",
    "hard_filter_pass",
    "is_official_alias",
    "alias_group_id",
]


class UnionFind:
    def __init__(self, values: Sequence[str]) -> None:
        self.parent = {value: value for value in values}

    def find(self, value: str) -> str:
        parent = self.parent.setdefault(value, value)
        if parent != value:
            self.parent[value] = self.find(parent)
        return self.parent[value]

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        self.parent[right_root] = left_root


def read_csv_with_fallback(path: str | Path) -> pd.DataFrame:
    input_path = Path(path)
    errors: list[str] = []
    for encoding in READ_ENCODINGS:
        try:
            return pd.read_csv(input_path, encoding=encoding, low_memory=False)
        except UnicodeDecodeError as exc:
            errors.append(f"{encoding}: {exc}")
    raise ValueError(f"failed to read {input_path}: {'; '.join(errors)}")


def build_official_alias_groups(
    whitelist: pd.DataFrame | None,
    profiles: pd.DataFrame | None,
    weak_tokens: set[str] | None = None,
    generic_tokens: set[str] | None = None,
) -> pd.DataFrame:
    records = load_target_records(whitelist, profiles)
    if records.empty:
        return pd.DataFrame(columns=GROUP_COLUMNS)

    weak = {token.lower() for token in (weak_tokens or set())}
    generic = {token.lower() for token in (generic_tokens or set())}
    records = records.drop_duplicates("target_domain", keep="first").reset_index(drop=True)
    domains = records["target_domain"].tolist()
    uf = UnionFind(domains)
    domain_reasons: dict[str, set[str]] = {domain: set() for domain in domains}

    for reason, key_column in (("exact_name", "target_name"), ("normalized_name", "normalized_name")):
        for _, group in records[records[key_column] != ""].groupby(key_column, dropna=False):
            union_domain_group(group["target_domain"].tolist(), reason, uf, domain_reasons)

    sld_candidates = records[
        records["target_sld"].map(lambda value: is_safe_sld_group_key(value, weak, generic))
    ]
    for _, group in sld_candidates.groupby("target_sld", dropna=False):
        if group["target_suffix"].nunique(dropna=False) < 2:
            continue
        union_domain_group(group["target_domain"].tolist(), "same_sld_diff_suffix", uf, domain_reasons)

    grouped_domains: dict[str, list[str]] = defaultdict(list)
    for domain in domains:
        grouped_domains[uf.find(domain)].append(domain)

    records_by_domain = records.set_index("target_domain", drop=False)
    rows: list[dict[str, Any]] = []
    sortable_groups = sorted(
        (sorted(set(items)) for items in grouped_domains.values() if len(set(items)) > 1),
        key=lambda items: (items[0], len(items)),
    )
    for idx, group_domains in enumerate(sortable_groups, start=1):
        group_id = f"alias_{idx:06d}"
        group_reason = choose_group_reason(group_domains, domain_reasons)
        for domain in group_domains:
            record = records_by_domain.loc[domain]
            rows.append(
                {
                    "alias_group_id": group_id,
                    "target_name": record.get("target_name", ""),
                    "target_domain": domain,
                    "target_sld": record.get("target_sld", ""),
                    "target_suffix": record.get("target_suffix", ""),
                    "group_reason": group_reason,
                }
            )

    return pd.DataFrame(rows, columns=GROUP_COLUMNS)


def build_official_alias_negative_pairs(groups: pd.DataFrame) -> pd.DataFrame:
    if groups.empty:
        return pd.DataFrame(columns=NEGATIVE_COLUMNS)

    rows: list[dict[str, Any]] = []
    for group_id, group in groups.groupby("alias_group_id", dropna=False):
        aliases = group.drop_duplicates("target_domain").to_dict(orient="records")
        for candidate in aliases:
            for target in aliases:
                candidate_domain = normalize_host(candidate.get("target_domain"))
                target_domain = normalize_host(target.get("target_domain"))
                if not candidate_domain or not target_domain or candidate_domain == target_domain:
                    continue
                rows.append(
                    build_alias_negative_record(
                        candidate_domain=candidate_domain,
                        target_domain=target_domain,
                        target_name=clean_cell(target.get("target_name")),
                        alias_group_id=str(group_id),
                    )
                )

    if not rows:
        return pd.DataFrame(columns=NEGATIVE_COLUMNS)
    result = pd.DataFrame(rows)
    result = result.drop_duplicates(
        subset=["candidate_domain", "target_domain", "label"], keep="first"
    )
    return result[NEGATIVE_COLUMNS].reset_index(drop=True)


def build_alias_negative_record(
    candidate_domain: str,
    target_domain: str,
    target_name: str,
    alias_group_id: str,
) -> dict[str, Any]:
    candidate = normalize_domain(candidate_domain)
    target = normalize_domain(target_domain)
    return {
        "candidate_domain": candidate["normalized_domain"],
        "candidate_registered_domain": candidate["registered_domain"],
        "candidate_sld": candidate["sld_clean"] or candidate["sld"],
        "candidate_suffix": candidate["suffix"],
        "candidate_subdomain": candidate["subdomain"],
        "target_name": target_name,
        "target_domain": target["normalized_domain"],
        "target_registered_domain": target["registered_domain"],
        "target_sld": target["sld_clean"] or target["sld"],
        "target_suffix": target["suffix"],
        "target_subdomain": target["subdomain"],
        "label": 0,
        "sample_type": "official_alias_negative",
        "source_type": "official_alias",
        "rule_score": 0.0,
        "matched_token": target["sld_clean"] or target["sld"],
        "matched_token_type": "official_alias",
        "recall_reason": "official_alias_group",
        "hard_filter_pass": True,
        "is_official_alias": 1,
        "alias_group_id": alias_group_id,
    }


def load_target_records(whitelist: pd.DataFrame | None, profiles: pd.DataFrame | None) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    if profiles is not None and not profiles.empty and "target_domain" in profiles.columns:
        for _, row in profiles.iterrows():
            rows.append(record_from_profile_row(row))
    if whitelist is not None and not whitelist.empty:
        name_column = find_optional_column(whitelist, NAME_COLUMNS)
        domain_column = find_optional_column(whitelist, DOMAIN_COLUMNS)
        if domain_column:
            existing_domains = {row["target_domain"] for row in rows}
            for _, row in whitelist.iterrows():
                domain = normalize_host(row.get(domain_column))
                if not domain or domain in existing_domains:
                    continue
                rows.append(record_from_domain_name(domain, clean_cell(row.get(name_column)) if name_column else ""))
                existing_domains.add(domain)

    result = pd.DataFrame(rows)
    if result.empty:
        return pd.DataFrame(
            columns=[
                "target_name",
                "target_domain",
                "target_sld",
                "target_suffix",
                "target_subdomain",
                "target_registered_domain",
                "normalized_name",
            ]
        )
    result["target_domain"] = result["target_domain"].map(normalize_host)
    result = result[result["target_domain"] != ""].copy()
    result["target_name"] = result["target_name"].fillna("").astype(str).str.strip()
    result["normalized_name"] = result["target_name"].map(normalize_name)
    return result


def record_from_profile_row(row: pd.Series) -> dict[str, Any]:
    domain = normalize_host(row.get("target_domain"))
    parsed = normalize_domain(domain) if domain else {}
    return {
        "target_name": clean_cell(row.get("target_name")),
        "target_domain": domain,
        "target_registered_domain": clean_cell(row.get("target_registered_domain")) or parsed.get("registered_domain", ""),
        "target_sld": clean_cell(row.get("target_sld")) or parsed.get("sld_clean", "") or parsed.get("sld", ""),
        "target_suffix": clean_cell(row.get("target_suffix")) or parsed.get("suffix", ""),
        "target_subdomain": clean_cell(row.get("target_subdomain")) or parsed.get("subdomain", ""),
    }


def record_from_domain_name(domain: str, target_name: str) -> dict[str, Any]:
    parsed = normalize_domain(domain)
    return {
        "target_name": target_name,
        "target_domain": parsed["normalized_domain"],
        "target_registered_domain": parsed["registered_domain"],
        "target_sld": parsed["sld_clean"] or parsed["sld"],
        "target_suffix": parsed["suffix"],
        "target_subdomain": parsed["subdomain"],
    }


def union_domain_group(
    domains: Sequence[str],
    reason: str,
    uf: UnionFind,
    domain_reasons: dict[str, set[str]],
) -> None:
    unique_domains = [domain for domain in dict.fromkeys(domains) if domain]
    if len(unique_domains) < 2:
        return
    first = unique_domains[0]
    for domain in unique_domains[1:]:
        uf.union(first, domain)
    for domain in unique_domains:
        domain_reasons.setdefault(domain, set()).add(reason)


def choose_group_reason(domains: Sequence[str], domain_reasons: dict[str, set[str]]) -> str:
    reasons = set()
    for domain in domains:
        reasons.update(domain_reasons.get(domain, set()))
    for reason in GROUP_REASON_PRIORITY:
        if reason in reasons:
            return reason
    return "unknown"


def is_safe_sld_group_key(sld: Any, weak_tokens: set[str], generic_tokens: set[str]) -> bool:
    value = clean_cell(sld).lower()
    if len(value) < 4:
        return False
    if value in weak_tokens or value in generic_tokens:
        return False
    if value.isdigit():
        return False
    if not re.fullmatch(r"[a-z0-9-]+", value):
        return False
    return True


def normalize_name(value: Any) -> str:
    text = clean_cell(value).lower()
    if not text:
        return ""
    text = re.sub(r"[\s\u3000]+", "", text)
    text = re.sub(r"[^\w\u4e00-\u9fff]+", "", text)
    suffixes = [
        "股份有限公司",
        "有限责任公司",
        "有限公司",
        "集团有限公司",
        "集团",
        "公司",
        "incorporated",
        "corporation",
        "limited",
        "company",
        "inc",
        "ltd",
        "corp",
        "co",
    ]
    for suffix in suffixes:
        if text.endswith(suffix) and len(text) > len(suffix) + 1:
            text = text[: -len(suffix)]
            break
    return text


def normalize_host(value: Any) -> str:
    text = clean_cell(value).lower().strip(".")
    if not text:
        return ""
    return normalize_domain(text)["normalized_domain"]


def clean_cell(value: Any) -> str:
    if value is None or pd.isna(value):
        return ""
    value_text = str(value).strip()
    return "" if value_text.lower() == "nan" else value_text


def find_optional_column(df: pd.DataFrame, candidates: Sequence[str]) -> str | None:
    for candidate in candidates:
        if candidate in df.columns:
            return candidate
    return None


def summarize_aliases(groups: pd.DataFrame, negatives: pd.DataFrame) -> dict[str, Any]:
    if groups.empty:
        return {
            "alias_group_count": 0,
            "official_alias_negative_count": int(len(negatives)),
            "max_alias_group_top20": [],
            "possible_misgroup_examples": [],
        }
    group_sizes = (
        groups.groupby("alias_group_id")
        .agg(
            group_size=("target_domain", "nunique"),
            group_reason=("group_reason", "first"),
            target_sld=("target_sld", "first"),
            target_domains=("target_domain", lambda values: "|".join(sorted(values.astype(str).unique())[:12])),
        )
        .reset_index()
        .sort_values(["group_size", "alias_group_id"], ascending=[False, True])
    )
    possible = group_sizes[
        (group_sizes["group_reason"] == "same_sld_diff_suffix") | (group_sizes["group_size"] >= 10)
    ].head(20)
    return {
        "alias_group_count": int(groups["alias_group_id"].nunique()),
        "official_alias_negative_count": int(len(negatives)),
        "max_alias_group_top20": group_sizes.head(20).to_dict(orient="records"),
        "possible_misgroup_examples": possible.to_dict(orient="records"),
    }


def write_outputs(
    groups: pd.DataFrame,
    negatives: pd.DataFrame,
    groups_out: str | Path,
    negatives_out: str | Path,
) -> None:
    groups_path = Path(groups_out)
    negatives_path = Path(negatives_out)
    groups_path.parent.mkdir(parents=True, exist_ok=True)
    negatives_path.parent.mkdir(parents=True, exist_ok=True)
    groups.to_csv(groups_path, index=False, encoding="utf-8-sig")
    negatives.to_csv(negatives_path, index=False, encoding="utf-8-sig")


def print_summary(summary: dict[str, Any]) -> None:
    print(f"alias_group_count={summary['alias_group_count']}")
    print(f"official_alias_negative_count={summary['official_alias_negative_count']}")
    for idx, row in enumerate(summary["max_alias_group_top20"], start=1):
        print(
            "max_alias_group_top20."
            f"{idx}={row['alias_group_id']} size={row['group_size']} "
            f"reason={row['group_reason']} sld={row['target_sld']} "
            f"domains={row['target_domains']}"
        )
    for idx, row in enumerate(summary["possible_misgroup_examples"], start=1):
        print(
            "possible_misgroup."
            f"{idx}={row['alias_group_id']} size={row['group_size']} "
            f"reason={row['group_reason']} sld={row['target_sld']} "
            f"domains={row['target_domains']}"
        )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build official alias groups and alias-negative pairs.")
    parser.add_argument("--whitelist", default=str(DEFAULT_WHITELIST), help="Whitelist clean CSV path.")
    parser.add_argument("--profiles", default=str(DEFAULT_PROFILES), help="Target profiles CSV path.")
    parser.add_argument("--groups-out", default=str(DEFAULT_GROUPS_OUT), help="Official alias groups output CSV.")
    parser.add_argument("--negatives-out", default=str(DEFAULT_NEGATIVES_OUT), help="Official alias negatives output CSV.")
    parser.add_argument("--keywords", default=str(DEFAULT_TOKEN_POLICY), help="Token policy YAML path.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    whitelist = read_csv_with_fallback(args.whitelist) if args.whitelist and Path(args.whitelist).exists() else None
    profiles = read_csv_with_fallback(args.profiles) if args.profiles and Path(args.profiles).exists() else None
    token_policy = load_token_policy(args.keywords)
    groups = build_official_alias_groups(
        whitelist=whitelist,
        profiles=profiles,
        weak_tokens=token_policy.get("weak_target_tokens", set()),
        generic_tokens=token_policy.get("generic_medium_target_tokens", set()),
    )
    negatives = build_official_alias_negative_pairs(groups)
    write_outputs(groups, negatives, args.groups_out, args.negatives_out)
    print_summary(summarize_aliases(groups, negatives))
    print(f"groups_out={Path(args.groups_out)}")
    print(f"negatives_out={Path(args.negatives_out)}")


if __name__ == "__main__":
    main()
