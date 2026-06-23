from __future__ import annotations

import math
import re
import urllib.parse
from collections import Counter, OrderedDict
from dataclasses import dataclass
from typing import Iterable


COMMON_MULTI_PART_SUFFIXES = {
    "ac.cn",
    "co.jp",
    "co.kr",
    "co.uk",
    "com.au",
    "com.cn",
    "com.hk",
    "com.sg",
    "edu.cn",
    "gov.cn",
    "net.cn",
    "org.cn",
}
VOWELS = set("aeiou")
FEATURE_COLUMNS = [
    "domain_len",
    "sld_len",
    "suffix_len",
    "subdomain_count",
    "token_count",
    "digit_count",
    "digit_ratio",
    "alpha_count",
    "alpha_ratio",
    "hyphen_count",
    "hyphen_ratio",
    "unique_char_ratio",
    "vowel_count",
    "vowel_ratio",
    "consonant_count",
    "consonant_ratio",
    "entropy",
    "longest_digit_run",
    "longest_alpha_run",
    "longest_consonant_run",
    "repeated_char_count",
    "max_repeated_char_run",
    "has_mixed_digit_alpha",
    "starts_with_digit",
    "ends_with_digit",
]


@dataclass(frozen=True)
class DomainParts:
    domain: str
    sld: str
    suffix: str
    subdomain: str
    subdomain_count: int


def normalize_domain(value: object) -> str:
    if value is None:
        return ""

    text = str(value).strip().strip("\"'").strip()
    if not text:
        return ""

    text = text.replace("\\", "/")
    if "://" in text:
        parsed = urllib.parse.urlsplit(text)
        host = parsed.netloc or parsed.path
    elif "/" in text or "?" in text or "#" in text:
        parsed = urllib.parse.urlsplit("//" + text)
        host = parsed.netloc or parsed.path
    else:
        host = text

    host = host.split("@")[-1]
    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    elif ":" in host:
        host = host.split(":", 1)[0]

    host = host.strip().lower().strip(".")
    while host.startswith("*."):
        host = host[2:]
    host = host.strip(".")

    labels: list[str] = []
    for label in host.split("."):
        label = label.strip()
        if not label:
            continue
        try:
            label = label.encode("idna").decode("ascii")
        except UnicodeError:
            label = re.sub(r"[^a-z0-9-]", "", label)
        label = re.sub(r"[^a-z0-9-]", "", label.lower()).strip("-")
        if label:
            labels.append(label)

    return ".".join(labels)


def split_domain(value: object) -> DomainParts:
    domain = normalize_domain(value)
    labels = [label for label in domain.split(".") if label]
    if not labels:
        return DomainParts(domain="", sld="", suffix="", subdomain="", subdomain_count=0)
    if len(labels) == 1:
        return DomainParts(domain=domain, sld=labels[0], suffix="", subdomain="", subdomain_count=0)

    two_part_suffix = ".".join(labels[-2:])
    if len(labels) >= 3 and two_part_suffix in COMMON_MULTI_PART_SUFFIXES:
        suffix = two_part_suffix
        sld = labels[-3]
        subdomain_labels = labels[:-3]
    else:
        suffix = labels[-1]
        sld = labels[-2]
        subdomain_labels = labels[:-2]

    return DomainParts(
        domain=domain,
        sld=sld,
        suffix=suffix,
        subdomain=".".join(subdomain_labels),
        subdomain_count=len(subdomain_labels),
    )


def _safe_ratio(numerator: float, denominator: float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    total = len(text)
    value = 0.0
    for count in Counter(text).values():
        probability = count / total
        value -= probability * math.log2(probability)
    return value


def _longest_run(text: str, predicate) -> int:
    longest = 0
    current = 0
    for char in text:
        if predicate(char):
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _repeat_stats(text: str) -> tuple[int, int]:
    repeated_count = 0
    max_run = 0
    current_run = 1
    previous = ""
    for char in text:
        if char == previous:
            current_run += 1
            repeated_count += 1
        else:
            current_run = 1
        max_run = max(max_run, current_run)
        previous = char
    return repeated_count, max_run if text else 0


def extract_dga_features(domain: object) -> OrderedDict[str, float]:
    parts = split_domain(domain)
    sld = parts.sld
    sld_len = len(sld)
    digit_count = sum(char.isdigit() for char in sld)
    alpha_count = sum(char.isalpha() for char in sld)
    hyphen_count = sld.count("-")
    vowel_count = sum(char in VOWELS for char in sld)
    consonant_count = sum(char.isalpha() and char not in VOWELS for char in sld)
    repeated_char_count, max_repeated_char_run = _repeat_stats(sld)
    token_count = len([token for token in re.split(r"[^a-z0-9]+", sld) if token])

    values = {
        "domain_len": len(parts.domain),
        "sld_len": sld_len,
        "suffix_len": len(parts.suffix),
        "subdomain_count": parts.subdomain_count,
        "token_count": token_count,
        "digit_count": digit_count,
        "digit_ratio": _safe_ratio(digit_count, sld_len),
        "alpha_count": alpha_count,
        "alpha_ratio": _safe_ratio(alpha_count, sld_len),
        "hyphen_count": hyphen_count,
        "hyphen_ratio": _safe_ratio(hyphen_count, sld_len),
        "unique_char_ratio": _safe_ratio(len(set(sld)), sld_len),
        "vowel_count": vowel_count,
        "vowel_ratio": _safe_ratio(vowel_count, sld_len),
        "consonant_count": consonant_count,
        "consonant_ratio": _safe_ratio(consonant_count, sld_len),
        "entropy": _entropy(sld),
        "longest_digit_run": _longest_run(sld, str.isdigit),
        "longest_alpha_run": _longest_run(sld, str.isalpha),
        "longest_consonant_run": _longest_run(
            sld,
            lambda char: char.isalpha() and char not in VOWELS,
        ),
        "repeated_char_count": repeated_char_count,
        "max_repeated_char_run": max_repeated_char_run,
        "has_mixed_digit_alpha": float(bool(digit_count and alpha_count)),
        "starts_with_digit": float(bool(sld[:1].isdigit())),
        "ends_with_digit": float(bool(sld[-1:].isdigit())),
    }
    return OrderedDict((column, float(values[column])) for column in FEATURE_COLUMNS)


def extract_feature_rows(domains: Iterable[object]) -> list[OrderedDict[str, float]]:
    return [extract_dga_features(domain) for domain in domains]


def build_rule_reasons(features: dict[str, float]) -> list[str]:
    reasons: list[str] = []
    sld_len = features.get("sld_len", 0.0)
    if features.get("entropy", 0.0) >= 2.5 and sld_len >= 8:
        reasons.append("entropy_high")
    if features.get("vowel_ratio", 0.0) <= 0.15 and sld_len >= 6:
        reasons.append("vowel_ratio_low")
    if features.get("digit_ratio", 0.0) >= 0.2 and sld_len >= 5:
        reasons.append("digit_ratio_high")
    if features.get("hyphen_ratio", 0.0) >= 0.15:
        reasons.append("hyphen_ratio_high")
    if features.get("longest_consonant_run", 0.0) >= 4:
        reasons.append("long_consonant_run")
    if features.get("unique_char_ratio", 0.0) >= 0.8 and sld_len >= 8:
        reasons.append("unique_char_ratio_high")
    if sld_len >= 24:
        reasons.append("sld_len_high")
    return reasons or ["no_strong_string_signal"]
