#!/usr/bin/env python3
"""Sklearn transformers for hybrid DGA string models."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Sequence

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

try:
    from dga_features import FEATURE_COLUMNS, extract_dga_features, split_domain
except ModuleNotFoundError:
    from .dga_features import FEATURE_COLUMNS, extract_dga_features, split_domain


LANGUAGE_PRIOR_COLUMNS = [
    "unigram_commonness",
    "bigram_commonness",
    "trigram_commonness",
    "markov_transition_logprob",
    "tld_frequency_share",
    "tld_frequency_tier",
]


class DomainStatsTransformer(BaseEstimator, TransformerMixin):
    """Transform domain strings into the fixed numeric DGA feature matrix."""

    def fit(self, domains: Sequence[str], y: Sequence[int] | None = None):
        return self

    def transform(self, domains: Sequence[str]) -> np.ndarray:
        return np.asarray(
            [[features[column] for column in FEATURE_COLUMNS] for features in map(extract_dga_features, domains)],
            dtype=np.float32,
        )


class DomainLanguagePriorTransformer(BaseEstimator, TransformerMixin):
    """Append lightweight benign-domain language priors to the base DGA stats."""

    def __init__(self, include_base_stats: bool = True):
        self.include_base_stats = include_base_stats

    def fit(self, domains: Sequence[str], y: Sequence[int] | None = None):
        domain_list = list(domains)
        if y is None:
            reference_domains = domain_list
        else:
            reference_domains = [domain for domain, label in zip(domain_list, y) if int(label) == 0]
        if not reference_domains:
            reference_domains = domain_list

        self.ngram_counts_ = {1: Counter(), 2: Counter(), 3: Counter()}
        self.ngram_totals_ = {1: 0, 2: 0, 3: 0}
        self.transition_counts_ = defaultdict(Counter)
        self.transition_totals_ = Counter()
        self.tld_counts_ = Counter()
        alphabet: set[str] = set()

        for domain in reference_domains:
            text, suffix = _language_text_and_suffix(domain)
            self.tld_counts_[suffix] += 1
            if not text:
                continue
            alphabet.update(text)
            for n in (1, 2, 3):
                grams = _ngrams(text, n)
                self.ngram_counts_[n].update(grams)
                self.ngram_totals_[n] += len(grams)
            padded = f"^{text}$"
            for left, right in zip(padded, padded[1:]):
                self.transition_counts_[left][right] += 1
                self.transition_totals_[left] += 1

        self.alphabet_size_ = max(len(alphabet), 1)
        self.transition_vocab_size_ = max(len(alphabet) + 2, 2)
        total_tlds = sum(self.tld_counts_.values())
        self.tld_shares_ = {
            suffix: count / total_tlds
            for suffix, count in self.tld_counts_.items()
        } if total_tlds else {}
        self.tld_tiers_ = _build_tld_tiers(self.tld_counts_)
        base_columns = FEATURE_COLUMNS if self.include_base_stats else []
        self.feature_columns_ = list(base_columns) + list(LANGUAGE_PRIOR_COLUMNS)
        return self

    def transform(self, domains: Sequence[str]) -> np.ndarray:
        rows: list[list[float]] = []
        for domain in domains:
            row: list[float] = []
            if self.include_base_stats:
                base_features = extract_dga_features(domain)
                row.extend(base_features[column] for column in FEATURE_COLUMNS)
            row.extend(self._language_prior_features(domain))
            rows.append(row)
        return np.asarray(rows, dtype=np.float32)

    def get_feature_names_out(self, input_features=None) -> np.ndarray:
        return np.asarray(self.feature_columns_, dtype=object)

    def _language_prior_features(self, domain: str) -> list[float]:
        text, suffix = _language_text_and_suffix(domain)
        return [
            _average_log_probability(text, 1, self.ngram_counts_, self.ngram_totals_, self.alphabet_size_),
            _average_log_probability(text, 2, self.ngram_counts_, self.ngram_totals_, self.alphabet_size_),
            _average_log_probability(text, 3, self.ngram_counts_, self.ngram_totals_, self.alphabet_size_),
            _average_markov_log_probability(
                text,
                self.transition_counts_,
                self.transition_totals_,
                self.transition_vocab_size_,
            ),
            float(self.tld_shares_.get(suffix, 0.0)),
            float(self.tld_tiers_.get(suffix, 0.0)),
        ]


def _language_text_and_suffix(domain: object) -> tuple[str, str]:
    parts = split_domain(domain)
    text = parts.sld or parts.domain.replace(".", "")
    return text, parts.suffix or "<none>"


def _ngrams(text: str, n: int) -> list[str]:
    if len(text) < n or n <= 0:
        return []
    return [text[index : index + n] for index in range(len(text) - n + 1)]


def _average_log_probability(
    text: str,
    n: int,
    ngram_counts: dict[int, Counter[str]],
    ngram_totals: dict[int, int],
    alphabet_size: int,
) -> float:
    grams = _ngrams(text, n)
    if not grams:
        return 0.0
    denominator = float(ngram_totals[n] + (alphabet_size ** n))
    values = [
        math.log((ngram_counts[n].get(gram, 0) + 1.0) / denominator)
        for gram in grams
    ]
    return float(sum(values) / len(values))


def _average_markov_log_probability(
    text: str,
    transition_counts: defaultdict[str, Counter[str]],
    transition_totals: Counter[str],
    transition_vocab_size: int,
) -> float:
    if not text:
        return 0.0
    padded = f"^{text}$"
    values: list[float] = []
    for left, right in zip(padded, padded[1:]):
        denominator = float(transition_totals.get(left, 0) + transition_vocab_size)
        probability = (transition_counts[left].get(right, 0) + 1.0) / denominator
        values.append(math.log(probability))
    return float(sum(values) / len(values)) if values else 0.0


def _build_tld_tiers(tld_counts: Counter[str]) -> dict[str, float]:
    total = sum(tld_counts.values())
    if not total:
        return {}
    tiers: dict[str, float] = {}
    cumulative = 0
    for suffix, count in sorted(tld_counts.items(), key=lambda item: (-item[1], item[0])):
        cumulative += count
        share = cumulative / total
        if share <= 0.50:
            tiers[suffix] = 3.0
        elif share <= 0.90:
            tiers[suffix] = 2.0
        else:
            tiers[suffix] = 1.0
    return tiers
