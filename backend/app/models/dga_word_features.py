from __future__ import annotations

import math
import re
from functools import lru_cache

try:
    from dga_features import split_domain
except ModuleNotFoundError:
    from .dga_features import split_domain


DEFAULT_EXTRA_WORDS = {
    "app",
    "bake",
    "case",
    "cloud",
    "coat",
    "date",
    "fee",
    "law",
    "loan",
    "man",
    "net",
    "pay",
    "star",
    "tech",
    "time",
    "web",
    "win",
}


def load_word_set(path: str | None = "/usr/share/dict/words") -> set[str]:
    words: set[str] = set(DEFAULT_EXTRA_WORDS)
    if path is None:
        return words
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip().lower()
                if 3 <= len(word) <= 16 and word.isalpha():
                    words.add(word)
    except OSError:
        pass
    return words


def _sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-value))


@lru_cache(maxsize=8)
def _words_by_length(words: frozenset[str]) -> tuple[tuple[int, frozenset[str]], ...]:
    lengths = sorted({len(word) for word in words if len(word) >= 3})
    return tuple((length, frozenset(word for word in words if len(word) == length)) for length in lengths)


def word_segment_stats(domain: str, words: frozenset[str]) -> tuple[float, int, int, int]:
    sld = re.sub(r"[^a-z]", "", split_domain(domain).sld.lower())
    length = len(sld)
    if not length or not words:
        return 0.0, 0, 0, length
    length_buckets = _words_by_length(words)

    @lru_cache(maxsize=None)
    def best_from(index: int) -> tuple[int, int, int]:
        if index >= length:
            return 0, 0, 0
        best = best_from(index + 1)
        for word_len, bucket in length_buckets:
            end = index + word_len
            if end > length:
                break
            if sld[index:end] not in bucket:
                continue
            covered, count, longest = best_from(end)
            candidate = (
                covered + end - index,
                count + 1,
                max(longest, end - index),
            )
            if candidate > best:
                best = candidate
        return best

    covered, count, longest = best_from(0)
    return covered / length, count, longest, length


def wordlist_score(
    domain: str,
    words: frozenset[str],
    *,
    len_center: float = 26.0,
    count_center: float = 6.0,
    coverage_center: float = 0.85,
) -> float:
    coverage, count, _longest, length = word_segment_stats(domain, words)
    raw_score = (coverage - coverage_center) * 8.0 + (count - count_center) * 0.9 + (length - len_center) * 0.25
    return float(_sigmoid(raw_score))
