"""Find NRD domains that are string-similar to historical APT-like domains.

First-version pipeline:
1. Normalize and route historical domains into coarse infrastructure classes.
2. Build a character TF-IDF nearest-neighbor index from A/E seeds.
3. Re-rank retrieved domain pairs with transparent string features.
4. Score DGA-like NRD strings separately and fuse that signal into output.

The output is a candidate screen, not an attribution or maliciousness verdict.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import time
import zipfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

try:
    import openpyxl

    HAS_OPENPYXL = True
except Exception:
    openpyxl = None
    HAS_OPENPYXL = False

try:
    import template_batch_detector as domain_utils
except ImportError:
    from . import template_batch_detector as domain_utils  # type: ignore


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_POSITIVES_PATH = SCRIPT_DIR / "dataset" / "history-like" / "训练黑数据.xlsx"
DEFAULT_NRD_INPUT = SCRIPT_DIR / "dataset" / "NRD"
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "outputs" / "apt_nrd_similarity"

TEXT_ENCODINGS = ("utf-8-sig", "utf-8", "gb18030", "latin-1")
SUPPORTED_INPUT_SUFFIXES = {".txt", ".csv", ".xlsx", ".zip"}
INDEX_ROUTES = {"A_registered_domain", "E_impersonation"}
SIMILARITY_FLOOR_FOR_DGA_BOOST = 0.35

SHARED_PLATFORM_REGISTERED_DOMAINS = {
    "azurewebsites.net",
    "blogspot.com",
    "cloudflareworkers.com",
    "duckdns.org",
    "dynu.net",
    "dynv6.net",
    "github.io",
    "hopto.org",
    "mydns.jp",
    "ngrok.app",
    "no-ip.biz",
    "no-ip.info",
    "pages.dev",
    "servehttp.com",
    "vercel.app",
}
SHARED_PLATFORM_SUFFIXES = {
    "workers.dev",
    "pages.dev",
    "vercel.app",
    "netlify.app",
    "ngrok.app",
}
IMPERSONATION_TOKENS = {
    "account",
    "accounts",
    "active",
    "adobe",
    "auth",
    "bank",
    "check",
    "cloud",
    "doc",
    "docs",
    "document",
    "documents",
    "download",
    "drive",
    "email",
    "file",
    "files",
    "gov",
    "govpk",
    "govt",
    "login",
    "mail",
    "meeting",
    "mfa",
    "mofa",
    "office",
    "onedrive",
    "password",
    "portal",
    "secure",
    "security",
    "server",
    "service",
    "services",
    "signin",
    "sso",
    "support",
    "update",
    "updates",
    "visa",
    "webmail",
    "zoom",
}
NORMAL_BUSINESS_TOKENS = {
    "agency",
    "business",
    "company",
    "consulting",
    "corp",
    "group",
    "inc",
    "llc",
    "ordinary",
    "shop",
    "store",
    "transportation",
}
VOWELS = set("aeiou")
ASCII_LETTERS = set("abcdefghijklmnopqrstuvwxyz")
CONSONANTS = ASCII_LETTERS - VOWELS


@dataclass(frozen=True)
class PositiveSeed:
    domain: str
    sld: str
    suffix: str
    subdomain: str
    route: str
    route_reason: str
    dga_score: float


@dataclass(frozen=True)
class PairFeatures:
    tfidf_similarity: float
    levenshtein_similarity: float
    jaro_winkler_similarity: float
    ngram_jaccard: float
    common_prefix_ratio: float
    common_suffix_ratio: float
    no_digit_similarity: float
    tld_replaced_similarity: float
    token_overlap: float
    length_similarity: float
    hyphen_delta: int
    digit_position_similarity: float
    same_suffix: bool


@dataclass(frozen=True)
class Candidate:
    domain: str
    normalized_domain: str
    route: str
    matched_positive: str
    matched_positive_route: str
    tfidf_similarity: float
    rerank_score: float
    dga_score: float
    final_score: float
    reasons: str
    features_json: str


class DomainSimilarityIndex:
    def __init__(
        self,
        seeds: list[PositiveSeed],
        vectors: list[dict[str, float]],
        norms: list[float],
        inverted: dict[str, list[tuple[int, float]]],
        idf: dict[str, float],
        top_k: int,
    ) -> None:
        self.seeds = seeds
        self.vectors = vectors
        self.norms = norms
        self.inverted = inverted
        self.idf = idf
        self.top_k = top_k

    @classmethod
    def build(cls, seeds: list[PositiveSeed], top_k: int = 10) -> "DomainSimilarityIndex":
        indexable = [seed for seed in seeds if seed.route in INDEX_ROUTES]
        texts = [similarity_text(seed.domain) for seed in indexable]
        vectors, norms, inverted, idf = build_tfidf_vectors(texts)
        return cls(indexable, vectors, norms, inverted, idf, max(1, top_k))

    def query(self, domain: str, top_k: int | None = None) -> list[tuple[PositiveSeed, float]]:
        if not self.seeds:
            return []
        text = similarity_text(domain)
        query_vector = vectorize_text(text, self.idf)
        query_norm = vector_norm(query_vector)
        if not query_vector or not query_norm:
            return []

        dots: Counter[int] = Counter()
        for gram, query_weight in query_vector.items():
            for seed_index, seed_weight in self.inverted.get(gram, ()):
                dots[seed_index] += query_weight * seed_weight

        scored = []
        for seed_index, dot in dots.items():
            denom = query_norm * self.norms[seed_index]
            similarity = float(dot / denom) if denom else 0.0
            scored.append((self.seeds[seed_index], similarity))
        scored.sort(key=lambda item: item[1], reverse=True)
        return scored[: max(1, top_k or self.top_k)]


def normalize_domain(raw: Any) -> str:
    return domain_utils.normalize_domain(raw)


def parse_domain(raw: Any) -> Any:
    return domain_utils.parse_domain(raw)


def is_domain_like(domain: str) -> bool:
    return bool(domain and domain_utils.is_normalized_domain_like(domain))


def registered_domain(record: Any) -> str:
    return f"{record.sld}.{record.suffix}" if record.suffix else record.sld


def similarity_text(domain: str) -> str:
    record = parse_domain(domain)
    return record.sld


def char_ngrams(text: str, min_n: int = 3, max_n: int = 5) -> list[str]:
    value = f" {text.lower()} "
    grams: list[str] = []
    for n in range(min_n, max_n + 1):
        if len(value) < n:
            continue
        grams.extend(value[index : index + n] for index in range(len(value) - n + 1))
    return grams


def build_tfidf_vectors(texts: list[str]) -> tuple[
    list[dict[str, float]],
    list[float],
    dict[str, list[tuple[int, float]]],
    dict[str, float],
]:
    counters = [Counter(char_ngrams(text)) for text in texts]
    document_frequency: Counter[str] = Counter()
    for counts in counters:
        document_frequency.update(counts.keys())

    total = len(texts)
    idf = {
        gram: math.log((1 + total) / (1 + frequency)) + 1
        for gram, frequency in document_frequency.items()
    }

    vectors: list[dict[str, float]] = []
    norms: list[float] = []
    inverted: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for index, counts in enumerate(counters):
        vector = {gram: count * idf[gram] for gram, count in counts.items()}
        norm = vector_norm(vector)
        vectors.append(vector)
        norms.append(norm)
        for gram, weight in vector.items():
            inverted[gram].append((index, weight))
    return vectors, norms, dict(inverted), idf


def vectorize_text(text: str, idf: dict[str, float]) -> dict[str, float]:
    counts = Counter(char_ngrams(text))
    return {gram: count * idf[gram] for gram, count in counts.items() if gram in idf}


def vector_norm(vector: dict[str, float]) -> float:
    return math.sqrt(sum(value * value for value in vector.values()))


def prepare_positive_seeds(raw_domains: Iterable[Any]) -> list[PositiveSeed]:
    seeds: list[PositiveSeed] = []
    seen: set[str] = set()
    for raw in raw_domains:
        domain = normalize_domain(raw)
        if not is_domain_like(domain) or domain in seen:
            continue
        seen.add(domain)
        record = parse_domain(domain)
        dga_score = heuristic_dga_score(record.sld)
        route, reason = route_positive_domain(record, dga_score)
        seeds.append(
            PositiveSeed(
                domain=record.domain,
                sld=record.sld,
                suffix=record.suffix,
                subdomain=record.subdomain,
                route=route,
                route_reason=reason,
                dga_score=dga_score,
            )
        )
    return seeds


def route_positive_domain(record: Any, dga_score: float) -> tuple[str, str]:
    reg_domain = registered_domain(record)
    tokens = set(domain_utils.tokenize_sld(record.sld))
    full_domain = record.domain

    if reg_domain in SHARED_PLATFORM_REGISTERED_DOMAINS or any(
        full_domain.endswith(f".{suffix}") or reg_domain == suffix
        for suffix in SHARED_PLATFORM_SUFFIXES
    ):
        return "B_shared_platform", f"registered domain is shared platform: {reg_domain}"
    if dga_score >= 0.68:
        return "D_dga_or_random", f"heuristic dga score {dga_score:.3f}"
    if tokens & IMPERSONATION_TOKENS:
        return "E_impersonation", "contains impersonation/social-engineering token"
    if record.subdomain:
        return "C_compromised_or_subdomain", "has subdomain outside known shared platforms"
    if len(tokens & NORMAL_BUSINESS_TOKENS) >= 1 and len(tokens) >= 2:
        return "C_compromised_or_subdomain", "business-like registered domain, weak template seed"
    return "A_registered_domain", "registered-domain seed"


def heuristic_dga_score(value: str) -> float:
    text = re.sub(r"[^a-z0-9-]", "", str(value or "").lower())
    compact = text.replace("-", "")
    length = len(compact)
    if length == 0:
        return 0.0

    digit_count = sum(char.isdigit() for char in compact)
    alpha_count = sum(char.isalpha() for char in compact)
    vowel_count = sum(char in VOWELS for char in compact)
    entropy = shannon_entropy(compact)
    normalized_entropy = entropy / math.log2(length) if length > 1 else 0.0
    digit_ratio = digit_count / length
    vowel_ratio = vowel_count / alpha_count if alpha_count else 0.0
    unique_ratio = len(set(compact)) / length
    max_consonants = max_run(compact, lambda char: char in CONSONANTS)
    max_digits = max_run(compact, lambda char: char.isdigit())

    score = 0.0
    if length >= 8 and normalized_entropy >= 0.82:
        score += 0.24
    if length >= 8 and digit_ratio >= 0.18:
        score += 0.20
    if length >= 8 and vowel_ratio <= 0.24:
        score += 0.16
    if length >= 8 and unique_ratio >= 0.70:
        score += 0.14
    if max_consonants >= 4:
        score += 0.16
    if max_digits >= 3:
        score += 0.08
    if "-" not in text and length >= 8:
        score += 0.08
    if len(domain_utils.tokenize_sld(text)) >= 2 and any(token in IMPERSONATION_TOKENS for token in domain_utils.tokenize_sld(text)):
        score -= 0.25
    if re.search(r"(login|secure|update|service|meeting|document|account)", text):
        score -= 0.18
    return max(0.0, min(1.0, score))


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def max_run(text: str, predicate: Any) -> int:
    best = 0
    current = 0
    for char in text:
        if predicate(char):
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def score_nrd_domains(
    raw_domains: Iterable[Any],
    index: DomainSimilarityIndex,
    *,
    min_score: float = 0.55,
    include_dga: bool = True,
    include_dga_only: bool = False,
    dga_threshold: float = 0.72,
    top_k: int | None = None,
) -> list[Candidate]:
    candidates: list[Candidate] = []
    seen: set[str] = set()
    for raw in raw_domains:
        domain = normalize_domain(raw)
        if not is_domain_like(domain) or domain in seen:
            continue
        seen.add(domain)

        record = parse_domain(domain)
        dga_score = heuristic_dga_score(record.sld) if include_dga else 0.0
        route, _ = route_positive_domain(record, dga_score)
        nearest = index.query(domain, top_k=top_k)

        emitted_for_similarity = False
        for seed, tfidf_similarity in nearest:
            features = compute_pair_features(record, parse_domain(seed.domain), tfidf_similarity)
            rerank_score, reasons = score_pair(features)
            final_score = rerank_score
            if dga_score >= dga_threshold and "dga_like" not in reasons:
                if (
                    rerank_score >= SIMILARITY_FLOOR_FOR_DGA_BOOST
                    or tfidf_similarity >= SIMILARITY_FLOOR_FOR_DGA_BOOST
                ):
                    reasons.append("dga_like")
                    final_score = max(final_score, dga_score * 0.75)
            if final_score < min_score:
                continue
            emitted_for_similarity = True
            candidates.append(
                Candidate(
                    domain=record.domain,
                    normalized_domain=record.domain,
                    route=route,
                    matched_positive=seed.domain,
                    matched_positive_route=seed.route,
                    tfidf_similarity=tfidf_similarity,
                    rerank_score=rerank_score,
                    dga_score=dga_score,
                    final_score=final_score,
                    reasons=";".join(reasons),
                    features_json=json.dumps(asdict(features), ensure_ascii=False, sort_keys=True),
                )
            )

        if include_dga_only and include_dga and not emitted_for_similarity and dga_score >= dga_threshold:
            final_score = dga_score * 0.75
            if final_score >= min_score:
                candidates.append(
                    Candidate(
                        domain=record.domain,
                        normalized_domain=record.domain,
                        route="D_dga_or_random",
                        matched_positive="",
                        matched_positive_route="D_dga_or_random",
                        tfidf_similarity=0.0,
                        rerank_score=0.0,
                        dga_score=dga_score,
                        final_score=final_score,
                        reasons="dga_like",
                        features_json="{}",
                    )
                )

    candidates.sort(key=lambda candidate: (-candidate.final_score, candidate.domain))
    return candidates


def compute_pair_features(nrd: Any, positive: Any, tfidf_similarity: float) -> PairFeatures:
    left = nrd.sld
    right = positive.sld
    return PairFeatures(
        tfidf_similarity=float(tfidf_similarity),
        levenshtein_similarity=levenshtein_similarity(left, right),
        jaro_winkler_similarity=jaro_winkler_similarity(left, right),
        ngram_jaccard=ngram_jaccard(left, right),
        common_prefix_ratio=common_prefix_ratio(left, right),
        common_suffix_ratio=common_suffix_ratio(left, right),
        no_digit_similarity=levenshtein_similarity(strip_digits(left), strip_digits(right)),
        tld_replaced_similarity=1.0 if left == right else levenshtein_similarity(left, right),
        token_overlap=token_overlap(domain_utils.tokenize_sld(left), domain_utils.tokenize_sld(right)),
        length_similarity=length_similarity(left, right),
        hyphen_delta=abs(left.count("-") - right.count("-")),
        digit_position_similarity=digit_position_similarity(left, right),
        same_suffix=nrd.suffix == positive.suffix,
    )


def score_pair(features: PairFeatures) -> tuple[float, list[str]]:
    score = (
        0.42 * features.tfidf_similarity
        + 0.15 * features.levenshtein_similarity
        + 0.10 * features.jaro_winkler_similarity
        + 0.10 * features.ngram_jaccard
        + 0.06 * features.common_prefix_ratio
        + 0.04 * features.common_suffix_ratio
        + 0.04 * features.no_digit_similarity
        + 0.05 * features.token_overlap
        + 0.03 * features.length_similarity
        + (0.01 if features.same_suffix else 0.0)
    )
    score -= min(0.08, features.hyphen_delta * 0.02)
    if features.digit_position_similarity < 0.5:
        score -= 0.03
    score = max(0.0, min(1.0, score))

    reasons: list[str] = []
    if features.tfidf_similarity >= 0.45 or score >= 0.45:
        reasons.append("similar_to_history")
    if features.token_overlap >= 0.5:
        reasons.append("token_overlap")
    if features.common_prefix_ratio >= 0.55:
        reasons.append("common_prefix")
    if features.common_suffix_ratio >= 0.55:
        reasons.append("common_suffix")
    if features.same_suffix:
        reasons.append("same_suffix")
    return score, reasons or ["weak_similarity"]


def levenshtein_similarity(left: str, right: str) -> float:
    if left == right:
        return 1.0
    max_len = max(len(left), len(right))
    if max_len == 0:
        return 1.0
    return 1.0 - (levenshtein_distance(left, right) / max_len)


def levenshtein_distance(left: str, right: str) -> int:
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (0 if left_char == right_char else 1)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]


def jaro_winkler_similarity(left: str, right: str) -> float:
    jaro = jaro_similarity(left, right)
    prefix = 0
    for left_char, right_char in zip(left, right):
        if left_char != right_char:
            break
        prefix += 1
        if prefix == 4:
            break
    return min(1.0, jaro + prefix * 0.1 * (1.0 - jaro))


def jaro_similarity(left: str, right: str) -> float:
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    match_distance = max(len(left), len(right)) // 2 - 1
    left_matches = [False] * len(left)
    right_matches = [False] * len(right)

    matches = 0
    for i, left_char in enumerate(left):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len(right))
        for j in range(start, end):
            if right_matches[j] or left_char != right[j]:
                continue
            left_matches[i] = True
            right_matches[j] = True
            matches += 1
            break
    if not matches:
        return 0.0

    transpositions = 0
    j = 0
    for i, left_char in enumerate(left):
        if not left_matches[i]:
            continue
        while not right_matches[j]:
            j += 1
        if left_char != right[j]:
            transpositions += 1
        j += 1
    return (
        matches / len(left)
        + matches / len(right)
        + (matches - transpositions / 2) / matches
    ) / 3


def ngram_jaccard(left: str, right: str, n: int = 3) -> float:
    left_set = set(simple_ngrams(left, n))
    right_set = set(simple_ngrams(right, n))
    if not left_set and not right_set:
        return 1.0
    if not left_set or not right_set:
        return 0.0
    return len(left_set & right_set) / len(left_set | right_set)


def simple_ngrams(text: str, n: int) -> list[str]:
    if len(text) <= n:
        return [text] if text else []
    return [text[index : index + n] for index in range(len(text) - n + 1)]


def common_prefix_ratio(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    count = 0
    for left_char, right_char in zip(left, right):
        if left_char != right_char:
            break
        count += 1
    return count / min(len(left), len(right))


def common_suffix_ratio(left: str, right: str) -> float:
    return common_prefix_ratio(left[::-1], right[::-1])


def strip_digits(text: str) -> str:
    return re.sub(r"\d+", "", text)


def token_overlap(left_tokens: list[str], right_tokens: list[str]) -> float:
    left = {token for token in left_tokens if token}
    right = {token for token in right_tokens if token}
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def length_similarity(left: str, right: str) -> float:
    max_len = max(len(left), len(right))
    if max_len == 0:
        return 1.0
    return 1.0 - abs(len(left) - len(right)) / max_len


def digit_position_similarity(left: str, right: str) -> float:
    left_positions = {index for index, char in enumerate(left) if char.isdigit()}
    right_positions = {index for index, char in enumerate(right) if char.isdigit()}
    if not left_positions and not right_positions:
        return 1.0
    if not left_positions or not right_positions:
        return 0.0
    return len(left_positions & right_positions) / len(left_positions | right_positions)


def read_domains_from_path(path: str | Path, *, max_domains: int = 0) -> list[str]:
    root = Path(path)
    files = discover_input_files(root)
    domains: list[str] = []
    seen: set[str] = set()
    for file_path in files:
        for raw in iter_domain_values_from_file(file_path):
            domain = normalize_domain(raw)
            if not is_domain_like(domain) or domain in seen:
                continue
            seen.add(domain)
            domains.append(domain)
            if max_domains and len(domains) >= max_domains:
                return domains
    return domains


def discover_input_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path] if path.suffix.lower() in SUPPORTED_INPUT_SUFFIXES else []
    if not path.exists():
        raise FileNotFoundError(f"input path does not exist: {path}")
    return sorted(
        item
        for item in path.rglob("*")
        if item.is_file() and item.suffix.lower() in SUPPORTED_INPUT_SUFFIXES
    )


def iter_domain_values_from_file(path: Path) -> Iterator[str]:
    suffix = path.suffix.lower()
    if suffix == ".txt":
        yield from iter_text_lines(path)
    elif suffix == ".csv":
        yield from iter_csv_values(path)
    elif suffix == ".xlsx":
        yield from iter_xlsx_values(path)
    elif suffix == ".zip":
        yield from iter_zip_values(path)


def iter_text_lines(path: Path) -> Iterator[str]:
    for encoding in TEXT_ENCODINGS:
        try:
            with path.open("r", encoding=encoding, errors="strict") as handle:
                for line in handle:
                    yield line.strip()
            return
        except UnicodeDecodeError:
            continue
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            yield line.strip()


def iter_csv_values(path: Path) -> Iterator[str]:
    for encoding in TEXT_ENCODINGS:
        try:
            with path.open("r", encoding=encoding, errors="strict", newline="") as handle:
                sample = handle.read(4096)
                handle.seek(0)
                has_header = csv.Sniffer().has_header(sample) if sample else False
                if has_header:
                    reader = csv.DictReader(handle)
                    domain_field = choose_domain_field(reader.fieldnames or [])
                    for row in reader:
                        yield row.get(domain_field, "") if domain_field else next(iter(row.values()), "")
                else:
                    reader = csv.reader(handle)
                    for row in reader:
                        if row:
                            yield row[0]
            return
        except UnicodeDecodeError:
            continue


def choose_domain_field(fields: list[str]) -> str:
    normalized = {field.lower().strip(): field for field in fields}
    for candidate in ("domain", "url", "hostname", "host", "fqdn", "registered_domain"):
        if candidate in normalized:
            return normalized[candidate]
    return fields[0] if fields else ""


def iter_xlsx_values(path: Path) -> Iterator[str]:
    if not HAS_OPENPYXL:
        raise RuntimeError("openpyxl is required to read xlsx files.")
    workbook = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        for sheet in workbook.worksheets:
            for row in sheet.iter_rows(values_only=True):
                if not row:
                    continue
                for value in row:
                    domain = normalize_domain(value)
                    if is_domain_like(domain):
                        yield domain
                        break
    finally:
        workbook.close()


def iter_zip_values(path: Path) -> Iterator[str]:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            for name in sorted(archive.namelist()):
                if name.endswith("/"):
                    continue
                suffix = Path(name).suffix.lower()
                if suffix not in {".txt", ".csv"}:
                    continue
                with archive.open(name, "r") as handle:
                    raw = handle.read()
                text = decode_bytes(raw)
                if suffix == ".csv":
                    for row in csv.reader(text.splitlines()):
                        if row:
                            yield row[0]
                else:
                    for line in text.splitlines():
                        yield line.strip()
    except zipfile.BadZipFile:
        return


def decode_bytes(raw: bytes) -> str:
    for encoding in TEXT_ENCODINGS:
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def run_detection(
    *,
    positives_path: str | Path = DEFAULT_POSITIVES_PATH,
    nrd_input: str | Path = DEFAULT_NRD_INPUT,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    top_k: int = 10,
    min_score: float = 0.55,
    max_nrd: int = 0,
    include_dga: bool = True,
    include_dga_only: bool = False,
    dga_threshold: float = 0.72,
) -> dict[str, Any]:
    started = time.time()
    positives = read_domains_from_path(positives_path)
    seeds = prepare_positive_seeds(positives)
    index = DomainSimilarityIndex.build(seeds, top_k=top_k)
    nrd_domains = read_domains_from_path(nrd_input, max_domains=max_nrd)
    candidates = score_nrd_domains(
        nrd_domains,
        index,
        min_score=min_score,
        include_dga=include_dga,
        include_dga_only=include_dga_only,
        dga_threshold=dga_threshold,
        top_k=top_k,
    )

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    candidates_file = output_path / "apt_nrd_similarity_candidates.csv"
    summary_file = output_path / "apt_nrd_similarity_summary.json"
    write_candidates(candidates_file, candidates)

    route_counts = Counter(seed.route for seed in seeds)
    summary = {
        "positives_path": str(Path(positives_path).resolve()),
        "nrd_input": str(Path(nrd_input).resolve()),
        "output_candidates_file": str(candidates_file.resolve()),
        "summary_file": str(summary_file.resolve()),
        "positive_domains": len(positives),
        "positive_seeds": len(seeds),
        "index_seeds": len(index.seeds),
        "seed_route_counts": dict(sorted(route_counts.items())),
        "nrd_domains": len(nrd_domains),
        "output_candidates": len(candidates),
        "parameters": {
            "top_k": top_k,
            "min_score": min_score,
            "max_nrd": max_nrd,
            "include_dga": include_dga,
            "include_dga_only": include_dga_only,
            "dga_threshold": dga_threshold,
            "tfidf_ngram_range": [3, 5],
        },
        "run_seconds": round(time.time() - started, 3),
    }
    summary_file.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def write_candidates(path: Path, candidates: list[Candidate]) -> None:
    fieldnames = [
        "domain",
        "normalized_domain",
        "route",
        "matched_positive",
        "matched_positive_route",
        "tfidf_similarity",
        "rerank_score",
        "dga_score",
        "final_score",
        "reasons",
        "features_json",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for candidate in candidates:
            row = asdict(candidate)
            for key in ("tfidf_similarity", "rerank_score", "dga_score", "final_score"):
                row[key] = f"{float(row[key]):.6f}"
            writer.writerow(row)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Screen NRD domains for string similarity to historical APT-like domains."
    )
    parser.add_argument("--positives", default=str(DEFAULT_POSITIVES_PATH), help="Historical positive domain file.")
    parser.add_argument("--input", default=str(DEFAULT_NRD_INPUT), help="NRD file or directory.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_DIR), help="Output directory.")
    parser.add_argument("--top-k", type=int, default=10, help="Nearest historical seeds per NRD domain.")
    parser.add_argument("--min-score", type=float, default=0.55, help="Minimum fused score to output.")
    parser.add_argument("--max-nrd", type=int, default=0, help="Optional cap for validation runs. 0 means all.")
    parser.add_argument("--dga-threshold", type=float, default=0.72, help="DGA branch score threshold.")
    parser.add_argument("--no-dga", action="store_true", help="Disable DGA-like branch fusion.")
    parser.add_argument(
        "--include-dga-only",
        action="store_true",
        help="Also output high DGA-like NRDs even when no historical-similarity pair passes the threshold.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        summary = run_detection(
            positives_path=args.positives,
            nrd_input=args.input,
            output_dir=args.output,
            top_k=max(1, args.top_k),
            min_score=max(0.0, min(1.0, args.min_score)),
            max_nrd=max(0, args.max_nrd),
            include_dga=not args.no_dga,
            include_dga_only=args.include_dga_only,
            dga_threshold=max(0.0, min(1.0, args.dga_threshold)),
        )
    except Exception as exc:
        print(f"Error: {exc}")
        raise SystemExit(1) from exc

    print(f"Positive seeds: {summary['positive_seeds']}")
    print(f"Index seeds (A+E): {summary['index_seeds']}")
    print(f"NRD domains scanned: {summary['nrd_domains']}")
    print(f"Output candidates: {summary['output_candidates']}")
    print(f"Candidate CSV: {summary['output_candidates_file']}")
    print(f"Summary JSON: {summary['summary_file']}")


if __name__ == "__main__":
    main()
