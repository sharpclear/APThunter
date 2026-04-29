import re
from dataclasses import dataclass
from typing import Optional, Sequence, Set, Tuple

try:
    import tldextract  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - fallback path
    tldextract = None


LOGIN_WORDS: Set[str] = {
    "login",
    "signin",
    "signon",
    "auth",
    "authenticate",
    "authentication",
    "account",
    "password",
}
SECURITY_WORDS: Set[str] = {
    "secure",
    "security",
    "verify",
    "verification",
    "confirm",
    "token",
    "otp",
    "2fa",
}
UPDATE_WORDS: Set[str] = {
    "update",
    "upgrade",
    "renew",
    "refresh",
    "patch",
}
SERVICE_WORDS: Set[str] = {
    "service",
    "portal",
    "mail",
    "email",
    "support",
    "cloud",
    "office",
    "web",
}


@dataclass(frozen=True)
class DomainFeatures:
    domain: str
    sld: str
    tld: str
    tokens: list[str]


def _normalize_domain_input(domain_name: str) -> str:
    value = (domain_name or "").strip().lower()
    if not value:
        return ""
    value = re.sub(r"^[a-z]+://", "", value)
    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if ":" in value:
        value = value.split(":", 1)[0]
    return value.strip(".")


def extract_domain_features(domain_name: str) -> DomainFeatures:
    domain = _normalize_domain_input(domain_name)
    sld = ""
    tld = ""

    if domain and tldextract is not None:
        extracted = tldextract.extract(domain)
        sld = (extracted.domain or "").lower()
        tld = (extracted.suffix or "").lower()
    elif domain:
        parts = [part for part in domain.split(".") if part]
        if len(parts) >= 2:
            sld = parts[-2]
            tld = parts[-1]
        elif parts:
            sld = parts[0]

    tokens = [token for token in re.split(r"[-_.\d]+", domain) if token]
    return DomainFeatures(domain=domain, sld=sld, tld=tld, tokens=tokens)


def char_ngrams(value: str, n: int = 3) -> Set[str]:
    normalized = (value or "").strip().lower()
    if not normalized or n <= 0:
        return set()
    if len(normalized) < n:
        return {normalized}
    return {normalized[i : i + n] for i in range(len(normalized) - n + 1)}


def jaccard_similarity(left: Set[str], right: Set[str]) -> float:
    if not left or not right:
        return 0.0
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def max_ioc_similarity(
    domain_name: str, domain_iocs: Sequence[str], ngram_size: int = 3
) -> Tuple[float, Optional[str]]:
    target_domain = extract_domain_features(domain_name).domain
    target_ngrams = char_ngrams(target_domain, ngram_size)

    best_score = 0.0
    best_ioc: Optional[str] = None

    for ioc in domain_iocs:
        ioc_domain = extract_domain_features(str(ioc)).domain
        if not ioc_domain:
            continue
        score = jaccard_similarity(target_ngrams, char_ngrams(ioc_domain, ngram_size))
        if score > best_score:
            best_score = score
            best_ioc = ioc_domain

    return best_score, best_ioc


def compute_pattern_score(tokens: Sequence[str]) -> float:
    token_set = {str(token).strip().lower() for token in tokens if str(token).strip()}
    if not token_set:
        return 0.0

    service_hit = bool(token_set & SERVICE_WORDS)
    login_hit = bool(token_set & LOGIN_WORDS)
    security_hit = bool(token_set & SECURITY_WORDS)
    update_hit = bool(token_set & UPDATE_WORDS)

    if service_hit and login_hit and security_hit:
        return 0.9
    if service_hit and login_hit and update_hit:
        return 0.85
    if login_hit and security_hit:
        return 0.6
    return 0.0
