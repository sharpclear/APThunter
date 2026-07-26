from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List
from urllib.parse import urlsplit


DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")
COMMON_3_PART_SUFFIXES = {
    "ac.cn",
    "com.cn",
    "edu.cn",
    "gov.cn",
    "net.cn",
    "org.cn",
    "com.hk",
    "edu.hk",
    "gov.hk",
    "net.hk",
    "org.hk",
    "com.tw",
    "edu.tw",
    "gov.tw",
    "net.tw",
    "org.tw",
    "ac.uk",
    "co.uk",
    "gov.uk",
    "ltd.uk",
    "me.uk",
    "net.uk",
    "org.uk",
    "com.au",
    "edu.au",
    "gov.au",
    "net.au",
    "org.au",
    "co.jp",
    "ne.jp",
    "or.jp",
    "com.br",
    "net.br",
    "org.br",
    "com.mx",
    "com.tr",
    "com.sg",
    "com.my",
    "co.kr",
    "or.kr",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_domain(value: object) -> str:
    """与 APT2 attribution_pipeline.normalize_domain 保持一致。"""
    if value is None:
        return ""
    text = str(value).strip().lower()
    if not text:
        return ""
    text = text.strip(" \t\r\n'\"`<>[](){}")
    text = text.replace("\\.", ".")
    if "://" in text:
        text = urlsplit(text).hostname or ""
    else:
        if "@" in text:
            text = text.rsplit("@", 1)[-1]
        text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if ":" in text and text.count(":") == 1:
            text = text.rsplit(":", 1)[0]
    while text.startswith("*."):
        text = text[2:]
    text = text.strip(".")
    if text.startswith("www."):
        text = text[4:]
    if not text or "." not in text:
        return ""
    try:
        ipaddress.ip_address(text)
        return ""
    except ValueError:
        pass

    labels: List[str] = []
    for label in text.split("."):
        if not label:
            return ""
        try:
            ascii_label = label.encode("idna").decode("ascii")
        except UnicodeError:
            return ""
        if len(ascii_label) > 63 or ascii_label.startswith("-") or ascii_label.endswith("-"):
            return ""
        labels.append(ascii_label)
    domain = ".".join(labels)
    if len(domain) > 253 or not DOMAIN_RE.match(domain):
        return ""
    return domain


def registered_domain(domain: str) -> str:
    labels = [label for label in domain.split(".") if label]
    if len(labels) <= 2:
        return domain
    suffix2 = ".".join(labels[-2:])
    if suffix2 in COMMON_3_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def split_tokens(value: object) -> List[str]:
    if not value:
        return []
    return [part.strip() for part in re.split(r"[;,|]", str(value)) if part.strip()]


def stable_json_hash(value: object) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def stable_values_hash(values) -> str:
    normalized = sorted({str(value).strip() for value in values if str(value or "").strip()})
    return stable_json_hash(normalized) if normalized else ""


def read_csv_rows(path: Path) -> Iterator[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as handle:
        yield from csv.DictReader(handle)


def parse_json_field(value: object, default: object) -> object:
    if not value:
        return default
    try:
        return json.loads(str(value))
    except Exception:
        return default


@dataclass(frozen=True)
class Candidate:
    domain: str
    registered_domain: str
    model_score: float = 1.0


@dataclass
class Evidence:
    source: str
    evidence_type: str
    confidence: float
    subject: str
    object_type: str = ""
    object_value: str = ""
    relation: str = ""
    observed_at: str = ""
    attrs: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "source": self.source,
            "evidence_type": self.evidence_type,
            "confidence": round(self.confidence, 4),
            "subject": self.subject,
            "object_type": self.object_type,
            "object_value": self.object_value,
            "relation": self.relation,
            "observed_at": self.observed_at,
            "attrs": self.attrs,
        }


@dataclass
class ProviderResult:
    provider: str
    status: str
    evidence: List[Evidence] = field(default_factory=list)
    detail: str = ""

